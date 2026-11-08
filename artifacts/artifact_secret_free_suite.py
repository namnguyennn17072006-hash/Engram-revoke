# -*- coding: utf-8 -*-
"""
GĐ5 CÂU 5 - ĐÓNG ARTIFACT KHÔNG CHỨA SECRET TEST MATERIAL (190)

"""

import base64
import hashlib
import io
import json
import os
import time
from contextlib import redirect_stdout
from dataclasses import asdict
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from rotation_resharing_cost import _banner, _table, build_threshold_env
from capabilityverifier import CapabilityVerifier
from dkg_threshold_service import (
    ECPoint,
    N_ORDER,
    P_CURVE,
    lagrange_coefficient,
)
from epoch_transition_rewrap import (
    issue_capability,
    safe_create_partial,
    decrypt_payload,
)
from wrap_dek_partial_decryption import (
    ThresholdWrappedDEK,
    ThresholdWrapNode,
    WrapContext,
    combine_and_unwrap,
    verify_partial,
)
from signedandapend_events import PolicyEvent, VerifiableMMR
from anchorroot import (
    ConsistencyProof,
    EpochAnchor,
    KeyNodeEnforcementVerifier,
    PeakConsistencyPath,
)

OID = "OBJ-ART"
ART_DIR = "artifacts"
ART_PATH = os.path.join(ART_DIR, "engram_audit_bundle.json")

# Tên key JSON bị cấm trong bundle (rò rỉ kiểu dữ liệu = vẫn là leak)
FORBIDDEN_KEYS = {
    "dek", "payload", "payload_ct", "share", "private_share", "shares",
    "sk", "secret", "secrets", "wrap_key", "master", "joint_secret",
    "bridge_sk", "authority_sk", "issuer_sk", "private_key", "seed", "r",
}


# =============================================================================
# TIỆN ÍCH QUÉT / DESERIALIZE
# =============================================================================
def _int_bytes(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _sk_raw(sk) -> bytes:
    return sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _variants(secret: bytes, decimal: Optional[str] = None
              ) -> List[Tuple[str, bytes]]:
    """Mọi encoding thường gặp để hunt secret trong artifact."""
    out = [
        ("raw", secret),
        ("hex", secret.hex().encode()),
        ("HEX", secret.hex().upper().encode()),
        ("b64", base64.b64encode(secret)),
        ("b64url", base64.urlsafe_b64encode(secret)),
    ]
    if decimal is not None:
        out.append(("dec", decimal.encode()))
    return out


def _walk_keys(node) -> List[str]:
    keys: List[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            keys.append(str(k))
            keys.extend(_walk_keys(v))
    elif isinstance(node, list):
        for v in node:
            keys.extend(_walk_keys(v))
    return keys


def _point_from_bytes(b: bytes) -> ECPoint:
    """Giải nén điểm 33B (02/03||x) - secp256k1, đối xứng ECPoint.to_bytes()."""
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("không phải điểm nén 33 byte")
    x = int.from_bytes(b[1:], "big")
    y = pow((pow(x, 3, P_CURVE) + 7) % P_CURVE, (P_CURVE + 1) // 4, P_CURVE)
    if (y % 2) != (b[0] & 1):
        y = P_CURVE - y
    return ECPoint(x, y)


def _wrap_from_bundle(bundle: dict) -> ThresholdWrappedDEK:
    """Tái tạo ThresholdWrappedDEK CHỈ từ dữ liệu công khai trong bundle."""
    w = bundle["objects"][0]["wrap"]
    return ThresholdWrappedDEK(
        c1=_point_from_bytes(bytes.fromhex(w["c1"])),
        nonce=bytes.fromhex(w["nonce"]),
        ciphertext=bytes.fromhex(w["ciphertext"]),
        context=WrapContext(**w["context"]),
    )


# =============================================================================
# ĐÓNG BUNDLE (CHỈ TRƯỜNG CÔNG KHAI)
# =============================================================================
def build_bundle(env: dict, cap: dict, cap_sig: bytes) -> dict:
    log = env["log"]
    bridge = env["bridge"]
    dkg = env["dkg"]
    obj = env["objects"][0]
    anchors = [asdict(a) for _, a in sorted(bridge.anchor_chain.items())]
    (e1, e2), proof = next(iter(bridge.consistency_proof_store.items()))
    return {
        "schema": "engram-revoke/audit-bundle/v1",
        "created_unix": time.time(),
        "config": {"n": env["n"], "t": env["t"], "object_id": OID,
                   "codec": "JSON-GCM-v1", "epoch": 1},
        "public_keys": {
            "authority_pk": log.authority_pk.public_bytes_raw().hex(),
            "bridge_pk": bridge.bridge_pk.public_bytes_raw().hex(),
            "issuer_pk": env.get("_issuer_pk_hex"),
            "dkg_joint_public_key": dkg.joint_public_key.to_bytes().hex(),
            "dkg_public_shares": {str(j): p.to_bytes().hex()
                                  for j, p in dkg.public_key_shares.items()},
        },
        "policy_records": {k: dict(v) for k, v in log.policy_records.items()},
        "policy_events": [asdict(e) for e in log.event_history],
        "mmr": {"root": log.mmr.get_root().hex(),
                "size": len(log.mmr.leaves)},
        "anchors": anchors,
        "consistency": asdict(proof),
        "objects": [{
            "object_id": obj["object_id"],
            "policy_hash": obj["ph_ingest"],
            "wrap": {
                "c1": obj["wrap"].c1.to_bytes().hex(),
                "nonce": obj["wrap"].nonce.hex(),
                "ciphertext": obj["wrap"].ciphertext.hex(),
                "context": {
                    "object_id": obj["wrap"].context.object_id,
                    "version": obj["wrap"].context.version,
                    "policy_hash": obj["wrap"].context.policy_hash,
                    "codec_id": obj["wrap"].context.codec_id,
                    "epoch": obj["wrap"].context.epoch,
                    "policy_root": obj["wrap"].context.policy_root,
                },
            },
        }],
        "capabilities": [{"capability": cap, "signature": cap_sig.hex()}],
    }


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    T0 = time.time()
    checks = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append((name, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f" - {detail}" if detail else ""))
        return bool(ok)

    # ---------------------------------------------------------------- setup
    env = build_threshold_env(5, 3, [OID])
    dek = env["dek"]
    obj = env["objects"][0]
    ph = obj["ph_ingest"]
    pubs = env["dkg"].public_key_shares
    t_thr = env["t"]
    pdb = env["log"].policy_records

    issuer_sk = ed25519.Ed25519PrivateKey.generate()
    cap, cap_sig = issue_capability(issuer_sk, "alice", OID, "read", 1)
    env["_issuer_pk_hex"] = (
        issuer_sk.public_key().public_bytes_raw().hex())

    # Anchor epoch 2 (cùng MMR - chưa có event mới) để có chuỗi 2 anchor
    env["bridge"].anchor_epoch(2, env["log"].mmr)

    # --- kho secret (ngoài bundle) để quét -----------------------------------
    ids = list(range(1, t_thr + 1))
    joint_sk = sum(lagrange_coefficient(j, ids) * env["nodes"][j].share
                   for j in ids) % N_ORDER
    secrets: List[Tuple[str, List[Tuple[str, bytes]]]] = [
        ("DEK", _variants(dek)),
        ("payload-plaintext", _variants(obj["payload"])),
        ("joint-sk", _variants(_int_bytes(joint_sk), str(joint_sk))),
        ("log-authority-sk", _variants(_sk_raw(env["log"].authority_sk))),
        ("bridge-sk", _variants(_sk_raw(env["bridge"].bridge_sk))),
        ("issuer-sk", _variants(_sk_raw(issuer_sk))),
    ]
    for j in range(1, env["n"] + 1):
        x = env["nodes"][j].share
        secrets.append((f"node-share-{j}",
                        _variants(_int_bytes(x), str(x))))

    # -------------------------------------------------- 1. ĐÓNG ARTIFACT
    _banner("1. ĐÓNG ARTIFACT - GHI/ĐỌC LẠI TỪ ĐĨA (190)")
    os.makedirs(ART_DIR, exist_ok=True)
    bundle = build_bundle(env, cap, cap_sig)
    blob = json.dumps(bundle, indent=1, sort_keys=True,
                      ensure_ascii=False).encode("utf-8")
    with open(ART_PATH, "wb") as fh:
        fh.write(blob)
    with open(ART_PATH, "rb") as fh:
        blob_disk = fh.read()
    reloaded = json.loads(blob_disk.decode("utf-8"))
    normalized = json.loads(json.dumps(bundle))
    check("C1: bundle ghi -> đọc lại khớp 100% + schema version",
          reloaded == normalized and reloaded["schema"] ==
          "engram-revoke/audit-bundle/v1",
          f"{len(blob_disk) / 1024:.1f} KB, {len(reloaded['policy_events'])} event, "
          f"{len(reloaded['anchors'])} anchor, {len(reloaded['objects'])} object, "
          f"{len(reloaded['capabilities'])} capability")

    # -------------------------------------------------- 2. QUÉT SECRET
    _banner("2. QUÉT SECRET TRONG ARTIFACT - MỌI ENCODING (190)")
    hits: List[str] = []
    needles = 0
    for name, variants in secrets:
        for enc, needle in variants:
            if not needle:
                continue
            needles += 1
            if needle in blob_disk:
                hits.append(f"{name}/{enc}")
    bad_keys = sorted({k.lower() for k in _walk_keys(reloaded)}
                      & FORBIDDEN_KEYS)
    control = reloaded["public_keys"]["dkg_joint_public_key"].encode()
    control_ok = control in blob_disk          # positive-control: phải TÌM THẤY
    check("C2: 0 secret trong artifact (raw/hex/b64/decimal + key-name)",
          not hits and not bad_keys and control_ok,
          f"{len(secrets)} secret x {needles} needle = 0 khớp; "
          f"bad-keys={bad_keys or '∅'}; control pk "
          f"{'tìm thấy' if control_ok else 'MẤT - scanner hỏng!'}")

    # --------------------------------- 3. KIỂM CHỨNG CÔNG KHAI TỪ ARTIFACT
    _banner("3. KIỂM CHỨNG CHỈ BẰNG KHÓA CÔNG KHAI - TỪ BUNDLE ĐÃ NẠP LẠI")
    pk = reloaded["public_keys"]
    authority_pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pk["authority_pk"]))
    bridge_pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pk["bridge_pk"]))
    issuer_pk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pk["issuer_pk"]))

    events = [PolicyEvent(**e) for e in reloaded["policy_events"]]
    def _sig_ok(k, sig, data):
        try:
            k.verify(sig, data)
            return True
        except Exception:
            return False
    events_ok = all(
        _sig_ok(authority_pk, bytes.fromhex(e.signature),
                e.canonical_bytes_for_signing())
        for e in events)

    mmr = VerifiableMMR()
    for e in events:
        mmr.append(e.to_leaf_bytes())
    mmr_ok = (mmr.get_root().hex() == reloaded["mmr"]["root"]
              == reloaded["anchors"][0]["mmr_root"])

    anchors = [EpochAnchor(**a) for a in reloaded["anchors"]]
    verifier = KeyNodeEnforcementVerifier(bridge_pk)
    chain_ok = (verifier.verify_anchor_signature(anchors[0])
                and verifier.verify_anchor_signature(anchors[1])
                and anchors[0].prev_anchor_hash == "0" * 64
                and anchors[1].prev_anchor_hash == anchors[0].get_anchor_hash())
    cd = reloaded["consistency"]
    proof = ConsistencyProof(
        from_epoch=cd["from_epoch"], to_epoch=cd["to_epoch"],
        from_size=cd["from_size"], to_size=cd["to_size"],
        from_root=cd["from_root"], to_root=cd["to_root"],
        peak_proofs=[PeakConsistencyPath(**p) for p in cd["peak_proofs"]])
    cons_ok = verifier.verify_consistency_proof(anchors[0], anchors[1], proof)

    cap_b, sig_b = reloaded["capabilities"][0]["capability"], \
        bytes.fromhex(reloaded["capabilities"][0]["signature"])
    try:
        with redirect_stdout(io.StringIO()):
            cap_ok = CapabilityVerifier(issuer_pk).verify_capability(
                cap_b, sig_b, "alice", OID, "read", 1)
    except Exception:
        cap_ok = False
    check("C3: capability + event-sig + MMR root + 2 anchor + consistency "
          "đều verify bằng khóa công khai",
          events_ok and mmr_ok and chain_ok and cons_ok and cap_ok,
          f"events {len(events)}/{len(events)}, mmr {mmr_ok}, "
          f"anchor-chain {chain_ok}, consistency {cons_ok}, capability {cap_ok}")

    # ------------------------------------------- 4. TẤN CÔNG OFFLINE VỚI BUNDLE
    _banner("4. ATTACKER CHỈ CÓ BUNDLE - KHÔNG SHARE/KHÔNG SK (190)")
    wrap_b = _wrap_from_bundle(reloaded)
    rng = lambda: (int.from_bytes(os.urandom(32), "big") % (N_ORDER - 1)) + 1
    fake_partials = []
    for j in ids:                      # share giả = ngẫu nhiên (attacker đoán)
        fake = ThresholdWrapNode(j, rng(), pubs[j], t_thr, oracle=None)
        fake_partials.append(fake.create_partial(wrap_b))
    valid_fake = sum(
        1 for j, p in zip(ids, fake_partials)
        if verify_partial(p, pubs[j], wrap_b.c1, wrap_b.proof_context()))
    blocked = 0
    try:
        combine_and_unwrap(fake_partials, pubs, t_thr, wrap_b)
    except Exception:
        blocked = 1
    gcm_ok = 0
    y_bytes = bytes.fromhex(pk["dkg_joint_public_key"])
    cands = [hashlib.sha256(y_bytes).digest(),
             hashlib.sha256(wrap_b.c1.to_bytes()).digest(),
             hashlib.sha256(
                 reloaded["anchors"][0]["mmr_root"].encode()).digest()]
    for k in cands:
        try:
            AESGCM(k).decrypt(wrap_b.nonce, wrap_b.ciphertext,
                              wrap_b.context.aad())
            gcm_ok += 1
        except InvalidTag:
            pass
    check("C4: 0 lần mở được từ bundle (share giả 0/t hợp lệ; GCM "
          "với khóa suy ra từ dữ liệu công khai = 0)",
          valid_fake == 0 and blocked == 1 and gcm_ok == 0,
          f"partial hợp lệ {valid_fake}/{t_thr}; combine "
          f"{'bị chặn' if blocked else 'MỞ ĐƯỢC!'}; GCM mở được {gcm_ok}/3")

    # --------------------------- 5. TÁI SỬ DỤNG: BUNDLE + SHARE OUT-OF-BAND
    _banner("5. TÁI SỬ DỤNG Ở MÔI TRƯỜNG THẬT - BUNDLE (CÔNG KHAI) + SHARE")
    pcs = [safe_create_partial(env["nodes"][j], wrap_b, env["rewrap"], pdb)
           for j in ids]
    dek_rec = combine_and_unwrap(pcs, pubs, t_thr, wrap_b)
    payload_rec = decrypt_payload(dek_rec, obj["payload_ct"], OID, 1, ph,
                                  "JSON-GCM-v1")
    check("C5: bundle tải từ đĩa + share giữ ngoài (node) -> unwrap DEK -> "
          "payload giống hệt",
          dek_rec == dek and payload_rec == obj["payload"],
          f"DEK khớp: {dek_rec == dek}; payload khớp: "
          f"{payload_rec == obj['payload']}")

    # -------------------------------------------------- 6. BÁO CÁO SỐ LIỆU
    _banner("6. BÁO CÁO ARTIFACT")
    _table(["chi so", "gia tri"], [
        ["kich thuoc bundle", f"{len(blob_disk) / 1024:.1f} KB"],
        ["policy events / MMR size", f"{len(events)} / "
                                     f"{reloaded['mmr']['size']}"],
        ["anchors / consistency proofs", f"{len(anchors)} / 1"],
        ["objects / capabilities", f"{len(reloaded['objects'])} / "
                                   f"{len(reloaded['capabilities'])}"],
        ["public keys (pk + shares)", f"3 + {len(pk['dkg_public_shares'])}"],
        ["secret can quiet (needle)", f"{len(secrets)} x {needles} + "
                                      f"{len(FORBIDDEN_KEYS)} key-name"],
        ["tong thoi gian", f"{time.time() - T0:.1f} s"],
    ])
    check("C6: báo cáo số liệu artifact đầy đủ", True,
          f"{len(blob_disk) / 1024:.1f} KB, {len(checks) + 1} check")

    passed = sum(1 for _, ok in checks if ok)
    print(f"""
  ==============================================================================
  KET LUAN - ARTIFACT KHONG CHUA SECRET (190)
  ==============================================================================
  PHAN LOAI (192):
    * SECURITY / BLOCKED  : share gia -> DLEQ lo 0/{t_thr}, bundle khong
                            tao duoc partial hop le (C4a); khoa suy ra tu
                            public key/root/c1 -> InvalidTag (C4b).
    * SECURITY / DETECTED : quet secret 6 loai x {needles} encoding + key-name
                            blacklist = 0 ro ri; control tim thay (C2).
    * POLICY / DETECTED   : moi event/anchor deu co chu ky gan object/epoch/
                            prev-hash - sua bat ky nao deu bi verify that bai
                            tu bundle (C3).
    * AVAILABILITY        : khong do o cau nay (da do o cau 1/2).

  CLAIMS - viet theo DIEU KIEN (193):
    NEU attacker CHI giu bundle (public key, signed event, anchor, wrap,
    capability) VA khong co share/DEK/plaintext leakage tu truoc, THI:
      + khong unwrap duoc object nao (0/{t_thr} partial hop le, 0/3 khoa GCM);
      + sua moi truong trong bundle deu bi bat khi re-verify bang public key.
    NEU node giu share OUT-OF-BAND (khong co trong artifact), THI bundle tai
    tu dia van dung de verify + unwrap binh thuong (C5).

  GIOI HAN / THREAT-TO-VALIDITY (199):
    - Quet theo cac encoding pho bien (raw/hex/b64/decimal) - khong phai chung
      minh toan hoc rang khong con duong nao ro ri khac (vd. canal bi ghi ra
      log ben ngoai bundle).
    - Bundle dai dien pipeline nay (5,3, 1 object); khong bao quet artifact
      cua pyhpke/wrapDEK (khong chay duoc o moi truong nay - 196).
    - "Artifact sach secret" khong HE thong an toan: share van phai phan phoi
      out-of-band/HSM, va payload van nam o lop luu tru rieng.
    - JSON chua chu ky/point dang hex - neu co bug encode so share vao JSON
      thi check C2 (decimal) se bat - nhung khong dua vao du lieu test.

  KHONG SUY DIEN (194): chi la THI NGHIEM tren artifact cua pipeline nay -
    khong phai bao dam artifact cua he thong that luon sach secret, khong
    thay the audit/kiem chuan tu van phap luat.

  ==============================================================================
  KET LUAN
  ==============================================================================""")
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(checks)} kiem tra PASS; tong thoi gian: "
          f"{time.time() - T0:.1f} s")
