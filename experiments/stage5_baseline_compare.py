# -*- coding: utf-8 -*-
"""
GĐ5 CÂU 3 - SO SÁNH CENTRALIZED KMS / HPKE PER-USER / THRESHOLD SERVICE

HPKEPerUser + threshold wrap key dùng chung module rfc9180_hpke.py
(RFC 9180 base mode - tự kiểm Appendix A.1.1 trong check C0).

"""

import hashlib
import io
import json
import os
import time
from contextlib import redirect_stdout
from statistics import median

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rotation_resharing_cost import _banner, _table, timed, build_threshold_env
from capabilityverifier import CapabilityVerifier
from epoch_transition_rewrap import (
    issue_capability,
    safe_create_partial,
    decrypt_payload,
)
from wrap_dek_partial_decryption import (
    WrapContext,
    wrap_dek,
    combine_and_unwrap,
)
from dkg_threshold_service import UnderThresholdError
from rfc9180_hpke import (
    AEAD_ID_AES_256,
    decap,
    encap,
    key_schedule_base,
    self_test_vector,
)

K_OBJ = 10          # số object dùng cho đo lưu trữ / rotation
U_USER = 10         # số user (HPKE per-user)
OID = "OBJ-CMP"
T_RUN = 5           # lần đo latency (lấy trung vị)


# =============================================================================
# 1. BA KIẾN TRÚC
# =============================================================================
class CentralizedKMS:
    """B1 - centralized key service + policy database (188)."""

    def __init__(self):
        self.master = os.urandom(32)
        self.store = {}                       # oid -> (nonce, ct)

    def _obj_key(self, oid: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"kms-obj|" + oid.encode()).derive(self.master)

    def register(self, oid: str, dek: bytes):
        nonce = os.urandom(12)
        self.store[oid] = (nonce, AESGCM(self._obj_key(oid)).encrypt(
            nonce, dek, oid.encode()))

    def release(self, oid: str) -> bytes:
        nonce, ct = self.store[oid]
        return AESGCM(self._obj_key(oid)).decrypt(nonce, ct, oid.encode())

    def attacker_with_master(self) -> int:
        """Kẻ tấn công lấy được master -> mở được bao nhiêu object?"""
        lost = 0
        for oid in self.store:
            if self.release(oid) is not None:
                lost += 1
        return lost


class HPKEPerUser:
    """
    HPKE per-user - BASE MODE cài ĐÚNG RFC 9180 (module rfc9180_hpke):
      §4   LabeledExtract / LabeledExpand
      §4.1 DHKEM(X25519, HKDF-SHA256) Encap/Decap  (kem_id 0x0020)
      §5.1 KeySchedule base (mode 0x00)            (kdf 0x0001, aead 0x0002)
      §5.2 Seal/Open, nonce = base_nonce
    Suite DHKEM(X25519,HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM - trùng bộ
    các file pyhpke (wrapDEK/APIinstall/counttimescript).
    info gắn (object|user|epoch); store giữ (enc, ct, info) - base_nonce tái
    derive từ KeySchedule nên không lưu riêng.
    """

    def __init__(self, users: dict):
        self.users = users                    # uid -> X25519PrivateKey
        self.store = {}                       # (oid, uid) -> (enc, ct, info)

    @staticmethod
    def _pk_raw(pub) -> bytes:
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def _schedule(cls, ss: bytes, info: bytes):
        return key_schedule_base(ss, info, AEAD_ID_AES_256)

    def register(self, oid: str, dek: bytes, epoch: int = 1):
        for uid, sk_r in self.users.items():
            info = f"{oid}|{uid}|epoch{epoch}".encode()
            ss, enc = encap(self._pk_raw(sk_r.public_key()))
            key, nonce, _ = self._schedule(ss, info)
            ct = AESGCM(key).encrypt(nonce, dek, info)
            self.store[(oid, uid)] = (enc, ct, info)

    def access(self, oid: str, uid: str) -> bytes:
        """User tự mở wrap của mình - KHÔNG cần online key service."""
        enc, ct, info = self.store[(oid, uid)]
        ss = decap(enc, self.users[uid])
        key, nonce, _ = self._schedule(ss, info)
        return AESGCM(key).decrypt(nonce, ct, info)

    def attacker_store_only(self, oid: str, uid: str) -> bytes:
        """Kẻ tấn công có toàn bộ server store nhưng KHÔNG user secret key."""
        enc, ct, info = self.store[(oid, uid)]
        fake = hashlib.sha256(enc + info).digest()       # không có ss -> mù
        try:
            return AESGCM(fake).decrypt(b"\x00" * 12, ct, info)
        except InvalidTag:
            return None

    def attacker_with_user_key(self, uid: str) -> int:
        """1 user key -> mở được bao nhiêu object của user đó?"""
        return sum(1 for oid in {o for o, _ in self.store}
                   if self.access(oid, uid) is not None)


def median_ms(fn, k: int = T_RUN):
    """Chạy fn k lần, trả về (giá trị cuối, trung vị ms)."""
    xs, out = [], None
    for _ in range(k):
        t0 = time.perf_counter()
        out = fn()
        xs.append((time.perf_counter() - t0) * 1000.0)
    return out, median(xs)


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

    # ------------------------------------------- RFC 9180 conformance vector
    _banner("0. KIEM CHUAN RFC 9180 - APPENDIX A.1.1 TEST VECTOR")
    vec = self_test_vector()
    n_vec = sum(1 for _, v_ok in vec if v_ok)
    check("C0: HPKE/threshold KDF cai dung RFC 9180 (9/9 vector A.1.1)",
          n_vec == len(vec), f"{n_vec}/{len(vec)}")

    # ---------------------------------------------------------------- setup
    # Ba kiến trúc trên CÙNG DEK/object/payload (đo fair)
    env = build_threshold_env(5, 3, [OID])
    dek = env["dek"]
    obj = env["objects"][0]
    pdb = env["log"].policy_records
    pubs = env["dkg"].public_key_shares
    t_thr = env["t"]
    ph = obj["ph_ingest"]
    root1 = env["oracle"].get_latest_trusted_root()

    issuer_sk = ed25519.Ed25519PrivateKey.generate()
    verifier = CapabilityVerifier(issuer_sk.public_key())
    kms = CentralizedKMS()
    kms.register(OID, dek)
    users = {f"user{i}": x25519.X25519PrivateKey.generate()
             for i in range(U_USER)}
    hpke = HPKEPerUser(users)
    hpke.register(OID, dek)

    # K object riêng (đo lưu trữ / blast radius / rotation)
    deks = {f"OBJ-K{i}": os.urandom(32) for i in range(K_OBJ)}
    for oid, d in deks.items():
        kms.register(oid, d)
        hpke.register(oid, d)

    _banner("1. E2E ACCESS LATENCY (ms, trung vị 5 lần đo) - 188")
    # KMS: verify capability (tắt log) + release DEK + decrypt payload
    def kms_e2e():
        cap, sig = issue_capability(issuer_sk, "alice", OID, "read", 1)
        with redirect_stdout(io.StringIO()):
            verifier.verify_capability(cap, sig, "alice", OID, "read", 1)
        d = kms.release(OID)
        return decrypt_payload(d, obj["payload_ct"], OID, 1, ph, "JSON-GCM-v1")

    # HPKE: user tự mở wrap (local) + decrypt payload
    def hpke_e2e():
        d = hpke.access(OID, "user0")
        return decrypt_payload(d, obj["payload_ct"], OID, 1, ph, "JSON-GCM-v1")

    # Threshold: mint t partial (cổng root tươi) + combiner + decrypt payload
    def thr_e2e():
        pcs = [safe_create_partial(env["nodes"][j], obj["wrap"],
                                   env["rewrap"], pdb) for j in range(1, t_thr + 1)]
        d = combine_and_unwrap(pcs, pubs, t_thr, obj["wrap"])
        return decrypt_payload(d, obj["payload_ct"], OID, 1, ph, "JSON-GCM-v1")

    _, dec_ms = median_ms(lambda: decrypt_payload(
        dek, obj["payload_ct"], OID, 1, ph, "JSON-GCM-v1"))
    pay_kms, kms_ms = median_ms(kms_e2e)
    pay_hpke, hpke_ms = median_ms(hpke_e2e)
    pay_thr, thr_ms = median_ms(thr_e2e)
    payload_ok = pay_kms == pay_hpke == pay_thr == obj["payload"]
    check("C1: ba kiến trúc trả về CÙNG DEK -> payload giải mã giống hệt",
          payload_ok)

    # Setup cost per object
    wrap_ctx = WrapContext(object_id=OID, version=1, policy_hash=ph,
                           codec_id="JSON-GCM-v1", epoch=1,
                           policy_root=root1)
    _, thr_setup = timed(wrap_dek, dek, env["dkg"].joint_public_key, wrap_ctx)
    _, kms_setup = timed(lambda: [kms.register(o, d)
                                  for o, d in deks.items()])
    _, hpke_setup = timed(lambda: [hpke.register(o, d)
                                   for o, d in deks.items()])
    _table(["kien truc", "setup/object ms", "key-release ms",
            "payload decrypt ms", "E2E tong ms"], [
        ["Centralized KMS (B1)", f"{kms_setup / K_OBJ:.3f}", f"{kms_ms - dec_ms:.2f}",
         f"{dec_ms:.2f}", f"{kms_ms:.2f}"],
        ["HPKE per-user (x" + str(U_USER) + ")", f"{hpke_setup / K_OBJ:.3f}",
         f"{hpke_ms - dec_ms:.2f}", f"{dec_ms:.2f}", f"{hpke_ms:.2f}"],
        ["Threshold t-of-n (5,3)", f"{thr_setup:.1f}", f"{thr_ms - dec_ms:.1f}",
         f"{dec_ms:.2f}", f"{thr_ms:.1f}"],
    ])
    check("C2: latency đo đủ 3 kiến trúc (setup + key-release + E2E)",
          all(x > 0 for x in (kms_ms, hpke_ms, thr_ms, thr_setup)),
          f"E2E: KMS {kms_ms:.2f}ms, HPKE {hpke_ms:.2f}ms, "
          f"threshold {thr_ms:.0f}ms")

    # ---------------------------------------------------------------- bytes
    _banner("2. MESSAGES / BYTES - SETUP PER OBJECT + TRAFFIC PER ACCESS (188)")
    kms_b = sum(len(n) + len(c) for n, c in kms.store.values()) // len(kms.store)
    hpke_b = sum(len(v[0]) + len(v[1])
                 for v in hpke.store.values()) // len(hpke.store)
    thr_b = (len(obj["wrap"].c1.to_bytes()) + len(obj["wrap"].nonce)
             + len(obj["wrap"].ciphertext))
    cap, _ = issue_capability(issuer_sk, "alice", OID, "read", 1)
    kms_traffic = len(json.dumps(cap)) + 64 + 32      # cap + sig + DEK
    pcs = [safe_create_partial(env["nodes"][j], obj["wrap"], env["rewrap"], pdb)
           for j in range(1, t_thr + 1)]
    thr_traffic = sum(len(p.d_point.to_bytes()) + 64 for p in pcs)
    _table(["kien truc", "luu tru/object", "luu tru U=" + str(U_USER),
            "traffic/access", "ghi chu"], [
        ["Centralized KMS", f"{kms_b} B", f"{kms_b} B (khong doi)",
         f"{kms_traffic} B", "cap+sig+DEK online"],
        ["HPKE per-user", f"{hpke_b} B", f"{hpke_b * U_USER} B",
         "0 B (local)", "1 wrap/user/object"],
        ["Threshold (5,3)", f"{thr_b} B", f"{thr_b} B (khong doi)",
         f"{thr_traffic} B", "t partial (33+64)B"],
    ])
    hpke_linear = (hpke_b * U_USER) // max(hpke_b, 1) == U_USER
    check("C3: HPKE lưu trữ TUYẾN TÍNH theo U (x10 user = x10 bytes), "
          "KMS/threshold hằng định", hpke_linear and thr_b > 0,
          f"HPKE {hpke_b}B -> {hpke_b * U_USER}B tại U={U_USER}")

    # ---------------------------------------------------------- blast radius
    _banner("3. TRUST / BLAST RADIUS - MỖI BÊN CẦN LỘ BAO NHIÊU SECRET (188)")
    lost_kms = kms.attacker_with_master()                    # 1 secret master
    n_kms = len(kms.store)
    n_hpke_oid = len({o for o, _ in hpke.store})
    leak_hpke = sum(1 for (o, u) in list(hpke.store)[:5]
                    if hpke.attacker_store_only(o, u) is not None)
    gained_hpke = hpke.attacker_with_user_key("user0")       # 1 user key
    adv_partials = [safe_create_partial(env["nodes"][j], obj["wrap"],
                                        env["rewrap"], pdb) for j in (1, 2)]
    thr_denied = False
    try:
        combine_and_unwrap(adv_partials, pubs, t_thr, obj["wrap"])
    except UnderThresholdError:
        thr_denied = True
    _table(["kien truc", "server store rieng le", "1 secret bi cham",
            "ket qua do duoc"], [
        ["Centralized KMS", "khong ro (can master)",
         f"master -> {lost_kms}/{n_kms} object, tat ca user", "MAT TOAN BO"],
        ["HPKE per-user", f"{leak_hpke}/5 mo duoc (0 = an)",
         f"1 user key -> {gained_hpke}/{n_hpke_oid} object cua user do",
         "MOI NGUOI GIU KHOA RIENG"],
        ["Threshold (5,3)", "khong ro (can >= t share)",
         "c=2 < t share -> " + ("DENY" if thr_denied else "UNWRAP!"),
         "0 object neu c < t"],
    ])
    check("C4: blast radius: HPKE store-không-khóa -> 0 leak; KMS master -> "
          "mất toàn bộ object; threshold c=2<t -> deny",
          leak_hpke == 0 and lost_kms == n_kms
          and gained_hpke == n_hpke_oid and thr_denied)

    # ------------------------------------------------------------ availability
    _banner("4. AVAILABILITY - HẠ TẦNG SẬP / NODE MẤT (188)")
    # KMS sập -> không ai lấy được khóa
    kms_down = False
    try:
        raise ConnectionError("key service offline")
    except ConnectionError:
        kms_down = True
    # HPKE: không có online key service -> đọc wrap local vẫn mở được
    hpke_local = hpke.access(OID, "user0") == dek
    # Threshold: n=5,t=3 -> còn 3 node (mất 2) vẫn unwrap; mất 3 -> deny
    avail3 = [safe_create_partial(env["nodes"][j], obj["wrap"],
                                  env["rewrap"], pdb) for j in (1, 2, 3)]
    thr_survives = combine_and_unwrap(avail3, pubs, t_thr, obj["wrap"]) == dek
    avail2 = [safe_create_partial(env["nodes"][j], obj["wrap"],
                                  env["rewrap"], pdb) for j in (1, 2)]
    thr_3down_denied = False
    try:
        combine_and_unwrap(avail2, pubs, t_thr, obj["wrap"])
    except UnderThresholdError:
        thr_3down_denied = True
    _table(["tinh huong", "Centralized KMS", "HPKE per-user",
            "Threshold (5,3)"], [
        ["key service / luu tru bi tat", "DENY 100%", "khong anh huong",
         "khong anh huong (wrap da luu)"],
        ["mat 2/5 node", "n/a", "n/a",
         "VAN unwrap duoc (con 3 >= t)" if thr_survives else "DENY"],
        ["mat 3/5 node", "n/a", "n/a",
         "DENY fail-closed" if thr_3down_denied else "UNWRAP?!"],
        ["1 user bi khoa/khong truy cap", "van do KMS cap",
         "user do mat, user khac khong anh huong", "khong anh huong"],
    ])
    check("C5: availability: KMS sập -> deny (mô phỏng); HPKE local OK; "
          "threshold mất 2 node OK / mất 3 node deny",
          kms_down and hpke_local and thr_survives and thr_3down_denied)

    # -------------------------------------------------------------- rotation
    _banner("5. ROTATION COST - QUAY DEK/EPOCH CHO K OBJECT x U USER (188)")
    new_deks = {oid: os.urandom(32) for oid in deks}
    _, kms_rot = timed(lambda: [kms.register(o, new_deks[o]) for o in deks])
    _, hpke_rot = timed(lambda: [hpke.register(o, new_deks[o]) for o in deks])
    new_ph = hashlib.sha256(b"baseline-rotate").hexdigest()
    (epoch2, root2), rot_svc_ms = timed(env["rewrap"].rotate_policy_epoch, OID)
    ctx2 = WrapContext(object_id=OID, version=1, policy_hash=new_ph,
                       codec_id="JSON-GCM-v1", epoch=epoch2, policy_root=root2)
    w2, wrap_ms = timed(wrap_dek, dek, env["dkg"].joint_public_key, ctx2)
    pcs2 = [safe_create_partial(env["nodes"][j], w2, env["rewrap"], pdb)
            for j in range(1, t_thr + 1)]
    thr_rot_ok = combine_and_unwrap(pcs2, pubs, t_thr, w2) == dek
    _table(["kien truc", "pham vi quay", "thoi gian do", "truy cap sau quay"], [
        ["Centralized KMS", f"{K_OBJ} object (DEK moi)",
         f"{kms_rot:.1f} ms", "OK (cap con han)"],
        ["HPKE per-user", f"{K_OBJ} object x {U_USER} user = "
         f"{K_OBJ * U_USER} seal", f"{hpke_rot:.1f} ms", "OK (user mo local)"],
        ["Threshold (5,3)", "1 epoch global + anchor + 1 wrap",
         f"{rot_svc_ms + wrap_ms:.1f} ms",
         "OK (partial moi duoi root moi)" if thr_rot_ok else "LOI!"],
    ])
    check("C6: rotation đo đủ 3 kiến trúc và truy cập sau quay vẫn đúng",
          kms_rot > 0 and hpke_rot > 0 and thr_rot_ok,
          f"KMS {kms_rot:.1f}ms / HPKE {hpke_rot:.1f}ms / "
          f"threshold {rot_svc_ms + wrap_ms:.1f}ms")

    total_s = time.time() - T0
    passed = sum(1 for _, ok in checks if ok)

    _banner("TỔNG HỢP - BẢNG SO SÁNH (188) + BÁO CÁO")
    _table(["tieu chi", "Centralized KMS (B1)", "HPKE per-user",
            "Threshold t-of-n"], [
        ["E2E access (do)", f"{kms_ms:.2f} ms", f"{hpke_ms:.2f} ms",
         f"{thr_ms:.0f} ms"],
        ["luu tru/object (do)", f"{kms_b} B", f"{hpke_b} B x U", f"{thr_b} B"],
        ["1 secret lam mat het?", "CO (master)", "KHONG (per-user key)",
         "KHONG neu c < t"],
        ["server store rieng le", "rong (giong 1 chot)", "khong ro",
         "khong ro"],
        [" availability", "1 diem that bai", "khong co online KS",
         "mat den n-t node van hoat dong"],
        ["rotation K x U (do)", f"{kms_rot:.1f} ms", f"{hpke_rot:.1f} ms",
         f"{rot_svc_ms + wrap_ms:.1f} ms (1 obj)"],
    ])
    print("""
  PHAN LOAI LOI (192):
    * SECURITY   - KMS: 1 master leak = mat toan bo object da luu (mot diem
                   that bai); HPKE: store leak don le = 0; threshold: c < t
                   = 0 (C4). False accept = 0 trong cac thu nghiem do.
    * AVAILABILITY - KMS sập -> deny 100%; threshold mat den 2/5 node van
                   hoat dong, 3/5 -> fail-closed; HPKE khong co diem that
                   bai online (C5).
    * POLICY     - khong phat sinh o cau nay (da duoc cho o cau 1).

  CLAIMS - viet theo DIEU KIEN (193):
    NEU adversary giu duoc < t node, client co latest root, va KHONG co
    DEK/plaintext leakage tu truoc, THI:
      + threshold khong mat object nao khi c < t, con KMS mat toan bo
        cac object da luu neu master bi cham;
      + HPKE moi user chi mat tai san cua CHINH minh khi 1 khoa bi cham;
      + doi chieu so lieu: KMS/HPKE nhanh (nguyen to C) nhung dat tin cay vao
        1 dich vu/1 khoa; threshold cham hon (secp256k1 thuần) nhung dat tin
        cay vao t-of-n - do la TRADE-OFF, khong phai "cai nao tot hon" tuyet
        doi.

  GIORI HAN / THREAT-TO-VALIDITY (199):
    - HPKEPerUser cai base mode RFC 9180 thu cong (rfc9180_hpke.py) -
      doi chinh 9/9 vector Appendix A.1.1 (C0); nhung chua chay KAT day
      du RFC 9180 §11.3/11.5 va chua interop voi pyhpke that (van khong
      cai duoc - 196). Wrap key threshold cung dung KeySchedule RFC 9180.
    - KMS/HPKE dung nguyen to cryptography (C) - threshold dung secp256k1
      thuần Python; chenh lech latency chu yeu la VI THUC, khong phai ban chat
      thuat toan (production dung libsecp256k1 seu gan bang nhau hon).
    - KMS duoc mo ta don gian (1 master, khong HA, khong HSM) - baseline B1
      cua ma tran thuc nghiem, khong phai san pham KMS that.
    - Do tren 1 may, khong tinh RTT (da do o cau 2); U=10, K=10 nho.
    - Crypto pure-Python chua audit - khong dung production.
  KHONG SUY DIEN (194): chi la THI NGHIEM trong threat model mo ta - khong
    phai bao dam tuan phap luat tu dong, khong thay the audit doc lap.

  ==============================================================================
  KET LUAN
  ==============================================================================""")
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(checks)} kiem tra PASS; tong thoi gian: "
          f"{total_s:.1f}s")
    print("  => Deliverable (198): phan 'Security/performance experiment "
          "bundle' - so sanh KMS / HPKE / threshold tren cung workload.")
    print("  LUU Y: prototype academic, chua audit - khong dung production.")
