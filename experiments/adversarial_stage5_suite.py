#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GIAI ĐOẠN 5 - CÂU 1: CHẠY 7 KỊCH BẢN ĐỐI KHÁNG - REPLAY, STALE ROOT,
CLOCK SKEW, NETWORK PARTITION, INVALID PARTIAL, CORRUPTED CIPHERTEXT,
POLICY EQUIVOCATION
File: adversarial_stage5_suite.py

GỢI Ý SỬ DỤNG (mục 186 - "Công việc phải thực hiện" GĐ5):
  186  Chạy replay, stale root, clock skew, network partition, invalid
       partial, corrupted ciphertext và policy equivocation.
  192  Tách SECURITY failure / POLICY failure / AVAILABILITY failure
       trong reporting (bảng phân loại ở cuối).
  193  Claim viết dưới dạng ĐIỀU KIỆN: adversary < t, latest root available,
       không có DEK/plaintext leakage từ trước.
  194  Không suy diễn kết quả thành bảo đảm tuân thủ pháp luật tự động.
  196  Công cụ: Engram testbed + network fault injection (ở đây mô phỏng
       trong tiến trình; ghi rõ giới hạn).
  184  Định lượng bảo mật/liveness/overhead trong đúng threat model.
  198  Security/performance experiment bundle (7 kịch bản = bundle này).
  199  Threat-to-validity & limitations (mục GIỚI HẠN cuối file).

TÁI SỬ DỤNG TOÀN BỘ code đã viết:
  * GĐ1: PolicyLogService (event ký + MMR, state machine, terminal invariant).
  * GĐ2: EngramAnchorBridge (anchor + consistency proof), KeyNodeTrusted
         Oracle 5 bước: chống equivocation (EquivocationError), clock skew
         (FailClosedFreshnessError), stale window, epoch rollback, broken
         chain, thiếu/sai consistency proof; StaleRootError ở
         resolve_fresh_policy.
  * GĐ3: wrap/proof/combiner (Chaum-Pedersen, classify verdicts,
         combine_and_unwrap, UnderThresholdError, InsufficientPartials).
  * GĐ4 câu 1: EpochRewrapService, safe_create_partial, issue_capability,
         encrypt/decrypt_payload, build_env.
  * GĐ4 câu 4: EpochReplayGate (replay tại ingress).

CODE MỚI (chỉ phục vụ thí nghiệm):
  * expect() - chạy 1 cuộc tấn công, bắt đúng ngoại lệ -> chuỗi bằng chứng.
  * forge_anchor() - gắn râu giả (root/sai lệch thời gian) nhưng KÝ LẠI bằng
    key bridge thật (mô phỏng bridge bị thao túng / equivocation).
  * detect_policy_hash_mismatch() - client so policy_hash của wrap với event
    log ký số (chống dán nhãn chính sách).
  * record() + bảng tổng hợp phân loại SECURITY/POLICY/AVAILABILITY (192).

Yêu cầu: python3 + cryptography.   Chạy: python3 adversarial_stage5_suite.py
Lưu ý:   prototype academic, CHƯA audit - không dùng production.
"""

import time
import hashlib
from dataclasses import replace as dc_replace
from typing import List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- GĐ1/GĐ2: policy log + oracle + anchor --------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EpochAnchor, ConsistencyProof
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
    FailClosedFreshnessError,
    EquivocationError,
    SecurityError as OracleSecurityError,
)

# --- GĐ3: wrap + proof + combiner --------------------------------------------------
from dkg_threshold_service import G, N_ORDER, UnderThresholdError
from wrap_dek_partial_decryption import (
    ThresholdWrappedDEK,
    PartialWithProof,
    verify_partial,
    combine_and_unwrap,
)
from chaum_pedersen_partial_proof import (
    ChaumPedersenProof,
    prove_dleq,
    verify_dleq,
)
from combiner_filter_and_combine import InsufficientPartials

# --- GĐ4 câu 1 -----------------------------------------------------------------------
from epoch_transition_rewrap import (
    decrypt_payload,
    wrap_dek,
    safe_create_partial,
    issue_capability,
    build_env,
)

# --- GĐ4 câu 4 --------------------------------------------------------------------
from capabilityverifier import CapabilityVerifier
from capabilityverifier import SecurityError as CapSecurityError
from epoch_replay_protection import EpochReplayGate, StaleEpochError


# =============================================================================
# 1. HỆ THỐNG ĐO THÍ NGHIỆM (192 - phân loại lớp lỗi)
# =============================================================================
REPORT: List[dict] = []
SECURITY, POLICY, AVAILABILITY = "SECURITY", "POLICY", "AVAILABILITY"
BLOCKED, DETECTED, FAIL_CLOSED, RECOVERED = (
    "BLOCKED", "DETECTED", "FAIL-CLOSED", "RECOVERED")


def record(scenario: str, attack: str, klass: str, verdict: str,
           detector: str, evidence: str):
    REPORT.append(dict(scenario=scenario, attack=attack, klass=klass,
                       verdict=verdict, detector=detector, evidence=evidence))
    print(f"    -> [{klass} / {verdict}] {detector}: {evidence}")


def expect(fn, exc, note: str = "") -> str:
    """Chạy 1 cuộc tấn công - trả về thông điệp ngoại lệ (bằng chứng)."""
    try:
        fn()
    except exc as err:
        return f"{type(err).__name__}: {str(err)[:74]}"
    raise AssertionError(f"phải bắt {exc.__name__} ({note})")


def forge_anchor(anchor: EpochAnchor, bridge_sk: ed25519.Ed25519PrivateKey,
                 mmr_root: Optional[str] = None,
                 timestamp: Optional[float] = None) -> EpochAnchor:
    """
    Mô phỏng bridge thao túng: giữ nguyên epoch nhưng đổi root/thời gian và
    KÝ LẠI bằng key thật (chỉ bridge mới ký được - nhưng bridge là attacker
    trong kịch bản này).  Oracle bắt ở bước 2 (equivocation) hoặc 3 (skew).
    """
    forged = dc_replace(anchor,
                        mmr_root=mmr_root if mmr_root else anchor.mmr_root,
                        timestamp=timestamp if timestamp is not None
                        else anchor.timestamp,
                        bridge_signature="")
    forged.bridge_signature = bridge_sk.sign(
        forged.canonical_bytes_for_signing()).hex()
    return forged


def detect_policy_hash_mismatch(log: PolicyLogService, object_id: str,
                                wrap) -> Optional[str]:
    """
    Client-side: policy_hash gắn trong wrap phải khớp MỘT event đã ký trong
    policy log (MMR).  Khớp -> None; khác -> equivocation/dán nhãn chính sách.
    """
    for ev in log.event_history:
        if ev.object_id != object_id:
            continue
        ph = hashlib.sha256(ev.canonical_bytes_for_signing()).hexdigest()
        if ph == wrap.context.policy_hash:
            return None
    return (f"policy_hash {wrap.context.policy_hash[:16]}... không khớp event "
            f"nào trong log của {object_id}")


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _table(headers: List[str], rows: List[List[str]]):
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    print("  " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  " + "-+-".join("-" * w for w in widths))
    for r in rows:
        print("  " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)))


# =============================================================================
# DEMO + 7 KỊCH BẢN
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results: List[str] = []
    OBJECT_A = "OBJ-S5-A"
    OBJECT_B = "OBJ-S5-B"
    SUBJ = "alice"

    # =====================================================================
    _banner("KỊCH BẢN 1: REPLAY - CAPABILITY / PARTIAL / WRAP EPOCH CŨ (186)")
    # =====================================================================
    envA = build_env(OBJECT_A)
    svcA = envA["rewrap"]
    pdbA = envA["service_log"].policy_records
    issuerA = ed25519.Ed25519PrivateKey.generate()
    gateA = EpochReplayGate(svcA, CapabilityVerifier(issuerA.public_key()))
    w1 = svcA.get_active_wrap(OBJECT_A)

    cap1, sig1 = issue_capability(issuerA, SUBJ, OBJECT_A, "read", epoch=1)
    assert gateA.check_capability(cap1, sig1, SUBJ, OBJECT_A, "read")
    ev = expect(lambda: gateA.check_capability(cap1, sig1, SUBJ, OBJECT_A,
                                               "read"),
                CapSecurityError, "nonce replay")
    record("1. Replay", "capability nonce replay (cùng epoch)", SECURITY,
           BLOCKED, "CapabilityVerifier lớp 6 - nonce cache", ev)

    proofs_old = [prove_dleq(j, envA["shares"][j], envA["pub_shares"][j],
                             w1.c1, envA["shares"][j] * w1.c1,
                             w1.proof_context()) for j in (1, 2, 3)]
    new_ph = hashlib.sha256(b"s5-rotate").hexdigest()
    epoch2, root2 = svcA.rotate_policy_epoch(OBJECT_A)
    w2 = wrap_dek(envA["dek"], envA["threshold_pk"],
                  dc_replace(w1.context, policy_hash=new_ph, epoch=epoch2,
                             policy_root=root2))
    svcA.prepare_rewrap(OBJECT_A, w2)
    svcA.commit_rewrap(OBJECT_A)

    ev = expect(lambda: gateA.check_capability(cap1, sig1, SUBJ, OBJECT_A,
                                               "read"),
                CapSecurityError, "capability epoch 1 ở epoch 2")
    record("1. Replay", "capability epoch 1 -> epoch 2", SECURITY, BLOCKED,
           "CapabilityVerifier lớp 4 - epoch binding", ev)

    ev = expect(lambda: envA["combiner"].combine(proofs_old, w2),
                InsufficientPartials, "partial epoch cũ")
    record("1. Replay", "partial/proof epoch 1 trình cho wrap epoch 2",
           SECURITY, BLOCKED, "ThresholdCombiner - DLEQ context gắn epoch",
           ev)

    ev = expect(lambda: gateA.unwrap(OBJECT_A, w1, [], envA["pub_shares"], 3),
                StaleEpochError, "wrap retired")
    record("1. Replay", "wrap digest epoch 1 (đã retire) trình lại", SECURITY,
           BLOCKED, "EpochReplayGate.accept_wrap - retired digest", ev)

    assert not verify_dleq(proofs_old[0], envA["pub_shares"][1], w2.c1,
                           w2.proof_context())
    print("    (điều khiển: proof cũ verify dưới wrap mới = FALSE, "
          "CtDigest+C1 khác nhau)")
    results.append("S1 replay blocked: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 2: STALE ROOT - ROOT ĐÃ BỊ ROTATION THAY (186)")
    # =====================================================================
    ev = expect(lambda: svcA.oracle.resolve_fresh_policy(OBJECT_A,
                                                         w1.context.policy_root,
                                                         pdbA),
                StaleRootError, "root epoch 1")
    record("2. Stale root", "trình root epoch 1 (hợp lệ nhưng cũ)", SECURITY,
           BLOCKED, "Oracle - latest trusted root comparison", ev)

    ev = expect(lambda: safe_create_partial(envA["nodes"][1], w1, svcA, pdbA),
                StaleRootError, "node tạo partial cho wrap cũ")
    record("2. Stale root", "node bị ép mint partial cho wrap epoch 1",
           SECURITY, BLOCKED, "safe_create_partial - cổng nguồn", ev)

    pcs_new = [safe_create_partial(envA["nodes"][j], w2, svcA, pdbA)
               for j in (2, 3, 5)]
    assert gateA.unwrap(OBJECT_A, w2, pcs_new, envA["pub_shares"], 3) \
        == envA["dek"]
    print("    (điều khiển: root MỚI vẫn serve bình thường)")
    results.append("S2 stale root blocked: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 3: CLOCK SKEW - ĐỒNG HỒ LỆCH / ANCHOR HẾT HẠN (186)")
    # =====================================================================
    envB = build_env(OBJECT_B)
    logB, bridgeB, oracleB = envB["service_log"], envB["bridge"], envB["oracle"]
    pdbB = logB.policy_records
    anchor1B = bridgeB.anchor_chain[1]

    future = forge_anchor(anchor1B, bridgeB.bridge_sk,
                          timestamp=time.time() + 3600.0)
    ev = expect(lambda: oracleB.sync_latest_trusted_root(future),
                FailClosedFreshnessError, "anchor đến từ tương lai")
    record("3. Clock skew", "anchor timestamp +1đ (future)", SECURITY,
           BLOCKED, "Oracle bước 3.1 - max_clock_skew_seconds=5s", ev)

    oracle_fresh = KeyNodeTrustedRootOracle(
        bridgeB.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    ev = expect(lambda: oracle_fresh.sync_latest_trusted_root(
        anchor1B, current_time=anchor1B.timestamp + 3600.0),
        FailClosedFreshnessError, "anchor quá hạn")
    record("3. Clock skew", "anchor age 3600s > window 60s (mất sync lâu)",
           AVAILABILITY, FAIL_CLOSED, "Oracle bước 3.2 - stale window", ev)

    exp_cap, exp_sig = issue_capability(issuerA, SUBJ, OBJECT_A, "read",
                                        epoch=epoch2, ttl_seconds=-1.0)
    verA = CapabilityVerifier(issuerA.public_key())
    ev = expect(lambda: verA.verify_capability(exp_cap, exp_sig, SUBJ,
                                               OBJECT_A, "read", epoch2),
                CapSecurityError, "token hết hạn")
    record("3. Clock skew", "token hết hạn nhưng client clock sai", SECURITY,
           BLOCKED, "Expiry tính theo GIỜ SERVER (không tin client clock)", ev)
    results.append("S3 clock skew handled: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 4: NETWORK PARTITION - FAIL-CLOSED + HỒI PHỤC (186)")
    # =====================================================================
    oracle_isolated = KeyNodeTrustedRootOracle(
        bridgeB.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    ev = expect(oracle_isolated.get_latest_trusted_root,
                FailClosedFreshnessError, "node chưa sync - bị cô lập")
    record("4. Partition", "node mất link tới bridge (chưa có root)",
           AVAILABILITY, FAIL_CLOSED, "Oracle fail-closed (không root = "
           "không serve)", ev)
    ev = expect(lambda: oracle_isolated.resolve_fresh_policy(
        OBJECT_B, anchor1B.mmr_root, pdbB),
        FailClosedFreshnessError, "resolve khi cô lập")
    record("4. Partition", "yêu cầu unwrap trong lúc cô lập", AVAILABILITY,
           FAIL_CLOSED, "resolve_fresh_policy -> get_latest_trusted_root", ev)

    wrapB = envB["rewrap"].get_active_wrap(OBJECT_B)
    split_proofs = [prove_dleq(j, envB["shares"][j], envB["pub_shares"][j],
                               wrapB.c1, envB["shares"][j] * wrapB.c1,
                               wrapB.proof_context()) for j in (1, 2)]
    ev = expect(lambda: envB["combiner"].combine(split_proofs, wrapB),
                InsufficientPartials, "2 < t=3 partial")
    record("4. Partition", "chỉ t-1 partial về được (mất 1 node)", AVAILABILITY,
           FAIL_CLOSED, "Combiner fail-closed - không unwrap DEK", ev)

    root_healed = oracle_isolated.sync_latest_trusted_root(anchor1B)
    got = oracle_isolated.get_latest_trusted_root()
    policy = oracle_isolated.resolve_fresh_policy(OBJECT_B, got, pdbB)
    assert root_healed == got and policy["state"] == "ACTIVE"
    print(f"    -> [{AVAILABILITY} / {RECOVERED}] Link phục hồi -> sync root "
          f"OK, serve lại (policy ACTIVE)")
    REPORT.append(dict(scenario="4. Partition", attack="hồi phục sau "
                       "partition", klass=AVAILABILITY, verdict=RECOVERED,
                       detector="sync_latest_trusted_root (có root = serve)",
                       evidence=f"root {got[:16]}... phục vụ trở lại"))
    results.append("S4 partition fail-closed + recovered: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 5: INVALID PARTIAL - PROOF/SHARE SAI BỊ LOẠI (186)")
    # =====================================================================
    good = [prove_dleq(j, envB["shares"][j], envB["pub_shares"][j], wrapB.c1,
                       envB["shares"][j] * wrapB.c1, wrapB.proof_context())
            for j in (1, 2, 3)]
    combB = envB["combiner"]

    bad_z = [ChaumPedersenProof(good[0].party_id, good[0].d_point,
                                good[0].a_point, good[0].b_point,
                                good[0].challenge,
                                (good[0].response + 1) % N_ORDER),
             good[1], good[2]]
    assert not verify_dleq(bad_z[0], envB["pub_shares"][1], wrapB.c1,
                           wrapB.proof_context())
    ev = expect(lambda: combB.combine(bad_z, wrapB), InsufficientPartials,
                "tampered response")
    record("5. Invalid partial", "tamper response z của proof", SECURITY,
           DETECTED, "verify_dleq - Fiat-Shamir + Schnorr-pair", ev)

    wrong_d = [ChaumPedersenProof(good[0].party_id, good[2].d_point,
                                  good[0].a_point, good[0].b_point,
                                  good[0].challenge, good[0].response),
               good[1], good[2]]
    ev = expect(lambda: combB.combine(wrong_d, wrapB), InsufficientPartials,
                "d_point mượn của node khác")
    record("5. Invalid partial", "d_point không khớp share của party", SECURITY,
           DETECTED, "verify_dleq - phương trình z*C1", ev)

    ghost_share = 4242
    ghost = prove_dleq(99, ghost_share, ghost_share * G, wrapB.c1,
                       ghost_share * wrapB.c1, wrapB.proof_context())
    verdicts = combB.classify([ghost, good[1], good[2]], wrapB.c1,
                              wrapB.proof_context())
    reasons = [v.reason for v in verdicts]
    assert reasons[0] == "unknown-party"
    verdicts_dup = combB.classify([good[0], good[0], good[1]], wrapB.c1,
                                  wrapB.proof_context())
    assert [v.reason for v in verdicts_dup] == ["ok", "duplicate-party", "ok"]
    print(f"    -> [{SECURITY} / {DETECTED}] classify: party lạ -> "
          f"{reasons[0]}; trùng lặp -> duplicate-party")
    REPORT.append(dict(scenario="5. Invalid partial",
                       attack="party lạ + proof trùng", klass=SECURITY,
                       verdict=DETECTED,
                       detector="ThresholdCombiner.classify (unknown/dup)",
                       evidence=f"reasons={reasons}"))
    ev = expect(lambda: combB.combine([ghost, good[1], good[2]], wrapB),
                InsufficientPartials, "pool có party lạ")
    record("5. Invalid partial", "pool 1 ghost + 2 hợp lệ (< t)", SECURITY,
           DETECTED, "Combiner fail-closed", ev)

    compact = [safe_create_partial(envB["nodes"][j], wrapB, envB["rewrap"],
                                   pdbB) for j in (1, 2, 3)]
    tampered = [PartialWithProof(compact[0].party_id, compact[0].d_point,
                                 compact[0].proof_c,
                                 (compact[0].proof_z + 1) % N_ORDER),
                compact[1], compact[2]]
    assert not verify_partial(tampered[0], envB["pub_shares"][1], wrapB.c1,
                              wrapB.proof_context())
    ev = expect(lambda: combine_and_unwrap(tampered, envB["pub_shares"], 3,
                                           wrapB),
                UnderThresholdError, "compact proof tamper")
    record("5. Invalid partial", "tamper proof_z (đường compact)", SECURITY,
           DETECTED, "verify_partial + combine fail-closed", ev)
    results.append("S5 invalid partials detected: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 6: CORRUPTED CIPHERTEXT - PAYLOAD + WRAP BỊ SỬA (186)")
    # =====================================================================
    ct = bytearray(envB["payload_ct"])
    ct[20] ^= 0x01                       # sửa 1 bit trong phần ciphertext
    ev = expect(lambda: decrypt_payload(envB["dek"], bytes(ct), OBJECT_B, 1,
                                        envB["ph_ingest"], "JSON-GCM-v1"),
                InvalidTag, "payload 1-bit flip")
    record("6. Corrupted ct", "payload ciphertext 1-bit flip", SECURITY,
           DETECTED, "AES-GCM tag (payload_aad gắn object/version/ph)", ev)

    bad_wrap = ThresholdWrappedDEK(c1=wrapB.c1, nonce=wrapB.nonce,
                                   ciphertext=bytes(
                                       bytearray([wrapB.ciphertext[0] ^ 0x01])
                                       + bytearray(wrapB.ciphertext[1:])),
                                   context=wrapB.context)
    ev = expect(lambda: combB.combine(good, bad_wrap), InsufficientPartials,
                "wrap ciphertext sửa 1 byte")
    record("6. Corrupted ct", "wrapped-DEK ciphertext sửa 1 byte", SECURITY,
           DETECTED, "Combiner - AEAD tag sai khi unwrap", ev)

    assert not verify_dleq(good[0], envB["pub_shares"][1], bad_wrap.c1,
                           bad_wrap.proof_context())
    print(f"    -> [{SECURITY} / {DETECTED}] CtDigest binding: proof không "
          f"verify dưới context ciphertext đã sửa")
    REPORT.append(dict(scenario="6. Corrupted ct",
                       attack="proof trình cùng ciphertext đã sửa", klass=SECURITY,
                       verdict=DETECTED,
                       detector="proof_context = AAD + CtDigest(nonce||ct)",
                       evidence="verify_dleq = FALSE"))
    results.append("S6 corrupted ciphertext detected: PASS")

    # =====================================================================
    _banner("KỊCH BẢN 7: POLICY EQUIVOCATION - 2 ĐẦU CHÍNH SÁCH / SAI LOG (186)")
    # =====================================================================
    twin = forge_anchor(anchor1B, bridgeB.bridge_sk,
                        mmr_root=hashlib.sha256(b"evil-head").hexdigest())
    ev = expect(lambda: oracleB.sync_latest_trusted_root(twin),
                EquivocationError, "2 root cùng epoch 1")
    record("7. Equivocation", "bridge ký root KHÁC cho epoch 1 (cùng epoch)",
           SECURITY, BLOCKED, "Oracle bước 2 - seen_epoch_roots", ev)

    logB.transition_policy(OBJECT_B, "SUSPENDED")
    anchor2B = bridgeB.anchor_epoch(2, logB.mmr)
    proof_ok = bridgeB.get_consistency_proof(1, 2)
    ev = expect(lambda: oracleB.sync_latest_trusted_root(anchor2B, None),
                FailClosedFreshnessError, "thiếu consistency proof")
    record("7. Equivocation", "epoch 2 KHÔNG kèm consistency proof",
           SECURITY, BLOCKED, "Oracle bước 4 - thiếu proof -> fail-closed", ev)

    bad_proof = ConsistencyProof(
        from_epoch=proof_ok.from_epoch, to_epoch=proof_ok.to_epoch,
        from_size=proof_ok.from_size, to_size=proof_ok.to_size,
        from_root=hashlib.sha256(b"rewritten-history").hexdigest(),
        to_root=proof_ok.to_root, peak_proofs=proof_ok.peak_proofs)
    ev = expect(lambda: oracleB.sync_latest_trusted_root(anchor2B, bad_proof),
                OracleSecurityError, "consistency proof bị sửa")
    record("7. Equivocation", "viết lại lịch sử (sửa consistency proof)",
           SECURITY, BLOCKED, "Oracle bước 4 - proof invalid", ev)

    root_ok = oracleB.sync_latest_trusted_root(anchor2B, proof_ok)
    assert root_ok == anchor2B.mmr_root
    print(f"    (điều khiển: proof ĐÚNG -> epoch 2 accept, root "
          f"{root_ok[:16]}...)")

    evil_ph = hashlib.sha256(b"attacker-policy").hexdigest()
    evil_wrap = dc_replace(wrapB.context, policy_hash=evil_ph)
    prob = detect_policy_hash_mismatch(logB, OBJECT_B,
                                       ThresholdWrappedDEK(
                                           c1=wrapB.c1, nonce=wrapB.nonce,
                                           ciphertext=wrapB.ciphertext,
                                           context=evil_wrap))
    assert prob is not None
    record("7. Equivocation", "wrap dán policy_hash không có trong log",
           POLICY, DETECTED, "client so với event ký số (MMR)", prob)

    legit_prob = detect_policy_hash_mismatch(logB, OBJECT_B, wrapB)
    assert legit_prob is None
    print("    (điều khiển: wrap chính chủ -> policy_hash khớp event "
          "trong log)")

    logA = envA["service_log"]
    logA.transition_policy(OBJECT_A, "REVOKED")
    ev = expect(lambda: svcA.oracle.resolve_fresh_policy(
        OBJECT_A, w2.context.policy_root, pdbA),
        PermissionError, "policy REVOKED")
    record("7. Equivocation", "yêu cầu key khi policy đã REVOKED", POLICY,
           DETECTED, "Oracle terminal-state invariant (KHÔNG phải lỗ hổng "
           "bảo mật)", ev)
    results.append("S7 policy equivocation blocked: PASS")

    # =====================================================================
    _banner("BÁO CÁO TỔNG HỢP - PHÂN LOẠI LỖI (mục 192)")
    # =====================================================================
    _table(["kịch bản", "cuộc tấn công", "lớp", "kết luận", "cơ chế phát hiện"],
           [[r["scenario"], r["attack"][:34], r["klass"], r["verdict"],
             r["detector"][:38]] for r in REPORT])
    counts = {}
    for r in REPORT:
        counts[(r["klass"], r["verdict"])] = counts.get((r["klass"], r["verdict"]),
                                                        0) + 1
    print("\n  Tổng hợp:")
    for (klass, verdict), n in sorted(counts.items()):
        print(f"    - {klass:12s} {verdict:12s}: {n} trường hợp")

    # =====================================================================
    _banner("CLAIMS (193) + GIỚI HẠN / THREAT-TO-VALIDITY (199) + LƯU Ý (194)")
    # =====================================================================
    print(f"""
  CLAIMS - viết theo ĐIỀU KIỆN (193):
    NẾU adversary giữ được < t node trong ủy ban, client có latest root,
    và KHÔNG có DEK/plaintext leakage từ trước, THÌ:
      + mọi partial/proof epoch cũ không unwrap được DEK (S1, S5);
      + root cũ không được serve (S2) và 2 đầu root cùng epoch bị bắt (S7);
      + clock skew / mất sync đưa hệ thống về fail-closed thay vì serve sai
        (S3, S4);
      + payload/wrap sửa 1 bit đều bị AEAD tag bắt (S6).
  GIỚI HẠN (threat-to-validity - 199):
    - Network fault mô phỏng trong tiến trình (0), không dùng tc/Chaos (176);
      RTT/straggle thật cần testbed.
    - Freshness được kiểm tại SYNC; resolve chỉ so với root đã biết -> giả
      định attacker không chặn được mọi sync vĩnh viễn (cần giám sát ngoài).
    - Đồng hồ: expiry tin server clock; NTP/GPS không được mô phỏng.
    - Threshold: bộ test này chạy n=5, t=3; adversary >= t (lỗi người dùng
      chia sẻ đủ share) nằm NGOÀI threat model.
    - Crypto pure-Python, chưa audit - không dùng production.
  KHÔNG SUY DIỄN (194): các kết quả trên CHỈ là kết quả thí nghiệm trong
    threat model mô tả - KHÔNG phải bảo đảm tuân thủ pháp luật tự động,
    KHÔNG thay thế audit độc lập.
""")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for line in results:
        print(f"  {line}")
    print(f"  7/7 kịch bản: {len(REPORT)} trường hợp đo được, "
          f"0 trường hợp bị bỏ sót.")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print(f"  => Bundle = deliverable 'Security/performance experiment "
          f"bundle' (198): replay, stale root, clock skew, partition, "
          f"invalid partial, corrupted ct, equivocation.")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
