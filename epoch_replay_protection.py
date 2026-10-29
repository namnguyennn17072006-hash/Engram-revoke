#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GIAI ĐOẠN 4 - CÂU 4: ĐẢM BẢO CAPABILITY VÀ PARTIAL DECRYPTIONS EPOCH CŨ
                      KHÔNG REPLAY SANG EPOCH MỚI
File: epoch_replay_protection.py

GỢI Ý SỬ DỤNG (mục 168 - "Công việc phải thực hiện" GĐ4):
  168  Đảm bảo capability và partial decryptions epoch cũ không replay
       sang epoch mới.
  171  Payload ciphertext không đổi; chỉ wrapped DEK và policy metadata đổi.
  172  Transcript/phản chứng phải kiểm chứng được và không tiết lộ secret.
  173  Old epoch material = compromised-after-use trong stress test; claim
       phải trung thực (forward-security thực tế).
  174  Batch rewrap worker + policy event log + threshold harness (tái sử dụng).
  181  CỔNG NGHIỆM THU: "Old capability không hoạt động ở epoch mới".
  182  RỦI RO: old shares/old wraps phải được xử lý đúng assumption
       (không bao giờ "tái sử dụng ngầm").

TÁI SỬ DỤNG TOÀN BỘ code đã viết ở các câu trước:
  * GĐ1: CapabilityVerifier + epoch-binding + nonce-replay-cache (capabilityverifier).
  * GĐ2: StaleRootError + latest trusted root (freshnesswindowandlatesttrustedroot).
  * GĐ3: ThresholdWrappedDEK + proof_context (object|version|policy_hash|
         codec|epoch|policy_root|CtDigest), ThresholdWrapNode.create_partial,
         verify_partial / combine_and_unwrap, prove_dleq / verify_dleq,
         ThresholdCombiner.classify/combine (InsufficientPartials fail-closed).
  * GĐ4 câu 1: EpochRewrapService (rotate/prepare/commit/recover_forward,
         retired_digests, object_epoch), safe_create_partial, issue_capability,
         rewrap_via_committee, batch_rewrap_worker, encrypt/decrypt_payload,
         build_env.
  * GĐ4 câu 3: build_rewrap_committee_env (multi-object) cho batch test.

CODE MỚI CHỈ 2 PHẦN (lõi của câu 4):
  1) reissue_capability_for_epoch(): CÁCH DUY NHẤT hợp lệ để đưa một
     capability sang epoch mới = KÝ LẠI với nonce mới + expiry mới; sửa epoch
     trong token cũ -> hỏng chữ ký (SecurityError) ngay lớp 1.
  2) EpochReplayGate: cổng ingress DUY NHẤT cho client/verifier, gắn mọi
     quyết định phục vụ vào epoch HIỆN HÀNH của object:
       - capability: delegate CapabilityVerifier với current_policy_epoch;
       - partial: wrap phải là ACTIVE wrap của epoch hiện tại
         (không retired, không pending, không phải wrap epoch cũ);
     có audit trail + bộ đếm từ chối phục vụ báo cáo stress (GĐ5 sau).

CHỐNG REPLAY - BẤT BIẾN CỦA THIẾT KẾ:
  (I)   Capability: chữ ký Ed25519 phủ (subject, object_id, rights, epoch,
        expiry, nonce) => sửa bất kỳ trường nào (kể cả epoch) -> sig fail;
        epoch phải bằng current epoch của object; nonce dùng 1 lần.
  (II)  Partial: challenge Chaum-Pedersen = H(G, Y_j, C1, D_j, A, B,
        proof_context) với proof_context = AAD(epoch, root, object, ...)
        + CtDigest(nonce||ciphertext của WRAP) => partial epoch e ký theo
        C1_e KHÔNG THỂ verify dưới C1_{e+1} hay context e+1 (cả đại số lẫn
        Fiat-Shamir đều lệch).
  (III) Node (nguồn phát hành): safe_create_partial chỉ tạo partial khi
        policy_root còn là LATEST TRUSTED ROOT -> wrap epoch cũ bị chặn ở
        gốc, không sinh thêm "đạn" replay.
  (IV)  Gate (tiếp nhận): wrap phải là active wrap hiện tại -> partial cho
        wrap retired/pending bị từ chối kể cả khi proof "đẹp" theo đại số.
  (V)   Trung thực 173: DEK GIỮ NGUYÊN qua rewrap (171 - payload không
        re-encrypt) nên epoch là TẤT CẢ thứ tách old material; old cap/
        old wrap/partial = compromised-after-use, phải reissue + mint mới.

Yêu cầu: python3 + cryptography (Ed25519, AESGCM); pure-python secp256k1.
Chạy:     python3 epoch_replay_protection.py
Lưu ý:    prototype academic, CHƯA audit - không dùng production.
"""

import os
import time
import hashlib
from dataclasses import replace as dc_replace
from typing import Dict, List

from cryptography.hazmat.primitives.asymmetric import ed25519

# --- GĐ1: capability verifier -----------------------------------------------------
from capabilityverifier import CapabilityVerifier
from capabilityverifier import SecurityError as CapSecurityError

# --- GĐ2: freshness oracle (stale root) -------------------------------------------
from freshnesswindowandlatesttrustedroot import StaleRootError

# --- GĐ3 câu 1: EC + wrap DEK + partial --------------------------------------------
from dkg_threshold_service import ECPoint, G, UnderThresholdError
from wrap_dek_partial_decryption import (
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
    verify_partial,
    combine_and_unwrap,
)

# --- GĐ3 câu 4: DLEQ proof -----------------------------------------------------------
from chaum_pedersen_partial_proof import prove_dleq, verify_dleq

# --- GĐ3 câu 5: combiner -----------------------------------------------------------------
from combiner_filter_and_combine import ThresholdCombiner, InsufficientPartials

# --- GĐ4 câu 1: epoch transition + rewrap -----------------------------------------------
from epoch_transition_rewrap import (
    decrypt_payload,
    wrap_digest,
    EpochRewrapService,
    safe_create_partial,
    issue_capability,
    rewrap_via_committee,
    batch_rewrap_worker,
    build_env,
    N,
    T,
)

# --- GĐ4 câu 3: môi trường multi-object cho batch -----------------------------------------
from resharing_committee_change import build_rewrap_committee_env


# =============================================================================
# 1. REISSUE - CÁCH DUY NHẤT HỢP LỆ ĐỂ CAPABILITY SANGNG EPOCH MỚI (168)
# =============================================================================
def reissue_capability_for_epoch(
    issuer_sk: ed25519.Ed25519PrivateKey,
    old_cap: dict,
    new_epoch: int,
    ttl_seconds: float = 300.0,
):
    """
    Ký lại capability cho epoch MỚI với nonce + expiry MỚI.

    (168) "Old capability không hoạt động ở epoch mới" => token cũ CHẾT;
    client không có đường "sửa epoch trong token" (sửa -> Ed25519 fail).
    (173) Giữ nguyên subject/object/rights nhưng epoch, expiry, nonce là
    vật liệu MỚI - token cũ vẫn là compromised-after-use.
    """
    cap = {
        "subject": old_cap["subject"],
        "object_id": old_cap["object_id"],
        "rights": old_cap["rights"],
        "epoch": new_epoch,
        "expiry": time.time() + ttl_seconds,
        "nonce": os.urandom(8).hex(),          # nonce MỚI - không tái sử dụng
    }
    canonical = (f"{cap['subject']}:{cap['object_id']}:{cap['rights']}"
                 f":{cap['epoch']}:{cap['expiry']}:{cap['nonce']}").encode()
    return cap, issuer_sk.sign(canonical)


# =============================================================================
# 2. EPOCH REPLAY GATE - INGRESS DUY NHẤT CHO CAPABILITY + PARTIAL (168/181)
# =============================================================================
class StaleEpochError(Exception):
    """(168) Wrap/partial thuộc epoch cũ, retired hoặc chưa commit."""


class EpochReplayGate:
    """
    Cổng ingress client-side/verifier-side: MỌI quyết định phục vụ đều so với
    epoch HIỆN HÀNH của object trong EpochRewrapService (nguồn sự thật).

      check_capability()  : delegate CapabilityVerifier nhưng ép
                            current_policy_epoch = object_epoch hiện tại.
      accept_wrap()       : wrap trình ra PHẢI là ACTIVE wrap của epoch
                            hiện tại (không retired / không pending) - partial
                            chỉ được phục vụ KÈM wrap của nó.
      unwrap()            : đường compact (PartialWithProof) + accept_wrap.
      unwrap_proofs()     : đường Chaum-PedersenProof (ThresholdCombiner)
                            + accept_wrap.

    Bộ đếm `rejected` + `audit` phục vụ báo cáo stress GĐ5 (mục 186-187):
    bao nhiêu request epoch cũ bị chặn theo từng lý do.
    """

    def __init__(self, rewrap: EpochRewrapService, verifier: CapabilityVerifier):
        self.rewrap = rewrap
        self.verifier = verifier
        self.audit: List[str] = []
        self.rejected: Dict[str, int] = {
            "cap_epoch": 0, "cap_other": 0,
            "partial_retired": 0, "partial_epoch": 0,
            "partial_pending": 0, "partial_not_active": 0,
        }

    # ------------------------------------------------------------------
    def current_epoch(self, object_id: str) -> int:
        return self.rewrap.object_epoch[object_id]

    # ------------------------------------------------------------------
    def _reject(self, bucket: str, object_id: str, detail: str):
        self.rejected[bucket] += 1
        self.audit.append(f"REJECT[{bucket}] {object_id}: {detail}")
        raise StaleEpochError(f"[{bucket}] {object_id}: {detail}")

    # ------------------------------------------------------------------
    def check_capability(self, cap: dict, signature: bytes, subject: str,
                         object_id: str, right: str) -> bool:
        """
        (168) Kiểm capability với epoch HIỆN HÀNH - epoch cũ -> SecurityError
        (CapabilityVerifier lớp 4 - epoch binding) + ghi audit.
        """
        try:
            ok = self.verifier.verify_capability(
                cap, signature, subject, object_id, right,
                self.current_epoch(object_id))
        except CapSecurityError as err:
            bucket = "cap_epoch" if "Epoch" in str(err) else "cap_other"
            self.rejected[bucket] += 1
            self.audit.append(f"REJECT[{bucket}] {object_id}: {str(err)[:70]}")
            raise
        self.audit.append(f"ACCEPT[cap] {object_id}@e{cap['epoch']} "
                          f"subject={subject} right={right}")
        return ok

    # ------------------------------------------------------------------
    def accept_wrap(self, object_id: str, wrap: ThresholdWrappedDEK):
        """
        (168/181) Partial chỉ được phục vụ khi wrap = ACTIVE wrap của epoch
        hiện tại. 4 lớp từ chối: retired digest -> pending -> không phải
        active -> lệch epoch.
        """
        if wrap.context.object_id != object_id:
            self._reject("partial_not_active", object_id,
                         f"wrap thuộc object {wrap.context.object_id}")
        digest = wrap_digest(wrap)
        if digest in self.rewrap.retired_digests:
            self._reject("partial_retired", object_id,
                         f"wrap epoch {wrap.context.epoch} đã RETIRED")
        pending = self.rewrap.pending_wrap.get(object_id)
        if pending is not None and wrap_digest(pending) == digest:
            self._reject("partial_pending", object_id,
                         f"wrap epoch {wrap.context.epoch} đang PENDING "
                         "(chưa commit - fail-closed)")
        active = self.rewrap.active_wrap.get(object_id)
        if active is None or wrap_digest(active) != digest:
            self._reject("partial_not_active", object_id,
                         f"wrap epoch {wrap.context.epoch} không phải active")
        if wrap.context.epoch != self.current_epoch(object_id):
            self._reject("partial_epoch", object_id,
                         f"wrap epoch {wrap.context.epoch} != "
                         f"epoch hiện tại {self.current_epoch(object_id)}")
        self.audit.append(f"ACCEPT[wrap] {object_id}@e{wrap.context.epoch} "
                          f"digest={digest[:12]}")

    # ------------------------------------------------------------------
    def unwrap(self, object_id: str, wrap: ThresholdWrappedDEK, partials,
               public_shares: Dict[int, ECPoint], threshold: int) -> bytes:
        """
        Đường compact (câu 3 GĐ3).  Caller TRÌNH RA wrap mà partial đã ký theo
        => (168) wrap epoch cũ -> StaleEpochError ngay tại gate; wrap active
        nhưng partial ký theo wrap khác -> UnderThresholdError (fail-closed).
        """
        self.accept_wrap(object_id, wrap)
        return combine_and_unwrap(partials, public_shares, threshold, wrap)

    # ------------------------------------------------------------------
    def unwrap_proofs(self, object_id: str, wrap: ThresholdWrappedDEK, proofs,
                      public_shares: Dict[int, ECPoint],
                      threshold: int) -> bytes:
        """
        Đường Chaum-Pedersen (câu 4/5 GĐ3).  Cùng nguyên tắc: wrap trình ra
        phải là active wrap của epoch hiện tại trước khi combine.
        """
        self.accept_wrap(object_id, wrap)
        report = ThresholdCombiner(public_shares, threshold).combine(proofs, wrap)
        return report.dek


# =============================================================================
# 3. PIPELINE NHỎ - mint material + rotate/rewrap tái sử dụng câu 1
# =============================================================================
def issue_for(issuer_sk: ed25519.Ed25519PrivateKey, subject: str,
              object_id: str, right: str = "read", epoch: int = 1,
              ttl: float = 300.0):
    return issue_capability(issuer_sk, subject, object_id, right, epoch, ttl)


def mint_partials(nodes: Dict[int, ThresholdWrapNode],
                  wrapped: ThresholdWrappedDEK,
                  service: EpochRewrapService, policy_db: Dict[str, dict],
                  subset: List[int]):
    """Bộ partial compact (đường node - qua cổng root tươi)."""
    return [safe_create_partial(nodes[j], wrapped, service, policy_db)
            for j in subset]


def mint_proofs(env: dict, wrapped: ThresholdWrappedDEK, subset: List[int]):
    """Bộ Chaum-PedersenProof cho wrap (đường client-side)."""
    return [prove_dleq(j, env["shares"][j], env["pub_shares"][j], wrapped.c1,
                       env["shares"][j] * wrapped.c1, wrapped.proof_context())
            for j in subset]


def rotate_and_rewrap(env: dict, new_policy_seed: str):
    """
    Reuse GĐ4 câu 1: rotate policy epoch + rewrap DEK dưới context MỚI
    (DEK GIỮ NGUYÊN - 171).  Trả về (wrap_mới, dek, epoch_mới).
    """
    svc: EpochRewrapService = env["rewrap"]
    object_id = env["object_id"]
    new_ph = hashlib.sha256(new_policy_seed.encode()).hexdigest()
    new_wrap, dek = rewrap_via_committee(
        svc, object_id, env["nodes"], env["combiner"], [1, 2, 3],
        env["threshold_pk"], new_ph, env["service_log"].policy_records)
    return new_wrap, dek, svc.object_epoch[object_id]


# =============================================================================
# 4. BANNER
# =============================================================================
def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results: List[str] = []
    OBJECT = "OBJ-RP-1"
    SUBJ = "alice"

    # =====================================================================
    _banner("TEST 1: CAPABILITY ĐỒNG EPOCH - OLD TOKEN CHẾT Ở EPOCH MỚI (168/181)")
    # =====================================================================
    env = build_env(OBJECT)
    svc: EpochRewrapService = env["rewrap"]
    issuer_sk = ed25519.Ed25519PrivateKey.generate()
    gate = EpochReplayGate(svc, CapabilityVerifier(issuer_sk.public_key()))
    policy_db = env["service_log"].policy_records

    cap1, sig1 = issue_for(issuer_sk, SUBJ, OBJECT, "read", epoch=1)
    assert gate.check_capability(cap1, sig1, SUBJ, OBJECT, "read")
    print(f"  [1a] Epoch 1: capability hợp lệ (subject={SUBJ}, right=read)")

    w1 = svc.get_active_wrap(OBJECT)
    pcs1 = mint_partials(env["nodes"], w1, svc, policy_db, [1, 2, 3])
    assert gate.unwrap(OBJECT, w1, pcs1, env["pub_shares"], T) == env["dek"]
    assert decrypt_payload(env["dek"], env["payload_ct"], OBJECT, 1,
                           env["ph_ingest"], env["codec"]) == env["payload"]
    print(f"  [1b] Epoch 1: unwrap qua GATE (3 partial compact) -> DEK đúng, "
          f"payload giải mã nguyên vẹn (171)")

    w2, dek2, epoch2 = rotate_and_rewrap(env, "rp-epoch-2-policy")
    assert dek2 == env["dek"] and epoch2 == 2
    assert wrap_digest(w1) in svc.retired_digests
    print(f"  [1c] rotate+rewrap -> epoch 2, wrap epoch 1 RETIRED, "
          f"DEK KHÔNG đổi (171), payload_ct giữ nguyên từng byte")

    try:
        gate.check_capability(cap1, sig1, SUBJ, OBJECT, "read")
        raise AssertionError("capability epoch 1 phải chết ở epoch 2")
    except CapSecurityError as err:
        print(f"  [1d] CÙNG token epoch 1 trình ở epoch 2 -> "
              f"{str(err)[:66]}...")

    cap2, sig2 = reissue_capability_for_epoch(issuer_sk, cap1, new_epoch=2)
    assert gate.check_capability(cap2, sig2, SUBJ, OBJECT, "read")
    assert cap2["nonce"] != cap1["nonce"] and cap2["epoch"] == 2
    print(f"  [1e] reissue_capability_for_epoch (ký lại, nonce MỚI) -> "
          f"token epoch 2 hợp lệ => CỔNG NGHIỆM THU 181 đạt")
    results.append("TEST1 old capability dead at new epoch: PASS")

    # =====================================================================
    _banner("TEST 2: TỪ CHỐI SỬA CAPABILITY / REUSE NONCE / SAI BINDING (168)")
    # =====================================================================
    env2 = build_env("OBJ-RP-2")
    issuer2 = ed25519.Ed25519PrivateKey.generate()
    ver2 = CapabilityVerifier(issuer2.public_key())
    capA, sigA = issue_for(issuer2, SUBJ, "OBJ-RP-2", "read", epoch=1)
    assert ver2.verify_capability(capA, sigA, SUBJ, "OBJ-RP-2", "read", 1)
    print("  [2a] Token gốc xác minh 1 lần OK (nonce đã tiêu)")

    for label, mut in (
        ("sửa epoch 1->2 (không ký lại)", {"epoch": 2}),
        ("sửa expiry (kéo dài hiệu lực)",
         {"expiry": capA["expiry"] + 99999}),
        ("sửa rights read->admin", {"rights": "admin"}),
        ("sửa subject", {"subject": "mallory"}),
    ):
        bad = dict(capA)
        bad.update(mut)
        try:
            ver2.verify_capability(bad, sigA, SUBJ, "OBJ-RP-2", "read", 1)
            raise AssertionError(f"phải bắt: {label}")
        except CapSecurityError as err:
            print(f"  [2b] {label:38s} -> {str(err)[:58]}...")

    try:
        ver2.verify_capability(capA, sigA, SUBJ, "OBJ-RP-2", "read", 1)
        raise AssertionError("nonce replay phải bị bắt")
    except CapSecurityError as err:
        print(f"  [2c] replay CÙNG token cùng epoch (nonce cache) -> "
              f"{str(err)[:52]}...")

    for label, args, exc in (
        ("sai expected_object_id", ("bob", "OBJ-RP-2", "read", 1),
         PermissionError),
        ("sai expected_subject", (SUBJ, "OBJ-OTHER", "read", 1),
         PermissionError),
        ("thiếu right (request 'admin')", (SUBJ, "OBJ-RP-2", "admin", 1),
         PermissionError),
    ):
        try:
            ver2.verify_capability(capA, sigA, *args)
            raise AssertionError(f"phải bắt: {label}")
        except exc as err:
            print(f"  [2d] {label:38s} -> {str(err)[:58]}...")

    exp_cap, exp_sig = issue_for(issuer2, SUBJ, "OBJ-RP-2", "read", epoch=1,
                                 ttl=-1.0)
    try:
        ver2.verify_capability(exp_cap, exp_sig, SUBJ, "OBJ-RP-2", "read", 1)
        raise AssertionError("token hết hạn phải bị bắt")
    except CapSecurityError as err:
        print(f"  [2e] token hết hạn (expiry < now) -> {str(err)[:58]}...")
    results.append("TEST2 capability tamper/reuse/binding rejected: PASS")

    # =====================================================================
    _banner("TEST 3: PARTIAL EPOCH CŨ KHÔNG REPLAY QUA EPOCH MỚI (168/172)")
    # =====================================================================
    env3 = build_env("OBJ-RP-3")
    svc3: EpochRewrapService = env3["rewrap"]
    gate3 = EpochReplayGate(svc3, CapabilityVerifier(issuer_sk.public_key()))
    pdb3 = env3["service_log"].policy_records
    OBJECT3 = "OBJ-RP-3"

    w3a = svc3.get_active_wrap(OBJECT3)
    pcs_old = mint_partials(env3["nodes"], w3a, svc3, pdb3, [1, 2, 3])
    proofs_old = mint_proofs(env3, w3a, [1, 2, 3])

    w3b, dek3, epoch3 = rotate_and_rewrap(env3, "rp3-epoch-2")
    assert dek3 == env3["dek"]
    print(f"  [3a] Bộ partial epoch 1 thu được TRƯỚC rotation "
          f"({len(pcs_old)} compact + {len(proofs_old)} DLEQ proof)")

    try:
        gate3.unwrap(OBJECT3, w3a, pcs_old, env3["pub_shares"], T)
        raise AssertionError("partial epoch cũ phải bị gate từ chối")
    except StaleEpochError as err:
        print(f"  [3b] GATE compact path: partial epoch 1 vs wrap epoch "
              f"{epoch3} -> {str(err)[:60]}...")
    try:
        gate3.unwrap_proofs(OBJECT3, w3a, proofs_old, env3["pub_shares"], T)
        raise AssertionError("proof epoch cũ phải bị gate từ chối")
    except StaleEpochError as err:
        print(f"  [3c] GATE DLEQ path: proof epoch 1 -> {str(err)[:60]}...")

    try:
        combine_and_unwrap(pcs_old, env3["pub_shares"], T, w3b)
        raise AssertionError("combiner compact phải fail-closed")
    except UnderThresholdError as err:
        print(f"  [3d] KHÔNG qua gate - combine_and_unwrap(partial epoch 1, "
              f"wrap epoch 2) -> {str(err)[:58]}...")

    try:
        env3["combiner"].combine(proofs_old, w3b)
        raise AssertionError("ThresholdCombiner phải fail-closed")
    except InsufficientPartials as err:
        assert all(r == "dleq-invalid" for _, r in err.report.rejected)
        print(f"  [3e] KHÔNG qua gate - ThresholdCombiner.combine: 3/3 "
              f"'dleq-invalid' -> {str(err)[:50]}...")

    assert not verify_dleq(proofs_old[0], env3["pub_shares"][1], w3b.c1,
                           w3b.proof_context())
    assert not verify_partial(pcs_old[0], env3["pub_shares"][1], w3b.c1,
                              w3b.proof_context())
    print("  [3f] ĐẠI SỐ: DLEQ/compact verify của node 1 epoch 1 = FALSE dưới "
          "C1/context epoch 2 (challenge gắn object|epoch|root|CtDigest)")

    try:
        safe_create_partial(env3["nodes"][1], w3a, svc3, pdb3)
        raise AssertionError("node phải từ chối wrap epoch cũ (stale root)")
    except StaleRootError as err:
        print(f"  [3g] CỔNG NGUỒN: safe_create_partial(wrap epoch 1) -> "
              f"StaleRootError (root đã bị rotation thay)")

    pcs_new = mint_partials(env3["nodes"], w3b, svc3, pdb3, [2, 3, 5])
    assert gate3.unwrap(OBJECT3, w3b, pcs_new, env3["pub_shares"], T) == env3["dek"]
    assert decrypt_payload(env3["dek"], env3["payload_ct"], OBJECT3, 1,
                           env3["ph_ingest"], env3["codec"]) == env3["payload"]
    print(f"  [3h] Partial MỚI epoch 2 qua gate -> DEK đúng; payload ciphertext "
          f"GIỮ NGUYÊN từ trước rotation (171)")
    results.append("TEST3 old partials cannot replay to new epoch: PASS")

    # =====================================================================
    _banner("TEST 4: MIXED POOL + CROSS-OBJECT + FORGED CONTEXT (168/172)")
    # =====================================================================
    envA = build_env("OBJ-RP-4A")
    envB = build_env("OBJ-RP-4B")
    svcA: EpochRewrapService = envA["rewrap"]
    OBJECTA = "OBJ-RP-4A"
    wA_old = svcA.get_active_wrap(OBJECTA)
    wA_new, _, epochA = rotate_and_rewrap(envA, "rp4a-epoch-2")

    old1 = mint_proofs(envA, wA_old, [1])[0]
    old2 = mint_proofs(envA, wA_old, [2])[0]
    new3 = mint_proofs(envA, wA_new, [3])[0]
    new5 = mint_proofs(envA, wA_new, [5])[0]
    ghost_share = 12345
    ghost9 = prove_dleq(9, ghost_share, ghost_share * G, wA_new.c1,
                        ghost_share * wA_new.c1, wA_new.proof_context())
    dup3 = new3

    pool = [old1, old2, new3, new5, ghost9, dup3]
    verdicts = envA["combiner"].classify(pool, wA_new.c1, wA_new.proof_context())
    print("  [4a] Pool trộn (2 proof epoch 1 + 2 epoch 2 + party lạ 9 + "
          "duplicate) - bảng verdict combiner:")
    for v in verdicts:
        print(f"        party {v.party_id}: "
              f"{'ACCEPT' if v.accepted else 'REJECT':6s} ({v.reason})")
    assert [v.reason for v in verdicts if v.accepted] == ["ok", "ok"]
    try:
        envA["combiner"].combine(pool, wA_new)
        raise AssertionError("2/3 partial hợp lệ phải fail-closed")
    except InsufficientPartials as err:
        print(f"  [4b] combine(pool) -> 2 accepted < t=3: {str(err)[:62]}...")

    wB = envB["rewrap"].get_active_wrap("OBJ-RP-4B")
    assert not verify_dleq(new3, envA["pub_shares"][3], wB.c1,
                           wB.proof_context())
    print("  [4c] CROSS-OBJECT: proof object A (epoch 2) verify dưới wrap "
          "object B -> FALSE (object_id + CtDigest khác)")

    forged_ctx = dc_replace(wA_old.context, epoch=epochA,
                            policy_hash=hashlib.sha256(b"forged").hexdigest(),
                            policy_root=svcA.oracle.get_latest_trusted_root())
    forged_wrap = ThresholdWrappedDEK(c1=wA_old.c1, nonce=wA_old.nonce,
                                      ciphertext=wA_old.ciphertext,
                                      context=forged_ctx)
    assert not verify_dleq(old1, envA["pub_shares"][1], forged_wrap.c1,
                           forged_wrap.proof_context())
    gateA = EpochReplayGate(svcA, CapabilityVerifier(issuer_sk.public_key()))
    try:
        gateA.accept_wrap(OBJECTA, forged_wrap)
        raise AssertionError("wrap 'epoch 2 dán nhãn' nhưng digest khác active"
                             " phải bị gate từ chối")
    except StaleEpochError as err:
        print(f"  [4d] FORGED CONTEXT: gắn epoch 2 + root mới vào c1 cũ -> "
              f"verify FALSE + gate: {str(err)[:46]}...")
    print("  [4e] Không có đường 'dán nhãn epoch': challenge phủ c1/context "
          "thực tế, gate so digest với ACTIVE wrap")
    results.append("TEST4 mixed pool/cross-object/forged context: PASS")

    # =====================================================================
    _banner("TEST 5: REWRAP ĐỨNG GIỮA (PENDING) - FAIL-CLOSED + RECOVERY (181)")
    # =====================================================================
    env5 = build_env("OBJ-RP-5")
    svc5: EpochRewrapService = env5["rewrap"]
    OBJECT5 = "OBJ-RP-5"
    issuer5 = ed25519.Ed25519PrivateKey.generate()
    gate5 = EpochReplayGate(svc5, CapabilityVerifier(issuer5.public_key()))
    pdb5 = env5["service_log"].policy_records

    cap5, sig5 = issue_for(issuer5, SUBJ, OBJECT5, "read", epoch=1)
    w5a = svc5.get_active_wrap(OBJECT5)
    pcs5_old = mint_partials(env5["nodes"], w5a, svc5, pdb5, [1, 2, 3])

    new_ph5 = hashlib.sha256(b"rp5-epoch-2").hexdigest()
    epoch5, root5 = svc5.rotate_policy_epoch(OBJECT5)
    w5b = wrap_dek(env5["dek"], env5["threshold_pk"],
                   dc_replace(w5a.context, policy_hash=new_ph5, epoch=epoch5,
                              policy_root=root5))
    svc5.prepare_rewrap(OBJECT5, w5b)          # KHÔNG commit - đứng giữa
    print(f"  [5a] prepare_rewrap xong CHƯA commit: active wrap epoch "
          f"{svc5.active_wrap[OBJECT5].context.epoch}, object_epoch="
          f"{svc5.object_epoch[OBJECT5]}, pending epoch={w5b.context.epoch}")

    try:
        gate5.check_capability(cap5, sig5, SUBJ, OBJECT5, "read")
        raise AssertionError("capability epoch 1 phải chết ngay khi rotate")
    except CapSecurityError as err:
        print(f"  [5b] Token epoch 1 (kể cả khi rewrap PENDING) -> "
              f"{str(err)[:56]}...")

    try:
        gate5.unwrap(OBJECT5, w5a, pcs5_old, env5["pub_shares"], T)
        raise AssertionError("wrap epoch cũ không được phục vụ")
    except StaleEpochError as err:
        print(f"  [5c] Wrap dán epoch {w5a.context.epoch} nhưng object "
              f"epoch={epoch5} -> gate: {str(err)[:48]}...")

    _ = safe_create_partial(env5["nodes"][2], w5b, svc5, pdb5)
    try:
        gate5.accept_wrap(OBJECT5, w5b)
        raise AssertionError("wrap PENDING chưa commit phải bị từ chối")
    except StaleEpochError as err:
        print(f"  [5d] Node CÓ THỂ mint partial cho wrap pending (root đã "
              f"trusted) nhưng GATE từ chối: {str(err)[:48]}...")

    try:
        safe_create_partial(env5["nodes"][1], w5a, svc5, pdb5)
        raise AssertionError("node phải chặn wrap epoch cũ")
    except StaleRootError:
        print("  [5e] Node từ chối wrap epoch 1 (stale root) - cả 2 hướng "
              "đều fail-closed: không partial cũ, không partial pending")

    svc5.recover_forward(OBJECT5)
    assert wrap_digest(svc5.active_wrap[OBJECT5]) == wrap_digest(w5b)
    assert wrap_digest(w5a) in svc5.retired_digests
    pcs5_new = mint_partials(env5["nodes"], w5b, svc5, pdb5, [2, 3, 4])
    assert gate5.unwrap(OBJECT5, w5b, pcs5_new, env5["pub_shares"], T) == env5["dek"]
    cap5b, sig5b = reissue_capability_for_epoch(issuer5, cap5, epoch5)
    assert gate5.check_capability(cap5b, sig5b, SUBJ, OBJECT5, "read")
    assert decrypt_payload(env5["dek"], env5["payload_ct"], OBJECT5, 1,
                           env5["ph_ingest"], env5["codec"]) == env5["payload"]
    print(f"  [5f] recover_forward -> epoch {epoch5} active; partial MỚI + "
          f"reissued capability unwrap DEK; payload nguyên (171) - "
          f"KHÔNG trạng thái mơ hồ (181)")
    results.append("TEST5 pending rewrap fail-closed both sides: PASS")

    # =====================================================================
    _banner("TEST 6: BATCH REWRAP 3 OBJECT - OLD MATERIAL CHẾT TOÀN BỘ (173/174)")
    # =====================================================================
    envb = build_rewrap_committee_env(object_prefix="OBJ-RPB", n_objects=3,
                                      payload_size=128)
    svcb: EpochRewrapService = envb["rewrap"]
    objs = envb["objects"]
    issuer_b = ed25519.Ed25519PrivateKey.generate()
    gate_b = EpochReplayGate(svcb, CapabilityVerifier(issuer_b.public_key()))
    pdb_b = envb["log"].policy_records
    subset_old = [1, 2, 3]

    stash = []
    for o in objs:
        oid = o["object_id"]
        cap, sig = issue_for(issuer_b, SUBJ, oid, "read", epoch=1)
        assert gate_b.check_capability(cap, sig, SUBJ, oid, "read")
        wrap = svcb.get_active_wrap(oid)
        pcs = mint_partials(envb["old_nodes"], wrap, svcb, pdb_b, subset_old)
        proofs = mint_proofs(envb, wrap, subset_old)
        stash.append(dict(oid=oid, cap=cap, sig=sig, wrap=wrap, pcs=pcs,
                          proofs=proofs, meta=o))
    print(f"  [6a] Epoch 1: {len(objs)} object - mỗi object 1 capability + "
          f"3 partial compact + 3 DLEQ proof đều hợp lệ")

    batch = [dict(object_id=item["oid"], dek=envb["dek"], wrap=item["wrap"],
                  new_policy_hash=hashlib.sha256(
                      f"rp-batch-{item['oid']}".encode()).hexdigest(),
                  threshold_pk=envb["threshold_pk"]) for item in stash]
    t_batch = time.time()
    stats = batch_rewrap_worker(svcb, batch, pdb_b)
    batch_ms = (time.time() - t_batch) * 1000
    print(f"  [6b] batch_rewrap_worker: {stats['count']} object | "
          f"median {stats['median_ms']:.1f} ms | p95 {stats['p95_ms']:.1f} ms | "
          f"{stats['throughput_obj_per_s']:.1f} obj/s (mục 174/169)")

    ok_rows = []
    t_sweep = time.time()
    for item in stash:
        oid, meta = item["oid"], item["meta"]
        active = svcb.get_active_wrap(oid)
        assert active.context.epoch >= 2
        assert wrap_digest(item["wrap"]) in svcb.retired_digests

        cap_dead = False
        try:
            gate_b.check_capability(item["cap"], item["sig"], SUBJ, oid, "read")
        except CapSecurityError:
            cap_dead = True
        old_wrap_dead = False
        try:
            gate_b.unwrap(oid, item["wrap"], item["pcs"], envb["pub_shares"], T)
        except StaleEpochError:
            old_wrap_dead = True
        old_proof_dead = False
        try:
            envb["old_combiner"].combine(item["proofs"], active)
        except InsufficientPartials:
            old_proof_dead = True
        assert cap_dead and old_wrap_dead and old_proof_dead

        proofs_new = [prove_dleq(j, envb["shares"][j], envb["pub_shares"][j],
                                 active.c1, envb["shares"][j] * active.c1,
                                 active.proof_context())
                      for j in (2, 3, 5)]
        assert gate_b.unwrap_proofs(oid, active, proofs_new,
                                    envb["pub_shares"], T) == envb["dek"]
        cap_new, sig_new = issue_for(issuer_b, SUBJ, oid, "read",
                                     epoch=active.context.epoch)
        assert gate_b.check_capability(cap_new, sig_new, SUBJ, oid, "read")
        assert decrypt_payload(envb["dek"], meta["payload_ct"], oid, 1,
                               meta["ph_ingest"], active.context.codec_id) \
            == meta["payload"]
        ok_rows.append((oid, active.context.epoch))
    sweep_ms = (time.time() - t_sweep) * 1000

    print("  [6c] SAU batch - từng object (cap/wrap/proof cũ đều chết; "
          "cap + proof MỚI unwrap được, payload nguyên):")
    for oid, ep in ok_rows:
        print(f"        {oid}: epoch {ep} - cap_old=REJECT wrap_old=REJECT "
              f"proof_old=REJECT new=OK")
    print(f"  [6d] Gate audit: {gate_b.rejected} | batch {batch_ms:.0f} ms + "
          f"sweep {sweep_ms:.0f} ms cho {len(objs)} object")
    assert sum(gate_b.rejected.values()) >= 2 * len(objs)
    results.append("TEST6 batch rewrap, old material dead everywhere: PASS")

    # =====================================================================
    _banner("BENCHMARK ĐƯỜNG TỪ CHỐI/CHẤP NHẬN REPLAY (mục 169)")
    # =====================================================================
    envm = build_env("OBJ-RP-BM")
    svcm: EpochRewrapService = envm["rewrap"]
    OBJECTM = "OBJ-RP-BM"
    issuer_m = ed25519.Ed25519PrivateKey.generate()
    ver_m = CapabilityVerifier(issuer_m.public_key())
    gate_m = EpochReplayGate(svcm, ver_m)
    pdb_m = envm["service_log"].policy_records

    cap_stale, sig_stale = issue_for(issuer_m, SUBJ, OBJECTM, "read", epoch=1)
    wM_old = svcm.get_active_wrap(OBJECTM)
    proofsM_old = mint_proofs(envm, wM_old, [1, 2, 3])
    wM_new, _, epM = rotate_and_rewrap(envm, "rp-bm-epoch-2")
    proofsM_new = mint_proofs(envm, wM_new, [2, 3, 5])
    caps_new = [issue_for(issuer_m, SUBJ, OBJECTM, "read", epoch=epM)
                for _ in range(20)]

    K = 20

    def bench(fn, k=K):
        t0 = time.time()
        for _ in range(k):
            fn()
        return (time.time() - t0) * 1000 / k

    cap_iter = iter(caps_new)

    def cap_ok_once():
        c, s = next(cap_iter)
        ver_m.verify_capability(c, s, SUBJ, OBJECTM, "read", epM)

    def cap_stale_once():
        try:
            ver_m.verify_capability(cap_stale, sig_stale, SUBJ, OBJECTM,
                                    "read", epM)
        except CapSecurityError:
            return
        raise AssertionError("cap epoch cũ phải bị chặn")

    def gate_old_once():
        try:
            gate_m.unwrap_proofs(OBJECTM, wM_old, proofsM_old,
                                 envm["pub_shares"], T)
        except (StaleEpochError, InsufficientPartials):
            return
        raise AssertionError("bộ proof epoch cũ phải bị chặn")

    ms_cap_ok = bench(cap_ok_once)
    ms_cap_stale = bench(cap_stale_once)
    ms_proof_ok = bench(lambda: verify_dleq(
        proofsM_old[0], envm["pub_shares"][1], wM_old.c1,
        wM_old.proof_context()))
    ms_proof_bad = bench(lambda: None if not verify_dleq(
        proofsM_old[0], envm["pub_shares"][1], wM_new.c1,
        wM_new.proof_context()) else (_ for _ in ()).throw(
            AssertionError("proof epoch cũ phải FAIL dưới wrap mới")))
    ms_gate_ok = bench(lambda: gate_m.unwrap_proofs(
        OBJECTM, wM_new, proofsM_new, envm["pub_shares"], T), k=5)
    ms_gate_bad = bench(gate_old_once)

    print(f"  - verify_capability ACCEPT (đúng epoch, nonce mới):  "
          f"{ms_cap_ok:.2f} ms/call")
    print(f"  - verify_capability REJECT (epoch cũ - lớp 4):       "
          f"{ms_cap_stale:.2f} ms/call  <- chặn TRƯỚC khi tiêu nonce")
    print(f"  - verify_dleq ACCEPT (đúng wrap/epoch):               "
          f"{ms_proof_ok:.2f} ms/proof")
    print(f"  - verify_dleq REJECT (proof e1 vs wrap e{epM}):         "
          f"{ms_proof_bad:.2f} ms/proof")
    print(f"  - gate unwrap PROOF epoch mới (t=3, qua combiner):    "
          f"{ms_gate_ok:.1f} ms/unwrap")
    print(f"  - gate REJECT bộ proof epoch cũ (1 lời gọi):          "
          f"{ms_gate_bad:.2f} ms/req")
    print(f"  - batch rewrap {stats['count']} object: median "
          f"{stats['median_ms']:.1f} ms | p95 {stats['p95_ms']:.1f} ms | "
          f"{stats['throughput_obj_per_s']:.1f} obj/s (174)")
    print(f"  - Bối cảnh: n={N}, t={T}, objects={len(objs)}, secp256k1 "
          f"pure-Python (mục 169: đo theo n, t, object count)")
    print("  - Lưu ý trung thực (173): chi phí chống replay PHỤ THUỘC epoch "
          "(context/AAD + root), KHÔNG phụ thuộc số payload; rewrap chỉ đổi "
          "wrapped DEK + metadata.")

    # =====================================================================
    _banner("REPLAY PROTECTION PLAYBOOK (gợi ý 179 - recovery guide)")
    # =====================================================================
    print("""
| Tình huống (168/181/182)              | Cổng chặn                     |
+---------------------------------------+-------------------------------+
| Capability epoch cũ tới verifier      | CapabilityVerifier: epoch     |
|                                       | binding (lớp 4) + EpochGate   |
| Sửa epoch/rights/expiry trong token   | Ed25519 phủ toàn bộ canonical |
|                                       | form -> SecurityError (sig)   |
| Dùng lại nonce cùng epoch             | Replay cache (used_nonces)    |
| Partial epoch cũ + wrap epoch mới     | DLEQ challenge gắn            |
|                                       | proof_context (AAD+CtDigest)  |
| Partial cho wrap retired / pending    | EpochReplayGate.accept_wrap   |
| Node bị ép mint partial cho wrap cũ   | safe_create_partial + stale   |
|                                       | root (oracle GĐ2)             |
| Wrap "dán nhãn epoch mới" nhưng c1 cũ | digest != active -> gate;     |
|                                       | verify_dleq vẫn FALSE         |
| Đứng giữa rewrap (PENDING)            | fail-closed CẢ 2 hướng +      |
|                                       | recover_forward (181)         |
| Sau rewrap                            | old material = compromised-   |
|                                       | after-use: reissue cap + mint |
|                                       | partial mới (173)             |
+---------------------------------------+-------------------------------+
""")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for line in results:
        print(f"  {line}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("""
  => Capability: chữ ký Ed25519 phủ epoch + nonce 1 lần => old token CHẾT
     ở epoch mới (cổng nghiệm thu 181); mở rộng epoch = KÝ LẠI (reissue).
  => Partial: challenge DLEQ gắn proof_context = object|epoch|policy_root|
     CtDigest(wrap) => partial epoch e không verify dưới epoch e+1, kể cả
     trộn pool, cross-object hay "dán nhãn" context (172).
  => Nguồn (node) chặn wrap cũ bằng stale-root; ingress (gate) chặn wrap
     retired/pending/lech epoch -> fail-closed cả 2 hướng, không mơ hồ.
  => DEK giữ nguyên qua rewrap, payload KHÔNG re-encrypt (171) => epoch là
     TẤT CẢ; old material = compromised-after-use (173) - claim trung thực.
  LƯU Ý: prototype academic, chưa audit - không dùng production.
""")
