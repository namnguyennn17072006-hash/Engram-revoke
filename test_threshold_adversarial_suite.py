"""
================================================================================
GIAI ĐOẠN 3 - THRESHOLD KEY SERVICE
Lời giải câu 6: "Chạy compromised-node, invalid-share, offline-node và
                   DKG-abort tests."

Gợi ý áp dụng (từ 03_Huong_dan_nghien_cuu):
- (146) ĐÚNG 4 nhóm test được nêu tên -> 4 lớp unittest + 1 lớp tích hợp:
       invalid-share | DKG-abort | offline-node | compromised-node.
- (155) Cổng nghiệm thu: "Dưới t shares không unwrap được DEK; Partial
       decryption sai bị phát hiện; Ít nhất t node hợp lệ vẫn phục vụ khi
       các node khác offline" -> asserts trực tiếp trong nhóm offline/compromised.
- (159) Rủi ro "DKG không terminate dưới partition" -> DKGAbortError khi
       QUAL < t (fail-safe, không bao giờ ra key lệch) + từ chối khởi tạo
       khi số participant < t.
- (234) Invariant: "Dưới t key shares không khôi phục/unwrap DEK".
- (235) Invariant: "Partial decryption sai không được combiner chấp nhận".
- (150) Partial/proof bind object/ciphertext/epoch/policy root -> nhóm
       compromised-node thêm test cross-wrap replay bị loại toàn bộ.

Kiểu trình bày: unittest như test_adversarial_suite.py (GĐ2) - mỗi test 1 docstring
kỳ vọng rõ ràng, chạy được độc lập:

  python3 test_threshold_adversarial_suite.py -v

Tái sử dụng code đã viết (câu 1-5 + GĐ1/2):
  câu 1: run_pedersen_dkg, DKGAbortError, UnderThresholdError, N_ORDER, G
  câu 2: FeldmanVSS, PedersenVSS, VSSMember, sign_broadcast, committee_keygen
  câu 3: WrapContext, wrap_dek, ThresholdWrapNode, combine_and_unwrap
  câu 4: ChaumPedersenProof, prove_dleq, verify_dleq, to_compact, _challenge
  câu 5: ThresholdCombiner, InsufficientPartials
  GĐ1/2: PolicyLogService, EngramAnchorBridge, KeyNodeTrustedRootOracle
================================================================================
"""

import os
import time
import unittest
import hashlib
import random
from dataclasses import replace as dc_replace

from cryptography.hazmat.primitives.asymmetric import ed25519

# --- Câu 1: DKG + lỗi fail-safe ----------------------------------------------
from dkg_threshold_service import (
    run_pedersen_dkg,
    DKGAbortError,
    UnderThresholdError,
    N_ORDER,
    G,
)

# --- Câu 4: proof Chaum-Pedersen (material cho compromised-node tests) --------
from chaum_pedersen_partial_proof import (
    ChaumPedersenProof,
    prove_dleq,
    verify_dleq,
    to_compact,
    _challenge,
)

# --- Câu 3: wrap + node gate + combine đối chiếu ------------------------------
from wrap_dek_partial_decryption import (
    WrapContext,
    wrap_dek,
    ThresholdWrapNode,
    combine_and_unwrap,
)

# --- Câu 5: combiner có báo cáo verdict ---------------------------------------
from combiner_filter_and_combine import ThresholdCombiner, InsufficientPartials

# --- Câu 2: VSS (invalid-share tests) -----------------------------------------
from vss_share_verification import (
    FeldmanVSS,
    PedersenVSS,
    VSSMember,
    sign_broadcast,
    committee_keygen,
)

# --- GĐ1 & GĐ2 ----------------------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
)

N, T = 5, 3                          # t=3/n=5 từ threat model (chịu 2 node chết)
_RNG = random.SystemRandom()


# =============================================================================
# PIPELINE DÙNG CHUNG (xây 1 lần, mọi lớp test tái sử dụng - tiết kiệm thời gian)
# =============================================================================
_PIPELINE_CACHE = {}


def pipeline() -> dict:
    """
    Pipeline đầy đủ: GĐ1 policy log + GĐ2 anchor/oracle -> context thật;
    câu 2 VSS phân phối + xác minh share; câu 1 Pedersen DKG -> shares/Y;
    câu 3 wrap DEK; câu 4 mọi node tạo full proof; câu 5 combiner.
    """
    if _PIPELINE_CACHE:
        return _PIPELINE_CACHE

    # GĐ1 + GĐ2 -> trusted root thật
    service = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
    event, _, _ = service.init_policy("OBJ-7001", initial_epoch=1)
    policy_hash = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    bridge.anchor_epoch(1, service.mmr)
    oracle = KeyNodeTrustedRootOracle(
        bridge.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    trusted_root = oracle.get_latest_trusted_root()

    # Câu 2: Feldman VSS - mỗi member xác minh toàn bộ share nhận được
    vss_ctx = f"adv-suite|epoch=1|root={trusted_root}"
    dealer_sks, dealer_pks = committee_keygen(N)
    feldman = {i: FeldmanVSS(i, T, rng=random.Random(7000 + i))
               for i in range(1, N + 1)}
    members = {j: VSSMember(j, vss_ctx, dealer_pks) for j in range(1, N + 1)}
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            sig = sign_broadcast(dealer_sks[i], vss_ctx, i, feldman[i].commitments)
            members[j].check_feldman_share(i, feldman[i].share_for(j),
                                           feldman[i].commitments, sig)
    assert all(m.report.all_ok for m in members.values())

    # Câu 1: Pedersen DKG (không trusted dealer)
    dkg, _ = run_pedersen_dkg(list(range(1, N + 1)), T)
    shares, pub_shares = dkg.private_shares, dkg.public_key_shares

    # Câu 3: wrap DEK dưới Y + mọi node tạo full proof (câu 4) + combiner (câu 5)
    wrap_ctx = WrapContext(object_id="OBJ-7001", version=1, policy_hash=policy_hash,
                           codec_id="JSON-GCM-v1", epoch=1, policy_root=trusted_root)
    dek = os.urandom(32)
    wrapped = wrap_dek(dek, dkg.joint_public_key, wrap_ctx)
    proof_ctx = wrapped.proof_context()
    proofs = {j: prove_dleq(j, shares[j], pub_shares[j], wrapped.c1,
                            shares[j] * wrapped.c1, proof_ctx)
              for j in dkg.qualified_parties}

    _PIPELINE_CACHE.update(
        service=service, oracle=oracle, trusted_root=trusted_root,
        vss_ctx=vss_ctx, dealer_sks=dealer_sks, dealer_pks=dealer_pks,
        feldman=feldman, members=members, dkg=dkg, shares=shares,
        pub_shares=pub_shares, wrap_ctx=wrap_ctx, dek=dek, wrapped=wrapped,
        proof_ctx=proof_ctx, proofs=proofs,
        combiner=ThresholdCombiner(pub_shares, T))
    return _PIPELINE_CACHE


def forge_wrong_witness(p: dict, party_id: int, delta: int = 1) -> ChaumPedersenProof:
    """
    Compromised-node: chứng minh với x' = x_j + delta (share đã bị sửa/thay).
    Kẻ tấn công biết Y_j (công khai) nhưng KHÔNG biết log_G(Y_j) -> proof phải fail.
    """
    c1, ctx = p["wrapped"].c1, p["proof_ctx"]
    x_wrong = (p["shares"][party_id] + delta) % N_ORDER
    d_wrong = x_wrong * c1
    u = _RNG.randrange(1, N_ORDER)
    a_point, b_point = u * G, u * c1
    c = _challenge(p["pub_shares"][party_id], c1, d_wrong, a_point, b_point, ctx)
    z = (u + c * x_wrong) % N_ORDER
    return ChaumPedersenProof(party_id, d_wrong, a_point, b_point, c, z)


# =============================================================================
# 1. INVALID-SHARE - share hỏng phải bị bắt NGAY TẠI NGUỒN (câu 2 + hook câu 1)
# =============================================================================
class TestInvalidShare(unittest.TestCase):
    """TC-INVALID-SHARE (146): share bị làm sai trên đường truyền/phát sóng."""

    def test_wire_tamper_detected_at_receiver(self):
        """TC-I1: Dealer 5 gửi share hỏng cho member 1 -> VSS equation bắt ngay."""
        p = pipeline()
        i, j = 5, 1
        bad_share = (p["feldman"][i].share_for(j) + 12345) % N_ORDER
        sig = sign_broadcast(p["dealer_sks"][i], p["vss_ctx"], i,
                             p["feldman"][i].commitments)
        res = p["members"][j].check_feldman_share(
            i, bad_share, p["feldman"][i].commitments, sig)
        self.assertFalse(res.ok)
        self.assertIn("vi phạm Feldman", res.reason)
        self.assertIn(i, p["members"][j].report.failed_dealers)
        print(f"\n[TC-I1] member {j} bắt share hỏng từ dealer {i}: {res.reason}")

    def test_dkg_disqualifies_tampering_sender(self):
        """TC-I2: Trong DKG thật, sender làm sai share bị loại khỏi QUAL, key vẫn nhất quán."""
        def tamper(sender, receiver, share):
            if sender == 4 and receiver == 2:
                return (share + 999) % N_ORDER
            return share

        dkg_bad, _ = run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper)
        self.assertNotIn(4, dkg_bad.qualified_parties, "sender gian lận phải bị loại")
        self.assertGreaterEqual(len(dkg_bad.qualified_parties), T,
                                "QUAL còn >= t -> DKG vẫn hoàn thành")
        self.assertEqual(dkg_bad.reconstruct_public_key([1, 2, 3]),
                         dkg_bad.joint_public_key, "key phải nhất quán sau khi loại")
        print(f"\n[TC-I2] QUAL={dkg_bad.qualified_parties} (dealer 4 bị loại), "
              f"Y tái tạo đúng từ subset 3 phần")

    def test_pedersen_blind_share_tamper_detected(self):
        """TC-I3: Cả share y lẫn blind share z của Pedersen bị sửa đều bị bắt."""
        p = pipeline()
        ped = PedersenVSS(1, T, rng=random.Random(9))
        member = VSSMember(3, p["vss_ctx"], p["dealer_pks"])
        sig = sign_broadcast(p["dealer_sks"][1], p["vss_ctx"], 1, ped.commitments)
        y, z = ped.share_for(3)

        r_y = member.check_pedersen_share(1, (y + 1) % N_ORDER, z,
                                          ped.commitments, sig)
        self.assertFalse(r_y.ok)
        r_z = member.check_pedersen_share(1, y, (z + 1) % N_ORDER,
                                          ped.commitments, sig)
        self.assertFalse(r_z.ok)
        print(f"\n[TC-I3] y sửa -> bắt | z sửa -> bắt ({r_y.scheme}/{r_z.scheme})")

    def test_unsigned_and_replayed_broadcast_rejected(self):
        """TC-I4: Broadcast thiếu chữ ký hoặc replay context cũ -> member từ chối."""
        p = pipeline()
        feld = p["feldman"][2]

        fresh = VSSMember(4, p["vss_ctx"], p["dealer_pks"])
        r_no_sig = fresh.check_feldman_share(2, feld.share_for(4),
                                             feld.commitments, None)
        self.assertFalse(r_no_sig.ok)
        self.assertIn("thiếu chữ ký", r_no_sig.reason)

        stale_member = VSSMember(4, "old-epoch|root=" + "ff" * 32, p["dealer_pks"])
        stale_sig = sign_broadcast(p["dealer_sks"][2], p["vss_ctx"], 2,
                                   feld.commitments)
        r_stale = stale_member.check_feldman_share(2, feld.share_for(4),
                                                   feld.commitments, stale_sig)
        self.assertFalse(r_stale.ok)
        print(f"\n[TC-I4] thiếu chữ ký -> từ chối | replay ctx cũ -> từ chối "
              f"(gắn epoch/root theo 145/150)")


# =============================================================================
# 2. DKG-ABORT - QUAL < t => HỦY, không bao giờ ra key lệch (159)
# =============================================================================
class TestDkgAbort(unittest.TestCase):
    """TC-DKG-ABORT (146): partition/lỗi majority làm QUAL rơi dưới t."""

    def test_qual_below_threshold_aborts(self):
        """TC-D1: 3/5 sender làm sai share -> QUAL=2 < t=3 -> DKGAbortError."""
        def tamper(sender, receiver, share):
            return (share + 999) % N_ORDER if sender in (3, 4, 5) else share

        with self.assertRaises(DKGAbortError) as ctx:
            run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper)
        msg = str(ctx.exception)
        self.assertIn("DKG ABORT", msg)
        self.assertIn("QUAL=2", msg)
        # Fail-safe: exception được ném TRƯỚC khi trả kết quả -> không tồn tại
        # bộ key nào để 2 nhóm node dùng khác nhau (không 'sinh key lệch').
        print(f"\n[TC-D1] {msg}")

    def test_qual_equals_threshold_boundary_succeeds(self):
        """TC-D2: Chạm đúng ngưỡng - 2 sender gian lận -> QUAL=3 = t -> DKG thành công."""
        def tamper(sender, receiver, share):
            return (share + 999) % N_ORDER if sender in (4, 5) else share

        dkg_ok, _ = run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper)
        self.assertEqual(dkg_ok.qualified_parties, [1, 2, 3])
        self.assertEqual(dkg_ok.reconstruct_public_key([1, 2, 3]),
                         dkg_ok.joint_public_key)
        print(f"\n[TC-D2] QUAL={dkg_ok.qualified_parties} = t -> DKG OK "
              f"(abort CHỈ khi QUAL < t, không phóng đại)")

    def test_below_t_participants_refuses_to_start(self):
        """TC-D3: 3 node offline ngay từ đầu (chỉ 2 participant, t=3) -> không khởi tạo."""
        with self.assertRaises(ValueError) as ctx:
            run_pedersen_dkg([1, 2], T)
        self.assertIn("t không được vượt quá n", str(ctx.exception))
        print(f"\n[TC-D3] < t participant -> từ chối start DKG: {ctx.exception}")


# =============================================================================
# 3. OFFLINE-NODE - 2 node chết vẫn phục vụ; dưới t fail-closed (155/234)
# =============================================================================
class TestOfflineNode(unittest.TestCase):
    """TC-OFFLINE (146): node không gửi partial (crash/network partition)."""

    def test_two_offline_still_unwrap(self):
        """TC-O1: Nodes 4,5 offline -> 3 node còn lại unwrap DEK đúng."""
        p = pipeline()
        report = p["combiner"].combine(
            [p["proofs"][j] for j in (1, 2, 3)], p["wrapped"])
        self.assertEqual(report.dek, p["dek"])
        self.assertEqual(report.used_ids, [1, 2, 3])
        print(f"\n[TC-O1] nodes 4,5 offline -> unwrap từ {report.used_ids} "
              f"({report.elapsed_ms:.0f} ms)")

    def test_any_online_subset_of_size_t(self):
        """TC-O2: BẤT KỲ bộ t node online nào (không cố định) cũng unwrap được."""
        p = pipeline()
        for subset in [(2, 3, 5), (1, 3, 4), (3, 4, 5)]:
            report = p["combiner"].combine([p["proofs"][j] for j in subset],
                                            p["wrapped"])
            self.assertEqual(report.dek, p["dek"])
        # Đối chiếu với combiner compact của câu 3 (cùng kết quả)
        cross = combine_and_unwrap([to_compact(p["proofs"][j]) for j in (1, 2, 3)],
                                   p["pub_shares"], T, p["wrapped"])
        self.assertEqual(cross, p["dek"])
        print(f"\n[TC-O2] subsets (2,3,5)/(1,3,4)/(3,4,5) đều OK; "
              f"khớp combine_and_unwrap (câu 3)")

    def test_below_t_online_fail_closed(self):
        """TC-O3: Chỉ 2 node online -> UnderThresholdError, KHÔNG unwrap (234)."""
        p = pipeline()
        with self.assertRaises(InsufficientPartials) as ctx:
            p["combiner"].combine([p["proofs"][1], p["proofs"][2]], p["wrapped"])
        self.assertIn("fail-closed", str(ctx.exception))
        self.assertEqual(ctx.exception.report.accepted_ids, [1, 2])
        print(f"\n[TC-O3] 2 < t=3 -> {ctx.exception}")


# =============================================================================
# 4. COMPROMISED-NODE - partial giả phải bị combiner loại (235/155)
# =============================================================================
class TestCompromisedNode(unittest.TestCase):
    """TC-COMPROMISED (146): node bị chiếm quyền gửi partial/proof gian lận."""

    def test_forged_share_partial_rejected_but_honest_serve(self):
        """TC-C1: Node 3 có share sửa -> proof giả bị loại; 3 node thật vẫn unwrap."""
        p = pipeline()
        forged = forge_wrong_witness(p, 3)
        self.assertFalse(verify_dleq(forged, p["pub_shares"][3],
                                     p["wrapped"].c1, p["proof_ctx"]))

        batch = [p["proofs"][1], forged, p["proofs"][4], p["proofs"][5]]
        report = p["combiner"].combine(batch, p["wrapped"])
        self.assertEqual(report.dek, p["dek"])
        self.assertEqual(dict(report.rejected)[3], "dleq-invalid")
        self.assertEqual(report.accepted_ids, [1, 4, 5])
        print(f"\n[TC-C1] compromised node 3 -> rejected={report.rejected}; "
              f"unwrap từ {report.used_ids} (attacker < t)")

    def test_tampered_d_point_rejected(self):
        """TC-C2: Tráo điểm D trên partial hợp lệ -> verifier độc lập bắt."""
        p = pipeline()
        good = p["proofs"][1]
        bad = dc_replace(good, d_point=_RNG.randrange(1, N_ORDER) * p["wrapped"].c1)
        self.assertFalse(verify_dleq(bad, p["pub_shares"][1],
                                     p["wrapped"].c1, p["proof_ctx"]))
        verdicts = p["combiner"].classify([bad], p["wrapped"].c1, p["proof_ctx"])
        self.assertEqual(verdicts[0].reason, "dleq-invalid")
        print("\n[TC-C2] tráo D_point -> dleq-invalid")

    def test_unknown_party_cannot_claim_partial(self):
        """TC-C3: Party_id không thuộc committee -> không có Y_j -> bị loại."""
        p = pipeline()
        fake = dc_replace(p["proofs"][4], party_id=99)
        verdicts = p["combiner"].classify([fake], p["wrapped"].c1, p["proof_ctx"])
        self.assertEqual(verdicts[0].reason, "unknown-party")
        self.assertFalse(verdicts[0].accepted)
        print("\n[TC-C3] party 99 không trong committee -> unknown-party")

    def test_wrong_witness_cannot_forge_dleq(self):
        """TC-C4: Với mọi delta, proof cho x' != x_j đều fail (cần biết log_G(Y_j))."""
        p = pipeline()
        for delta in (1, 2, 7, N_ORDER - 1, 12345):
            forged = forge_wrong_witness(p, 2, delta)
            self.assertFalse(
                verify_dleq(forged, p["pub_shares"][2], p["wrapped"].c1,
                            p["proof_ctx"]),
                f"delta={delta} không được phép lừa qua DLEQ")
        print("\n[TC-C4] 5/5 delta khác nhau đều bị DLEQ từ chối (soundness)")

    def test_cross_wrap_partial_rejected(self):
        """TC-C5: Partial của wrap(OBJ-7002) trình cho wrap(OBJ-7001) -> loại toàn bộ."""
        p = pipeline()
        wrapped2 = wrap_dek(p["dek"], p["dkg"].joint_public_key,
                            dc_replace(p["wrap_ctx"], object_id="OBJ-7002"))
        batch = [prove_dleq(j, p["shares"][j], p["pub_shares"][j],
                            wrapped2.c1, p["shares"][j] * wrapped2.c1,
                            wrapped2.proof_context())
                 for j in (1, 2, 3)]
        with self.assertRaises(InsufficientPartials) as ctx:
            p["combiner"].combine(batch, p["wrapped"])
        self.assertTrue(all(r == "dleq-invalid"
                            for _, r in ctx.exception.report.rejected))
        print(f"\n[TC-C5] 3/3 proof cross-wrap bị loại theo binding (145/150): "
              f"{ctx.exception}")


# =============================================================================
# 5. TÍCH HỢP - offline + compromised đồng thời; gate GĐ2 + combiner
# =============================================================================
class TestCombinedFailures(unittest.TestCase):
    """TC-X: scenarios kết hợp 2+ loại fault + policy gate GĐ1/2."""

    def test_offline_plus_compromised_below_t_fail_closed(self):
        """TC-X1: 2 node offline + 1 node compromised -> chỉ 2 thật -> fail-closed."""
        p = pipeline()
        forged = forge_wrong_witness(p, 3)         # node 3 compromised
        batch = [p["proofs"][1], p["proofs"][2], forged]   # 4,5 offline
        with self.assertRaises(InsufficientPartials) as ctx:
            p["combiner"].combine(batch, p["wrapped"])
        rep = ctx.exception.report
        self.assertEqual(rep.accepted_ids, [1, 2])
        self.assertEqual(dict(rep.rejected)[3], "dleq-invalid")
        print(f"\n[TC-X1] offline(4,5)+compromised(3) -> accepted={rep.accepted_ids}"
              f" < t -> fail-closed: {ctx.exception}")

    def test_revoked_gate_blocks_new_partials_then_combiner_fails(self):
        """TC-X2: REVOKED -> node từ chối partial MỚI (PermissionError) ->
        không thu thập đủ t -> combiner fail-closed (invariant 232)."""
        p = pipeline()
        # Môi trường policy RIÊNG (không đụng pipeline dùng chung)
        service = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
        event, _, _ = service.init_policy("OBJ-GATE", initial_epoch=1)
        ph = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
        bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
        bridge.anchor_epoch(1, service.mmr)
        oracle = KeyNodeTrustedRootOracle(
            bridge.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
        oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
        root = oracle.get_latest_trusted_root()

        wrap_ctx = WrapContext("OBJ-GATE", 1, ph, "JSON-GCM-v1", 1, root)
        wrapped = wrap_dek(p["dek"], p["dkg"].joint_public_key, wrap_ctx)
        nodes = {j: ThresholdWrapNode(j, p["shares"][j], p["pub_shares"][j],
                                      T, oracle=oracle)
                 for j in p["dkg"].qualified_parties}

        # a) ACTIVE + root tươi -> 3 partial qua gate -> full proof -> combiner OK
        compact = [nodes[j].create_partial(wrapped, presented_policy_root=root,
                                           policy_db=service.policy_records)
                   for j in (1, 2, 3)]
        full = [prove_dleq(j, p["shares"][j], p["pub_shares"][j], wrapped.c1,
                           cp.d_point, wrapped.proof_context())
                for j, cp in zip((1, 2, 3), compact)]
        report = p["combiner"].combine(full, wrapped)
        self.assertEqual(report.dek, p["dek"])
        print(f"\n[TC-X2a] ACTIVE -> 3 partial qua gate -> unwrap OK")

        # b) Stale root -> node fail-closed, KHÔNG tạo partial
        with self.assertRaises(StaleRootError):
            nodes[1].create_partial(wrapped, presented_policy_root="00" * 32,
                                    policy_db=service.policy_records)
        print("[TC-X2b] stale root -> StaleRootError (fail-closed)")

        # c) REVOKED -> mọi node từ chối partial mới; combiner không đủ t
        service.transition_policy("OBJ-GATE", "REVOKED")
        for j in (1, 2, 3):
            with self.assertRaises(PermissionError):
                nodes[j].create_partial(wrapped, presented_policy_root=root,
                                        policy_db=service.policy_records)
        with self.assertRaises(InsufficientPartials) as ctx:
            p["combiner"].combine([], wrapped)      # 0 partial mới thu thập được
        self.assertIn("0/3", str(ctx.exception))
        print("[TC-X2c] REVOKED -> 3/3 node từ chối; 0 < t -> combiner fail-closed")


# =============================================================================
if __name__ == "__main__":
    t0 = time.time()
    program = unittest.main(verbosity=2, exit=False)
    ok = program.result.wasSuccessful()
    print(f"\nKết quả: {'ALL PASS' if ok else 'FAILED'} - "
          f"{program.result.testsRun} tests, "
          f"{len(program.result.failures)} fail, {len(program.result.errors)} err")
    print(f"Tổng thời gian suite: {time.time() - t0:.2f} s "
          f"(pipeline xây 1 lần, tái sử dụng cho mọi test)")
    raise SystemExit(0 if ok else 1)
