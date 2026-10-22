"""
================================================================================
GIAI ĐOẠN 3 - THRESHOLD KEY SERVICE
Lời giải câu 5: "Client/combiner loại partial sai và kết hợp ít nhất t phần
                   hợp lệ."

Gợi ý áp dụng (từ 03_Huong_dan_nghien_cuu, mục 145, 155, 160, 235):
- (145) "Client/combiner loại partial sai và kết hợp ít nhất t phần hợp lệ"
      => ThresholdCombiner.classify(): MỖI partial được xác minh lại bằng
         verifier độc lập Chaum-Pedersen DLEQ (verify_dleq, câu 4) TRƯỚC khi
         vào Lagrange; partial sai / party lạ / bản trùng bị loại kèm lý do;
         chỉ khi >= t partial hợp lệ mới unwrap DEK, không thì fail-closed.
- (235) Invariant bảo mật: "Partial decryption sai không được combiner chấp
         nhận" => không partial nào vào bước kết hợp nếu chưa qua DLEQ check
         với Y_j ghim từ DKG (client không cần tin node/combiner nào).
- (155) Cổng nghiệm thu: "Ít nhất t node hợp lệ vẫn phục vụ khi các node khác
         offline" => batch gồm node offline + partial rác vẫn unwrap được từ
         đúng bộ partial hợp lệ bất kỳ (subset >= t, không phụ thuộc thứ tự).
- (160) Rủi ro "Combiner trở thành trust bottleneck" -> mô phỏng combiner
         bên thứ ba GIAN LẬN; client đại diện (không tin combiner) tự
         classify + tự combine lại từ partials thô nên:
           + che bớt partial  -> client thấy < t -> fail-closed, biết NGUYÊN NHÂN
           + trộn partial giả -> client tự loại, vẫn unwrap nếu còn >= t thật
           + trả DEK bịa      -> client bỏ, tự combine lại -> DEK đúng
- (146) Tests: compromised-node (proof witness sai), invalid-share,
         offline-node, cross-wrap replay.

So với các câu trước:
  + câu 3: combine_and_unwrap() có lọc nhưng chỉ in thông báo -> ở đây
    combiner có BÁO CÁO chi tiết (mỗi partial 1 verdict + lý do reject).
  + câu 4: proof Chaum-Pedersen full transcript -> đây là chỗ DÙNG nó:
    combiner/client chạy verify_dleq() trên từng partial trước khi Lagrange.

Pipeline tái sử dụng TOÀN BỘ code đã viết:
  GĐ1 PolicyLogService + GĐ2 EngramAnchorBridge/KeyNodeTrustedRootOracle
  GĐ3 câu 1 dkg_threshold_service  -> ECPoint/G/N/Lagrange/UnderThresholdError
  GĐ3 câu 2 vss_share_verification  -> FeldmanVSS/VSSMember phân phối share
  GĐ3 câu 3 wrap_dek_partial_decryption -> WrapContext/wrap_dek/ThresholdWrapNode
  GĐ3 câu 4 chaum_pedersen_partial_proof -> ChaumPedersenProof/prove_dleq/
                                            verify_dleq/to_compact (DÙNG LẠI)
================================================================================
"""

import os
import time
import hashlib
import random
from dataclasses import dataclass, replace as dc_replace
from typing import Dict, List, Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- Câu 1: toán học EC + Lagrange + lỗi fail-closed ------------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    hash_to_scalar,
    lagrange_coefficient,
    UnderThresholdError,
)

# --- Câu 4: proof Chaum-Pedersen (verifier độc lập dùng cho combiner) -------
from chaum_pedersen_partial_proof import (
    ChaumPedersenProof,
    prove_dleq,
    verify_dleq,
    to_compact,
    _challenge,
)

# --- Câu 3: wrap DEK + node tạo partial + combine đối chiếu -----------------
from wrap_dek_partial_decryption import (
    WrapContext,
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
    verify_partial,
    combine_and_unwrap,
)

# --- Câu 2: VSS gate trước khi node giữ share -------------------------------
from vss_share_verification import (
    FeldmanVSS,
    VSSMember,
    sign_broadcast,
    committee_keygen,
)

# --- GĐ1 & GĐ2 ---------------------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
)

_RNG = random.SystemRandom()


# =============================================================================
# 1. VERDICT + BÁO CÁO COMBINE - mỗi partial 1 kết luận kèm lý do (145)
# =============================================================================
@dataclass(frozen=True)
class PartialVerdict:
    """Kết luận của combiner/client với MỘT partial."""
    party_id: int
    accepted: bool
    reason: str            # "ok" | "unknown-party" | "duplicate-party" | "dleq-invalid"


@dataclass
class CombineReport:
    """
    Báo cáo combine: cho thấy CHÍNH XÁC partial nào bị loại và vì sao
    (yêu cầu minh bạch với client - combiner không thể 'âm thầm' gạt partial).
    """
    verdicts: List[PartialVerdict]
    used_ids: List[int]                 # party_id thực sự vào Lagrange
    dek: Optional[bytes]                # None nếu fail-closed
    elapsed_ms: float

    @property
    def accepted_ids(self) -> List[int]:
        return [v.party_id for v in self.verdicts if v.accepted]

    @property
    def rejected(self) -> List[Tuple[int, str]]:
        return [(v.party_id, v.reason) for v in self.verdicts if not v.accepted]


class InsufficientPartials(UnderThresholdError):
    """
    Fail-closed (155): dưới t partial HỢP LỆ -> không unwrap.
    Kèm CombineReport để client thấy rõ bao nhiêu partial bị loại/vì sao.
    """
    def __init__(self, message: str, report: CombineReport):
        super().__init__(message)
        self.report = report


# =============================================================================
# 2. THRESHOLD COMBINER - "loại partial sai, kết hợp ít nhất t phần hợp lệ"
# =============================================================================
class ThresholdCombiner:
    """
    Cả COMBINER (bên thứ ba) lẫn CLIENT đều khởi tạo từ CÙNG public_key_shares
    (Y_j công bố từ DKG/Feldman - client xác minh được) và chạy CÙNG code
    classify() -> hai bên luôn đồng thuận; combiner không phải trust bottleneck
    vì client tự kiểm lại toàn bộ trước khi nhận DEK.

    classify() cho mỗi partial, theo thứ tự:
      1) party_id có trong committee không?       -> "unknown-party"
      2) party đã có partial hợp lệ chưa?          -> "duplicate-party"
         (bắt buộc: Lagrange không được trộn 2 chỉ số trùng)
      3) verify_dleq(proof, Y_j, C1, proof_ctx)   -> "dleq-invalid" nếu fail
         (3 check câu 4: Fiat-Shamir + 2 phương trình Schnorr-pair)
    combine(): gộp MỌI partial hợp lệ (>= t) bằng Lagrange -> K -> unwrap.
    """

    def __init__(self, public_key_shares: Dict[int, ECPoint], threshold: int):
        self.public_key_shares = public_key_shares
        self.threshold = threshold

    # ------------------------------------------------------------------
    def classify(self, proofs: List[ChaumPedersenProof],
                 c1: ECPoint, proof_context: bytes) -> List[PartialVerdict]:
        """Client/combiner tự xác minh từng partial - không tin lời ai."""
        verdicts: List[PartialVerdict] = []
        accepted_so_far: set = set()
        for p in proofs:
            if p.party_id not in self.public_key_shares:
                verdicts.append(PartialVerdict(p.party_id, False, "unknown-party"))
                continue
            if p.party_id in accepted_so_far:
                verdicts.append(PartialVerdict(p.party_id, False, "duplicate-party"))
                continue
            ok = verify_dleq(p, self.public_key_shares[p.party_id], c1, proof_context)
            if ok:
                accepted_so_far.add(p.party_id)
            verdicts.append(PartialVerdict(
                p.party_id, ok, "ok" if ok else "dleq-invalid"))
        return verdicts

    # ------------------------------------------------------------------
    def combine(self, proofs: List[ChaumPedersenProof],
                wrapped: ThresholdWrappedDEK) -> CombineReport:
        """
        "Loại partial sai" (classify) -> "kết hợp ít nhất t phần hợp lệ"
        (Lagrange trên TẤT CẢ partial hợp lệ; >= t điểm cùng đa thức bậc t-1
        vẫn nội suy đúng hằng số f(0) -> robust hơn cắt đúng t).
        Dưới t -> InsufficientPartials (fail-closed, kèm báo cáo lý do).
        """
        t0 = time.time()
        proof_ctx = wrapped.proof_context()          # gắn object/ct/epoch/root (145)
        verdicts = self.classify(proofs, wrapped.c1, proof_ctx)
        accepted = [p for p, v in zip(proofs, verdicts) if v.accepted]
        rejected = [(v.party_id, v.reason) for v in verdicts if not v.accepted]

        report = CombineReport(verdicts=verdicts, used_ids=[], dek=None,
                               elapsed_ms=0.0)
        if len(accepted) < self.threshold:
            report.elapsed_ms = (time.time() - t0) * 1000
            raise InsufficientPartials(
                f"Chỉ có {len(accepted)}/{self.threshold} partial hợp lệ "
                f"(bị loại: {rejected}) - fail-closed, KHÔNG unwrap DEK.",
                report)

        # --- Kết hợp Lagrange trên mọi partial hợp lệ ---
        ids = [p.party_id for p in accepted]
        combined = ECPoint(None, None)
        for p in accepted:
            lam = lagrange_coefficient(p.party_id, ids)
            combined = combined + (lam * p.d_point)

        wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                        info=wrapped.context.aad()).derive(combined.to_bytes())
        try:
            dek = AESGCM(wrap_key).decrypt(wrapped.nonce, wrapped.ciphertext,
                                           wrapped.context.aad())
        except InvalidTag as err:
            report.elapsed_ms = (time.time() - t0) * 1000
            raise InsufficientPartials(
                f"AEAD tag sai - bộ partial không tái tạo đúng K: {err}", report)
        report.used_ids = ids
        report.dek = dek
        report.elapsed_ms = (time.time() - t0) * 1000
        return report


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _print_verdicts(report: CombineReport):
    for v in report.verdicts:
        tag = "ACCEPT" if v.accepted else f"REJECT ({v.reason})"
        print(f"    - node {v.party_id:>2}: {tag}")


# =============================================================================
# 3. DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    N, T = 5, 3                       # (146) t=3/n=5 từ threat model: chịu 2 node chết

    # ------------------------------------------------------------------
    # PIPELINE (tái sử dụng câu 1-4): GĐ1/2 context; VSS shares; wrap DEK;
    # mỗi node tạo partial+proof Chaum-Pedersen đầy đủ.
    # ------------------------------------------------------------------
    _banner("PIPELINE: GĐ1+GĐ2, VSS (CÂU 2), WRAP+PARTIAL (CÂU 3), PROOF (CÂU 4)")

    authority_sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(authority_sk)
    event, leaf_idx, root_hex = service.init_policy("OBJ-6001", initial_epoch=1)
    policy_hash = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()

    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    bridge.anchor_epoch(1, service.mmr)
    oracle = KeyNodeTrustedRootOracle(bridge.bridge_pk,
                                      FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    trusted_root = oracle.get_latest_trusted_root()

    vss_ctx = f"combiner-pipeline|epoch=1|root={trusted_root}"
    dealer_sks, dealer_pks = committee_keygen(N)
    feldman = {i: FeldmanVSS(i, T, rng=random.Random(6000 + i)) for i in range(1, N + 1)}
    vss_members = {j: VSSMember(j, vss_ctx, dealer_pks) for j in range(1, N + 1)}
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            sig = sign_broadcast(dealer_sks[i], vss_ctx, i, feldman[i].commitments)
            vss_members[j].check_feldman_share(i, feldman[i].share_for(j),
                                               feldman[i].commitments, sig)
    assert all(m.report.all_ok for m in vss_members.values())

    shares = {j: sum(feldman[i].share_for(j) for i in range(1, N + 1)) % N_ORDER
              for j in range(1, N + 1)}
    pub_shares = {j: shares[j] * G for j in range(1, N + 1)}
    threshold_pk = ECPoint(None, None)
    for i in range(1, N + 1):
        threshold_pk = threshold_pk + feldman[i].commitments[0]
    print(f"- Shares qua VSS check (câu 2); Y = {format(threshold_pk.x, 'x')[:24]}...")

    wrap_ctx = WrapContext(object_id="OBJ-6001", version=1, policy_hash=policy_hash,
                           codec_id="JSON-GCM-v1", epoch=1, policy_root=trusted_root)
    dek = os.urandom(32)
    wrapped = wrap_dek(dek, threshold_pk, wrap_ctx)
    c1 = wrapped.c1
    proof_ctx = wrapped.proof_context()

    nodes = {j: ThresholdWrapNode(j, shares[j], pub_shares[j], T, oracle=oracle)
             for j in range(1, N + 1)}
    # Mọi node tạo full proof (câu 4)
    proofs = {j: prove_dleq(j, shares[j], pub_shares[j], c1,
                            shares[j] * c1, proof_ctx) for j in range(1, N + 1)}
    print(f"- {N}/{N} node có proof Chaum-Pedersen hợp lệ; combiner t={T}/n={N}")

    combiner = ThresholdCombiner(pub_shares, T)

    # =====================================================================
    _banner("TEST 1: COMBINER NHẬN BATCH HỢP LỆ - KẾT HỢP TẤT CẢ -> DEK")
    # =====================================================================
    report = combiner.combine([proofs[j] for j in range(1, N + 1)], wrapped)
    _print_verdicts(report)
    assert report.dek == dek and report.used_ids == [1, 2, 3, 4, 5]
    print(f"  -> accepted={report.accepted_ids}, dùng toàn bộ 5 partial "
          f"(Lagrange >= t), DEK khớp ({report.elapsed_ms:.1f} ms)")
    results.append("TEST1 combiner accept-all + combine: PASS")

    # =====================================================================
    _banner("TEST 2: LOẠI TỪNG LOẠI PARTIAL SAI (145) - VẪN >= T -> UNWRAP")
    # =====================================================================
    # Proof cho node 3 với witness SAI (x3+1) - compromised-node giả mạo
    x_wrong = (shares[3] + 1) % N_ORDER
    d_wrong = x_wrong * c1
    u_a = _RNG.randrange(1, N_ORDER)
    a_f, b_f = u_a * G, u_a * c1
    c_f = _challenge(pub_shares[3], c1, d_wrong, a_f, b_f, proof_ctx)
    z_f = (u_a + c_f * x_wrong) % N_ORDER
    forged_witness = ChaumPedersenProof(3, d_wrong, a_f, b_f, c_f, z_f)

    batch = [
        proofs[1],                                          # hợp lệ
        dc_replace(proofs[1], response=(proofs[1].response + 1) % N_ORDER),
                                                           # bản 2 của node 1 -> trùng
        forged_witness,                                     # witness sai (compromised)
        dc_replace(proofs[4], party_id=99),                 # party không trong committee
        dc_replace(proofs[2], challenge=(proofs[2].challenge + 1) % N_ORDER),
                                                           # tráo challenge
        proofs[4],                                          # hợp lệ
        proofs[5],                                          # hợp lệ
    ]
    report = combiner.combine(batch, wrapped)
    _print_verdicts(report)
    assert report.dek == dek
    assert report.accepted_ids == [1, 4, 5]
    reasons = dict(report.rejected)
    assert reasons[1] == "duplicate-party"      # node 1 gửi 2 bản -> bản 2 loại
    assert reasons[3] == "dleq-invalid"         # compromised-node (witness sai)
    assert reasons[99] == "unknown-party"       # party lạ
    assert reasons[2] == "dleq-invalid"         # tráo challenge
    print(f"  -> rejected={report.rejected}")
    print(f"  -> còn đúng 3 partial hợp lệ ({report.accepted_ids}) -> unwrap DEK đúng")
    results.append("TEST2 reject invalid/unknown/duplicate: PASS")

    # =====================================================================
    _banner("TEST 3: ĐÚNG T -> OK; DƯỚI T (KỂ CẢ CÓ PARTIAL GIÁ) -> FAIL-CLOSED")
    # =====================================================================
    # a) Đúng t: 2 node offline (1,2) - 3 node còn lại vẫn phục vụ (155)
    r3 = combiner.combine([proofs[j] for j in (3, 4, 5)], wrapped)
    assert r3.dek == dek and r3.used_ids == [3, 4, 5]
    print(f"  [3a] Đúng t=3 (nodes 1,2 offline) -> unwrap OK, used={r3.used_ids}")

    # b) Nhận 3 partial nhưng 1 cái giả -> chỉ 2 hợp lệ -> fail-closed
    try:
        combiner.combine([proofs[1], proofs[2], forged_witness], wrapped)
        raise AssertionError("2/3 partial hợp lệ phải fail-closed")
    except InsufficientPartials as err:
        assert err.report.accepted_ids == [1, 2]
        assert dict(err.report.rejected)[3] == "dleq-invalid"
        print(f"  [3b] 3 partial nhưng 1 giả -> fail-closed: {err}")
        print(f"       Báo cáo: accepted={err.report.accepted_ids}, "
              f"rejected={err.report.rejected}")

    # c) Trộn 1 thật + 2 giả -> fail-closed, không bao giờ gộp lậu
    try:
        combiner.combine([proofs[1], forged_witness,
                          dc_replace(proofs[2], party_id=99)], wrapped)
        raise AssertionError("1/3 hợp lệ phải fail")
    except InsufficientPartials as err:
        print(f"  [3c] 1 thật + 2 giả -> fail-closed: {err}")
    results.append("TEST3 exactly-t ok / under-t fail-closed: PASS")

    # =====================================================================
    _banner("TEST 4: BẤT KỲ SUBSET >= T NÀO CŨNG RA CÙNG DEK (LAGRANGE)")
    # =====================================================================
    for subset in [(1, 2, 3), (2, 3, 5), (1, 4, 5), (3, 4, 5), (1, 2, 3, 4, 5)]:
        r = combiner.combine([proofs[j] for j in subset], wrapped)
        assert r.dek == dek
        print(f"  - subset {subset}: DEK khớp (used={r.used_ids})")
    # Đối chiếu với combiner gốc của câu 3 (dùng compact proof, đúng t phần đầu)
    cross = combine_and_unwrap([to_compact(proofs[j]) for j in (1, 2, 3)],
                               pub_shares, T, wrapped)
    assert cross == dek
    print("  - Đối chiếu câu 3: combine_and_unwrap(subset 3) = DEK giống hệt")
    # Dưới t bất biến theo mọi subset
    try:
        combiner.combine([proofs[1], proofs[2]], wrapped)
        raise AssertionError("subset 2 phải fail")
    except InsufficientPartials:
        print("  - Subset < t -> luôn fail-closed (không phụ thuộc thứ tự)")
    results.append("TEST4 any-subset >= t same DEK: PASS")

    # =====================================================================
    _banner("TEST 5: COMBINER GIAN LẬN - CLIENT TỰ VERIFY, KHÔNG TIN (160)")
    # =====================================================================
    # (a) Combiner che bớt xuống 1 partial nhưng vẫn tuyên bố 'đủ t'
    try:
        combiner.combine([proofs[1]], wrapped)
        raise AssertionError("Che bớt phải bị client phát hiện")
    except InsufficientPartials as err:
        print(f"  [5a] Che bớt -> client tự thấy {err.report.accepted_ids} "
              f"< t, fail-closed: {err}")

    # (b) Combiner trộn partial giả cho batch vẫn còn >= t thật
    r = combiner.combine([proofs[1], forged_witness, proofs[4], proofs[5]], wrapped)
    assert r.dek == dek and dict(r.rejected)[3] == "dleq-invalid"
    print(f"  [5b] Trộn partial giả -> client loại {r.rejected}, "
          f"unwrap từ {r.used_ids} -> DEK đúng")

    # (c) Combiner trả DEK BỊA -> client bỏ, tự combine lại từ partials thô
    liar_dek = os.urandom(32)
    client = ThresholdCombiner(pub_shares, T)     # đại diện client, cùng code
    own = client.combine([proofs[j] for j in (1, 3, 5)], wrapped)
    assert own.dek == dek and liar_dek != dek
    print(f"  [5c] Combiner trả DEK bịa -> client tự combine -> DEK đúng, "
          f"bỏ qua DEK của combiner")

    # (d) Hai bên classify cùng 1 batch -> verdict GIỐNG HỆT (không lừa được
    #     client bằng lời 'partial tốt')
    server_v = combiner.classify(batch, c1, proof_ctx)
    client_v = client.classify(batch, c1, proof_ctx)
    assert server_v == client_v
    print(f"  [5d] Verdict combiner == verdict client trên cùng batch "
          f"({len(server_v)} partial) -> không có 'lời khai' nào lọt qua")
    results.append("TEST5 byzantine combiner neutralized: PASS")

    # =====================================================================
    _banner("TEST 6: CROSS-WRAP REPLAY - PROOF CỦA WRAP KHÁC -> LOẠI TOÀN BỘ")
    # =====================================================================
    wrapped_other = wrap_dek(dek, threshold_pk,
                             dc_replace(wrap_ctx, object_id="OBJ-6002"))
    proof_ctx_other = wrapped_other.proof_context()
    batch_other = [prove_dleq(j, shares[j], pub_shares[j], wrapped_other.c1,
                              shares[j] * wrapped_other.c1, proof_ctx_other)
                   for j in (1, 2, 3)]
    try:
        # Combiner trộn proof của wrap(OBJ-6002) vào yêu cầu unwrap wrap(OBJ-6001)
        combiner.combine(batch_other, wrapped)
        raise AssertionError("Proof cross-wrap phải bị loại toàn bộ")
    except InsufficientPartials as err:
        assert all(r == "dleq-invalid" for _, r in err.report.rejected)
        print(f"  [6] 3/3 proof từ wrap khác bị loại theo binding (145): {err}")
    results.append("TEST6 cross-wrap batch rejected: PASS")

    # =====================================================================
    _banner("TEST 7: E2E - GATE POLICY GĐ2 + COMBINER (REVOKED -> FAIL-CLOSED)")
    # =====================================================================
    partials = []
    for j in (1, 2, 3):
        p_compact = nodes[j].create_partial(wrapped, presented_policy_root=trusted_root,
                                            policy_db=service.policy_records)
        # Node tạo partial (câu 3) -> full proof (câu 4) -> combiner (câu 5)
        partials.append(prove_dleq(j, shares[j], pub_shares[j], c1,
                                   p_compact.d_point, proof_ctx))
    r = combiner.combine(partials, wrapped)
    assert r.dek == dek
    print(f"  [7a] 3 partial qua gate GĐ2 + proof + combiner -> DEK đúng "
          f"(used={r.used_ids})")

    service.transition_policy("OBJ-6001", "REVOKED")
    try:
        nodes[4].create_partial(wrapped, presented_policy_root=trusted_root,
                                policy_db=service.policy_records)
        raise AssertionError("REVOKED phải chặn node")
    except PermissionError:
        print("  [7b] REVOKED -> node từ chối tạo partial (gate GĐ2)")
    try:
        combiner.combine(partials[:1], wrapped)     # các node khác không còn partial
        raise AssertionError("REVOKED + thiếu t phải fail-closed")
    except InsufficientPartials as err:
        print(f"  [7c] Sau revoke, combiner < t -> fail-closed: {err}")
    results.append("TEST7 e2e gate + combiner: PASS")

    # =====================================================================
    _banner("BENCHMARK (deliverable 153: classify + combine latency)")
    # =====================================================================
    all_proofs = [proofs[j] for j in range(1, N + 1)]
    t0 = time.time()
    for _ in range(5):
        combiner.classify(all_proofs, c1, proof_ctx)
    per_classify = (time.time() - t0) / 5 * 1000
    t0 = time.time()
    for _ in range(5):
        combiner.combine(all_proofs, wrapped)
    per_full = (time.time() - t0) / 5 * 1000
    print(f"- classify {N} partial (n*verify_dleq): {per_classify:.1f} ms")
    print(f"- classify + Lagrange + HKDF + AEAD  : {per_full:.1f} ms")
    print(f"- (verify_dleq dominates ~140 ms/proof - câu 4 đã đo)")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r_ in results:
        print(f"  {r_}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => Combiner/client xác minh lại MỖI partial bằng verifier DLEQ")
    print("     độc lập (câu 4) trước khi Lagrange: partial sai, party lạ,")
    print("     bản trùng, proof cross-wrap đều bị loại kèm lý do (145/235);")
    print("     >= t partial hợp lệ bất kỳ subset nào vẫn unwrap (155); dưới t")
    print("     fail-closed kèm báo cáo; combiner gian lận không ảnh hưởng vì")
    print("     client tự classify + tự combine (hóa giải 160).")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
