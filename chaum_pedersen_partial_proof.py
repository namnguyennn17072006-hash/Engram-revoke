"""
================================================================================
GIAI ĐOẠN 3 - THRESHOLD KEY SERVICE
Lời giải câu 4: "Gắn Chaum-Pedersen hoặc proof tương đương để chứng minh
                   partial decryption đúng."

Gợi ý áp dụng (từ 03_Huong_dan_nghien_cuu, mục 142-155):
- (145) "Partial decryptions phải bind object, ciphertext, epoch và policy root"
      => proof_context = AAD(ObjectID|Version|PolicyHash|CodecID|Epoch|PolicyRoot)
         + CtDigest(SHA256(nonce||ct)) tham gia TRỰC TIẾP vào Fiat-Shamir
         challenge -> proof vô hiệu nếu bất kỳ yếu tố nào bị đổi.
- (152) "Independent partial proof verifier"
      => verify_dleq() độc lập: mọi client tự xác minh từng partial,
         không cần tin node phát partial cũng KHÔNG cần tin combiner.
- (154) Cổng nghiệm thu: "Partial decryption sai bị phát hiện"
      => chứng minh NĂNG LỰC: proof giả (sai share / sai D / sai transcript)
         đều bị verify_dleq() từ chối (soundness của DLEQ dưới giả định DL).
- (155) Rủi ro: "Combiner trở thành trust bottleneck"
      => chỉ ra cách hóa giải: combiner KHÔNG cần được tin cậy vì
         client tự verify lại toàn bộ proof; combiner không thể tạo proof
         hợp lệ cho D sai (yêu cầu biết log_G(Y_j) = x_j - thuộc về DL).
- (148) "Prototype ... test vectors; academic/not production"
      => test vector tất định (seed=1337) + cảnh báo audit.
- (149) Curve/field nhất quán: secp256k1, tái sử dụng EC math từ GĐ3.

PHÁP CHỨNG MINH - Chaum-Pedersen DLEQ (Discrete Log Equality):
  Mệnh đề cần chứng minh cho partial của node j:
        log_G(Y_j) == log_{C1}(D_j)      (với cùng witness x_j,
         tức Y_j = x_j*G  và  D_j = x_j*C1 - partial decryption đúng)
  Giao thức 3 bước -> không tương tác qua Fiat-Shamir:
    Prover : u random;  A = u*G;  B = u*C1;
             c = H(G, Y_j, C1, D_j, A, B, context);   z = (u + c*x_j) mod N
    Proof  : (A, B, c, z)  - full transcript, tự chứa
    Verifier (độc lập - 152):
             1) c' = H(...)  ==  c                     (Fiat-Shamir)
             2) z*G  == A + c*Y_j                      (Schnorr trên base G)
             3) z*C1 == B + c*D_j                      (Schnorr trên base C1)
  "Proof tương đương": hai check (2)+(3) dùng CÙNG (c,z) cho 2 base -
  chính xác là 2 Schnorr proof đồng bộ witness, nên DLEQ = Schnorr-pair.
  Zero-knowledge: verifier chỉ thấy phương trình; u ngẫu nhiên che x_j.
  (Mục 3 demo: BẤT KỲ AI cũng simulate được proof -> proof thật không lộ gì.)

Tái sử dụng code trước:
- dkg_threshold_service (câu 1)        -> ECPoint/G/N/hash_to_scalar/Lagrange/
                                           UnderThresholdError
- wrap_dek_partial_decryption (câu 3)  -> WrapContext, wrap_dek, ThresholdWrapNode,
                                           PartialWithProof (định dạng compact),
                                           verify_partial, combine_and_unwrap
- vss_share_verification (câu 2)       -> FeldmanVSS + VSSMember (share gate)
- GĐ1/GĐ2                              -> PolicyLogService, EngramAnchorBridge,
                                           KeyNodeTrustedRootOracle
================================================================================
"""

import os
import time
import hashlib
import random
from dataclasses import dataclass, replace as dc_replace
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

# --- Câu 1: toán học EC + Lagrange + lỗi ------------------------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    hash_to_scalar,
    lagrange_coefficient,
    UnderThresholdError,
)

# --- Câu 3: wrap/partial/combine (định dạng partial + pipeline) -------------
from wrap_dek_partial_decryption import (
    WrapContext,
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
    PartialWithProof,
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
# 1. CHAUM-PEDERSEN DLEQ PROOF (full transcript, tự chứa)
# =============================================================================
@dataclass
class ChaumPedersenProof:
    """
    Full transcript (A, B, c, z) cho DLEQ:
        log_G(Y_j) == log_{C1}(D_j)  với witness x_j.
    Khác định dạng compact (c, z) của câu 3: chứa cả A, B nên proof
    tự kiểm chứng được cả đại lượng z*G = A + c*Y_j (không cần tái tạo A', B').
    """
    party_id: int
    d_point: ECPoint            # D_j = x_j * C1 (partial decryption)
    a_point: ECPoint            # A = u * G
    b_point: ECPoint            # B = u * C1
    challenge: int              # c = Fiat-Shamir(G, Y_j, C1, D_j, A, B, context)
    response: int               # z = (u + c * x_j) mod N


def _challenge(public_share: ECPoint, c1: ECPoint, d_point: ECPoint,
               a_point: ECPoint, b_point: ECPoint, proof_context: bytes) -> int:
    """Fiat-Shamir challenge - context (object/ct/epoch/root) nằm trong H()."""
    return hash_to_scalar(G, public_share, c1, d_point, a_point, b_point, proof_context)


def prove_dleq(
    party_id: int,
    share: int,
    public_share: ECPoint,
    c1: ECPoint,
    d_point: ECPoint,
    proof_context: bytes,
    rng: Optional[random.Random] = None,
) -> ChaumPedersenProof:
    """
    Node j tạo proof Chaum-Pedersen cho partial decryption D_j = x_j*C1.
    Tự kiểm tra witness nhất quán trước khi chứng minh (chống nhầm lẫn).
    """
    rng = rng or _RNG
    if c1.is_infinity() or c1 == G:
        raise ValueError("C1 degenerate - không tạo proof")
    if share * G != public_share:
        raise ValueError("share không khớp Y_j - witness nhất quán sai")
    if share * c1 != d_point:
        raise ValueError("share không khớp D_j - witness nhất quán sai")

    u = rng.randrange(1, N_ORDER)
    a_point = u * G
    b_point = u * c1
    c = _challenge(public_share, c1, d_point, a_point, b_point, proof_context)
    z = (u + c * share) % N_ORDER
    return ChaumPedersenProof(party_id, d_point, a_point, b_point, c, z)


def _verify_algebra(proof: ChaumPedersenProof, public_share: ECPoint,
                    c1: ECPoint) -> bool:
    """
    Hai check ĐẠI SỐ (Schnorr-pair) của DLEQ, không qua Fiat-Shamir:
      z*G  == A + c*Y_j    và    z*C1 == B + c*D_j
    Đây chính là 'proof tương đương': 2 Schnorr proof dùng chung (c,z).
    """
    c, z = proof.challenge, proof.response
    if z * G != proof.a_point + (c * public_share):
        return False
    if z * c1 != proof.b_point + (c * proof.d_point):
        return False
    return True


def verify_dleq(
    proof: ChaumPedersenProof,
    public_share: ECPoint,
    c1: ECPoint,
    proof_context: bytes,
    challenge_fn=None,
) -> bool:
    """
    INDEPENDENT PARTIAL PROOF VERIFIER (gợi ý 152) - 3 check:
      1) Fiat-Shamir: c' == c   (challenge_fn tùy chọn = random oracle có
         lập trình - dùng cho demo mô hình ROM ở TEST 3)
      2) Schnorr trên G    : z*G  == A + c*Y_j
      3) Schnorr trên C1   : z*C1 == B + c*D_j
    """
    c, z = proof.challenge, proof.response
    # 1) Transcript Fiat-Shamir (gắn object/ciphertext/epoch/policy root - 145)
    recompute = (challenge_fn(public_share, c1, proof.d_point, proof.a_point,
                              proof.b_point, proof_context)
                 if challenge_fn is not None
                 else _challenge(public_share, c1, proof.d_point, proof.a_point,
                                 proof.b_point, proof_context))
    if recompute != c:
        return False
    # 2) + 3) Schnorr-pair (đại số)
    return _verify_algebra(proof, public_share, c1)


def simulate_dleq(
    party_id: int,
    public_share: ECPoint,
    c1: ECPoint,
    d_point: ECPoint,
    proof_context: bytes,
    rng: Optional[random.Random] = None,
) -> ChaumPedersenProof:
    """
    HVZK simulation: chọn (c, z) NGẪU NHIÊN rồi tính ngược A, B.
    Proof giả này vẫn verify = True -> bằng chứng thực tế zero-knowledge:
    proof không chứa thông tin nào về x_j (bất kỳ ai cũng 'giả' được).
    """
    rng = rng or _RNG
    c = rng.randrange(0, N_ORDER)
    z = rng.randrange(0, N_ORDER)
    a_point = (z * G) - (c * public_share)
    b_point = (z * c1) - (c * d_point)
    return ChaumPedersenProof(party_id, d_point, a_point, b_point, c, z)


def to_compact(proof: ChaumPedersenProof) -> PartialWithProof:
    """Chuyển sang định dạng compact (c, z) của câu 3 để dùng lại combine."""
    return PartialWithProof(party_id=proof.party_id, d_point=proof.d_point,
                            proof_c=proof.challenge, proof_z=proof.response)


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 2. DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    N, T = 5, 3                       # (146) t=3/n=5 từ threat model

    # ------------------------------------------------------------------
    # PIPELINE (tái sử dụng câu 1-3): GĐ1/2 -> context; VSS -> shares;
    # wrap DEK dưới Y (câu 3); node tạo partial (câu 3) + proof (câu 4).
    # ------------------------------------------------------------------
    _banner("PIPELINE: GĐ1+GĐ2 CONTEXT, VSS SHARES (CÂU 2), WRAP (CÂU 3)")

    authority_sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(authority_sk)
    event, leaf_idx, root_hex = service.init_policy("OBJ-5001", initial_epoch=1)
    policy_hash = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()

    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    bridge.anchor_epoch(1, service.mmr)
    oracle = KeyNodeTrustedRootOracle(bridge.bridge_pk,
                                      FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    trusted_root = oracle.get_latest_trusted_root()

    vss_ctx = f"cp-pipeline|epoch=1|root={trusted_root}"
    dealer_sks, dealer_pks = committee_keygen(N)
    feldman = {i: FeldmanVSS(i, T, rng=random.Random(5000 + i)) for i in range(1, N + 1)}
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

    wrap_ctx = WrapContext(object_id="OBJ-5001", version=1, policy_hash=policy_hash,
                           codec_id="JSON-GCM-v1", epoch=1, policy_root=trusted_root)
    dek = os.urandom(32)
    wrapped = wrap_dek(dek, threshold_pk, wrap_ctx)
    proof_ctx = wrapped.proof_context()          # AAD + CtDigest (145)
    print(f"- DEK 32B wrap dưới Y; proof_context = AAD + CtDigest")

    nodes = {j: ThresholdWrapNode(j, shares[j], pub_shares[j], T, oracle=oracle)
             for j in range(1, N + 1)}

    # =====================================================================
    _banner("TEST 1: PROOF HỢP LỆ - TRANSCRIPT + VERIFY + ĐỐI CHIẾU CÂU 3")
    # =====================================================================
    # Node 1 tạo full proof (test vector tất định seed=1337)
    c1 = wrapped.c1
    d1 = shares[1] * c1
    proof1 = prove_dleq(1, shares[1], pub_shares[1], c1, d1, proof_ctx,
                        rng=random.Random(1337))
    print(f"  Prover (node 1): u ngẫu nhiên -> A = u*G, B = u*C1")
    print(f"    A.x    = {format(proof1.a_point.x, 'x')[:40]}...")
    print(f"    c      = {format(proof1.challenge, 'x')[:40]}...")
    print(f"    z      = {format(proof1.response, 'x')[:40]}...  (seed=1337, tất định)")
    assert verify_dleq(proof1, pub_shares[1], c1, proof_ctx)
    print("  Verifier: c'==c OK | z*G==A+c*Y_1 OK | z*C1==B+c*D_1 OK  => VALID")
    print("  (2 check Schnorr dùng chung (c,z) => 'proof tương đương' DLEQ)")

    # Đối chiếu: định dạng compact (câu 3) verify cùng kết quả
    compact = to_compact(proof1)
    assert verify_partial(compact, pub_shares[1], c1, proof_ctx)
    print("  Đối chiếu câu 3: verify_partial(compact) = verify_dleq(full) = True")

    # Mọi node tạo proof đều verify
    proofs = {j: prove_dleq(j, shares[j], pub_shares[j], c1,
                            shares[j] * c1, proof_ctx) for j in range(1, N + 1)}
    assert all(verify_dleq(proofs[j], pub_shares[j], c1, proof_ctx) for j in proofs)
    print(f"  {N}/{N} node tạo proof hợp lệ - PASS")
    results.append("TEST1 valid proof + equivalence: PASS")

    # =====================================================================
    _banner("TEST 2: SOUNDNESS - PROOF SAI ĐỀU BỊ TỪ CHỐI (154)")
    # =====================================================================
    # 2a. Kẻ tấn công biết x' != x_j cố tạo proof cho D'=x'*C1 nhưng vẫn
    #     claim Y_j (combiner pin Y_j từ DKG - attacker không thay được).
    x_wrong = (shares[1] + 1) % N_ORDER
    d_wrong = x_wrong * c1
    u_a = random.SystemRandom().randrange(1, N_ORDER)
    a_f, b_f = u_a * G, u_a * c1
    c_f = _challenge(pub_shares[1], c1, d_wrong, a_f, b_f, proof_ctx)
    z_f = (u_a + c_f * x_wrong) % N_ORDER
    forged_wrong_witness = ChaumPedersenProof(1, d_wrong, a_f, b_f, c_f, z_f)
    assert not verify_dleq(forged_wrong_witness, pub_shares[1], c1, proof_ctx)
    print("  [2a] Witness sai (x'=x+1) -> proof INVALID (cần biết log_G(Y_j) để lừa)")

    # 2b. Tráo từng trường của proof hợp lệ
    for name, bad in [
        ("tráo response z",  dc_replace(proof1, response=(proof1.response + 1) % N_ORDER)),
        ("tráo challenge c", dc_replace(proof1, challenge=(proof1.challenge + 1) % N_ORDER)),
        ("tráo A",           dc_replace(proof1, a_point=(_RNG.randrange(1, N_ORDER) * G))),
        ("tráo D",           dc_replace(proof1, d_point=(_RNG.randrange(1, N_ORDER) * c1))),
    ]:
        assert not verify_dleq(bad, pub_shares[1], c1, proof_ctx)
        print(f"  [2b] {name} -> INVALID")

    # 2c. Thử z ngẫu nhiên cho transcript đã chốt c -> không bao giờ thỏa cả 2 Schnorr
    hits = 0
    for _ in range(20):
        z_try = _RNG.randrange(0, N_ORDER)
        if (z_try * G == proof1.a_point + (proof1.challenge * pub_shares[1]) and
                z_try * c1 == proof1.b_point + (proof1.challenge * d1)):
            hits += 1
    assert hits == 0
    print("  [2c] 20 lần brute z ngẫu nhiên: 0 hit (dưới giả định DL)")
    results.append("TEST2 soundness: PASS")

    # =====================================================================
    _banner("TEST 3: ZERO-KNOWLEDGE - BẤT KỲ AI CŨNG GIẢ ĐƯỢC PHƯƠNG TRÌNH")
    # =====================================================================
    # Giả lập transcript: chọn (c, z) NGẪU NHIÊN, tính ngược A, B
    fake = simulate_dleq(1, pub_shares[1], c1, d1, proof_ctx)
    # Bước 1: proof giả thỏa CẢ 2 phương trình Schnorr mà không biết x_j
    assert _verify_algebra(fake, pub_shares[1], c1)
    print("  [3a] Transcript giả (c,z ngẫu nhiên, tính ngược A,B) thỏa")
    print("       ĐỦ 2 phương trình z*G==A+c*Y và z*C1==B+c*D mà KHÔNG biết x_j")
    # Bước 2: với hash Fiat-Shamir THẬT, H(A,B) != c -> bị check 1 bắt
    assert not verify_dleq(fake, pub_shares[1], c1, proof_ctx)
    print("  [3b] Hash Fiat-Shamir thật: H(A,B) != c -> chỉ hash phân biệt thật/giả")
    # Bước 3: mô hình ROM - 'lập trình' random oracle output c tại transcript này
    programmed = verify_dleq(fake, pub_shares[1], c1, proof_ctx,
                             challenge_fn=lambda *args: fake.challenge)
    assert programmed
    print("  [3c] Mô hình ROM: 'lập trình' hash output c -> proof giả VERIFY như thật")
    print("  => Honest-verifier ZK (chuẩn DLEQ/Fiat-Shamir): toàn bộ 'nội dung'")
    print("     proof chỉ là phương trình đại số; x_j bị che bởi u ngẫu nhiên")
    results.append("TEST3 zero-knowledge (ROM): PASS")

    # =====================================================================
    _banner("TEST 4: BINDING (145) - PROOF GẮN OBJECT/CT/EPOCH/POLICY ROOT")
    # =====================================================================
    for label, ctx in [
        ("đổi ObjectID",  dc_replace(wrap_ctx, object_id="OBJ-EVIL").proof_context(wrapped.nonce, wrapped.ciphertext)),
        ("đổi Epoch",     dc_replace(wrap_ctx, epoch=99).proof_context(wrapped.nonce, wrapped.ciphertext)),
        ("đổi PolicyRoot", dc_replace(wrap_ctx, policy_root="dd" * 32).proof_context(wrapped.nonce, wrapped.ciphertext)),
        ("tráo ciphertext", wrap_ctx.proof_context(wrapped.nonce, bytes([wrapped.ciphertext[0] ^ 1]) + wrapped.ciphertext[1:])),
    ]:
        assert not verify_dleq(proof1, pub_shares[1], c1, ctx)
        print(f"  [4] {label} -> challenge H() đổi -> proof INVALID")
    results.append("TEST4 context binding: PASS")

    # =====================================================================
    _banner("TEST 5: COMBINER KHÔNG CẦN TIN (hóa giải rủi ro 155)")
    # =====================================================================
    # Combiner gian lận: trộn partial giả (witness sai, vẫn claim là node 1)
    forged_evil = forged_wrong_witness
    # Client tự verify từng proof với Y_j ghim từ DKG (không tin lời "tốt"
    # của combiner): proof thật hợp lệ, proof giả bị loại
    legit_ok = {j: verify_dleq(proofs[j], pub_shares[j], c1, proof_ctx)
                for j in range(1, N + 1)}
    evil_ok = verify_dleq(forged_evil, pub_shares[forged_evil.party_id], c1, proof_ctx)
    bad_claim = [forged_evil.party_id] if not evil_ok else []
    assert all(legit_ok.values()) and not evil_ok
    print(f"  Client re-verify: {sum(legit_ok.values())}/{N} proof THẬT hợp lệ")
    print(f"  Partial giả (claim node {forged_evil.party_id}, D sai) -> "
          f"{'BỊ LOẠI' if bad_claim else 'lọt'} (combiner không lừa được)")
    # Combiner giữ lại partial thật -> client vẫn gộp được từ t partial tự chọn
    recovered = combine_and_unwrap(
        [to_compact(proofs[j]) for j in (1, 2, 3)], pub_shares, T, wrapped)
    assert recovered == dek
    print("  Client tự chọn 3 proof hợp lệ -> unwrap DEK đúng, bỏ qua combiner")
    # Combiner che bớt partial -> client thấy < t và fail-closed
    try:
        combine_and_unwrap([to_compact(proofs[1])], pub_shares, T, wrapped)
        raise AssertionError("1 partial phải fail")
    except UnderThresholdError as err:
        print(f"  Combiner che bớt -> UnderThresholdError: {err}")
    results.append("TEST5 combiner non-trust: PASS")

    # =====================================================================
    _banner("TEST 6: REPLAY CROSS-WRAP - PROOF KHÔNG DÙNG LẠI ĐƯỢC")
    # =====================================================================
    # Wrap thứ 2 cho object khác (nonce/ct/C1 đều khác)
    wrapped2 = wrap_dek(dek, threshold_pk,
                        dc_replace(wrap_ctx, object_id="OBJ-5002"))
    assert not verify_dleq(proof1, pub_shares[1], wrapped2.c1,
                           wrapped2.proof_context())
    print("  [6a] Proof của wrap(OBJ-5001) trình cho wrap(OBJ-5002) -> INVALID")
    # Cùng object nhưng nonce mới -> CtDigest đổi -> INVALID
    wrapped3 = wrap_dek(dek, threshold_pk, wrap_ctx)
    assert wrapped3.nonce != wrapped.nonce
    assert not verify_dleq(proof1, pub_shares[1], wrapped3.c1,
                           wrapped3.proof_context())
    print("  [6b] Re-wrap cùng object (nonce/ct/C1 mới) -> INVALID (CtDigest+C1 đổi)")
    results.append("TEST6 no cross-wrap replay: PASS")

    # =====================================================================
    _banner("TEST 7: E2E - PROOF ĐI KÈM PARTIAL, GATE POLICY GĐ2, UNWRAP")
    # =====================================================================
    # Partial từ node (câu 3) + proof full (câu 4) -> combine (câu 3)
    partials_full = []
    for j in (1, 2, 3):
        p_compact = nodes[j].create_partial(wrapped, presented_policy_root=trusted_root,
                                            policy_db=service.policy_records)
        p_full = prove_dleq(j, shares[j], pub_shares[j], c1, p_compact.d_point, proof_ctx)
        assert verify_dleq(p_full, pub_shares[j], c1, proof_ctx)
        partials_full.append(p_full)
    assert combine_and_unwrap([to_compact(p) for p in partials_full],
                              pub_shares, T, wrapped) == dek
    print("  [7a] 3 partial+proof qua policy gate GĐ2 -> unwrap DEK đúng")

    service.transition_policy("OBJ-5001", "REVOKED")
    try:
        nodes[1].create_partial(wrapped, presented_policy_root=trusted_root,
                                policy_db=service.policy_records)
        raise AssertionError("REVOKED phải chặn")
    except PermissionError:
        print("  [7b] REVOKED -> node từ chối tạo partial+proof (gate GĐ2)")
    results.append("TEST7 e2e + policy gate: PASS")

    # =====================================================================
    _banner("BENCHMARK (deliverable 153)")
    # =====================================================================
    t0 = time.time()
    for _ in range(20):
        prove_dleq(1, shares[1], pub_shares[1], c1, d1, proof_ctx)
    per_prove = (time.time() - t0) / 20 * 1000
    t0 = time.time()
    for _ in range(20):
        verify_dleq(proof1, pub_shares[1], c1, proof_ctx)
    per_verify = (time.time() - t0) / 20 * 1000
    print(f"- prove_dleq: {per_prove:.1f} ms/node | verify_dleq: {per_verify:.1f} ms/proof")
    print(f"- (verify = 1 hash + 4 scalar mul; prove = 2 scalar mul + 1 hash)")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => Mỗi partial decryption đi kèm proof Chaum-Pedersen DLEQ")
    print("     gắn object/ciphertext/epoch/policy root (145); verifier độc lập")
    print("     (152) phát hiện mọi partial sai (154); combiner không còn là")
    print("     trust bottleneck vì client tự verify (155); proof zero-knowledge.")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
