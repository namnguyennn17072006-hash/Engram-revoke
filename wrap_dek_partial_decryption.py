"""
================================================================================
GIAI ĐOẠN 3 - THRESHOLD KEY SERVICE
Lời giải câu 3: "Wrap DEK dưới threshold public key; mỗi node tạo partial
                   decryption."

Gợi ý áp dụng (từ 03_Huong_dan_nghien_cuu, mục 142-154):
- (144) "Threshold ElGamal chỉ mã hóa/wrap DEK ngắn, không mã hóa payload lớn"
      => wrap_dek CHỈ nhận DEK 32 bytes (64B bị chặn ValueError);
         payload lớn do client mã hóa riêng bằng chính DEK này.
- (145) "Partial decryptions phải bind object, ciphertext, epoch và policy root"
      => WrapContext = (ObjectID, Version, PolicyHash, CodecID, Epoch, PolicyRoot)
         + AAD của AEAD;
         CHAUM-PEDERSEN CHALLENGE gắn thêm CtDigest = SHA256(nonce||ct)
         => partial gắn cả 4 yếu tố: object + ciphertext + epoch + policy root.
         (Đây là nâng cấp so với wrapDEK.py chỉ có AAD tĩnh.)
- (146) "Ngưỡng t chọn từ threat model và liveness target" -> t=3/n=5 (chịu 2 node chết).
- (152) "Independent partial proof verifier" -> verify_partial() độc lập,
         mọi client tự xác minh, không cần tin node nào.
- Cổng nghiệm thu (154): dưới t partial không unwrap; partial sai bị phát hiện;
      >= t node thật vẫn phục vụ khi node khác offline.

Pipeline trong file này (tái sử dụng TOÀN BỘ code trước):
  GĐ1 PolicyLogService   -> policy log, sự kiện ACTIVE/REVOKED (sign Ed25519)
  GĐ2 EngramAnchorBridge + KeyNodeTrustedRootOracle
                          -> epoch + policy root thật để đưa vào binding
  GĐ3 vss_share_verification (câu 2)
                          -> FeldmanVSS phân phối share cho 5 node,
                             MỖI node (VSSMember) tự xác minh share NHẬN ĐƯỢC
                             trước khi trở thành threshold node (chống share giả)
  GĐ3 dkg_threshold_service (câu 1)
                          -> ECPoint/G/N/hash_to_scalar/Lagrange/UnderThresholdError
                             (cùng curve với Chaum-Pedersen)
================================================================================
"""

import os
import time
import hashlib
import random
from dataclasses import dataclass, replace as dc_replace
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- Tái sử dụng câu 1: dkg_threshold_service -------------------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    hash_to_scalar,
    lagrange_coefficient,
    UnderThresholdError,
)

# --- Tái sử dụng câu 2: vss_share_verification ------------------------------
from vss_share_verification import (
    FeldmanVSS,
    VSSMember,
    sign_broadcast,
    committee_keygen,
)

# --- Tái sử dụng GĐ1 & GĐ2 --------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
)

_RNG = random.SystemRandom()


# =============================================================================
# 1. WRAP CONTEXT - BINDING THEO GỢI Ý (145): object + epoch + policy root,
#    được nâng cấp thêm CtDigest (ciphertext) ở proof_context().
# =============================================================================
@dataclass(frozen=True)
class WrapContext:
    object_id: str
    version: int
    policy_hash: str
    codec_id: str
    epoch: int
    policy_root: str

    def aad(self) -> bytes:
        """
        AAD cho AEAD - GIỮ ĐỊNH DẠNG wrapDEK.py (ObjectID|Version|PolicyHash|CodecID)
        + Epoch|PolicyRoot theo gợi ý (145).
        """
        return (
            f"ObjectID:{self.object_id}|Version:{self.version}"
            f"|PolicyHash:{self.policy_hash}|CodecID:{self.codec_id}"
            f"|Epoch:{self.epoch}|PolicyRoot:{self.policy_root}"
        ).encode("utf-8")

    def proof_context(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Ngữ cảnh cho Chaum-Pedersen challenge = AAD + CtDigest(nonce||ct).
        => Partial decryption gắn ĐỦ object, ciphertext, epoch, policy root (145).
        """
        ct_digest = hashlib.sha256(nonce + ciphertext).hexdigest()
        return self.aad() + f"|CtDigest:{ct_digest}".encode("utf-8")


@dataclass
class ThresholdWrappedDEK:
    c1: ECPoint                 # ephemeral r * G
    nonce: bytes
    ciphertext: bytes           # DEK 32B đã bọc
    context: WrapContext

    def proof_context(self) -> bytes:
        return self.context.proof_context(self.nonce, self.ciphertext)


@dataclass
class PartialWithProof:
    """Partial decryption + Chaum-Pedersen DLEQ proof (GĐ3 câu 4)."""
    party_id: int
    d_point: ECPoint            # D_j = x_j * C1
    proof_c: int
    proof_z: int


# =============================================================================
# 2. WRAP DEK DƯỚI THRESHOLD PUBLIC KEY (gợi ý 144)
# =============================================================================
def wrap_dek(dek: bytes, threshold_public_key: ECPoint, context: WrapContext) -> ThresholdWrappedDEK:
    """
    Threshold EC-ElGamal/ECIES wrap:
      r random; C1 = r*G; K = r*Y; wrap_key = HKDF(K, info=AAD);
      ct = AES-GCM(wrap_key, dek, AAD).
    CHỈ wrap DEK ngắn (144) - payload lớn do client tự mã hóa bằng DEK.
    """
    if len(dek) != 32:
        raise ValueError(
            f"Threshold ElGamal chỉ wrap DEK 32 bytes (mục 144), nhận {len(dek)}B - "
            "payload lớn phải được client mã hóa riêng bằng DEK."
        )
    if threshold_public_key.is_infinity():
        raise ValueError("Threshold public key không hợp lệ")
    r = _RNG.randrange(1, N_ORDER)
    c1 = r * G
    shared = r * threshold_public_key
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=context.aad()).derive(shared.to_bytes())
    nonce = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(nonce, dek, context.aad())
    return ThresholdWrappedDEK(c1=c1, nonce=nonce, ciphertext=ct, context=context)


# =============================================================================
# 3. MỖI NODE TẠO PARTIAL DECRYPTION (Chaos-Pedersen DLEQ bound theo 145)
# =============================================================================
class ThresholdWrapNode:
    """
    Node t-of-n. Giữ share x_j đã được VSS xác minh (câu 2) + oracle GĐ2.
    - Gate policy: nếu có oracle -> resolve_fresh_policy TRƯỚC khi phát partial
      (stale root / REVOKED / fail-closed -> KHÔNG tạo partial).
    - Tạo D_j = x_j*C1 kèm proof Chaum-Pedersen với challenge gắn
      (object, ciphertext digest, epoch, policy root).
    """

    def __init__(self, party_id: int, share: int, public_share: ECPoint,
                 threshold: int, oracle: Optional[KeyNodeTrustedRootOracle] = None):
        self.party_id = party_id
        self.share = share
        self.public_share = public_share
        self.threshold = threshold
        self.oracle = oracle

    def create_partial(
        self,
        wrapped: ThresholdWrappedDEK,
        presented_policy_root: Optional[str] = None,
        policy_db: Optional[Dict[str, dict]] = None,
    ) -> PartialWithProof:
        # --- Policy gate: tái sử dụng oracle GĐ2 (fail-closed) ---
        if self.oracle is not None:
            self.oracle.resolve_fresh_policy(
                wrapped.context.object_id, presented_policy_root, policy_db)

        c1 = wrapped.c1
        if c1.is_infinity() or c1 == G:
            raise ValueError("C1 degenerate - không tạo partial")
        d_point = self.share * c1

        # --- Chaum-Pedersen: log_G(Y_j) == log_{C1}(D_j), challenge gắn context ---
        proof_ctx = wrapped.proof_context()
        u = _RNG.randrange(1, N_ORDER)
        a_point = u * G
        b_point = u * c1
        c = hash_to_scalar(G, self.public_share, c1, d_point, a_point, b_point, proof_ctx)
        z = (u + c * self.share) % N_ORDER
        return PartialWithProof(self.party_id, d_point, c, z)


# =============================================================================
# 4. INDEPENDENT VERIFIER + COMBINER (gợi ý 152: verifier độc lập)
# =============================================================================
def verify_partial(partial: PartialWithProof, public_share: ECPoint,
                   c1: ECPoint, proof_context: bytes) -> bool:
    """Client/combiner nào cũng tự xác minh được - không phụ thuộc node."""
    a_prime = (partial.proof_z * G) - (partial.proof_c * public_share)
    b_prime = (partial.proof_z * c1) - (partial.proof_c * partial.d_point)
    c_recomputed = hash_to_scalar(G, public_share, c1, partial.d_point,
                                  a_prime, b_prime, proof_context)
    return c_recomputed == partial.proof_c


def combine_and_unwrap(partials: List[PartialWithProof],
                       public_key_shares: Dict[int, ECPoint],
                       threshold: int,
                       wrapped: ThresholdWrappedDEK) -> bytes:
    """
    Combiner: xác minh từng proof theo proof_context (gắn object/ct/epoch/root),
    loại partial sai, giữ >= t phần hợp lệ, Lagrange -> K = r*Y -> unwrap DEK.
    """
    proof_ctx = wrapped.proof_context()
    valid: List[PartialWithProof] = []
    rejected: List[int] = []
    for p in partials:
        y_j = public_key_shares.get(p.party_id)
        if y_j is None or not verify_partial(p, y_j, wrapped.c1, proof_ctx):
            rejected.append(p.party_id)
        else:
            valid.append(p)

    if len(valid) < threshold:
        raise UnderThresholdError(
            f"Chỉ có {len(valid)}/{threshold} partial hợp lệ "
            f"(bị loại: {rejected}) - không unwrap được DEK.")

    subset = valid[:threshold]
    combined = ECPoint(None, None)
    for p in subset:
        lam = lagrange_coefficient(p.party_id, [q.party_id for q in subset])
        combined = combined + (lam * p.d_point)

    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=wrapped.context.aad()).derive(combined.to_bytes())
    try:
        return AESGCM(wrap_key).decrypt(wrapped.nonce, wrapped.ciphertext,
                                        wrapped.context.aad())
    except InvalidTag as err:
        raise UnderThresholdError(f"AEAD tag sai - bộ partial không tái tạo đúng K: {err}")


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 5. DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    N, T = 5, 3                      # (146) t=3/n=5 từ threat model: chịu 2 node chết

    # ------------------------------------------------------------------
    # PIPELINE SETUP: GĐ1 + GĐ2 -> context thật; VSS (câu 2) -> shares
    # ------------------------------------------------------------------
    _banner("PIPELINE: POLICY LOG (GĐ1) + ANCHOR ORACLE (GĐ2) + VSS (CÂU 2)")

    # GĐ1: policy log với event ký Ed25519
    authority_sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(authority_sk)
    event, leaf_idx, root_hex = service.init_policy("OBJ-4001", initial_epoch=1)
    policy_hash = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()

    # GĐ2: anchor epoch 1 + oracle latest trusted root
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    bridge.anchor_epoch(1, service.mmr)
    oracle = KeyNodeTrustedRootOracle(bridge.bridge_pk,
                                      FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    trusted_root = oracle.get_latest_trusted_root()
    print(f"- Latest trusted root (GĐ2) = {trusted_root[:32]}...")

    # CÂU 2: FeldmanVSS phân phối share; MỖI node xác minh trước khi nhận
    vss_ctx = f"wrap-pipeline|epoch=1|root={trusted_root}"
    dealer_sks, dealer_pks = committee_keygen(N)
    feldman = {i: FeldmanVSS(i, T, rng=random.Random(4000 + i)) for i in range(1, N + 1)}
    vss_members = {j: VSSMember(j, vss_ctx, dealer_pks) for j in range(1, N + 1)}
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            share = feldman[i].share_for(j)
            sig = sign_broadcast(dealer_sks[i], vss_ctx, i, feldman[i].commitments)
            vss_members[j].check_feldman_share(i, share, feldman[i].commitments, sig)
    assert all(m.report.all_ok for m in vss_members.values())
    print(f"- VSS: {N}x{N} share đều được từng node xác minh (Feldman, chữ ký ctx OK)")

    # Xây threshold key từ share ĐÃ VSS-VERIFY (không ai có full key)
    shares = {j: sum(feldman[i].share_for(j) for i in range(1, N + 1)) % N_ORDER
              for j in range(1, N + 1)}
    threshold_pk = ECPoint(None, None)
    for i in range(1, N + 1):
        threshold_pk = threshold_pk + feldman[i].commitments[0]
    # Kiểm chứng: 3 share nội suy ra đúng Y
    acc = ECPoint(None, None)
    for j in (1, 2, 3):
        acc = acc + (lagrange_coefficient(j, [1, 2, 3]) * (shares[j] * G))
    assert acc == threshold_pk
    print(f"- Threshold public key Y = {format(threshold_pk.x, 'x')[:32]}... "
          f"(tái tạo đúng từ 3/5 share)")

    nodes = {j: ThresholdWrapNode(j, shares[j], shares[j] * G, T, oracle=oracle)
             for j in range(1, N + 1)}

    # ------------------------------------------------------------------
    _banner("TEST 1: WRAP DEK DƯỚI THRESHOLD PUBLIC KEY (gợi ý 144)")
    # ------------------------------------------------------------------
    dek = os.urandom(32)
    wrap_ctx = WrapContext(object_id="OBJ-4001", version=1, policy_hash=policy_hash,
                           codec_id="JSON-GCM-v1", epoch=1, policy_root=trusted_root)
    t0 = time.time()
    wrapped = wrap_dek(dek, threshold_pk, wrap_ctx)
    wrap_ms = (time.time() - t0) * 1000
    print(f"- DEK 32B -> ciphertext {len(wrapped.ciphertext)}B + C1 33B "
          f"(wrap {wrap_ms:.2f} ms) - KHÔNG mã hóa payload lớn (144)")
    print(f"- AAD = {wrap_ctx.aad().decode()[:90]}...")

    # Chặn wrap sai kích thước
    try:
        wrap_dek(os.urandom(64), threshold_pk, wrap_ctx)
        raise AssertionError("Phải chặn DEK 64B")
    except ValueError as err:
        print(f"- 64B payload bị chặn: {err}")
    results.append("TEST1 wrap-under-Y: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 2: MỖI NODE TẠO PARTIAL DECRYPTION + GỘP >= T")
    # ------------------------------------------------------------------
    all_partials: List[PartialWithProof] = []
    for j in range(1, N + 1):
        t0 = time.time()
        p = nodes[j].create_partial(wrapped, presented_policy_root=trusted_root,
                                    policy_db=service.policy_records)
        ms = (time.time() - t0) * 1000
        all_partials.append(p)
        print(f"  - Node {j}: D_j = x_j*C1 + Chaum-Pedersen proof  ({ms:.1f} ms)")

    # 2 node offline (4,5) vẫn đủ t=3 -> unwrap OK
    recovered = combine_and_unwrap(all_partials[:3], {j: shares[j] * G for j in shares},
                                   T, wrapped)
    assert recovered == dek
    print("- PASS: nodes 1,2,3 (4,5 offline) gộp 3 partial -> unwrap DEK đúng")
    results.append("TEST2 per-node partials: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 3: BINDING (145) - PARTIAL GẮN OBJECT/CT/EPOCH/POLICY ROOT")
    # ------------------------------------------------------------------
    p1 = all_partials[0]
    y1 = shares[1] * G
    good_ctx = wrapped.proof_context()

    assert verify_partial(p1, y1, wrapped.c1, good_ctx)
    print("  [3a] Proof với ngữ cảnh gốc (object+ct+epoch+root) -> VALID")

    wrong_obj = dc_replace(wrap_ctx, object_id="OBJ-EVIL").proof_context(wrapped.nonce, wrapped.ciphertext)
    assert not verify_partial(p1, y1, wrapped.c1, wrong_obj)
    print("  [3b] Đổi ObjectID -> proof INVALID (partial không giả mạo được object)")

    wrong_epoch = dc_replace(wrap_ctx, epoch=99).proof_context(wrapped.nonce, wrapped.ciphertext)
    assert not verify_partial(p1, y1, wrapped.c1, wrong_epoch)
    print("  [3c] Đổi Epoch -> proof INVALID (chống replay cross-epoch)")

    wrong_root = dc_replace(wrap_ctx, policy_root="ee" * 32).proof_context(wrapped.nonce, wrapped.ciphertext)
    assert not verify_partial(p1, y1, wrapped.c1, wrong_root)
    print("  [3d] Đổi PolicyRoot -> proof INVALID (gắn policy root theo 145)")

    tampered_ct = bytearray(wrapped.ciphertext)
    tampered_ct[0] ^= 0x01
    wrong_ct = wrap_ctx.proof_context(wrapped.nonce, bytes(tampered_ct))
    assert not verify_partial(p1, y1, wrapped.c1, wrong_ct)
    print("  [3e] Tráo ciphertext (CtDigest đổi) -> proof INVALID (gắn ciphertext theo 145)")

    # Ghép partial đúng nhưng wrapped có context khác -> combiner loại TOÀN BỘ
    wrapped_wrong = ThresholdWrappedDEK(c1=wrapped.c1, nonce=wrapped.nonce,
                                        ciphertext=wrapped.ciphertext,
                                        context=dc_replace(wrap_ctx, object_id="OBJ-X"))
    try:
        combine_and_unwrap(all_partials, {j: shares[j] * G for j in shares}, T, wrapped_wrong)
        raise AssertionError("Phải fail do mọi proof bị loại")
    except UnderThresholdError as err:
        print(f"  [3f] Combiner với context sai -> mọi partial bị loại: {err}")
    results.append("TEST3 binding object/ct/epoch/root: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 4: PARTIAL SAI BỊ LOẠI (compromised-node, gợi ý 152)")
    # ------------------------------------------------------------------
    evil = ThresholdWrapNode(4, (shares[4] + 1) % N_ORDER, shares[4] * G, T)
    forged = evil.create_partial(wrapped)
    assert not verify_partial(forged, shares[4] * G, wrapped.c1, wrapped.proof_context())
    print("- Node 4 (share sửa) -> proof INVALID, combiner loại (rejected=[4])")

    forged.d_point = _RNG.randrange(1, N_ORDER) * G
    assert not verify_partial(forged, shares[4] * G, wrapped.c1, wrapped.proof_context())
    print("- Tráo D_point -> verifier độc lập vẫn phát hiện")

    mixed = all_partials[:3] + [forged]
    assert combine_and_unwrap(mixed, {j: shares[j] * G for j in shares}, T, wrapped) == dek
    print("- Ghép 3 partial thật + 1 giả -> unwrap vẫn OK (loại được giả)")
    results.append("TEST4 forged partial rejected: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 5: DƯỚI T PARTIAL -> KHÔNG UNWRAP (cổng nghiệm thu 154)")
    # ------------------------------------------------------------------
    try:
        combine_and_unwrap(all_partials[:2], {j: shares[j] * G for j in shares}, T, wrapped)
        raise AssertionError("2 partial phải fail")
    except UnderThresholdError as err:
        print(f"- Đúng như dự kiến: {err}")
    results.append("TEST5 under-threshold: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 6: POLICY GATE - NODE TỪ CHỐI TẠO PARTIAL (GĐ2)")
    # ------------------------------------------------------------------
    try:
        nodes[1].create_partial(wrapped, presented_policy_root="00" * 32,
                                policy_db=service.policy_records)
        raise AssertionError("Stale root phải bị chặn")
    except StaleRootError:
        print("  [6a] Stale root -> node KHÔNG tạo partial (fail-closed)")

    service.transition_policy("OBJ-4001", "REVOKED")
    denied = 0
    for j in (1, 2, 3):
        try:
            nodes[j].create_partial(wrapped, presented_policy_root=trusted_root,
                                    policy_db=service.policy_records)
        except PermissionError:
            denied += 1
    assert denied == 3
    print(f"  [6b] REVOKED -> {denied}/3 node từ chối tạo partial")
    try:
        combine_and_unwrap([], {j: shares[j] * G for j in shares}, T, wrapped)
        raise AssertionError("0 partial phải fail")
    except UnderThresholdError:
        print("  [6c] 0 partial -> UnderThresholdError: DEK không thể mở sau khi revoke")
    results.append("TEST6 policy gate: PASS")

    # ------------------------------------------------------------------
    _banner("TEST 7: VSS GATE (CÂU 2) - SHARE PHẢI QUA KIỂM TRA TRƯỚC KHI NODE DÙNG")
    # ------------------------------------------------------------------
    # Broadcast sai chữ ký -> member từ chối -> share không được đưa vào node
    m2 = VSSMember(2, vss_ctx, dealer_pks)
    bad_sig = m2.check_feldman_share(1, feldman[1].share_for(2),
                                     feldman[1].commitments, None)
    assert not bad_sig.ok
    print(f"  [7a] Broadcast thiếu chữ ký -> member 2 từ chối: {bad_sig.reason}")

    # Broadcast với context khác (replay) -> từ chối
    m3 = VSSMember(3, f"wrap-pipeline|epoch=1|root={'ff'*32}", dealer_pks)
    stale_sig = sign_broadcast(dealer_sks[1], vss_ctx, 1, feldman[1].commitments)
    stale = m3.check_feldman_share(1, feldman[1].share_for(3),
                                   feldman[1].commitments, stale_sig)
    assert not stale.ok
    print(f"  [7b] Replay context cũ -> member 3 từ chối: {stale.reason}")
    print("- Node share chỉ được nhận qua Feldman VSS verified (câu 2) trước khi")
    print("  được dùng cho partial decryption ở pipeline wrap này.")
    results.append("TEST7 VSS gate before node share: PASS")

    # ------------------------------------------------------------------
    _banner("BENCHMARK (deliverable 153: threshold latency)")
    # ------------------------------------------------------------------
    t0 = time.time()
    for _ in range(20):
        wrap_dek(dek, threshold_pk, wrap_ctx)
    per_wrap = (time.time() - t0) / 20 * 1000

    t0 = time.time()
    for _ in range(20):
        verify_partial(p1, y1, wrapped.c1, wrapped.proof_context())
    per_verify = (time.time() - t0) / 20 * 1000

    t0 = time.time()
    combine_and_unwrap(all_partials, {j: shares[j] * G for j in shares}, T, wrapped)
    per_combine = (time.time() - t0) * 1000
    print(f"- wrap_dek: {per_wrap:.1f} ms | create_partial: ~{ms:.1f} ms/node")
    print(f"- verify 1 proof: {per_verify:.1f} ms | combine>=3 + unwrap: {per_combine:.1f} ms")

    # ------------------------------------------------------------------
    _banner("KẾT LUẬN")
    # ------------------------------------------------------------------
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => DEK 32B được wrap dưới threshold key Y (144); MỖI node tạo")
    print("     partial + Chaum-Pedersen proof gắn object/ciphertext/epoch/policy root")
    print("     (145); verifier độc lập (152); dưới t partial không mở được (154);")
    print("     shares đến node phải qua VSS check của câu 2.")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
