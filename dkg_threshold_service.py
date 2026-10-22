"""
================================================================================
GIAI ĐOẠN 3 - THRESHOLD KEY SERVICE
Lời giải câu: "Cài DKG để không có trusted dealer nắm full private key."

Gợi ý áp dụng (từ 03_Huong_dan_nghien_cuu, mục 142-149):
- Pedersen DKG; Feldman VSS (commitment công khai) cho mỗi thành viên kiểm tra share.
- Threshold ElGamal chỉ mã hóa/wrap DEK ngắn (32 bytes), không mã hóa payload lớn.
- Partial decryptions bind object, ciphertext, epoch và policy root.
- Chaum-Pedersen (DLEQ) proof chứng minh partial decryption đúng.
- Combiner loại partial sai, gộp >= t phần hợp lệ.
- Ngưỡng t lấy từ threat model (đặt t=3/n=5: chịu được 2 node chết - liveness target).
- Prototype academic/not production (chưa audit).

Cổng nghiệm thu:
  [x] Dưới t shares không unwrap được DEK
  [x] Partial decryption sai bị phát hiện (Chaum-Pedersen reject)
  [x] Ít nhất t node hợp lệ vẫn phục vụ khi node khác offline
  [x] DKG-abort: QUAL < t thì hủy, không bao giờ sinh key lệch

Tái sử dụng code trước đó:
- signedandapend_events.PolicyLogService    -> policy log + terminal invariant (GĐ1)
- anchorroot.EngramAnchorBridge             -> neo MMR root theo epoch (GĐ2)
- freshnesswindowandlatesttrustedroot.KeyNodeTrustedRootOracle
      -> mỗi node chỉ phát partial khi policy ACTIVE và root còn tươi (GĐ2)
- wrapDEK.py                                -> giữ nguyên định dạng AAD binding
      (ObjectID|Version|PolicyHash|CodecID) và bổ sung Epoch|PolicyRoot (GĐ3)
================================================================================
"""

import os
import time
import hashlib
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
    FailClosedFreshnessError,
)

_RNG = random.SystemRandom()


# =============================================================================
# 1. TOÁN HỌC ELLIPTIC CURVE secp256k1 (pure Python - academic, not production)
#    cryptography chỉ cấp ECDSA/ECDH nên tự cài phép toán điểm cho DKG/VSS.
# =============================================================================
P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A_CURVE = 0
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ECPoint:
    """Điểm trên secp256k1. Ô (0,0) biểu diễn điểm vô cực dùng (None, None)."""

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y

    def __add__(self, other: "ECPoint") -> "ECPoint":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        if self.x == other.x:
            if self.y != other.y or self.y == 0:
                return ECPoint(None, None)
            lam = (3 * self.x * self.x + A_CURVE) * pow(2 * self.y, P_CURVE - 2, P_CURVE) % P_CURVE
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, P_CURVE - 2, P_CURVE) % P_CURVE
        x3 = (lam * lam - self.x - other.x) % P_CURVE
        y3 = (lam * (self.x - x3) - self.y) % P_CURVE
        return ECPoint(x3, y3)

    def __neg__(self) -> "ECPoint":
        if self.is_infinity():
            return self
        return ECPoint(self.x, (P_CURVE - self.y) % P_CURVE)

    def __sub__(self, other: "ECPoint") -> "ECPoint":
        return self + (-other)

    def __rmul__(self, scalar: int) -> "ECPoint":
        scalar = scalar % N_ORDER
        if scalar == 0 or self.is_infinity():
            return ECPoint(None, None)
        result = ECPoint(None, None)
        current = self
        while scalar > 0:
            if scalar & 1:
                result = result + current
            current = current + current
            scalar >>= 1
        return result

    def to_bytes(self) -> bytes:
        """Điểm nén 33 bytes (02/03 || x) - dùng trong Fiat-Shamir hash."""
        if self.is_infinity():
            return b"\x00" * 33
        prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
        return prefix + self.x.to_bytes(32, "big")


G = ECPoint(Gx, Gy)


def hash_to_scalar(*items) -> int:
    """Fiat-Shamir: băm (điểm, byte, số, chuỗi) -> vô cùng trường Z_N."""
    h = hashlib.sha256()
    for item in items:
        if isinstance(item, ECPoint):
            h.update(item.to_bytes())
        elif isinstance(item, bytes):
            h.update(item)
        elif isinstance(item, int):
            h.update(item.to_bytes(32, "big"))
        elif isinstance(item, str):
            h.update(item.encode("utf-8"))
        else:
            raise TypeError(f"Không hỗ trợ kiểu trong hash: {type(item)}")
    return int.from_bytes(h.digest(), "big") % N_ORDER


# =============================================================================
# 2. VSS: Đánh giá đa thức + Lagrange interpolation (chia sẻ bí mật ẩn)
# =============================================================================
def evaluate_polynomial(coeffs: List[int], x: int) -> int:
    """Tính f(x) theo Horner modulo N."""
    value = 0
    for c in reversed(coeffs):
        value = (value * x + c) % N_ORDER
    return value


def lagrange_coefficient(i: int, indices: List[int]) -> int:
    """Hệ số Lagrange lambda_i nội suy tại 0."""
    num, den = 1, 1
    for j in indices:
        if j != i:
            num = (num * (-j)) % N_ORDER
            den = (den * (i - j)) % N_ORDER
    return (num * pow(den, N_ORDER - 2, N_ORDER)) % N_ORDER


# =============================================================================
# 3. PEDERSEN DKG - KHÔNG CÓ TRUSTED DEALER
#    Round 1: mỗi party i tự sinh đa thức f_i bậc (t-1) với a_{i,0} ngẫu nhiên,
#             broadcast commitment C_{i,k} = a_{i,k} * G (Feldman VSS),
#             gửi share riêng s_{i,j} = f_i(j) cho party j.
#    Round 2: party j xác minh s_{i,j} * G == sum_k j^k * C_{i,k}; lỗi -> complaint.
#    Round 3: QUAL = ban hợp lệ; x_j = sum_{i in QUAL} s_{i,j};
#             Y = sum_i C_{i,0} (không ai biết x = log_G(Y)).
# =============================================================================
class DKGAbortError(Exception):
    """DKG bị hủy: QUAL < t (partition/lỗi majority) - key service không sinh ra."""


class UnderThresholdError(Exception):
    """Không đủ t partial hợp lệ để unwrap DEK."""


@dataclass
class DKGResult:
    threshold: int
    committee_size: int
    joint_public_key: ECPoint                    # Y = sum C_{i,0}
    public_key_shares: Dict[int, ECPoint]        # Y_j = x_j * G
    private_shares: Dict[int, int]               # x_j - CHỈ share của chính mình
    qualified_parties: List[int]

    def reconstruct_public_key(self, subset: List[int]) -> ECPoint:
        """Kiểm chứng: nội suy Y_j trên subset size t phải ra Y (không cần private key)."""
        acc = ECPoint(None, None)
        for j in subset:
            lam = lagrange_coefficient(j, subset)
            acc = acc + (lam * self.public_key_shares[j])
        return acc


class DKGParty:
    """Một thành viên ủy ban. Lưu poly của mình + share cuối - KHÔNG có full key."""

    def __init__(self, party_id: int, committee_size: int, threshold: int, rng=None):
        if threshold > committee_size:
            raise ValueError("t không được vượt quá n")
        self.party_id = party_id
        self.n = committee_size
        self.t = threshold
        self.rng = rng or _RNG
        self.coeffs: Optional[List[int]] = None
        self.commitments: Optional[List[ECPoint]] = None
        self.share: Optional[int] = None          # x_j sau Round 3
        self.public_share: Optional[ECPoint] = None

    def round1_generate(self) -> List[ECPoint]:
        """Sinh poly bí mật bậc (t-1) và commitment công khai. Không cần dealer."""
        self.coeffs = [self.rng.randrange(1, N_ORDER) for _ in range(self.t)]
        self.commitments = [c * G for c in self.coeffs]
        return list(self.commitments)

    def share_for(self, receiver_id: int) -> int:
        """Share riêng s_{i,j} = f_i(j) gửi qua kênh riêng (prototype: in-memory)."""
        if self.coeffs is None:
            raise RuntimeError("Round 1 chưa chạy")
        return evaluate_polynomial(self.coeffs, receiver_id)

    @staticmethod
    def verify_share(receiver_id: int, share: int, commitments: List[ECPoint]) -> bool:
        """VSS verification: s*G == sum_k (receiver^k) * C_k. Mọi receiver tự làm."""
        if share is None or not commitments:
            return False
        lhs = share * G
        rhs = ECPoint(None, None)
        power = 1
        for c_k in commitments:
            rhs = rhs + (power * c_k)
            power = (power * receiver_id) % N_ORDER
        return lhs == rhs

    def finalize(self, share: int):
        self.share = share % N_ORDER
        self.public_share = share * G


def run_pedersen_dkg(
    party_ids: List[int],
    threshold: int,
    share_tamper: Optional[Callable[[int, int, int], int]] = None,
) -> Tuple[DKGResult, Dict[int, DKGParty]]:
    """
    Điều phối Pedersen DKG 3 round.
    - share_tamper(sender, receiver, share): hook giả lập attacker làm sai share
      (dùng cho invalid-share / DKG-abort tests).
    - Complaint resolution: receiver khiếu nại -> hỏi lại sender; share vẫn sai
      -> sender bị loại khỏi QUAL. QUAL < t -> DKGAbortError.
    """
    n = len(party_ids)
    parties = {pid: DKGParty(pid, n, threshold) for pid in party_ids}

    # ---- Round 1: broadcast commitments ----
    commitments: Dict[int, List[ECPoint]] = {}
    for pid in party_ids:
        commitments[pid] = parties[pid].round1_generate()

    # ---- Phân phối share qua kênh riêng ----
    delivered: Dict[Tuple[int, int], int] = {}   # (sender, receiver) -> share
    for sender in party_ids:
        for receiver in party_ids:
            s = parties[sender].share_for(receiver)
            if share_tamper is not None:
                s = share_tamper(sender, receiver, s)
            delivered[(sender, receiver)] = s

    # ---- Round 2: VSS verify + complaint resolution ----
    disqualified: set = set()
    for receiver in party_ids:
        complaints: List[int] = []
        for sender in party_ids:
            share = delivered[(sender, receiver)]
            if not DKGParty.verify_share(receiver, share, commitments[sender]):
                complaints.append(sender)
        # Giải quyết: hỏi lại sender (attacker vẫn gửi sai -> loại khỏi QUAL)
        for sender in complaints:
            resend = parties[sender].share_for(receiver)
            if share_tamper is not None:
                resend = share_tamper(sender, receiver, resend)
            if not DKGParty.verify_share(receiver, resend, commitments[sender]):
                disqualified.add(sender)

    qual = [pid for pid in party_ids if pid not in disqualified]
    if len(qual) < threshold:
        raise DKGAbortError(
            f"DKG ABORT: QUAL={len(qual)} < t={threshold} "
            f"(disqualified={sorted(disqualified)}) - không sinh key lệch."
        )

    # ---- Round 3: gom share từ ban hợp lệ ----
    private_shares: Dict[int, int] = {}
    public_shares: Dict[int, ECPoint] = {}
    for receiver in qual:
        x_j = sum(delivered[(sender, receiver)] for sender in qual) % N_ORDER
        parties[receiver].finalize(x_j)
        private_shares[receiver] = x_j
        public_shares[receiver] = x_j * G

    joint_public_key = ECPoint(None, None)
    for pid in qual:
        joint_public_key = joint_public_key + commitments[pid][0]

    result = DKGResult(
        threshold=threshold,
        committee_size=n,
        joint_public_key=joint_public_key,
        public_key_shares=public_shares,
        private_shares=private_shares,
        qualified_parties=qual,
    )
    return result, parties


# =============================================================================
# 4. THRESHOLD EC-ELGAMAL WRAP DEK + PARTIAL DECRYPTION (Chaum-Pedersen DLEQ)
# =============================================================================
@dataclass
class ThresholdWrappedDEK:
    c1: ECPoint                 # ephemeral r * G
    nonce: bytes                # AES-GCM nonce
    ciphertext: bytes           # DEK đã bọc (32 bytes plaintext)
    binding: bytes              # AAD = ObjectID|Version|PolicyHash|CodecID|Epoch|PolicyRoot


@dataclass
class PartialDecryption:
    party_id: int
    d_point: ECPoint            # D_j = x_j * C1
    proof_c: int                # challenge (Fiat-Shamir)
    proof_z: int                # response z = u + c*x_j


def make_binding(object_id: str, version: int, policy_hash: str,
                 codec_id: str, epoch: int, policy_root: str) -> bytes:
    """
    Binding theo gợi ý 'partial decryptions phải bind object, ciphertext,
    epoch và policy root'. Giữ định dạng AAD của wrapDEK.py, thêm Epoch|PolicyRoot.
    """
    return (
        f"ObjectID:{object_id}|Version:{version}|PolicyHash:{policy_hash}"
        f"|CodecID:{codec_id}|Epoch:{epoch}|PolicyRoot:{policy_root}"
    ).encode("utf-8")


def wrap_dek(dek: bytes, joint_public_key: ECPoint, binding: bytes) -> ThresholdWrappedDEK:
    """Threshold EC-ElGamal/ECIES: bọc DEK ngắn dưới Y = x*G."""
    if len(dek) != 32:
        raise ValueError("Threshold ElGamal ở đây chỉ wrap DEK 32 bytes")
    if joint_public_key.is_infinity():
        raise ValueError("Joint public key không hợp lệ")
    r = _RNG.randrange(1, N_ORDER)
    c1 = r * G
    shared = r * joint_public_key
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=binding).derive(shared.to_bytes())
    nonce = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(nonce, dek, binding)
    return ThresholdWrappedDEK(c1=c1, nonce=nonce, ciphertext=ct, binding=binding)


class ThresholdKeyNode:
    """
    Node trong ủy ban t-of-n. Giữ (x_j, Y_j) + oracle policy GĐ2.
    Chỉ phát partial decryption khi policy ACTIVE và root còn tươi (fail-closed).
    """

    def __init__(self, party_id: int, share: int, public_share: ECPoint,
                 threshold: int, oracle: Optional[KeyNodeTrustedRootOracle] = None):
        self.party_id = party_id
        self.share = share
        self.public_share = public_share
        self.threshold = threshold
        self.oracle = oracle

    def partial_decrypt(
        self,
        wrapped: ThresholdWrappedDEK,
        object_id: Optional[str] = None,
        presented_policy_root: Optional[str] = None,
        policy_db: Optional[Dict[str, dict]] = None,
    ) -> PartialDecryption:
        """
        Tạo D_j = x_j * C1 kèm Chaum-Pedersen proof:
        chứng minh log_G(Y_j) == log_{C1}(D_j) mà không lộ x_j.
        Tích hợp GĐ2: nếu có oracle thì gate bằng resolve_fresh_policy
        (stale root / REVOKED / fail-closed -> KHÔNG phát partial).
        """
        # --- Policy gate (tái sử dụng GĐ2) ---
        if self.oracle is not None:
            self.oracle.resolve_fresh_policy(object_id, presented_policy_root, policy_db)

        c1 = wrapped.c1
        if c1.is_infinity() or c1 == G:
            raise ValueError("C1 degenerate - không tạo partial")

        d_point = self.share * c1

        # --- Chaum-Pedersen DLEQ: log_G(Y_j) = log_{C1}(D_j) ---
        u = _RNG.randrange(1, N_ORDER)
        a_point = u * G
        b_point = u * c1
        c = hash_to_scalar(G, self.public_share, c1, d_point, a_point, b_point, wrapped.binding)
        z = (u + c * self.share) % N_ORDER
        return PartialDecryption(party_id=self.party_id, d_point=d_point, proof_c=c, proof_z=z)


def verify_partial(
    partial: PartialDecryption,
    public_share: ECPoint,
    c1: ECPoint,
    binding: bytes,
) -> bool:
    """Independent partial proof verifier - ai cũng xác minh được."""
    c, z = partial.proof_c, partial.proof_z
    a_prime = (z * G) - (c * public_share)
    b_prime = (z * c1) - (c * partial.d_point)
    c_recomputed = hash_to_scalar(G, public_share, c1, partial.d_point, a_prime, b_prime, binding)
    return c_recomputed == c


def combine_and_unwrap(
    partials: List[PartialDecryption],
    public_key_shares: Dict[int, ECPoint],
    threshold: int,
    wrapped: ThresholdWrappedDEK,
) -> bytes:
    """
    Combiner: xác minh từng proof (loại partial sai), giữ >= t phần hợp lệ,
    nội suy Lagrange để tái tạo K = r*Y rồi unwrap DEK.
    """
    valid: List[PartialDecryption] = []
    rejected: List[int] = []
    for p in partials:
        y_j = public_key_shares.get(p.party_id)
        if y_j is None or not verify_partial(p, y_j, wrapped.c1, wrapped.binding):
            rejected.append(p.party_id)
        else:
            valid.append(p)

    if len(valid) < threshold:
        raise UnderThresholdError(
            f"Chỉ có {len(valid)}/{threshold} partial hợp lệ "
            f"(bị loại: {rejected}) - không unwrap được DEK."
        )

    subset = valid[:threshold]
    combined = ECPoint(None, None)
    for p in subset:
        lam = lagrange_coefficient(p.party_id, [q.party_id for q in subset])
        combined = combined + (lam * p.d_point)

    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=wrapped.binding).derive(combined.to_bytes())
    try:
        return AESGCM(wrap_key).decrypt(wrapped.nonce, wrapped.ciphertext, wrapped.binding)
    except InvalidTag as err:
        raise UnderThresholdError(f"AEAD tag sai - bộ partial không tái tạo đúng K: {err}")


# =============================================================================
# 5. DEMO + TESTS (cổng nghiệm thu Giai đoạn 3)
# =============================================================================
def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []

    # ---------------------------------------------------------------------
    _banner("TEST 1: PEDERSEN DKG 5-3 - KHÔNG CÓ TRUSTED DEALER")
    # ---------------------------------------------------------------------
    N, T = 5, 3
    t0 = time.time()
    dkg, party_objs = run_pedersen_dkg(list(range(1, N + 1)), T)
    dkg_time = time.time() - t0

    print(f"- n={N}, t={T} -> joint public key Y = ({format(dkg.joint_public_key.x, 'x')[:32]}...)")
    print(f"- QUAL = {dkg.qualified_parties}, thời gian DKG: {dkg_time*1000:.1f} ms")
    print(f"- Mỗi party chỉ giữ 1 share; bằng chứng không ai có full key:")
    print(f"    party 1 stores x_1 = {hex(dkg.private_shares[1])[:26]}... (1 số, ko phải key đầy đủ)")

    # Y phải tái tạo được từ MỌI subset size t (không cần private key nào)
    from itertools import combinations
    for subset in combinations(range(1, N + 1), T):
        assert dkg.reconstruct_public_key(list(subset)) == dkg.joint_public_key
    print("- PASS: Y tái tạo đúng từ mọi subset 3/5 (C(5,3)=10 subset)")
    results.append("TEST1 DKG-no-dealer: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 2: INVALID-SHARE - SHARE BỊ LÀM SAI BỊ VSS BẮT")
    # ---------------------------------------------------------------------
    def tamper_sender5(sender, receiver, share):
        if sender == 5 and receiver == 1:
            return (share + 12345) % N_ORDER   # attacker sửa share trên đường truyền
        return share

    dkg_bad, _ = run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper_sender5)
    assert 5 not in dkg_bad.qualified_parties, "Party 5 phải bị QUAL loại"
    print(f"- Share hỏng (5->1) bị receiver bắt qua VSS equation")
    print(f"- QUAL = {dkg_bad.qualified_parties} (party 5 bị loại), DKG vẫn hoàn thành với t=3")
    # DKGResult vẫn nhất quán
    assert dkg_bad.reconstruct_public_key([1, 2, 3]) == dkg_bad.joint_public_key
    print("- PASS")
    results.append("TEST2 invalid-share: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 3: DKG-ABORT - QUAL < T THÌ HỦY, KHÔNG SINH KEY LỆCH")
    # ---------------------------------------------------------------------
    def tamper_three(sender, receiver, share):
        if sender in (3, 4, 5):
            return (share + 999) % N_ORDER
        return share

    try:
        run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper_three)
        raise AssertionError("Phải abort khi QUAL=2 < t=3")
    except DKGAbortError as err:
        print(f"- Đúng như dự kiến: {err}")
        print("- PASS: fail-safe - không bao giờ ra bộ key khác nhau giữa các node")
    results.append("TEST3 dkg-abort: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 4: WRAP DEK + OFFLINE-NODE (2 NODE CHẾT VẪN PHỤC VỤ)")
    # ---------------------------------------------------------------------
    dek = os.urandom(32)
    binding = make_binding("OBJ-3001", 1, "ph_" + "ab" * 31, "JSON-GCM-v1",
                           epoch=1, policy_root="pr_" + "cd" * 31)
    wrapped = wrap_dek(dek, dkg.joint_public_key, binding)
    print(f"- Đã wrap DEK 32B dưới Y (ciphertext {len(wrapped.ciphertext)}B + C1)")

    nodes = {pid: ThresholdKeyNode(pid, dkg.private_shares[pid],
                                   dkg.public_key_shares[pid], T)
             for pid in dkg.qualified_parties}

    # Node 4,5 offline -> 3 node còn lại vẫn đủ t
    online = [nodes[1], nodes[2], nodes[3]]
    t0 = time.time()
    partials = [nd.partial_decrypt(wrapped) for nd in online]
    recovered = combine_and_unwrap(partials, dkg.public_key_shares, T, wrapped)
    lat = time.time() - t0
    assert recovered == dek
    print(f"- PASS: nodes 1,2,3 (4,5 offline) unwrap DEK đúng trong {lat*1000:.1f} ms")
    results.append("TEST4 offline-node: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 5: DƯỚI T SHARES - KHÔNG UNWRAP ĐƯỢC DEK")
    # ---------------------------------------------------------------------
    try:
        combine_and_unwrap(partials[:2], dkg.public_key_shares, T, wrapped)
        raise AssertionError("2 shares phải fail")
    except UnderThresholdError as err:
        print(f"- Đúng như dự kiến: {err}")
        print("- PASS: cổng nghiệm thu 'dưới t shares không unwrap được DEK'")
    results.append("TEST5 under-threshold: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 6: COMPROMISED-NODE - PARTIAL GIẢ BỊ CHAUM-PEDERSEN LOẠI")
    # ---------------------------------------------------------------------
    evil = ThresholdKeyNode(4, (dkg.private_shares[4] + 1) % N_ORDER,   # share bị sửa
                            dkg.public_key_shares[4], T)
    forged = evil.partial_decrypt(wrapped)                               # proof sai lệch
    assert not verify_partial(forged, dkg.public_key_shares[4], wrapped.c1, binding)
    print("- Node 4 (compromised) gửi partial với share sai -> proof DLEQ KHÔNG pass")

    # Partial hợp lệ nhưng bị tráo điểm D (mạo nhận tin nhắn)
    import copy
    forged2 = copy.copy(partials[0])
    forged2.d_point = _RNG.randrange(1, N_ORDER) * G
    assert not verify_partial(forged2, dkg.public_key_shares[forged2.party_id], wrapped.c1, binding)
    print("- Partial bị tráo D_point -> verifier độc lập cũng phát hiện")

    # Ghép 1 partial giả + 2 partial thật -> combiner vẫn unwrap được nhờ loại giả,
    # nhưng với >= t partial thật; ở đây 3 thật + 1 giả vẫn OK:
    ok_partials = partials + [forged]
    recovered = combine_and_unwrap(ok_partials, dkg.public_key_shares, T, wrapped)
    assert recovered == dek
    print(f"- Combiner loại partial giả (rejected=[{forged.party_id}]), 3 partial thật vẫn unwrap OK")
    results.append("TEST6 compromised-node: PASS")

    # ---------------------------------------------------------------------
    _banner("TEST 7: TÍCH HỢP GĐ1+GĐ2 - POLICY GATE TRƯỚC KHI PHÁT PARTIAL")
    # ---------------------------------------------------------------------
    authority_sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(authority_sk)
    event, leaf_idx, root_hex = service.init_policy("OBJ-3001", initial_epoch=1)

    bridge_sk = ed25519.Ed25519PrivateKey.generate()
    bridge = EngramAnchorBridge(bridge_sk)
    bridge.anchor_epoch(1, service.mmr)

    oracle = KeyNodeTrustedRootOracle(bridge.bridge_pk, FreshnessWindowConfig(
        max_anchor_age_seconds=60.0, max_clock_skew_seconds=5.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    trusted_root = oracle.get_latest_trusted_root()
    print(f"- Policy log (GĐ1) + Anchor epoch 1 (GĐ2), latest trusted root = {trusted_root[:24]}...")

    policy_hash = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
    binding_real = make_binding("OBJ-3001", 1, policy_hash, "JSON-GCM-v1", 1, trusted_root)
    wrapped_real = wrap_dek(dek, dkg.joint_public_key, binding_real)

    gated_nodes = {pid: ThresholdKeyNode(pid, dkg.private_shares[pid],
                                         dkg.public_key_shares[pid], T, oracle=oracle)
                   for pid in dkg.qualified_parties}

    # 7a. Policy ACTIVE + root tươi -> phát partial bình thường
    p_ok = [gated_nodes[j].partial_decrypt(
                wrapped_real, object_id="OBJ-3001",
                presented_policy_root=trusted_root, policy_db=service.policy_records)
            for j in (1, 2, 3)]
    assert combine_and_unwrap(p_ok, dkg.public_key_shares, T, wrapped_real) == dek
    print("  [7a] ACTIVE + fresh root -> unwrap DEK OK")

    # 7b. Stale root -> node từ chối (fail-closed)
    try:
        gated_nodes[1].partial_decrypt(
            wrapped_real, object_id="OBJ-3001",
            presented_policy_root="00" * 32, policy_db=service.policy_records)
        raise AssertionError("Stale root phải bị từ chối")
    except StaleRootError:
        print("  [7b] Stale root -> StaleRootError, node KHÔNG phát partial")

    # 7c. REVOKED -> terminal invariant chặn release
    service.transition_policy("OBJ-3001", "REVOKED")
    denied = 0
    for j in (1, 2, 3):
        try:
            gated_nodes[j].partial_decrypt(
                wrapped_real, object_id="OBJ-3001",
                presented_policy_root=trusted_root, policy_db=service.policy_records)
        except PermissionError:
            denied += 1
    assert denied == 3
    print("  [7c] REVOKED -> cả 3 node từ chối phát partial (0/3 partial)")
    try:
        combine_and_unwrap([], dkg.public_key_shares, T, wrapped_real)
        raise AssertionError("Không partial thì không unwrap")
    except UnderThresholdError:
        print("  [7c] -> 0 < t partial: UnderThresholdError, DEK không thể mở lại")
    results.append("TEST7 policy-gate integration: PASS")

    # ---------------------------------------------------------------------
    _banner("BENCHMARK NHANH (deliverable: threshold latency)")
    # ---------------------------------------------------------------------
    t0 = time.time()
    for _ in range(50):
        nd = nodes[1]
        _ = nd.partial_decrypt(wrapped)
    per_partial = (time.time() - t0) / 50 * 1000

    t0 = time.time()
    for _ in range(50):
        _ = verify_partial(partials[0], dkg.public_key_shares[1], wrapped.c1, binding)
    per_verify = (time.time() - t0) / 50 * 1000
    print(f"- partial_decrypt: {per_partial:.2f} ms/node; verify proof: {per_verify:.3f} ms/partials")
    print(f"- Tổng DKG (5 parties, t=3): {dkg_time*1000:.1f} ms")

    # ---------------------------------------------------------------------
    _banner("KẾT LUẬN")
    # ---------------------------------------------------------------------
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => DKG KHÔNG CÓ TRUSTED DEALER: toàn bộ ủy ban cùng sinh Y,")
    print("     không ai từng biết private key đầy đủ; partial được chứng minh")
    print("     bằng Chaum-Pedersen và bị gate bởi policy/freshness GĐ2.")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
