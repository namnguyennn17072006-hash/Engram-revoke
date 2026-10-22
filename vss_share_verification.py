
import time
import random
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- Tái sử dụng từ dkg_threshold_service.py (GĐ3 câu 1) ---------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    P_CURVE,
    DKGParty,
    evaluate_polynomial,
    run_pedersen_dkg,
    DKGAbortError,
)
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import KeyNodeTrustedRootOracle, FreshnessWindowConfig


# =============================================================================
# 1. H GENERATOR (nothing-up-my-sleeve qua hash-to-curve) - riêng cho Pedersen
#    H must independent discrete log vs G: sinh từ tag cố định, không có "chủ".
# =============================================================================
def hash_to_curve(tag: bytes) -> ECPoint:
    """Try-and-increment: SHA256(tag||counter) -> x hợp lệ trên secp256k1."""
    counter = 0
    while True:
        digest = hashlib.sha256(tag + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(digest, "big")
        if x < P_CURVE:
            rhs = (pow(x, 3, P_CURVE) + 7) % P_CURVE           # y^2 = x^3 + 7
            if pow(rhs, (P_CURVE - 1) // 2, P_CURVE) == 1:      # Legendre = 1
                y = pow(rhs, (P_CURVE + 1) // 4, P_CURVE)       # P = 3 (mod 4)
                if y * y % P_CURVE == rhs:
                    return ECPoint(x, y)
        counter += 1


H: Optional[ECPoint] = None


def get_H() -> ECPoint:
    global H
    if H is None:
        H = hash_to_curve(b"engram-revoke/pedersen-vss/H/v1")
    return H


# =============================================================================
# 2. BINDING COMMITMENT BROADCAST (Ed25519, style GĐ1) -
#    Member xác minh Nguồn broadcast trước khi kiểm tra share (chống giả mạo),
#    gắn epoch/policy root để chống replay commitment từ context cũ.
# =============================================================================
def broadcast_bytes(context: str, dealer_id: int, commitments: List[ECPoint]) -> bytes:
    commits_hex = ",".join(c.to_bytes().hex() for c in commitments)
    return f"VSS-BROADCAST|ctx={context}|dealer={dealer_id}|commits={commits_hex}".encode("utf-8")


def sign_broadcast(sk: ed25519.Ed25519PrivateKey, context: str,
                   dealer_id: int, commitments: List[ECPoint]) -> bytes:
    return sk.sign(broadcast_bytes(context, dealer_id, commitments))


# =============================================================================
# 3. FELDMAN VSS - COMMITMENT CÔNG KHAI (publicly verifiable)
#    Verify:  y_j * G  ==  sum_k (j^k) * C_k        với C_k = a_k * G
#    Ưu điểm: mọi người (không chỉ receiver) kiểm chứng được, Y = C_0.
#    Hạn chế: commitment tiết lộ a_k*G (không che giấu).
# =============================================================================
class FeldmanVSS:
    """Dealer-side Feldman VSS. Dùng chung verify với DKGParty.verify_share."""

    def __init__(self, dealer_id: int, threshold: int,
                 coeffs: Optional[List[int]] = None, rng: Optional[random.Random] = None):
        self.dealer_id = dealer_id
        self.t = threshold
        rng = rng or random.SystemRandom()
        # Cho phép ép bộ test vector (coeffs cố định) hoặc sinh ngẫu nhiên
        self.coeffs = coeffs if coeffs is not None else \
            [rng.randrange(1, N_ORDER) for _ in range(threshold)]
        self.commitments = [a * G for a in self.coeffs]

    def share_for(self, member_id: int) -> int:
        return evaluate_polynomial(self.coeffs, member_id)

    @staticmethod
    def verify_share(member_id: int, share: int, commitments: List[ECPoint]) -> bool:
        """Thành viên TỰ xác minh share nhận được (Feldman equation)."""
        return DKGParty.verify_share(member_id, share, commitments)


# =============================================================================
# 4. PEDERSEN VSS - COMMITMENT CHE GIẤU (perfectly hiding)
#    Dealer sinh thêm blinding poly g(x) bậc (t-1), C_k = a_k*G + b_k*H,
#    gửi kèm blind share z_j = g(j).
#    Verify:  y_j*G + z_j*H  ==  sum_k (j^k) * C_k
#    Ưu điểm: C_k là perfectly-hiding -> không lộ thông tin về a_k.
#    Hạn chế: C_0 KHÔNG bằng a_0*G -> muốn public Y thì dealer phải công bố
#             Y = a_0*G riêng (hoặc dùng Feldman cho bước public key).
# =============================================================================
class PedersenVSS:
    """Dealer-side Pedersen VSS (Feldman/Pedersen 'tùy yêu cầu hiding')."""

    def __init__(self, dealer_id: int, threshold: int,
                 coeffs: Optional[List[int]] = None, rng: Optional[random.Random] = None):
        self.dealer_id = dealer_id
        self.t = threshold
        rng = rng or random.SystemRandom()
        self.coeffs = coeffs if coeffs is not None else \
            [rng.randrange(1, N_ORDER) for _ in range(threshold)]
        self.blinds = [rng.randrange(1, N_ORDER) for _ in range(threshold)]
        self.commitments = [self.coeffs[k] * G + self.blinds[k] * get_H()
                            for k in range(threshold)]

    def share_for(self, member_id: int) -> Tuple[int, int]:
        """Trả về cặp (y_j, z_j): y = f(j) - secret share, z = g(j) - blind share."""
        y = evaluate_polynomial(self.coeffs, member_id)
        z = evaluate_polynomial(self.blinds, member_id)
        return y, z

    @staticmethod
    def verify_share(member_id: int, y: int, z: int, commitments: List[ECPoint]) -> bool:
        """Thành viên TỰ xác minh cặp (y, z) nhận được (Pedersen equation)."""
        if y is None or z is None or not commitments:
            return False
        lhs = y * G + z * get_H()
        rhs = ECPoint(None, None)
        power = 1
        for c_k in commitments:
            rhs = rhs + (power * c_k)
            power = (power * member_id) % N_ORDER
        return lhs == rhs


# =============================================================================
# 5. VSSMember - "MỖI THÀNH VIÊN kiểm tra share NHẬN ĐƯỢC"
#    Trực diện hóa vai trò receiver: nhận (commitment broadcast, share),
#    xác minh chữ ký -> xác minh phương trình VSS -> báo cáo lỗi từng dealer.
# =============================================================================
@dataclass
class ShareCheckResult:
    member_id: int
    dealer_id: int
    ok: bool
    scheme: str          # "feldman" | "pedersen"
    reason: str = ""


@dataclass
class MemberVerificationReport:
    member_id: int
    results: List[ShareCheckResult] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def failed_dealers(self) -> List[int]:
        return [r.dealer_id for r in self.results if not r.ok]


class VSSMember:
    """
    Thành viên j trong ủy ban. Nhận share từ mỗi dealer và kiểm tra độc lập:
    1) Chữ ký Ed25519 trên broadcast (gắn context epoch/policy root) hợp lệ?
    2) Phương trình VSS đúng? (Feldman hoặc Pedersen tùy biến thể)
    Bất kỳ step nào fail -> ghi nhận complaint đối với dealer đó.
    """

    def __init__(self, member_id: int, context: str,
                 trusted_dealer_keys: Dict[int, ed25519.Ed25519PublicKey]):
        self.member_id = member_id
        self.context = context
        self.trusted_dealer_keys = trusted_dealer_keys
        self.report = MemberVerificationReport(member_id=member_id)

    def _check_signature(self, dealer_id: int, commitments: List[ECPoint],
                         signature: Optional[bytes]) -> Optional[str]:
        pk = self.trusted_dealer_keys.get(dealer_id)
        if pk is None:
            return f"dealer {dealer_id} không có key tin cậy"
        if signature is None:
            return "thiếu chữ ký broadcast"
        try:
            pk.verify(signature, broadcast_bytes(self.context, dealer_id, commitments))
        except (InvalidSignature, ValueError):
            return "chữ ký broadcast sai hoặc sai context (replay?)"
        return None

    def check_feldman_share(self, dealer_id: int, share: int,
                            commitments: List[ECPoint],
                            signature: Optional[bytes]) -> ShareCheckResult:
        err = self._check_signature(dealer_id, commitments, signature)
        if err:
            res = ShareCheckResult(self.member_id, dealer_id, False, "feldman", err)
        elif not FeldmanVSS.verify_share(self.member_id, share, commitments):
            res = ShareCheckResult(
                self.member_id, dealer_id, False, "feldman",
                f"vi phạm Feldman: {share}*G != sum(j^k * C_k) với j={self.member_id}")
        else:
            res = ShareCheckResult(self.member_id, dealer_id, True, "feldman", "OK")
        self.report.results.append(res)
        return res

    def check_pedersen_share(self, dealer_id: int, y: int, z: int,
                             commitments: List[ECPoint],
                             signature: Optional[bytes]) -> ShareCheckResult:
        err = self._check_signature(dealer_id, commitments, signature)
        if err:
            res = ShareCheckResult(self.member_id, dealer_id, False, "pedersen", err)
        elif not PedersenVSS.verify_share(self.member_id, y, z, commitments):
            res = ShareCheckResult(
                self.member_id, dealer_id, False, "pedersen",
                f"vi phạm Pedersen: y*G + z*H != sum(j^k * C_k) với j={self.member_id}")
        else:
            res = ShareCheckResult(self.member_id, dealer_id, True, "pedersen", "OK")
        self.report.results.append(res)
        return res


def committee_keygen(n: int) -> Tuple[Dict[int, ed25519.Ed25519PrivateKey],
                                      Dict[int, ed25519.Ed25519PublicKey]]:
    """Sinh cặp key Ed25519 cho n dealer (mỗi dealer 1 key, style GĐ1)."""
    sks, pks = {}, {}
    for i in range(1, n + 1):
        sks[i] = ed25519.Ed25519PrivateKey.generate()
        pks[i] = sks[i].public_key()
    return sks, pks


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 6. DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    N, T = 5, 3
    CONTEXT = "DKG-epoch-1|root=" + "ab" * 32   # context mặc định (sẽ có test đổi ctx)

    # Bộ key dealer
    dealer_sks, dealer_pks = committee_keygen(N)

    # =====================================================================
    _banner("TEST 1: FELDMAN VSS - MỌI THÀNH VIÊN KIỂM TRA ĐƯỢC TOÀN BỘ SHARE")
    # =====================================================================
    feldman_dealers = {i: FeldmanVSS(i, T, rng=random.Random(1000 + i))
                       for i in range(1, N + 1)}
    members = {j: VSSMember(j, CONTEXT, dealer_pks) for j in range(1, N + 1)}

    # Mỗi thành viên j nhận share từ MỖI dealer i và tự xác minh
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            share = feldman_dealers[i].share_for(j)
            sig = sign_broadcast(dealer_sks[i], CONTEXT, i, feldman_dealers[i].commitments)
            members[j].check_feldman_share(i, share, feldman_dealers[i].commitments, sig)

    assert all(m.report.all_ok for m in members.values())
    total_checks = sum(len(m.report.results) for m in members.values())
    print(f"- 5 thành viên x 5 dealer = {total_checks} lần xác minh, tất cả PASS")
    print("- Feldman equation: y_j*G == sum_k (j^k)*C_k  (verify chung bằng code GĐ3)")
    results.append("TEST1 Feldman all-members verify: PASS")

    # =====================================================================
    _banner("TEST 2: SHARE BỊ LÀM SAI TRÊN ĐƯỜNG TRUYỀN -> THÀNH VIÊN PHÁT HIỆN")
    # =====================================================================
    # Dealer 5 gửi share hỏng cho thành viên 1
    tampered = (feldman_dealers[5].share_for(1) + 12345) % N_ORDER
    sig5 = sign_broadcast(dealer_sks[5], CONTEXT, 5, feldman_dealers[5].commitments)
    bad = members[1].check_feldman_share(5, tampered, feldman_dealers[5].commitments, sig5)
    assert not bad.ok
    print(f"- Thành viên 1 phát hiện share hỏng từ dealer 5: {bad.reason}")
    print(f"- Complaint report của member 1: failed_dealers={members[1].report.failed_dealers}")

    # Tích hợp với DKG thật (share_tamper hook của dkg_threshold_service)
    def tamper_hook(sender, receiver, share):
        return (share + 999) % N_ORDER if (sender == 4 and receiver == 2) else share
    dkg_result, _ = run_pedersen_dkg(list(range(1, N + 1)), T, share_tamper=tamper_hook)
    assert 4 not in dkg_result.qualified_parties
    print(f"- DKG thật với share_tamper(4->2): QUAL={dkg_result.qualified_parties} "
          f"(dealer 4 bị loại, VSS chặn từ round 2)")
    results.append("TEST2 invalid-share: PASS")

    # =====================================================================
    _banner("TEST 3: PEDERSEN VSS - KIỂM TRA VỚI BLIND SHARE (hiding)")
    # =====================================================================
    pedersen_dealers = {i: PedersenVSS(i, T, rng=random.Random(2000 + i))
                        for i in range(1, N + 1)}
    ped_members = {j: VSSMember(j, CONTEXT, dealer_pks) for j in range(1, N + 1)}
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            y, z = pedersen_dealers[i].share_for(j)
            sig = sign_broadcast(dealer_sks[i], CONTEXT, i, pedersen_dealers[i].commitments)
            ped_members[j].check_pedersen_share(i, y, z, pedersen_dealers[i].commitments, sig)
    assert all(m.report.all_ok for m in ped_members.values())
    print(f"- {N*N} lần xác minh Pedersen (y*G + z*H == sum(j^k*C_k)) toàn bộ PASS")
    results.append("TEST3 Pedersen verify: PASS")

    # =====================================================================
    _banner("TEST 4: PEDERSEN - SHARE HOẶC BLIND SHARE BỊ SỬA ĐỀU BỊ BẮT")
    # =====================================================================
    d1 = pedersen_dealers[1]
    sig1 = sign_broadcast(dealer_sks[1], CONTEXT, 1, d1.commitments)
    y3, z3 = d1.share_for(3)

    r1 = members[3].check_pedersen_share(1, (y3 + 1) % N_ORDER, z3, d1.commitments, sig1)
    assert not r1.ok
    print(f"- y bị sửa -> bị bắt: {r1.reason}")

    r2 = members[3].check_pedersen_share(1, y3, (z3 + 1) % N_ORDER, d1.commitments, sig1)
    assert not r2.ok
    print(f"- z (blind) bị sửa -> bị bắt: {r2.reason}")
    results.append("TEST4 tampered y/z: PASS")

    # =====================================================================
    _banner("TEST 5: HIDING PROPERTY - PEDERSEN CHE, FELDMAN LỘ (mục 143)")
    # =====================================================================
    fixed_a = [11111, 22222, 33333]                 # cùng bộ hệ số a_k
    ped_a = PedersenVSS(1, T, coeffs=fixed_a, rng=random.Random(42))
    ped_b = PedersenVSS(1, T, coeffs=fixed_a, rng=random.Random(43))  # blind khác
    assert ped_a.commitments != ped_b.commitments, "blind khác phải ra commitment khác"
    a0G = fixed_a[0] * G
    assert ped_a.commitments[0] != a0G, "Pedersen C_0 KHÔNG được phép = a_0*G"
    print(f"- Cùng f(x), 2 lần blind khác nhau -> commitment khác nhau (perfectly hiding)")
    print(f"- Pedersen C_0 != a_0*G  => không rút ra được thông tin public từ commitment")

    feld_a = FeldmanVSS(1, T, coeffs=fixed_a)
    assert feld_a.commitments[0] == a0G
    print(f"- Đối chiếu Feldman: C_0 == a_0*G (CÔNG KHAI - cần cho public Y)")
    print(f"  => Chọn Feldman khi cần public verify, Pedersen khi cần hiding (mục 143)")
    results.append("TEST5 hiding property: PASS")

    # =====================================================================
    _banner("TEST 6: BINDING CONTEXT (Ed25519 + epoch/policy root GĐ2)")
    # =====================================================================
    # Lấy context thật từ policy log GĐ1 + anchor GĐ2
    authority_sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(authority_sk)
    service.init_policy("OBJ-3001", initial_epoch=1)
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    bridge.anchor_epoch(1, service.mmr)
    oracle = KeyNodeTrustedRootOracle(bridge.bridge_pk,
                                      FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(bridge.anchor_chain[1])
    real_root = oracle.get_latest_trusted_root()
    real_ctx = f"DKG-epoch-1|root={real_root}"
    print(f"- Context thật từ oracle GĐ2: root={real_root[:24]}...")

    # 6a. Broadcast đúng context -> OK
    m1 = VSSMember(1, real_ctx, dealer_pks)
    sig_ok = sign_broadcast(dealer_sks[1], real_ctx, 1, feldman_dealers[1].commitments)
    ok = m1.check_feldman_share(1, feldman_dealers[1].share_for(1),
                                feldman_dealers[1].commitments, sig_ok)
    assert ok.ok
    print("  [6a] Ký đúng context (epoch+root) -> member chấp nhận")

    # 6b. Replay commitment cũ với context khác (root đã đổi) -> bị từ chối
    m1_stale = VSSMember(1, f"DKG-epoch-1|root={'cd'*32}", dealer_pks)
    stale = m1_stale.check_feldman_share(1, feldman_dealers[1].share_for(1),
                                         feldman_dealers[1].commitments, sig_ok)
    assert not stale.ok
    print(f"  [6b] Replay với context cũ -> bị từ chối: {stale.reason}")

    # 6c. Broadcast không có chữ ký -> bị từ chối
    m2 = VSSMember(2, real_ctx, dealer_pks)
    nosig = m2.check_feldman_share(2, feldman_dealers[2].share_for(2),
                                   feldman_dealers[2].commitments, None)
    assert not nosig.ok
    print(f"  [6c] Thiếu chữ ký broadcast -> bị từ chối: {nosig.reason}")
    results.append("TEST6 context binding: PASS")

    # =====================================================================
    _banner("TEST 7: TEST VECTORS TẤT ĐỊNH (mục 148 - có test vectors để đối chiếu)")
    # =====================================================================
    seed_rng = random.Random(1337)
    vec_dealer = FeldmanVSS(dealer_id=1, threshold=T, rng=seed_rng)
    y1 = vec_dealer.share_for(1)
    print(f"- Seed=1337, Feldman dealer=1, t={T}:")
    print(f"  coeffs[0..2]  = {[hex(c)[:14]+'...' for c in vec_dealer.coeffs]}")
    print(f"  commit[0].x   = {format(vec_dealer.commitments[0].x, 'x')[:40]}...")
    print(f"  share y_1     = {format(y1, 'x')}")

    ped_rng = random.Random(1337)
    vec_ped = PedersenVSS(dealer_id=1, threshold=T, rng=ped_rng)
    py1, pz1 = vec_ped.share_for(1)
    print(f"- Seed=1337, Pedersen dealer=1, t={T}:")
    print(f"  C_0.x         = {format(vec_ped.commitments[0].x, 'x')[:40]}...")
    print(f"  (y_1, z_1)    = ({format(py1, 'x')[:32]}..., {format(pz1, 'x')[:32]}...)")
    # Tính lại từ cùng seed phải giống nhau (tính tất định)
    vec_dealer2 = FeldmanVSS(dealer_id=1, threshold=T, rng=random.Random(1337))
    assert vec_dealer2.share_for(1) == y1
    print("- Chạy lại cùng seed -> share giống hệt (đối chiếu được)")
    results.append("TEST7 test vectors: PASS")

    # =====================================================================
    _banner("BENCHMARK XÁC MINH SHARE")
    # =====================================================================
    bench_commit = feldman_dealers[1].commitments
    bench_share = feldman_dealers[1].share_for(2)
    t0 = time.time()
    ITER = 200
    for _ in range(ITER):
        FeldmanVSS.verify_share(2, bench_share, bench_commit)
    per_f = (time.time() - t0) / ITER * 1_000_000

    y2, z2 = pedersen_dealers[1].share_for(2)
    t0 = time.time()
    for _ in range(ITER):
        PedersenVSS.verify_share(2, y2, z2, pedersen_dealers[1].commitments)
    per_p = (time.time() - t0) / ITER * 1_000_000
    print(f"- Feldman verify  : {per_f:.0f} µs/share (t={T}, {T} điểm mul)")
    print(f"- Pedersen verify : {per_p:.0f} µs/share (t={T}, {T+1} điểm mul)")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => MỌI thành viên tự kiểm tra được share nhận qua Feldman/Pedersen VSS;")
    print("     share hỏng bị phát hiện ngay tại receiver, broadcast bị gắn")
    print("     chữ ký Ed25519 + epoch/policy root (chống replay từ context cũ).")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
