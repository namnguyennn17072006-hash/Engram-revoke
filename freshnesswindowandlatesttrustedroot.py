import time
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# Kế thừa các thành phần đã xây dựng từ signedandapend_events và anchorroot
from signedandapend_events import VerifiableMMR, PolicyEvent, PolicyLogService
from anchorroot import EpochAnchor, ConsistencyProof, EngramAnchorBridge, _find_path_to_ancestor


# =============================================================================
# 1. ĐỊNH NGHĨA CẤU HÌNH FRESHNESS WINDOW & LIVENESS METRICS
# =============================================================================
@dataclass
class FreshnessWindowConfig:
    """
    Cấu hình cửa sổ độ tươi (Freshness Window):
    - max_anchor_age_seconds: Khoảng thời gian tối đa anchor được coi là có hiệu lực.
    - max_clock_skew_seconds: Dung sai trôi đồng hồ (Clock Skew) giữa các node.
    - max_epoch_drift: Số epoch tối đa được phép trôi (mặc định = 0 để enforce latest epoch).
    """
    max_anchor_age_seconds: float = 60.0
    max_clock_skew_seconds: float = 5.0
    max_epoch_drift: int = 0


class LivenessMetrics:
    """
    Đo lường sự suy giảm Liveness (Liveness Reduction) do quy tắc Fail-closed,
    phục vụ yêu cầu đo lường và đánh giá thực nghiệm của Giai đoạn 2.
    """
    def __init__(self):
        self.total_requests = 0
        self.served_requests = 0
        self.blocked_fail_closed = 0
        self.blocked_stale_root = 0

    def record_request(self): self.total_requests += 1
    def record_served(self): self.served_requests += 1
    def record_fail_closed(self): self.blocked_fail_closed += 1
    def record_stale_root(self): self.blocked_stale_root += 1

    @property
    def liveness_ratio(self) -> float:
        return self.served_requests / self.total_requests if self.total_requests > 0 else 1.0


# Các ngoại lệ an ninh theo threat model
class SecurityError(Exception): pass
class StaleRootError(SecurityError): pass
class FailClosedFreshnessError(SecurityError): pass
class EquivocationError(SecurityError): pass


# =============================================================================
# 2. KEY NODE TRUSTED ROOT ORACLE & FRESHNESS ENFORCEMENT
# =============================================================================
class KeyNodeTrustedRootOracle:
    """
    Module tại Key Node quản lý vòng đời của Latest Trusted Root,
    xác thực tính tươi (Freshness) và thực thi kiểm tra truy cập theo Fail-closed.
    """
    def __init__(self, bridge_public_key: ed25519.Ed25519PublicKey, config: FreshnessWindowConfig = FreshnessWindowConfig()):
        self.bridge_pk = bridge_public_key
        self.config = config
        self.metrics = LivenessMetrics()

        self.latest_trusted_anchor: Optional[EpochAnchor] = None
        # Bảng ghi vết chống Equivocation (ngăn chặn 2 roots khác nhau cùng epoch)
        self.seen_epoch_roots: Dict[int, str] = {}

    def sync_latest_trusted_root(
        self,
        candidate_anchor: EpochAnchor,
        consistency_proof: Optional[ConsistencyProof] = None,
        current_time: Optional[float] = None
    ) -> str:
        """
        Quy trình 5 bước lấy và chứng thực Latest Trusted Root tại Key Node.
        """
        now = current_time if current_time is not None else time.time()

        # BƯỚC 1: Xác thực chữ ký số của Anchor Bridge (Attestation)
        try:
            self.bridge_pk.verify(
                bytes.fromhex(candidate_anchor.bridge_signature),
                candidate_anchor.canonical_bytes_for_signing()
            )
        except (InvalidSignature, ValueError) as err:
            raise SecurityError(f"[Attestation Failed] Chữ ký Anchor Bridge không hợp lệ: {err}")

        # BƯỚC 2: Kiểm tra chống Equivocation (Rủi ro hai policy heads cùng hợp lệ)
        if candidate_anchor.epoch in self.seen_epoch_roots:
            existing_root = self.seen_epoch_roots[candidate_anchor.epoch]
            if candidate_anchor.mmr_root != existing_root:
                raise EquivocationError(
                    f"[Equivocation Attack] Phát hiện 2 roots khác nhau cho cùng Epoch {candidate_anchor.epoch}! "
                    f"Existing: {existing_root[:16]}..., Candidate: {candidate_anchor.mmr_root[:16]}..."
                )
        else:
            self.seen_epoch_roots[candidate_anchor.epoch] = candidate_anchor.mmr_root

        # BƯỚC 3: Kiểm tra Freshness Window (Ràng buộc thời gian & Clock Skew)
        # 3.1. Chống trôi đồng hồ về tương lai
        if candidate_anchor.timestamp > now + self.config.max_clock_skew_seconds:
            raise FailClosedFreshnessError(
                f"[Clock Skew Exceeded] Anchor timestamp đến từ tương lai quá xa: "
                f"Anchor={candidate_anchor.timestamp:.2f}, Node={now:.2f}, Skew={candidate_anchor.timestamp - now:.2f}s"
            )

        # 3.2. Chống anchor quá hạn (Stale Window / Partition delay)
        anchor_age = now - candidate_anchor.timestamp
        if anchor_age > self.config.max_anchor_age_seconds:
            raise FailClosedFreshnessError(
                f"[Stale Anchor Window] Anchor đã hết hạn tính tươi: "
                f"Age={anchor_age:.2f}s > MaxAllowed={self.config.max_anchor_age_seconds:.2f}s"
            )

        # 3.3. Chống Epoch Rollback (Epoch phải tăng đơn điệu)
        if self.latest_trusted_anchor:
            if candidate_anchor.epoch < self.latest_trusted_anchor.epoch - self.config.max_epoch_drift:
                raise StaleRootError(
                    f"[Epoch Rollback] Candidate epoch ({candidate_anchor.epoch}) "
                    f"thấp hơn latest trusted epoch ({self.latest_trusted_anchor.epoch})"
                )

        # BƯỚC 4: Kiểm tra Hash-Chain & Consistency Proof khi chuyển Epoch
        if self.latest_trusted_anchor and candidate_anchor.epoch > self.latest_trusted_anchor.epoch:
            if candidate_anchor.prev_anchor_hash != self.latest_trusted_anchor.get_anchor_hash():
                raise SecurityError("[Broken Anchor Chain] prev_anchor_hash không khớp với anchor trước đó!")

            if not consistency_proof:
                raise FailClosedFreshnessError("[Missing Consistency Proof] Thiếu Consistency Proof khi chuyển Epoch!")

            if not self._verify_consistency(self.latest_trusted_anchor, candidate_anchor, consistency_proof):
                raise SecurityError("[Consistency Proof Invalid] Bằng chứng append-only giữa 2 MMR roots bị sai!")

        # BƯỚC 5: Cập nhật thành Latest Trusted Anchor
        self.latest_trusted_anchor = candidate_anchor
        return self.latest_trusted_anchor.mmr_root

    def _verify_consistency(self, old_anchor: EpochAnchor, new_anchor: EpochAnchor, proof: ConsistencyProof) -> bool:
        """Xác minh toán học rằng root mới là sự mở rộng hợp lệ từ root cũ."""
        if proof.from_epoch != old_anchor.epoch or proof.to_epoch != new_anchor.epoch: return False
        if proof.from_root != old_anchor.mmr_root or proof.to_root != new_anchor.mmr_root: return False

        old_peaks = [bytes.fromhex(p) for p in old_anchor.peak_hashes]
        new_peaks = [bytes.fromhex(p) for p in new_anchor.peak_hashes]
        if VerifiableMMR.bag_peaks(old_peaks).hex() != old_anchor.mmr_root: return False
        if VerifiableMMR.bag_peaks(new_peaks).hex() != new_anchor.mmr_root: return False

        new_peaks_set = set(new_anchor.peak_hashes)
        for p_proof in proof.peak_proofs:
            curr_hash = bytes.fromhex(p_proof.old_peak)
            for sibling_hex, direction in p_proof.sibling_path:
                sib_bytes = bytes.fromhex(sibling_hex)
                if direction == "right":
                    curr_hash = VerifiableMMR.hash_node(curr_hash, sib_bytes)
                else:
                    curr_hash = VerifiableMMR.hash_node(sib_bytes, curr_hash)

            if curr_hash.hex() != p_proof.new_peak or p_proof.new_peak not in new_peaks_set:
                return False
        return True

    def get_latest_trusted_root(self) -> str:
        """Trả về Latest Trusted Root. Kích hoạt Fail-closed nếu chưa có."""
        if not self.latest_trusted_anchor:
            self.metrics.record_fail_closed()
            raise FailClosedFreshnessError("Fail-closed: Key Node chưa đồng bộ được Latest Trusted Root nào!")
        return self.latest_trusted_anchor.mmr_root

    def resolve_fresh_policy(self, object_id: str, presented_policy_root: str, local_policy_db: Dict[str, dict]) -> dict:
        """
        Hàm ResolveFreshPolicy(object) theo đặc tả kiến trúc:
        - Kiểm tra tính tươi với Latest Trusted Root.
        - Áp dụng gợi ý GĐ2: Key node chỉ nhận proof dưới latest trusted root, từ chối stale root.
        - Kiểm tra Terminal state invariant (REVOKED / EXPIRED).
        """
        self.metrics.record_request()

        # 1. Lấy Latest Root (Fail-closed nếu mất tính tươi hoặc chưa có sync)
        latest_root = self.get_latest_trusted_root()

        # 2. Chặn Stale Root: Bằng chứng hợp lệ nhưng thuộc Root cũ bị từ chối
        if presented_policy_root != latest_root:
            self.metrics.record_stale_root()
            raise StaleRootError(
                f"[Stale Root Rejected] Yêu cầu bị từ chối do sử dụng Root cũ! "
                f"Presented Root: {presented_policy_root[:16]}..., Latest Root: {latest_root[:16]}..."
            )

        policy = local_policy_db.get(object_id)
        if not policy:
            self.metrics.record_fail_closed()
            raise PermissionError(f"Policy cho Object ID '{object_id}' không tồn tại!")

        # 3. Kiểm tra Terminal Invariant (REVOKED / EXPIRED không được cấp khóa)
        state = policy.get("state")
        if state in ["REVOKED", "EXPIRED"]:
            self.metrics.record_fail_closed()
            raise PermissionError(f"Từ chối cấp khóa (Key Release Blocked): Policy đang ở trạng thái '{state}'!")

        if state != "ACTIVE":
            self.metrics.record_fail_closed()
            raise PermissionError(f"Từ chối cấp khóa: Policy không ở trạng thái ACTIVE (hiện tại: '{state}')!")

        self.metrics.record_served()
        return policy


# =============================================================================
# 3. KỊCH BẢN THỬ NGHIỆM TÍCH HỢP TOÀN DIỆN (E2E TEST CORPUS)
# =============================================================================
if __name__ == "__main__":
    print("=" * 80)
    print("DEMO GIAI ĐOẠN 2: FRESHNESS WINDOW & LATEST TRUSTED ROOT ORACLE")
    print("=" * 80)

    # 1. Khởi tạo các cặp khóa cho Authority và Anchor Bridge
    auth_sk = ed25519.Ed25519PrivateKey.generate()
    bridge_sk = ed25519.Ed25519PrivateKey.generate()

    policy_service = PolicyLogService(auth_sk)
    anchor_bridge = EngramAnchorBridge(bridge_sk)
    oracle = KeyNodeTrustedRootOracle(bridge_sk.public_key())

    # --- KỊCH BẢN 1: KHỞI TẠO VÀ ĐỒNG BỘ EPOCH 1 ---
    print("\n--- [Kịch bản 1] Khởi tạo Policy & Neo Epoch 1 ---")
    policy_service.init_policy("OBJ-2026-X")
    anchor_ep1 = anchor_bridge.anchor_epoch(epoch=1, mmr=policy_service.mmr)
    
    trusted_root_1 = oracle.sync_latest_trusted_root(anchor_ep1)
    print(f"Key Node đã đồng bộ Trusted Root (Epoch 1): {trusted_root_1[:20]}...")

    # Truy cập hợp lệ với Root 1
    pol_active = oracle.resolve_fresh_policy("OBJ-2026-X", anchor_ep1.mmr_root, policy_service.policy_records)
    print(f"-> Truy cập thành công! Policy State: {pol_active['state']}")

    # --- KỊCH BẢN 2: CHUYỂN TRẠNG THÁI REVOKED VÀ NEO EPOCH 2 ---
    print("\n--- [Kịch bản 2] Thu hồi (REVOKE) & Neo Epoch 2 ---")
    policy_service.transition_policy("OBJ-2026-X", "REVOKED")
    anchor_ep2 = anchor_bridge.anchor_epoch(epoch=2, mmr=policy_service.mmr)
    proof_1_2 = anchor_bridge.get_consistency_proof(1, 2)

    trusted_root_2 = oracle.sync_latest_trusted_root(anchor_ep2, consistency_proof=proof_1_2)
    print(f"Key Node đã cập nhật Trusted Root mới (Epoch 2): {trusted_root_2[:20]}...")

    # --- KỊCH BẢN 3: TẤN CÔNG STALE ROOT (GỢI Ý GIAI ĐOẠN 2) ---
    print("\n--- [Kịch bản 3] Thử nghiệm tấn công Stale Root (gửi Root cũ ở Epoch mới) ---")
    try:
        oracle.resolve_fresh_policy("OBJ-2026-X", anchor_ep1.mmr_root, policy_service.policy_records)
    except StaleRootError as e:
        print(f"-> Chặn đứng tấn công thành công: {e}")

    # --- KỊCH BẢN 4: KIỂM TRA TERMINAL INVARIANT (REVOKED) ---
    print("\n--- [Kịch bản 4] Thử giải mã khi đã Revoked (gửi Root 2 hợp lệ) ---")
    try:
        oracle.resolve_fresh_policy("OBJ-2026-X", anchor_ep2.mmr_root, policy_service.policy_records)
    except PermissionError as e:
        print(f"-> Chặn đứng cấp khóa thành công: {e}")

    # --- KỊCH BẢN 5: KIỂM TRA ĐỐI KHÁNG CLOCK SKEW & EQUIVOCATION ---
    print("\n--- [Kịch bản 5] Thử nghiệm phát hiện Clock Skew bất thường ---")
    skewed_anchor = EpochAnchor(
        epoch=3,
        mmr_root="abcd" * 16,
        tree_size=10,
        peak_hashes=["abcd" * 16],
        timestamp=time.time() + 100,  # Lệch 100 giây về tương lai
        prev_anchor_hash=anchor_ep2.get_anchor_hash(),
        bridge_signature=""
    )
    skewed_anchor.bridge_signature = bridge_sk.sign(skewed_anchor.canonical_bytes_for_signing()).hex()
    try:
        oracle.sync_latest_trusted_root(skewed_anchor)
    except FailClosedFreshnessError as e:
        print(f"-> Chặn đứng lệch đồng hồ: {e}")

    # --- BÁO CÁO LIVENESS REDUCTION ---
    print("\n" + "=" * 50)
    print(f"THỐNG KÊ LIVENESS METRICS (FAIL-CLOSED):")
    print(f"  • Tổng số lượt truy cập : {oracle.metrics.total_requests}")
    print(f"  • Lượt phục vụ thành công: {oracle.metrics.served_requests}")
    print(f"  • Bị chặn bởi Stale Root : {oracle.metrics.blocked_stale_root}")
    print(f"  • Tỷ lệ Liveness khả dụng: {oracle.metrics.liveness_ratio * 100:.1f}%")
    print("=" * 50)