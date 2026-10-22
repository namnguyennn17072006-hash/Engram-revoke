import unittest
import threading
import time
import concurrent.futures
from cryptography.hazmat.primitives.asymmetric import ed25519
from signedandapend_events import VerifiableMMR, PolicyEvent, PolicyLogService
from anchorroot import EpochAnchor, ConsistencyProof, EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
    FailClosedFreshnessError,
    EquivocationError,
    SecurityError
)


class TestPhase2AdversarialCorpus(unittest.TestCase):
    def setUp(self):
        """Khởi tạo môi trường giả lập Key Node, Authority và Anchor Bridge trước mỗi test case."""
        self.auth_sk = ed25519.Ed25519PrivateKey.generate()
        self.bridge_sk = ed25519.Ed25519PrivateKey.generate()
        self.bridge_pk = self.bridge_sk.public_key()

        self.policy_service = PolicyLogService(self.auth_sk)
        self.anchor_bridge = EngramAnchorBridge(self.bridge_sk)
        self.oracle = KeyNodeTrustedRootOracle(self.bridge_pk)

    # =========================================================================
    # 1. NHÓM TEST: STALE-ROOT TESTS
    # =========================================================================
    def test_stale_root_rejected_when_epoch_advances(self):
        """
        TC 1.1: Client sử dụng Root hợp lệ của Epoch 1 khi hệ thống đã chuyển sang Epoch 2.
        Kỳ vọng: Key Node từ chối bằng StaleRootError theo đúng gợi ý Giai đoạn 2.
        """
        self.policy_service.init_policy("OBJ-001")
        anchor_ep1 = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor_ep1)

        # Truy cập ở Epoch 1 hợp lệ
        pol1 = self.oracle.resolve_fresh_policy("OBJ-001", anchor_ep1.mmr_root, self.policy_service.policy_records)
        self.assertEqual(pol1["state"], "ACTIVE")

        # Hệ thống chuyển trạng thái sang Epoch 2
        self.policy_service.transition_policy("OBJ-001", "SUSPENDED")
        anchor_ep2 = self.anchor_bridge.anchor_epoch(2, self.policy_service.mmr)
        proof = self.anchor_bridge.get_consistency_proof(1, 2)
        self.oracle.sync_latest_trusted_root(anchor_ep2, proof)

        # Client cố tình tái sử dụng Root cũ của Epoch 1
        with self.assertRaises(StaleRootError) as ctx:
            self.oracle.resolve_fresh_policy("OBJ-001", anchor_ep1.mmr_root, self.policy_service.policy_records)
        self.assertIn("Stale Root Rejected", str(ctx.exception))

    def test_stale_root_cannot_bypass_revocation(self):
        """
        TC 1.2: Client cố tình dùng Stale Root để qua mặt hệ thống khi dữ liệu đã bị REVOKED.
        Kỳ vọng: Bị chặn đứng tuyệt đối, không rò rỉ khóa DEK qua snapshot cũ.
        """
        self.policy_service.init_policy("OBJ-REVOKE-TEST")
        anchor_ep1 = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor_ep1)

        # Thu hồi dữ liệu ở Epoch 2
        self.policy_service.transition_policy("OBJ-REVOKE-TEST", "REVOKED")
        anchor_ep2 = self.anchor_bridge.anchor_epoch(2, self.policy_service.mmr)
        proof = self.anchor_bridge.get_consistency_proof(1, 2)
        self.oracle.sync_latest_trusted_root(anchor_ep2, proof)

        # Client gửi Root 1 để giả vờ trạng thái vẫn là ACTIVE
        with self.assertRaises(StaleRootError):
            self.oracle.resolve_fresh_policy("OBJ-REVOKE-TEST", anchor_ep1.mmr_root, self.policy_service.policy_records)

    # =========================================================================
    # 2. NHÓM TEST: ROLLBACK TESTS
    # =========================================================================
    def test_terminal_state_invariant_rollback_prevented(self):
        """
        TC 2.1: Terminal State Invariant: REVOKED/EXPIRED không thể quay lại ACTIVE trên cùng policy lineage.
        """
        self.policy_service.init_policy("OBJ-TERMINAL")
        self.policy_service.transition_policy("OBJ-TERMINAL", "REVOKED")

        # Cố tình vi phạm bất biến: chuyển REVOKED -> ACTIVE
        with self.assertRaises(ValueError) as ctx:
            self.policy_service.transition_policy("OBJ-TERMINAL", "ACTIVE")
        self.assertIn("Terminal State Invariant", str(ctx.exception))

    def test_epoch_rollback_anchor_rejected(self):
        """
        TC 2.2: Kẻ tấn công gửi Anchor với Epoch lùi (E_candidate < E_latest).
        Kỳ vọng: Bị từ chối để chống tua lại lịch sử mạng.
        """
        self.policy_service.init_policy("OBJ-EPOCH")
        anchor1 = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor1)

        self.policy_service.transition_policy("OBJ-EPOCH", "SUSPENDED")
        anchor2 = self.anchor_bridge.anchor_epoch(2, self.policy_service.mmr)
        proof = self.anchor_bridge.get_consistency_proof(1, 2)
        self.oracle.sync_latest_trusted_root(anchor2, proof)

        # Thử tua lùi lại Epoch 1 khi Key Node đã ở Epoch 2
        with self.assertRaises(StaleRootError) as ctx:
            self.oracle.sync_latest_trusted_root(anchor1)
        self.assertIn("Epoch Rollback", str(ctx.exception))

    def test_broken_hash_chain_rejected(self):
        """
        TC 2.3: Kẻ tấn công gửi Anchor mới nhưng làm đứt gãy chuỗi prev_anchor_hash.
        """
        self.policy_service.init_policy("OBJ-CHAIN")
        anchor1 = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor1)

        # Tạo candidate anchor epoch 2 giả mạo prev_anchor_hash
        bad_anchor = EpochAnchor(
            epoch=2,
            mmr_root="aa" * 32,
            tree_size=10,
            peak_hashes=["aa" * 32],
            timestamp=time.time(),
            prev_anchor_hash="00" * 64,  # Hash không khớp với anchor1
            bridge_signature=""
        )
        bad_anchor.bridge_signature = self.bridge_sk.sign(bad_anchor.canonical_bytes_for_signing()).hex()

        with self.assertRaises(SecurityError) as ctx:
            self.oracle.sync_latest_trusted_root(bad_anchor)
        self.assertIn("Broken Anchor Chain", str(ctx.exception))

    # =========================================================================
    # 3. NHÓM TEST: EQUIVOCATION TESTS (HAI POLICY HEADS CÙNG HỢP LỆ)
    # =========================================================================
    def test_equivocation_two_roots_same_epoch_detected(self):
        """
        TC 3.1: Kẻ tấn công ký 2 roots khác nhau cho cùng một Epoch ID (Split-Brain Attack).
        Kỳ vọng: Key Node phát hiện xung đột và kích hoạt Fail-Closed (EquivocationError).
        """
        self.policy_service.init_policy("OBJ-EQ")
        anchor1_A = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor1_A)

        # Kẻ tấn công tạo một Root B khác cho cùng Epoch 1 và ký số hợp lệ
        anchor1_B = EpochAnchor(
            epoch=1,
            mmr_root="bb" * 32,  # Root khác với Root A
            tree_size=anchor1_A.tree_size,
            peak_hashes=["bb" * 32],
            timestamp=anchor1_A.timestamp,
            prev_anchor_hash="0" * 64,
            bridge_signature=""
        )
        anchor1_B.bridge_signature = self.bridge_sk.sign(anchor1_B.canonical_bytes_for_signing()).hex()

        with self.assertRaises(EquivocationError) as ctx:
            self.oracle.sync_latest_trusted_root(anchor1_B)
        self.assertIn("Equivocation Attack", str(ctx.exception))

    # =========================================================================
    # 4. NHÓM TEST: CONCURRENT ACCESS / REVOKE TESTS (ĐỒNG THỜI)
    # =========================================================================
    def test_concurrent_revoke_wins_future_key_release(self):
        """
        TC 4.1: Cổng nghiệm thu Giai đoạn 2:
        'Concurrent revoke thắng future key release theo semantics đã chốt'.
        Mô phỏng 8 luồng Client liên tục xin cấp khóa trong khi 1 luồng thực thi Revoke.
        """
        self.policy_service.init_policy("OBJ-CONCURRENT")
        anchor1 = self.anchor_bridge.anchor_epoch(1, self.policy_service.mmr)
        self.oracle.sync_latest_trusted_root(anchor1)

        lock = threading.Lock()
        results = {
            "success_before_revoke": 0,
            "blocked_after_revoke": 0,
            "illegal_leak_after_revoke": 0
        }
        revoke_committed_event = threading.Event()
        stop_workers = threading.Event()

        def client_worker():
            while not stop_workers.is_set():
                is_after = revoke_committed_event.is_set()
                try:
                    curr_root = self.oracle.get_latest_trusted_root()
                    self.oracle.resolve_fresh_policy(
                        "OBJ-CONCURRENT",
                        curr_root,
                        self.policy_service.policy_records
                    )
                    with lock:
                        if is_after:
                            # NGUY HIỂM: Cấp khóa thành công SAU KHI revoke đã commit
                            results["illegal_leak_after_revoke"] += 1
                        else:
                            results["success_before_revoke"] += 1
                except (PermissionError, StaleRootError):
                    with lock:
                        if is_after:
                            results["blocked_after_revoke"] += 1
                time.sleep(0.001)

        def revoker_worker():
            time.sleep(0.02)  # Cho phép một số request trước đó chạy
            # 1. Ghi nhận transition sang REVOKED
            self.policy_service.transition_policy("OBJ-CONCURRENT", "REVOKED")
            # 2. Neo Epoch 2
            anchor2 = self.anchor_bridge.anchor_epoch(2, self.policy_service.mmr)
            proof = self.anchor_bridge.get_consistency_proof(1, 2)
            # 3. Đồng bộ Latest Trusted Root vào Key Node
            self.oracle.sync_latest_trusted_root(anchor2, proof)
            # 4. Đánh dấu mốc Commit chính thức
            revoke_committed_event.set()

        # Thực thi đa luồng
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            client_futures = [executor.submit(client_worker) for _ in range(8)]
            revoker_future = executor.submit(revoker_worker)

            revoker_future.result()  # Đợi Revoke hoàn tất
            time.sleep(0.05)         # Cho phép các client tiếp tục gửi request sau commit
            stop_workers.set()

        print(f"\n[Kết quả Test Đồng Thời]: {results}")
        
        # BẤT BIẾN NGHIỆM THU: Tuyệt đối không được rò rỉ khóa sau khi Revoke đã Commit
        self.assertEqual(
            results["illegal_leak_after_revoke"],
            0,
            "VI PHẠM AN NINH: Phát hiện rò rỉ khóa DEK sau khi Revoke đã Commit!"
        )
        self.assertGreater(
            results["blocked_after_revoke"],
            0,
            "Hệ thống phải chặn thành công các request diễn ra sau mốc Revoke!"
        )


if __name__ == "__main__":
    unittest.main()