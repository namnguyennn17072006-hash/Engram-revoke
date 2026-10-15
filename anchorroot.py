import os
import time
import hashlib
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# =============================================================================
# 1. CẤU TRÚC MERKLE MOUNTAIN RANGE (MMR) HỖ TRỢ TRÍCH XUẤT PROOF
# =============================================================================
class MMRNode:
    """Nút trong cây con MMR, lưu vết quan hệ cây con để sinh Merkle/Consistency Proof."""
    def __init__(self, hash_val: bytes, height: int, left=None, right=None, size: int = 1):
        self.hash_val = hash_val
        self.height = height
        self.left = left
        self.right = right
        self.size = size  # Số lá trong cây con này


class VerifiableMMR:
    """
    MMR append-only lưu vết các nút cây để tính Root và sinh Consistency Proof.
    """
    def __init__(self):
        self.peaks: List[MMRNode] = []
        self.leaves: List[bytes] = []

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + data).digest()

    @staticmethod
    def hash_node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    @staticmethod
    def bag_peaks(peak_hashes: List[bytes]) -> bytes:
        """Kỹ thuật Peak Bagging: Kết hợp các đỉnh từ phải sang trái."""
        if not peak_hashes:
            return hashlib.sha256(b"EMPTY_MMR").digest()
        cur = peak_hashes[-1]
        for p in reversed(peak_hashes[:-1]):
            cur = hashlib.sha256(b"\x02" + p + cur).digest()
        return cur

    def append(self, leaf_data: bytes) -> int:
        leaf_hash = self.hash_leaf(leaf_data)
        leaf_idx = len(self.leaves)
        self.leaves.append(leaf_hash)

        curr_node = MMRNode(leaf_hash, height=0, size=1)
        while self.peaks and self.peaks[-1].height == curr_node.height:
            left_node = self.peaks.pop()
            parent_hash = self.hash_node(left_node.hash_val, curr_node.hash_val)
            curr_node = MMRNode(
                hash_val=parent_hash,
                height=left_node.height + 1,
                left=left_node,
                right=curr_node,
                size=left_node.size + curr_node.size
            )

        self.peaks.append(curr_node)
        return leaf_idx

    def get_root(self) -> bytes:
        return self.bag_peaks([p.hash_val for p in self.peaks])

    def get_peak_hashes(self) -> List[bytes]:
        return [p.hash_val for p in self.peaks]


def _find_path_to_ancestor(target_hash: bytes, current: MMRNode) -> Optional[List[Tuple[bytes, str]]]:
    """Tìm đường dẫn anh chị em (sibling path) từ nút mục tiêu lên đỉnh tổ tiên."""
    if current.hash_val == target_hash:
        return []
    if not current.left or not current.right:
        return None

    # Tìm phía cây con trái
    left_path = _find_path_to_ancestor(target_hash, current.left)
    if left_path is not None:
        return left_path + [(current.right.hash_val, "right")]

    # Tìm phía cây con phải
    right_path = _find_path_to_ancestor(target_hash, current.right)
    if right_path is not None:
        return right_path + [(current.left.hash_val, "left")]

    return None


# =============================================================================
# 2. ĐỊNH NGHĨA EPOCH ANCHOR VÀ CONSISTENCY PROOF
# =============================================================================
@dataclass
class EpochAnchor:
    epoch: int
    mmr_root: str
    tree_size: int
    peak_hashes: List[str]
    timestamp: float
    prev_anchor_hash: str
    bridge_signature: str

    def canonical_bytes_for_signing(self) -> bytes:
        peaks_str = ",".join(self.peak_hashes)
        return f"{self.epoch}:{self.mmr_root}:{self.tree_size}:{peaks_str}:{int(self.timestamp)}:{self.prev_anchor_hash}".encode("utf-8")

    def get_anchor_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes_for_signing()).hexdigest()


@dataclass
class PeakConsistencyPath:
    old_peak: str
    new_peak: str
    sibling_path: List[Tuple[str, str]]  # [(sibling_hash_hex, direction)]


@dataclass
class ConsistencyProof:
    from_epoch: int
    to_epoch: int
    from_size: int
    to_size: int
    from_root: str
    to_root: str
    peak_proofs: List[PeakConsistencyPath]


# =============================================================================
# 3. ANCHOR BRIDGE & KHO LƯU TRỮ CONSISTENCY PROOF
# =============================================================================
class EngramAnchorBridge:
    """
    Neo MMR Root theo từng Epoch và duy trì tính nhất quán (Consistency).
    """
    def __init__(self, bridge_private_key: ed25519.Ed25519PrivateKey):
        self.bridge_sk = bridge_private_key
        self.bridge_pk = bridge_private_key.public_key()
        self.bridge_id = self.bridge_pk.public_bytes_raw().hex()

        # Lưu trữ lịch sử Anchor theo Epoch: {epoch: EpochAnchor}
        self.anchor_chain: Dict[int, EpochAnchor] = {}
        # Lưu trữ Consistency Proof giữa các Roots: {(from_epoch, to_epoch): ConsistencyProof}
        self.consistency_proof_store: Dict[Tuple[int, int], ConsistencyProof] = {}

    def anchor_epoch(self, epoch: int, mmr: VerifiableMMR) -> EpochAnchor:
        """Neo MMR Root tại mốc Epoch và tự động sinh Consistency Proof với Epoch trước."""
        if epoch in self.anchor_chain:
            raise ValueError(f"Epoch {epoch} đã được anchor trước đó!")

        # Xác định hash của Anchor liền trước để tạo chuỗi khối liên tục
        prev_anchor_hash = "0" * 64
        if epoch > 1:
            prev_anchor = self.anchor_chain.get(epoch - 1)
            if not prev_anchor:
                raise ValueError(f"Thiếu anchor của epoch tiền nhiệm ({epoch - 1})!")
            prev_anchor_hash = prev_anchor.get_anchor_hash()

        peak_hashes_hex = [p.hex() for p in mmr.get_peak_hashes()]
        root_hex = mmr.get_root().hex()

        anchor = EpochAnchor(
            epoch=epoch,
            mmr_root=root_hex,
            tree_size=len(mmr.leaves),
            peak_hashes=peak_hashes_hex,
            timestamp=time.time(),
            prev_anchor_hash=prev_anchor_hash,
            bridge_signature=""
        )

        # Ký số xác thực anchor bằng Ed25519
        sig = self.bridge_sk.sign(anchor.canonical_bytes_for_signing())
        anchor.bridge_signature = sig.hex()
        self.anchor_chain[epoch] = anchor

        # Tự động sinh và lưu Consistency Proof với epoch trước đó
        if epoch > 1:
            prev_anchor = self.anchor_chain[epoch - 1]
            proof = self._generate_consistency_proof(prev_anchor, anchor, mmr)
            self.consistency_proof_store[(epoch - 1, epoch)] = proof

        return anchor

    def _generate_consistency_proof(self, old_anchor: EpochAnchor, new_anchor: EpochAnchor, current_mmr: VerifiableMMR) -> ConsistencyProof:
        """Tạo bằng chứng chuyển tiếp tính nhất quán giữa 2 trạng thái MMR."""
        peak_proofs: List[PeakConsistencyPath] = []

        for old_p_hex in old_anchor.peak_hashes:
            old_p_bytes = bytes.fromhex(old_p_hex)
            found = False
            for current_p in current_mmr.peaks:
                path = _find_path_to_ancestor(old_p_bytes, current_p)
                if path is not None:
                    sibling_path = [(h.hex(), direction) for h, direction in path]
                    peak_proofs.append(
                        PeakConsistencyPath(
                            old_peak=old_p_hex,
                            new_peak=current_p.hash_val.hex(),
                            sibling_path=sibling_path
                        )
                    )
                    found = True
                    break
            if not found:
                raise RuntimeError(f"Lỗi: Không thể tìm thấy đường dẫn hợp nhất cho old peak {old_p_hex}!")

        return ConsistencyProof(
            from_epoch=old_anchor.epoch,
            to_epoch=new_anchor.epoch,
            from_size=old_anchor.tree_size,
            to_size=new_anchor.tree_size,
            from_root=old_anchor.mmr_root,
            to_root=new_anchor.mmr_root,
            peak_proofs=peak_proofs
        )

    def get_consistency_proof(self, from_epoch: int, to_epoch: int) -> Optional[ConsistencyProof]:
        """Truy xuất Consistency Proof đã lưu giữa 2 epoch."""
        return self.consistency_proof_store.get((from_epoch, to_epoch))


# =============================================================================
# 4. BỘ XÁC MINH CỦA KEY NODE (KIỂM TRA FRESHNESS & TỪ CHỐI STALE ROOT)
# =============================================================================
class KeyNodeEnforcementVerifier:
    """
    Thực thi quy tắc kiểm tra tại Key Node:
    - Xác minh tính toàn vẹn của Anchor và Consistency Proof.
    - Áp dụng gợi ý: "Chỉ chấp nhận latest trusted root; từ chối stale root".
    """
    def __init__(self, bridge_public_key: ed25519.Ed25519PublicKey):
        self.bridge_pk = bridge_public_key

    def verify_anchor_signature(self, anchor: EpochAnchor) -> bool:
        """Kiểm tra chữ ký số của Anchor Bridge."""
        try:
            self.bridge_pk.verify(
                bytes.fromhex(anchor.bridge_signature),
                anchor.canonical_bytes_for_signing()
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify_consistency_proof(self, old_anchor: EpochAnchor, new_anchor: EpochAnchor, proof: ConsistencyProof) -> bool:
        """Xác minh toán học rằng MMR Root mới thực sự mở rộng từ MMR Root cũ không bị sửa đổi."""
        if proof.from_epoch != old_anchor.epoch or proof.to_epoch != new_anchor.epoch:
            return False
        if proof.from_root != old_anchor.mmr_root or proof.to_root != new_anchor.mmr_root:
            return False
        if new_anchor.prev_anchor_hash != old_anchor.get_anchor_hash():
            return False

        # 1. Kiểm tra tính toàn vẹn của peak bagging ở cả 2 root
        old_peaks_bytes = [bytes.fromhex(p) for p in old_anchor.peak_hashes]
        new_peaks_bytes = [bytes.fromhex(p) for p in new_anchor.peak_hashes]
        if VerifiableMMR.bag_peaks(old_peaks_bytes).hex() != old_anchor.mmr_root:
            return False
        if VerifiableMMR.bag_peaks(new_peaks_bytes).hex() != new_anchor.mmr_root:
            return False

        # 2. Tái tạo đường dẫn từ old peaks lên các đỉnh mới
        new_peaks_set = set(new_anchor.peak_hashes)
        for p_proof in proof.peak_proofs:
            curr_hash = bytes.fromhex(p_proof.old_peak)
            for sibling_hex, direction in p_proof.sibling_path:
                sibling_bytes = bytes.fromhex(sibling_hex)
                if direction == "right":
                    curr_hash = VerifiableMMR.hash_node(curr_hash, sibling_bytes)
                else:
                    curr_hash = VerifiableMMR.hash_node(sibling_bytes, curr_hash)

            if curr_hash.hex() != p_proof.new_peak or p_proof.new_peak not in new_peaks_set:
                return False

        return True

    def validate_request_freshness(self, presented_root: str, latest_anchor: EpochAnchor) -> bool:
        """
        Gợi ý Giai đoạn 2:
        Key node chỉ chấp nhận proof dưới latest trusted root. Proof hợp lệ nhưng cũ vẫn bị từ chối.
        """
        if presented_root != latest_anchor.mmr_root:
            raise PermissionError(
                f"[Stale Root Rejected] Yêu cầu bị từ chối do sử dụng Root cũ! "
                f"Root cung cấp: {presented_root[:16]}..., Latest Trusted Root: {latest_anchor.mmr_root[:16]}..."
            )
        return True

"""
# =============================================================================
# 5. CHẠY THỬ NGHIỆM VÀ KIỂM TRA ĐỐI KHÁNG (STALE ROOT & TAMPERING)
# =============================================================================
if __name__ == "__main__":
    bridge_sk = ed25519.Ed25519PrivateKey.generate()
    bridge_pk = bridge_sk.public_key()

    anchor_bridge = EngramAnchorBridge(bridge_sk)
    verifier = KeyNodeEnforcementVerifier(bridge_pk)

    mmr = VerifiableMMR()

    print("=== 1. CHU KỲ EPOCH 1: THÊM 5 POLICY EVENTS & ANCHOR ===")
    for i in range(5):
        mmr.append(f"event_ep1_{i}".encode())
    anchor_ep1 = anchor_bridge.anchor_epoch(epoch=1, mmr=mmr)
    print(f"Anchor Epoch 1: Root={anchor_ep1.mmr_root[:16]}... | Size={anchor_ep1.tree_size}")
    print(f"Chữ ký Anchor Bridge: {verifier.verify_anchor_signature(anchor_ep1)}")

    print("\n=== 2. CHU KỲ EPOCH 2: THÊM 7 POLICY EVENTS & ANCHOR ===")
    for i in range(5, 12):
        mmr.append(f"event_ep2_{i}".encode())
    anchor_ep2 = anchor_bridge.anchor_epoch(epoch=2, mmr=mmr)
    print(f"Anchor Epoch 2: Root={anchor_ep2.mmr_root[:16]}... | Size={anchor_ep2.tree_size}")
    print(f"Prev Anchor Hash Chain khớp: {anchor_ep2.prev_anchor_hash == anchor_ep1.get_anchor_hash()}")

    print("\n=== 3. TRUY XUẤT VÀ XÁC MINH CONSISTENCY PROOF GIỮA EPOCH 1 VÀ 2 ===")
    proof_1_2 = anchor_bridge.get_consistency_proof(from_epoch=1, to_epoch=2)
    assert proof_1_2 is not None
    is_consistent = verifier.verify_consistency_proof(anchor_ep1, anchor_ep2, proof_1_2)
    print(f"Bằng chứng tính nhất quán (Consistency Proof) hợp lệ: {is_consistent}")

    print("\n=== 4. THỬ NGHIỆM TẤN CÔNG STALE-ROOT TẠI KEY NODE ===")
    # Client gửi yêu cầu giải mã với root của Epoch 1 khi hệ thống đã lên Epoch 2
    try:
        verifier.validate_request_freshness(
            presented_root=anchor_ep1.mmr_root,
            latest_anchor=anchor_ep2
        )
    except PermissionError as e:
        print(f"Chặn thành công tấn công Stale Root: {e}")

    print("\n=== 5. THỬ NGHIỆM TẤN CÔNG TAMPERING (SỬA ĐỔI ROOT GIẢ MẠO) ===")
    fake_anchor = EpochAnchor(
        epoch=2,
        mmr_root="ffff" * 16,
        tree_size=anchor_ep2.tree_size,
        peak_hashes=anchor_ep2.peak_hashes,
        timestamp=anchor_ep2.timestamp,
        prev_anchor_hash=anchor_ep2.prev_anchor_hash,
        bridge_signature=""
    )
    tampered_verify = verifier.verify_consistency_proof(anchor_ep1, fake_anchor, proof_1_2)
    print(f"Xác minh với Root giả mạo bị từ chối: {not tampered_verify}")
    """