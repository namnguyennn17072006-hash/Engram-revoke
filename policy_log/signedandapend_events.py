import os
import time
import hashlib
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# -------------------------------------------------------------
# 1. CẤU TRÚC MERKLE MOUNTAIN RANGE (MMR) - THAY THẾ TỪ ANCHORROOT.PY
# -------------------------------------------------------------
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

    def append(self, leaf_data: bytes) -> Tuple[int, bytes]:
        """Thêm một lá mới vào MMR và cập nhật các peaks, trả về (leaf_index, mmr_root)."""
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
        return leaf_idx, self.get_root()

    def get_root(self) -> bytes:
        return self.bag_peaks([p.hash_val for p in self.peaks])

    def get_peak_hashes(self) -> List[bytes]:
        return [p.hash_val for p in self.peaks]


# -------------------------------------------------------------
# 2. ĐỊNH NGHĨA POLICY EVENT VÀ INVARIANTS THEO GỢI Ý GIAI ĐOẠN 2
# PolicyEvent = (ObjectID, oldState, newState, epoch, sequence, signer, signature)
# -------------------------------------------------------------
VALID_TRANSITIONS = {
    ('ACTIVE', 'SUSPENDED'),
    ('SUSPENDED', 'ACTIVE'),
    ('ACTIVE', 'EXPIRED'),
    ('ACTIVE', 'REVOKED'),
    ('SUSPENDED', 'REVOKED')
}

TERMINAL_STATES = {'REVOKED', 'EXPIRED'}

@dataclass
class PolicyEvent:
    object_id: str
    old_state: str
    new_state: str
    epoch: int
    sequence: int
    signer: str         # Hex representation của Public Key hoặc Signer ID
    signature: str      # Hex representation của Ed25519 signature

    def canonical_bytes_for_signing(self) -> bytes:
        """Dữ liệu chuẩn tắc (canonical representation) để tạo và xác thực chữ ký."""
        return f'{self.object_id}:{self.old_state}:{self.new_state}:{self.epoch}:{self.sequence}:{self.signer}'.encode('utf-8')

    def to_leaf_bytes(self) -> bytes:
        """Dữ liệu chuẩn tắc để băm và đưa vào lá (leaf) của MMR."""
        return f'{self.object_id}:{self.old_state}:{self.new_state}:{self.epoch}:{self.sequence}:{self.signer}:{self.signature}'.encode('utf-8')


# -------------------------------------------------------------
# 3. POLICY STATE MACHINE & LOG SERVICE TÍCH HỢP MMR
# -------------------------------------------------------------
class PolicyLogService:
    def __init__(self, authority_sk: ed25519.Ed25519PrivateKey):
        self.authority_sk = authority_sk
        self.authority_pk = authority_sk.public_key()
        self.signer_id = self.authority_pk.public_bytes_raw().hex()
        
        self.mmr = VerifiableMMR()
        # Lưu trạng thái hiện tại theo Object: {object_id: {'state': ..., 'epoch': ..., 'sequence': ...}}
        self.policy_records: Dict[str, dict] = {}
        self.event_history: List[PolicyEvent] = []

    def init_policy(self, object_id: str, initial_epoch: int = 1):
        """Khởi tạo trạng thái ban đầu của Policy (ACTIVE) và ghi event đầu tiên."""
        if object_id in self.policy_records:
            raise ValueError(f'Policy cho Object ID {object_id} đã tồn tại!')
        
        self.policy_records[object_id] = {
            'state': 'ACTIVE',
            'epoch': initial_epoch,
            'sequence': 1
        }
        
        # Ghi nhận event khởi tạo (None -> ACTIVE)
        event = self._create_signed_event(object_id, 'NONE', 'ACTIVE', initial_epoch, 1)
        leaf_idx, mmr_root = self.mmr.append(event.to_leaf_bytes())
        self.event_history.append(event)
        return event, leaf_idx, mmr_root

    def _create_signed_event(self, object_id: str, old_state: str, new_state: str, epoch: int, sequence: int) -> PolicyEvent:
        """Tạo PolicyEvent và ký số bằng Ed25519."""
        unsigned_event = PolicyEvent(
            object_id=object_id,
            old_state=old_state,
            new_state=new_state,
            epoch=epoch,
            sequence=sequence,
            signer=self.signer_id,
            signature=''
        )
        sig = self.authority_sk.sign(unsigned_event.canonical_bytes_for_signing())
        unsigned_event.signature = sig.hex()
        return unsigned_event

    def transition_policy(self, object_id: str, new_state: str) -> Tuple[PolicyEvent, int, str]:
        """
        Thực hiện chuyển đổi trạng thái Policy:
        - Kiểm tra Terminal state invariant
        - Kiểm tra tính hợp lệ của State Machine
        - Cập nhật epoch và sequence
        - Tạo signed event và append vào MMR
        """
        record = self.policy_records.get(object_id)
        if not record:
            raise ValueError(f'Không tìm thấy Policy cho Object ID {object_id}')

        current_state = record['state']
        current_epoch = record['epoch']
        current_seq = record['sequence']

        # 1. Kiểm tra Terminal State Invariant: REVOKED/EXPIRED không quay lại ACTIVE hoặc bất kỳ trạng thái nào khác
        if current_state in TERMINAL_STATES:
            raise ValueError(
                f'Vi phạm Terminal State Invariant: Policy đã ở trạng thái {current_state}, không thể chuyển sang {new_state}!'
            )

        # 2. Kiểm tra chuyển đổi trạng thái hợp lệ
        if (current_state, new_state) not in VALID_TRANSITIONS:
            raise ValueError(f'Chuyển đổi trạng thái không hợp lệ: {current_state} -> {new_state}')

        # 3. Cập nhật chu kỳ (epoch tăng khi revoke hoặc cập nhật quyền) và sequence
        next_epoch = current_epoch + 1 if new_state in TERMINAL_STATES else current_epoch
        next_seq = current_seq + 1

        # Cập nhật record cục bộ
        record['state'] = new_state
        record['epoch'] = next_epoch
        record['sequence'] = next_seq

        # 4. Tạo signed event: PolicyEvent = (ObjectID, oldState, newState, epoch, sequence, signer, signature)
        signed_event = self._create_signed_event(
            object_id=object_id,
            old_state=current_state,
            new_state=new_state,
            epoch=next_epoch,
            sequence=next_seq
        )

        # 5. Append vào MMR và nhận MMR Root mới
        leaf_index, mmr_root = self.mmr.append(signed_event.to_leaf_bytes())
        self.event_history.append(signed_event)

        return signed_event, leaf_index, mmr_root.hex()


# Kiểm tra chạy thử
if __name__ == "__main__":
    sk = ed25519.Ed25519PrivateKey.generate()
    service = PolicyLogService(sk)

    evt1, idx1, root1 = service.init_policy('OBJ-001')
    print(f'Init: leaf={idx1}, root={root1[:16]}...')

    evt2, idx2, root2 = service.transition_policy('OBJ-001', 'SUSPENDED')
    print(f'Transition to SUSPENDED: leaf={idx2}, root={root2[:16]}...')

    evt3, idx3, root3 = service.transition_policy('OBJ-001', 'ACTIVE')
    print(f'Transition to ACTIVE: leaf={idx3}, root={root3[:16]}...')

    evt4, idx4, root4 = service.transition_policy('OBJ-001', 'REVOKED')
    print(f'Transition to REVOKED: leaf={idx4}, root={root4[:16]}...')

    # Thử vi phạm terminal invariant
    try:
        service.transition_policy('OBJ-001', 'ACTIVE')
    except ValueError as e:
        print('Catch invariant violation:', e)