import time

class PolicyEngine:
    def __init__(self):
        self.policy_db = {}
        self.used_nonces = set()

    def register_policy(self, object_id: str, policy_root: str, policy_hash: str, version: int = 1):
        """
        đăng ký mới hoặc cập nhật policy cho bất kỳ object nào 
        được đẩy vào hệ thống (thường gọi từ API Ingest).
        """
        self.policy_db[object_id] = {
            "state": "ACTIVE",    
            "epoch": 1,
            "policy_root": policy_root,
            "policy_hash": policy_hash,
            "version": version,
            "last_verified_timestamp": time.time()
        }
        print(f"[Policy Engine] Đã đăng ký thành công policy cho object: {object_id}")

    def update_policy_state(self, object_id: str, new_state: str):
        """Mô phỏng việc chuyển đổi trạng thái policy theo State Machine"""
        policy = self.policy_db.get(object_id)
        if not policy:
            raise ValueError("Object không tồn tại!")
        
        current_state = policy["state"]
        
        # Kiểm tra tính hợp lệ của việc chuyển đổi trạng thái
        valid_transitions = {
            ("ACTIVE", "SUSPENDED"), ("SUSPENDED", "ACTIVE"),
            ("ACTIVE", "EXPIRED"), ("ACTIVE", "REVOKED"),
            ("SUSPENDED", "REVOKED")
        }
        
        if current_state in ["EXPIRED", "REVOKED"]:
            raise ValueError(f"Không thể đổi trạng thái từ '{current_state}' vì đây là trạng thái Terminal (Kết thúc)!")
            
        if (current_state, new_state) not in valid_transitions:
            raise ValueError(f"Chuyển đổi trạng thái từ {current_state} sang {new_state} không hợp lệ!")
            
        policy["state"] = new_state
        print(f"[Policy Engine] Object {object_id} đã chuyển trạng thái: {current_state} -> {new_state}")

    def evaluate_policy(self, object_id: str, current_policy_root: str) -> dict:
        """
        1. Policy Decision Point (PDP) tích hợp State Machine & Fail-closed.
        """
        policy = self.policy_db.get(object_id)
        if not policy:
            raise PermissionError(f"Policy cho object {object_id} không tồn tại!")
        
        # Kiểm tra quy tắc Fail-closed: Xác thực Policy Root mới nhất và Freshness[cite: 4]
        if policy["policy_root"] != current_policy_root:
            print("[Warning] Liveness reduction: Không khớp Policy Root mới nhất!")
            raise SecurityError("Fail-closed: Không xác định được policy root mới nhất hoặc mất tính tươi!")

        state = policy["state"]

        # Kiểm tra trạng thái Terminal cho Key Release[cite: 4]
        if state in ["REVOKED", "EXPIRED"]:
            raise PermissionError(f"Từ chối cấp khóa (Key Release Blocked): Policy đang ở trạng thái terminal '{state}'[cite: 4].")
        
        if state == "SUSPENDED":
            raise PermissionError("Từ chối cấp khóa: Policy đang bị tạm ngưng (SUSPENDED).")
            
        if state != "ACTIVE":
            raise PermissionError("Trạng thái policy không hợp lệ để cấp khóa.")
        
        return policy

    def request_access_gatekeeper(self, object_id: str, current_policy_root: str, capability: dict):
        """Cổng gác tổng hợp trước khi cho phép Key Service tiến hành Unwrap DEK."""
        print(f"\n[Access Control] Đang xử lý yêu cầu cho Object: {object_id}")

        # Đánh giá chính sách qua PDP theo State Machine
        policy = self.evaluate_policy(object_id, current_policy_root)

        # Kiểm tra capability và chống Replay
        if capability["nonce"] in self.used_nonces:
            raise SecurityError("Phát hiện Replay Attack!")
        if time.time() > capability["expiry"]:
            raise TimeoutError("Capability đã hết hạn!")

        self.used_nonces.add(capability["nonce"])
        print("[Access Control] Hợp lệ! Cho phép Key Service tiến hành Unwrap DEK.")
        return True