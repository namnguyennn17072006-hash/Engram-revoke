import time

class PolicyEngine:
    def __init__(self):
        # Control State lưu trữ trạng thái policy của từng Object
        self.policy_db = {
            "OBJ-2026-001": {
                "state": "ACTIVE", # Các trạng thái: ACTIVE, SUSPENDED, EXPIRED, REVOKED
                "epoch": 1,
                "policy_root": "root_hash_v1",
                "last_verified_timestamp": time.time()
            }
        }
        self.used_nonces = set()

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

# --- Đoạn code chạy kiểm thử ---
if __name__ == "__main__":
    engine = PolicyAndCapabilityEngine()
    cap = {"nonce": "nonce_xyz", "expiry": time.time() + 60}

    try:
        # 1. Truy cập khi đang ACTIVE (Thành công)
        engine.request_access_gatekeeper("OBJ-2026-001", "root_hash_v1", cap)

        # 2. Chuyển trạng thái sang REVOKED (Terminal State)
        engine.update_policy_state("OBJ-2026-001", "REVOKED")

        # 3. Thử xin cấp khóa lại sau khi đã Revoke (Sẽ bị chặn đứng)
        print("\n--- Thử xin cấp khóa sau khi Revoke ---")
        engine.request_access_gatekeeper("OBJ-2026-001", "root_hash_v1", {"nonce": "nonce_abc", "expiry": time.time() + 60})

    except Exception as e:
        print(f"[FAIL-CLOSED KÍCH HOẠT] {e}")