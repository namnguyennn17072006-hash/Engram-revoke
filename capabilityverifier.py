import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class SecurityError(Exception): pass

class CapabilityVerifier:
    def __init__(self, issuer_public_key: ed25519.Ed25519PublicKey):
        self.issuer_pk = issuer_public_key
        self.used_nonces = set() # Replay cache

    def verify_capability(self, capability: dict, signature: bytes, expected_subject: str, expected_object_id: str, required_right: str, current_policy_epoch: int):
        print("[Verifier] Bắt đầu quy trình kiểm tra của Capability...")

        # 1. Xác thực Chữ ký số
        canonical_data = f"{capability['subject']}:{capability['object_id']}:{capability['rights']}:{capability['epoch']}:{capability['expiry']}:{capability['nonce']}".encode('utf-8')
        try:
            self.issuer_pk.verify(signature, canonical_data)
            print("[Step 1] ✓ Xác thực chữ ký số thành công.")
        except InvalidSignature:
            raise SecurityError("[Step 1] LỖI: Chữ ký số không hợp lệ hoặc thẻ bị chỉnh sửa trái phép!")

        # 2. Kiểm tra Ràng buộc Chủ thể & Đối tượng
        if capability['object_id'] != expected_object_id or capability['subject'] != expected_subject:
            raise PermissionError("[Step 2] LỖI: Ràng buộc Chủ thể hoặc Đối tượng không khớp!")

        # 3. Kiểm tra Quyền hạn
        if required_right not in capability['rights']:
            raise PermissionError(f"[Step 3] LỖI: Thẻ không được cấp quyền '{required_right}'!")

        # 4. Kiểm tra Ràng buộc Chu kỳ (Epoch Binding)
        if capability['epoch'] != current_policy_epoch:
            raise SecurityError(f"[Step 4] LỖI: Epoch không khớp! Thẻ thuộc epoch {capability['epoch']}, hiện tại là epoch {current_policy_epoch}.")

        # 5. Kiểm tra Thời gian hiệu lực
        if time.time() > capability['expiry']:
            raise SecurityError("[Step 5] LỖI: Capability đã hết hạn (Expired)!")

        # 6. Kiểm tra Chống phát lại (Nonce / Replay Cache)
        nonce = capability['nonce']
        if nonce in self.used_nonces:
            raise SecurityError(f"[Step 6] LỖI: Phát hiện Replay Attack! Nonce '{nonce}' đã từng được sử dụng.")
        
        self.used_nonces.add(nonce)
        print("[Step 6] ✓ Nonce chưa bị lặp (Chống phát lại thành công).")

        print("[Verifier] HOÀN TẤT: Capability vượt qua toàn bộ 6 lớp kiểm tra an ninh!\n")
        return True

# --- CHẠY THỬ NGHIỆM ---
if __name__ == "__main__":
    # 1. Giả lập Policy Service sinh cặp khóa Ed25519
    policy_service_sk = ed25519.Ed25519PrivateKey.generate()
    policy_service_pk = policy_service_sk.public_key()

    # 2. Khởi tạo Verifier với Public Key của Policy Service
    verifier = CapabilityVerifier(issuer_public_key=policy_service_pk)

    # 3. Tạo một Capability hợp lệ
    capability_data = {
        "subject": "user_alice",
        "object_id": "OBJ-2026-001",
        "rights": "READ",
        "epoch": 1,
        "expiry": int(time.time()) + 300, # Còn hạn 5 phút
        "nonce": "unique_nonce_abc123"
    }

    # Policy Service ký lên canonical_data
    canonical_bytes = f"{capability_data['subject']}:{capability_data['object_id']}:{capability_data['rights']}:{capability_data['epoch']}:{capability_data['expiry']}:{capability_data['nonce']}".encode('utf-8')
    valid_signature = policy_service_sk.sign(canonical_bytes)

    # 4. Thử nghiệm xác thực thành công
    verifier.verify_capability(
        capability=capability_data,
        signature=valid_signature,
        expected_subject="user_alice",
        expected_object_id="OBJ-2026-001",
        required_right="READ",
        current_policy_epoch=1
    )

    # 5. Thử nghiệm phát lại (Replay Attack)
    try:
        print("[Test] Thử phát lại (Replay) thẻ vừa dùng...")
        verifier.verify_capability(
            capability=capability_data,
            signature=valid_signature,
            expected_subject="user_alice",
            expected_object_id="OBJ-2026-001",
            required_right="READ",
            current_policy_epoch=1
        )
    except SecurityError as e:
        print(f"[Test Pass] Đã chặn Replay thành công: {e}")