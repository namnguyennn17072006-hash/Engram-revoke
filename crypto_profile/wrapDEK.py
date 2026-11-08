import os
from pyhpke import CipherSuite, KEMId, KDFId, AEADId
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def client_wrap_dek_pipeline(raw_dek: bytes, recipient_public_key, object_id: str, version: int, policy_hash: str, codec_id: str):
    """
     Wrap DEK bằng HPKE kèm theo ràng buộc ngữ cảnh mở rộng
    """
    print(f"\n[Client] Bắt đầu quá trình Wrap DEK cho Object: {object_id} (Codec: {codec_id})")

    # Khởi tạo chuẩn Ciphersuite theo HPKE RFC 9180
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM
    )

    # Xây dựng chuỗi AAD mở rộng (Bao gồm ObjectID, Version, PolicyHash và CodecID)
    aad = f"ObjectID:{object_id}|Version:{version}|PolicyHash:{policy_hash}|CodecID:{codec_id}".encode('utf-8')

    # 3. Thực hiện HPKE Encap và Seal để bọc khóa DEK gắn chặt với AAD mới
    enc, sender_context = suite.create_sender_context(recipient_public_key)
    ct = sender_context.seal(raw_dek, aad=aad)

    # Đóng gói thành Wrapped DEK chuẩn hóa: [enc (32 bytes) || ct]
    wrapped_dek_package = enc + ct

    print("[Client] Wrap DEK bằng HPKE kèm CodecID thành công!")
    print(f"- AAD Binding: {aad.decode('utf-8')}")
    print(f"- Kích thước gói Wrapped DEK: {len(wrapped_dek_package)} bytes")

    return wrapped_dek_package, aad

# --- Kiểm thử tích hợp ---
if __name__ == "__main__":
    # Khởi tạo khóa mẫu cho Key-Release Service
    test_suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    service_key_pair = test_suite.kem.derive_key_pair(os.urandom(32))
    service_pk_r = service_key_pair.public_key

    # Sinh DEK giả lập 
    raw_dek = AESGCM.generate_key(bit_length=256)

    # Thực thi Wrap DEK
    wrapped_package, used_aad = client_wrap_dek_pipeline(
        raw_dek=raw_dek,
        recipient_public_key=service_pk_r,
        object_id="OBJ-2026-001",
        version=1,
        policy_hash="hash_policy_xyz789",
        codec_id="JSON-GCM-v1" 
    )
    
    print("Gói Wrapped DEK và AAD đã sẵn sàng gửi sang Key Service.")