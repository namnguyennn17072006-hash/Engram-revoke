import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def client_ingest_pipeline(plaintext_payload: bytes, object_id: str, version: int, policy_hash: str, codec_id: int = 1):
    """
    Client sinh DEK, AEAD-encrypt payload kèm Canonical AAD, 
    và chuẩn bị gói tin để đẩy vào pipeline RS (Storage Node).
    """
    print(f"[Client] Bắt đầu xử lý Ingest cho Object: {object_id} (Version: {version})")

    #Client sinh khóa DEK ngẫu nhiên 256-bit và Nonce 12-byte (CSPRNG)
    raw_dek = AESGCM.generate_key(bit_length=256)
    payload_nonce = os.urandom(12)

    #Đóng gói Canonical AAD 
    aad_str = f"ObjectID:{object_id}|Version:{version}|PolicyHash:{policy_hash}|CodecID:{codec_id}"
    canonical_aad = aad_str.encode('utf-8')

    # Mã hóa AEAD payload 
    aes_engine = AESGCM(raw_dek)
    payload_ciphertext = aes_engine.encrypt(
        nonce=payload_nonce, 
        data=plaintext_payload, 
        associated_data=canonical_aad 
    )

    #Đóng gói gói tin gửi vào pipeline RS
    rs_payload_package = {
        "object_id": object_id,
        "version": version,
        "policy_hash": policy_hash,
        "codec_id": codec_id,
        "payload_nonce": payload_nonce,
        "payload_ciphertext": payload_ciphertext,
        "canonical_aad": canonical_aad
    }
    
    print("[Client] Mã hóa payload thành công. Gói tin sẵn sàng gửi vào pipeline RS.")
    return rs_payload_package, raw_dek

if __name__ == "__main__":
    file_path = "secret.txt" 
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            
        print(f"Đã đọc thành công file '{file_path}' với kích thước: {len(file_data)} bytes.")

        # Đưa dữ liệu từ file vào pipeline Ingest
        package, dek = client_ingest_pipeline(
            plaintext_payload=file_data,
            object_id="OBJ-FILE-001",
            version=1,
            policy_hash="policy_hash_from_file_xyz",
            codec_id=1
        )
        
        print("\nDữ liệu đóng gói sẵn sàng gửi lên RS:")
        print(f"- Object ID: {package['object_id']}")
        print(f"- Canonical AAD: {package['canonical_aad'].decode('utf-8')}")
        print(f"- Nonce (hex): {package['payload_nonce'].hex()}")
        print(f"- Ciphertext (bytes): {len(package['payload_ciphertext'])} bytes")

    except FileNotFoundError:
        print(f"[LỖI] Không tìm thấy file '{file_path}'. Hãy tạo file thử nghiệm trước khi chạy.")