import os
import unittest
from pyhpke import CipherSuite, KEMId, KDFId, AEADId
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class TestEngramEnvelopeEncryption(unittest.TestCase):
    
    def setUp(self):
        #Khởi tạo ciphersuite chuẩn RFC 9180
        self.suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256,
            KDFId.HKDF_SHA256,
            AEADId.AES128_GCM
        )
        #Tạo cặp khóa ngẫu nhiên cho phía nhận hợp lệ (Key Committee)
        self.receiver_key = self.suite.kem.derive_key_pair(os.urandom(32))
        self.pk_r = self.receiver_key.public_key
        self.sk_r = self.receiver_key.private_key

    def test_envelope_encryption_flow_with_packaging(self):
        """Xây known-answer tests"""
        plaintext = b"Tai lieu bi mat"
        aad = b"ObjectID:999|Version:1|PolicyHash:xyz789"

        #Sinh DEK và mã hóa payload
        raw_dek = AESGCM.generate_key(bit_length=128)
        payload_nonce = os.urandom(12)
        payload_ciphertext = AESGCM(raw_dek).encrypt(payload_nonce, plaintext, None)

        #KEM Encap + KDF KeySchedule + AEAD Seal
        enc, sender_context = self.suite.create_sender_context(self.pk_r)
        ct = sender_context.seal(raw_dek, aad=aad)

        #Đóng gói thành Wrapped DEK = [enc || ct]
        wrapped_dek_package = enc + ct

        # --- PHÍA NHẬN GIẢI MÃ ---
        enc_received = wrapped_dek_package[:32]
        ct_received = wrapped_dek_package[32:]
        receiver_context = self.suite.create_recipient_context(enc_received, self.sk_r)
        recovered_dek = receiver_context.open(ct_received, aad=aad)

        # Kiểm tra tính chính xác
        self.assertEqual(raw_dek, recovered_dek, "Key wrapping failed: DEK mismatch!")
        decrypted_plaintext = AESGCM(raw_dek).decrypt(payload_nonce, payload_ciphertext, None)
        self.assertEqual(plaintext, decrypted_plaintext, "Payload decryption failed!")
        print("\n Test chạy thành công!")

    def test_misuse_aad_mismatch(self):
        """Misuse Test: Chặn đứng khi AAD bị thay đổi trái phép (Fail-closed)"""
        plaintext = b"Du lieu toi mat"
        valid_aad = b"ObjectID:999|Version:1|PolicyHash:ValidPolicyHash"
        tampered_aad = b"ObjectID:999|Version:2|PolicyHash:MaliciousPolicyHash"

        raw_dek = AESGCM.generate_key(bit_length=128)
        payload_nonce = os.urandom(12)
        _ = AESGCM(raw_dek).encrypt(payload_nonce, plaintext, None)

        enc, sender_context = self.suite.create_sender_context(self.pk_r)
        ct = sender_context.seal(raw_dek, aad=valid_aad)
        wrapped_dek_package = enc + ct

        enc_received = wrapped_dek_package[:32]
        ct_received = wrapped_dek_package[32:]
        receiver_context = self.suite.create_recipient_context(enc_received, self.sk_r)
        
        with self.assertRaises(Exception) as context:
            receiver_context.open(ct_received, aad=tampered_aad)
            
        print(f"Misuse AAD Test Passed!Error: {context.exception}")

    def test_misuse_ciphertext_tampering(self):
        """Misuse Test 2: Bản mã bị hỏng hoặc giả mạo (Ciphertext Corruption / Tampering)"""
        aad = b"ObjectID:999|Version:1|PolicyHash:xyz789"
        raw_dek = AESGCM.generate_key(bit_length=128)

        enc, sender_context = self.suite.create_sender_context(self.pk_r)
        ct = sender_context.seal(raw_dek, aad=aad)
        wrapped_dek_package = enc + ct

        enc_received = wrapped_dek_package[:32]
        
        # CỐ TÌNH SỬA ĐỔI BẢN MÃ
        ct_bytes = bytearray(wrapped_dek_package[32:])
        ct_bytes[-1] ^= 0xFF # Lật bit byte cuối để phá hỏng tính toàn vẹn
        tampered_ct = bytes(ct_bytes)
        receiver_context = self.suite.create_recipient_context(enc_received, self.sk_r)

        # Cố gắng mở bản mã đã bị can thiệp
        with self.assertRaises(Exception) as context:
            receiver_context.open(tampered_ct, aad=aad)

        print(f"Misuse Ciphertext Tampering Test Passed!Error:{context.exception}")
    def test_misuse_wrong_secret_key(self):
            """Misuse Test 1: Sai khóa bí mật (Wrong Secret Key)"""
            aad = b"ObjectID:999|Version:1|PolicyHash:xyz789"
            raw_dek = AESGCM.generate_key(bit_length=128)
    
            enc, sender_context = self.suite.create_sender_context(self.pk_r)
            ct = sender_context.seal(raw_dek, aad=aad)
            wrapped_dek_package = enc + ct
    
            enc_received = wrapped_dek_package[:32]
            ct_received = wrapped_dek_package[32:]
    
            # Tạo một khóa bí mật HOÀN TOÀN KHÁC
            wrong_receiver_key = self.suite.kem.derive_key_pair(os.urandom(32))
            wrong_sk_r = wrong_receiver_key.private_key
    
            # Cố gắng giải mã bằng khóa sai
            with self.assertRaises(Exception) as context:
                wrong_receiver_context = self.suite.create_recipient_context(enc_received, wrong_sk_r)
                wrong_receiver_context.open(ct_received, aad=aad)
    
            print(f"Misuse Wrong Key Test Passed!Error: {context.exception}")

if __name__ == "__main__":
    unittest.main()