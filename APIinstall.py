import time
import os
from fastapi import FastAPI, HTTPException, status,Query
from typing import Optional
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyhpke import CipherSuite, KEMId, KDFId, AEADId
from PDPinstall import PolicyEngine
from capabilityverifier import CapabilityVerifier, SecurityError
app = FastAPI(title="Engram-Revoke MVP API", version="1.0")

# --- 1. KHỞI TẠO HỆ THỐNG KHO VÀ KHÓA GIẢ LẬP ---
# Kho lưu trữ Control State (RocksDB/PostgreSQL giả lập trong RAM)[cite: 3]
policy_db = {}
storage_node_db = {} # Lưu payload ciphertext (RS)
audit_logs = []      # Lưu lịch sử audit events
used_nonces = set()  # Replay cache chống phát lại[cite: 5]

# Tạo cặp khóa cho Key-Release Service (HPKE) và Issuer (Ed25519)
hpke_suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
service_key_pair = hpke_suite.kem.derive_key_pair(os.urandom(32))

issuer_private_key = ed25519.Ed25519PrivateKey.generate()
issuer_public_key = issuer_private_key.public_key
policy_engine = PolicyEngine()
verifier = CapabilityVerifier(issuer_public_key)
# --- 2. ĐỊNH NGHẠI CÁC CẤU TRÚC DỮ LIỆU (PYDANTIC MODELS) ---
class IngestRequest(BaseModel):
    object_id: str
    version: int
    policy_hash: str
    codec_id: str
    payload_nonce: str # Dạng hex string
    payload_ciphertext: str # Dạng hex string
    wrapped_dek: str # Dạng hex string

class AccessRequest(BaseModel):
    object_id: str
    current_policy_root: str
    subject: str
    required_right: str
    capability: dict
    signature: str # Dạng hex string
    wrapped_dek: str # Dạng hex string


# --- 3. TRIỂN KHAI CÁC API ENDPOINTS ---

@app.post("/api/v1/ingest")
#1. Ingest API: Nhận dữ liệu mã hóa và thông tin policy từ client đẩy vào RS
def ingest_data(req: IngestRequest):
    #Kiểm tra trùng lặp Object ID
    if req.object_id in storage_node_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Lỗi: Object ID '{req.object_id}' đã tồn tại trong hệ thống."
        )
    #Validate định dạng chuỗi Hex đầu vào
    try:
        nonce_bytes = bytes.fromhex(req.payload_nonce)
        ciphertext_bytes = bytes.fromhex(req.payload_ciphertext)
        wrapped_dek_bytes = bytes.fromhex(req.wrapped_dek)
        
        if len(nonce_bytes) != 12:
            raise ValueError("AES-GCM Nonce phải có độ dài đúng 12 bytes (24 ký tự hex).")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Dữ liệu Hex không hợp lệ: {str(e)}"
        )
    # Lưu vào Storage Node giả lập
    storage_node_db[req.object_id] = {
        "version": req.version,
        "payload_nonce": req.payload_nonce,
        "payload_ciphertext": req.payload_ciphertext,
        "codec_id": req.codec_id
        
    }

    # Khởi tạo Policy ban đầu ở trạng thái ACTIVE & Quản lý Wrapped DEK tại Key Service
    policy_db[req.object_id] = {
        "state": "ACTIVE",
        "epoch": 1,
        "policy_root": req.policy_hash,
        "policy_hash": req.policy_hash,
         "wrapped_dek": req.wrapped_dek
    }

    audit_logs.append({"timestamp": time.time(), "action": "INGEST", "object_id": req.object_id, "status": "SUCCESS"})
    return {"status": "success", "message": f"Đã lưu trữ thành công object {req.object_id} lên RS pipeline."}


@app.get("/api/v1/policy/{object_id}")
def get_policy(object_id: str):
    """
    2. GetPolicy API: Cung cấp thông tin policy và metadata hiện tại.
    """
    policy = policy_db.get(object_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Không tìm thấy chính sách cho object này.")
    policy_metadata = {
        "object_id": object_id,
        "state": policy.get("state"),
        "epoch": policy.get("epoch"),
        "policy_hash": policy.get("policy_hash"),
        "policy_root": policy.get("policy_root")
    }
    return {
        "status": "success",
        "object_id": object_id,
        "policy": policy_metadata
    }

@app.post("/api/v1/revoke/{object_id}")
def revoke_policy(object_id: str):
    """
    3. Revoke API: Chuyển policy sang trạng thái TERMINAL (REVOKED) để chặn unwrap tương lai.
    """
    policy = policy_db.get(object_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Object không tồn tại.")
    old_state = policy.get("state")
    if policy["state"] in ["REVOKED", "EXPIRED"]:
        raise HTTPException(status_code=400, detail="Policy đã ở trạng thái terminal từ trước.")

    policy["state"] = "REVOKED"
    policy["epoch"] = policy.get("epoch", 1) + 1
    audit_logs.append({"timestamp": time.time(), "action": "REVOKE", "object_id": object_id,"old_state": old_state,"new_state": "REVOKED","epoch": policy["epoch"], "status": "SUCCESS"})
    return {"status": "success", "message": f"Đã thu hồi (REVOKE) thành công object {object_id}. Chặn vĩnh viễn quyền cấp khóa.","object_id": object_id,
        "previous_state": old_state,
        "current_state": "REVOKED",
        "current_epoch": policy["epoch"]}


@app.post("/api/v1/request-access")
def request_access(req: AccessRequest):
    """
    4. RequestAccess API (Key Service): Chạy PDP + 6 bước Capability Verifier rồi mới Unwrap DEK[cite: 3, 5].
    """
    object_id = req.object_id
    current_time = time.time()

    # --- BƯỚC A: POLICY DECISION POINT (PDP) & FAIL-CLOSED ---
    try:
        policy = policy_engine.evaluate_policy(object_id, req.current_policy_root)
    except (PermissionError, SecurityError) as e:
        audit_logs.append({
            "timestamp": current_time, 
            "action": "REQUEST_ACCESS", 
            "object_id": object_id, 
            "status": "BLOCKED_PDP",
            "reason": str(e)
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=f"PDP Blocked: {str(e)}"
        )

    # --- BƯỚC B: CHỐNG REPLAY ATTACK & 6 BƯỚC CAPABILITY VERIFIER ---
    cap_nonce = req.capability.get("nonce")
    if cap_nonce in used_nonces:
        audit_logs.append({
            "timestamp": current_time, 
            "action": "REQUEST_ACCESS", 
            "object_id": object_id, 
            "status": "BLOCKED_REPLAY"
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Tấn công phát lại (Replay Attack): Capability Nonce này đã được sử dụng."
        )

    try:
        sig_bytes = bytes.fromhex(req.signature)
        verifier.verify_capability(
            capability=req.capability,
            signature=sig_bytes,
            expected_subject=req.subject,
            expected_object_id=object_id,
            required_right=req.required_right,
            current_policy_epoch=policy.get("epoch", 1)
        )
    except (PermissionError, SecurityError, ValueError) as e:
        audit_logs.append({
            "timestamp": current_time, 
            "action": "REQUEST_ACCESS", 
            "object_id": object_id, 
            "status": "BLOCKED_VERIFIER",
            "reason": str(e)
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=f"Capability Verification Failed: {str(e)}"
        )

    # --- BƯỚC C: HPKE UNWRAP DEK THỰC TẾ ---
    try:
        raw_wrapped = bytes.fromhex(req.wrapped_dek)
        if len(raw_wrapped) < 32:
            raise ValueError("Kích thước wrapped_dek không hợp lệ (phải >= 32 bytes KEM encapsulation).")

        enc = raw_wrapped[:32]
        ct = raw_wrapped[32:]

        # Lấy metadata an toàn từ Storage Node & Policy DB để tái tạo Canonical AAD
        storage_info = storage_node_db.get(object_id, {})
        obj_version = storage_info.get("version", policy.get("version", 1))
        codec_id = storage_info.get("codec_id", "default")
        policy_hash = policy.get("policy_hash", req.current_policy_root)

        canonical_aad = f"ObjectID:{object_id}|Version:{obj_version}|PolicyHash:{policy_hash}|CodecID:{codec_id}".encode('utf-8')

        # Giải mã HPKE Unwrap DEK
        receiver_context = hpke_suite.create_receiver_context(enc, service_key_pair.private_key)
        raw_dek = receiver_context.open(ct, aad=canonical_aad)

    except Exception as e:
        audit_logs.append({
            "timestamp": current_time, 
            "action": "REQUEST_ACCESS", 
            "object_id": object_id, 
            "status": "BLOCKED_CRYPTO",
            "reason": str(e)
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Lỗi giải mã HPKE Unwrap DEK (Sai AAD hoặc dữ liệu bị sửa đổi): {str(e)}"
        )

    # Đánh dấu Nonce đã sử dụng thành công
    if cap_nonce:
        used_nonces.add(cap_nonce)

    # Ghi nhận Audit Log thành công
    audit_logs.append({
        "timestamp": current_time, 
        "action": "REQUEST_ACCESS", 
        "object_id": object_id, 
        "status": "SUCCESS"
    })

    return {
        "status": "success",
        "message": "Đã vượt qua tất cả vòng kiểm tra an ninh và giải mã DEK thành công!",
        "object_id": object_id,
        "raw_dek_hex": raw_dek.hex()
    }
    
@app.get("/api/v1/audit-events")
def get_audit_events(
    object_id: Optional[str] = Query(None, description="Lọc log theo Object ID cụ thể"),
    action: Optional[str] = Query(None, description="Lọc theo loại hành động (INGEST, REQUEST_ACCESS, REVOKE)"),
):
    """
    5. AuditEvents API: Truy xuất lịch sử kiểm toán an ninh của hệ thống.
    Hỗ trợ lọc theo object_id, action và giới hạn số lượng bản ghi.
    """
    filtered_logs = audit_logs

    # 1. Lọc theo object_id nếu có
    if object_id:
        filtered_logs = [log for log in filtered_logs if log.get("object_id") == object_id]

    # 2. Lọc theo action nếu có
    if action:
        filtered_logs = [log for log in filtered_logs if log.get("action") == action.upper()]

    return {
        "status": "success",
        "total_system_events": len(audit_logs),
        "filtered_count": len(filtered_logs),
        "returned_count": len(filtered_logs),
        "events": filtered_logs
    }