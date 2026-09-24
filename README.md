ENGRAM-REVOKE
Khả dụng có thời hạn và thu hồi quyền giải mã có kiểm toán
Xây dựng lớp mã hóa, policy và threshold key service để Engram vẫn lưu ciphertext bền vững nhưng ngừng cấp khả năng giải mã sau khi policy hết hạn hoặc bị thu hồi.
Mục đích sử dụng tài liệu
Đề tài phải được triển khai như một nghiên cứu an toàn hệ thống, không phải tuyên bố tuân thủ pháp luật hoặc xóa vật lý tuyệt đối. Mọi bảo đảm đều phải gắn với threat model và assumptions cụ thể.
Claim cốt lõi: Sau khi policy bị thu hồi, hạ tầng không phát hành decryption capability mới cho đối thủ kiểm soát dưới ngưỡng t, với điều kiện plaintext hoặc DEK chưa bị lấy trước đó.
Không claim: Xóa mọi bản sao vật lý, thu hồi plaintext đã tải, hoặc vô hiệu hóa khóa mà người dùng đã lưu trước khi revoke.
2. Câu hỏi nghiên cứu và threat model
Câu hỏi nghiên cứu
•	RQ1. Định nghĩa revocable availability thế nào để phân biệt availability của ciphertext và decryptability của plaintext?
•	RQ2. Làm thế nào bảo đảm key service luôn quyết định theo policy state mới nhất, không chấp nhận stale proof hoặc replay capability?
•	RQ3. Threshold key service đạt cân bằng nào giữa ngưỡng an toàn, liveness, latency và chi phí resharing?
•	RQ4. Thu hồi theo epoch và rewrap DEK có thể tránh mã hóa lại toàn bộ ciphertext đến mức nào?
*Threat model tối thiểu*

| Thực thể | Có thể lỗi/Byzantine | Giả định tối thiểu |
| :--- | :--- | :--- |
| **Data owner** | Có thể cấu hình policy sai. | Sinh và gửi plaintext qua client tin cậy ở thời điểm ingest. |
| **Storage node** | Giữ ciphertext, trả stale/corrupt shards. | Không được biết DEK; chịu cơ chế integrity/availability của Engram. |
| **Policy service** | Trả state cũ hoặc không sẵn sàng. | State được ghi log và anchor; khi không xác định freshness thì fail closed. |
| **Key committee** | Dưới t node bị chiếm quyền; một số node offline. | Ít nhất t node hợp tác hợp lệ để giải mã; không quá ngưỡng bị thông đồng. |
| **Authorized client** | Có thể lưu DEK/plaintext sau truy cập. | Revocation không thể xóa dữ liệu đã được client lấy hợp lệ. |
| **Network** | Delay, replay, partition, reorder. | Kênh xác thực; epoch và nonce chống replay. |

3. Kiến trúc mật mã và policy
D --AEAD(K_D, AAD)--> C --RS--> (C_1, C_2, ..., C_n)
AAD = (ObjectID, Version, PolicyHash, CodecID)
Capability = Sign(ObjectID, Subject, Rights, Epoch, Expiry, Nonce)
Các lớp của Engram-Revoke

| Lớp | Chức năng | Lựa chọn ban đầu |
| :--- | :--- | :--- |
| **Data encryption** | Mã hóa payload trước khi RS và kiểm tra integrity. | Random DEK/object; AEAD; unique nonce policy. |
| **Key wrapping** | Không lưu DEK dạng rõ trong storage/control plane. | HPKE cho MVP; threshold ElGamal ở giai đoạn sau. |
| **Policy decision** | Đánh giá subject, rights, epoch, expiry và object state. | OPA/Rego hoặc policy engine tương đương. |
| **Policy log** | Cung cấp lịch sử và freshness commitment. | MMR append-only log; root được anchor. |
| **Key enforcement** | Chỉ phát partial decryption khi policy hợp lệ. | Single service trước; t-of-n committee sau. |
| **Audit** | Ghi access/revoke/key events không chứa plaintext/DEK. | Signed events, Merkle proofs và metrics. |

Policy state machine
ACTIVE -> SUSPENDED -> ACTIVE
ACTIVE -> EXPIRED
ACTIVE -> REVOKED
SUSPENDED -> REVOKED
REVOKED and EXPIRED are terminal states for key release
Fail-closed: Nếu key node không xác định được policy root mới nhất hoặc không kiểm chứng được freshness, node không phát partial decryption. Liveness reduction phải được đo và báo cáo.

