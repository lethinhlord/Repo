# Kết quả xử lý lỗi chặn — 27/10/2026

Hoàn tất đối chiếu và hướng dẫn bàn giao ngày 28/10/2026, Asia/Saigon.

## Phạm vi và giới hạn nghiệm thu

Bản này đối chiếu 15 lỗi R01–R15 tái hiện trên commit
`a05441c74b4cea98acf0ec374adcef249f7aaae0`. Đây là phần bổ sung cho sổ 28 phát hiện
trước đó, không thay thế hoặc xóa lịch sử phát hiện. Dataset cũ không được dùng lại.
Telemetry sinh trong kiểm thử chỉ kiểm chứng phần mềm, không phải dữ liệu train thật.

Các thay đổi dưới đây xử lý lỗi code, contract và hướng dẫn. Nghiệm thu triển khai trên
bốn VM của Kiên, chất lượng dataset mới và chất lượng model thật vẫn là các cổng riêng.
40–48 run là quota cho tập pilot; không bảo đảm khả năng tổng quát hóa hoặc đủ bằng
chứng để tự động phản ứng. Hệ thống tiếp tục ở SHADOW.

## Cổng kiểm tra cuối

- Toàn bộ bộ test tại thời điểm chốt: 298 test, không lỗi hoặc skip; JUnit được lưu
  ngoài repo trong `outputs/audit-20261027/remediation-pytest.xml` của workspace Codex.
- Sau đó bổ sung ca event ID chứa dấu `/`: 21 test notification/API/artifact liên
  quan đều đạt; lookup dùng path converter để không bỏ sót replay hợp lệ.
- Ruff, dependency consistency và `git diff --check` đạt; 33 block PowerShell trong
  hướng dẫn parse thành công. Runner DNS chạy với resolver giả lập trong child
  Windows PowerShell có policy RemoteSigned; không gửi truy vấn DNS thật trong test.
- Bản `Kiên.txt` và runbook trong repo được đối chiếu SHA-256 giống nhau.

## Đối chiếu sửa lỗi và bằng chứng hồi quy

| Mã | Thay đổi | Bằng chứng chính trong repo |
|---|---|---|
| R01 | Taxonomy đọc từ cấu hình canonical có thật | `tests/test_feature_pipeline.py`: raw C2 qua taxonomy |
| R02 | Parser dùng chung; timestamp nguồn, IPv4-mapped IPv6, LogonType, hướng kết nối, ProcessGuid và tương quan EVE; thời gian tương quan cố định theo source contract | `ml/telemetry.py`; kiểm thử parity account/HTTP/DNS trong `test_feature_pipeline.py` |
| R03 | DNS bắt buộc ProcessCreate có nonce/domain và ProcessGuid trùng; không có đường chấp nhận GUID rỗng | `test_scenario_collection.py`, `test_dns_scenario_script.py`; child PowerShell trong runbook |
| R04 | Health poll tám lần tạo overlap cần thiết; giữ nguyên các gate separation/collision | `test_collection_acceptance.py`: catalog thật đạt 40/48 run |
| R05 | Outbox lưu revision, escalation gửi thông báo mới; revision cũ chưa gửi bị supersede | `test_notification_revisions.py`: retry, race, migration, idempotency key |
| R06 | Bucket UTC cố định, membership ổn định; collector buộc action và nguồn cùng bucket | `test_feature_state.py`, `test_collection_windows.py` |
| R07 | Auditor dựng lại vector từ Archives và đối chiếu bản Windows/EVE đã chọn | `test_dataset_audit.py`: raw vô nghĩa, sai hash/feature/window đều bị từ chối |
| R08 | JSON sai kiểu được báo thành lỗi dataset, không làm mất báo cáo | `test_dataset_audit.py`: bảy loại tài liệu JSON sai kiểu và agent/EVE lồng nhau bị hỏng |
| R09 | Thiếu group độc lập thì CI null, nêu lý do và khóa automation eligibility | `test_ml_metrics.py`, `test_training_integrity.py` |
| R10 | Colab đọc schema kết quả thực tế; cell kết quả và archive chạy trên output trainer mới | `test_training_integrity.py` |
| R11 | Manifest v2 ràng buộc hash/count từng partition, schema và provenance; trainer kiểm trước fit | `test_training_integrity.py`: thay TRAIN/VALIDATION bị chặn, locked test không được mở |
| R12 | Lưu outcome theo event và raw hash; workflow lookup trước features/ML/TI; retry đúng revision | `test_notification_revisions.py`, `test_workflow_replay.py`; kiểm thử n8n thật bên dưới |
| R13 | Runtime chỉ ready khi đủ account+C2, estimator nhị phân, threshold và profile khớp schema | `test_ml_package.py` |
| R14 | Hướng dẫn mở khóa local account bằng ADSI/CIM và kiểm lại Lockout | `docs/scenario-collection-runbook.md`; cần xác nhận tài khoản thật trên Windows 11 |
| R15 | Feedback đối chiếu predicted_class, gắn sự kiện gốc, một incident/model là một mẫu; verdict mâu thuẫn không vào FPR/FNR | `test_feedback_adjudication.py`, `test_feedback_store.py` |

## Kiểm thử tích hợp n8n/API thực tế

Đã import và publish workflow hiện tại bằng n8n 2.44.6 (image khóa bằng digest), chạy
API với source hiện tại và SQLite mới trong mạng Docker riêng. Receiver HTTP loopback
thật được dùng để chủ động trả 200 hoặc 503. Các ca sau đạt:

- Webhook chưa ký trả 401.
- Trained model chưa cấu hình dẫn tới review; không fallback âm thầm.
- Payload ký hợp lệ được persist và thông báo qua receiver.
- Retry cùng payload bằng nonce mới trả `duplicate`, giữ route/timestamp/revision,
  không gọi `/predict` thêm lần nào.
- Cùng event ID nhưng raw payload khác trả 409.
- Receiver lỗi trả `notification_pending`/503; decision mới supersede hàng cũ.
- Retry hàng cũ trả `decision_superseded`, không gửi nội dung cũ; revision mới gửi
  thành công với Idempotency-Key khác.

Đây là nghiệm thu luồng phần mềm với fixture và trạng thái tạm. Nó không chứng minh
chất lượng mô hình hoặc độ đầy đủ telemetry trên hệ thống bốn VM.

## Quy tắc bàn giao để thu lại

1. Cập nhật repo tới commit được bàn giao sau khi merge; kiểm tra SHA đầy đủ. Tag
   `data-collection-v2.0.0` tại `136bb754...` đã cũ và không phải baseline lượt này.
2. Chỉ dùng hướng dẫn `docs/scenario-collection-runbook.md` cùng revision; bản
   `D:\Tài liệu\Đồ án\Kiên.txt` được đồng bộ nguyên nội dung từ file đó.
3. Chạy preflight trên bốn VM, gồm hai DNS scenario có Event 1/22 cùng ProcessGuid
   và SID 900002/900004. Kiểm tra unlock local account trên tài khoản lab thật.
4. Thu mới trong thư mục sạch; dùng `begin-action --wait-for-window`, thao tác ngay
   và `complete-action` trước `action_deadline`. Không sửa receipt/hash để vượt gate.
5. Mỗi run phải VALID; tập tổng phải READY/TARGET_MET, không có lỗi provenance,
   collision hoặc separation trước khi build. Chạy lại builder để có manifest v2.
6. Chỉ gửi TRAIN, VALIDATION và manifest sang Colab. Locked test giữ UNOPENED trên
   máy tin cậy. Ghi nhận CI thiếu group là thiếu bằng chứng, không phải CI bằng zero.

## Trạng thái sổ 28 phát hiện trước

Không tự đổi các mục cần dữ liệu/hạ tầng thật sang CLOSED bằng unit test. Các cổng
F-01/F-16/F-17/F-23 vẫn cần nghiệm thu bốn VM; F-02/F-03/F-04/F-05/F-09/F-11/F-27/F-28
vẫn cần dataset/model/evaluation thực tế theo tiêu chí của sổ gốc. Bản vá hiện tại bổ
sung rào chặn và bằng chứng phần mềm cho các cổng đó; không thay thế phép đo thực.
