# Kiểm thử tích hợp runtime v3 — 28/10/2026

> Hồ sơ lịch sử, không dùng làm hướng dẫn hiện hành. Xem [hướng dẫn thu dữ liệu](../scenario-collection-runbook.md) và [trạng thái hiện tại](../current-status.md).

Kết quả: **PASS đối với đường tích hợp được mô tả dưới đây**.
Đây là thử nghiệm phần mềm bằng dữ liệu tổng hợp mới tạo, không phải nghiệm thu bốn
VM, dữ liệu train thật hay đánh giá chất lượng phát hiện. Không dùng package smoke
để phát hành hoặc thay cho dataset Kiên sẽ thu.

## Phạm vi và revision

- API image build từ source `e8cec84`, tag riêng `datn-ai-soar-api:handoff-e8cec84`;
  API 4.0.0, features-v3. Cài runtime từ requirements khóa hash thành công.
- n8n 2.44.6 dùng image pin của repo; project Docker riêng `handoff-e8cec84`, cổng
  host 18080/15678, network riêng. Không sửa stack triển khai của người dùng.
- Workflow thử nghiệm có SHA-256
  `79072c0143468e3c808b5e6b2684c82a5319d9c43a0a291350cc313341d478b3`.
  Quyết định được bổ sung context status/revision/quality và review reasons.
- Package được train mới bằng smoke generator, qua builder/trainer/freeze thực.
  Provenance là SMOKE_ONLY; các gate giữ automation ineligible. Không mở locked test.
- Context riêng tên `SYNTHETIC-E2E-NOT-LAB`; baseline không được ghi vào thư mục
  enrollment hoặc dataset chính thức của repo.
- Receiver HTTP nằm trên loopback của container API, không gửi tin cho người khác.
  Strong actions luôn tắt.

## Bằng chứng đã kiểm

1. Webhook thiếu chữ ký trả 401; webhook ký hợp lệ đi qua n8n, model, policy và outbox.
2. Receiver thật nhận hai thông báo với hai idempotency key khác nhau cho hai revision.
3. Replay trước/sau restart API không gửi thêm thông báo. Số dự đoán trước/sau replay
   đều bằng 2; trạng thái được lưu qua SQLite và volume.
4. Bản ghi decision trong SQLite chứa context AVAILABLE, revision đúng, quality PARTIAL
   và `window:open` của pha ingest. Không suy context từ nhãn hay tên scenario.
5. Chờ watermark bằng đồng hồ thật rồi gọi finalize-window: quality COMPLETE,
   failed=1/success=1 và toàn bộ vector bằng kết quả batch của cùng raw/context.
6. Gọi finalize từ event khác của cùng window trả cache duplicate, cùng kết quả.
7. Event đến sau grace giữ `window:late_arrival`; reconcile window trả 409.
8. Cùng raw event ID nhưng nội dung khác trả 409 trước model/notification.

Thông báo cũ đã SENT có thể trả ALREADY_SENT dù sau đó có revision khác; nó không
được gửi lại. SUPERSEDED dùng để chặn revision đang chờ đã bị thay thế. Phép thử đầu
tiên dùng kỳ vọng sai cho trường hợp đã SENT; evidence lần đầu được giữ trong
`attempt1`, sau đó chạy lại với state thử nghiệm mới và kỳ vọng đúng.

## Vị trí evidence

`D:\DataCodex\2026-10-05\c\outputs\handoff-implementation-20261028\runtime-e2e-e8cec84`

Gồm summary.json, raw HTTP response, closed-window.json, persisted-context-trace.json,
metrics trước/sau restart, receiver/received.jsonl và runtime.log. File .env trong
thư mục thử nghiệm chỉ có khóa tạm của test; không đưa vào Git hoặc tài liệu bàn giao.

Full suite trước thay đổi trace workflow: 451 test, 0 lỗi/skip, pip check và Ruff đạt.
JUnit `checkpoint-v3-runtime-preflight-full.xml`, SHA-256
`b021d9712ddef894c878fe4a1932a852411950ef7e2ffefd20f623d10884e296`.
Sau thay đổi trace: 23 test workflow/replay/notification đạt, cộng lượt Docker trên.

## Phần còn mở

- Bước close trong thử nghiệm được gọi qua API bởi test driver; workflow n8n hiện
  vẫn xử lý ingest tạm thời. Chưa có scheduler/final-window workflow tự động hoàn chỉnh.
- Chưa thu telemetry thật từ Windows 11/Wazuh/Suricata của Kiên; chưa đo grace trên lab.
- Catalog đối chứng G01–G07, challenge thực và baseline bàn giao chưa freeze.
- Chưa có kết luận precision/recall/coverage hoặc đủ dữ liệu để bật phản ứng mạnh.
