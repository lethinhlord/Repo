# Context, cửa sổ quan sát và dataset v3 — trạng thái triển khai

Ngày: 28/10/2026. Nhánh: `fix/handoff-context-v3`.
Đây là hợp đồng kỹ thuật đang triển khai, chưa phải biên bản nghiệm thu bốn VM hoặc
hướng dẫn bàn giao cuối cùng cho Kiên. Chưa đổi COLLECTION_BASELINE_COMMIT.

## Hợp đồng đã triển khai

- `features-v3` gồm 24 giá trị: 10 account và 14 C2. Bốn trường mới là
  `source_history_known`, `new_source_for_user`, `destination_history_known`,
  `new_destination`. Mask bằng 0 biểu thị chưa có lịch sử, không có nghĩa là bình thường.
- Baseline lấy từ capture enrollment riêng trước sự kiện; có revision, SHA-256 của
  capture, thời điểm quan sát/capture và TTL. Chỉ 4624 hợp lệ được enroll lịch sử account;
  network/DNS outbound cung cấp lịch sử đích. Nhãn/scenario/approval không vào vector.
- Collector đóng băng baseline và capture gốc tại START. Thay đổi context sau START
  hoặc restore sửa snapshot bị từ chối. Công cụ enrollment không đọc lại nguồn sau khi
  đã hash, tránh lưu nhầm bytes khi nguồn đang thay đổi.
- Source production yêu cầu bucket sạch, final flow counter và full-capture parity.
  Finalize phải đợi hết bucket cộng grace 60 giây; CLI hỗ trợ
  `scenario_session.py finalize --run-id ... --wait-for-window`.
- `archive_capture.jsonl` giữ bytes đã đọc trước lọc. Replay dùng source/taxonomy/context
  đóng băng và toàn bộ bucket, không dùng nonce/nhãn để lọc. Có khác biệt vector/quality
  với online thì run bị từ chối. Traffic nền phải được xử lý trước khi thu lại.
- Final EVE flow dùng thời gian `flow.start` để quay về bucket gốc. Cumulative counters
  của transaction/final flow không cộng lặp. Flow kéo qua cửa sổ, thiếu final counter,
  ID tái dùng mơ hồ hoặc counter xung đột không được coi là COMPLETE.
- Ingest online trả kết quả tạm thời với `window:open` hoặc `window:late_arrival` và
  yêu cầu REVIEW. `POST /features/wazuh/finalize-window` nhận `alert_id`,
  `window_minutes`; chỉ đóng sau watermark. Kết quả cuối được cache bất biến. Log đến
  sau hạn gây 409 khi reconcile, không sửa âm thầm quyết định đã đóng. Thiếu context
  hoặc telemetry vẫn PARTIAL sau khi đóng.
- Dataset manifest/record hỗ trợ `purpose` và `cohort_id` ngoài feature. Purpose được
  cố định trong catalog/draft/frozen parameters trước hành động. Pilot có thể dùng
  scenario hiện hành để kiểm hạ tầng; không được đổi thành trainable sau khi xem kết quả.
- Discovery mặc định chỉ trả trainable nhưng vẫn parse/kiểm các run bị loại. Builder
  xuất challenge riêng cùng hash/count, không tính vào quota và không dùng để fit.
- Split có chế độ `cohort_id`, giữ các cohort cả hai nhãn cùng fold. Thiếu cohort hoặc
  không đủ coverage mỗi fold thì dừng. Inner CV ưu tiên cohort; leakage audit chặn
  cohort trùng giữa train/validation dù scenario khác nhau.
- Auditor kiểm bucket trùng, purpose, context COMPLETE của dữ liệu production, quota,
  provenance và collision. Progress cho phép tiếp tục khi chỉ thiếu quota; run hỏng
  luôn chặn. Final chưa đủ điều kiện không được build.

## Giới hạn và phần chưa được nghiệm thu

1. Catalog/runner/taxonomy hiện hành còn cần thiết kế lại đối chứng G01–G07. Không dùng
   chỉ tên file/domain/nhịp riêng của lab để chứng minh intent. Chưa freeze cohort cho
   đợt thu thật; cấu hình production hiện vẫn giữ split scenario của bản nền.
2. Cần nối bước đóng window tự động vào workflow n8n. Docker API/n8n/receiver đã
   kiểm với smoke mới; test driver gọi close thủ công. Xem runtime-acceptance-v3-20261028.md.
   Ingest tạm thời luôn REVIEW; chưa có quyết định cuối tự động hoàn chỉnh.
3. Compose đã mount đúng file baseline mặc định của collector vào API ở chế độ chỉ
   đọc, không tự tạo directory thay cho file thiếu. Deploy kiểm baseline/TTL và model
   trước khi dừng stack cũ. Trace revision và parity đã kiểm ở lượt Docker có driver
   close thủ công; final-window workflow tự động còn mở. Chưa đo hiệu quả phát hiện
   hay coverage trên dữ liệu mới; Docker không thay nghiệm thu telemetry bốn VM.
4. Challenge cần được thiết kế trước thu, gồm các cặp không đủ observability. Chưa có
   bộ challenge thật hay chính sách nhận diện mọi vùng xám. Context mới không đảm bảo
   phân biệt được hai ý định có cùng toàn bộ đầu vào.
5. 10–12 run mỗi nhóm chỉ là quota thu thập. Số cohort validation có thể vẫn quá ít để
   ước lượng CI hoặc bật automation; không hạ gate để đạt trạng thái đẹp.
6. Windows helper đã qua 33 test logic/parse, gồm giao của profile, interface alias/type,
   địa chỉ local IPv4/IPv6/CIDR/range trên cùng adapter. Scope chưa giải được giữ
   INCONCLUSIVE. Chưa kiểm kết nối allowed/denied trên bốn VM thật. Thịnh xác nhận
   lab ở máy Kiên; máy hiện tại không có lab để nghiệm thu.
7. Kiên.txt 3.0 đã đồng bộ với runbook cho giai đoạn setup/enrollment/pilot và giữ G7
   đóng. Xem handoff-guide-validation-v3-20261028.md. Chưa chốt baseline/tag thu chính
   thức, chưa merge nhánh triển khai. Không dùng dataset cũ, fixture, smoke hoặc PCAP
   tổng hợp làm kết quả train thật.

Các test dùng dữ liệu xác định hoặc PCAP/EVE offline nhằm kiểm correctness, không
thay thế pilot thật. Xem JUnit tại
`D:\DataCodex\2026-10-05\c\outputs\handoff-implementation-20261028`.
