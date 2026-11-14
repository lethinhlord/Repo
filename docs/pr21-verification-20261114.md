# Kiểm chứng khắc phục PR21 — 14/11/2026

Phạm vi: lỗi parity của run003, tương thích cache khi đổi asset grouping và
ràng buộc source/G7 cho candidate.7. Không đổi schema24, profile thu, quota,
nhãn, chronology hoặc điều kiện COMPLETE. Dữ liệu gốc được kiểm đọc, không sửa.

## Nguyên nhân và thay đổi

Log sshd/journald của NET-SENSOR từng được quy thuộc WIN11-TARGET như EVE.
Run003 có9fail/3success đúng hành động, nhưng log sensor tạo thêm Windows account
group, khiến full-capture parity từ chối. PR21 chỉ quy thuộc EVE cho target;
log OS giữ asset sensor. Khi finalize gọi theo action time, sửa asset này đã
giải quyết dữ liệu thật. Receipt anchoring bổ sung bảo vệ helper nếu caller đưa
session START ở bucket trước; không mô tả nó như nguyên nhân thứ hai của run003.

Cache source6 vẫn có thể trả asset cũ sau khi source đổi. Bản khắc phục thêm
`feature_grouping_policy=sensor-asset-origin-v1`; metadata chronology giữ nguyên.
Cache có derived state cũ hoặc policy không tương thích bị từ chối trước khi
đổi DB. DB path mặc định mới giữ nguyên file cũ để audit, không ghi lại decisions.
Chuyển đổi audit-only của schema cũ vẫn được giữ.

Source của PR21 khác production patch đã được policy G7 phê duyệt. Candidate.7
và policy kế thừa hiện ràng buộc toàn bộ diff production từ candidate.4, thay vì
chỉ thông qua test policy giả lập. Test source conformance đối chiếu HEAD Git thật.
Runtime, pilot commit/tree, raw preflight, backup restore và active source vẫn
được kiểm; không có manual PASS hoặc đổi metadata để khớp.

## Bằng chứng đã đối chiếu

- 61 checksum ngoài và 36 checksum trong gói 001–003 khớp; 62 file giữ nguyên bytes.
- 001/002 vẫn VALID/RUN_EVIDENCE_CHECK_PASS dưới code mới. Chúng thuộc source6.
- 003 giữ STARTED; component replay đạt COMPLETE, 9 fail/3 success, không review reason.
  Kết quả replay không tạo manifest hoặc biến run lỗi thành trainable được chấp nhận.
- 7 pilot lịch sử đều VALID/PASS, trong đó 4 pilot candidate.4 dùng lại cho G7.
- 4 test nâng cấp cache thất bại trước sửa; 61 test liên quan đạt sau sửa.
- 13 test cache/lifecycle/real-source-binding/adoption đạt sau commit khắc phục.
  Negative controls của mô hình độc lập chứng minh grouping cũ làm test lifecycle
  thất bại; receipt helper cũ làm case session anchor thất bại.
- 84 khối Bash của 3 guide đúng cú pháp; link tài liệu local tồn tại. Đây là kiểm
  cú pháp, không giả định các lệnh đã được thực thi trên VM Kiên.
- Replay G7 dùng 4 pilot/preflight/backup thật trong checkout cách ly: runtime laptop
  khác bị REJECTED; mô phỏng chỉ 3 field inventory bằng runtime SOC gốc thì PASS.
  Không phát hành production acceptance và chưa kiểm active enrollment CLI thật.
- Kiểm tra chéo độc lập bằng GPT-6 Astra không tìm thêm lỗi chặn. Góp ý tạo plan
  trùng đã được xử lý: upgrade → G7 bước 1–5 → quay lại tạo một plan, runbook dùng lại.

Toàn bộ hồi quy đang chạy tại savepoint này; số lượng cuối được ghi vào ledger
`tasks/pr21-remediation-20261114.md` trước bàn giao release.

## Ranh giới vận hành

Không có lab4VM của Kiên tại máy Thịnh để nghiệm thu triển khai. Trên SOC thật,
làm [nâng cấp candidate.7](collector-upgrade-candidate7.md), enrollment còn hạn,
[G7](g7-existing-candidate4-pilots.md) và authorize trước run trainable mới.
Không cần chạy lại4pilot chỉ để đổi tag. Giữ source6trainables riêng; auditor
và builder vẫn yêu cầu một candidate/runtime cho dataset mới40/48run.

Nhịp HTTP nhanh vẫn có thể trễ frozen schedule; không hạ guard hoặc ép run đạt.
Bộ test/replay không bảo đảm mọi độ trễ hay sự cố VM tương lai; nếu fail, giữ
raw/state/receipt/checkpoint, dừng và xử lý evidence theo runbook.
