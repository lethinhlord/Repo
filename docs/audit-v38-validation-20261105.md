# Kiểm chứng sửa lỗi3.8 — 05/11/2026

Code anchor: `0d6e44ffdf4936182a4ee337db78f29116469b94`; baseline trước sửa:
`63e73ac1f741208fe57d0880223423f7d20c8e10`. Pilot tag 3.8 được resolve tại clone;
không ghi source SHA dự đoán trước khi merge. Hướng dẫn kiểm annotated tag, ancestor
và tree ngoài8 file tài liệu; không dùng main động làm collection baseline.

## Phạm vi và kết quả

[Ledger từng finding](../tasks/audit-v38-20261105.md) ghi V37-01…11, nguyên nhân,
source và phép thử. Đã tái hiện RED trước sửa, GREEN, kiểm hồi quy, kiểm chéo khác
mô hình và xử lý các regression tìm thêm. Không xóa feature, giảm schema 24 feature,
bỏ unknown raw hoặc nới clock/flow/split/SHADOW gate.

- Full Windows pytest: 749 passed, 1 skip do symlink Windows; không failure/error.
- Linux pytest: 340 test case riêng biệt đạt, không skip, qua các lượt runtime,
  collection/ML, filesystem và hậu kiểm. Trong đó có bài symlink bị skip trên
  Windows; không cộng lặp các case được chạy lại giữa những lượt Linux.
- Ruff toàn repo PASS; PowerShell parser41 block tài liệu và4 script PASS.
- n8n 2.44.6 engine + API thật, Docker network nội bộ chỉ có peer QA: unsigned401;
  first feature503 giữ một retryable record, zero processed/decision/outbox;
  retry200 tạo một processed event/decision; replay200 duplicate không tăng count.
  Notification chỉ audit-log nội bộ. QA resources đã dọn; stack đang chạy không đổi.
- Notebook shell trong container không Internet kiểm fresh clone có README,
  versioned package, existing destination, sai identity, traversal, symlink.
  Failure không freeze package cũ hoặc export nhầm host selection.
- Native-clock precision kiểm ranh 5 s và thêm100ns; malformed opening record,
  metrics hỏng/mất, cached readiness và legacy snapshot migration có regression.

Lượt QA bổ sung chạy cả n8n engine; không suy Code-node unit PASS thành E2E.
Native EVTX helper được parser/unit kiểm; chưa đọc driver/event service trên VM
Kiên, không giả bằng dữ liệu host. Các kiểm tra không thay cho real-lab acceptance.

## Dataset không được tự sửa thành đạt

158 file gốc giữ nguyên. Tám output mới khớp hash metadata; missing-output đã đóng.
Hai account có đúng1/2 selected Security events, Suricata0 hợp lý. Patch background
giải quyết extra account group; account cần supplementary review khi destination
context chứa native-clock mismatch. Hai C2 có4/8 selected rows mâu thuẫn
SystemTime/UtcTime, mặc dù Wazuh nhận log trễ khoảng 0,6 s.

[Bảng timestamp gốc](dataset-handoff-20261105.md) ghi record 149398/150153, đường
dẫn, line, hash và lệnh đối chiếu. Chưa có EVTX để kết luận nguồn sai; không đổi
timestamp, receipt, nhãn, purpose hoặc checksum. Sau khi xử lý nguồn, chạy
enrollment/pilot mới theo release gate, bảo toàn toàn bộ evidence cũ.

## Bàn giao và giới hạn

Kiên.txt ngoài repo phải khớp byte runbook từ GitHub tag 3.8; bản cũ giữ riêng trong
kho lịch sử. Raw, backup, secrets và environment thật không lên GitHub. Phải gửi
source receipt và hồ sơ operator thật; code mới không chứng minh source đã thực
thi cho run cũ. Recovery vẫn yêu cầu backup, dừng collector, giữ owner/metadata và
không hồi sinh ABORTED/QUARANTINED.

Không train model thật, mở locked test thật, gọi live VirusTotal hoặc deploy lên
lab 4 VM. G7 CLOSED; software fix không chứng nhận quota trainable, accuracy hay
quyền bật strong response. Lab clock/firewall/flow/loss/restore vẫn cần chứng cứ thật.
