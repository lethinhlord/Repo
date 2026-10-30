# Kiên.txt 3.2 — kiểm soát thu đủ dữ liệu

Yêu cầu: sửa hướng dẫn hiện hành theo lỗi của bộ DATN_SOC_20_VALID_RUNS, thao tác
từng bước rõ ràng, kiểm chéo trước bàn giao. Chỉ sửa tài liệu; không sửa dataset,
không tạo baseline thu chính thức khi G7 chưa đạt.

Nguồn mã: d06d04034f0d1c996907365841f21cdb874e4d5a (đã merge PR8).
Nhánh tài liệu: docs/kien-collection-v3-2, base origin/main 9687ed3.
File chuẩn: docs/scenario-collection-runbook.md; đã ghi Kiên.txt sau QA ngày 30/10.
Evidence: D:\DataCodex\2026-10-05\c\outputs\guide-v3-2-20261029.

- [x] Lộ trình G0–G9, ranh giới trách nhiệm và source/purpose, không trộn run cũ.
- [x] Canary nonce riêng, Sysmon native RecordId/UTC, raw XML giữ trước parse.
- [x] Poll refresh tới khi đủ mọi kênh, request/response và từng full-tuple final flow.
- [x] Kiểm sau mỗi VALID: 24 feature, context/snapshot/checkpoint, Sysmon UTC/final coverage.
- [x] Chuyển source: backup/cách ly pilot cũ; gói source/wheelhouse local đúng lock;
  venv sạch no-index và restore đối chiếu lock; không bật trainable bằng đổi biến.
- [x] Sửa hai dấu + thừa trong nmcli kế thừa từ bản cũ; kiểm đối số cả add/modify.
- [x] Đọc chéo Sol/Astra/Terra; các lỗi/đề nghị có ý nghĩa được xử lý.
- [x] QA cuối trên đúng hash tài liệu: Bash/PS parser, actual-block fault cases,
  source G7 từ chối đúng và metadata-design test không tạo execution evidence.
- [x] Đồng bộ Kiên.txt 3.2 cùng hash, giữ bản trước khi sửa, ghi biên bản phạm vi kiểm.
- [ ] Commit/push/PR; kiểm đúng HEAD và merge theo ủy quyền trước đó.

Điều kiện chưa thể thay bằng tài liệu: lab thực thuộc máy Kiên; G7 còn thiếu thiết
kế cohort/challenge/taxonomy và release được nghiệm thu. Không gọi QA là pilot thật
hoặc hứa mọi lỗi đều bất khả xảy ra. Các lỗi đã biết phải dừng được khi làm đúng hướng dẫn.

Đã đạt 77 Bash/38 PowerShell parser, 35 ca actual-block và 22 test runbook/DNS.
Hash bản gửi: aabed037b518e8a752ef0db4b5aa5521865c1d9528dcc7b4e55cf6a87b6eb7c7.
Mục PR là snapshot trước gửi merge; trạng thái cuối tra trên PR/GitHub, không coi
checkbox chưa cập nhật trong commit chuẩn bị là một lỗi QA còn mở.
