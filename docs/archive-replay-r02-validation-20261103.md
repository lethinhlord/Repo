# Kiểm chứng sửa lỗi archive replay R02 — 03/11/2026

## Kết quả và phạm vi

Đã sửa lỗi giữ ID nguồn không duy nhất của archive thiếu `rule` khi replay full
capture. Commit phần mềm: `38eb4f4fe47508e04826c0f6a54e675a7ba66b34`.
Không thay đổi feature schema, catalog, context contract, dependency hoặc API alert
thật. Không sửa dữ liệu R02 gốc và không dùng diagnostic excerpt làm dữ liệu train.

Collector tạo ID ảo `archive-raw-v1-{ordinal}-{sha256}` cho từng lần xuất hiện raw:
ordinal tính trên toàn bộ danh sách record đã capture trước lọc agent/thời gian;
hash tính trên toàn bộ record gốc trước Pydantic/defaults. Vì vậy ID nguồn bị trùng
và raw giống hệt nhau vẫn được bảo toàn số lần xuất hiện. ID ảo chỉ dùng replay,
không được ghi đè raw hay coi là bằng chứng xác thực nguồn độc lập.

Alert có `rule` vẫn giữ định danh và guard cũ. Trường rule hiện diện nhưng null/sai
cấu trúc vẫn bị từ chối. Same-ID/different-payload không bị bỏ qua; lỗi aggregation
được chuyển thành CollectionError để CLI trả JSON ERROR và exit 1 có cấu trúc.
Không giảm kiểm provenance, checkpoint, cutoff, full-bucket parity hoặc context.

## Kiểm thử và đối chiếu

- TDD trên mã cũ: **6 failed, 4 passed**. Các ca RED bắt trùng ID, mất multiplicity,
  định danh sai và ValueError chưa được chuẩn hóa; bốn malformed-rule đã fail closed.
- Sau sửa: 10 ca đầu GREEN; bổ sung C2 HTTP/DNS và subprocess CLI thành **13 passed**.
- Các integration dùng capture/intake, aggregation, finalize thật trong fixture tổng
  hợp; sau đó xóa nguồn archive fixture và validate offline từ evidence đã lưu.
  Không mock feature hoặc kết quả parity. Một spy quan sát ID nhưng gọi aggregator thật.
- C2 HTTP/DNS: tất cả wrapper raw dùng cùng một native ID; process/network/DNS,
  HTTP, flow và alert vẫn được giữ, có tám action tương ứng và tám alert, offline
  replay VALID. Đây là test phần mềm với telemetry tổng hợp, không là nghiệm thu lab.
- Genuine alert xung đột vẫn bị chặn; subprocess CLI exit 1, stderr rỗng và stdout
  là JSON ERROR. Không tạo output cuối cho ca bị từ chối.
- Full suite cuối: **603 passed, 1 skipped**, 308.59 giây; skip là khả năng tạo
  symlink trên Windows ở test quarantine. Không xóa hoặc disable test để đạt kết quả.
- Ruff toàn repo và `git diff --check` đạt.
- Native Bash `bash -n` trong container tách mạng: **85 block** đạt, gồm 80 trong
  Kiên.txt/runbook và 5 trong companion R02. Không sửa/restart stack API/n8n đang chạy.
- Source update trong checkout QA riêng dùng Git thật, có state tổng hợp và config
  local bị sửa có chủ ý: đổi từ main cũ sang commit fix giữ nguyên cả hai; config,
  schema và lock dependency giữa hai commit không đổi. Đây không phải lab R02.

## Kiểm tra trên diagnostic thật

Gói đầu vào có 43 record khác nhau, hai native ID, không có rule. Adapter thực sau
sửa xử lý đúng 40 record nằm trong bucket: **40 input / 40 unique / 0 duplicate**.
Ba record ngoài bucket theo thời gian nguồn vẫn được loại đúng quy tắc cũ.

Kiểm tra sau đó **tiếp tục từ chối** vì excerpt không có nhóm ACCOUNT đầy đủ để
đối chiếu. Không dựng baseline giả để biến excerpt thành run hợp lệ. Bốn SHA-256
đầu vào trước/sau giống nhau. Không chạy finalize/validate trên lab Kiên.

## Kiểm chéo giữa các mô hình

- Sol viết test trước khi product được sửa, xác nhận RED và mở rộng ca C2/CLI.
- Astra kiểm thiết kế và diff độc lập, chạy 46 ca liên quan trước khi bổ sung ba ca
  cuối; không có lỗi chặn. Full suite của parent bao gồm toàn bộ 13 ca cuối.
- Terra kiểm quy trình bàn giao và code state/provenance. Phát hiện companion bị
  thiếu trong danh sách file giao; đã bổ sung companion và đóng gói cùng Kiên.txt.

Các report độc lập và log được lưu riêng, không thay thế bằng tuyên bố chung rằng
toàn bộ hệ thống không còn lỗi. Phạm vi lượt sửa là lỗi archive identity R02 và
đường báo lỗi/khôi phục liên quan.

## Bàn giao và giới hạn

[Kiên.txt/runbook 3.4](scenario-collection-runbook.md) dẫn tới
[quy trình R02](pilot-r02-recovery.md). Gói source gồm bundle, checksum và pointer
pilot phát hành từ SHA main thực sau merge; trạng thái merge và hash file giao
được ghi trong receipt ngoài repo, tránh SHA tự tham chiếu trong commit.

Kiên chỉ thử lại trên run có checkpoint sealed hợp lệ, đủ immutable snapshots và
nguồn live còn vượt kiểm toàn vẹn/tail. Nếu nguồn đã rotate/truncate, thiếu evidence
đúng hạn hoặc có late input vi phạm, giữ R02 làm bằng chứng lỗi và chạy pilot mới
theo runbook; không sửa snapshot, timestamp, state hoặc action để ép đạt.

**G7 vẫn đóng.** R02 chưa được nghiệm thu; cần full raw/evidence và kiểm lab thực.
Không tuyên bố model đạt accuracy, có dữ liệu train mới hoặc strong response AUTO.
Mã trên lab và container đang chạy không được tự cập nhật chỉ vì đã merge GitHub.

## Hồ sơ kiểm chứng

`D:\DataCodex\2026-10-05\c\outputs\pilot-r02-fix-20261103`

Gồm RED/GREEN log, full-suite.xml/log, independent-design-review.md,
real-excerpt-results.json, verify_real_excerpt.py, bash-docs-check.log,
same-checkout-qa.json và receipt phát hành/merge. Gói diagnostic gốc giữ nguyên ở
`D:\DATN-V3-PILOT-R02-ERROR\DATN-V3-PILOT-R02-ERROR`.
