# Trạng thái phần mềm và bàn giao

Ngày 20/11/2026: candidate.8 bổ sung quy trình xử lý 40 run đã có, không thu lại.
Xem [hướng dẫn dùng 40 run](training-existing-40-runs.md). Hai nguồn thu gốc giữ
nguyên; chế độ được review xác minh input, source, replay và partition trước khi
tạo manifest v3. Chế độ một nguồn cũ vẫn hoạt động. Cache dẫn xuất dùng DB/version
mới cho thay đổi grouping và dung sai300ms; file DB cũ được giữ để audit.

Các ghi nhận dưới đây là lịch sử candidate.7. Chúng không phải chỉ dẫn yêu cầu
chạy lại pilot hoặc scenario cho bộ40 hiện có, và không cấp G7 cho candidate mới.

## Lịch sử 14/11/2026

Ngày 14/11/2026. Điểm vào: [runbook 4 VM](scenario-collection-runbook.md).
Candidate: [collection-v4.0.0-candidate.7](https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.7).
Lab đã có bốn pilot candidate.4: dùng [hướng dẫn G7 kế thừa](g7-existing-candidate4-pilots.md).
Lab đã thu source6: làm [nâng cấp candidate.7](collector-upgrade-candidate7.md)
trước khi resume trainable. Giữ source6 riêng, không sửa frozen identity để ghép nguồn.
Đối chiếu nguyên nhân, bằng chứng và giới hạn ở
[biên bản khắc phục PR21](pr21-verification-20261114.md).

- Thiết kế20trainable+8challenge đã triển khai:10pairedcohort, neutralusers,
  cùng HTTP/DNS endpoint/tool, schedule frozen theo seed và kiểm observed account.
- Thu40/48run mới,10/12mỗi stratum; cohort_id giữ cảpair cùng partition.
  Đây là thí nghiệm profile lab, không chứng minh ý định hoặc general C2 detection.
  Một validation cohort/nhãn chưa đủ uncertainty; automation_eligible=false.
- Candidate/source/runtime được đóng băng ở START. Trainable yêu cầu acceptance
  thực ở lab:4pilot hợp lệ,rawpreflight replay và backup restore validate.
  Gate được kiểm cả draft/start; không có manual PASS thay evidence.
- Enrollment được rebuild từ capture có hash, đủ3user local+SMB/HTTP/DNS trước run.
  Frozen JSON được chuyển sang actor và kiểm SHA, không nhập lại schedule.
- HTTP Event3 unknown-image chỉ được nhận khi có Event1GUID/PID/user/chronology
  nhất quán; conflicting creation vẫn bị chặn. DNS giữ strict.
- Bốn pilot candidate.4 trong BAN_GIAO_SOC_CHO_THINH ngày11/11 đã replay VALID và
  RUN_EVIDENCE_CHECK_PASS; ba pilot candidate.2 trong cùng backup cũng replay đạt.
  Giữ nguyên raw/evidence/nhãn và không tính pilot vào quota trainable.
- G7 v2 kiểm file source active thực tế, không nhầm với config mặc định trong repo.
  Policy kế thừa ràng buộc đúng commit/tree candidate.4, runtime không đổi và hash
  toàn bộ bản vá production đã review. Receipt ghi riêng candidate tạo pilot và
  candidate thu mới; source được kiểm xuyên suốt draft/START/audit/build.
- Enrollment pilot đã hết hạn phải được giữ trong evidence; thu enrollment thật
  mới cho baseline active. Không sửa timestamp/TTL hoặc dùng log gán nhãn làm lịch sử.
- Native1/3/5 dùng cùng UTC đã kiểm; cache policy mới từ chối dữ liệu dẫn xuất
  features-v3 cũ. HTTP giữ cùng curl sống sau request bằng hai transfer local.
  Nhịp quá nhanh vẫn có thể missed schedule; không đổi gap, profile hoặc quality gate.
- Handoff001–003 có61 checksum khớp.001/002 là trainable source6 VALID;
  003 còn STARTED, raw đủ9/3 nhưng log sshd NET-SENSOR tạo nhầm Windows group.
  Asset fix của PR21 làm replay003 COMPLETE; chưa biến nó thành finalized data.
- Grouping policy riêng từ chối cache source6 trước khi thay đổi DB; chỉ EVE
  được quy thuộc target, OS log sensor giữ đúng asset. Native clock policy không đổi.
- G7 candidate.6 đã được nhúng đúng trong handoff. Candidate.7 vẫn phải tạo thật
  theo source mới. Phần mềm candidate đã
  sẵn sàng chạy quy trình; chỉ acceptance từ artifact thật trên lab mới mở trainable.
  Không có4VMremote ở máy Thịnh để xác nhận thay Kiên.
- Chưa train hoặc mở lockedtest thật; không deploy/chứng nhận strong response.
  Các biên bản3.7/3.8,R02/R03 và handoff04/11 là lịch sử, không chỉ dẫn thu mới.

Candidate.2 đã khắc phục các lỗi audit ngày 07/11: bao phủ từng giao dịch/response,
inventory backup hai chiều, checksum host không rỗng, quota/seed, provenance
local/Colab, calibration, freeze/evaluation bất biến, retry notification và lọc TI.
Runtime giữ process identity qua bucket nhưng không cộng hành vi bucket cũ.
Biên bản 06/11 chỉ áp dụng candidate.1 tại thời điểm đó; xem biên bản 08/11 và
test evidence mới trước khi dùng. Container local features-v2 chưa phải nghiệm
thu candidate features-v3; không dùng health của container cũ làm bằng chứng mới.

[Thiết kế/giới hạn](collection-training-design.md),
[biên bản lịch sử 08/11](collection-v4-verification-20261108.md),
[contract](week3-data-contract.md),
[training](week3-model-training-runbook.md),
[ledger công việc](../tasks/audit-remediation-20261107.md).
