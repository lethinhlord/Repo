# Trạng thái phần mềm và bàn giao
Ngày 06/11/2026. Điểm vào: [runbook 4 VM](scenario-collection-runbook.md).
Candidate: [collection-v4.0.0-candidate.1](https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.1).

- Thiết kế20trainable+8challenge đã triển khai:10pairedcohort, neutralusers,
  cùng HTTP/DNS endpoint/tool, schedule frozen theo seed và kiểm observed account.
- Thu40/48run mới,10/12mỗi stratum; cohort_id giữ cảpair cùng partition.
  Đây là thí nghiệm profile lab, không chứng minh ý định hoặc general C2 detection.
  Một validation cohort/nhãn chưa đủ uncertainty; automation_eligible=false.
- Candidate/source/runtime được đóng băng ở START. Trainable yêu cầu acceptance
  thực ở lab:4pilot mới,rawpreflight replay và backup restore validate.
  Gate được kiểm cả draft/start; không có manual PASS thay evidence.
- Enrollment được rebuild từ capture có hash, đủ3user local+SMB/HTTP/DNS trước run.
  Frozen JSON được chuyển sang actor và kiểm SHA, không nhập lại schedule.
- HTTP Event3 unknown-image chỉ được nhận khi có Event1GUID/PID/user/chronology
  nhất quán; conflicting creation vẫn bị chặn. DNS giữ strict.
- Bốn pilot trong BAN-GIAO-THINH-4-PILOTS-FULL đã được replay VALID và supplementary
  PASS bằng candidate;432file gốc không sửa. Chúng có purposepilot,không quota;
  source bundle cũ không được gán ngược thành source release này.
- G7 của lab Kiên còn CHƯA NGHIỆM THU bằng candidate này. Phần mềm candidate đã
  sẵn sàng chạy quy trình; chỉ acceptance từ artifact thật trên lab mới mở trainable.
  Không có4VMremote ở máy Thịnh để xác nhận thay Kiên.
- Chưa train hoặc mở lockedtest thật; không deploy/chứng nhận strong response.
  Các biên bản3.7/3.8,R02/R03 và handoff04/11 là lịch sử, không chỉ dẫn thu mới.

[Thiết kế/giới hạn](collection-training-design.md),
[biên bản kiểm thử](collection-v4-verification-20261106.md),
[contract](week3-data-contract.md),
[training](week3-model-training-runbook.md),
[ledger công việc](../tasks/training-collection-release-20261106.md).
