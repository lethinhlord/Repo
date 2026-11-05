# Trạng thái phần mềm và bàn giao hiện tại

Ngày 05/11/2026. Điểm vào vận hành là [runbook lab 4 VM](scenario-collection-runbook.md),
pilot tag [pilot-v3.8-20261105](https://github.com/lethinhlord/Repo/tree/pilot-v3.8-20261105).
Code anchor đã kiểm: `0d6e44ffdf4936182a4ee337db78f29116469b94`.
Tag chỉ đổi tài liệu trong allowlist so với anchor; không mở G7.

- 11 finding V37 đã có source fix và RED/GREEN tương ứng; xem
  [ledger](../tasks/audit-v38-20261105.md) và [biên bản 3.8](audit-v38-validation-20261105.md).
- Close không chứng nhận COMPLETE sau eviction/ngoài retention. Snapshot revision
  và migration giữ provenance; completion cũ không hạ incident hoặc hủy escalation mới.
  Feature failure retryable giữ raw/error, trả503, không chốt processed/outbox.
- Auth thiếu target/type/source giữ uncertainty và raw; remote source thiếu không
  alias local-console. Windows background không tự trở thành account incident.
- Central Sysmon checker giữ timestamp gốc: selected C2 sai clock bị chặn,
  destination history lỗi không enroll. Start/late wait giữ prefix/cutoff, không
  bỏ fragment hoặc nhận byte late để làm mẫu đạt.
- Cohort constraint fallback phân biệt infeasible với bounded-search unknown.
  Locked-test reservation có trước exposure; interrupted không trở lại UNOPENED.
  Runtime kiểm metrics integrity động, kể cả khi đã cache.
- Notebook bàn giao model thật theo versioned host path, safe extraction và exact
  provenance trước freeze. Smoke PASS không nghiệm thu archive Colab; host path
  và container path được phân biệt trong runbook tuần3.
- Windows full 749 passed/1 symlink skip; Linux 340 test case riêng biệt đạt,
  không skip (gồm bài symlink); Ruff PASS.
  QA n8n 2.44.6 + API thật kiểm feature503→retry200→duplicate, không gửi ra ngoài và
  không thay stack đang chạy. QA không thay real-lab telemetry acceptance.
- Gói bàn giao158 file, thêm8 output gốc khớp metadata 8/8. Hai account collector
  VALID nhưng supplementary REVIEW do destination enrollment clocks. Hai C2 còn
  native SystemTime/UtcTime mâu thuẫn; Wazuh arrival lag 0,6 s là phép đo khác.
  [Record/dòng/hash và tiêu chí parity](dataset-handoff-20261105.md).
- Chưa có EVTX để xác định endpoint hay forwarding/export gây mâu thuẫn. Giữ raw,
  lưu native evidence rồi xử lý nguồn và pilot mới; không sửa timestamp/hash.
  Source receipt phải phản ánh phiên bản thật đã chạy, không gán source mới ngược ngày.
- G7 CLOSED: catalog/cohort/challenge/taxonomy và lab acceptance chưa phát hành làm
  baseline trainable. Pilot không tính quota40–48, không chứng minh accuracy hoặc
  quyền phản ứng tự động. Giữ SHADOW; auto-close workflow/decision cuối vẫn chưa nghiệm thu.

Nguồn và tài liệu lấy từ GitHub tag đã pin, trong bảo trì không có run active;
không dùng code offline sửa riêng rồi báo đã chạy release. Node.js cần cho regression
workflow; cài trước khi cô lập. Source/runtime receipts và backup vẫn phải giữ thật.

[Runbook tuần3](week3-model-training-runbook.md), [contract](week3-data-contract.md)
và [operations](model-operations-runbook.md) áp dụng khi gate tương ứng đạt.
Biên bản3.7/R02/R03 cũ là lịch sử; hướng dẫn recovery hiện hành ở tag 3.8 vẫn bảo toàn
raw và không hồi sinh ABORTED/QUARANTINED. Chưa deploy lên lab 4 VM hoặc train/test thật.
