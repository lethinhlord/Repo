# Hướng dẫn Kiên v3.1 — kiểm chứng ngày 29/10/2026

Bản bàn giao hiện hành đã được thay bằng 3.2 ngày 30/10/2026. Xem
[biên bản 3.2](handoff-guide-validation-v3.2-20261030.md); nội dung dưới đây được
giữ để truy vết 3.1 và các lần kiểm trước.

Lab 4 VM thuộc máy Kiên. Bản hiện hành kiểm phần mềm/câu lệnh và chuẩn bị pilot;
không thay cho nghiệm thu telemetry hoặc dataset thật ở lab đó. G7 vẫn đóng.

- Kiên.txt 3.1 và runbook cùng byte: 148815 byte UTF-8, SHA-256
  `63aacb26788a86bb1a8d86dc5053abcb107db9eec791a2f46dfc744bbb05597e`.
- File gửi: `D:\Tài liệu\Đồ án\Kiên.txt`; bản repo:
  `docs/scenario-collection-runbook.md`.
- Source pilot mới được pin: `d06d04034f0d1c996907365841f21cdb874e4d5a`.
  Revision tài liệu phát hành sau source; dùng Kiên.txt 3.1 đi kèm.
- Bản 3.0 giữ tại `D:\Tài liệu\Đồ án\Bản lưu hướng dẫn\Kiên_3_0_truoc_3_1_a3fe9a9aa0f2.txt`.
- Full suite Windows: **552 passed, 1 skipped**, không failure/error. Case skip là
  quyền tạo symlink trên Windows; Linux bổ sung **69 passed, 0 skipped**, gồm case đó.
- Ruff/pip check đạt; OpenAPI xuất lại cho proto/sensor_instance. Feature vector
  24 trường không đổi. Hai snapshot OpenAPI v1/week2 đã xuất lại bằng CLI; không thay thuật toán sau test.
- Native 3.1: 74 block Bash qua bash -n, 37 block PowerShell qua parser 5.1;
  inline Python/XML và đường dẫn CLI/module được đối chiếu source. Block measured
  clock chạy trong Linux với UTC thật/SSH transport mô phỏng có độ trễ: raw span
  >5 giây nhưng measured gate PASS đúng; không phải đo clock của VM Kiên.

JUnit final-full.xml có SHA-256
`4bf9a3c2d73d5bfbe47cc055afc055f29c8e9ecf40dc55e7c53fc14f3ab2d086`.
Evidence RED/GREEN/review và published-guide.json hiện hành nằm tại
`D:\DataCodex\2026-10-05\c\outputs\handoff-fixes-20261028`.
Các finding kiểm chéo và giới hạn được ghi tại
[collection-blocker-validation-20261029.md](collection-blocker-validation-20261029.md).

3.1 dùng measured clock, foreground intake trước cutoff, sealed-only retry và giữ
late evidence. Quarantine giữ cả raw cuối/output tạm; phục hồi chỉ quyền bucket,
không biến run hỏng thành VALID. Offline validation kiểm saved evidence; replay
feature không chứng minh API received_at. Hash kiểm toàn vẹn, không xác thực người
có quyền sửa đồng thời toàn bộ chứng cứ. Bản mới không mở G7 hoặc dùng lại dataset cũ.

## Lịch sử kiểm bản 3.0 — thông tin dưới đây không phải revision hiện hành

Các kết quả native enrollment/jq/chrony/Suricata/wheelhouse/backup cũ được giữ để
truy vết; block cấu hình tương ứng không đổi ở 3.1. Mã, hash và số test bên dưới chỉ
áp dụng bản 3.0, không thay các kết quả mới ở đầu tài liệu.

Ngày 28/10/2026. Theo xác nhận của Thịnh, máy đang làm việc không có lab 4 VM;
lab thuộc máy Kiên. Tài liệu này ghi bằng chứng kiểm phần mềm/câu lệnh, không thay
cho nghiệm thu telemetry thật hoặc xác nhận dataset sẵn sàng train.

## Bản được gửi

- File người dùng: `D:\Tài liệu\Đồ án\Kiên.txt`, UTF-8, 143180 byte.
- Bản trong repo: `docs/scenario-collection-runbook.md`, cùng byte với file trên.
- SHA-256 cả hai: `a3fe9a9aa0f2acb5872ea5e0e527f16f0805699cdb30d29ae4929ab7e1edb236`.
- Bản gốc được bảo toàn tại
  `D:\Tài liệu\Đồ án\Bản lưu hướng dẫn\Kiên_truoc_v3_01ce6c84fec0.txt`;
  SHA-256 `01ce6c84fec0c078f5f8d653c61f91414e20437d20b17996bc396722e1e3ed89`.
- Mã pilot được hướng dẫn pin chính xác:
  `24d98c3b20f8a9668a25a03c97b2b026c7ce07b5`, nhánh `fix/handoff-context-v3`.
  Revision tài liệu được phát hành sau mã pilot. Dùng Kiên.txt 3.0 đi kèm khi thao tác,
  thay vì lấy runbook lịch sử trong checkout mã pilot.

Đây là bàn giao để dựng/kiểm lab, enrollment riêng, chạy bốn pilot và backup/restore.
**G7 vẫn đóng:** chưa phát hành COLLECTION_BASELINE_COMMIT mới cho thu chính thức.
Catalog/cohort/taxonomy/challenge G01–G07 còn mở. Không dùng tag v2, pilot, fixture,
smoke hoặc dataset cũ để đủ 40–48 run.

## Những đối chiếu đã thực hiện

1. Mỗi CLI/file tham chiếu trong Bash được đối chiếu với source thực tế. Inline Python
   và XML fragment được parse. Kiểm Bash bằng `bash -n` thật trong Linux: **74 block**;
   PowerShell bằng parser của Windows PowerShell 5.1: **37 block**. Không thực thi các
   block cài đặt/firewall/đổi IP lên Windows host của Thịnh.
2. Chạy nguyên bộ lọc enrollment, capture byte range/checksum và CLI enrollment v3
   trong Linux với input QA mới có tên SYNTHETIC/NOT-LAB. Đủ năm user local/remote,
   ba port và DNS suffix; event ngoài phạm vi được loại. Baseline/capture crosslink
   và hash được kiểm. Đây không phải evidence thu thật hoặc dataset training.
3. Chạy block canary trên input QA đủ kênh và input bỏ final UDP flow: đủ kênh PASS,
   thiếu flow bị từ chối. Compile **27 jq filter** được trích từ tài liệu.
4. Chạy cổng G7 trên catalog hiện hành: từ chối đúng với `G7 CHUA MO`. Không hạ gate,
   thêm cohort giả hoặc đổi purpose để mở đợt thu.
5. Parse hai cấu hình giờ bằng chronyd thật (4.6.1 trong container); các directive
   được đối chiếu tài liệu chrony 4.5. Không chỉnh đồng hồ host hoặc tuyên bố đã đo
   skew của bốn VM Kiên. Hướng dẫn đặt SOC-AI làm NTP nội bộ, đo UTC trước cô lập,
   đo skew thật trước mỗi run và cấm step/resume trong run.
6. Nạp cấu hình tương đương từ stock Suricata **8.0.7**, giữ header YAML, local rules
   và timeout regular/emergency trong tài liệu. Native `--init-errors-fatal -T`
   đạt, không còn warning timeout đảo ngược. Phép kiểm không capture traffic thật;
   route/interface, final counter và độ trễ EVE→Archives vẫn phải qua G4/pilot.
7. Tải wheel cho Linux x86_64/Python 3.12, tạo venv sạch rồi cài bằng `--no-index`.
   **38 wheel**, pip check đạt, import scikit-learn 1.9.1/xgboost 3.4.1 đạt. Hướng dẫn
   tải/sao lưu wheelhouse trước cô lập để restore không cần Internet. Không dùng
   wheel Windows cho Ubuntu và không trộn wheelhouse này vào dataset.
8. Kiểm `git bundle create --all HEAD`/verify thật, gồm commit detached được pin.
   Chạy block tar/checksum/count với filesystem QA có manifest cùng tên ở cả raw
   và quarantine: giữ cả raw/evidence cách ly, nhưng chỉ đếm manifest dưới data/raw.
9. `.gitignore` bổ sung đúng hai thư mục quarantine do collector sinh. Native
   `git check-ignore` xác nhận cả hai được loại khỏi source dirtiness gate. Cách ly
   vẫn có trong backup; không che thay đổi code hoặc đưa run hỏng vào quota.

## Test hồi quy và vị trí bằng chứng

Toàn repo tại mã `95794cce0d05f79f39bdfea65a0cce9510eb5522`: **461/461** test đạt,
0 failure/error/skip, pip check và Ruff đạt. Mã pilot `24d98c3` chỉ thêm hai dòng
ignore quarantine; không thay logic Python, CLI, schema, workflow hoặc requirements
so với lượt full suite đó. **22 test** runbook/DNS đạt sau khi xuất bản tài liệu mới.

JUnit `checkpoint-95794cc-full.xml` có SHA-256
`2d3c6895e758d68e25839a418043103792deb9199745b8f182fb5be8fb0da3c9`.
Evidence QA nằm ngoài repo tại:

`D:\DataCodex\2026-10-05\c\outputs\handoff-implementation-20261028`

- `guide-validation/blocks.json`, các block theo số dòng, parser Bash/PowerShell;
- `guide-validation/native-test-publish.log`, input/output SYNTHETIC mới;
- `guide-validation/g7-expected-stop.txt`, `jq-filters.json`, cấu hình chrony;
- `guide-validation/suricata-stock.yaml`, `suricata-qa.yaml`, local rules;
- `guide-validation/wheelhouse-qa.log`, `backup-source-QA.bundle`;
- `guide-doc-regressions.xml`, `published-guide.json`, JUnit full suite phía trên.

## Điều kiện còn phải thực hiện ở Kiên

Kiên làm G0–G6, giữ raw/enrollment/receipt/snapshot/hash và ảnh nguyên màn hình host
có VMware, rồi gửi bundle/checksum/progress report cho Thịnh. Chưa có bằng chứng
Windows 11 logon type 2/3, SMB firewall allowed/denied, Suricata final TCP/UDP hoặc
backup/restore của lab Kiên. Không đánh dấu các mục đó đạt sẵn.

Thịnh tiếp tục chốt catalog đối chứng/cohort/taxonomy/challenge, final-window automation
và nghiệm thu runtime còn mở trước baseline thu chính thức. Dữ liệu thiếu hoặc hai
ý định không phân biệt được bằng đầu vào hiện có phải REVIEW/SHADOW. Quota 10–12
run/nhóm không chứng minh accuracy, CI hoặc đủ điều kiện phản ứng mạnh.
