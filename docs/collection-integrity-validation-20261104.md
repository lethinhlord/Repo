# Kiểm chứng collector 3.7 và pilot R06 — 04/11/2026

Runtime đã sửa ở commit `402d40658be416d3d6a3112afe6d63bdeca7033c`, merge qua
[PR 14](https://github.com/lethinhlord/Repo/pull/14). Source và hướng dẫn pilot
được pin bằng annotated tag `pilot-v3.7-20261104`; so với anchor runtime này, tag
chỉ cho phép đúng năm file tài liệu thay đổi theo full-tree gate của runbook.

## Các lỗi đã xử lý

- C01: kiểm checksum trước recovery, tách quan sát tail mới khỏi evidence đã
  chứng nhận, validate candidate trước publish/FINALIZED/nhả owner. Ngắt ngay sau
  commit FINALIZED có thể hoàn tất owner của chính run sau kiểm dữ liệu; dữ liệu
  hỏng hoặc owner của run khác vẫn bị từ chối. Capture/checkpoint không bị nới.
- C02: start/begin/complete/finalize/abort/quarantine dùng một mutex OS trong
  checkout. Lệnh cạnh tranh bị từ chối ngay; chết tiến trình tự nhả mutex. Không
  xóa file mutex để mở khóa. Owner và bucket là trạng thái riêng, không bị reset.
- T01: Subject không thay Target của 4624/4625. Known interactive logon thiếu
  target nằm trong account window nhưng PARTIAL và không thêm target/login count;
  vì vậy event đầy đủ bên cạnh không che được thiếu identity. Thiếu logon type
  vẫn unknown/PARTIAL. OS-background được loại theo identity đầy đủ như trước.
- T02: byte chỉ lấy một lần từ final flow, cùng canonical tuple/protocol/start.
  Alert/severity và transaction vẫn được giữ; final counter/interval/reset/reuse
  guards vẫn có hiệu lực. Oracle độc lập dùng tổng final, không chỉ so hai pipeline.
- R06: mọi occurrence Archives, có hoặc không có rule hợp lệ, có ID replay từ
  ordinal 12 chữ số đệm 0 và hash canonical record gốc. Native ID, firedtimes, rule,
  thứ tự/occurrence và raw bytes được giữ nguyên. Có test rule 67023, firedtimes
  8/9 và timestamp lệch 2 ms; ACCOUNT, C2 HTTP/DNS và occurrence giống nhau đều
  replay/validate offline được. API và store chưa qua adapter vẫn chặn cùng
  transport ID khác payload; rule sai cấu trúc không được che đi bằng ID ảo.
- Backup forensic: giữ thêm drafts, clock gốc, enrollment/context và recovery
  observations; liệt kê phần thiếu, kiểm checksum trên host. Thiếu bằng chứng
  không được bù bằng file tự tạo. Mã dự án lấy trên GitHub; backup dữ liệu riêng tư.

## Kiểm tra phần mềm

- Full suite cuối: **651 passed, 1 skipped**, 323,97 giây trên Windows. Skip là
  quyền tạo symlink của Windows. **230 passed, không skip** trên Linux/Python 3.12,
  gồm mutex nhiều tiến trình, crash release và symlink recovery guard.
- RED được lưu trước fix: telemetry 5 failed/1 control passed; lifecycle 12
  failed/3 guard passed; R06 ruled collision ba ca failed và guard online passed;
  ba contract tests identity cũ failed khi đổi yêu cầu thành occurrence identity;
  boundary commit-before-owner-release có ba RED. Sau sửa các ca đều GREEN.
- Lượt full trung gian có một test kỳ vọng family_hint unknown khi thiếu target.
  Đã đối chiếu độc lập và cập nhật contract thành account/PARTIAL cho event kind
  đã biết, đồng thời thêm assertion không đếm target và giữ raw_ref. Không xóa
  test, không bỏ quality gate hoặc nới context FUTURE/MISSING để đạt PASS.
- Test oracle R06 đầu dùng LF giả định trong khi fixture Windows ghi CRLF. Chỉ
  sửa oracle lấy đúng source-byte slice trước finalize; production không normalize
  hay sửa newline. Một lệnh test trỏ nhầm file không tồn tại được giữ log riêng,
  không gọi là PASS.
- Ruff toàn repo và git diff --check đạt. Không đổi feature schema, catalog,
  taxonomy, source config hoặc dependency để che lỗi.

## Kiểm tra lệnh trong hướng dẫn

- **29 ca native Linux/Git đạt** bằng block Bash thực của hướng dẫn. Transport
  GitHub được chuyển sang bare Git fixture riêng; clone/fetch/tag-object/commit/
  tree và tar/checksum vẫn là công cụ native thật. Có các ca chặn owner, state
  STARTED/FINALIZING/unknown, dirty tree, origin sai, tag bị đổi, code lệch anchor,
  cùng backup/restore khi 0 run hợp lệ và recovery gate R02/R03.
- Riêng hai forensic case tạo run STARTED/receipt COMPLETED với sealed capture
  bằng collector thật trên dữ liệu tổng hợp, gọi CLI status thật rồi chạy block
  forensic và GNU tar. Drafts/clock/enrollment/context/recovery/hidden staging
  được giữ; synthetic env/bundle bị loại. Hai bản sao được kiểm checksum bằng
  chính block PowerShell hướng dẫn trên host Windows và đều đạt.
- Source prefix của 6.2 và phần Git của 6.3 được kiểm riêng, không giả là đã chạy
  toàn bộ bootstrap/test suffix ở hai mục đó. Riêng restore chạy đầy đủ bootstrap
  online từ lockfile và pip check trong container QA. Không train hay dùng secret.
- **90 block Bash** qua bash -n; **40 block PowerShell** qua parser Windows
  PowerShell 5.1. Bốn tài liệu có lệnh khớp SHA-256 bytes thực thi; báo cáo này
  chỉ bổ sung văn bản. Final real-GitHub download/tag/SHA và Kiên.txt byte check
  được ghi trong receipt sau khi phát hành, không thay bằng transport fixture.

## Kiểm chéo

Sol thực hiện telemetry và lưu RED/GREEN; Terra kiểm độc lập telemetry, viết R06
regressions/oracle và kiểm guide forensic; Astra viết lifecycle regressions và
probe tail adversarial. GPT-6.1 Sol rà soát độc lập bản sửa cuối, chạy 18 lifecycle
và 30 archive/telemetry/intake tests, cùng probe partial completion, prefix rewrite,
persisted relevant-tail rejection và immutable evidence; không có finding chặn
trong phạm vi này. Lượt follow-up của Sol trước đó gặp giới hạn usage; không ghi
nhận một phê duyệt cuối của lượt đã lỗi đó.

## Hướng dẫn, phát hành và giới hạn

Hồ sơ QA, log RED/GREEN và receipt phát hành ở
`D:\DataCodex\2026-10-05\c\outputs\fix-collection-20261104`.
Kết quả kiểm lệnh và tag/download được ghi trong receipt cuối tại thư mục đó.
Kiên.txt chỉ cập nhật sau khi tải bản tag thực từ GitHub và so byte/hash. Câu giới
thiệu đã được người dùng bỏ khỏi Kiên.txt 3.6 được giữ nguyên lựa chọn bỏ trong
canonical 3.7; không ghi đè bằng bản cũ.

Ảnh R06 báo run đã ABORTED và backup checksum PASS. Chưa có gói evidence R06 thật
trong các thư mục dự án đã tìm trên máy Thịnh; không tuyên bố đã cứu hay nghiệm thu
R06. Không đổi ABORTED về STARTED: Kiên cập nhật trong bảo trì và chạy pilot mới
theo mục 0.3. Dữ liệu synthetic của tests không dùng train hoặc bù quota.

G7, catalog/cohort/challenge và nghiệm thu bốn VM thật vẫn chưa đạt. Stack Docker
cũ trên máy Thịnh không được thay bằng model/baseline giả để báo ready. Bản 3.7
phục vụ setup/pilot và kiểm phần mềm, không phải nghiệm thu model hay phản ứng mạnh.
