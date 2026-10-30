# Kiên.txt 3.2 — biên bản kiểm trước bàn giao 30/10/2026

Bản hướng dẫn được soạn/kiểm từ 29/10 và bàn giao ngày 30/10. Mục tiêu là chặn các
thiếu sót đã thấy trong DATN_SOC_20_VALID_RUNS ngay ở preflight và sau từng run,
trước khi tính quota hoặc chuyển sang train. Không sửa hoặc dùng lại dataset đó.

## Bản gửi

- File: `D:\Tài liệu\Đồ án\Kiên.txt`, UTF-8, 180703 byte.
- Cùng byte với `docs/scenario-collection-runbook.md` trong repo.
- SHA-256: `aabed037b518e8a752ef0db4b5aa5521865c1d9528dcc7b4e55cf6a87b6eb7c7`.
- Mã pilot vẫn pin `d06d04034f0d1c996907365841f21cdb874e4d5a`; lượt này sửa tài liệu,
  không đổi collector, schema, taxonomy, catalog hoặc bộ train.
- File người dùng trước bàn giao đã bỏ phần mở đầu so với 3.1. Đã giữ nguyên tại
  `D:\Tài liệu\Đồ án\Bản lưu hướng dẫn\Kiên_truoc_3_2_e9064de6b417.txt`.
  Bản 3.1 đầy đủ từ Git cũng được giữ tại
  `D:\Tài liệu\Đồ án\Bản lưu hướng dẫn\Kiên_3_1_day_du_63aacb26788a.txt`.

## Các điểm sửa và kiểm chéo

1. Lộ trình thao tác/trách nhiệm G0–G9, source mode khác run purpose; kiểm source v3,
   đủ 24 feature, ba source gate bật và grace đúng trước thu.
2. Canary có ID riêng, child DNS runner có hash đúng và đủ process/DNS events.
   Native Windows đọc XML bằng RecordId, so SystemTime/UtcTime và độ mới; giữ XML
   trước parse, CSV sau parse; chép log sang SOC trước sign-out.
3. Polling không dừng sớm ở channel/SID đầu tiên. Nó refresh tới khi đủ Security,
   nonce-bound Sysmon/time, ba HTTP port, bốn DNS query/response và final flow cho
   mọi full connection key. Có log cụ thể khi thiếu từng kênh.
4. Sau VALID còn kiểm đúng RUN_ID: snapshot/context/checkpoint, schema 24 trường,
   hai thời gian Sysmon, final coverage. Kết quả/lỗi nằm ngoài cây evidence đã hash;
   lỗi phải quarantine và thu mới, không sửa raw hoặc đếm thư mục là đủ quota.
5. Timeline complete/finalize/cutoff, pre-stage thao tác, ID mới sau quarantine và
   cách ly pilot source cũ trước khi thay catalog được chỉ rõ.
6. G7 có kiểm tính khả thi cohort/fold từ metadata thiết kế, không tạo run giả.
   G7 thực vẫn đóng; chủ trì phải chốt đối chứng/cohort/challenge/taxonomy và nghiệm
   thu pilot trước release chính thức. Source-check PASS không tự mở thu train.
7. Chuyển release offline bằng local bundle, checkout đúng SHA ancestor; wheelhouse
   phải đúng OS/Python và hai lockfile. Có venv sạch no-index, hash lock trong backup
   và kiểm lại trước restore. Không gọi bootstrap tải Internet trong collection mode.
8. Source lấy từ main đã merge, không phụ thuộc feature branch cũ. Colab phải chọn
   nhánh release đúng SHA/config của source build; các cell kiểm nguồn có hướng dẫn.
9. Sửa hai dấu `+` thừa kế thừa trong lệnh nmcli của 3.1; kiểm đối số add/modify và
   chặn dấu prefix diff lọt vào bản xuất. Sửa tham chiếu mục cô lập Internet về 10.1.

Sol kiểm native PowerShell/XML và timestamp precision; Astra đối chiếu collector,
DNS arguments, flow/counter helper và cohort design; Terra kiểm luồng thao tác,
backup/restore, dependency release và các biến/field Colab. Các đề nghị có ảnh hưởng
đến vận hành được sửa rồi đối chiếu lại. Đây là đọc chéo hữu hạn, không là chứng
nhận mọi lỗi có thể có đều đã bị loại bỏ.

## Phép thử đã thực hiện

- 77 block Bash qua `bash -n`; 38 block qua Windows PowerShell 5.1 parser; hai block
  Python, inline Python/XML và đường dẫn CLI/module được kiểm.
- 22 test runbook/DNS của repo đạt. Không chạy lại full suite 552 của mã pilot chỉ
  để đổi tài liệu; kết quả mã đó được ghi riêng ở biên bản 3.1.
- **35 ca thử dùng chính code block trích từ bản có hash nêu trên**, không viết lại
  logic kiểm thay thế. Gồm canary đầy đủ/thiếu response/thiếu final/sai tuple/proto/
  sai giờ/cùng hai giờ cũ/thiếu UTC/thiếu process; post-run đủ/thiếu chứng cứ; source
  G7 thật từ chối đúng, thiết kế cohort metadata cân bằng/thiếu group; polling có
  final tới ở lần đọc sau; nmcli add/modify; bundle ancestor và lock sai; venv sạch
  no-index từ wheel Linux; Colab source/config khớp và sai.
- Timestamp parser kiểm UTC/offset, thiếu timezone, bảy chữ số phần lẻ và ngưỡng
  chính xác 5 giây/5.0000001 giây. Không làm tròn sai để nhận một record quá ngưỡng.

Các input là QA mới, có tên SYNTHETIC/NOT-LAB, nằm ngoài repo/dataset chính thức.
Collector thực tạo hai fixture v3 trong vùng QA để thử phép kiểm sau VALID; không
coi đó là run đã thu trên VM Kiên. Các nhánh nmcli dùng recorder đối số, không đổi
NIC thật; native Windows được parse/kiểm XML, không chạy lên dịch vụ host của Thịnh.
Metadata thiết kế không có execution/feature rows; không mở locked test, không train.

Evidence ngoài repo:

`D:\DataCodex\2026-10-05\c\outputs\guide-v3-2-20261029`

Gồm `actual-block-results.json` (35 ca), `final-native-qa.txt`,
`tested-guide-sha256.txt`, `final-guide-regressions.xml`, parser/blocks trong
`guide-validation`, các ghi chú review và `published-guide.json`.

## Phạm vi còn phải thực hiện

Kiên vẫn phải chạy canary/pilot trên bốn VM thật, chụp ảnh toàn màn hình và gửi raw,
checkpoint/context/hash cùng backup restore. Thịnh còn phải phát hành candidate và
baseline/challenge/cohort/taxonomy được nghiệm thu ở G7. Không mở G7 bằng sửa biến,
gán cohort tùy ý, đổi purpose của pilot hoặc điền feature lịch sử bằng 0.

Quy trình mới cung cấp điều kiện đạt/dừng và cách giữ lỗi; nó không thay bằng chứng
lab, không xác nhận sẵn dataset đủ train và không cam kết tuyệt đối không có sự cố.
