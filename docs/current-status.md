# Trạng thái phần mềm và bàn giao hiện tại

Ngày 03/11/2026. Đây là điểm vào hiện hành; các báo cáo trong `history/` và nhật ký
`tasks/` là hồ sơ theo thời điểm, không phải chỉ dẫn chạy phiên bản cũ.

- Hướng dẫn Kiên hiện hành: [lab bốn VM và thu dữ liệu v3](scenario-collection-runbook.md).
- Dataset mới phải có 24 feature v3, baseline/capture/checkpoint và policy thời gian
  `last-relevant-source-v1`. Chỉ nhận evidence mới theo đúng source phát hành.
- Pilot 3.6 lấy mã và hướng dẫn trực tiếp từ tag GitHub `pilot-v3.6-20261103`,
  kiểm annotated tag, anchor 9c599f6 và ghi SHA đầy đủ theo mục 6.2/6.3. Không dùng
  gói source offline hoặc file pointer; tag pilot không mở G7. GitHub chỉ truy cập
  trong bảo trì không có owner active, trước khi cô lập collection mode.
- Pilot R02 chưa nghiệm thu: gói chẩn đoán chỉ là trích xuất, thiếu full capture nên
  không xác nhận được khả năng khôi phục hay bằng chứng ACCOUNT. Cần kiểm bản run
  đầy đủ và source sửa lỗi đã phát hành trước khi thử finalize lại theo runbook.
- Sửa archive identity và kiểm chéo ngày 03/11 được ghi trong
  [biên bản R02](archive-replay-r02-validation-20261103.md), kèm
  [quy trình cập nhật/khôi phục](pilot-r02-recovery.md).
- R03: sửa phân loại late tail không xác nhận pilot đã được cứu hay nghiệm thu;
  chưa tìm thấy evidence run R03 thực tế trong các nơi đã kiểm. Không dựng lại hoặc
  ghi lùi checkpoint `capturing` cũ; xem [quy trình pilot R03](pilot-r03-runbook.md)
  cho run mới sau khi source sửa lỗi được kiểm chứng và phát hành.
- Kết quả sửa intake, kiểm kê thư mục/GitHub/Docker và sai lệch runtime v2 trên máy
  Thịnh nằm trong [biên bản R03](pilot-r03-validation-20261103.md). Image QA v3 đã
  kiểm riêng; stack cũ chưa được nâng cấp khi thiếu baseline/package v3 hợp lệ.
- G7 vẫn đóng; nghiệm thu lab thực tế hiện chưa được thực hiện. Thu chính thức còn cần
  catalog/cohort/challenge/taxonomy và pilot lab được nghiệm thu. Không dùng quota run
  thay cho số cohort độc lập hoặc bằng chứng thống kê.
- Workflow n8n hiện SHADOW và ingest tạm thời. API finalize-window đã có; workflow
  đóng window tự động/decision cuối và phản ứng mạnh vẫn chưa được nghiệm thu.
- Kiểm clock/firewall/loss/flow/restore trên bốn VM thật do Kiên thực hiện. Không có
  lab ở máy Thịnh để thay bằng chứng đó bằng unit test hoặc container QA.
- Train theo [runbook tuần3](week3-model-training-runbook.md) và notebook phát hành,
  với SHA được duyệt khớp manifest builder/config, đủ bốn file staging, test khóa
  vẫn UNOPENED. [Operations](model-operations-runbook.md) dùng schema v3.

Các sửa F01–F09, phạm vi kiểm, mốc source và tài nguyên đã loại bỏ được ghi trong
biên bản nghiệm thu lượt sửa này. Không có tuyên bố model đã đạt độ chính xác hoặc
hệ thống đã đủ điều kiện phản ứng tự động.

Bàn giao GitHub-only 3.6 và các kiểm tra thao tác được ghi trong
[biên bản hướng dẫn 3.6](github-handoff-validation-v3.6-20261103.md). Các biên bản
R02/R03 và 3.3 trước đó là hồ sơ theo thời điểm; mô tả bundle trong đó không còn là
quy trình nhận mã hiện hành.
