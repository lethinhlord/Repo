# Huấn luyện từ 40 run hiện có với profile TCP stream

Phiên bản tài liệu: 21/11/2026. Bản bàn giao cuối có SHA source, checksum dữ
liệu, kết quả test và archive thực tế trong `KIEM_TRA_BAN_GIAO.json`.

## 1. Chọn đúng bộ dữ liệu

Dùng bốn file trong thư mục `colab-processed` của bộ bàn giao mới:

1. `train.jsonl`
2. `validation.jsonl`
3. `dataset_manifest.json`
4. `colab-upload.sha256`

Đây là dữ liệu dẫn xuất từ đúng 40 run đã có, sau khi xác minh lại raw và
evidence. Không cần chạy lại pilot hoặc thu lại raw để bắt đầu thí nghiệm này.
Giữ nguyên nhãn, cohort và phân chia **24 TRAIN / 8 VALIDATION / 8 LOCKED**.
Không dùng bốn file v3 đã upload trước đó cho notebook stream.

Vector mới có 44 giá trị: 24 giá trị cũ giữ nguyên và 20 giá trị conversation
mới. Mỗi bản ghi giữ thêm `source_incident` để tái dựng và đối chiếu chính xác
bản ghi gốc. Trường này là metadata truy vết, không phải feature đưa vào model.
Account dùng nguyên 10 feature; C2 dùng bộ 12 feature TCP đã chốt trước bước
biến đổi held-out. Raw, DNS và feature v3 không bị xóa. Các gói v3 trước đó vẫn
được giữ để đối chiếu.

Giữ bản gốc tại máy tin cậy. Không upload raw, `.env`, khóa ký, token,
`locked_test.jsonl` hoặc `ml/splits/test.txt` lên Colab. Không chỉnh manifest,
nhãn, cohort, checksum hoặc danh sách feature bằng tay để vượt kiểm tra.

## 2. Upload bộ bốn file mới

1. Mở Drive đúng tài khoản dùng cho Colab.
2. Trong My Drive, tạo `DATN/week3-stream-data/processed-stream-v1`.
3. Upload đúng bốn file từ `colab-processed` vào thư mục này. Chờ cả bốn báo
   upload hoàn tất; không kéo cả thư mục raw hoặc repo lên Drive.
4. Kiểm tra đường dẫn: `MyDrive/DATN/week3-stream-data/processed-stream-v1/train.jsonl`
   phải là file trực tiếp, không nằm trong thêm một thư mục `colab-processed`.
5. Giữ nguyên bộ v3 tại `DATN/week3-data/processed` để có thể tái hiện kết quả
   cũ. Hai bộ không được trộn lẫn trong cùng một lần train.

Đối chiếu SHA-256 trên Windows bằng `Get-FileHash -LiteralPath <file> -Algorithm
SHA256`. Giá trị phải khớp file checksum bàn giao. Notebook cũng kiểm lại cả
checksum và phê duyệt chính xác manifest trong Git, không chỉ sự tồn tại file.

## 3. Mở notebook đúng phiên bản

Dùng link Colab cố định theo SHA trong `BAT_DAU_TRAIN_COLAB.txt`. Tên notebook
là **week3_train_stream_colab.ipynb**. Chọn **Sao chép vào Drive**, đặt tên bản
sao theo ngày/phiên. Dùng runtime CPU Linux x86_64 mới; GPU không bắt buộc.

Trong cell cấu hình:

```python
BRANCH = "training-v2.0.0"
EXPECTED_TRAINING_COMMIT = "<SHA 40 ký tự trong bản bàn giao>"
```

Đặt SHA trainer đầy đủ đã được bàn giao; không dùng SHA của builder gốc v3
hoặc của hai commit đã thu raw. Giữ đường dẫn mặc định stream và seed 42.
Notebook không tự tin vào một nhánh có thể thay đổi: nó checkout detached và
kiểm đúng SHA. Nếu SHA, source, config, schema hoặc phê duyệt không khớp thì
dừng; không bỏ assertion hoặc đổi hash để cho chạy.

## 4. Chạy tuần tự và đối chiếu đầu ra

1. **Cấu hình/source:** gắn Drive đúng tài khoản. Phải thấy SHA source đúng và
   thông báo xác minh source compatibility. Builder dẫn xuất có thể khác
   trainer chỉ trong chuyển tiếp đã được Git phê duyệt chính xác.
2. **Môi trường:** notebook tạo CPython 3.12.15 cô lập. Các wheel triển khai
   được khóa phiên bản/SHA; `pip check` và bước kiểm môi trường phải PASS.
   Không `%pip install` ngẫu nhiên vào kernel hoặc đổi lock file.
3. **Nạp dữ liệu:** chỉ sao chép ba file dữ liệu và checksum; không có file
   test khóa trong nguồn Drive hoặc project Colab.
4. **Preflight:** phải có 24 TRAIN, 8 VALIDATION; cả bốn strata có mặt; không
   trùng run/incident/cohort giữa các tập; schema `features-v4-stream-v1`,
   manifest `dataset-manifest-v4-stream-v1`, collection audit
   `DERIVED_VERIFIED`, leakage PASS và locked `UNOPENED`.
5. **EDA:** chỉ dùng TRAIN để xem phân bố, missing, outlier và nhãn. Không dùng
   validation/test để chọn lại feature, đổi scenario hoặc chia lại tập.
6. **Quality:** chạy Ruff và toàn bộ pytest. Log in tên từng test/giai đoạn.
   Một số test giả lập đầy đủ bộ thu 40/48 run mất vài phút. Không bấm lại khi
   cell vẫn có tiến trình/log; số "0 giây" của UI không xác nhận bị treo.
7. **Train:** ba candidate Logistic Regression, Random Forest, XGBoost được
   so sánh bằng grouped CV trong TRAIN. Scaler/calibration chỉ fit trong
   phần train tương ứng. Validation chọn threshold và đánh giá các gate,
   không dùng để fit model hoặc chọn biểu diễn mới.
8. **Đọc kết quả:** xem cả precision, recall, PR-AUC, F1, FPR, Brier, ECE,
   khoảng tin cậy, độ ổn định và mọi `gate_failures`. Không chỉ nhìn F1 hoặc
   dấu tích xanh của cell. `automation_eligible=false` phải giữ nguyên.
9. **Xuất model:** archive nằm ở
   `MyDrive/DATN/week3-stream-results/model-package-week3-stream.tar.gz`.
   Ghi lại model version, source SHA, dataset hash và SHA-256 của archive.
   Archive gồm model thật, metadata, schema, metrics, EDA, leakage và log;
   không có raw hoặc test khóa.
10. Tải archive vào thư mục phiên mới và dùng `Get-FileHash` kiểm đúng SHA
    notebook đã in. Giữ bản sao model/archive phiên trước trước khi chạy lại.
    Lưu notebook đã có output; không chỉ lưu một bản code trắng.

Nếu source/checksum/dependency/test thất bại, giữ nguyên log để điều tra. Với
bootstrap dở dang, tạo runtime mới; không chạy tiếp bằng môi trường cài dở.
Không thay đổi dữ liệu hoặc bỏ gate để có thông báo thành công.

## 5. Diễn giải phạm vi kết quả

Train được ngay không đồng nghĩa đã đủ bằng chứng để tự động khóa/chặn.
Tập hiện tại nhỏ; một cohort validation độc lập/family chưa đủ đánh giá độ
tin cậy. Không đổi tên run hoặc tách cùng một run thành nhiều "mẫu độc lập".
Đã chốt biểu diễn bằng kiểm tra TRAIN trước khi xử lý held-out. Các so sánh
TRAIN ít cohort chỉ hỗ trợ thí nghiệm, không chứng minh cải thiện tổng quát.

Profile này mô tả conversation TCP. DNS-only, đích đại diện hòa nhau hoặc
không có lịch sử đã xác minh vẫn bắt buộc REVIEW. Dữ liệu các trường hợp đó
được giữ, không xóa để làm đẹp điểm. Thực hiện kiểm chứng DNS C2 độc lập trong
một kế hoạch dữ liệu sau, thay vì tuyên bố model TCP đã bao phủ DNS C2.

Model Colab xuất ra chưa freeze/ký. Bước train không mở test khóa, không cấp
G7 mới và không tự thay đổi n8n hay hệ thống SOC của Kiên.

## 6. Dùng đúng API khi kiểm model trên SOC

Giữ API/n8n v3 hiện có. Kiểm stream trên **một API kiểm thử riêng**, cổng hoặc
container riêng, package/registry/monitoring/cache riêng. Mỗi API hiện chọn một
`MODEL_PACKAGE_DIR`; hai route không đồng nghĩa nạp hai model đồng thời. Không
đổi package của API v3 đang chạy sang stream rồi cho rằng workflow v3 vẫn dự
đoán được. Không đưa incident 44 feature vào workflow v3 mà chưa đổi hợp đồng.

Sau khi xác minh archive/metadata, freeze/ký bằng khóa tại máy SOC theo phần
bàn giao fail-stop ở cuối notebook; khóa ký không đưa lên Colab. Đối chiếu
đúng UID, registry và bind mount như runbook gốc. `/model/ready` phải báo
`mode: trained`, đúng model version, `features-v4-stream-v1`, locked
`UNOPENED`; `/ready` phải xác nhận đúng profile và strong actions false.

Tạo feature bằng `/features/wazuh/stream/batch` hoặc hai route
`/features/wazuh/stream/stateful` và `/features/wazuh/stream/finalize-window`,
rồi gửi incident trả về vào `/predict/stream`. Cache stream dùng
`FEATURE_STREAM_STATE_DB`; không trỏ vào database v3. Khác profile phải bị
từ chối, không âm thầm bỏ feature hoặc fallback về mock.

Đây là kiểm model SHADOW/ASSISTED; việc nối workflow production/challenge
độc lập và nghiệm thu phản ứng vẫn cần các bước tương ứng. Tập test khóa chỉ
đánh giá một lần sau freeze ở cổng Week 6; không mở ở quá trình phát triển này.

## 7. Lưu ảnh minh chứng

Chụp toàn màn hình laptop thực tế, có thanh ứng dụng/trình duyệt như yêu cầu;
không crop, ghép hoặc dựng terminal giả. Lưu vào
`D:\Tài liệu\Đồ án\Ảnh báo cáo` theo model version, thứ tự bước:

1. Drive: đủ bốn file đúng đường dẫn stream, hoàn tất upload.
2. Colab: SHA source và môi trường CPython 3.12.15.
3. Preflight: 24+8, strata, leakage PASS, schema mới, locked UNOPENED.
4. Quality: toàn bộ pytest/Ruff đã kết thúc, có tổng số test thật.
5. TRAIN comparison và validation: đầy đủ FPR/calibration/gate failures.
6. Export: đường dẫn archive, model version và SHA-256.
7. Nếu kiểm SOC: màn hình VMware thật với dịch vụ/API và model readiness.

Lưu cùng notebook có output, archive, checksum và log. Không dùng ảnh chụp
code PowerShell được viết để mô phỏng thông báo của hệ thống.

## Tài liệu phương pháp

- [Scikit-learn: tránh leakage và fit preprocessing trong pipeline](https://scikit-learn.org/stable/common_pitfalls.html).
- [Scikit-learn: cross-validation với các nhóm phụ thuộc](https://scikit-learn.org/stable/modules/cross_validation.html).
- [Scikit-learn: calibration của xác suất dự đoán](https://scikit-learn.org/stable/modules/calibration.html).
