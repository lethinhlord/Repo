# Chạy model phát triển bằng Docker trên Windows

Dùng model đã train trên Colab để suy luận offline qua Linux trong Docker.
Model và bộ 48 run hiện có được giữ nguyên. Môi trường này nạp nguyên estimator
đã calibration và áp dụng đúng thứ tự feature, threshold lưu trong artifact.

## 1. Chuẩn bị

Mở Docker Desktop, dùng **Linux containers**. Kiểm tra trong PowerShell:

```powershell
docker info --format '{{.OSType}}'
```

Kết quả phải là `linux`. Lần build đầu cần Internet để tải image và thư viện;
những lần sau dùng cache. Runtime suy luận không có mạng, không mở cổng, chỉ
mount archive và file đầu vào ở chế độ đọc. Không cần cài Python trên Windows.

Dùng bản repository có thư mục `docs/development-runtime`. Chuẩn bị:

- Archive gốc `.tar.gz` được xuất từ Colab, gồm model và evidence.
- SHA-256 gốc của archive từ kết quả xuất Colab hoặc bản bàn giao tin cậy.
- File JSONL chứa feature cần suy luận. Có thể dùng `train.jsonl` đã kiểm tra
  để kiểm chức năng; kết quả trên TRAIN không phải kiểm định độc lập.

Hash được kiểm tra lại bên trong container trên chính byte sẽ được nạp. Chỉ
dùng model từ nguồn tin cậy: joblib/pickle có thể thực thi mã khi nạp. Không lấy
checksum do một nguồn model không tin cậy tự cung cấp làm bằng chứng tin cậy.

## 2. Chạy ngay với artifact và 48 run đã có trên máy Thịnh

Trong PowerShell:

```powershell
Set-Location D:\Repo
& .\docs\development-runtime\run.ps1 `
  -Archive 'D:\development-model-development-20261127T154124Z.tar.gz' `
  -Sha256 '1831f7125e68944f8426467a29b9e4efec33f33eb7ae346318bb9467f966b0d0' `
  -Records 'D:\Repo\data\processed-development-v1\train.jsonl' `
  -OutputPath 'D:\development-predictions-48.json'
```

Đường dẫn trên dành cho bộ hiện tại; đổi đường dẫn và SHA cho một artifact khác.
Giữ file archive gốc. Không cần nạp `joblib` bằng Python Windows hoặc train lại.
Nếu output đã tồn tại, chọn tên mới: launcher từ chối ghi đè. Nếu Docker đang
tắt, SHA sai, archive thiếu/hỏng, model sai contract hoặc feature không hợp lệ,
lệnh dừng với lỗi và không ghi file kết quả suy luận.

Kết quả thành công ghi `Saved 48 development predictions` và image ID bất biến.
Đọc kết quả:

```powershell
$result = Get-Content -LiteralPath 'D:\development-predictions-48.json' -Raw | ConvertFrom-Json
$result | Select-Object status, model_version, record_count, automation_eligible, deployment_eligible
$result.predictions | Select-Object run_id, family, probability_malicious, development_threshold, development_prediction
```

`development_prediction` là `1` cho malicious và `0` cho benign tại threshold
phát triển đã lưu. `label` của JSONL không được dùng để tính xác suất. Lưu kết
quả cùng image ID, SHA archive và SHA input để đối chiếu lần chạy sau.

## 3. Suy luận dữ liệu khác

Mỗi dòng UTF-8 là một object JSON chứa `family` (`account` hoặc `c2`) và `features`:

```text
{"run_id":"ID-cua-ban","family":"account","features":{...}}
```

Đây là khung minh họa, không phải dữ liệu chạy được. Điền đủ các feature được
liệt kê ở `x-family-features` của family đó trong `feature_schema.json` đi kèm
model; hoặc dùng đầy đủ 56 feature của record từ pipeline đã duyệt. Không điền
0 để thay thế feature chưa thu được. Giá trị phải là số hữu hạn, đúng kiểu và
miền giá trị của schema; tên feature ngoài schema bị từ chối. Các field metadata
của record như `label`, `incident`, `collection_context` không quyết định dự đoán.
Lệnh nhận 1–4096 dòng, tối đa 32 MiB mỗi file input/archive.

Chạy lại lệnh mục 2 với `-Records` và `-OutputPath` mới. Launcher giữ nguyên
calibration và threshold; không tự chọn lại model, threshold hoặc sửa nhãn.

## 4. Phạm vi kết quả

Model này là `development-model-v1`: `automation_eligible=false` và
`deployment_eligible=false` trong mọi kết quả. Docker xử lý môi trường suy luận;
không biến OOF phát triển thành validation/test độc lập hoặc bật phản ứng SOAR.
Việc phân loại đúng 48 dòng TRAIN chỉ chứng minh đường nạp/suy luận hoạt động.
Không dùng file này thay signed production package trong FastAPI/ModelRuntime.

Tài liệu kỹ thuật chính thức:
[Docker build context và Dockerfile.dockerignore](https://docs.docker.com/build/concepts/context/),
[Docker container runtime](https://docs.docker.com/engine/containers/run/),
[XGBoost model IO và memory snapshots](https://xgboost.readthedocs.io/en/stable/tutorials/saving_model.html).
