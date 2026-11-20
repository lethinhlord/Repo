# Huấn luyện từ bộ 40 run đã có

Tài liệu này hướng dẫn sử dụng nguyên trạng bộ 40 run đã bàn giao, không yêu cầu thu lại dữ liệu. Quy trình dành riêng cho hai nguồn thu đã được review và được ghi trong `config/training-source-compatibility.json`. Không áp dụng quy trình này cho một bộ dữ liệu hỗn hợp khác.

Bản mã dự kiến dùng cho xử lý và huấn luyện là `collection-v4.0.0-candidate.8`. Chỉ thực hiện các lệnh lấy mã dưới đây sau khi tag này đã được phát hành lên GitHub và chủ dự án đã cung cấp SHA đầy đủ được phê duyệt. Tài liệu không xác nhận tag đã được phát hành, lab đã đạt G7 mới hoặc mô hình đã được huấn luyện đạt chất lượng.

## 1. Phạm vi dữ liệu và bằng chứng

Kết quả đối chiếu ngày 20/11/2026 đã xác minh cây mã nguồn frozen và replay đúng nguồn cho cả hai nhóm:

| Nhóm | Số run | Commit thu ban đầu |
|---|---:|---|
| Source2 | 23 | `db166d814857ef061982839a74a17af6e500625f` |
| Source3 | 17 | `273d1d0800fa45e686488e8965a81ed19c4de7e6` |

Cả 40 run replay đạt bằng nguồn bàn giao cuối. Mỗi stratum có 10 run, đủ mức tối thiểu 40; mục tiêu ưu tiên 48 chưa đạt. Kết quả này xác nhận khả năng tái lập dữ liệu, chưa chứng minh hiệu quả phân loại của mô hình.

Chế độ mặc định vẫn kiểm tra nguồn đơn nhất và xuất manifest v2 cho các bộ dữ liệu phù hợp, kể cả fixture smoke. Chế độ mới phải được yêu cầu rõ bằng `--compatibility-policy config/training-source-compatibility.json`. Policy khóa đúng 40 run, hai nguồn thu, bytes đầu vào, bản ghi đã xử lý, source xử lý và split đã review. Policy không phải một cờ cho phép ghép nguồn bất kỳ.

Nguồn thu ban đầu được giữ nguyên trong frozen state và certificate. Commit xử lý mới được ghi riêng; không đổi nhãn, cohort, run ID, manifest gốc, trạng thái phiên thu, thời gian hay checksum để làm dữ liệu trông như được thu bằng candidate.8. Thiết kế candidate.8 giữ nguyên nội dung ngữ nghĩa đã review, chỉ cập nhật `candidate_tag`. Không chép `collection-design.yaml` cũ trong bundle đè lên cấu hình tracked của bản phát hành.

Kiểm tra ngoại tuyến dùng bằng chứng context, clock và acceptance đã frozen tại thời điểm run. Không gia hạn enrollment, chạy preflight/G7 mới, tạo run hoặc thu pilot chỉ để xử lý bộ 40 này; không sửa timestamp của bằng chứng cũ. Nếu sau này cần thu dữ liệu mới bằng candidate.8, phải nghiệm thu G7 thật cho candidate mới trên lab. Các hướng dẫn G7 candidate.4/candidate.7 là hồ sơ lịch sử, không phải approval G7 cho candidate.8.

## 2. Chọn bộ Colab dựng sẵn hoặc tự dựng

Ưu tiên dùng ZIP Colab dựng sẵn do chủ dự án bàn giao cùng SHA-256 và SHA source được phê duyệt. Bộ này chỉ chứa `train.jsonl`, `validation.jsonl`, `dataset_manifest.json` và `colab-upload.sha256`; người dùng không cần dựng lại nếu đã nhận đủ bộ và đối chiếu đúng danh tính. Tài liệu không khẳng định ZIP đã được phát hành hoặc có sẵn tại một đường dẫn tải cụ thể.

Nếu cần tự dựng lại để đối chiếu, thực hiện mục 3–5 trên bản sao ngoại tuyến. Giữ nguyên bundle gốc. Không chạy các lệnh này trong checkout đang vận hành collector hoặc đang có phiên thu.

## 3. Chuẩn bị checkout và runtime xử lý

Dùng clone hoặc worktree mới, sạch, của đúng release đã phê duyệt. Ví dụ dưới đây dùng Bash trên máy xử lý tin cậy. Đặt các biến bằng đường dẫn thực tế và thông tin do chủ dự án cung cấp:

- `APPROVED_PROCESSING_COMMIT`: SHA Git đủ 40 ký tự của candidate.8 đã phát hành và được phê duyệt.
- `HANDOFF_ROOT`: thư mục bundle đã kiểm chứng, chứa `data/raw` và `evidence/scenario-runs` của đúng bộ 40 run.
- `HANDOFF_SOURCE_ACTIVE`: đường dẫn file source active nguyên bản trong handoff.
- `PROCESSING_PYTHON`: đường dẫn tuyệt đối tới Python trong môi trường xử lý đã được review, còn nguyên package inventory.

Hai runtime xử lý được review gồm môi trường local Python 3.12 với package hash bắt đầu `2cd…` và môi trường SOC Python 3.14 với package hash bắt đầu `4b7…`. Đây chỉ là tên nhận diện rút gọn; phép kiểm bên dưới so sánh toàn bộ Python identity và SHA-256 package inventory với `processing_runtimes` trong policy. Không chạy `pip install`, nâng cấp pip hoặc thay package của môi trường xử lý để thử vượt kiểm tra này. Nếu môi trường không khớp, giữ nguyên dữ liệu và dùng lại đúng môi trường đã được phê duyệt.

```bash
set -euo pipefail
: "${APPROVED_PROCESSING_COMMIT:?Nhap SHA release da duoc phe duyet}"
: "${HANDOFF_ROOT:?Nhap duong dan bundle 40 run}"
: "${HANDOFF_SOURCE_ACTIVE:?Nhap file source active nguyen ban}"
: "${PROCESSING_PYTHON:?Nhap Python cua runtime xu ly da review}"
export APPROVED_PROCESSING_COMMIT
TAG=collection-v4.0.0-candidate.8
BUILD_ROOT="$HOME/datn-ai-soar-40-candidate8"
test ! -e "$BUILD_ROOT"
test -x "$PROCESSING_PYTHON"
test -d "$HANDOFF_ROOT/data/raw"
test -d "$HANDOFF_ROOT/evidence/scenario-runs"
test -f "$HANDOFF_SOURCE_ACTIVE"
git clone --branch "$TAG" https://github.com/lethinhlord/Repo.git "$BUILD_ROOT"
cd "$BUILD_ROOT"
test "$(git cat-file -t "refs/tags/$TAG")" = tag
test "$(git rev-parse HEAD)" = "$APPROVED_PROCESSING_COMMIT"
test "$(git rev-parse "${TAG}^{commit}")" = "$APPROVED_PROCESSING_COMMIT"
test -z "$(git status --porcelain --untracked-files=all)"
mkdir -p operator-logs
"$PROCESSING_PYTHON" - <<'PY' | tee operator-logs/processing-runtime.json
import json
from pathlib import Path
from ml.training_sources import runtime_identity

policy = json.loads(Path("config/training-source-compatibility.json").read_text())
actual = runtime_identity()
if actual not in policy["processing_runtimes"]:
    raise SystemExit("Runtime xu ly khong khop inventory da review")
print(json.dumps(actual, indent=2))
PY
```

Clone đầy đủ lịch sử Git; không dùng shallow clone. Cần có các commit nguồn thu gốc để kiểm cây mã và quan hệ kế thừa. Không tự tạo lại tag cũ bằng object mới. Giữ nguyên các file tracked, kể cả `ml/training_config.yaml`, feature schema, collection design và compatibility policy.

Chỉ đưa bản sao raw, bằng chứng từng run và source active vào các thư mục được bỏ qua bởi Git. Không chép toàn bộ cấu hình, `.venv`, cache hoặc thư mục `operator-logs` của bundle đè lên checkout mới:

```bash
test ! -e data/raw
test ! -e evidence/scenario-runs
mkdir -p data/raw evidence/scenario-runs
cp -a -- "$HANDOFF_ROOT/data/raw/." data/raw/
cp -a -- "$HANDOFF_ROOT/evidence/scenario-runs/." evidence/scenario-runs/
cp -p -- "$HANDOFF_SOURCE_ACTIVE" operator-logs/collection-sources-active.yaml
cmp -- "$HANDOFF_SOURCE_ACTIVE" operator-logs/collection-sources-active.yaml
sha256sum operator-logs/collection-sources-active.yaml \
  > operator-logs/collection-sources-active.sha256
test -z "$(git status --porcelain --untracked-files=all)"
```

`cp -a` giữ lại metadata thời gian của bản sao. Bundle gốc chỉ được đọc. Nếu Git báo thay đổi hoặc inventory run không đúng policy, dừng để đối chiếu; không dùng reset/clean, đổi state hoặc sửa hash nhằm làm phép kiểm đi tiếp.

## 4. Audit và dựng manifest v3

Chạy cả auditor và builder với cùng file source active và cùng policy. Không thay bằng script chỉ in `PASS`, không bỏ audit và không đổi quota để đạt target:

```bash
"$PROCESSING_PYTHON" -m scripts.audit_dataset \
  --mode final \
  --raw-dir data/raw \
  --evidence-dir evidence/scenario-runs \
  --source-config operator-logs/collection-sources-active.yaml \
  --compatibility-policy config/training-source-compatibility.json \
  --output operator-logs/dataset-audit-existing40.json \
  | tee operator-logs/dataset-audit-existing40.log

"$PROCESSING_PYTHON" -m ml.build_dataset \
  --config ml/training_config.yaml \
  --source-config operator-logs/collection-sources-active.yaml \
  --compatibility-policy config/training-source-compatibility.json \
  | tee operator-logs/build-existing40.log
```

Kết quả mong đợi cho bộ tối thiểu là audit `READY`, 40 valid run, 0 invalid run và không có lỗi chặn. `TARGET_MET` dành cho mục tiêu ưu tiên, không phải điều kiện để bộ 40 đạt mức tối thiểu. Bất kỳ lỗi nguồn, runtime, bytes, record hoặc split nào đều cần được giải quyết từ đầu vào hoặc phiên bản được phê duyệt; không sửa manifest sau build.

Manifest mới phải là `dataset-manifest-v3`, có certificate `collection_audit.source_compatibility` và digest tương ứng trong provenance. Split theo cohort với seed 42 giữ nguyên cấu hình: **24 TRAIN, 8 VALIDATION, 8 LOCKED TEST**. Kiểm thông tin tổng hợp mà không mở file hay mapping locked test:

```bash
"$PROCESSING_PYTHON" - <<'PY' | tee operator-logs/manifest-existing40-summary.json
import json
import os
from pathlib import Path
from ml.training_sources import verify_training_manifest

manifest = json.loads(Path("data/processed/dataset_manifest.json").read_text())
verify_training_manifest(
    manifest, root=Path.cwd(), expected_commit=os.environ["APPROVED_PROCESSING_COMMIT"],
)
assert manifest["manifest_version"] == "dataset-manifest-v3"
assert manifest["record_counts"] == {"train": 24, "validation": 8, "locked_test": 8}
assert manifest["locked_test_status"] == "UNOPENED"
print(json.dumps({
    "manifest_version": manifest["manifest_version"],
    "record_counts": manifest["record_counts"],
    "builder_git_commit": manifest["provenance"]["builder_git_commit"],
    "dataset_hash_sha256": manifest["dataset_hash_sha256"],
    "source_compatibility_sha256": manifest["provenance"]["source_compatibility_sha256"],
    "locked_test_status": manifest["locked_test_status"],
}, indent=2))
PY
```

Sau build, không mở `data/processed/locked_test.jsonl` hoặc `ml/splits/test.txt`, không in nội dung hay danh sách thành viên tập test. Giữ chúng tại máy tin cậy cho cổng đánh giá sau đóng băng theo quy trình được phê duyệt. Loader chỉ đọc TRAIN và VALIDATION; các commitment của locked test được kiểm qua manifest và policy.

## 5. Chuẩn bị đúng bốn file cho Colab

Nếu dùng ZIP dựng sẵn, đối chiếu SHA-256 toàn bộ ZIP với giá trị chủ dự án cung cấp rồi giải nén vào thư mục staging mới, trống. Nếu tự dựng, tạo checksum và staging như sau:

```bash
(cd data/processed && \
  sha256sum train.jsonl validation.jsonl dataset_manifest.json > colab-upload.sha256)
STAGE="$BUILD_ROOT/operator-logs/colab-existing40"
test ! -e "$STAGE"
mkdir "$STAGE"
cp -- data/processed/train.jsonl data/processed/validation.jsonl \
  data/processed/dataset_manifest.json data/processed/colab-upload.sha256 "$STAGE/"
(cd "$STAGE" && sha256sum -c colab-upload.sha256)
```

Đưa đúng bốn file vào `MyDrive/DATN/week3-data/processed/`:

```text
train.jsonl
validation.jsonl
dataset_manifest.json
colab-upload.sha256
```

Không đưa raw, bằng chứng run, mapping split, locked test, `.env` hoặc khóa lên Colab. Checksum upload bảo vệ file khi vận chuyển; approval của SHA source phải đến từ bàn giao tin cậy, không suy ra từ chính file được upload.

## 6. Chạy notebook bằng source đã phê duyệt

Mở [notebook Week 3](../notebooks/week3_train_colab.ipynb) từ đúng source GitHub đã phát hành. Dùng runtime Colab mới; đặt `BRANCH` thành `collection-v4.0.0-candidate.8` và `EXPECTED_TRAINING_COMMIT` thành cùng SHA đã được phê duyệt, khớp `provenance.builder_git_commit` của manifest. Tên tag chỉ giúp lấy source; SHA đầy đủ mới là danh tính thực thi.

Chạy các cell theo thứ tự. Trước khi cài dependency và đọc partition, notebook lấy đúng checkout detached, kiểm config/design và xác minh certificate bằng policy nằm trong source đã pin. Loader tiếp tục kiểm bytes, record, split và leakage của TRAIN/VALIDATION trước khi fit. Đổi nhãn phiên bản v2 thành v3 hoặc bỏ certificate không thể thay cho quá trình audit/build.

Môi trường huấn luyện Colab tách biệt với runtime xử lý ở mục 3. Dùng các bước cài đặt từ `requirements.lock`, `requirements-ml.lock` và `requirements-notebook.lock` của đúng checkout trong notebook; không yêu cầu Colab giả danh runtime thu hoặc runtime xử lý. Không chuyển các lệnh cài package của notebook sang môi trường xử lý đã frozen.

Đầu ra là model package, metric validation, calibration, EDA trên TRAIN, leakage audit và log trong `MyDrive/DATN/week3-results/model-package-week3.tar.gz`. Metadata và experiment summary giữ provenance cùng certificate đã kiểm. Chỉ kết luận chất lượng sau khi xem metric thực tế, confidence interval, FPR, Brier, latency và các gate; `automation_eligible=false` tiếp tục yêu cầu chế độ ASSISTED/SHADOW. Không mở locked test để chọn model hoặc threshold.

Đối chiếu và đóng băng package thật theo [runbook huấn luyện](week3-model-training-runbook.md). Các mục hướng dẫn manifest v2 trong runbook chung áp dụng cho chế độ nguồn đơn nhất; bộ 40 này phải dùng quy trình v3 tại tài liệu hiện tại. Smoke PASS hoặc test mã nguồn không thay thế nghiệm thu package Colab.

## 7. Chụp bằng chứng thực tế

Chụp thủ công toàn màn hình thật của PyCharm và Colab sau khi từng bước đã thực sự chạy. Giữ giao diện ứng dụng, lệnh và kết quả liên quan trong ảnh; chuẩn bị màn hình không chứa khóa hoặc dữ liệu locked test trước khi chụp. Không tạo ảnh mô phỏng, dán kết quả giả vào terminal hoặc dùng script chỉ in trạng thái thành công.

1. Trong PyCharm: checkout/SHA hiện tại, config và policy được pin; ảnh terminal cho runtime identity và audit final thật.
2. Trong PyCharm: kết quả builder và bản tóm tắt manifest 24/8/8, dataset hash, certificate digest, `UNOPENED`; không mở file hoặc mapping locked test.
3. Trong Colab: SHA detached và kết quả kiểm nguồn/certificate trước train; sau đó ảnh leakage audit và EDA chỉ trên TRAIN.
4. Sau phiên train thật: bảng kết quả candidate/validation, gate calibration và metadata `UNOPENED`, đường dẫn archive cùng SHA-256 đã xuất.

Ghi rõ phiên bản, thời gian và bước được chứng minh của từng ảnh. Ảnh test fixture, kiểm mã nguồn, replay ngoại tuyến và G7 lab là các loại bằng chứng khác nhau; chỉ gắn kết luận mà thao tác thực tế đã xác nhận.
