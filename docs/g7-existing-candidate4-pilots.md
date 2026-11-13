# G7 cho bốn pilot candidate.4 đã đạt — 13/11/2026

Bản này dành cho lab của Kiên đã thu đủ bốn pilot dưới đây. Mã candidate.4 được
kế thừa trong `collection-v4.0.0-candidate.6`, gồm sửa G7/source, native lifecycle
và HTTP post-request hold đã review. Không chạy lại bốn pilot chỉ để đổi phiên bản.
Không sửa raw, state, manifest, start contract, nhãn hoặc checksum của pilot.
Lab đã gặp lỗi jitter ngày13/11 cần hoàn thành
[cập nhật và một retest lỗi mới](sysmon-jitter-retest-20261113.md) trước khi thu tiếp.
Receipt candidate.5 được lưu lại làm hồ sơ; tạo acceptance mới cho candidate.6.

G7 v2 ghi riêng candidate tạo pilot và candidate dùng cho các run mới. Cơ chế
kế thừa kiểm chính xác commit/tree pilot, cùng Python/Node/package inventory,
patch thu thập đã được review, bốn strata/transports, raw preflight và restore
backup. Hash của cấu hình active được kiểm lại tại draft/START và frozen state.
Các gate khác vẫn hoạt động. Receipt là kiểm tính toàn vẹn, không phải chữ ký.

HTTP dùng hold cục bộ sau request; một số profile nhịp quá nhanh vẫn có thể lỗi
schedule. Không đổi frozen gap, bỏ profile, hạ quality gate hoặc
đếm run ABORTED để đủ quota. G7 cho phép thu chính thức; dataset vẫn phải đạt
audit sau khi thu. Không cam kết mọi profile HTTP nhanh sẽ thành công.

## 1. Cập nhật trên SOC-AI, giữ nguyên dữ liệu

Chạy trong SSH của Ubuntu SOC-AI, user `ubuntu` đã dùng để thu pilot. Không chạy
trong Kali/NET-SENSOR hoặc PowerShell của Windows. Chưa có quyền truy cập lab từ
máy của Thịnh nên acceptance thật phải được tạo tại đây, đúng môi trường thu.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
test -z "$(git status --porcelain --untracked-files=all)"
test ! -e evidence/scenario-runs/.active-run.json
git fetch origin tag collection-v4.0.0-candidate.6
git switch --detach collection-v4.0.0-candidate.6
test "$(git cat-file -t refs/tags/collection-v4.0.0-candidate.6)" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse collection-v4.0.0-candidate.6^{commit})"
test -z "$(git status --porcelain --untracked-files=all)"
mkdir -p operator-logs
.venv-ml/bin/python -m scripts.collection_release candidate \
 --tag collection-v4.0.0-candidate.6 --check-remote \
 > operator-logs/candidate6-current.json
cat operator-logs/candidate6-current.json
mkdir -p operator-logs/releases
REF_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
for NAME in candidate.json source-tag.txt source-commit.txt; do
 REF="operator-logs/releases/$NAME"
 if [ -e "$REF" ]; then
  test -f "$REF"
  test ! -e "$REF.before-native6-$REF_STAMP"
  mv -- "$REF" "$REF.before-native6-$REF_STAMP"
 fi
done
cp -- operator-logs/candidate6-current.json operator-logs/releases/candidate.json
printf '%s\n' collection-v4.0.0-candidate.6 > operator-logs/releases/source-tag.txt
git rev-parse HEAD > operator-logs/releases/source-commit.txt
```

Giữ nguyên `.venv-ml`, Python, Node và các package đã dùng thu candidate.4;
không chạy pip install/upgrade trong bước này. Nếu kiểm báo runtime khác, dừng
và đối chiếu môi trường trước, không đổi hash trong receipt để khớp.
Tag candidate.4 cũ chưa có trên remote không ngăn kế thừa: policy đối chiếu commit
`a7df9b623125ffd0d1403181005e05b136680bb5` và fingerprint đủ300file; tag object cũ
vẫn được giữ đúng trong hồ sơ. Không tạo lại tag cũ bằng object khác.

## 2. Kiểm bốn ID và evidence tại chỗ

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
PILOTS=(
 PILOT-ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS-20261111T102846Z-V4
 PILOT-ACCOUNT-MALICIOUS-REPEATED-FAILURES-6-20261111T101754Z-RETRY-V4
 PILOT-C2-BENIGN-DNS-20261111T094840Z-V4
 PILOT-C2-MALICIOUS-HTTP-BEACON-20261111T093029Z-R2
)
for rid in "${PILOTS[@]}"; do
 .venv-ml/bin/python -m scripts.scenario_session validate --run-id "$rid"
 .venv-ml/bin/python -m scripts.verify_run_evidence --run-id "$rid"
done
```

Cả hai lệnh của mỗi run phải lần lượt báo VALID và RUN_EVIDENCE_CHECK_PASS. Nếu
thiếu file trên máy SOC, khôi phục từ backup gốc đúng quy trình; không tự tạo
manifest/incident hoặc lấy file khác run. Ba pilot cũ và run aborted vẫn giữ
trong evidence; không đưa chúng vào bốn ID nghiệm thu này hoặc quota trainable.

## 3. Kiểm enrollment active; làm mới nếu hết hạn

Baseline frozen của bốn pilot đã hết hạn lúc 12:15:00 UTC ngày11/11/2026
(19:15:00 Việt Nam). Giữ nó trong evidence cũ. Để thu các run mới, dùng enrollment
thật còn hạn ở `evidence/context-baseline.json`, với capture tương ứng trong
`evidence/context-captures/`. Nếu chưa có baseline còn hạn, thực hiện mục10.5 của
`docs/scenario-collection-runbook.md` bằng một capture enrollment mới, kiểm
ENROLLMENT_REBUILD_AND_INVENTORY=PASS rồi quay lại bước này. Đây là làm mới context,
không phải chạy lại pilot. Không dùng capture cũ gắn thời gian mới hoặc sửa TTL.

Chuẩn bị file active mới từ source đã được xác minh của pilot:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
COLLECTION_SOURCE_CONFIG=operator-logs/collection-sources-active.yaml
if [ ! -e "$COLLECTION_SOURCE_CONFIG" ]; then
 .venv-ml/bin/python -m scripts.prepare_collection_source \
  --pilot PILOT-ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS-20261111T102846Z-V4 \
  --baseline evidence/context-baseline.json --output "$COLLECTION_SOURCE_CONFIG"
fi
test -f "$COLLECTION_SOURCE_CONFIG"
cat "$COLLECTION_SOURCE_CONFIG"
sha256sum "$COLLECTION_SOURCE_CONFIG"
```

File mới phải báo ACTIVE_SOURCE_PREPARED; file đã có được kiểm lại ở accept và
authorize. Script kiểm hash/rebuild/enrollment và thời hạn baseline thật trước khi
ghi. Source giữ `feature_scope=full-window` cùng mọi gate;
chỉ đổi đường dẫn baseline active. Không sửa file tracked trong `config/` để mở
gate. Nếu file active đã tồn tại, đối chiếu bản đó; không ghi đè hoặc xóa tùy tiện.
Sau khi đã nghiệm thu, giữ nguyên bytes file active. Có thể enrollment mới vào
baseline active theo mục10.5 khi hết hạn; mỗi run tự đóng băng baseline/capture mới.

## 4. Xác định đúng backup và preflight đã có

Các đường dẫn dưới đây là đường dẫn trong gói bàn giao của lab này. Kiểm chúng
tồn tại trên SOC; nếu đã chuyển thư mục, dùng đường dẫn tuyệt đối thực tế của bản
backup còn nguyên bytes và directory preflight đầy đủ. Không sửa metadata bên
trong backup. G7 kiểm lại các file và tự restore vào thư mục tạm.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
BACKUP_DIR="$HOME/datn-backups/PILOT-V4-HANDOFF-20261111T105802Z"
PREFLIGHT_DIR="$PWD/operator-logs/preflight/pf179430094631096"
test -d "$BACKUP_DIR"
test -f "$PREFLIGHT_DIR/archives-fresh.jsonl"
test -f "$PREFLIGHT_DIR/channel-check.txt"
test -f "$PREFLIGHT_DIR/capture.sha256"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
(cd "$PREFLIGHT_DIR" && sha256sum --check capture.sha256)
```

Không thay backup cũ bằng backup tạo trên candidate.6 rồi vẫn khai nó là backup
candidate.4. Acceptance này kiểm source metadata của backup theo candidate tạo
pilot, đồng thời kiểm candidate đang chạy theo candidate.6. Mỗi START trainable
sẽ kiểm lại hai bộ thông tin này và toàn bộ evidence liên quan.

## 5. Tạo acceptance G7 v2 thật

Chạy cùng phiên shell đã đặt BACKUP_DIR/PREFLIGHT_DIR ở bước4. Nếu mở phiên mới,
đặt lại hai biến bằng chính các lệnh bước4.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
: "${BACKUP_DIR:?Thuc hien buoc 4 trong phien shell nay}"
: "${PREFLIGHT_DIR:?Thuc hien buoc 4 trong phien shell nay}"
COLLECTION_SOURCE_CONFIG=operator-logs/collection-sources-active.yaml
test -f "$COLLECTION_SOURCE_CONFIG"
if [ -e evidence/collection-acceptance.json ]; then
 test -f evidence/collection-acceptance.json
 LEGACY_RECEIPT="evidence/collection-acceptance-before-native6-$(date -u +%Y%m%dT%H%M%SZ).json"
 test ! -e "$LEGACY_RECEIPT"
 sha256sum evidence/collection-acceptance.json
 mv -- evidence/collection-acceptance.json "$LEGACY_RECEIPT"
 sha256sum "$LEGACY_RECEIPT"
fi
.venv-ml/bin/python -m scripts.collection_release accept \
 --tag collection-v4.0.0-candidate.6 --source-config "$COLLECTION_SOURCE_CONFIG" \
 --pilot PILOT-ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS-20261111T102846Z-V4 \
 --pilot PILOT-ACCOUNT-MALICIOUS-REPEATED-FAILURES-6-20261111T101754Z-RETRY-V4 \
 --pilot PILOT-C2-BENIGN-DNS-20261111T094840Z-V4 \
 --pilot PILOT-C2-MALICIOUS-HTTP-BEACON-20261111T093029Z-R2 \
 --backup-dir "$BACKUP_DIR" --preflight-dir "$PREFLIGHT_DIR" \
 --output evidence/collection-acceptance.json \
 > operator-logs/g7-candidate6-acceptance.json
.venv-ml/bin/python -m scripts.collection_release authorize \
 --source-config "$COLLECTION_SOURCE_CONFIG"
sha256sum evidence/collection-acceptance.json
jq '{version,candidate,pilot_candidate,source_config,collection_contract,pilot_adoption}' \
 evidence/collection-acceptance.json
```

Chỉ bắt đầu thu chính thức khi `authorize` báo COLLECTION_AUTHORIZED. Receipt phải
là collection-acceptance-v2; candidate là candidate.6, pilot_candidate giữ nguyên
candidate.4; source_config đúng file active. Nếu ERROR, dừng ở bước đó và gửi
output lỗi cùng evidence; không ghi PASS bằng tay hoặc hạ điều kiện kiểm.
Không xóa/di chuyển backup, preflight hoặc evidence đã gắn với acceptance.

## 6. Tạo plan chính thức và thu từng run

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
PLAN="run-drafts/preferred-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan --kind preferred --output "$PLAN"
jq '.kind, (.runs|length)' "$PLAN"
sha256sum "$PLAN"
jq -r '.runs[]|[.ordinal,.scenario_id,.run_id,.purpose,.collection_seed]|@tsv' "$PLAN"
```

Plan preferred có48run,12mỗi stratum, đúng năm cohort. Có thể chọn `minimum` để
thu40run; không trộn hai plan hoặc thay seed theo outcome. Giữ bốn pilot để audit
và G7 nhưng không tính chúng vào quota hoặc đưa vào train/validation/test.

Theo từng ordinal, thực hiện đủ mục11 của runbook: clock đo mới, draft, START,
export frozen parameters, begin-action, runner thật trên Windows/Kali, receipt,
complete-action, finalize, validate và verify evidence. Dùng cùng source active
ở cả draft và START; hai CLI đều hỗ trợ `--source-config`:

```bash
.venv-ml/bin/python -m scripts.create_run_draft \
 --scenario "$SCENARIO" --run-id "$RUN_ID" --operator Kien --purpose trainable \
 --collection-seed "$COLLECTION_SEED" --clock-preflight "$CLOCK_FILE" \
 --source-config operator-logs/collection-sources-active.yaml
.venv-ml/bin/python -m scripts.scenario_session start \
 --draft "run-drafts/$RUN_ID.yaml" \
 --source-config operator-logs/collection-sources-active.yaml
```

SCENARIO/RUN_ID/COLLECTION_SEED phải lấy đúng dòng plan; CLOCK_FILE phải được tạo
từ đo clock mới theo mục11.2, không sao chép biến hoặc clock file từ pilot.
Receipt chấp thuận không làm baseline/clock hết hạn trở thành hợp lệ.

## 7. Audit và build bằng cùng source active

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
.venv-ml/bin/python -m scripts.audit_dataset --mode final \
 --source-config operator-logs/collection-sources-active.yaml \
 --output evidence/dataset-audit.json
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml \
 --source-config operator-logs/collection-sources-active.yaml
```

Không sửa training_config.yaml để đổi source, vì làm dirty candidate. Builder ghi
override và hash vào provenance, vẫn kiểm audit. Auditor kiểm raw/frozen evidence
của cả pilot/challenge; contract active và candidate đồng nhất áp dụng cho
trainable, nên giữ pilot cũ không làm mất khả năng build dataset mới.

Chỉ train khi audit READY/TARGET_MET và builder thành công. Giữ locked_test tại
SOC theo runbook; Colab chỉ nhận train.jsonl, validation.jsonl,
dataset_manifest.json và colab-upload.sha256. Không đưa raw, credential hoặc
locked_test lên Colab. Bốn pilot VALID không thay thế kiểm tra dataset sau thu.

## 8. Ảnh minh chứng

Chụp toàn màn hình laptop, không crop: VMware có terminal SOC hiện candidate,
validate4pilot, baseline/capture kiểm đạt, source active, lệnh accept và authorize,
plan48run, rồi các bước thu thật. Giữ thanh VMware/taskbar theo yêu cầu. Tên ảnh
nên có timestamp và bước; lưu D:/Tài liệu/Đồ án/Ảnh báo cáo. Không dùng ảnh script
in PASS giả thay cho kết quả công cụ. Không tuyên bố đã chụp/đã chạy lab từ các
phép thử synthetic hoặc replay offline trên máy Thịnh.
