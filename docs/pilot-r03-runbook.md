# Kiên — kiểm thử bản sửa intake và chạy pilot mới sau R03

Ngày 03/11/2026, đi cùng Kiên.txt 3.5 và source SHA phát hành. Gói bàn giao phải có
`PILOT_SOURCE.bundle`, checksum bundle, `PILOT_SOURCE_COMMIT.txt`, Kiên.txt,
`pilot-r02-recovery.md` và chính `pilot-r03-runbook.md` này.

## 1. Phạm vi bản sửa

Đã tái hiện hai lỗi bằng dữ liệu tổng hợp: đoạn đọc 1 MiB bị cắt giữa JSON khi nguồn
đã có dòng hoàn chỉnh; late tail đã lưu còn thiếu phần cuối bị parse trước khi đọc
lại nguồn. Bản sửa quan sát phần late tới EOF snapshot hữu hạn và giữ toàn bộ prefix
đã lưu. Quan sát thêm không làm bất kỳ byte late nào thành byte nhận đúng hạn.
Record thuộc bucket cũ đến muộn, record của agent cấu hình thiếu thời gian nguồn,
JSON malformed/chưa xong, nguồn rotate/truncate hoặc prefix thay đổi vẫn bị từ chối.

Không có evidence R03 thật trong các nguồn đã kiểm trên máy Thịnh, nên chưa xác
nhận được R03 thuộc tình huống nào. Checkpoint `capturing` cũ thiếu bằng chứng đọc
hoàn tất không được tạo lại hoặc ghi lùi để cứu run.

Giữ **bucket 300 giây + grace 60 giây**. Các lịch C2 đang dài hơn 60 giây; account
cũng có budget 60 giây cộng guard. Không đổi interval/frozen parameters để chạy
nhanh. Grace 90 giây chỉ là ứng viên cho profile mới được đối chiếu online/offline;
số đo max 81,063 giây không chứng minh mọi nguồn sẽ đến trong 90 giây. Nhóm 4625 chỉ
có năm mẫu. Không đổi config/snapshot của R03 để tăng grace.

## 2. Giữ evidence và đọc trạng thái cũ

Trên Bash của SOC-AI, user sở hữu checkout nhập đường dẫn đang dùng và run ID thật.
Không đồng thời để một terminal khác chạy collector trên run. Không nhập lại action.

```bash
set -euo pipefail
read -er -p 'Existing project root: ' PROJECT_ROOT
cd "$PROJECT_ROOT"
test -d .git
test -x .venv-ml/bin/python
read -rp 'Exact failed R03 run ID: ' R03_ID
[[ "$R03_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
test -f "evidence/scenario-runs/$R03_ID/.collection_state.json"
BACKUP_DIR=$(mktemp -d "$HOME/datn-r03-before-fix-XXXXXXXX")
items=(evidence/scenario-runs)
for item in evidence/bucket-reservations evidence/quarantine data/raw data/quarantine; do
  if [ -e "$item" ]; then items+=("$item"); fi
done
git rev-parse HEAD > "$BACKUP_DIR/source-before.txt"
git status --short > "$BACKUP_DIR/worktree-before.txt"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$R03_ID" \
  > "$BACKUP_DIR/run-status.json"
tar -czf "$BACKUP_DIR/evidence-before-fix.tar.gz" -- "${items[@]}"
tar -tzf "$BACKUP_DIR/evidence-before-fix.tar.gz" > "$BACKUP_DIR/archive.list"
grep -Fq "evidence/scenario-runs/$R03_ID/.collection_state.json" "$BACKUP_DIR/archive.list"
(cd "$BACKUP_DIR" && sha256sum evidence-before-fix.tar.gz > checksums.sha256)
cat "$BACKUP_DIR/run-status.json"
echo "$BACKUP_DIR"
```

Chép cả thư mục backup sang host. Gói này giữ file ẩn, capture, late tail, checkpoint,
snapshots, reservations và output tạm. Không bỏ riêng late tail vì nó báo lỗi.
Không gửi `.env`, private key hoặc Wazuh credentials.

## 3. Cập nhật source trên chính checkout cũ

Chép ba file source từ gói Thịnh gửi vào `$HOME/datn-r03-fix`. Không cần Internet
trên SOC trong collection mode. Quy trình dưới áp dụng khi source trước sửa là
main phát hành R02 `faac227...`; nếu SHA khác, dừng đối chiếu source-before.txt,
không dùng force/reset hoặc ghi đè sửa đổi local để ép tiếp tục.

```bash
HANDOFF="$HOME/datn-r03-fix"
(cd "$HANDOFF" && sha256sum --check PILOT_SOURCE.bundle.sha256)
FIX_SHA=$(cat "$HANDOFF/PILOT_SOURCE_COMMIT.txt")
[[ "$FIX_SHA" =~ ^[0-9a-f]{40}$ ]]
git bundle verify "$HANDOFF/PILOT_SOURCE.bundle"
git fetch "$HANDOFF/PILOT_SOURCE.bundle" refs/heads/main
test "$(git rev-parse FETCH_HEAD)" = "$FIX_SHA"
test "$(git rev-parse HEAD)" = faac2274ed3e03c614b801132cfa661528dab5e2
git diff --exit-code -- ml api scripts tests requirements.lock requirements-ml.lock
git diff --cached --exit-code
git diff --exit-code HEAD "$FIX_SHA" -- \
  config ml/feature_schema.json requirements.lock requirements-ml.lock
git checkout --detach "$FIX_SHA"
test "$(git rev-parse HEAD)" = "$FIX_SHA"
mkdir -p operator-logs/r03-fix
git rev-parse HEAD > operator-logs/r03-fix/source-after.txt
.venv-ml/bin/python -m pytest -q \
  tests/test_intake_tail_boundaries.py tests/test_intake_watermark.py \
  tests/test_intake_review.py tests/test_intake_collection.py \
  tests/test_collection_windows.py tests/test_archive_replay_identity.py \
  > operator-logs/r03-fix/pytest.txt 2>&1
cat operator-logs/r03-fix/pytest.txt
```

Phải exit 0. Test dùng fixture/temporary files, không phải thao tác tấn công lên VM.
Không bootstrap lại, không enrollment lại để sửa snapshot cũ, không đụng capture
hoặc `evidence/collection-source-commit.txt` cũ. Lưu source-after ngoài evidence run.
Nếu local edits/source gate hoặc test lỗi, giữ log và dừng bước phụ thuộc.

## 4. Quyết định xử lý run cũ

Đọc `intake_checkpoint.json` từ bản backup và đối chiếu file thật. Không chỉnh nó.

- Checkpoint còn `capturing`, mất checkpoint hoặc không có seal hợp lệ: không retry
  bằng cách xóa marker. Sau backup, dùng quarantine theo Kiên.txt mục 11 Bước 6 để
  giữ run lỗi và giải phóng owner đúng cách; bắt đầu pilot mới với ID và bucket mới.
- Checkpoint đã `sealed`: chỉ được thử finalize lại trên cùng checkout nếu source
  gốc/device/inode/hash/prefix/tail/snapshots còn hợp lệ. Mã mới có thể hoàn tất quan
  sát một late record không liên quan đã được nguồn ghi đầy đủ. Nó vẫn phải từ chối
  late record thuộc bucket cũ hoặc chưa xác định được tính liên quan.
- State đã FINALIZING/FINALIZED/ABORTED/QUARANTINED: làm đúng nhánh trạng thái ở
  Kiên.txt; không đặt nó ngược về STARTED.

Riêng nhánh đã sealed còn nguyên provenance, lệnh thử một lần:

```bash
set +e
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$R03_ID" \
  > operator-logs/r03-fix/finalize.json 2> operator-logs/r03-fix/finalize.stderr.txt
FINALIZE_RC=$?
set -e
cat operator-logs/r03-fix/finalize.json
test "$FINALIZE_RC" -eq 0
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$R03_ID" \
  > operator-logs/r03-fix/validate.json
cat operator-logs/r03-fix/validate.json
```

Nếu lệnh dừng, giữ JSON/stderr và toàn bộ evidence; không chạy action bổ sung.
Không coi JSON partial do nguồn thực sự đang ghi là một record không liên quan.
Không dùng status STARTED hoặc sự tồn tại file JSON để tính đạt.

## 5. Pilot mới và phần chờ có thể bỏ

Đo clock preflight mới và tạo draft `purpose: pilot` bằng đúng catalog như Kiên.txt
mục 11. Không dùng lại run ID, seed/nonce/file clock cũ hoặc sửa timestamp.
Chuẩn bị console/lệnh trước begin-action; giữ frozen pre-delay và các interval.
Sau action/cleanup, gọi complete-action rồi finalize --wait-for-window ngay như
quy trình chuẩn. Khoảng chờ finalize là intake có ghi thời điểm đọc, không phải sleep
có thể bỏ. Không đóng sớm khi vừa đếm đủ event.

Nếu cleanup đã xong trước complete-action và đã kiểm không còn process/artifact/
traffic của scenario, bỏ khoảng nghỉ cố định 60 giây bị lặp sau finalize. Vẫn tuân
thủ cooldown thật, owner lock, clean bucket và reservation. Với lifecycle hiện tại,
300s+60s và clean-bucket có thể khiến bucket action cách nhau khoảng 10 phút;
không hứa đổi một sleep sẽ giảm còn một phút/run. Tăng throughput mạnh cần thiết kế
intake liên tục/queue riêng và kiểm isolation, không thuộc hotfix này.

## 6. Gói evidence cần gửi lại

Gửi backup bước 2, source-before/source-after, pytest log, JSON/stderr finalize/
validate, **toàn bộ** evidence/scenario-runs hoặc evidence/quarantine của run,
reservations, data/raw hoặc data/quarantine tương ứng, cùng source bundle và
checksum. Chạy backup/restore kiểm chứng theo Kiên.txt mục 15 sau pilot đạt.
Nếu bản Archives gốc vẫn còn, giữ nguyên trên SOC và gửi thêm snapshot chẩn đoán
qua quy trình backup của lab; không chỉ gửi các dòng trùng ID hay một late fragment.
Snapshot làm sau cutoff không thay thế được read-completion evidence trước cutoff.

Phải có FINALIZED, VALID và RUN_EVIDENCE_CHECK_PASS/context/quality như Kiên.txt
mục 11 Bước 6 trước nghiệm thu. Pilot không nhập vào quota train; G7 vẫn đóng.
