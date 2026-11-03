# Cập nhật mã và đánh giá phục hồi pilot R02

Ngày 03/11/2026. Áp dụng cho run
`ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS-R02-20261103` trên SOC-AI của Kiên.
Hướng dẫn này không xác nhận run đã được cứu hoặc đạt VALID.

Bản sửa xử lý ID của archive **thiếu trường rule** trong replay. Raw và ID nguồn
không đổi; ID nội bộ gắn với ordinal của record trong full capture và hash nguyên
record. Cùng ID khác payload của alert có rule vẫn bị chặn. Không cần cài thêm
dependency hoặc dựng lại VM vì bản sửa này.

## 1. Giữ nguyên run và xác định checkout

Không chạy action lần nữa trong R02, không tạo run mới khi khóa cũ chưa được xử lý,
không sửa receipt/clock/config/context/hash/checkpoint. Không để hai lệnh collector
cùng thao tác trên run. Wazuh và đường telemetry vẫn giữ nguyên; không restart hay
rotate Archives để thử sửa lỗi ID.

Gói bốn file đã gửi chỉ là trích xuất. Cần giữ **toàn bộ** thư mục run, kể cả file
ẩn, full capture, checkpoint, các snapshot và mọi late tail. Giữ cả reservations,
active-run owner và output tạm nếu có. Không kết luận ACCOUNT thiếu event chỉ vì
file trích xuất collision không chứa 4624/4625.

Mở Bash trên SOC-AI bằng user sở hữu checkout, không dùng root. Đường dẫn dưới đây
lấy từ `origin_project_root` trong gói R02; nếu thực tế khác thì dừng đối chiếu với
state, không đổi path frozen để làm khớp.

```bash
set -euo pipefail
cd /home/ubuntu/datn-ai-soar-v3
RUN_ID='ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS-R02-20261103'
RUN_DIR="evidence/scenario-runs/$RUN_ID"
test -d .git
test -f "$RUN_DIR/.collection_state.json"
test -x .venv-ml/bin/python
git rev-parse HEAD
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
```

Phải đúng RUN_ID, state còn STARTED và receipt COMPLETED như bản lỗi đã gửi.
Nếu FINALIZING/FINALIZED/ABORTED/QUARANTINED thì dừng quy trình này và đối chiếu
trạng thái thật theo Kiên.txt; không đổi state về STARTED.

## 2. Sao lưu trước khi đổi mã

Sau khi chắc chắn không còn lệnh collector đang chạy, sao lưu ra thư mục mới ngoài
checkout. Lệnh tar bên dưới giữ file ẩn và các thư mục staging, không sửa nguồn.
Không gửi `.env`, credentials hoặc toàn bộ home vào gói.

```bash
BACKUP_DIR=$(mktemp -d "$HOME/datn-r02-before-fix-XXXXXXXX")
items=(evidence/scenario-runs)
for item in evidence/bucket-reservations data/raw data/quarantine evidence/quarantine; do
  if [ -e "$item" ]; then items+=("$item"); fi
done
git rev-parse HEAD > "$BACKUP_DIR/source-before.txt"
git status --short > "$BACKUP_DIR/worktree-before.txt"
tar -czf "$BACKUP_DIR/run-before-fix.tar.gz" -- "${items[@]}"
tar -tzf "$BACKUP_DIR/run-before-fix.tar.gz" > "$BACKUP_DIR/archive.list"
grep -Fq "$RUN_DIR/.collection_state.json" "$BACKUP_DIR/archive.list"
(cd "$BACKUP_DIR" && sha256sum run-before-fix.tar.gz > checksums.sha256)
echo "$BACKUP_DIR"
```

Chép bộ backup ra host để bảo toàn. Backup này chưa phải xác nhận run hợp lệ và
không bảo đảm có thể restore inode/prefix của archive live để tiếp tục finalize.

## 3. Nhận bản sửa đã phát hành, không đổi snapshot của run

Thịnh gửi năm file cùng đợt: `PILOT_SOURCE.bundle`, `PILOT_SOURCE.bundle.sha256`,
`PILOT_SOURCE_COMMIT.txt`, Kiên.txt 3.4 và chính `pilot-r02-recovery.md` này.
Đặt companion cùng thư mục Kiên.txt để liên kết trong bản TXT không trỏ tới file
còn thiếu ở checkout cũ. Bundle được tạo từ main sau merge đã kiểm; SHA trong
pointer chỉ dùng pilot, không mở G7.

Chép ba file source vào `$HOME/datn-r02-fix` trên SOC-AI trước khi thực hiện khối
dưới. Bundle cho phép cập nhật khi SOC đang collection mode không có Internet.
Checksum kiểm lỗi sao chép; chỉ nhận bộ source từ Thịnh qua kênh bàn giao đã biết.

```bash
HANDOFF="$HOME/datn-r02-fix"
(cd "$HANDOFF" && sha256sum --check PILOT_SOURCE.bundle.sha256)
FIX_SHA=$(cat "$HANDOFF/PILOT_SOURCE_COMMIT.txt")
[[ "$FIX_SHA" =~ ^[0-9a-f]{40}$ ]]
git bundle verify "$HANDOFF/PILOT_SOURCE.bundle"
git fetch "$HANDOFF/PILOT_SOURCE.bundle" refs/heads/main
test "$(git rev-parse FETCH_HEAD)" = "$FIX_SHA"
```

Tiếp tục trên **chính checkout cũ**. Bản sửa đã kiểm từ main cũ `35c043c...`;
nếu checkout có nguồn khác thì không tự nâng cấp xuyên nhiều contract. Kiểm này
chủ động dừng để gửi SHA/worktree và evidence cho Thịnh đối chiếu.

```bash
OLD_PILOT='35c043c3a9a4874d3bcffe7d06522ab500355546'
test "$(git rev-parse HEAD)" = "$OLD_PILOT"
git diff --exit-code -- ml api scripts tests requirements.lock requirements-ml.lock
git diff --cached --exit-code
git diff --exit-code "$OLD_PILOT" "$FIX_SHA" -- \
  config ml/feature_schema.json requirements.lock requirements-ml.lock
git checkout --detach "$FIX_SHA"
test "$(git rev-parse HEAD)" = "$FIX_SHA"
mkdir -p operator-logs/r02-recovery
git rev-parse HEAD > operator-logs/r02-recovery/source-after.txt
.venv-ml/bin/python -m pytest -q tests/test_archive_replay_identity.py \
  tests/test_feature_pipeline.py tests/test_feature_state.py
```

Không dùng `reset --hard`, `clean`, `checkout -f`, stash rồi chép ngược config, hay
xóa file cản checkout. Nếu kiểm source/local edits hoặc test lỗi, dừng và gửi log.
Không chạy bootstrap/enrollment lại, không ghi đè `evidence/collection-source-commit.txt`
của đợt cũ. Mã mới không thay đổi contract/config/schema/dependency; các cấu hình lab
và snapshot frozen phải còn nguyên. Ghi cập nhật source ngoài evidence run đã đóng checksum.

## 4. Thử finalize một lần khi provenance còn nguyên

Chỉ làm bước này khi đã giữ đủ original evidence. Không dựng checkpoint bằng tay.
Nếu trước đó không có checkpoint sealed hợp lệ trước cutoff, hoặc archive nguồn
đã rotate/truncate/thay đổi, code phải từ chối; không dùng export rời để thay nguồn.

```bash
set +e
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID" \
  > operator-logs/r02-recovery/finalize.json \
  2> operator-logs/r02-recovery/finalize.stderr.txt
FINALIZE_RC=$?
set -e
cat operator-logs/r02-recovery/finalize.json
test "$FINALIZE_RC" -eq 0
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID" \
  > operator-logs/r02-recovery/validate.json
cat operator-logs/r02-recovery/validate.json
```

Nếu test exit-code dừng khối, **không chạy validate để tính đạt, không chạy lại action**.
Giữ JSON/stderr và toàn bộ evidence gửi Thịnh. Same-ID conflict còn lại ở alert có
rule phải tiếp tục bị chặn, không sửa rule hoặc ID gốc để chuyển sang nhánh raw.
Nếu không thể phục hồi theo provenance, dùng abort/quarantine đúng trạng thái theo
Kiên.txt, rồi chạy pilot mới với run ID và bucket mới sau khi sửa nguyên nhân.

Nếu finalize và validate đạt, tiếp tục phép kiểm `RUN_EVIDENCE_CHECK_PASS`, kiểm
context AVAILABLE/quality COMPLETE, backup/restore và bàn giao full raw/evidence
theo Kiên.txt mục 11 Bước 6 và mục 15/18. Không chỉ gửi hai file JSON kết quả.
R02 vẫn là `purpose: pilot`, không nhập vào quota train. G7 vẫn đóng cho tới nghiệm
thu đủ các điều kiện và phát hành baseline thu chính thức.
