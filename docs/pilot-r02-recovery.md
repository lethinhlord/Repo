# Cập nhật mã và đánh giá phục hồi pilot R02

Ngày 04/11/2026. Áp dụng cho run
`ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS-R02-20261103` trên SOC-AI của Kiên.
Hướng dẫn này không xác nhận run đã được cứu hoặc đạt VALID.

Bản 3.7 xử lý ID lặp của mọi record Archives trong replay, kể cả record có rule
hợp lệ như R06. Raw, native ID, rule và firedtimes không đổi; ID nội bộ gắn với
ordinal trước lọc và hash nguyên record. Guard cùng transport ID khác payload tại
API/store chưa qua adapter vẫn giữ nguyên. Không cần dựng lại VM vì bản sửa này.

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
for item in evidence/bucket-reservations evidence/quarantine data/raw data/quarantine \
  run-drafts operator-logs/enrollment operator-logs/recovery \
  evidence/context-baseline.json evidence/context-captures; do
  if [ -e "$item" ]; then
    items+=("$item")
    printf 'PRESENT %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  else
    printf 'MISSING %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  fi
done
for item in "run-drafts/$RUN_ID.yaml" "run-drafts/$RUN_ID-clock.yaml" \
  "run-drafts/$RUN_ID-clock-measurements.json"; do
  if [ -f "$item" ]; then
    printf 'PRESENT %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  else
    printf 'MISSING %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  fi
done
git rev-parse HEAD > "$BACKUP_DIR/source-before.txt"
git status --short > "$BACKUP_DIR/worktree-before.txt"
tar -czf "$BACKUP_DIR/run-before-fix.tar.gz" \
  --exclude='*.env' --exclude='*.pem' --exclude='*.key' \
  --exclude='*wheelhouse*' --exclude='*.whl' --exclude='*.bundle' \
  -- "${items[@]}"
tar -tzf "$BACKUP_DIR/run-before-fix.tar.gz" > "$BACKUP_DIR/archive.list"
grep -Fq "$RUN_DIR/.collection_state.json" "$BACKUP_DIR/archive.list"
cat "$BACKUP_DIR/coverage.txt"
(cd "$BACKUP_DIR" && sha256sum run-before-fix.tar.gz source-before.txt worktree-before.txt archive.list coverage.txt > checksums.sha256)
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
echo "$BACKUP_DIR"
```

Chép backup ra host qua kênh riêng tư và kiểm `checksums.sha256` tại host. Đây là
backup forensic khi owner còn active; không chạy backup thường mục 15 lúc này.
Backup này chưa phải xác nhận run hợp lệ và
không bảo đảm có thể restore inode/prefix của archive live để tiếp tục finalize.

Kiểm `coverage.txt` và `archive.list`: `MISSING` ghi rõ bằng chứng không có sẵn,
không biến bản sao thành bằng chứng đầy đủ. Giữ riêng và báo Thịnh những mục thiếu;
không tự tạo lại clock, enrollment hay context. Archive chứa dữ liệu riêng tư; không
đưa lên GitHub. Các đuôi `.env`, `.pem`, `.key`, wheelhouse, wheel và bundle bị loại;
không đặt secrets/credentials khác trong các thư mục evidence được chọn. Kiểm
`archive.list` trước khi chuyển và dùng kênh riêng tư được bảo vệ.

Sau khi chép **cả** thư mục backup sang host Windows, mở PowerShell tại thư mục
bản sao đó (không phải thư mục trên SOC-AI), kiểm từng file theo checksum đã chép:

```powershell
$ErrorActionPreference = 'Stop'
foreach ($line in Get-Content -LiteralPath .\checksums.sha256) {
  if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Bad checksum line: $line" }
  $expected = $Matches[1]
  $path = Join-Path (Get-Location) $Matches[2]
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -ne $expected) {
    throw "Host checksum mismatch: $path"
  }
}
Write-Output 'HOST_FORENSIC_CHECKSUM=PASS'
```

Chỉ xác nhận host backup sau khi kiểm đạt và đã đọc danh sách `MISSING`. Checksum
chỉ xác minh bản sao, không chứng minh evidence ban đầu đầy đủ hoặc run hợp lệ.

## 3. Kiểm mã local và xử lý owner

Source và hướng dẫn pilot ở tag [pilot-v3.7-20261104](https://github.com/lethinhlord/Repo/tree/pilot-v3.7-20261104);
anchor mã đã kiểm là `402d40658be416d3d6a3112afe6d63bdeca7033c`. Tag pilot
không mở G7. Khi owner còn active, không fetch, checkout, cài/sửa venv hoặc nối
Internet. Không bootstrap lại, đổi snapshot hay ghi đè
`evidence/collection-source-commit.txt` cũ.

Chỉ thử finalize tối đa một lần khi mã đã sửa được cài trước khi cô lập, checkpoint
sealed và provenance còn nguyên. Kiểm local chỉ chấp nhận đúng anchor hoặc commit
của tag 3.7 đã có sẵn; với tag, kiểm tổ tiên và toàn bộ cây ngoài năm file tài liệu.
Nếu thiếu object hoặc tag local, không tải giữa run; đi nhánh quarantine bên dưới:

```bash
CODE_ANCHOR=402d40658be416d3d6a3112afe6d63bdeca7033c
RUN_DIR="evidence/scenario-runs/$RUN_ID"
retry_local_gate() {
  local head_sha clean
  test -d "$RUN_DIR" || return 1
  jq -e --arg id "$RUN_ID" 'type=="object" and .run_id==$id' \
    evidence/scenario-runs/.active-run.json >/dev/null || return 1
  jq -e '.status == "STARTED" and .execution_receipt.status == "COMPLETED"' \
    "$RUN_DIR/.collection_state.json" >/dev/null || return 1
  jq -e '.status == "sealed"' "$RUN_DIR/intake_checkpoint.json" >/dev/null || return 1
  head_sha=$(git rev-parse HEAD) || return 1
  git cat-file -e "$CODE_ANCHOR^{commit}" || return 1
  if [ "$head_sha" != "$CODE_ANCHOR" ]; then
    test "$(git cat-file -t refs/tags/pilot-v3.7-20261104)" = tag || return 1
    test "$head_sha" = "$(git rev-parse 'refs/tags/pilot-v3.7-20261104^{commit}')" || return 1
  fi
  git merge-base --is-ancestor "$CODE_ANCHOR" "$head_sha" || return 1
  git diff --exit-code "$CODE_ANCHOR" "$head_sha" -- . \
    ':(exclude)docs/scenario-collection-runbook.md' ':(exclude)docs/current-status.md' \
    ':(exclude)docs/pilot-r02-recovery.md' ':(exclude)docs/pilot-r03-runbook.md' \
    ':(exclude)docs/collection-integrity-validation-20261104.md' || return 1
  clean=$(git status --porcelain --untracked-files=all) || return 1
  test -z "$clean" || return 1
}
LOCAL_RETRY_OK=0
if retry_local_gate; then
  LOCAL_RETRY_OK=1
  mkdir -p operator-logs/r02-recovery
  git rev-parse HEAD > operator-logs/r02-recovery/source-retry.txt
  echo 'LOCAL_RETRY_OK=1: inspect provenance, then consider one retry in step 4'
else
  echo 'LOCAL_RETRY_OK=0: preserve backup, use quarantine branch below'
fi
```

Dùng cùng Bash session cho các block. Nếu trạng thái khác STARTED, dừng và xử lý
theo nhánh trạng thái ở Kiên.txt; không tự quarantine theo block này. Nếu kiểm
không đạt hoặc run không đủ điều kiện retry, không chạy finalize. Sau
forensic backup ở mục 2 và khi collector đã dừng, dùng CLI và venv cũ để quarantine
đúng run, rồi kiểm owner đã được giải phóng:

```bash
if [ "$LOCAL_RETRY_OK" != 1 ]; then
  if [ -e evidence/scenario-runs/.active-run.json ]; then
    jq -e --arg id "$RUN_ID" 'type=="object" and .run_id==$id' \
      evidence/scenario-runs/.active-run.json >/dev/null
  fi
  jq -e '.status == "STARTED"' "$RUN_DIR/.collection_state.json" >/dev/null
  read -rp 'Forensic backup copied to host and checksum verified there? Type YES: ' HOST_BACKUP_VERIFIED
  test "$HOST_BACKUP_VERIFIED" = YES
  .venv-ml/bin/python -m scripts.scenario_session quarantine \
    --run-id "$RUN_ID" --reason 'Failed R02; preserve evidence before maintenance'
  jq -e --arg id "$RUN_ID" '.status == "QUARANTINED" and .run_id == $id' \
    "evidence/quarantine/$RUN_ID/quarantine.json" >/dev/null
  test ! -e evidence/scenario-runs/.active-run.json
  LOCAL_RETRY_OK=0
else
  echo 'Local gate passed; skip quarantine and assess provenance in step 4'
fi
```

Nếu lệnh lỗi, owner không đúng hoặc khóa vẫn còn, dừng và giữ evidence; không xóa
khóa thủ công. Sau quarantine thành công, giữ forensic backup đã kiểm trên host.
Nếu checkout cũ đã có tag annotated được duyệt và receipt hợp lệ theo
[mục 15](https://github.com/lethinhlord/Repo/blob/pilot-v3.7-20261104/docs/scenario-collection-runbook.md#15-sao-lưu-và-bàn-giao-dữ-liệu-gốc),
làm backup/restore bình thường trước bảo trì. Với source cũ 35c, faac hoặc 9c thiếu
receipt tag được duyệt, forensic backup vẫn giữ nguyên nhưng chưa phải bản restore
được chứng nhận 3.7; không tự tạo receipt hay gán tag ngược cho source cũ.

Khi khóa đã được giải phóng, có thể dùng forensic backup đã kiểm để vào cửa sổ bảo
trì, nối mạng và cập nhật theo
[mục 6.3](https://github.com/lethinhlord/Repo/blob/pilot-v3.7-20261104/docs/scenario-collection-runbook.md#63-cập-nhật-source-qua-github-trong-cửa-sổ-bảo-trì).
Sau khi cài source 3.7 và có receipt hợp lệ, làm backup và kiểm restore mục 15;
sau đó cô lập lại, chạy preflight đầy đủ và thu pilot mới với ID/bucket mới.
Ghi SHA cũ từ forensic backup và SHA mới vào log riêng, không suy diễn immutable
state đã ghi SHA mã chạy. Dữ liệu/evidence được backup riêng tư ngoài GitHub.
Không dùng force, reset, clean hoặc ghi đè sửa đổi local.

## 4. Thử finalize một lần khi provenance còn nguyên

Chỉ làm bước này khi đã giữ đủ original evidence và mọi kiểm local ở mục 3 đạt. Không dựng checkpoint bằng tay.
Nếu trước đó không có checkpoint sealed hợp lệ trước cutoff, hoặc archive nguồn
đã rotate/truncate/thay đổi, code phải từ chối; không dùng export rời để thay nguồn.

```bash
test "${LOCAL_RETRY_OK:-0}" = 1
test -d "$RUN_DIR"
jq -e '.status == "STARTED" and .execution_receipt.status == "COMPLETED"' \
  "$RUN_DIR/.collection_state.json" >/dev/null
jq -e '.status == "sealed"' "$RUN_DIR/intake_checkpoint.json" >/dev/null
if ! (set -o noclobber; : > "operator-logs/r02-recovery/${RUN_DIR##*/}.retry-attempted") 2>/dev/null; then
  echo 'STOP: retry already attempted or marker cannot be created' >&2
  exit 1
fi
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
theo Kiên.txt mục 11 Bước 6 và mục 15/18. Nếu source chưa có receipt tag được duyệt,
giữ forensic backup và chỉ thực hiện backup/restore 3.7 sau khi run đã đóng, owner
được giải phóng và đã cập nhật trong cửa sổ bảo trì theo mục 6.3. Không chỉ gửi hai
file JSON kết quả.
R02 vẫn là `purpose: pilot`, không nhập vào quota train. G7 vẫn đóng cho tới nghiệm
thu đủ các điều kiện và phát hành baseline thu chính thức.
