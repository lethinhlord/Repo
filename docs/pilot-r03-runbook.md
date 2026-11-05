# Kiên — kiểm thử bản sửa intake và chạy pilot mới sau R03

Ngày 05/11/2026. Hướng dẫn và source pilot có trên GitHub tại tag
[`pilot-v3.8-20261105`](https://github.com/lethinhlord/Repo/tree/pilot-v3.8-20261105).
Anchor mã đã kiểm là `0d6e44ffdf4936182a4ee337db78f29116469b94`.
Tag pilot không mở G7; dữ liệu và evidence lưu riêng tư ngoài GitHub.

## 1. Phạm vi bản sửa

Đã tái hiện hai lỗi bằng dữ liệu tổng hợp: đoạn đọc 1 MiB bị cắt giữa JSON khi nguồn
đã có dòng hoàn chỉnh; late tail đã lưu còn thiếu phần cuối bị parse trước khi đọc
lại nguồn. Bản sửa quan sát phần late tới EOF snapshot hữu hạn và giữ toàn bộ prefix
đã lưu. Quan sát thêm không làm bất kỳ byte late nào thành byte nhận đúng hạn.
Record thuộc bucket cũ đến muộn, record của agent cấu hình thiếu thời gian nguồn,
JSON malformed/chưa xong, nguồn rotate/truncate hoặc prefix thay đổi vẫn bị từ chối.

Chưa có bộ evidence đầy đủ của run lỗi intake R03 được báo ngày03/11 trong các
nguồn đã kiểm trên máy Thịnh. Run đó khác HTTP-C2 R03 trong gói04/11; không dùng
kết quả của HTTP-C2 để kết luận run lỗi intake cũ đã được cứu. Checkpoint `capturing` cũ thiếu bằng chứng đọc
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
for item in "run-drafts/$R03_ID.yaml" "run-drafts/$R03_ID-clock.yaml" \
  "run-drafts/$R03_ID-clock-measurements.json"; do
  if [ -f "$item" ]; then
    printf 'PRESENT %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  else
    printf 'MISSING %s\n' "$item" >> "$BACKUP_DIR/coverage.txt"
  fi
done
git rev-parse HEAD > "$BACKUP_DIR/source-before.txt"
git status --short > "$BACKUP_DIR/worktree-before.txt"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$R03_ID" \
  > "$BACKUP_DIR/run-status.json"
tar -czf "$BACKUP_DIR/evidence-before-fix.tar.gz" \
  --exclude='*.env' --exclude='*.pem' --exclude='*.key' \
  --exclude='*wheelhouse*' --exclude='*.whl' --exclude='*.bundle' \
  -- "${items[@]}"
tar -tzf "$BACKUP_DIR/evidence-before-fix.tar.gz" > "$BACKUP_DIR/archive.list"
grep -Fq "evidence/scenario-runs/$R03_ID/.collection_state.json" "$BACKUP_DIR/archive.list"
cat "$BACKUP_DIR/coverage.txt"
(cd "$BACKUP_DIR" && sha256sum evidence-before-fix.tar.gz source-before.txt worktree-before.txt run-status.json archive.list coverage.txt > checksums.sha256)
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
cat "$BACKUP_DIR/run-status.json"
echo "$BACKUP_DIR"
```

Chép cả thư mục backup sang host qua kênh riêng tư và kiểm `checksums.sha256` tại
host. Đây là backup forensic khi owner còn active; không chạy backup thường mục 15
lúc này. Gói này giữ file ẩn, capture, late tail, checkpoint,
snapshots, reservations và output tạm. Không bỏ riêng late tail vì nó báo lỗi.
Không gửi `.env`, private key hoặc Wazuh credentials.

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

Source và hướng dẫn pilot ở tag [pilot-v3.8-20261105](https://github.com/lethinhlord/Repo/tree/pilot-v3.8-20261105);
anchor mã đã kiểm là `0d6e44ffdf4936182a4ee337db78f29116469b94`. Tag pilot
không mở G7. Khi owner còn active, không fetch, checkout, cài/sửa venv hoặc nối
Internet. Không bootstrap lại, đổi snapshot hay ghi đè
`evidence/collection-source-commit.txt` cũ.

Chỉ thử finalize tối đa một lần khi mã đã sửa được cài trước khi cô lập, checkpoint
sealed và provenance còn nguyên. Kiểm local chỉ chấp nhận đúng anchor hoặc commit
của tag 3.8 đã có sẵn; với tag, kiểm tổ tiên và toàn bộ cây ngoài tám file tài liệu.
Nếu thiếu object hoặc tag local, không tải giữa run; đi nhánh quarantine bên dưới:

```bash
CODE_ANCHOR=0d6e44ffdf4936182a4ee337db78f29116469b94
RUN_DIR="evidence/scenario-runs/$R03_ID"
retry_local_gate() {
  local head_sha clean
  test -d "$RUN_DIR" || return 1
  jq -e --arg id "$R03_ID" 'type=="object" and .run_id==$id' \
    evidence/scenario-runs/.active-run.json >/dev/null || return 1
  jq -e '.status == "STARTED" and .execution_receipt.status == "COMPLETED"' \
    "$RUN_DIR/.collection_state.json" >/dev/null || return 1
  jq -e '.status == "sealed"' "$RUN_DIR/intake_checkpoint.json" >/dev/null || return 1
  head_sha=$(git rev-parse HEAD) || return 1
  git cat-file -e "$CODE_ANCHOR^{commit}" || return 1
  if [ "$head_sha" != "$CODE_ANCHOR" ]; then
    test "$(git cat-file -t refs/tags/pilot-v3.8-20261105)" = tag || return 1
    test "$head_sha" = "$(git rev-parse 'refs/tags/pilot-v3.8-20261105^{commit}')" || return 1
  fi
  git merge-base --is-ancestor "$CODE_ANCHOR" "$head_sha" || return 1
  git diff --exit-code "$CODE_ANCHOR" "$head_sha" -- . \
    ':(exclude)docs/scenario-collection-runbook.md' ':(exclude)docs/current-status.md' \
    ':(exclude)docs/pilot-r02-recovery.md' ':(exclude)docs/pilot-r03-runbook.md' \
    ':(exclude)docs/week3-model-training-runbook.md' ':(exclude)README.md' \
  ':(exclude)docs/dataset-handoff-20261105.md' \
  ':(exclude)docs/audit-v38-validation-20261105.md' || return 1
  clean=$(git status --porcelain --untracked-files=all) || return 1
  test -z "$clean" || return 1
}
LOCAL_RETRY_OK=0
if retry_local_gate; then
  LOCAL_RETRY_OK=1
  mkdir -p operator-logs/r03-recovery
  git rev-parse HEAD > operator-logs/r03-recovery/source-retry.txt
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
    jq -e --arg id "$R03_ID" 'type=="object" and .run_id==$id' \
      evidence/scenario-runs/.active-run.json >/dev/null
  fi
  jq -e '.status == "STARTED"' "$RUN_DIR/.collection_state.json" >/dev/null
  read -rp 'Forensic backup copied to host and checksum verified there? Type YES: ' HOST_BACKUP_VERIFIED
  test "$HOST_BACKUP_VERIFIED" = YES
  .venv-ml/bin/python -m scripts.scenario_session quarantine \
    --run-id "$R03_ID" --reason 'Failed R03; preserve evidence before maintenance'
  jq -e --arg id "$R03_ID" '.status == "QUARANTINED" and .run_id == $id' \
    "evidence/quarantine/$R03_ID/quarantine.json" >/dev/null
  test ! -e evidence/scenario-runs/.active-run.json
  LOCAL_RETRY_OK=0
else
  echo 'Local gate passed; skip quarantine and assess provenance in step 4'
fi
```

Nếu lệnh lỗi, owner không đúng hoặc khóa vẫn còn, dừng và giữ evidence; không xóa
khóa thủ công. Sau quarantine thành công, giữ forensic backup đã kiểm trên host.
Nếu checkout cũ đã có tag annotated được duyệt và receipt hợp lệ theo
[mục 15](https://github.com/lethinhlord/Repo/blob/pilot-v3.8-20261105/docs/scenario-collection-runbook.md#15-sao-lưu-và-bàn-giao-dữ-liệu-gốc),
làm backup/restore bình thường trước bảo trì. Với source cũ 35c, faac hoặc 9c thiếu
receipt tag được duyệt, forensic backup vẫn giữ nguyên nhưng chưa phải bản restore
được chứng nhận 3.8; không tự tạo receipt hay gán tag ngược cho source cũ.

Khi khóa đã được giải phóng, có thể dùng forensic backup đã kiểm để vào cửa sổ bảo
trì, nối mạng và cập nhật theo
[mục 6.3](https://github.com/lethinhlord/Repo/blob/pilot-v3.8-20261105/docs/scenario-collection-runbook.md#63-cập-nhật-source-qua-github-trong-cửa-sổ-bảo-trì).
Sau khi cài source 3.8 và có receipt hợp lệ, làm backup và kiểm restore mục 15;
sau đó cô lập lại, chạy preflight đầy đủ và thu pilot mới với ID/bucket mới.
Ghi SHA cũ từ forensic backup và SHA mới vào log riêng, không suy diễn immutable
state đã ghi SHA mã chạy. Dữ liệu/evidence được backup riêng tư ngoài GitHub.
Không dùng force, reset, clean hoặc ghi đè sửa đổi local.

## 4. Quyết định xử lý run cũ

Đọc `intake_checkpoint.json` từ bản backup và đối chiếu file thật. Không chỉnh nó.

- Checkpoint còn `capturing`, mất checkpoint hoặc không có seal hợp lệ: không retry
  bằng cách xóa marker. Sau backup, dùng lệnh quarantine ở mục 3 để
  giữ run lỗi và giải phóng owner đúng cách; bắt đầu pilot mới với ID và bucket mới.
- Checkpoint đã `sealed`: chỉ được thử finalize lại tối đa một lần trên cùng checkout nếu kiểm local ở mục 3 đạt và source
  gốc/device/inode/hash/prefix/tail/snapshots còn hợp lệ. Mã mới có thể hoàn tất quan
  sát một late record không liên quan đã được nguồn ghi đầy đủ. Nó vẫn phải từ chối
  late record thuộc bucket cũ hoặc chưa xác định được tính liên quan.
- State đã FINALIZING/FINALIZED/ABORTED/QUARANTINED: làm đúng nhánh trạng thái ở
  Kiên.txt; không đặt nó ngược về STARTED.

Riêng nhánh đã sealed còn nguyên provenance, lệnh thử một lần:

```bash
test "${LOCAL_RETRY_OK:-0}" = 1
test -d "$RUN_DIR"
jq -e '.status == "STARTED" and .execution_receipt.status == "COMPLETED"' \
  "$RUN_DIR/.collection_state.json" >/dev/null
jq -e '.status == "sealed"' "$RUN_DIR/intake_checkpoint.json" >/dev/null
if ! (set -o noclobber; : > "operator-logs/r03-recovery/${RUN_DIR##*/}.retry-attempted") 2>/dev/null; then
  echo 'STOP: retry already attempted or marker cannot be created' >&2
  exit 1
fi
set +e
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$R03_ID" \
  > operator-logs/r03-recovery/finalize.json 2> operator-logs/r03-recovery/finalize.stderr.txt
FINALIZE_RC=$?
set -e
cat operator-logs/r03-recovery/finalize.json
test "$FINALIZE_RC" -eq 0
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$R03_ID" \
  > operator-logs/r03-recovery/validate.json
cat operator-logs/r03-recovery/validate.json
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

Gửi backup bước 2, source-before/source-retry hoặc source mới sau bảo trì, log kiểm
tra nếu có, JSON/stderr finalize/
validate, **toàn bộ** evidence/scenario-runs hoặc evidence/quarantine của run,
reservations, data/raw hoặc data/quarantine tương ứng qua kênh riêng tư; gửi thêm
tag GitHub, SHA đầy đủ đã phân giải và checksum backup. Chạy backup/restore kiểm
chứng theo Kiên.txt mục 15 sau pilot đạt; nếu source chưa có receipt tag được duyệt,
đóng run và giải phóng owner rồi cập nhật trong cửa sổ bảo trì theo mục 6.3 trước
khi thực hiện backup/restore 3.8.
Nếu bản Archives gốc vẫn còn, giữ nguyên trên SOC và gửi thêm snapshot chẩn đoán
qua quy trình backup của lab; không chỉ gửi các dòng trùng ID hay một late fragment.
Snapshot làm sau cutoff không thay thế được read-completion evidence trước cutoff.

Phải có FINALIZED, VALID và RUN_EVIDENCE_CHECK_PASS/context/quality như Kiên.txt
mục 11 Bước 6 trước nghiệm thu. Pilot không nhập vào quota train; G7 vẫn đóng.
