# Sysmon native chronology và chạy lại jitter HTTP — 13/11/2026

Nguồn vận hành mới: `collection-v4.0.0-candidate.6` trên GitHub. Không đổi tag
candidate.5, bốn pilot đã nghiệm thu hoặc dữ liệu đã đóng băng.

## 1. Kết quả đối chiếu gói retest

Run `PILOT-C2-MALICIOUS-JITTER-BEACON-20261113T114033Z-SYSMON-RETEST` có
261 bản ghi Archives, 8 curl ProcessGuid, 8 Event1, 8 Event3, 8 Event5 liên quan,
8 HTTP và 8 final flow. State vẫn STARTED, purpose là pilot, action COMPLETED.
Chưa có manifest/incident cuối cùng. Đây chưa phải run trainable hợp lệ.

Ví dụ GUID kết thúc `8702-000000002600`, PID7776, source port51464, UTC:

| Bản ghi | Native UtcTime | SystemTime |
|---|---|---|
| Event1 | 11:45:14.685 | 11:45:14.7052185 |
| Event5 | 11:45:18.732 | 11:45:18.7343032 |
| Event3 | 11:45:20.319 | 11:45:19.8647723 |

Tất cả 8 native Event3 đều sau native Event5 khoảng1.586–1.591s. EVE start
đúng tuple nhưng sau Windows exit khoảng9.613–15.966ms trên clock NET-SENSOR.
Clock preflight không chứng minh được thứ tự ở độ chính xác vài ms này.
Không thay timestamp bằng EVE, không thêm grace sau process exit để ép COMPLETE.

Replay cũ tái hiện: scenario-scoped đếm8, full-window đếm0 và trả PARTIAL.
`flow:missing_final_counters` ở đây là thiếu flow ĐÃ ĐƯỢC QUY THUỘC trong vector;
không có nghĩa raw không chứa8 final flow. Nút chặn chính là process proof.

## 2. Những gì bản mới thay đổi

- Event1/3/5 dùng cùng native UTC đã kiểm provider và độ lệch tối đa5s.
  Chấp nhận casing `utcTime`/`UtcTime`/`UTCTIME`; alias mâu thuẫn bị chặn.
  DNS22 và Security4624/4625 giữ cách tính thời gian hiện có.
- Vẫn kiểm GUID, agent, image, PID, user, thời điểm tạo/kết thúc. Native network
  sau native exit vẫn bị loại. Raw và SystemTime luôn được giữ nguyên.
- HTTP được gửi trước. Cùng curl sau đó thực hiện hai lần đọc win.ini cục bộ,
  rate1/2s; có ít nhất2s process còn sống sau khi HTTP hoàn thành, kể cả response
  chậm. Chỉ có1 HTTP request/action; lịch và nonce vẫn lấy từ frozen export.
  Sleep5s của PowerShell sau loop không được coi là thời gian sống của curl.
- Hold hữu hạn không bảo đảm mọi mức trễ Sysmon trong tương lai. Nếu native
  Event3 vẫn sau exit, tiếp tục REJECT/REVIEW và gửi evidence; không nới gate.
  Nhịp HTTP quá nhanh vẫn có thể missed schedule, không đổi gap hoặc bỏ profile.
- Cache SQLite cũ có timestamps/response theo policy cũ không được tái sử dụng.
  Database mới ghi policy `sysmon-native-lifecycle-v1`. DB features-v3 cũ được
  giữ nguyên; chỉ các legacy v1/v2 audit-only tiếp tục migration như trước.
  Compose mặc định chọn file mới trong cùng volume, không xóa volume hay DB cũ.

Tài liệu nền: [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[curl --rate và --next](https://curl.se/docs/manpage.html).
Phép thử localhost xác nhận lệnh curl thật; đó không thay thế retest Sysmon trên VM.

## 3. SOC-AI: giữ evidence và kết thúc run lỗi trước khi cập nhật

Chạy trên SOC-AI bằng user thu dữ liệu. Giữ phiên shell này.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
OLD_RUN=PILOT-C2-MALICIOUS-JITTER-BEACON-20261113T114033Z-SYSMON-RETEST
test -f "evidence/scenario-runs/$OLD_RUN/.collection_state.json"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p operator-logs/incident-preservation
ARCHIVE="operator-logs/incident-preservation/$OLD_RUN-before-abort-$STAMP.tar"
test ! -e "$ARCHIVE"
tar -cf "$ARCHIVE" "evidence/scenario-runs/$OLD_RUN"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
sha256sum -c "$ARCHIVE.sha256"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$OLD_RUN"
.venv-ml/bin/python -m scripts.scenario_session abort --run-id "$OLD_RUN" \
 --reason 'Native Sysmon Event3 occurs after native process exit; preserved for diagnosis'
test ! -e evidence/scenario-runs/.active-run.json
```

Lệnh abort chính thức ghi trạng thái ABORTED và log, không sửa raw hay tạo vector
train giả. Gói retest đã nhận có15 file gốc; bản tar trên lab giữ toàn bộ thư mục
run tại thời điểm sao lưu. Không xóa lock bằng tay;
nếu status là FINALIZING/FINALIZED, dừng và xử lý recovery/quarantine đúng runbook.

## 4. Cập nhật từ GitHub và kiểm phần mềm

```bash
test -z "$(git status --porcelain --untracked-files=all)"
git fetch origin tag collection-v4.0.0-candidate.6
git switch --detach collection-v4.0.0-candidate.6
test "$(git cat-file -t refs/tags/collection-v4.0.0-candidate.6)" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse collection-v4.0.0-candidate.6^{commit})"
mkdir -p operator-logs/releases
REF_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
VERIFIED_REF="operator-logs/releases/candidate-native6-$REF_STAMP.json"
test ! -e "$VERIFIED_REF"
.venv-ml/bin/python -m scripts.collection_release candidate \
 --tag collection-v4.0.0-candidate.6 --check-remote > "$VERIFIED_REF"
cat "$VERIFIED_REF"
for NAME in candidate.json source-tag.txt source-commit.txt; do
 REF="operator-logs/releases/$NAME"
 if [ -e "$REF" ]; then
  test -f "$REF"
  test ! -e "$REF.before-native6-$REF_STAMP"
  mv -- "$REF" "$REF.before-native6-$REF_STAMP"
 fi
done
cp -- "$VERIFIED_REF" operator-logs/releases/candidate.json
printf '%s\n' collection-v4.0.0-candidate.6 > operator-logs/releases/source-tag.txt
git rev-parse HEAD > operator-logs/releases/source-commit.txt
.venv-ml/bin/python -m pytest -q tests/test_process_timing_regressions.py \
 tests/test_process_lifetime.py tests/test_pilot4_native_network_time.py \
 tests/test_feature_state.py tests/test_feature_window_closure.py
sha256sum scripts/run_training_http.ps1 scripts/run_frozen_windows.ps1
```

Giữ Python/Node/package inventory đã thu pilot. Không pip upgrade để làm hash
runtime khớp bằng tay. Kiểm thử native PowerShell/curl trên Windows máy Thịnh
không chạy được trên Ubuntu; kiểm thử chronology ở trên vẫn phải đạt tại SOC.
Ba file reference trong releases được lưu bản cũ rồi cập nhật đúng checkout mới;
nếu giữ candidate.json cũ, bước10.2 sẽ dừng đúng do source/runtime không khớp.

Nếu đã chạy API container: dừng nhận alert ở ranh giới giữa các run, rebuild
image bằng quy trình triển khai hiện có rồi recreate API. Kiểm config trước:

```bash
docker compose config --format json | .venv-ml/bin/python -c \
 'import json,sys; print(json.load(sys.stdin)["services"]["api"]["environment"]["FEATURE_STATE_DB"])'
```

Mặc định mới là `/app/state/feature-state-native-lifecycle-v1.sqlite3`. Nếu có
`FEATURE_STATE_DB` override trong .env, đổi nó sang một file mới trong `/app/state`
bằng cấu hình triển khai của lab trước khi recreate. Không trỏ lại DB cũ, không
xóa WAL/SHM, không `docker compose down -v`. Các DB incident/feedback/nonce và
evaluation registry vẫn giữ nguyên. Collector offline không đòi model đã train;
không triển khai model giả để chạy retest này.

## 5. Windows11: cập nhật actor trước khi đo clock/start run mới

Dùng cùng bước copy+SHA của runbook mục7 (các script từ checkout GitHub vừa pin
trên SOC), bao gồm `run_training_http.ps1`, `run_frozen_windows.ps1`, runner
account/DNS và `Export-DatnSysmonClockEvidence.ps1`. Không dùng bản PS1 cũ trong
C:\DATN. SHA256 Windows phải đúng SHA file trong checkout candidate.6 của SOC;
nếu mismatch dừng, không chạy. Lưu actor cũ riêng để đối chiếu, không ghi đè raw.
Kiểm Windows PowerShell5.1 x64, Sysmon và Wazuh Agent đang chạy như runbook.

## 6. Chạy một retest jitter trên lab

Không cần dựng lại VM hay thu lại bốn pilot cũ. Cần retest đúng lỗi mới trên
Windows/Sysmon thật trước khi tiếp tục các run trainable HTTP bị ảnh hưởng.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
SCENARIO=C2-MALICIOUS-JITTER-BEACON
RUN_ID="PILOT-C2-JITTER-$(date -u +%Y%m%dT%H%M%SZ)-NATIVE6"
RUN_PURPOSE=pilot
COLLECTION_SEED=3636731640
```

Tiếp tục nguyên khối runbook11.2: đo clock mới trên4VM, tạo clock file riêng,
create_run_draft và START với source active. Clock phải còn hạn lúc START.
Không sao chép clock hay execution-parameters của run lỗi sang run mới.
Sau START: mục11.3 export frozen JSON và kiểm transport SHA; Windows dùng đúng
file export, chạy `run_frozen_windows.ps1` và chờ ACTION_READY. SOC begin-action
--wait-for-window, sau đó Enter trên Windows; giữ nguyên expected intervals.
Chỉ complete-action sau HTTP_ACTION_COMPLETE và8 HTTP_REQUEST_OK, không báo hoàn
thành ngay sau khi gửi request cuối. Sau đó:

```bash
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID" --wait-for-window
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.verify_run_evidence --run-id "$RUN_ID"
jq '{observation_quality,context_status,review_reasons,features}' "data/raw/$RUN_ID/incidents.jsonl"
```

Chỉ đạt khi finalize thành công, VALID, RUN_EVIDENCE_CHECK_PASS, context AVAILABLE,
observation_quality COMPLETE, review_reasons rỗng; full-window replay vẫn phải
đạt với toàn bộ raw bucket. Đếm8 HTTP riêng lẻ không thay thế các gate này.
Lưu Event1/3/5, flow.start/end và original UTC, không sửa dữ liệu để đạt điều kiện.
Nếu lỗi, giữ thư mục run cùng checkpoint/receipt/log, không chạy action lần hai
trong cùng run; dùng backup/abort chính thức trước một run ID mới.

## 7. G7 và quay lại plan trainable

Receipt candidate.5 vẫn là hồ sơ lịch sử, không phải authorization candidate.6.
Sau retest đạt, lưu receipt cũ sang đường dẫn lưu trữ riêng bằng lệnh move/copy
có kiểm tồn tại (không overwrite), rồi làm [G7 bốn pilot đã có](g7-existing-candidate4-pilots.md).
Tạo G7 v2 mới bằng bốn pilot candidate.4 gốc, source active, baseline còn hạn,
preflight và backup/restore đã gắn đúng pilot. Không thay backup cũ bằng backup
candidate.6 rồi ghi nhận sai nguồn. Policy mới kiểm toàn bộ patch đã review.

Chỉ resume plan trainable khi retest lỗi mới đạt và authorize trả
COLLECTION_AUTHORIZED trên candidate.6. Mỗi run trainable mới dùng run ID/seed
theo plan; không đổi purpose của pilot, không đưa pilot vào quota40/48.
Chụp toàn màn hình laptop có VMware/taskbar cho checkout, script SHA, native
Event1/3/5, actor receipts, finalize/validate, G7 authorize. Không crop hoặc dùng
output giả thay log công cụ. Thực hiện đủ audit/build/Colab như runbook11–14.
