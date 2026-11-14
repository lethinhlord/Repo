# Nâng cấp collector candidate.7 — 14/11/2026

Nguồn duy nhất: https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.7

Run001/002 của source6 đã VALID; giữ nguyên chúng. Run003 có đủ9fail/3success
nhưng chưa finalize. Sửa asset của PR21 giải quyết nhiễu sshd sensor. Bản này bổ
sung policy cache cho grouping, G7/source binding và test lifecycle thật.
Không đổi schema24, nhãn, cohort, lịch frozen, kiểm clock hay quality gate.

## 1. Quyết định dữ liệu và thư mục

Một dataset trainable hiện yêu cầu cùng candidate/runtime. Không ghép001/002
candidate.6 với run candidate.7 bằng sửa metadata hoặc tắt auditor. Để tiếp tục
ngay với gate hiện có, tạo checkout/dataset candidate.7 riêng, lập plan40/48 mới;
hai run tốt source6 và debug003 vẫn nằm nguyên trong checkout cũ để audit.
Đây không phải thu lại bốn pilot: chỉ sao chép bốn pilot đã đạt để G7 kiểm lại.
Tái sử dụng trainable qua nhiều candidate cần một cơ chế provenance được review
riêng; bản này không tự cấp quyền di trú dữ liệu đó.

Các khối Bash chạy trên SOC-AI bằng user đã thu data. Dùng cùng phiên shell:

```bash
set -euo pipefail
OLD_ROOT="$HOME/datn-ai-soar-v4"
NEW_ROOT="$HOME/datn-ai-soar-v4-candidate7"
TAG=collection-v4.0.0-candidate.7
test -x "$OLD_ROOT/.venv-ml/bin/python"
test ! -e "$NEW_ROOT"
test -z "$(git -C "$OLD_ROOT" status --porcelain --untracked-files=all)"
OLD_COMMIT=$(git -C "$OLD_ROOT" rev-parse HEAD)
case "$OLD_COMMIT" in
 42dab78e4ec1f6a093689e6e75f233c455c35159|d6e2c50bef359c5b69990117f3f93325a3a785a0) ;;
 *) printf 'Inspect unexpected old source commit: %s\n' "$OLD_COMMIT" >&2; exit 1 ;;
esac
```

Chấp nhận source6 nguyên bản hoặc commit PR21 đã review. Nếu source cũ dirty hoặc
là commit khác, giữ nguyên các file đó và đối chiếu trước;
không git reset/clean để làm mất bản Kiên đang kiểm tra. Không mở hai collector
song song cho cùng lab. Khối dưới chỉ kết thúc run003 nếu nó vẫn STARTED.

```bash
cd "$OLD_ROOT"
OLD_RUN=TRAINABLE-ACCOUNT-MALICIOUS-MULTIACCOUNT-GUESSING-20261114T061914Z-003
STATE="evidence/scenario-runs/$OLD_RUN/.collection_state.json"
test -f "$STATE"
STATUS=$(jq -r '.status' "$STATE")
if [ "$STATUS" = STARTED ]; then
 STAMP=$(date -u +%Y%m%dT%H%M%SZ)
 mkdir -p operator-logs/incident-preservation
 SAVE="operator-logs/incident-preservation/$OLD_RUN-before-candidate7-$STAMP.tar"
 test ! -e "$SAVE"
 tar -cf "$SAVE" "evidence/scenario-runs/$OLD_RUN"
 sha256sum "$SAVE" > "$SAVE.sha256"
 sha256sum -c "$SAVE.sha256"
 .venv-ml/bin/python -m scripts.scenario_session abort --run-id "$OLD_RUN" \
  --reason 'Preserved source6 parity failure; collection continues under a separate approved candidate'
elif [ "$STATUS" != ABORTED ] && [ "$STATUS" != FINALIZED ]; then
 printf 'Recover existing state before upgrading: %s\n' "$STATUS" >&2
 exit 1
fi
test ! -e evidence/scenario-runs/.active-run.json
```

Abort chính thức ghi state/log của run003 và giải phóng lock; bản tar giữ phiên
bản trước đó. Run001/002 không đổi. FINALIZED đã có thì giữ nguyên để audit, không
abort hoặc tự đổi purpose. Không xóa lock/Archives hay can thiệp thời gian bằng tay.

## 2. Lấy code từ GitHub, giữ đúng runtime đã nghiệm thu

```bash
git clone --branch "$TAG" --single-branch https://github.com/lethinhlord/Repo.git "$NEW_ROOT"
cd "$NEW_ROOT"
test "$(git cat-file -t "refs/tags/$TAG")" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")"
test ! -e .venv-ml
ln -s "$OLD_ROOT/.venv-ml" .venv-ml
unset PYTHONPATH PYTHONHOME
.venv-ml/bin/python -c 'from pathlib import Path; import ml.feature_pipeline as f; assert Path(f.__file__).resolve().is_relative_to(Path.cwd().resolve()); print(f.__file__)'
mkdir -p operator-logs/releases evidence/scenario-runs data/raw run-drafts
.venv-ml/bin/python -m scripts.collection_release candidate --tag "$TAG" --check-remote \
 > operator-logs/releases/candidate.json
printf '%s\n' "$TAG" > operator-logs/releases/source-tag.txt
git rev-parse HEAD > operator-logs/releases/source-commit.txt
cat operator-logs/releases/candidate.json
```

Symlink dùng nguyên Python/package của lab cũ, không di chuyển virtualenv hoặc
pip upgrade. Node cũng phải giữ nguyên. Candidate capture/G7 kiểm lại runtime.
Nếu venv cũ không đủ package, dừng đối chiếu inventory; không thay fingerprint.
Nguồn code được import từ checkout mới, không từ source6. Khi mở SSH mới, đặt
lại OLD_ROOT/NEW_ROOT/TAG và cd đúng NEW_ROOT trước khi chạy các bước sau.

## 3. Sao chép đúng bốn pilot; giữ trainable source6 riêng

```bash
cd "$NEW_ROOT"
PILOTS=(
 PILOT-ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS-20261111T102846Z-V4
 PILOT-ACCOUNT-MALICIOUS-REPEATED-FAILURES-6-20261111T101754Z-RETRY-V4
 PILOT-C2-BENIGN-DNS-20261111T094840Z-V4
 PILOT-C2-MALICIOUS-HTTP-BEACON-20261111T093029Z-R2
)
for RID in "${PILOTS[@]}"; do
 test -d "$OLD_ROOT/evidence/scenario-runs/$RID"
 test -d "$OLD_ROOT/data/raw/$RID"
 test ! -e "evidence/scenario-runs/$RID"
 test ! -e "data/raw/$RID"
 cp -a -- "$OLD_ROOT/evidence/scenario-runs/$RID" "evidence/scenario-runs/$RID"
 cp -a -- "$OLD_ROOT/data/raw/$RID" "data/raw/$RID"
 diff -qr -- "$OLD_ROOT/evidence/scenario-runs/$RID" "evidence/scenario-runs/$RID"
 diff -qr -- "$OLD_ROOT/data/raw/$RID" "data/raw/$RID"
 .venv-ml/bin/python -m scripts.verify_run_evidence --run-id "$RID"
done
.venv-ml/bin/python -m pytest -q tests/test_feature_grouping_upgrade.py \
 tests/test_real_soc_collector_regression.py tests/test_process_timing_regressions.py \
 tests/test_feature_state.py tests/test_feature_window_closure.py tests/test_pilot_adoption.py
```

Nếu đã chép một phần thì đối chiếu các thư mục có sẵn, không ghi đè để che lỗi.
Không copy toàn bộ data/raw hoặc toàn bộ scenario-runs: chúng chứa trainable6
và run đang lỗi. Không copy collection-acceptance.json của candidate.6 sang nguồn7.
Giữ nguyên backup và preflight gốc ở đường dẫn cũ; G7 sẽ đọc/restore kiểm chúng.

## 4. Enrollment active còn hạn và G7 mới

Baseline frozen trong handoff hết hạn16:45:28 ngày14/11/2026 giờ Việt Nam.
Các run trước hạn vẫn hợp lệ; không sửa snapshot của chúng. Làm enrollment mới
ở NEW_ROOT theo runbook10.5 (cùng4VM,3user,console/SMB/HTTP/DNS, capture có hash).
Đừng lấy log đã gán nhãn trong các run trainable để dựng lịch sử baseline.

Sau ENROLLMENT_REBUILD_AND_INVENTORY=PASS, làm đủ bước1–5 của
[G7 bốn pilot đã có](g7-existing-candidate4-pilots.md), ngay trong checkout7,
rồi quay lại bước5 dưới đây để tạo duy nhất một plan. Chưa làm bước6 của guide G7.
Guide này kiểm source active full-window, runtime, policy patch, backup restore,
raw preflight và4pilot. Chỉ chuyển bước5 khi authorize báo COLLECTION_AUTHORIZED.
Receipt mới ghi candidate.7 và pilot_candidate.4; receipt6 giữ nguyên ở OLD_ROOT.
Không phải chạy lại bốn pilot trên VM chỉ để đổi tag.

## 5. Actor và thu plan mới

So sánh SHA các runner Windows/Kali với file trong checkout7 theo runbook7/9.
Nội dung runner không đổi trong PR21; file nào đã khớp SHA thì không cần cài lại.
Nếu copy qua SSH, dùng đường dẫn SOC repo mới. Frozen export cho mỗi run phải
được tạo mới tại START và kiểm đúng transport hash; không dùng export của003.

```bash
cd "$NEW_ROOT"
PLAN="run-drafts/preferred-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan --kind preferred --output "$PLAN"
jq '.kind, (.runs|length)' "$PLAN"
sha256sum "$PLAN"
```

Preferred48run/12mỗi stratum; minimum40run/10mỗi stratum. Chọn một plan trước
khi thu, không đổi seed/cohort theo kết quả. Thực hiện đủ runbook11–14 trong
NEW_ROOT: đo clock mới, draft/START cùng source active, export, begin-action,
actor, complete-action, finalize --wait-for-window, validate, verify evidence,
audit và builder. Mỗi run phải đủ24 features, COMPLETE/AVAILABLE, review reasons
rỗng và hash/provenance hợp lệ. Pilot/challenge/ABORTED không tính quota.

Tách log native sensor không bỏ raw: archive_capture vẫn giữ SSH/journald,
nhưng chỉ nhóm đúng Windows được dùng cho Windows incident. Nếu còn parity lỗi,
giữ raw/state/receipt/checkpoint, dừng ở run đó; không xóa sự kiện để ép đạt.

## 6. Nếu lab đang dùng API/n8n

Collector offline lấy dữ liệu không đòi model đã train hay API/n8n đang chạy.
Nếu có API/n8n triển khai sẵn, nâng cấp image qua quy trình hiện có trước run mới;
giữ đúng Compose project và state volume cũ để bảo toàn incidents/feedback/nonce.
Xác định project của lab bằng `docker compose ls --all`, không đoán project name.
Chỉ thực hiện trong khoảng không có run đang thu.

Ví dụ cách kiểm config, sau khi đặt PROJECT bằng tên project thực của lab:

```bash
: "${PROJECT:?Chon dung Compose project cua lab tu docker compose ls --all}"
FEATURE_STATE_DB=/app/state/feature-state-sensor-asset-origin-v1.sqlite3 \
 CONTEXT_BASELINE_HOST_FILE="$NEW_ROOT/evidence/context-baseline.json" \
 docker compose -p "$PROJECT" --project-directory "$OLD_ROOT" \
 --env-file "$OLD_ROOT/.env" -f "$NEW_ROOT/compose.yaml" config --format json \
 | .venv-ml/bin/python -c 'import json,sys; d=json.load(sys.stdin); a=d["services"]["api"]; print(d["name"],a["environment"]["FEATURE_STATE_DB"],a["volumes"])'
```

Project-directory cũ giữ các bind mount model/registry tương đối. Đối chiếu các
mount trước recreate; dùng signed model/registry hiện có, không tạo registry rỗng.
Giữ các biến FEATURE_STATE_DB/CONTEXT_BASELINE_HOST_FILE này trong lệnh triển khai
thực của lab; config check riêng không thay đổi container đang chạy. Không in .env
hoặc xóa Docker volume. Nếu env override cố trỏ vào DB source6, code từ chối với
grouping policy error; chọn path mới thay vì sửa metadata của DB cũ.

Hai DB cũ native-lifecycle và DB mới sensor-asset-origin có thể cùng tồn tại trong
volume. Các decision cũ được giữ để audit, không bị đổi asset hoặc cấp revision mới.
Sau recreate kiểm /ready, webhook/auth và workflow như runbook; không tuyên bố
runtime đã nghiệm thu chỉ vì các test trên máy Thịnh đạt.

## 7. Minh chứng

Chụp toàn màn hình laptop có VMware/taskbar: source7 commit/tag, script SHA,
enrollment/G7 authorize, từng bước actor/collector và kết quả validate/audit.
Lưu ảnh theo timestamp/bước. Giữ ảnh và output công cụ thật, không crop hoặc dùng
script in PASS thay bằng chứng. Bản này không xác nhận các VM của Kiên đã nâng cấp.
