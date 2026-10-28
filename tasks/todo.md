# Checklist triển khai và nghiệm thu

Baseline: `ee7f4f6a56c355ff855802671db4d9aabc5412fe`.
Đang triển khai trên nhánh `fix/handoff-context-v3`. Checkbox chỉ đánh dấu phần đã đủ bằng chứng; nghiệm thu bốn VM và dữ liệu thật còn tách riêng.
Kế hoạch chi tiết và giới hạn: `plan.md` trong cùng thư mục này.
Tên test/module mới là đề xuất; lệnh kiểm chỉ chạy sau khi chúng được triển khai.
Nếu một task thực tế cần sửa quá năm file hoặc có hai subsystem độc lập, tách task
thêm trước khi thực hiện; không gom thay đổi lớn để né checkpoint.

## Chặng A — Đóng lỗi thu thập có thể tái hiện

- [x] **P01 — Đưa năm probe audit thành test hồi quy chính thức.**
  - Đạt khi: test H01/H02/H05/H06 fail trên baseline vì đúng sai lệch đã ghi; fixture
    byte là EVE thật từ PCAP với nguồn rõ ràng; không dùng helper bị giảm gate để
    tuyên bố đã nghiệm thu một run catalog đầy đủ.
  - Kiểm: chạy test mới, lưu JUnit RED; giữ các assertion bất biến khi sửa.
  - Phụ thuộc: không. File dự kiến: test hồi quy mới và fixture EVE/PCAP liên quan (≤5).

- [x] **P02 — H05: normalize IP khi tạo observation.**
  - Đạt khi: parity IPv4/mapped IPv6/IPv6 tương đương; raw giữ nguyên; dữ liệu IP sai
    được xử lý nhất quán và không gây đếm đích giả.
  - Kiểm: test feature pipeline/scenario collection và ca mixed-IP RED chuyển GREEN.
  - Phụ thuộc: P01. File: `ml/scenario_collection.py`, `ml/telemetry.py`, hai test tương ứng.

- [ ] **P03 — H01: reservation bucket có tính bền vững.**
  - Đạt khi: không có hai run dùng cùng cửa sổ được bảo vệ; restart/race không bypass;
    abort/quarantine vẫn giữ bucket đã phát sinh hành động bị sử dụng.
  - Kiểm: run ngắn cách 175 giây, process tranh chấp và first-run sau canary.
  - Phụ thuộc: P01. File: collector, module reservation mới, test collection windows,
    test restart/race mới (≤4).

- [x] **P04 — H02: validator portable giữ nguyên origin và checksum.**
  - Đạt khi: restore khác root/home thành công; đổi raw/snapshot bị chặn; không cần
    original Archives còn tồn tại để xác minh offline.
  - Kiểm: restore probe GREEN và test đường dẫn không an toàn/contract sai revision.
  - Phụ thuộc: P01. File: collector, test restore mới, fixture contract (≤3).

- [x] **P05 — H06: dùng chung correlation và hợp nhất flow counter.**
  - Đạt khi: HTTP 654/DNS 202 đúng; dedup theo flow và chống ID tái dùng; DNS response
    và final flow được liên kết khi flow record không chứa dns rrname.
  - Kiểm: PCAP/EVE thật, duplicate, đảo thứ tự, restart và counter bất nhất.
  - Phụ thuộc: P01/P02. File: `ml/telemetry.py`, `ml/behavior_features.py`,
    `ml/scenario_collection.py`, `ml/feature_pipeline.py`, test flow mới (5).

- [ ] **P06 — H01/H06: raw capture, thời gian flow và record đến muộn.**
  - Đạt khi: nguyên liệu trước lọc đủ replay; record đến muộn sửa đúng window gốc;
    flow kéo qua bucket có quy tắc đúng hoặc báo thiếu thông tin.
  - Kiểm: replay full capture offline/online với background, late final-flow, hết grace
    và receipt ngoài deadline; trước đủ dữ liệu phải PARTIAL/REVIEW.
  - Phụ thuộc: P03/P05. File: collector, feature state, feature pipeline và test parity
    cùng test late arrival (5).

- [ ] **Checkpoint A.**
  - [ ] Năm probe cũ GREEN; không giảm assertion hay dùng feature từ nhãn.
  - [ ] Raw replay, timing/late-flow và restore đạt; chất lượng telemetry được mô tả rõ.
  - [ ] Nếu chưa đo đúng byte từng window, đã chốt loại feature khỏi schema mới thay
    vì giả zero hoặc giữ tên gọi tổng byte không đúng nghĩa.

## Chặng B — Quy trình Windows và audit chạy được

- [ ] **P07 — H03: canary console/SMB và quyền user.**
  - Đạt khi: sign-out/new password logon đúng type 2; SMB type 3 đúng source/user;
    quyền logon, lockout, cursor và record mới được kiểm.
  - Kiểm: parse 5.1 cộng thao tác thật Windows 11, đối chiếu Event Viewer với Archives.
  - Phụ thuộc: P03. File: script preflight Windows mới, runbook, test script/guide (≤3).

- [ ] **P08 — H04: preflight firewall không báo nhầm.**
  - Đạt khi: xét TCP445/Any/range/application/service/profile/interface; UDP/41 không
    false-positive; mạng cho phép và không cho phép có kết quả thực tế đúng.
  - Kiểm: mock rule chỉ kiểm logic, sau đó phép thử TCP trên các VM thật.
  - Phụ thuộc: không. File: preflight Windows, runbook, test firewall mới (≤3).

- [x] **P09 — H07: audit progress/final và verify script.**
  - Đạt khi: thiếu quota hợp lệ → COLLECTING cho phép thu tiếp; run hỏng luôn chặn;
    final chưa đạt quota/coverage/quality không cho build.
  - Kiểm: Bash set-e sau một run VALID, checksum sai và final trên tập thiếu mẫu.
  - Phụ thuộc: P03/P04. File: `ml/dataset_audit.py`, `scripts/audit_dataset.py`,
    `scripts/verify_collection_dataset.sh`, `tests/test_dataset_audit.py`, runbook (5).

- [ ] **Checkpoint B.**
  - [ ] H01–H07 có bằng chứng hồi quy, không chỉ schema/cú pháp hợp lệ.
  - [ ] Hướng dẫn có nhánh xử lý lỗi/tiếp tục cụ thể; quyền user và firewall không bỏ ngỏ.
  - [ ] Chưa chốt baseline thu train nếu feature/context revision còn thay đổi.

## Chặng C — Feature/context và kịch bản đối chứng

- [x] **P10 — Baseline/context độc lập và hợp đồng as-of.**
  - Đạt khi: nguồn/revision/hash/TTL được ghi; dữ liệu trước sự kiện; chưa biết giữ là
    UNKNOWN, không suy từ label hoặc dữ liệu tương lai.
  - Kiểm: missing/stale/context đổi, chưa enroll user/host, context chỉnh sửa và cutoff.
  - Phụ thuộc: P04/P06. File: module context mới, config context, công cụ enrollment
    mới, test context mới (≤4).

- [ ] **P11 — Feature revision mới cùng mask/quality.**
  - Đạt khi: từng feature có nguồn/đơn vị/window/validity; cùng raw+context cho vector
    và quality giống nhau; chuỗi lab không làm chứng cứ độc lập của intent.
  - Kiểm: feature contract/parity, dấu vết tên file/domain/nonce, missing ≠ zero.
  - Phụ thuộc: P02/P05/P06/P10. File: schema, behavior_features, feature_pipeline,
    scenario_collection và test feature mới (5).

- [ ] **P12 — G01–G04: account catalog và đối chứng.**
  - Đạt khi: có benign remote, benign fail-only, valid-credential simulation và tác vụ
    đa tài khoản hợp lệ; pool user/nhịp/source được cân bằng, có truth tách riêng.
  - Kiểm: draft/catalog/runner kiểm số lượng và nguồn thật; counterfactual intent/context.
  - Phụ thuộc: P07/P10/P11. File: scenario catalog, collector parameter contract,
    export parameters và hai test catalog/acceptance (5).

- [ ] **P13 — G05–G07: C2 catalog và đối chứng.**
  - Đạt khi: health/beacon có nhịp chồng lấp; DNS count/shape đa dạng cả hai nhãn;
    download/retry hai nhãn không mang fingerprint filename/port/payload riêng.
  - Kiểm: HTTP/DNS child process, nonce/GUID, SID quan sát và counterfactual bỏ chuỗi lab.
  - Phụ thuộc: P05/P10/P11. File: catalog, taxonomy, parameter contract, DNS runner,
    test C2 catalog/acceptance (5); tách runner/test thêm nếu cần quá phạm vi này.

- [ ] **P14 — API và policy REVIEW theo observability/context.**
  - Đạt khi: thiếu/stale context, ambiguous/unsupported profile, sai schema không bị
    probability cao ghi đè; model/policy decision được phân biệt; SHADOW giữ nguyên.
  - Kiểm: request thiếu context, schema cũ, high-confidence thiếu chứng cứ và trace reasons.
  - Phụ thuộc: P10/P11. File: API contracts, risk policy, main, test API/risk policy (5).

- [ ] **P15 — Xuất schema và n8n consume đúng contract.**
  - Đạt khi: schema xuất đúng source, workflow truyền quality/context revision đầy đủ;
    replay/late revision không gửi thông báo sai hay tính feedback trùng.
  - Kiểm: schema export không làm dirty checkout và n8n/API/receiver thực trong môi trường tạm.
  - Phụ thuộc: P14/P06. File: exporter/schema pipeline, workflow, test replay, test
    notification, test schema artifacts (≤5 nhóm file; tách generated artifacts thành task riêng).

- [ ] **Checkpoint C.**
  - [ ] Đo được context/feature mới bằng telemetry thật, không lấy từ manifest nhãn.
  - [ ] Cặp thiếu khả năng phân biệt được xử lý REVIEW theo input thực tế.
  - [ ] Schema/context/taxonomy/catalog đã freeze trước thu chính thức.

## Chặng D — Dataset, training và đánh giá trung thực

- [ ] **P16 — Purpose/cohort và split không rò rỉ.**
  - Đạt khi: enrollment/pilot/trainable/challenge tách từ trước run; cohort gần nhau
    cùng partition, kể cả cohort có cả hai nhãn; manifest kiểm hash/count đúng.
  - Kiểm: builder không đưa challenge vào train; không đổi purpose sau khi xem prediction;
    cohort mixed-label không bị tách và locked test vẫn UNOPENED.
  - Phụ thuộc: P11/P12/P13. File: dataset, builder, training config, test dataset,
    test training integrity (5).

- [ ] **P17 — Auditor collision, shortcut và challenge.**
  - Đạt khi: collision trainable vẫn chặn; challenge thống kê riêng; feature separation
    cần chứng minh nguồn/counterfactual/holdout, không có bypass để làm READY.
  - Kiểm: label-derived proxy, fingerprint, legitimate separator, conflicting truth,
    nhóm thiếu coverage và ngoại lệ có ADR.
  - Phụ thuộc: P09/P16. File: dataset auditor, audit CLI, test auditor, ADR/spec (≤4).

- [ ] **P18 — Trainer và metric theo group/REVIEW.**
  - Đạt khi: fit chỉ trên train; validation chọn threshold/calibration; CI đủ group;
    báo coverage/REVIEW và metric từng family/scenario, không che mẫu khó.
  - Kiểm: group leakage, CI thiếu mẫu, review-all, calibration và threshold hiện hành.
  - Phụ thuộc: P16/P17. File: training, metrics, config, test metrics,
    test training integrity (5).

- [ ] **P19 — Package/runtime/Colab cùng feature revision.**
  - Đạt khi: v2/new schema không trộn; package ký/hash và context revision kiểm trước
    predict; Colab nhận train/validation+manifest, không mở locked test.
  - Kiểm: package mismatch, raw/context provenance sai, notebook stage và xuất artifact.
  - Phụ thuộc: P11/P14/P18. File: models/package loader, freeze_model, notebook,
    test package, test notebook (5); tách thêm nếu đường package ở nhiều module.

- [ ] **Checkpoint D.**
  - [ ] Full suite + targeted regressions + Ruff + dependency/schema checks đạt.
  - [ ] Metric/CI/challenge/coverage không dựa vào dataset cũ hay fixture để tuyên bố model tốt.
  - [ ] Chưa mở locked test hoặc bật strong action trong lúc tối ưu.

## Chặng E — Nghiệm thu và bàn giao

- [ ] **P20 — Viết lại hướng dẫn chạy được và đồng bộ baseline.**
  - Đạt khi: lệnh đúng tool đã triển khai, pre/post/failure cho từng bước; cùng hash
    Kiên.txt/runbook; ghi SHA sau merge đã qua kiểm.
  - Kiểm: parse PowerShell/Bash rồi đọc đối chiếu từng bước với CLI, source và đầu ra.
  - Phụ thuộc: P09/P12/P13/P17/P19. File: runbook, verify script, guide tests,
    bản Kiên.txt ngoài repo, baseline file (≤5).

- [ ] **P21 — Pilot thật bốn VM và drill bàn giao.**
  - Đạt khi: console/SMB/HTTP/DNS benign+malicious đều qua collector; parity, thiếu
    context/late-flow/REVIEW đúng; backup chép host rồi restore khác root VALID.
  - Kiểm: native service/log/GUI và ảnh nguyên màn hình host có VMware; không lấy output
    mô phỏng làm chứng cứ triển khai. Lưu biên bản theo SHA thực tế.
  - Phụ thuộc: mọi checkpoint trước. File: biên bản nghiệm thu, manifest evidence,
    ảnh/screenshots và báo cáo kết quả; không sửa feature để hợp thức hóa pilot.

- [ ] **P22 — Thu mới và chốt đủ điều kiện Colab.**
  - Đạt khi: dữ liệu mới đúng quota/group hiện hành, challenge riêng, final audit
    READY/TARGET_MET và manifest/hash/split hợp lệ.
  - Kiểm: source commit/config đúng bản bàn giao, validate từng run, final audit,
    build dataset và kiểm chỉ đúng gói train/validation/manifest đưa sang Colab.
  - Phụ thuộc: P21. File: dataset/evidence sinh thật và biên bản thu; không nhập data cũ.

- [ ] **Checkpoint bàn giao.**
  - [ ] Không còn P1/P2 H01–H07 chưa đóng bằng chứng.
  - [ ] G01–G07 có đối chứng và giới hạn REVIEW rõ; chưa có chứng cứ thì chưa tuyên bố phân biệt được.
  - [ ] Bản source, guide, toolchain, catalog/context spec và evidence dùng cùng revision.
  - [ ] Kiên có thể bắt đầu từ VM sạch, thu/validate, xử lý lỗi, backup/restore và xuất
    gói Colab theo hướng dẫn mà không đoán lệnh hoặc sửa hash bằng tay.

## Nhật ký 28/10 — checkpoint nền thu

- Hồi quy toàn repo: 347 test đạt; JUnit ngoài repo `outputs/handoff-implementation-20261028/foundation-full-suite.xml`.
- P01/P02/P04/P09 đã có bằng chứng hồi quy. P03/P05/P07/P08 đã sửa phần cốt lõi và có test, tiếp tục kiểm các điều kiện còn lại; P06 chưa đóng.
- Context primitive/enrollment đã tích hợp vào feature/API/runtime; không lấy baseline từ dataset cũ.
- Bốn địa chỉ SSH đã biết không phản hồi; không có nghiệm thu VM thật ở checkpoint này.

## Nhật ký 28/10 — context, raw replay và cohort

- Snapshot tích hợp đã qua 426 test toàn repo, không lỗi/skip; JUnit `context-parity-cohort-full.xml`.
- Đóng window được triển khai tiếp sau snapshot đó: năm test closure/late flow/API đạt
  (`window-close-late-flow.xml`); trạng thái cuối qua **431/431 test**, 0 lỗi/skip, Ruff
  và `git diff --check` đạt. JUnit `checkpoint-v3-final-full.xml`, SHA-256
  `1e86cadf3940541f82328f1cfaa29cbf7a1d0c802e554cd3131c0d92f107a5d4`.
- P05 có test EVE audit HTTP=654/DNS=202; 13 test quality/counter bổ sung kiểm duplicate,
  thứ tự, reused ID, counter reset, cross-window, malformed flow và late original time.
- P10 có baseline/capture hash bất biến, cutoff/TTL, UNKNOWN mask, context update và
  race nguồn thay đổi trong enrollment. Thiếu context không thể vượt gate bằng probability cao.
- Full-capture parity đã chặn nhiễu nền không có nonce; source production bắt buộc
  bucket sạch, closed bucket + 60s grace và final flow. Finalize hỗ trợ `--wait-for-window`.
- Ingest online luôn tạm thời/REVIEW. API finalize-window tạo/cache kết quả cuối sau
  watermark; late input gây conflict. Workflow n8n chưa nối bước close: P15 còn mở.
- Purpose/cohort đóng băng trong catalog/draft/parameters; auditor kiểm, discovery lọc,
  challenge xuất riêng; mixed-label cohort split và inner-CV/leakage gate có test.
  P16 chưa đóng vì catalog/cohort production, manifest/Colab và challenge thực còn phải đồng bộ.
- Auditor bổ sung gate bucket trùng và context COMPLETE cho trainable production.
- P03/P06 có phần mềm và hồi quy mới nhưng tiếp tục kiểm đủ điều kiện trong checklist.
- Catalog/taxonomy G01–G07, Windows hiệu lực mạng, runtime context mount, n8n E2E,
  metric REVIEW/challenge, Colab và bản Kiên.txt chưa hoàn tất. Không ghi chúng là đã sửa xong.
- Chưa freeze baseline/tag mới, chưa merge và không dùng lại bất kỳ dataset đã thu cũ nào.

## Nhật ký 28/10 — firewall hiệu lực

- H04 bổ sung kiểm giao profile, interface alias/type và local address trên cùng NIC;
  không lấy profile từ NIC lab ghép với địa chỉ NIC management để báo broad nhầm.
- IPv4/IPv6, CIDR/range, wildcard và scope chưa giải được có 11 case mới.
  Tổng 33 test Windows đạt trên PowerShell 5.1; JUnit `windows-effective-scope-green.xml`.
- Không sửa rule/user/service trên host. P08 còn cần phép thử allowed/denied trên
  Windows 11 của lab; không lấy unit test thay cho bằng chứng kết nối thực tế.

## Nhật ký 28/10 — runtime và Colab

- Commit `77ad956`: mount baseline chỉ đọc, kiểm baseline/model trước khi dừng stack cũ.
- Commit `1d19f88`: giữ scenario trong cùng cohort; builder/challenge/Colab qua 28 test,
  không cần đọc locked test để xác minh train/validation.
- Commit `dd765de`: collector và API dùng cùng grace cấu hình, từ chối giá trị không hợp lệ;
  63 test liên quan đạt. `e8cec84` sửa verifier shell v2 còn giả COMPLETE cho legacy fixture.
- Full suite mới **451/451** đạt, 0 lỗi/skip; pip check/Ruff đạt. JUnit/hash xem
  `docs/runtime-acceptance-v3-20261028.md`.
- Docker API/n8n/receiver thật đã PASS với dữ liệu smoke mới, context riêng: signed
  ingress, replay/restart, idempotent notification, trace context, đóng window theo
  đồng hồ thật, parity và late/raw conflict. Không phải dữ liệu lab/VM hay metric model.
- P15 vẫn mở: cần workflow đóng window tự động và nghiệm thu revision/outbox/feedback
  đầy đủ; test driver gọi close thủ công không thay cho thành phần đó.

## Nhật ký 28/10 — bàn giao hướng dẫn pilot theo xác nhận của Thịnh

- Thịnh xác nhận lab 4 VM ở máy Kiên, máy hiện tại chưa cài lab. Chuyển ưu tiên sang
  hướng dẫn thao tác cho Kiên; không tiếp tục dò/bật VM cục bộ để coi là nghiệm thu.
- Kiên.txt 3.0 đã viết lại và đồng bộ byte/hash với runbook trong repo; giữ bản gốc
  riêng. Có điều kiện trước/sau/lỗi, enrollment, NTP nội bộ, watermark/grace, final
  flow, khóa bucket, target yên, progress/final audit, restore offline và ảnh full host.
- Full suite 461 đạt tại 95794cc; 24d98c3 chỉ sửa ignore quarantine sinh tự động.
  Native Bash/PowerShell/jq/chrony/Suricata và backup/wheelhouse được kiểm riêng;
  xem `docs/handoff-guide-validation-v3-20261028.md` để biết phạm vi và evidence.
- P20 hoàn tất phần hướng dẫn pilot hiện hành; checkbox tổng vẫn mở cho baseline
  chính thức. G7/catalog/cohort/taxonomy/challenge chưa chốt, không mở thu 40–48
  trainable. P21/P22 chưa được nghiệm thu trên lab Kiên, không dùng dataset cũ.
