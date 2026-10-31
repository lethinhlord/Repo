# Kiểm chứng sửa lỗi và bàn giao v3.3 ngày 31/10/2026

Đã xử lý F01–F09 của lượt kiểm tra chéo ngày 30/10: sửa phần mềm, đồng bộ hướng dẫn
và loại bỏ các điểm vào lỗi thời. Không dùng lại dataset cũ; chưa nghiệm thu lab Kiên
hoặc mở G7. Kiên.txt được phát hành từ chính bytes của runbook đã kiểm.

## Thay đổi đã đối chiếu

| Mục | Kết quả phần mềm và tài liệu |
|---|---|
| F01 | Collector/online dùng chung last-relevant-source-v1; as-of không vượt controller finalize; baseline vẫn phải trước quan sát đầu; replay kiểm policy và thời gian; không sửa raw. Evidence thiếu policy phải thu mới. |
| F02 | Fixture verifier đủ 10 feature account v3 và context tổng hợp rõ; CLI nhận package ký hợp lệ. |
| F03 | Guard Security trong chính code block được chạy bằng test; thiếu event, type unlock hoặc sai nguồn SMB đều bị chặn. |
| F04 | README bỏ quick-start thiếu clock preflight và dẫn về một quy trình đầy đủ. |
| F05 | Notebook kiểm đủ bốn file, checksum và owner SHA/builder/config trước dependency/EDA; clone mới và detached đúng SHA. |
| F06 | Operations dùng v3, inventory đủ chín artifact + FROZEN; tài liệu tuần2 ghi rõ snapshot lịch sử, không coi fixture PARTIAL là COMPLETE. |
| F07 | Kali có ACL management đúng nơi thực thi, persist/rollback riêng; không nhầm default route với cô lập peer. |
| F08 | Bản hướng dẫn 3.3 chốt Wazuh4.14.9-1, ghi thay đổi so với kế hoạch4.14.7; pin installer, key, APT và kiểm phiên bản, không tự downgrade. |
| F09 | Bỏ lệnh in test mapping trước Week6, thống nhất blinding. |

Các mô hình Astra, Sol và Terra đã kiểm độc lập/phản biện. Đã sửa tiếp các vấn đề được
phát hiện: encoding/tree thiếu file, thiếu python3-venv trên Ubuntu mới, rollback unit
còn enabled và metadata không phải mapping. Không hạ runtime hoặc dữ liệu gate để xanh test.
Fixture audit tổng hợp được cập nhật policy; không sửa metadata của dữ liệu người dùng.

## Kiểm tra đã thực hiện

- Full pytest cuối: **590 passed, 1 skipped**, 275.67 giây. Skip là Windows symlink;
  không xóa/disable test. JUnit `full-final.xml`, log `full-final.txt`.
- Ruff toàn repo đạt; Markdown local links được kiểm ngoài code fences, không có link hỏng.
- 22 regression clock/context: lệch âm/0/dương, C2 full parity/replay, TTL biên, future
  baseline, controller ceiling, metadata thay đổi và raw bytes giữ nguyên.
- 32 test Windows/canary, gồm 10 ca trên guard Security trích trực tiếp từ hướng dẫn.
- 6 regression ML handoff: package ký + verifier CLI; actual notebook cell với local Git
  thật ở các ca đúng nguồn, sai config/checksum, thiếu approval, sai SHA và checkout cũ.
  Stub chỉ thay Google Drive; không gọi Drive, pip hay train thật trong những test đó.
- Chạy toàn bộ `verify_week3_model.sh` từ snapshot ba60d28 trên Linux riêng: tạo smoke
  mới, build, LR/RF/XGBoost, freeze/ký, inference và PASS. Test khóa vẫn UNOPENED.
  Đây là kiểm phần mềm, không là chất lượng model hoặc dữ liệu lab.
- 80 block Bash qua bash -n, 38 block PowerShell qua parser Windows PowerShell5.1;
  inline Python/XML/module paths được kiểm. 32 ca dùng actual guide blocks trên Linux:
  canary/missing flow/DNS/time/context/schema/source, G7 đúng là từ chối, polling có
  final đến muộn ở lần đọc sau, nmcli argv, bundle ancestor, lock và no-index venv.
  Ba ca source-binding thủ công của bản3.2 được thay bằng native notebook gate và
  các test Git thật nêu trên, không giữ recipe patch notebook cũ.
- Native nft chạy trong network namespace riêng với listener thật trước/sau ACL:
  chặn 8 kết nối management IPv4 và IPv6; vẫn cho NTP transport, SOC-initiated SSH
  transport và data NIC. Không phải SSH/NTP service certification trên lab Kiên.
- APT container xác minh signed metadata/key, Candidate4.14.9-1 cho ba core package,
  revision khác bị pin -1; installer hash khớp. Không cài Wazuh lên host.

Các ca RED/failed đầu được giữ: lỗi thật ban đầu và các lỗi harness/fixture trong quá
trình sửa, rồi GREEN cuối riêng. Không gọi một lượt có lỗi là PASS.

## Dọn tài nguyên và nguồn bàn giao

Sáu biên bản/implementation snapshot đã chuyển vào `docs/history/`, có cảnh báo lịch sử
và sửa liên kết. `docs/current-status.md` là điểm vào hiện tại. Nhật ký tasks giữ để
truy vết, có header ngăn dùng SHA/nhánh cũ làm nguồn thu mới. Các fixture/mock tuần1
vẫn có consumer và test, nên giữ đúng vai trò tương thích thay vì xóa logic đang dùng.

File baseline v2 bên ngoài repo được rút khỏi chỗ đang dùng và lưu riêng có nhãn
ngừng dùng. Các nhánh cũ chỉ gỡ sau khi xác minh commit nằm trong main; refs trước
cleanup có bundle kiểm lại ngoài repo. Không xóa original FINAL, dữ liệu gốc, secrets
hoặc hệ thống đang chạy. Lịch sử/tag vẫn truy vết được, không dùng để phát hành thu mới.

`PILOT_SOURCE_COMMIT.txt` được ghi sau merge từ SHA main thực đã đối chiếu, gửi cùng
Kiên.txt3.3. Không ghi source SHA tự tham chiếu vào commit và không biến pilot SHA
thành COLLECTION_BASELINE_COMMIT. Merge receipt ghi trạng thái cuối.

## Phạm vi chưa thể xác nhận bằng lượt sửa này

G7 cần thiết kế/thu cohort, challenge/taxonomy và pilot bốn VM được nghiệm thu theo
runbook. Final-window workflow tự động và strong response là hạng mục công khai chưa
hoàn tất; ingest hiện SHADOW/REVIEW. Không có kết luận model đủ accuracy/AUTO.
Codex Security Deep Scan ở lượt trước không khởi chạy do thiếu managed filesystem
permission profile; không có kết quả scan bảo mật được suy diễn từ test chức năng.

## Evidence

`D:\DataCodex\2026-10-05\c\outputs\remediation-20261030`

Gồm JUnit/log, red/green clock/ML/canary, `actual-block-results.json`,
`tested-guide-sha256.txt`, native-network-qa.txt, apt-pin-qa.txt, full-smoke-script.txt,
parser blocks, refs bundle và receipt xuất bản/merge. SHA-256 guide đã thực thi:
`b969b2f41f735df16ca0320261b614b1057def797643ea4553c091f00b6aa1b3`.

Nguồn phiên bản: [Wazuh package list](https://documentation.wazuh.com/current/installation-guide/packages-list.html),
[official assistant release4.14.9](https://github.com/wazuh/wazuh-installation-assistant/releases/tag/v4.14.9).
Hash/fingerprint trong hướng dẫn được đối chiếu trực tiếp với artifact/repository chính
thức và giữ bằng chứng; nếu nguồn thay đổi thì quy trình dừng, không tự nới pin.