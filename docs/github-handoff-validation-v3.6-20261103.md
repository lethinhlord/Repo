# Bàn giao GitHub-only 3.6 — 03/11/2026

Mã và hướng dẫn phát hành tại tag annotated `pilot-v3.6-20261103` trên
https://github.com/lethinhlord/Repo. Tag chỉ thay đúng năm file tài liệu so với
anchor runtime đã kiểm `9c599f656cb12009492cd8dda721529f8335de04`:
runbook, current-status, hai companion R02/R03 và biên bản này. Mọi file khác phải
giữ nguyên theo phép so sánh Git full-tree trong hướng dẫn.

Không cần truyền source bundle, pointer TXT hay gói dependency offline. GitHub
chỉ truy cập trong cửa sổ bảo trì không còn owner/STARTED/FINALIZING; collection
mode vẫn cô lập. Dependencies cài từ lockfile trước khi cô lập. Raw/evidence,
receipt và backup dữ liệu không đưa lên GitHub.

Hai mô hình Sol và Terra đã đối chiếu quy trình. Các vấn đề phát hiện gồm:
pointer/bundle còn sót; cập nhật giữa active run trái isolation; set-e làm thoát
trước quarantine; thiếu tag receipt cho restore; tar ghi đè root config/schema;
cache dependency legacy không tồn tại; backup zero-run dùng grep exit 1. Bản sửa
chuyển sang source tag rõ ràng, forensic backup trước quarantine, local retry
chỉ khi code đã có sẵn, và backup/restore dữ liệu với exact tag-object/commit.

## Kiểm chứng trước phát hành

- Hai vòng rà soát và đối chiếu tiếp của Sol/Terra đã phát hiện và xử lý các nhánh
  legacy, owner, source restore và backup còn mâu thuẫn. Không cập nhật source
  trong run active; forensic backup được tách khỏi backup release đã kiểm.
- **27 ca QA native Linux/Git đạt**. Dùng các block hướng dẫn thực; chỉ redirect
  transport GitHub sang bare Git fixture riêng. Git clone/fetch/tag/commit/tree,
  owner/state gate, tar/checksum và giải nén thực sự được thực thi.
- Bao gồm clone mới, maintenance, owner/STARTED/FINALIZING/unknown/dirty/wrong
  origin bị chặn trước fetch, runtime tree sai hoặc tag bị đổi bị chặn, local
  retry gate R02/R03 với anchor/tag/legacy/capturing/owner khác, backup và dry
  restore khi có 0 run hợp lệ, và restore bị chặn khi owner đang active, đường
  dẫn checkout không tồn tại hoặc owner ở checkout có đường dẫn tùy chỉnh. Cài
  mới tạo sẵn thư mục scenario-runs để kiểm owner khi khôi phục trên máy dựng lại.
- Source prefix 6.2 và phần Git 6.3 được kiểm riêng; không giả là đã chạy toàn bộ
  bước cài/pytest Ubuntu. Riêng restore đã chạy toàn bộ bootstrap online từ lockfile,
  pip check và kiểm import scikit-learn 1.9.1 / XGBoost 3.4.1 trong container QA.
  Không train, không dùng dữ liệu lab hoặc secret runtime.
- Backup không chứa tracked evidence, source/config/schema root, wheelhouse/wheel
  hay bundle. Source restore lấy từ exact annotated tag, kiểm cả tag object và
  commit; Git tracked tree sau restore không bị private tar sửa đổi.
- **90 block Bash** qua bash -n; **38 block PowerShell** qua parser Windows
  PowerShell 5.1. Ruff và git diff --check đạt. Bốn tài liệu có lệnh được đối
  chiếu SHA-256 đúng bytes đã thực thi; biên bản này chỉ bổ sung kết quả văn bản.
- Không chạy lại full suite 622 test của anchor chỉ để lặp kiểm trên code không
  đổi: full-tree gate giữ nguyên toàn bộ chương trình, tests và lockfiles ngoài
  đúng năm file tài liệu đã liệt kê.

Hai lỗi harness đầu (shebang Python và redirect transport) được giữ log riêng;
chúng không bị gọi là PASS. Các ca sau chạy GREEN bằng transport fixture đúng.

Hồ sơ và receipt phát hành cuối:
`D:\DataCodex\2026-10-05\c\outputs\github-handoff-20261103`, gồm
actual-flow-results.json/log, từng ca, powershell-syntax.json, các SHA đã kiểm và
receipt merge/tag/download. Kiên.txt chỉ được thay thế sau khi tag đã được đưa lên
GitHub, rồi kiểm byte-for-byte với runbook của tag tải từ GitHub thật.

Tag/SHA dùng pilot; G7 và nghiệm thu lab R02/R03 vẫn chưa đạt. QA trên fixture
không phải bằng chứng bốn VM Kiên đã cài hoặc thu thành công.
