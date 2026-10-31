# Sửa lỗi thu dữ liệu và bàn giao v3.3

Ngày 31/10/2026. Yêu cầu: khắc phục F01–F09 trong báo cáo kiểm chéo, đối chiếu lại
và bỏ thành phần cũ gây nhầm. Nhánh fix/collection-handoff-consistency từ main94c84d2.
Không sử dụng dữ liệu train cũ; không thay đổi đề cương/kế hoạch FINAL gốc.

- [x] F01: shared as-of last-relevant-source-v1, bound controller finalize, metadata/replay,
  future-history/TTL/parity giữ nguyên. 22 test mới; sửa fixture audit theo contract mới
  và chặn metadata không phải mapping. Source/evidence cũ không tự chuyển đổi.
- [x] F02: verifier fixture đủ feature/context v3; regression CLI package ký thật tổng hợp;
  toàn pipeline smoke Linux đạt, không mở locked test.
- [x] F03: chạy guard Security từ block hướng dẫn; các ca sai type/thiếu cặp/sai IP bị chặn.
- [x] F04: bỏ quick-start không đầy đủ, README dẫn một quy trình đo clock/enrollment.
- [x] F05: notebook yêu cầu approved SHA, checksum, builder/config và checkout mới;
  test Git thật đúng nguồn/sai config/sai checksum, không gọi pip/Drive thật trong test.
- [x] F06: active docs schema v3; snapshot tuần2 ghi lịch sử rõ; inventory package đủ.
- [x] F07: nft ACL tại Kali trên management NIC + persistence/rollback, thử bằng namespace
  riêng với listener thật; không thay firewall host/VM Kiên. Thêm bước python3-venv bị thiếu.
- [x] F08: exact Wazuh4.14.9-1, installer SHA256 và signing fingerprint; live signed APT
  candidate/pin được kiểm trong container, không cài Wazuh lên host.
- [x] F09: không in test mapping trước cổng Week6.
- [x] Chuyển sáu biên bản cũ vào docs/history, sửa link; current-status là điểm vào mới.
- [x] Full suite cuối 590 passed/1 Windows symlink skip, Ruff, native QA và biên bản đạt.
- [ ] Publish Kiên.txt đúng hash và pilot SHA sau merge.
- [ ] Loại bỏ refs fully merged/file baseline lỗi thời khỏi chỗ đang dùng, lưu receipt.
- [ ] PR/kiểm HEAD/merge/đối chiếu main và publish.

Đã kiểm chéo Astra/Sol/Terra; sửa thêm các lỗi được phản biện về encoding/tree inventory,
thiếu venv, rollback service còn enable và native QA prerequisites. Log giữ ngoài repo:
D:\DataCodex\2026-10-05\c\outputs\remediation-20261030.

G7 và pilot bốn VM vẫn là điều kiện thực tế; workflow final-window tự động là hạng mục
công khai còn mở. Không chuyển các mục đó thành PASS bằng unit test hoặc đổi cấu hình.
Các checkbox xuất bản là snapshot trước merge; trạng thái cuối theo PR và merge receipt.