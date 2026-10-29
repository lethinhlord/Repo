# Sửa blocker thu dữ liệu — 28/10/2026

Yêu cầu: sửa chính xác R01–R05, kiểm chéo nhiều mô hình sau từng nhóm thay đổi,
đồng bộ Kiên.txt và merge các sửa đổi đã kiểm lên GitHub. Không dùng dataset cũ;
nghiệm thu lab Kiên và G7 thu chính thức vẫn phải được ghi đúng trạng thái.

Baseline: 192f5cd4ca013545659b1d461a34656ea739e9d5.
Phát hiện và probe gốc: outputs/handoff-review-20261028 ngoài repo.
Evidence RED/GREEN/review mới: outputs/handoff-fixes-20261028 ngoài repo.

## Cách triển khai

- [x] R01: shared eligibility account trước grouping; virtual/system có identity
  xác định không phá console/SMB, vẫn giữ raw và chặn user thật chồng lấp.
- [x] R02: giữ connection tuple/protocol và transaction link; flow không liên quan
  không tạo COMPLETE; thiếu trường cần thiết giữ uncertainty.
- [x] R03: receive-time/watermark evidence có provenance; không đọc muộn rồi chấp
  nhận hồi tố. Chia parser/intake policy thành phần độc lập trước tích hợp collector.
- [x] R04: phục hồi bucket ownership từ chứng cứ còn nguyên, giữ original hỏng và
  reservation cũ; recovery thiếu/xung đột không được bỏ qua.
- [x] R05: per-host midpoint/RTT/freshness; CLI và guide dùng cùng measured evidence.

## Kiểm chéo và bàn giao

- [x] Mỗi lỗi có RED rồi GREEN; không hạ gate/assertion để đạt.
- [x] Review bằng mô hình khác theo từng artifact nhỏ, đối chiếu từng finding;
  tối đa ba vòng cho mỗi artifact không đổi, lỗi còn lại được ghi rõ.
- [x] Full suite, Ruff, dependency/schema, Linux command/PowerShell parser và
  các phép kiểm runtime liên quan đạt sau tích hợp.
- [x] Kiên.txt/runbook cùng byte/hash, đúng SHA triển khai, native commands và
  hướng dẫn xử lý lỗi/retry/backup rõ; không tuyên bố đã nghiệm thu bốn VM.
- [ ] Kiểm PR base/checks, tạo/attach PR, merge HEAD đã kiểm khi đủ điều kiện;
  không force-push hoặc bỏ branch protection.

Phân công ghi để tránh tranh file: parent giữ production account/C2/collector;
reviewer Astra viết regression account/flow trước. Terra giữ module/CLI clock;
Sol giữ module/test bucket recovery. Không cùng sửa collector đồng thời.

Ngày 29/10: kiểm chéo phát hiện thêm empty OS-only batch/missing account fields,
invalid IP/data-only EVE mất proto/sensor identity, nonce inheritance sai tuple,
chunk >1 MiB sát cutoff và saved-late tail bypass. Đã có regression/bản sửa.
FINALIZING recovery và quarantine output tạm cũng được bổ sung để không để lại
raw orphan. Full suite 552 passed/1 Windows symlink skip; Linux 69 passed/0 skip
bao gồm case đó. Kiên.txt 3.1 đã cùng hash/runbook và pin source d06d0403.
Xem docs/collection-blocker-validation-20261029.md và evidence ngoài repo.
Checkbox PR là trạng thái trước khi gửi merge; trạng thái merge cuối xem trên PR.
