# Kiểm chứng bản sửa collector và hướng dẫn Kiên — 29/10/2026

> Hồ sơ lịch sử, không dùng làm hướng dẫn hiện hành. Xem [hướng dẫn thu dữ liệu](../scenario-collection-runbook.md) và [trạng thái hiện tại](../current-status.md).

Phạm vi: năm nhóm blocker R01–R05 được tái hiện sau bản pilot
`192f5cd4ca013545659b1d461a34656ea739e9d5`. Giữ nguyên dataset cũ ở ngoài đợt thu;
không dùng QA/fixture/pilot để đủ quota train. Lab 4 VM ở máy Kiên, chưa được nghiệm
thu trực tiếp trong lượt sửa này. Đây là kiểm chứng phần mềm và hướng dẫn.

## Các lỗi và cách chặn hồi quy

| Nhóm | Lỗi đã tái hiện | Cách sửa và điều kiện từ chối |
|---|---|---|
| R01 | DWM/UMFD hoặc logon type dịch vụ làm lệch account window; batch chỉ có OS event bị rỗng và lỗi; event thiếu trường bị bỏ qua | Cùng eligibility cho collector/context/online; chỉ loại danh tính OS xác định khỏi feature người dùng. Raw vẫn có unknown/PARTIAL riêng, kể cả thiếu user/logonType. User thật và DWM giả tên vẫn được quan sát. |
| R02 | Cùng đích/thời gian nhưng sai source port/protocol vẫn có thể COMPLETE; final tự hỗ trợ; flow ID trùng cho socket khác thừa kế nonce | Bảo toàn tuple, IP hợp lệ, protocol và sensor identity; final bắt buộc transaction cùng tuple/time. Nonce inheritance dùng các reference không mơ hồ sau lọc. DNS22 nhiều socket cạnh tranh giữ uncertainty. Data-only EVE cũng giữ proto/sensor_instance qua API. |
| R03 | Finalize muộn đọc hồi tố event timestamp cũ trong khi online từ chối late arrival | Intake foreground bắt đầu trước cutoff, ghi thời điểm đọc xong và hash/cursor/start prefix; checkpoint sealed đóng băng byte nhận đúng hạn. Cold late finalize, dòng dở, rotate/truncate, clock lùi, tail muộn hoặc thay đổi chứng cứ đều bị chặn. Saved late evidence không thể bị xóa bằng truncate tail rồi retry. |
| R04 | Receipt hỏng trong quarantine làm mọi bucket mới không phục hồi được; receipt parse được nhưng bị đổi/mất có thể né kiểm | Phục hồi quyền bucket từ bằng chứng crosslink còn nguyên và reservation độc lập; giữ original hỏng, ghi recovery record. Thiếu/xung đột thì dừng để restore backup. Không biến run hỏng thành VALID. |
| R05 | Năm lần đọc đồng hồ nối tiếp bị hiểu nhầm là clock skew | Mỗi host lưu controller-before/remote/controller-after; kiểm RTT, UTC, freshness và sai lệch xấu nhất giữa các khoảng. CLI và hướng dẫn dùng cùng measured evidence, không tăng ngưỡng cho qua. |

R03 còn có hai regression từ kiểm chéo: dòng hoàn chỉnh >1 MiB sát cutoff không bị
nhầm thành partial do chunk nội bộ; late input đã bị từ chối vẫn chặn retry sau khi
nguồn bị truncate về offset sealed. Mỗi lần đọc vẫn phải hoàn tất không muộn hơn
cutoff; drain nhiều chunk không được kéo dài hạn nhận.

R04 xử lý cả trạng thái FINALIZING: metadata/checksum đã đóng băng được dùng để
giữ quyền bucket, không để trạng thái trung gian chặn vĩnh viễn bucket mới. Khi
quarantine, cả raw cuối và `.RUN_ID.tmp` (nếu có) được chuyển riêng và ghi marker;
không bỏ output tạm trong data/raw. Owner khóa được kiểm trước khi di chuyển,
lỗi di chuyển/ghi marker hoàn tác các đường dẫn, rồi mới nhả khóa sau khi bảo toàn.

## Kiểm chéo

- Terra kiểm R01/R02 của bản triển khai ban đầu, phát hiện batch rỗng, thiếu trường
  bị bỏ qua, IP không hợp lệ và nonce inheritance sai tuple. Có regression độc lập
  và kiểm lại bản sửa; collector được kiểm thêm bằng hai socket và flow ID trùng.
- Sol kiểm R03 do Astra triển khai, tái hiện hai lỗi chunk/tail nêu trên; bản sửa
  được kiểm lại ở lượt thứ ba. Không còn blocker được tìm thấy trong phạm vi này.
- Clock được kiểm chéo Astra/Terra ở lượt trước; bổ sung worst-case uncertainty và
  lỗi CLI đầu vào. Recovery được Sol/Terra/parent đối chiếu chứng cứ và điều kiện lỗi.
- Hướng dẫn 3.1 được đọc chéo với source, đặc biệt thứ tự complete/finalize,
  sealed-only retry, clock measurements, quarantine, inventory và backup.

Review hữu hạn và test đạt không chứng minh phần mềm không còn mọi lỗi có thể có.
Hash xác minh toàn vẹn và crosslink, không xác thực người có quyền sửa đồng thời
toàn bộ chứng cứ. Kiên cần gửi checksum/backup qua kênh độc lập.

## Bằng chứng kiểm thử

Revision mã được pin trong Kiên.txt 3.1:
`d06d04034f0d1c996907365841f21cdb874e4d5a`.
Full suite Windows: 552 passed, 1 skipped (symlink), 0 failure/error.
Linux bổ sung: 69 passed, 0 skipped, gồm chính case symlink đó. Ruff và pip check
đạt. Schema OpenAPI được xuất lại từ model mới, không đổi feature vector 24 trường.
JUnit final-full.xml có SHA-256
`4bf9a3c2d73d5bfbe47cc055afc055f29c8e9ecf40dc55e7c53fc14f3ab2d086`.
Evidence RED/GREEN/review nằm tại:

`D:\DataCodex\2026-10-05\c\outputs\handoff-fixes-20261028`

Các test bổ sung dùng dữ liệu QA mới, không phải dữ liệu thu trên VM:

- `test_account_scope.py`, `test_account_scope_review.py`;
- `test_account_scope_flow_binding.py`, `test_flow_binding_review.py`;
- `test_intake_watermark.py`, `test_intake_collection.py`, `test_intake_review.py`;
- `test_quarantine_bucket_recovery.py`, `test_measured_clock_evidence.py`.

Native guide QA: 74 block Bash qua `bash -n`, 37 block PowerShell qua parser thật;
inline Python/XML và đường dẫn module được kiểm. Block clock mới chạy trong Linux
với lệnh đọc UTC thật và SSH transport mô phỏng có độ trễ: raw span >5 giây nhưng
measured gate PASS đúng. Đây không phải phép đo clock của lab Kiên. Recovery symlink
được chạy thêm trên Linux vì Windows host không cho tạo symlink trong test.

## Giới hạn bàn giao

`require_online_parity=True` áp dụng foreground receive cutoff. Legacy mode tắt cờ
này không có bằng chứng receive-time tương đương và không dùng cho đợt production.
Offline validate kiểm saved checkpoint/raw; live finalize/retry còn kiểm nguồn và
tail hiện tại. Collector-observed arrival không phải timestamp Wazuh sinh log hay
API nhận log. Replay kiểm feature parity, không thay cho nghiệm thu received_at.

G7 vẫn đóng. Catalog/cohort/taxonomy/challenge G01–G07, workflow tự đóng window và
nghiệm thu Windows/telemetry/latency/backup trên lab Kiên còn là điều kiện phát hành
COLLECTION_BASELINE_COMMIT thu chính thức. Merge bản sửa không tự mở G7. Bốn pilot
được hướng dẫn để kiểm hệ thống; chưa có dataset mới hoặc metric phân biệt model.
