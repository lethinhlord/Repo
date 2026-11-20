# Đối chiếu hai nguồn thu của bộ 40 run — 20/11/2026

## Mục tiêu và phạm vi

Cho phép xử lý lại đúng bộ `raw-evidence-40valid` mà không thu lại dữ liệu. Bộ này
có 23 run từ `db166d814857ef061982839a74a17af6e500625f` và 17 run từ
`273d1d0800fa45e686488e8965a81ed19c4de7e6`. Không sửa raw, nhãn, run ID,
cohort, frozen state, receipt hoặc checksum ban đầu.

Hai nguồn thu được xác minh bằng cây Git, runtime, bytes từng run và bằng chứng
frozen. Mã xử lý hiện tại có danh tính riêng. Không gán candidate mới cho dữ liệu
đã thu và không tạo lại các tag thu lịch sử chưa được công bố.

## Các kiểm tra đã thực hiện

- Đối chiếu độc lập cây mã nguồn của cả hai commit thu và SHA của toàn bộ 40 run.
- Replay raw từng run, kiểm tra parity và frozen acceptance bằng verifier thật.
- Đối chiếu độc lập bản ghi portable, hash toàn bộ dataset và split theo cohort.
- Kiểm thử từ chối nguồn thứ ba, inventory thiếu/thừa/trùng, raw/state thay đổi,
  mã xử lý thay đổi kể cả `assume-unchanged`, policy thay thế và runtime khác.
- Kiểm thử từ chối đổi nhãn manifest v2/v3, bỏ certificate, thay bản ghi hoặc
  đổi nguyên cohort rồi tự tính lại các hash trong manifest.
- Kiểm tra chéo phát hiện và sửa các mâu thuẫn audit status, candidate tổng hợp,
  số run theo stratum và checksum source active. Kiểm tra v2 được thực hiện trước
  khi notebook cài dependency hoặc đọc partition.
- Thử loader thật với file locked test vắng mặt và chặn mọi lần mở tên file đó.
- Thực thi cell bootstrap notebook tại máy kiểm chứng; chỉ thay Drive mount và
  Git transport. Đây là kiểm tra cục bộ, không phải phiên huấn luyện Google Colab.
- Hồi quy default v2 và CLI cũ; cache cũ bị từ chối trước khi thay đổi, dùng cache
  có phiên bản mới; kiểm thử actor HTTP bất đồng bộ với server thật tại loopback.

Chi tiết kết quả hồi quy và source SHA của gói bàn giao được ghi trong báo cáo
phát hành kèm gói Colab. Sau merge phải build lại bằng đúng SHA phát hành; không
sửa trường commit của manifest đã build để làm nó khớp bản phát hành.

## Các commitment đã đối chiếu

| Thành phần | SHA-256 |
|---|---|
| Dataset portable | `35c28169363ac5b52ada2e4d30615ebd7b7d0d69ebb22a8bf667ff67cead272f` |
| TRAIN, 24 bản ghi | `651432d922116c2d7c02d3b91208d745db332252c6e94176ccc366ba759604ba` |
| VALIDATION, 8 bản ghi | `e1dafe0d2f3b1a640ef7b39c3b5fb43cf56ee226d1781aa84e3e816950a2eb65` |
| LOCKED TEST, 8 bản ghi | `9f3ad2381c9c7a890fbba263c5edffdff9532d90c30898bfb3842d2ea6332210` |

Các giá trị này là commitment của đúng bộ dữ liệu đã review, không cho phép một
bộ dữ liệu hỗn hợp khác đi qua. Mỗi partition dùng bytes UTF-8/LF cố định.
Certificate và manifest được tạo mới để ràng buộc source xử lý và runtime thật.

## Giới hạn của kết luận

40 run đạt mức tối thiểu của thiết kế, chưa đạt mục tiêu ưu tiên 48. Tính hợp lệ
của dataset và khả năng tái lập không chứng minh mô hình đã đạt chất lượng phát
hiện, calibration hoặc khả năng tự động phản ứng. Metric chỉ được kết luận sau
khi train và đánh giá đúng quy trình; locked test không dùng để chọn mô hình.

Bộ này phục vụ thí nghiệm có kiểm soát; phạm vi lab và số cohort còn hạn chế.
Các quan sát về traffic DNS ngoài profile và độ mới không cân bằng giữa một số
cohort phải được giữ trong diễn giải kết quả. Không khẳng định khả năng tổng quát
hóa trên hệ thống sản xuất từ 40 run này. Chế độ tự động phản ứng chưa được duyệt.

Không cần G7 mới để xử lý ngoại tuyến đúng 40 run đã frozen. Thu run mới bằng
candidate mới vẫn phải qua nghiệm thu lab thật; tài liệu này không cấp G7 mới.

Quy trình thao tác: [Huấn luyện từ bộ 40 run đã review](training-existing-40-runs.md).
