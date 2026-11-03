# Archive replay R02 — 03/11/2026

Mục tiêu: sửa lỗi định danh archive thiếu rule gây finalize thất bại, giữ guard và
provenance, kiểm chéo giữa các mô hình, cập nhật hướng dẫn và merge mã đã kiểm.

- [x] Bảo toàn diagnostic gốc và tái hiện lỗi trên đúng bucket.
- [x] Test trước sửa: 6 RED, 4 GREEN; sửa occurrence identity và CollectionError.
- [x] 13 regression account/C2/CLI GREEN; full suite 603 passed, 1 platform skip.
- [x] Astra kiểm code độc lập; Sol kiểm test/C2/CLI; Terra kiểm hướng dẫn.
- [x] Kiên.txt 3.4 và companion R02 được đối chiếu; 85 Bash block parse đạt.

Phát hành: tạo PR từ fix/archive-replay-record-identity, merge với expected head
đã kiểm, phát pointer/bundle/guide từ main được xác minh, giữ receipt ngoài repo.
Trạng thái cuối nằm ở PR và merge receipt; đây là hồ sơ viết trước publish.

R02 lab recovery và G7 vẫn chưa đạt; các dấu kiểm trên chỉ là kiểm chứng phần mềm.
Chi tiết: [biên bản](../docs/archive-replay-r02-validation-20261103.md).
