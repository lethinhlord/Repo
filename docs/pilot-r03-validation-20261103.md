# Kiểm chứng intake R03 và kiểm kê nguồn dự án — 03/11/2026

## Bản sửa phần mềm

Commit phần mềm `d1ee8af6b57f2ff667b902871c4f5993de9d032e` xử lý:

1. Khi một read hoàn tất sau cutoff, buffer 1 MiB có thể dừng giữa một JSON dù
   nguồn đã chứa phần còn lại. Trước đây buffer đó bị parse ngay và báo partial.
   Nay giữ pending làm late, quan sát phần nguồn tới EOF snapshot hữu hạn, kiểm
   prefix rồi mới phân loại; không thêm byte vào capture nhận đúng hạn.
2. Một late tail đã lưu còn thiếu phần cuối từng bị parse trước khi kiểm live
   source. Nay giữ kiểm tra các complete record đã lưu, rồi cho quan sát phần mở
   rộng cùng prefix từ nguồn còn nguyên. Offline hoặc EOF thực sự chưa hoàn chỉnh
   vẫn phải từ chối; relevant late input không được biến thành timely input.
3. Kiểm chéo phát hiện race mới: nguồn có thể thu ngắn giữa identity check và
   fstat lấy EOF, làm remaining âm và gọi read(-1). Đã tái hiện và thêm guard
   end < offset trước mọi read. Test cũng chứng minh không đuổi theo log đang tăng.

Capture/checkpoint đã sealed, admitted offset, read-completion timestamps và
deadline không thay đổi khi quan sát late tail. Nguồn rotate/truncate, prefix bị
sửa, record của agent cấu hình thiếu original timestamp, JSON malformed hoặc
chưa hoàn chỉnh và record thuộc bucket cũ đến muộn vẫn fail closed.

Không thay đổi schema/catalog/dependency/default 300 giây + grace 60 giây.
Không có evidence R03 thật để nghiệm thu hoặc khôi phục R03 trên máy này.

## Kiểm kê theo yêu cầu mở rộng

- Đã tìm trong D:\Repo, Downloads/Tài liệu/Máy ảo/DataCodex và các vùng Documents,
  PycharmProjects, OneDrive đang có của user. Danh sách root/file đầy đủ được lưu
  riêng trong evidence kiểm kê. Không mở nội dung các tài liệu cá nhân không liên
  quan chỉ vì chúng cùng ổ đĩa.
- Có 6.264 path khớp tên archive/checkpoint/state/project, gồm 6.258 path trong
  DataCodex; 2.583 collection state đều thuộc các hồ sơ kiểm thử được tìm thấy,
  không có run ID R03 hoặc origin /home/... của lab thật. Ba state không phải object/
  JSON là negative fixtures. Có 18 .git/config, phần lớn là clone QA trong outputs;
  D:\Repo là checkout làm việc chính. Không tìm thấy R03 trong các nguồn này.
- Kho metadata GitHub của account có năm repository; Repo là dự án DATN liên quan.
  Đã kiểm refs origin và tìm R03 trong code/PR của Repo, không có kết quả evidence.
  Không sửa repository cá nhân không thuộc dự án.
- Docker có hai container repo-api-1/repo-n8n-1 và hai volume feature_state/n8n_data.
  Đã kiểm mounts, thư mục data/evidence/state và metadata SQLite ở chế độ read-only.
  API có hai alert state, không có payload R03; n8n có workflow Week 2 SHADOW,
  không có execution R03. Không có /var/ossec/logs hoặc archive collector trong API.
- Gói ZIP dự án tìm thấy trong Tài liệu/Đồ án là gói source R02, không chứa run data.
  Đường dẫn D:\DATN-V3-PILOT-R02-ERROR trước đây hiện không còn tồn tại tại lúc kiểm.

Đây là kết quả của các nguồn đã truy cập, không phải kết luận về filesystem bên
trong VMDK offline hoặc máy Kiên chưa kết nối. Không khởi động/mount sửa VM để giả
làm lab bốn máy. Không in .env, private keys hoặc secret runtime ra log.

## Sai lệch Docker thực tế và giới hạn deployment

Container đang chạy báo API 3.1.0/features-v2; package bind mount là smoke v2 từ
23/10. Repo hiện yêu cầu API 4.0.0/features-v3. Image cũ còn thiếu intake_window.py.
Host hiện không có baseline v3 ở đường dẫn deploy mặc định và không có .env để tái
triển khai theo compose hiện hành. Chỉ có signing/config trong runtime cũ không
thay thế được enrollment context hay package v3 đã được duyệt.

Đã build image QA từ Dockerfile/requirements lock hiện hành và chạy native Linux
test: import intake thành công, case >2 MiB không cắt mất late record, health API
4.0.0. Khi không cấu hình model, readiness vẫn degraded đúng guard. Không dùng
baseline hoặc model smoke giả làm dữ liệu lab để ép deployment thành ready.

Stack đang chạy, volume, model cũ và workflow không bị xóa/ghi đè. Image QA được
kiểm riêng; việc này chưa nâng cấp stack Docker thật. Muốn nâng cấp thật phải có
baseline enrollment v3 cùng signed package v3 theo deployment runbook rồi kiểm
SHADOW; không dùng API/schema v2 làm minh chứng cho source v3.

## Kiểm tra và kiểm chéo

- TDD cuối trên module pristine HEAD faac227 (ghi module hash): **7 failed,
  10 passed**; log RED đầu có một lỗi fixture được sửa và giữ riêng để truy vết.
- Bộ regression cuối có 19 ca; cùng các guard intake cũ: **39 passed**.
- Race fstat được Astra phát hiện, parent tái hiện read(-1) ở RED rồi sửa guard;
  test nguồn tăng liên tục giữ đúng EOF snapshot cũng đạt.
- Full suite: **622 passed, 1 skipped**, 298.79 giây. Skip do quyền symlink Windows;
  không bỏ/disable test để đạt kết quả. Ruff toàn repo và diff checks đạt.
- Native Linux/Docker: case 2 MiB late unrelated với timely prefix bảo toàn byte,
  checkpoint và offline replay; API health 4.0.0, không-model vẫn degraded.
- **88 Bash block** parse bằng bash -n trên Linux: 80 runbook, 5 R02 và 3 R03.

Sol kiểm nguyên nhân và viết tests; Astra kiểm time contract, late-tail và tìm race;
Terra rà soát hướng dẫn. Các lượt kiểm chéo phát hiện lỗi thật và đã được đối chiếu
bằng test. Hai agent cuối gặp giới hạn usage trước vòng approve sau guard; không
ghi nhận một phê duyệt cuối không có. Parent xác minh guard bằng RED/GREEN, full
suite và Linux QA. Kiểm phần mềm không thay cho nghiệm thu lab R03.

## Thời gian thu và bàn giao

Không phát hành profile 60s: lịch C2 có inter-action span 73,5–273s, còn account
budget 60s cộng guard. Thay bucket sẽ đổi feature counts/interval/periodicity và
có thể phá success-after-failure/flow. Grace 90s chỉ là ứng viên cần đo đủ nguồn
và cấu hình mới nhất quán; không chỉnh snapshot cũ. Đã bỏ yêu cầu nghỉ cố định
60s trùng sau finalize chỉ khi cleanup/process/artifact/traffic đã được kiểm xong.

Finalize --wait vẫn là intake thực cần thiết. Lock và clean-bucket hiện có thể
tạo cadence action khoảng 10 phút; không hứa bỏ một sleep sẽ đổi throughput này.
Tối ưu mạnh cần thiết kế continuous intake/queue và isolation riêng.

[Kiên.txt 3.5](scenario-collection-runbook.md) và [hướng dẫn R03](pilot-r03-runbook.md)
có lệnh backup, cập nhật bằng source bundle, test, phân biệt sealed/capturing và
bàn giao full evidence. G7 vẫn đóng; pilot không dùng bù quota train.

Hồ sơ: `D:\DataCodex\2026-10-05\c\outputs\pilot-r03-20261103` gồm inventory,
RED/GREEN, snapshot-race-red.log, full-suite.xml/log, docker-build.log,
native-linux-qa.log, bash-docs-check.log và receipt sau publish/merge.
