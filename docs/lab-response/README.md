# Bật phản ứng thật cho lab 4 VM

Trạng thái kiểm tra ngày 28/11/2026.

Phạm vi đã được chủ dự án yêu cầu: chặn IP và khóa tài khoản thật trên VM lab.
Trạng thái hiện tại: **chưa bật**, do chưa có kết nối và danh tính VM để triển
khai/nghiệm thu. Thư mục này chuẩn bị thông tin kết nối và thiết kế thực thi;
chưa cung cấp hoặc tuyên bố đã có bộ thực thi phản ứng thật.

Không dùng IP trong hình cũ làm địa chỉ hiện tại. Script thu dữ liệu mới dùng
mạng `10.20.0.0`, trong khi tài liệu lịch sử từng dùng `192.168.58.0`; phải lấy
địa chỉ đang chạy. Máy laptop Thịnh không phải WIN11-TARGET của Kiên.

## Kiên cung cấp gì để triển khai được

1. Trên WIN11-TARGET, mở PowerShell 64-bit bằng quyền quản trị. Cập nhật code
   từ GitHub trên máy đã có bản clone, rồi chạy trong thư mục repository:

   ```powershell
   git pull --ff-only
   & .\docs\lab-response\Get-EndpointInfo.ps1 `
     -OutputPath "$env:USERPROFILE\Desktop\datn-endpoint-info.json"
   ```

   Script chỉ đọc hostname, OS, địa chỉ IPv4, trạng thái dịch vụ, ba tài khoản
   `datn_lab01/02/03`, SID, cmdlet, execution policy và fingerprint SSH công khai
   nếu có. Nó không đọc private key, `client.keys`, mật khẩu hoặc token; không
   sửa firewall/tài khoản/dịch vụ/execution policy. Nếu file output đã có, đổi
   tên output. Nếu execution policy chặn script, gửi lỗi và policy hiện tại để
   chọn cách triển khai phù hợp; script không tự thay đổi policy.

   Nếu Windows chưa có Git/bản clone, tải riêng
   [Get-EndpointInfo.ps1](Get-EndpointInfo.ps1) bằng nút tải file Raw trên GitHub,
   rồi chạy file đã lưu với cùng tham số `-OutputPath`. SHA-256 của file Raw
   phiên bản này là
   `e3d375e4bb27be9dee9e92233db58434c17e89cfd1380cd9c11410b288419960`.
   Kiểm bằng `Get-FileHash -LiteralPath '<đường dẫn file vừa tải>'` trước khi chạy.
   Hash này áp dụng byte của file Raw, không áp dụng bản clone đã đổi LF/CRLF.

2. Trên Wazuh/SOAR, lấy thông tin sau và gửi lại phần kết quả, không gửi secret:

   ```bash
   hostname
   ip -brief address
   sudo /var/ossec/bin/agent_control -l
   sudo /var/ossec/bin/wazuh-control info
   ```

   Nếu Wazuh và SOAR cùng một máy thì ghi rõ. Agent ID phải thuộc WIN11-TARGET,
   không chọn `all`, `000` hoặc agent của SOC/Suricata.

3. Cung cấp cách truy cập từ máy Thịnh: VPN/SSH/WinRM hoặc máy điều khiển đã
   kết nối được; user quản trị và đường dẫn key/secret đã lưu. Không dán mật khẩu
   hoặc private key vào chat. Nếu chưa có truy cập từ xa, Kiên sẽ phải chạy phần
   cài đặt và nghiệm thu tại lab rồi gửi bằng chứng.

4. Chốt **IP lab được phép chặn** và **SID tài khoản lab được phép khóa** từ
   report. Nêu riêng IP quản trị/Wazuh/SOAR/Suricata để bảo vệ đường quản lý.
   Inventory chỉ ghi direct membership trong Administrators; đây chưa phải
   chứng nhận tài khoản không có quyền cao hoặc không được dịch vụ sử dụng.

## Thiết kế phản ứng được kiểm tra chéo

Hai thao tác có tên cố định, không nhận câu lệnh tùy ý:

- Chặn một IP: tạo hai firewall rule Inbound/Outbound có tên chứa operation ID
  duy nhất, chỉ trên endpoint/IP đã cho phép. Kiểm tra lại rule và thử lưu lượng
  giữa các VM để chứng minh có tác dụng.
- Khóa tài khoản local: giải tên thành SID rồi so với allowlist, từ chối tài khoản
  quản trị, dịch vụ và tài khoản vận hành. Lưu trạng thái trước hành động. Khóa
  tài khoản chỉ chặn đăng nhập mới, không tự kết thúc phiên đã mở.

Trước khi thay đổi, lưu journal bảo vệ bằng ACL và đăng ký hoàn tác trên chính
Windows dưới SYSTEM. Chạy canary vô hại dưới cùng principal để chứng minh task
có thể thực thi, kể cả khi execution policy khác giữa admin và SYSTEM. TTL ban
đầu 300 giây, không quá 900 giây; startup reconciliation xử lý thao tác quá hạn.
TTL/giới hạn này là thiết kế đề xuất, chưa phải cấu hình đã áp dụng trên VM.

Một operation ID có một ý nghĩa bất biến, không gia hạn bằng cách gửi lại. Từ
chối hai operation đang hoạt động trên cùng mục tiêu. Hoàn tác chỉ xóa rule do
chính operation tạo và không tự bật tài khoản vốn đã tắt. Không tái sử dụng tên
tài khoản để hoàn tác nếu SID đã đổi. Phải quy định một chủ thể điều khiển tài
khoản lab trong thời gian lease để tránh hoàn tác đè thay đổi của quản trị viên.

Chỉ báo `APPLIED` sau khi đọc lại trạng thái endpoint. Nếu mất kết nối sau khi
gửi, báo `UNKNOWN`, đối chiếu operation ID trước khi thử lại. Phản hồi API Wazuh
thành công chỉ chứng minh lệnh đã gửi; phải có receipt/read-back từ Windows.
Rollback thất bại phải giữ journal/task để thử lại và yêu cầu xử lý, không báo
hoàn tất hoặc xóa dấu vết.

## Nối với model mới

Model `development-20261127T154124Z` vẫn giữ đúng trạng thái phát triển và
`automation_eligible=false`, `deployment_eligible=false`. Thẩm quyền chạy hành
động trong lab đến từ chính sách lab và yêu cầu của chủ dự án, không đến từ việc
sửa metric/metadata cho thành đủ chuẩn vận hành.

Cần thêm luồng tích hợp model mới và dữ liệu live vào bộ thực thi. API hiện đang
chạy model cũ/schema v2; workflow hiện chỉ SHADOW và chưa có executor. Không
phát lệnh thật từ 48 dòng TRAIN hoặc từ replay bằng chứng lịch sử. Dữ liệu live
phải có danh tính nguồn/mục tiêu xác minh được, còn mới, đầy đủ feature/context
và liên kết với operation ID; thiếu SID/IP quy thuộc thì đưa vào review.

Phạm vi này không khẳng định model đạt chất lượng production. Nếu cần vận hành
ngoài lab, phải đánh giá độc lập trước và dùng quy trình triển khai phù hợp.

## Nghiệm thu trước khi báo đã bật

1. Kết nối và kiểm đúng hostname/OS/agent ID/fingerprint; thử quyền và SYSTEM
   rollback canary mà không thay đổi firewall hoặc tài khoản.
2. Thử một IP được phép: xác nhận lưu lượng trước, rule sau chặn, lưu lượng bị
   chặn và được phục hồi sau TTL.
3. Thử một tài khoản local được phép: xác nhận SID/trạng thái ban đầu, đăng nhập
   mới bị từ chối sau khóa và được phục hồi theo đúng trạng thái gốc.
4. Thử request trùng ID, mất kết nối, khởi động lại, mục tiêu ngoài allowlist,
   IP quản trị và tài khoản được bảo vệ. Chứng minh không có thay đổi ngoài phạm vi.
5. Nối live event vào model mới và xác nhận prediction → operation → receipt →
   rollback. Giữ log/ảnh/operation ID thực; không lấy kết quả mock thay nghiệm thu.

Nguồn chính thức đã đối chiếu:
[Wazuh 4.14.9 Windows netsh](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/active-response/netsh.c),
[Wazuh 4.14.9 API dispatch](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/framework/wazuh/active_response.py),
[Custom active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html),
[Disable-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/disable-localuser?view=powershell-5.1),
[Register-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=win10-ps).
Đối chiếu đúng phiên bản Wazuh được inventory; không dùng giao thức `enable`/
`disable` của nhánh main mới thay cho `add`/`delete` của 4.14.9.
