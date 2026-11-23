# HƯỚNG DẪN THU DATASET PHÁT TRIỂN SOC–AI–SOAR TRONG 3 NGÀY — 4 VM

Phiên bản development-three-day-v1, ngày 23/11/2026. Đọc toàn bộ trước khi thu.
Code chỉ lấy từ https://github.com/lethinhlord/Repo.git, tag annotated
development-collection-v1.0.0-candidate.1. Chỉ chạy khi tag đã công bố và kiểm
nguồn báo COLLECTION_READY. Không dùng code offline hoặc git pull giữa đợt thu.

## 0. Mục tiêu, trách nhiệm và giới hạn

Đợt này chốt ngân sách tối thiểu của giao thức phát triển: 48 run hợp lệ,
12 account-benign, 12 account-malicious, 12 c2-benign, 12 c2-malicious.
Thu trên ba ngày UTC liên tiếp, mỗi ngày 16 run: 8 Account và 8 C2;
mỗi family/ngày gồm bốn benign và bốn malicious, ghép bốn context có thật.
Tổng 12 context/family, mỗi context chạy mỗi nhãn một lần. Một đơn vị có ba
attempt định trước, nhưng chỉ một attempt hợp lệ được tính. Giữ toàn bộ lỗi.
Bốn pilot G7 và canary/enrollment không tính vào 48. Không thay bằng dữ liệu cũ.

Mục tiêu vận hành: hoàn tất dưới 72 giờ tính từ khi bắt đầu buổi thu ngày 1.
Lịch khuyến nghị giờ Việt Nam: ngày 1 08:00–15:00 gồm preflight/pilot/G7 và quota;
ngày 2 và ngày 3 08:00–12:00. Như vậy khoảng 52 giờ theo đồng hồ từ đầu đến cuối,
không phải 72 giờ máy chạy liên tục. Kiểm/cài sẵn lab trước ngày 1; lỗi thực tế
phải dừng an toàn và báo ngay để xử lý trong ngày, không ghi đủ quota giả.

### 0.1 Ma trận bao phủ bắt buộc trong 48 run

Không chỉ chạy lặp bốn pilot. Compiler đã phân đều chín cặp template dưới đây.
Cả hai nhãn trong một cặp dùng cùng công cụ, đích, user inventory và context.
Không dùng IP, tên user, scenario_id, nhãn hoặc nonce làm feature để phân biệt.

| Cặp | Benign khó dễ nhầm | Profile malicious của lab | Run mỗi nhãn |
|---|---|---|---|
| account-recovery | Hai lần gõ sai rồi thành công | Chuỗi thất bại dồn rồi thành công | 3 |
| account-sessions | Các phiên đăng nhập remote hợp lệ | Sáu thất bại remote | 3 |
| account-maintenance | Bảo trì nhiều tài khoản | Password spray qua nhiều tài khoản lab | 2 |
| account-retries | Credential cũ gây retry hợp lệ | Đoán nhanh liên tiếp | 2 |
| account-multiuser | Nhiều user khôi phục sau lỗi gõ | Đoán qua nhiều user | 2 |
| tcp-poll | Health polling đều, gồm GET/POST | Beacon đều, upload biến đổi | 3 |
| tcp-transfer | Tải xuống/upload hợp lệ theo đợt | Trao đổi staging theo thứ tự khác | 3 |
| tcp-api | API không đều, gồm POST hợp lệ | Beacon có jitter | 3 |
| tcp-retry | API burst/retry hợp lệ | Staging/retry lặp | 3 |

Account không gán benign=thành công, malicious=thất bại. Cần đủ Security4624/4625,
tỷ lệ remote, số tài khoản, tốc độ/cửa sổ thất bại và history thật. C2 không gán
đều=malicious hoặc POST=malicious: cần thứ tự method, transaction, response,
flow upload/dispersion, TCP timing và process/parent proof. Giữ nguyên frozen
schedule; không tự điều chỉnh actor để tạo đầu vào đẹp. Bản này bao phủ các
profile lab đã khai báo; không tuyên bố bao phủ mọi hành vi Account/C2 ngoài thực tế.

Sau mỗi run kiểm VALID/evidence/checksum theo mục14. Sau mỗi ngày bàn giao backup
cho Thịnh kiểm ngay, không chờ hết ba ngày mới xem dữ liệu. Cuối đợt audit tự
kiểm đủ toàn bộ plan/48 đơn vị và báo TRAIN_SELECTED_REPRESENTATION_AMBIGUITY nếu
hai nhãn trùng đúng vector đầu vào của model. Báo cáo giữ cả collision ở 24
feature cũ. Không xóa mẫu, đổi label hoặc bỏ feature để làm mất cảnh báo. Chỉ
được stage/train khi raw audit và exact review đạt; khả năng phân biệt thực tế
phải đọc sau train, không bảo đảm bằng số lượng run.

Đây là dữ liệu TRAIN/development để bắt đầu train và kiểm khả năng phân biệt.
Không thu tập validation hay locked test trong ngân sách này. Chỉ có ba nhóm
hostname/ngày UTC độc lập cho mỗi family; 48 run không phải 48 nhóm độc lập.
Không tạo nhóm giả bằng đổi seed, user, snapshot hoặc environment_id trong cùng
ngày. Không chia ngẫu nhiên run cùng ngày sang hai fold. Toàn bộ 48 run thuộc TRAIN.

Notebook dùng grouped CV theo ba ngày, chọn/calibrate hoàn toàn trong phần fit
của từng fold. Đánh giá OOF là chẩn đoán quy trình phát triển; threshold cũng được
chọn từ OOF nên số đo tại threshold đó không là nghiệm thu độc lập. Fold có thể
chọn model khác nhau. Model cuối fit lại cả ba ngày chưa có số đo external.
Protocol này kiểm ngày khác, không phải kiểm tương lai theo thứ tự thời gian.
Kết quả ghi NOT_COLLECTED cho validation/test, CI=null,
INSUFFICIENT_EXTERNAL_ASSESSMENT, automation_eligible=false và
deployment_eligible=false. Artifact riêng không nạp vào production ModelRuntime.
Không hứa chất lượng chỉ vì đủ 48 run; nếu feature/nhãn còn chồng lấn phải ghi rõ.

Kiên cài/kiểm bốn VM, chạy hành động lab, giữ raw, clock, receipt, checksum và
backup. Thịnh audit raw, dựng feature, phê duyệt đúng manifest qua GitHub rồi
train trên Colab. Không cần VM thứ năm, Domain Controller, Atomic Red Team hay
API key. Lab đã có thì kiểm điều kiện, không cài đè hoặc downgrade mù quáng.

Raw giữ 24 feature gốc. Dẫn xuất features-v5-http-v1 lưu 56 feature (24 gốc,
20 stream, 12 HTTP/flow/process-context); Account dùng 10 đầu vào và C2 dùng 24
đầu vào trong feature_schema_http.json. Hành vi GET/POST chỉ gửi byte Z vô hại.
Malicious là profile lab, không chứng minh ý định. DNS pilot kiểm đường log,
không chứng minh phát hiện DNS-C2 tổng quát. Không bỏ guard để có PASS.

Bash chạy user thường có sudo; Windows PowerShell 5.1 64-bit Administrator khi
chỉ định. Sửa NIC/firewall ở console VMware có snapshot. Không thay cursor/raw,
ngày giờ, nhãn hay kết quả bằng tay. Biến mất khi đóng terminal thì đọc state;
không START/chạy actor lại một run đã tồn tại.

## 1. Lịch thực hiện và điều kiện chuyển bước

| Mốc | Công việc | Quota hợp lệ |
|---|---|---|
| Ngày UTC 1, đầu buổi | Kiểm lab mục 4–10, đăng ký lịch mục 11, bốn pilot mới và G7 mục 12–13 | Pilot không tính quota |
| Ngày UTC 1 | Thu bốn context/family theo plan, mỗi context hai nhãn | 16 run, bốn mỗi nhóm |
| Ngày UTC 2 | Preflight lại; thu bốn context/family tiếp theo | 32 lũy kế, tám mỗi nhóm |
| Ngày UTC 3 | Preflight lại; thu bốn context/family cuối, kiểm và backup | 48 lũy kế, 12 mỗi nhóm |
| Sau bàn giao | Thịnh audit → build → exact review GitHub → stage → Colab | Train phát triển |

Một run cần dự trù khoảng 10 phút: đợi bucket sạch, action window 300 giây và
grace 60 giây, cùng kiểm/luân chuyển log. 48 run khoảng tám giờ capture;
với lab đã dựng, dự trù tổng 10–14 giờ thao tác trong ba ngày, cộng retry nếu lỗi.
Ngày đầu khoảng 5–7 giờ gồm pilot/G7; hai ngày sau khoảng 3–4 giờ/ngày là lịch
dự phòng thực tế, không cam kết thời gian máy chưa kiểm. Thu tuần tự một active
run; không chạy song song cho nhanh. Không giảm 300/60 giây hoặc bỏ provenance.

Ba ngày là ba ngày UTC thực (07:00 hôm nay–06:59 hôm sau giờ Việt Nam). Hoàn tất
G7 đầu ngày 1 rồi mới lấy quota cùng ngày. Tránh 23:45–00:15 UTC (06:45–07:15 VN).
Đăng ký ngày 1 khi chắc đủ thời gian; nếu chưa sẵn lab thì phần cài đặt phải làm
trước ngày 1. Có thể chọn ngày bắt đầu khác, không dời ngày đã đóng băng sau thu.

Thực hiện tuần tự mục 4–10 → 11 → 12–13 → 14 → 15–17 → 18. Lỗi bước trước thì
dừng, giữ evidence. Bốn pilot mới cần một lần trên nguồn/giao thức/kế hoạch mới;
không lặp cả bốn trước từng run nếu source/runtime/G7 còn nguyên và hợp lệ.
G7 chứng minh lab/công cụ, không thay audit 48 run hoặc chất lượng mô hình.

## 2. Kiến trúc và tuyến dữ liệu

| VM | Hostname | VMnet8 management | Data NIC |
|---|---|---|---|
| Kali | ATTACK-LAB |192.168.58.132|10.40.0.10/24 VMnet2|
| Windows 11 | WIN11-TARGET |192.168.58.148|10.20.0.10/24 VMnet3|
| Ubuntu Wazuh + Collector | SOC-AI |192.168.58.147|Không cần|
| Ubuntu Suricata/router | NET-SENSOR |192.168.58.150|10.40.0.1 VMnet2;10.20.0.1 VMnet3|

Windows Security/Sysmon → Wazuh Agent → Wazuh Manager Archives JSON → Collector.
Windows ↔ Kali đi qua router NET-SENSOR → Suricata EVE → Wazuh Agent → Archives.
Không coi đặt NIC cùng VMnet là Suricata tự nhìn thấy mọi traffic. VMnet2/3 không
NAT, bridge, DHCP hoặc host adapter. Management chỉ phục vụ quản trị/Wazuh/NTP.

## 3. Các cổng kiểm soát

G0 phần cứng/mạng/disk; G1 tag/full SHA/tree sạch/runtime; G2 Agent/Archives;
G3 Security/Sysmon/EVE/HTTP/DNS/final-flow; G4 clock thật; G5 enrolled context;
G6 bốn pilot và restore; G7 acceptance v3 gắn toàn bộ kế hoạch; G8 audit raw,
56 feature, split, nguồn và đúng manifest; sau đó mới train.

Không chép record acceptance hay READY từ bộ cũ. Cấu hình mới duy nhất cho đợt này
là config/development-sources.yaml, catalog mới là development-catalog.yaml.
Không dùng operator-logs/collection-sources-active.yaml của đợt cũ. Không git pull,
thay source, nâng package hay đổi grace trong đợt đã đóng băng. Phải release lại
nếu phát hiện cần thay phần có ảnh hưởng; giữ nguyên dữ liệu cũ để điều tra.

## 4. Chuẩn bị và snapshot

Khuyến nghị SOC-AI và NET-SENSOR dùng Ubuntu Server 24.04 LTS x86_64 vì đây là bản
Ubuntu nằm trong danh sách hỗ trợ của Wazuh 4.14. Không dùng dữ liệu cá nhân hoặc tài
khoản thật trong lab.

Tài nguyên khởi điểm:

- SOC-AI: tối thiểu 4 vCPU, 8 GB RAM, 80 GB disk cho Wazuh all-in-one; khuyến nghị
  12–16 GB RAM nếu chạy đồng thời Docker, n8n và API. Trong lúc thu dữ liệu nên dừng
  dịch vụ Week 2 không cần thiết để tránh OOM và I/O contention.
- Windows 11: 4 vCPU, 8 GB RAM, 80 GB disk.
- NET-SENSOR: 2 vCPU, 4 GB RAM, 40 GB disk.
- Kali: 2 vCPU, 4 GB RAM, 40 GB disk.

### 4.1 Tạo mới bốn VM trong VMware Workstation

1. Tải ISO x86_64 từ các trang chính thức: Ubuntu Server 24.04 LTS tại
   https://releases.ubuntu.com/24.04/ ; Windows 11 ISO tại
   https://www.microsoft.com/software-download/windows11 ; Kali Installer tại
   https://www.kali.org/get-kali/ . Chọn đúng OS/architecture trong installer, không
   dựa chỉ vào tiêu đề trang. Lưu filename/version/SHA256SUMS; đối chiếu hash bằng
   `Get-FileHash <ISO> -Algorithm SHA256` trên host. Không dùng ISO chỉnh sửa từ nguồn khác.
2. Chọn `File > New Virtual Machine > Custom`, EFI/UEFI, rồi gắn ISO.
3. Tạo đúng bốn VM, cấp CPU/RAM/disk theo bảng trên; disk dùng một file hoặc split đều
   được nhưng phải còn ít nhất 30 GB trống trên host trong suốt đợt thu.
4. Ubuntu dùng bản Server 24.04 LTS, chọn `Install OpenSSH server`; Kali dùng bản stable;
   Windows 11 bật TPM/Secure Boot theo yêu cầu của installer.
5. Chỉ gắn một NIC VMnet8 khi cài OS. Sau khi cập nhật xong mới shutdown và gắn NIC dữ
   liệu theo mục 5 để tránh chọn nhầm default route.
6. Không bật shared folders/clipboard trên máy mục tiêu nếu ảnh hoặc dataset có thể chứa
   thông tin nhạy cảm. Không bridge lab ra mạng cơ quan/trường.

Sau lần boot đầu trên Ubuntu/Kali:

```bash
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y open-vm-tools openssh-server curl git jq gnupg python3 python3-venv python3-pip nodejs
node --version
sudo systemctl enable --now ssh
grep '^PRETTY_NAME=' /etc/os-release
if [ -f /var/run/reboot-required ]; then
  echo 'REBOOT REQUIRED: reboot Linux now, then resume setup from the next section'
fi
```

Trên hai VM Ubuntu, `. /etc/os-release; test "$ID" = ubuntu; test "$VERSION_ID" = 24.04` phải đạt; PRETTY_NAME có thể kèm số point release như 24.04.3 LTS. Nếu đang là Ubuntu 26.04 hoặc một bản chưa
nằm trong ma trận hỗ trợ hiện hành của Wazuh, dừng và cài lại 24.04; không cố cài Wazuh
rồi dùng kết quả lỗi làm dữ liệu.

Đặt hostname:

```bash
# CHỈ SOC-AI chạy dòng này:
sudo hostnamectl set-hostname SOC-AI
```

NET-SENSOR:

```bash
sudo hostnamectl set-hostname NET-SENSOR
```

Kali:

```bash
sudo hostnamectl set-hostname ATTACK-LAB
```

Trên Windows PowerShell (Administrator), đặt tên rồi reboot:

```powershell
Rename-Computer -NewName WIN11-TARGET -Restart
```

Sau reboot, chụp `hostname` và IP management. Trong `Virtual Network Editor > VMnet8 >
DHCP Settings`, chỉnh dải DHCP để **không chứa** `.132`, `.147`, `.148`, `.150`, rồi đặt
bốn địa chỉ này tĩnh trên guest. Trước khi đặt, tắt VM cần gán và kiểm tra địa chỉ chưa bị
dùng bằng `ping` và bảng ARP trên host. Gateway/DNS phải chép từ `Virtual Network Editor`;
không tự đoán. Ghi ba giá trị `VMNET8_SUBNET`, `VMNET8_GATEWAY`, `VMNET8_DNS` vào biên
bản lab. Sau khi đặt tĩnh, reboot từng VM và xác nhận địa chỉ không đổi. Nếu chưa thực
hiện đủ bước này thì các địa chỉ ở phần sau chưa phải điều kiện đảm bảo và không được thu.

Trên Ubuntu Server, xác định NIC management bằng `ip route show default`, sao lưu
`/etc/netplan`, rồi sửa **file đang khai báo NIC đó** bằng `sudoedit`; không tạo declaration
thứ hai. Mẫu dưới dùng giá trị gateway/DNS đã ghi từ VMware (thay `ens33`):

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses: [192.168.58.147/24] # SOC-AI; NET-SENSOR dùng .150
      routes:
        - to: default
          via: <VMNET8_GATEWAY>
      nameservers:
        addresses: [<VMNET8_DNS>]
```

Chạy `sudo netplan generate`, rồi `sudo netplan try --timeout 120` từ console VMware;
chỉ xác nhận khi ping gateway và host thành công. Trên Kali, thay đúng connection/NIC:

```bash
MGMT_IF=eth0
MGMT_CON=$(nmcli -g GENERAL.CONNECTION device show "$MGMT_IF")
sudo nmcli connection modify "$MGMT_CON" ipv4.method manual \
  ipv4.addresses 192.168.58.132/24 \
  ipv4.gateway '<VMNET8_GATEWAY>' ipv4.dns '<VMNET8_DNS>'
sudo nmcli connection up "$MGMT_CON"
```

Trên Windows PowerShell Administrator, thay alias/MAC đúng NIC VMnet8 và giá trị đã ghi:

```powershell
$MgmtIf = 'Ethernet'
Set-NetIPInterface -InterfaceAlias $MgmtIf -AddressFamily IPv4 -Dhcp Disabled
Get-NetIPAddress -InterfaceAlias $MgmtIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias $MgmtIf -IPAddress 192.168.58.148 `
  -PrefixLength 24 -DefaultGateway '<VMNET8_GATEWAY>'
Set-DnsClientServerAddress -InterfaceAlias $MgmtIf `
  -ServerAddresses '<VMNET8_DNS>'
```

Không dán literal `<VMNET8_GATEWAY>`/`<VMNET8_DNS>`; thay bằng giá trị thật trước khi
chạy. SOC-AI dùng `.147`, NET-SENSOR `.150`, Kali `.132`, Windows `.148`.

Trên mọi Linux VM:

```bash
hostnamectl
ip -br address
timedatectl status
sudo timedatectl set-timezone Asia/Ho_Chi_Minh
sudo timedatectl set-ntp true
timedatectl show -p NTPSynchronized --value
```

Trên Windows PowerShell (Administrator):

```powershell
hostname
Get-NetIPConfiguration
Get-Date
Set-TimeZone -Id "SE Asia Standard Time"
w32tm /resync
```

Tạo snapshot `00-BASELINE` khi bốn VM đã cập nhật, thời gian đúng và chưa chạy kịch
bản. Tạo snapshot `01-TELEMETRY-READY` sau khi đạt G4.

## 5. Cấu hình mạng quan sát

### 5.1 VMware

Trong Virtual Network Editor, tạo:

- VMnet8: NAT/management `192.168.58.0/24`.
- VMnet2: Host-only `10.40.0.0/24`, tắt DHCP và bỏ chọn
  `Connect a host virtual adapter to this network`.
- VMnet3: Host-only `10.20.0.0/24`, tắt DHCP và bỏ chọn
  `Connect a host virtual adapter to this network`.

Hai mạng dữ liệu không được có adapter host dùng `10.40.0.1` hoặc `10.20.0.1`, vì hai
địa chỉ đó thuộc NET-SENSOR. Trên host PowerShell (Administrator), xác nhận adapter cũ
đã biến mất hoặc bị disable:

```powershell
Get-NetAdapter -Name 'VMware Network Adapter VMnet2','VMware Network Adapter VMnet3' `
  -ErrorAction SilentlyContinue | Select-Object Name,Status,MacAddress
```

Nếu vẫn còn adapter host ở trạng thái `Up`, quay lại Virtual Network Editor và bỏ kết
nối host; không chỉ đổi IP để che xung đột.

Gắn NIC:

- Kali: VMnet8 + VMnet2.
- Windows: VMnet8 + VMnet3.
- SOC-AI: VMnet8.
- NET-SENSOR: VMnet8 + VMnet2 + VMnet3.

Trước khi boot, mở `VM > Settings > Network Adapter > Advanced` và ghi MAC của từng
NIC. Sau boot, đối chiếu MAC bằng `ip -br link` trên Linux và
`Get-NetAdapter | Format-Table Name,MacAddress,Status` trên Windows. Lập bảng
`MAC -> VMnet -> tên interface` trong biên bản. Không suy tên NIC theo thứ tự. Trong ví
dụ dưới đây, NET-SENSOR dùng `ens37` phía Kali và `ens38` phía Windows; chỉ dùng các
tên đó nếu MAC đã khớp.

### 5.2 NET-SENSOR

Trước khi tạo file mới, sao lưu và kiểm tra các NIC dữ liệu chưa được khai báo ở file
Netplan khác:

```bash
sudo cp -a /etc/netplan "/etc/netplan.backup.$(date -u +%Y%m%dT%H%M%SZ)"
sudo netplan get
sudo grep -R -nE 'ens37|ens38' /etc/netplan || true
```

Nếu `ens37`/`ens38` đã xuất hiện, sửa đúng file hiện hữu thay vì tạo khai báo trùng.
Nếu chưa có, tạo `/etc/netplan/60-datn-data.yaml` (thay đúng tên NIC; giữ cấu hình
management đang hoạt động trong file Netplan hiện hữu):

```yaml
network:
  version: 2
  ethernets:
    ens37:
      dhcp4: false
      addresses: [10.40.0.1/24]
    ens38:
      dhcp4: false
      addresses: [10.20.0.1/24]
```

Không đặt default gateway trên hai NIC dữ liệu. Kiểm tra trước khi apply:

Mở sẵn một console VMware thứ hai, sau đó chạy:

```bash
sudo netplan generate
sudo netplan try --timeout 120
```

Trong lúc `netplan try` đang chờ, dùng console thứ hai chạy `ip -br address` và
`ip route`; chỉ bấm `ENTER` xác nhận ở console thứ nhất khi hai IP dữ liệu đúng và chỉ
có một default route qua VMnet8. Nếu sai, không xác nhận để Netplan tự rollback. Sau khi
xác nhận mới chạy lại `ip -br address` và `ip route` để lưu bằng chứng.

Bật chuyển tiếp IPv 4:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' | sudo tee /etc/sysctl.d/99-datn-router.conf
sudo sysctl --system
```

Nếu dùng UFW, mở SSH trước rồi mới bật route:

```bash
sudo ufw allow 22/tcp
sudo ufw route allow in on ens37 out on ens38 from 10.40.0.0/24 to 10.20.0.0/24
sudo ufw route allow in on ens38 out on ens37 from 10.20.0.0/24 to 10.40.0.0/24
sudo ufw enable
sudo ufw status verbose
```

### 5.3 Kali

Thay `eth1` bằng NIC VMnet2 thực tế. Khối dưới có thể chạy lại: nếu profile đã tồn
tại thì chỉ cập nhật, không tạo profile trùng.

```bash
DATA_IF=eth1
if nmcli -t -f NAME connection show | grep -qx 'ATTACK-LAB'; then
  sudo nmcli connection modify ATTACK-LAB \
    connection.interface-name "$DATA_IF" ipv4.method manual \
    ipv4.addresses 10.40.0.10/24 \
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv4.gateway "" \
    ipv4.never-default yes ipv4.ignore-auto-dns yes ipv6.method disabled
else
  sudo nmcli connection add type ethernet ifname "$DATA_IF" con-name ATTACK-LAB \
    ipv4.method manual ipv4.addresses 10.40.0.10/24 \
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv4.gateway "" \
    ipv4.never-default yes ipv4.ignore-auto-dns yes ipv6.method disabled
fi
sudo nmcli connection up ATTACK-LAB
ip route get 10.20.0.10
```

### 5.4 Windows 11

Mở PowerShell Administrator tại console VMware. Đối chiếu MAC trước khi nhập alias:

```powershell
$ErrorActionPreference = 'Stop'
Get-NetAdapter | Format-Table Name,MacAddress,Status
$DataIf = Read-Host 'Alias cua NIC VMnet3 da doi chieu MAC (vi du Ethernet 2)'
$adapter = Get-NetAdapter -Name $DataIf -ErrorAction Stop
$adapter | Format-List Name,MacAddress,Status
$confirm = Read-Host 'Go VMNET3 de xac nhan day la NIC du lieu, KHONG phai management'
if ($confirm -cne 'VMNET3') { throw 'NIC identification not confirmed' }
Set-NetIPInterface -InterfaceAlias $DataIf -AddressFamily IPv4 -Dhcp Disabled
# Chi bo APIPA tu NIC du lieu vua xac nhan; giu va bao loi moi IP khac.
Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object IPAddress -Like '169.254.*' |
  Remove-NetIPAddress -Confirm:$false
$unexpectedIp = Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -ne '10.20.0.10' -and $_.PrefixOrigin -ne 'WellKnown'
  }
if ($unexpectedIp) { throw "Unexpected IPv4 address exists on $DataIf" }
if (Get-NetRoute -InterfaceAlias $DataIf -DestinationPrefix '0.0.0.0/0' `
  -ErrorAction SilentlyContinue) { throw 'Data NIC must not have a default gateway' }
if (-not (Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '10.20.0.10')) {
  New-NetIPAddress -InterfaceAlias $DataIf -IPAddress 10.20.0.10 -PrefixLength 24
}
$routes = @(Get-NetRoute -DestinationPrefix '10.40.0.0/24' -ErrorAction SilentlyContinue)
if ($routes | Where-Object {
  $_.InterfaceAlias -ne $DataIf -or $_.NextHop -ne '10.20.0.1'
}) { throw 'Competing route to 10.40.0.0/24 exists' }
if (-not $routes) {
  New-NetRoute -DestinationPrefix 10.40.0.0/24 -InterfaceAlias $DataIf `
    -NextHop 10.20.0.1 -PolicyStore PersistentStore
}
Get-NetRoute -DestinationPrefix 10.40.0.0/24
Test-NetConnection 10.40.0.10
tracert -d 10.40.0.10
```

Đạt G1 khi route dùng `10.20.0.1` trên NIC VMnet3 và `tracert` tới Kali. Nếu ICMP bị
firewall chặn, không suy route đúng chỉ từ timeout: đối chiếu `Get-NetRoute`, MAC và
canary TCP/DNS tại G4, quan sát cùng traffic ở NIC NET-SENSOR. Không thu qua management.

## 6. Cài SOC-AI

### 6.1 Ma trận Wazuh và quyết định thay đổi

Ma trận tái lập của tài liệu này cố định **4.14.9** theo bản lab đã bàn giao;
đây là lựa chọn phiên bản có ghi nhận, không phải tuyên bố bản mới nhất. Ghi
phiên bản thực trong evidence pilot. Nếu lab đang chạy khác, chốt inventory và
review trước khi thu; không tự downgrade. Ma trận đích: manager, indexer, dashboard
và hai agent Windows/NET-SENSOR đều 4.14.9; gói Debian mục tiêu `4.14.9-1`,
MSI Windows `wazuh-agent-4.14.9-1.msi`. Không tự downgrade máy đang chạy.

Với máy đã cài, kiểm chính xác và dừng nếu bất kỳ gói khác phiên bản:

```bash
set -euo pipefail
for pkg in wazuh-manager wazuh-indexer wazuh-dashboard; do
  test "$(dpkg-query -W -f='${Version}' "$pkg")" = 4.14.9-1 || {
    echo "FAIL: $pkg không phải 4.14.9-1" >&2; exit 1; }
done
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
dpkg-query -W -f='${Package}=${Version}\n' wazuh-manager wazuh-indexer wazuh-dashboard | tee wazuh-package-versions.txt
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard
```

Máy mới: chỉ tiếp tục khi chưa có ba package trên;
không dùng quy trình này để downgrade hay ghi đè máy đang chạy. Cài repository
Wazuh theo hướng dẫn chính thức, xác minh fingerprint khóa với nguồn Wazuh tin cậy
trước khi tin khóa; dừng nếu không xác minh được. Dùng các lệnh cài key/repository
ở đầu mục 8.2 trên SOC (không chạy lệnh cài agent ở đó). APT phải xác minh chữ ký metadata
repository; không dùng `trusted=yes` hoặc cho phép gói không xác thực. Sau khi đã
cấu hình repository ký và chạy `apt update`, kiểm có đúng cả ba package 4.14.9-1.

```bash
set -euo pipefail
for pkg in wazuh-manager wazuh-indexer wazuh-dashboard; do
  if dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null | grep -qx installed; then
    echo "FAIL: $pkg đã cài; kiểm riêng, không tự downgrade" >&2; exit 1
  fi
  apt-cache madison "$pkg" | awk -F ' *\| *' '$2 == "4.14.9-1" {found=1} END {exit !found}' || {
    echo "FAIL: thiếu $pkg=4.14.9-1 trong repository đã xác thực" >&2; exit 1; }
done
sudo tee /etc/apt/preferences.d/datn-wazuh-pin >/dev/null <<'PIN'
Package: wazuh-manager wazuh-indexer wazuh-dashboard
Pin: version 4.14.9-1
Pin-Priority: 1001

Package: wazuh-manager wazuh-indexer wazuh-dashboard
Pin: version *
Pin-Priority: -1
PIN
apt-cache policy wazuh-manager wazuh-indexer wazuh-dashboard
# URL /4.14/wazuh-install.sh is rolling (now 4.14.10), do not use it.
TOOLCHAIN="$HOME/datn-toolchain/wazuh-assistant-4.14.9"
test ! -e "$TOOLCHAIN"
git clone --branch v4.14.9 --single-branch \
  https://github.com/wazuh/wazuh-installation-assistant.git "$TOOLCHAIN"
test "$(git -C "$TOOLCHAIN" rev-parse 'v4.14.9^{commit}')" = 8739c47527bf18563eba44140db9a5e36568cee0
git -C "$TOOLCHAIN" checkout --detach 8739c47527bf18563eba44140db9a5e36568cee0
test -z "$(git -C "$TOOLCHAIN" status --porcelain)"
curl -fL --retry 2 --max-time 30 \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/init/dist-detect.sh \
  -o "$TOOLCHAIN/dist-detect-pinned.sh"
bash "$TOOLCHAIN/builder.sh" -i
bash -n "$TOOLCHAIN/wazuh-install.sh"
python3 - "$TOOLCHAIN" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
expected = "\n".join(s for s in (root / "dist-detect-pinned.sh").read_text().splitlines()
                     if not s.startswith("#"))
if expected not in (root / "wazuh-install.sh").read_text():
    raise SystemExit("Installer dist-detect differs from pinned v4.14.9")
PY
grep -Fx 'readonly wazuh_version="4.14.9"' "$TOOLCHAIN/wazuh-install.sh"
sha256sum "$TOOLCHAIN/wazuh-install.sh" > "$TOOLCHAIN/installer.sha256"
sudo bash "$TOOLCHAIN/wazuh-install.sh" -a
for pkg in wazuh-manager wazuh-indexer wazuh-dashboard; do
  test "$(dpkg-query -W -f='${Version}' "$pkg")" = 4.14.9-1 || {
    echo "FAIL: $pkg sai phiên bản; dừng pilot" >&2; exit 1; }
done
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
dpkg-query -W -f='${Package}=${Version}\n' wazuh-manager wazuh-indexer wazuh-dashboard filebeat | tee wazuh-package-versions.txt
dpkg-query -W -f='${Version}' filebeat | grep -E '^7\.10\.2([-.]|$)'
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

Filebeat do assistant dùng phiên bản 7.10.2; kiểm version thực tế trong output và
dừng nếu khác. Lưu installer, SHA-256, pin, metadata APT có chữ ký, log cài và
phiên bản các gói vào evidence toolchain (không lưu mật khẩu). Nếu URL thay hash,
chữ ký không hợp lệ, thiếu package hoặc version sai: dừng và yêu cầu artifact đã
xác minh, không bỏ kiểm tra. Source assistant được pin full commit để tránh rolling URL đổi patch;
không khẳng định tái lập toàn bộ dependency nếu chưa lưu và xác minh artifact của
chúng. Các agent cũng phải giữ bằng chứng SHA-256 và chữ ký nguồn chính thức.
Lưu thông tin đăng nhập từ output cài đặt ở nơi riêng, không đưa mật khẩu vào repo hoặc
ảnh báo cáo. Dashboard: `https://192.168.58.147`.

Sao lưu rồi mở `/var/ossec/etc/ossec.conf`; trong khối `<global>` đặt:

```bash
sudo cp -a /var/ossec/etc/ossec.conf \
  "/var/ossec/etc/ossec.conf.bak.$(date -u +%Y%m%dT%H%M%SZ)"
sudoedit /var/ossec/etc/ossec.conf
```

```xml
<logall>no</logall>
<logall_json>yes</logall_json>
```

Sau đó:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-control restart
sudo systemctl is-active wazuh-manager
sudo ls -ld /var/ossec/logs/archives
```

`archives.json` có thể chỉ xuất hiện sau event đầu tiên; kiểm tra nội dung file ở G2 khi
agent đã gửi dữ liệu, không tự tạo file rỗng để vượt kiểm tra.

`logall_json` làm tăng disk I/O và dung lượng; chỉ bật trong đợt thu lab, theo dõi bằng
`df -h /var/ossec` và tắt sau khi đã đóng gói dữ liệu. Không chạy một scenario qua thời
điểm Archives rotate; nếu source rotate/truncate, collector sẽ từ chối run đó.


### 6.2 Checkout mới từ GitHub, cài runtime

Khi còn Internet/NAT và không có active run, tạo checkout mới v4. Giữ dữ liệu
cũ ngoài checkout. COLLECTION_BASELINE_COMMIT lấy từ tag này, không dùng 136 bb 754.

```bash
set -euo pipefail
test "$(id -u)" -ne 0
PROJECT_ROOT="$HOME/datn-ai-soar-development-3day"
COLLECTION_TAG=development-collection-v1.0.0-candidate.1
test ! -e "$PROJECT_ROOT"
git clone --branch "$COLLECTION_TAG" --single-branch https://github.com/lethinhlord/Repo.git "$PROJECT_ROOT"
cd "$PROJECT_ROOT"
test "$(git remote get-url origin)" = https://github.com/lethinhlord/Repo.git
test "$(git cat-file -t "refs/tags/$COLLECTION_TAG")" = tag
COLLECTION_BASELINE_COMMIT=$(git rev-parse "refs/tags/$COLLECTION_TAG^{commit}")
test "$(git rev-parse HEAD)" = "$COLLECTION_BASELINE_COMMIT"
git checkout --detach "$COLLECTION_BASELINE_COMMIT"
test -z "$(git status --porcelain --untracked-files=all)"
mkdir -p operator-logs/releases run-drafts evidence/scenario-runs
printf '%s\n' "$COLLECTION_TAG" > operator-logs/releases/source-tag.txt
printf '%s\n' "$COLLECTION_BASELINE_COMMIT" > operator-logs/releases/source-commit.txt
bash scripts/bootstrap_ml.sh
.venv-ml/bin/python -m pip check
node --version
.venv-ml/bin/python -m pytest -q
.venv-ml/bin/python -m scripts.collection_release candidate --tag "$COLLECTION_TAG" --check-remote > operator-logs/releases/candidate.json
cat operator-logs/releases/candidate.json
.venv-ml/bin/python - <<'PY'
from pathlib import Path
from ml.development_sources import require_collection_source
review, commit = require_collection_source(Path.cwd(), 'development-collection-v1.0.0-candidate.1')
print('SOURCE_COLLECTION_READY', commit, review['status'])
PY
```

Phải đúng fullSHA/tag/hash toàn tracked tree/runtime. Test Windows-native có thể
SKIP trên Ubuntu, ghi kết quả thực, không copy số từ Thịnh. --check-remote làm khi
còn Internet; lúc thu chỉ kiểm local. Không sửa tracked file hoặc nâng package
giữa pilot/acceptance/trainable; cần đổi phải release/checkout/nghiệm thu mới.

Cho user đọc Archives, thoát SSH rồi đăng nhập lại:

```bash
sudo usermod -aG wazuh "$(id -un)"
id "$(id -un)"
```

Phiên mới, sau khi agent đã gửi event:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
id
test -r /var/ossec/logs/archives/archives.json
stat -c '%U %G %a %n' /var/ossec/logs/archives/archives.json
```

Không chmod777, chạy repo bằng root hay tạo Archives giả/rỗng. Kiểm quyền sau
logrotate. Không mở run qua vùng 23:45–00:15 UTC.

### 6.3 Bảo trì nguồn

Không git pull trong checkout đang thu. Đóng/abort run có lý do, backup rồi dùng
checkout/tag mới nếu cần thay code/config. Không ghép raw các release vào quota
mới. Các release và pilot trước đây chỉ là bằng chứng lịch sử. Phục hồi pilot
cũ không thay quy trình hiện hành mục14 hoặc acceptance mới của đợt này.


### 6.4 Phân biệt collector và dịch vụ AI

Đợt này thu raw bằng collector thật, chưa cần model đã train hoặc API key. Không
thay n8n production, không activate mock thành model thật. UI n8n hiện hữu là
minh chứng hệ thống điều phối riêng; nó không tạo ground truth hay quota dataset.
Kiểm đủ RAM/disk và dừng dịch vụ không cần thiết trước buổi thu để tránh mất log.

## 7. Cài WIN11-TARGET

### 7.0 Chuẩn bị công cụ kiểm Windows từ đúng checkout SOC-AI

Mở Windows PowerShell 64-bit bằng Administrator. Cài OpenSSH Client nếu thiếu rồi
copy helper từ checkout đã kiểm SHA ở SOC-AI; không lấy script từ một nhánh khác:

```powershell
$ErrorActionPreference = 'Stop'
$client = Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
if ($client.State -ne 'Installed') {
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
}
New-Item -ItemType Directory -Force C:\DATN | Out-Null
$SocUser = Read-Host 'SOC-AI SSH username'
scp "${SocUser}@192.168.58.147:datn-ai-soar-development-3day/scripts/Test-DatnWindowsPreflight.ps1" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw 'Cannot copy the Windows preflight helper' }
Get-FileHash C:\DATN\Test-DatnWindowsPreflight.ps1 -Algorithm SHA256
```

Đối chiếu hash với `sha256sum scripts/Test-DatnWindowsPreflight.ps1` trên SOC-AI.
Helper chỉ đọc trạng thái; quyền sửa user/firewall nằm ở các bước riêng bên dưới.

Từ SOC-AI, chạy sha256sum cho config/sysmon-datn.xml và
config/wazuh-windows-localfile.xml; trên Windows dùng Get-FileHash từng file vừa
copy và đối chiếu hai SHA trước khi cài. Sai một byte thì dừng, copy lại từ checkout
đã pin. Tương tự helper Test-DatnWindowsPreflight.ps1 phải khớp SHA hiển thị ở SOC.


Trước G7, kiểm curl.exe mà runner sẽ tìm thấy đầu tiên trên PATH. HTTP v2 dùng
--rate/--next và giao thức FILE để giữ process sống đủ cho Sysmon, bên cạnh HTTP.
Windows11 cũ có thể thiếu tùy chọn; không chờ đến khi thu mới phát hiện:

```powershell
$ErrorActionPreference='Stop'
$CurlExe=@(Get-Command curl.exe -CommandType Application -ErrorAction Stop)[0].Source
$CurlHelp=(& $CurlExe --help all | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'curl help failed' }
foreach ($flag in '--rate','--next','--fail-early','--http1.0','--data-binary') {
  if ($CurlHelp -notmatch [regex]::Escape($flag)) { throw "curl lacks required option $flag" }
}
$CurlVersion=(& $CurlExe --version | Out-String)
if ($LASTEXITCODE -ne 0 -or $CurlVersion -notmatch '\bfile\b' -or $CurlVersion -notmatch '\bhttp\b') { throw 'curl must support FILE and HTTP' }
if (-not (Test-Path -LiteralPath C:\Windows\win.ini -PathType Leaf)) { throw 'Expected process-hold file is missing' }
$CurlVersion | Set-Content C:\DATN\curl-version.txt -Encoding ascii
Get-FileHash -LiteralPath $CurlExe -Algorithm SHA256
Get-Content C:\DATN\curl-version.txt
```

Nếu thiếu, cài Windows Updates chính thức trên VM trước cô lập/G7 để cập nhật
curl đi kèm hệ điều hành, reboot rồi chạy lại kiểm tra. Tài liệu tùy chọn chuẩn:
https://curl.se/docs/manpage.html . Không tải curl từ link không rõ nguồn, không
thay executable/PATH trong đợt đã đóng băng. Lưu path/version/hash trong inventory
toolchain và gửi cùng bàn giao; SYS/HTTP canary vẫn phải kiểm thật sau đó.

### 7.1 Tài khoản lab và audit policy

Mở PowerShell bằng quyền Administrator. Tạo các tài khoản **chỉ dùng trong lab** bằng
`New-LocalUser`; không ghi mật khẩu vào hướng dẫn, Git hoặc manifest:

```powershell
$ErrorActionPreference = 'Stop'
function Ensure-DatnLabUser([string]$Name, [string]$Description) {
  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if (-not $existing) {
    $password = Read-Host "Password for $Name" -AsSecureString
    New-LocalUser -Name $Name -Password $password -Description $Description | Out-Null
  } else {
    Enable-LocalUser -Name $Name
    Set-LocalUser -Name $Name -Description $Description
  }
  $verified = Get-LocalUser -Name $Name
  if (-not $verified.Enabled) { throw "Lab account is disabled: $Name" }
  $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
  if (-not (Get-LocalGroupMember -Group $usersGroup | Where-Object SID -eq $verified.SID)) {
    Add-LocalGroupMember -Group $usersGroup -Member $verified
  }
}
Ensure-DatnLabUser datn_benign 'DATN benign lab account'
Ensure-DatnLabUser datn_attack 'DATN attack decoy'
1..3 | ForEach-Object {
  Ensure-DatnLabUser ("datn_lab{0:D2}" -f $_) 'DATN neutral training account'
}
$LogonAuditGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
auditpol /set /subcategory:$LogonAuditGuid /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) { throw 'Cannot enable Logon audit policy' }
auditpol /get /subcategory:$LogonAuditGuid
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify Logon audit policy' }
```

GUID làm cho lệnh không phụ thuộc ngôn ngữ Windows. Xuất policy gốc, sau đó vô hiệu hóa
lockout **chỉ trên VM target dùng riêng cho lab** để các các run nhiều lần sai không bị phụ
thuộc trạng thái của run trước:

```powershell
New-Item -ItemType Directory -Force C:\DATN | Out-Null
secedit /export /cfg C:\DATN\before-collection-security.inf /areas SECURITYPOLICY /quiet
if ($LASTEXITCODE -ne 0) { throw 'Cannot export original security policy' }
net accounts /lockoutthreshold:0
if ($LASTEXITCODE -ne 0) { throw 'Cannot disable lab account lockout' }
net accounts
```

Output phải hiện `Lockout threshold: Never` (hoặc giá trị tương đương theo ngôn ngữ hệ
thống). Không được tự giảm số attempt: collector kiểm đúng số trong catalog.

Các account remote profile của cả hai nhãn dùng SMB từ duy nhất Kali
`10.40.0.10`, nên mở port 445 chỉ cho địa chỉ đó trên NIC lab. Không bật rule chia sẻ rộng
toàn subnet và không tạo share chứa dữ liệu:

```powershell
$ErrorActionPreference = 'Stop'
Set-Service LanmanServer -StartupType Automatic
Start-Service LanmanServer
if (Get-NetFirewallRule -Name DATN-SMB-From-Kali -ErrorAction SilentlyContinue) {
  Remove-NetFirewallRule -Name DATN-SMB-From-Kali
}
New-NetFirewallRule -Name DATN-SMB-From-Kali `
  -DisplayName 'DATN SMB authentication from Kali only' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 `
  -RemoteAddress 10.40.0.10 -LocalAddress 10.20.0.10 -Profile Any | Out-Null
Get-NetFirewallRule -Name DATN-SMB-From-Kali | Format-List Name,Enabled,Action
& C:\DATN\Test-DatnWindowsPreflight.ps1 -InspectHost -AllowedSource 10.40.0.10
if ($LASTEXITCODE -ne 0) { throw 'Windows firewall preflight needs review' }
```

Nếu helper báo BROAD hoặc INCONCLUSIVE, xem rule cụ thể cùng Profile, InterfaceAlias,
LocalAddress, application và service. Không disable hàng loạt rule UDP/ứng dụng khác.
Rule ngoài profile/interface/address đang dùng không được xem là đang mở SMB; ghi
bằng chứng hiệu lực và xử lý rule thực sự cho phép TCP 445 ngoài Kali. Sau đó vẫn
phải kiểm kết nối từ Kali thành công và từ VM nguồn khác bị từ chối ở mục 10.

Chỉ sau backup/restore đã kiểm, khi không còn run active và đã kết thúc đợt thu, có
thể khôi phục policy gốc bằng lệnh
sau rồi reboot:

```powershell
secedit /configure /db C:\DATN\restore-security.sdb `
  /cfg C:\DATN\before-collection-security.inf /areas SECURITYPOLICY /quiet
if ($LASTEXITCODE -ne 0) { throw 'Cannot restore original security policy' }
Restart-Computer
```

### 7.2 Sysmon

PowerShell phải chạy bằng quyền Administrator. Xác nhận/cài OpenSSH Client theo đúng
Windows Capability trước khi dùng `scp`, sau đó nhập user SSH thực tế của SOC-AI.
Không ghi mật khẩu vào biến hoặc tài liệu:

```powershell
$sshClient = Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
if ($sshClient.State -ne "Installed") {
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}
ssh -V
$SocUser = Read-Host "SOC-AI SSH username"
$SocHome = ssh "${SocUser}@192.168.58.147" 'printf %s "$HOME"'
if ($LASTEXITCODE -ne 0 -or -not $SocHome) { throw "Cannot resolve SOC-AI HOME" }
$SocRepo = "$SocHome/datn-ai-soar-development-3day"
New-Item -ItemType Directory -Force C:\DATN | Out-Null
scp "${SocUser}@192.168.58.147:${SocRepo}/config/sysmon-datn.xml" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw "Cannot copy pinned resource: config/sysmon-datn.xml" }
scp "${SocUser}@192.168.58.147:${SocRepo}/config/wazuh-windows-localfile.xml" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw "Cannot copy pinned resource: config/wazuh-windows-localfile.xml" }
scp "${SocUser}@192.168.58.147:${SocRepo}/scripts/run_dns_scenario.ps1" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw "Cannot copy pinned resource: scripts/run_dns_scenario.ps1" }
$remoteDnsScriptHashLine = ssh "${SocUser}@192.168.58.147" `
  "sha256sum '${SocRepo}/scripts/run_dns_scenario.ps1'"
if ($LASTEXITCODE -ne 0 -or -not $remoteDnsScriptHashLine) {
  throw 'Cannot hash run_dns_scenario.ps1 on SOC-AI'
}
$remoteDnsScriptHash = ($remoteDnsScriptHashLine -split '\s+')[0].ToLower()
$localDnsScriptHash = (Get-FileHash C:\DATN\run_dns_scenario.ps1 `
  -Algorithm SHA256).Hash.ToLower()
if ($localDnsScriptHash -ne $remoteDnsScriptHash) {
  throw 'run_dns_scenario.ps1 does not match the pinned repo copy'
}
$localDnsScriptHash | Set-Content C:\DATN\run_dns_scenario.ps1.sha256.txt -Encoding ascii
foreach ($runnerName in 'run_supplemental_http.ps1','run_training_http.ps1','run_training_account.ps1',
  'run_frozen_windows.ps1','Export-DatnSysmonClockEvidence.ps1') {
  scp "${SocUser}@192.168.58.147:${SocRepo}/scripts/$runnerName" C:\DATN\
  if ($LASTEXITCODE -ne 0) { throw "Cannot copy pinned resource: $runnerName" }
  $remoteLine = ssh "${SocUser}@192.168.58.147" "sha256sum '${SocRepo}/scripts/$runnerName'"
  if ($LASTEXITCODE -ne 0 -or -not $remoteLine) { throw "Cannot hash $runnerName" }
  $expected = ($remoteLine -split '\s+')[0].ToLower()
  $localPath = Join-Path C:\DATN $runnerName
  $actual = (Get-FileHash -LiteralPath $localPath -Algorithm SHA256).Hash.ToLower()
  if ($expected -notmatch '^[0-9a-f]{64}$' -or $actual -ne $expected) {
    throw "Pinned script hash mismatch: $runnerName"
  }
  $actual | Set-Content -LiteralPath "$localPath.sha256.txt" -Encoding ascii
  if (Get-Item -LiteralPath $localPath -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
    Unblock-File -LiteralPath $localPath
  }
}
$executionPolicies = Get-ExecutionPolicy -List
$executionPolicies | Format-Table -AutoSize
$enforcedPolicy = @($executionPolicies | Where-Object {
  $_.Scope -in 'MachinePolicy','UserPolicy' -and
  $_.ExecutionPolicy -in 'AllSigned','Restricted'
})
if ($enforcedPolicy.Count -gt 0) {
  throw 'Group Policy requires an approved signed script or blocks scripts; resolve before collection'
}
$internetZone = Get-Item -LiteralPath C:\DATN\run_dns_scenario.ps1 `
  -Stream Zone.Identifier -ErrorAction SilentlyContinue
if ($internetZone) {
  # Hash has just been verified against the pinned repository copy.
  Unblock-File -LiteralPath C:\DATN\run_dns_scenario.ps1
}
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip `
  -OutFile C:\DATN\Sysmon.zip
Get-FileHash C:\DATN\Sysmon.zip -Algorithm SHA256 |
  Format-List | Out-File C:\DATN\Sysmon.zip.sha256.txt -Encoding ascii
Expand-Archive C:\DATN\Sysmon.zip C:\DATN\Sysmon -Force
$sysmonSignature = Get-AuthenticodeSignature C:\DATN\Sysmon\Sysmon64.exe
if ($sysmonSignature.Status -ne 'Valid' -or
    $sysmonSignature.SignerCertificate.Subject -notmatch 'Microsoft') {
  throw 'Invalid Sysmon executable signature'
}
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  C:\DATN\Sysmon\Sysmon64.exe -c C:\DATN\sysmon-datn.xml
} else {
  C:\DATN\Sysmon\Sysmon64.exe -accepteula -i C:\DATN\sysmon-datn.xml
}
if ($LASTEXITCODE -ne 0) { throw 'Sysmon installation/configuration failed' }
C:\DATN\Sysmon\Sysmon64.exe -c
Get-Service Sysmon64
```

Config repo bật ProcessCreate (ID 1), NetworkConnect (ID 3), ProcessTerminate (ID 5)
và DnsQuery (ID 22). Event 5 cũng được forward qua Wazuh để đóng lifecycle index;
không bỏ query EventID=5 trong localfile. Không
dùng DNS Internet để test. Sau khi dịch vụ Kali ở mục 9 đã chạy, tạo traffic lab (chưa
dùng làm dữ liệu train), sau đó xác nhận:

Windows 11 có thể mặc định `Restricted`. Runner DNS bên dưới dùng
`-ExecutionPolicy RemoteSigned` **chỉ cho child process**, không sửa policy lưu trong
registry. File được copy và đối chiếu SHA-256 trước; chỉ gỡ `Zone.Identifier` của đúng
file đã xác minh. Nếu Group Policy áp `AllSigned`, dùng bản ký bằng chứng thư được
quản trị chấp thuận và chốt lại hash trước khi thu; không vượt Group Policy hoặc đổi
policy toàn máy. Đối chiếu phạm vi và thứ tự ưu tiên tại
[Microsoft about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1).

```powershell
Test-NetConnection 192.168.58.147 -Port 443
Resolve-DnsName www.datn.test -Server 10.40.0.10
Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c whoami' -Wait
1,3,5,22 | ForEach-Object {
  Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=$_
  } -MaxEvents 1 | Select-Object Id,TimeCreated,MachineName
}
```

Nếu ID 3 không có, không tiếp tục: Sysmon mặc định không tự thu NetworkConnect nếu
config không bật đúng event family.

### 7.3 Wazuh Agent 4.14.9

```powershell
Invoke-WebRequest `
  https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi `
  -OutFile C:\DATN\wazuh-agent-4.14.9-1.msi
$wazuhSignature = Get-AuthenticodeSignature C:\DATN\wazuh-agent-4.14.9-1.msi
if ($wazuhSignature.Status -ne 'Valid') { throw 'Invalid Wazuh MSI signature' }
Get-FileHash C:\DATN\wazuh-agent-4.14.9-1.msi -Algorithm SHA256 |
  Format-List | Out-File C:\DATN\wazuh-agent-4.14.9-1.msi.sha256.txt -Encoding ascii
$msiArgs = '/i C:\DATN\wazuh-agent-4.14.9-1.msi /qn /norestart ' +
  'WAZUH_MANAGER="192.168.58.147" WAZUH_REGISTRATION_SERVER="192.168.58.147" ' +
  'WAZUH_AGENT_NAME="WIN11-TARGET" /l*v C:\DATN\wazuh-agent-install.log'
$install = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($install.ExitCode -notin 0,3010) { throw "Wazuh MSI failed: $($install.ExitCode)" }
if ($install.ExitCode -eq 3010) {
  throw 'Installation succeeded; reboot now, then continue ossec.conf setup after login'
}
Get-Service WazuhSvc -ErrorAction Stop
```

Wazuh Windows đã thu `Security` theo mặc định. **Không chèn thêm block Security thứ
hai.** Sao lưu file, đếm block hiện có rồi chỉ chèn đúng một block Sysmon từ
`config/wazuh-windows-localfile.xml` vào bên trong một khối `<ossec_config>`:

```powershell
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $conf "$conf.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
(Select-String -Path $conf -SimpleMatch '<location>Security</location>').Count
(Select-String -Path $conf -SimpleMatch `
  '<location>Microsoft-Windows-Sysmon/Operational</location>').Count
notepad.exe $conf
```

Trước khi sửa, Security phải có đúng một block; sau khi lưu, Sysmon cũng phải có đúng
một block. Nếu count khác 1, dừng và phục hồi backup thay vì restart. Sau đó:

```powershell
$securityCount = (Select-String -Path $conf -SimpleMatch `
  '<location>Security</location>').Count
$sysmonCount = (Select-String -Path $conf -SimpleMatch `
  '<location>Microsoft-Windows-Sysmon/Operational</location>').Count
if ($securityCount -ne 1 -or $sysmonCount -ne 1) {
  throw "ossec.conf must contain exactly one Security and one Sysmon localfile"
}
[xml]$validatedConfig = Get-Content -LiteralPath $conf -Raw
if (-not $validatedConfig.ossec_config) { throw 'ossec.conf XML root is invalid' }
Restart-Service WazuhSvc
Get-Service WazuhSvc
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 30
```

Trên SOC-AI:

```bash
sudo /var/ossec/bin/agent_control -l | grep WIN11-TARGET
sudo jq -c 'select(.agent.name=="WIN11-TARGET")' \
  /var/ossec/logs/archives/archives.json | tail -n 3
```

### 7.4 SSH key chỉ dùng để đo clock

Clock evidence phải được lấy từ SOC-AI mà không dừng giữa chừng để nhập mật khẩu. Cài
OpenSSH Server trên Windows khi lab vẫn còn Internet/NAT; không làm bước này trong cửa
sổ đang thu. Trên SOC-AI, tạo một key riêng (nếu file đã có thì giữ nguyên, không ghi đè):

```bash
set -euo pipefail
CLOCK_KEY="$HOME/.ssh/id_ed25519_datn_clock"
install -d -m 700 "$HOME/.ssh"
if [ ! -f "$CLOCK_KEY" ]; then
  ssh-keygen -t ed25519 -N '' -C datn-clock -f "$CLOCK_KEY"
fi
chmod 600 "$CLOCK_KEY"
cat "$CLOCK_KEY.pub"
```

Copy **đúng một dòng public key vừa in**. Trên Windows PowerShell Administrator, tạo user
không có quyền quản trị và chỉ mở SSH từ IP management của SOC-AI:

```powershell
$ErrorActionPreference = 'Stop'
$server = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
if ($server.State -ne 'Installed') {
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}
if (-not (Get-LocalUser -Name datn_clock -ErrorAction SilentlyContinue)) {
  $password = Read-Host 'One-time strong password for datn_clock' -AsSecureString
  New-LocalUser -Name datn_clock -Password $password `
    -Description 'DATN clock evidence account' | Out-Null
}
$publicKey = Read-Host 'Paste SOC-AI datn-clock public key'
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ datn-clock$') {
  throw 'Unexpected public key format'
}
$sshDir = 'C:\Users\datn_clock\.ssh'
New-Item -ItemType Directory -Force $sshDir | Out-Null
Set-Content -LiteralPath "$sshDir\authorized_keys" -Value $publicKey `
  -Encoding ascii -NoNewline
$principal = "$env:COMPUTERNAME\datn_clock"
icacls $sshDir /inheritance:r /grant:r "${principal}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
icacls "$sshDir\authorized_keys" /inheritance:r /grant:r "${principal}:F" 'SYSTEM:F' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
Get-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue |
  Disable-NetFirewallRule
if (Get-NetFirewallRule -Name DATN-Clock-SSH -ErrorAction SilentlyContinue) {
  Remove-NetFirewallRule -Name DATN-Clock-SSH
}
New-NetFirewallRule -Name DATN-Clock-SSH -DisplayName 'DATN clock SSH from SOC-AI' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 `
  -RemoteAddress 192.168.58.147 -Profile Any | Out-Null
Get-Service sshd
Get-NetFirewallRule -Name DATN-Clock-SSH | Format-List Name,Enabled,Direction,Action
```

Trên NET-SENSOR và Kali, cài public key bằng user SSH thực tế. Lần `ssh-copy-id` này có
thể hỏi mật khẩu vì chỉ là cấu hình ban đầu:

```bash
set -euo pipefail
CLOCK_KEY="$HOME/.ssh/id_ed25519_datn_clock"
read -rp 'NET-SENSOR SSH username: ' SENSOR_USER
read -rp 'Kali SSH username: ' KALI_USER
[[ "$SENSOR_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$KALI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
ssh-copy-id -i "$CLOCK_KEY.pub" "${SENSOR_USER}@192.168.58.150"
ssh-copy-id -i "$CLOCK_KEY.pub" "${KALI_USER}@192.168.58.132"
# Lan dau ket noi Windows: doi chieu fingerprint tren console guest truoc khi accept.
ssh -i "$CLOCK_KEY" -o ConnectTimeout=5 datn_clock@192.168.58.148 whoami
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  datn_clock@192.168.58.148 powershell.exe -NoProfile -NonInteractive -Command \
  "[DateTimeOffset]::UtcNow.ToString('o')"
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${SENSOR_USER}@192.168.58.150" date -u --iso-8601=seconds
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${KALI_USER}@192.168.58.132" date -u --iso-8601=seconds
```

Đối chiếu fingerprint Windows bằng `ssh-keygen.exe -lf
C:\ProgramData\ssh\ssh_host_ed25519_key.pub` trên console guest; Linux dùng
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Chỉ accept host key đúng.
Cả ba lệnh cuối phải trả kết quả mà không hỏi mật khẩu. Nếu không, sửa key/ACL trước;
không bỏ `BatchMode=yes`, không lưu mật khẩu trong script và không mở port 22 Windows
cho địa chỉ khác.


## 8. Cài NET-SENSOR

### 8.1 Suricata

```bash
sudo apt update
sudo apt install -y software-properties-common jq curl gnupg acl netcat-openbsd
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
suricata --build-info | sed -n '1,20p'
suricata -V | grep -E 'version 8\.'
dpkg-query -W -f='${Package}=${Version}\n' suricata
sudo apt-mark hold suricata
```

PPA stable có thể đổi major theo thời gian. Phải xác nhận Suricata 8.x đã cài và ghi
version/hash cấu hình; nếu không phải 8.x, dừng để Thịnh xác nhận tương thích. Không
downgrade tùy ý hoặc chạy tiếp với schema EVE chưa kiểm. Kiểm service thật bằng
`systemctl cat suricata`: tham số interface/capture mode từ unit/default không được
ghi đè NIC YAML. `ps -C Suricata-Main -o args=; pgrep -a suricata` hỗ trợ đối chiếu.

Trong `/etc/suricata/suricata.yaml`:

- đặt `HOME_NET` là `[10.20.0.0/24]`;
- cấu hình `af-packet` nghe **chỉ NIC phía Kali** (ví dụ `ens37`) để tránh đếm đôi;
- trong `eve-log.types` bật `alert`, `dns`, `http`, `tls`, `flow`;
- trong lab kiểm soát này, `rule-files` chỉ chứa `/etc/suricata/rules/datn.rules`.
  Không tham chiếu `suricata.rules` khi chưa có file, không tự cập nhật ET giữa đợt thu;
  mở rộng ruleset cần phiên bản/hash và pilot lại trước một đợt mới.

Khối tối thiểu cần đối chiếu trong YAML (không tạo block trùng nếu file đã có):

```yaml
vars:
  address-groups:
    HOME_NET: "[10.20.0.0/24]"

af-packet:
  - interface: ens37
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns:
            version: 3
            requests: yes
            responses: yes
        - http
        - tls
        - flow

rule-files:
  - /etc/suricata/rules/datn.rules
```

Giữ hai dòng đầu `%YAML 1.1` và `---` của file stock. Đây là fragment để sửa
trong các section sẵn có, không thay toàn bộ suricata.yaml bằng fragment này.
Không dán thêm một bộ khóa
`vars`/`af-packet`/`outputs`/`rule-files` ở cuối file. Trước khi lưu, dùng
`grep -nE '^(vars:|af-packet:|outputs:|rule-files:)'` và bảo đảm mỗi khóa cấp cao nhất chỉ
có một lần. Nếu không xác định được đúng vị trí, phục hồi backup và nhờ người phụ trách
kiểm tra; không đoán thứ tự YAML.

Chuyển rule từ SOC-AI:

```bash
read -rp 'SOC-AI SSH username: ' SOC_USER
SOC_HOME=$(ssh "${SOC_USER}@192.168.58.147" 'printf %s "$HOME"') || exit 1
SOC_REPO="$SOC_HOME/datn-ai-soar-development-3day"
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/config/suricata-datn.rules" /tmp/
REMOTE_RULE_HASH=$(ssh "${SOC_USER}@192.168.58.147" "sha256sum '${SOC_REPO}/config/suricata-datn.rules'" | awk '{print $1}')
test "$(sha256sum /tmp/suricata-datn.rules | awk '{print $1}')" = "$REMOTE_RULE_HASH"
sudo install -d -m 0755 /etc/suricata/rules
sudo install -m 0644 /tmp/suricata-datn.rules /etc/suricata/rules/datn.rules
sudo suricata --init-errors-fatal -T -c /etc/suricata/suricata.yaml
sudo systemctl enable suricata
sudo systemctl restart suricata
sudo systemctl is-active suricata
sudo suricata --dump-config -c /etc/suricata/suricata.yaml | \
  grep -F '/etc/suricata/rules/datn.rules'
sudo grep -E 'sid:(900001|900002|900004);' /etc/suricata/rules/datn.rules
sudo tail -n 5 /var/log/suricata/eve.json | jq -c .
```

Ba SID local 900001/900002/900004 nhận diện traffic mô phỏng HTTP/DNS/canary trong lab.
DNS phải có cả request và response thành công trên UDP53 tại resolver đã đóng băng.
Suricata 8.0.7 dùng type=request/response; wire dns.id phải khớp, còn tx_id của
request và response có thể khác nhau. Không sửa tx_id trong raw để ép bằng nhau.
Định dạng: https://docs.suricata.io/en/suricata-8.0.7/upgrade/8.0-dns-logging-changes.html
SID không phải ground truth ý định; mọi HTTP profile trainable của cả hai nhãn
dùng cùng endpoint và rule. DNS cả hai nhãn cũng dùng cùng suffix/rule.
Alert count có thể phản ánh action count, nhưng tên SID/severity riêng theo nhãn
không được làm shortcut. Nếu
`suricata -T` báo lỗi, dừng; không chạy collector bằng ruleset lỗi.



#### 8.1.1 Final flow phải về trước hạn thu

Collector yêu cầu final flow counter. Suricata 8.0.7 mặc định có UDP established
300 giây và TCP closed 60 giây; chờ tùy ý 90 giây sau thao tác có thể chưa có final flow.
Đây là timeout sau hoạt động cuối của flow, không phải thời lượng của kịch bản.

Trên NET-SENSOR, sao lưu YAML rồi dùng `sudoedit` sửa các khóa sẵn có trong
`flow-timeouts`. Giữ các khóa/protocol khác của cấu hình gốc; không dán thêm một
block `flow-timeouts` thứ hai. Các giá trị sau dành riêng cho lab HTTP/DNS ngắn:

```yaml
flow-timeouts:
  tcp:
    new: 15
    established: 60
    closed: 15
    emergency-new: 5
    emergency-established: 10
    emergency-closed: 5
  udp:
    new: 10
    established: 15
    emergency-new: 5
    emergency-established: 5
```

Kiểm cấu hình thật và restart trước preflight, không đổi giữa run:

```bash
set -euo pipefail
sudo suricata --init-errors-fatal -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl is-active suricata
sudo suricata --dump-config -c /etc/suricata/suricata.yaml \
  | grep -E '^flow-timeouts\.(tcp|udp)\.'
sudo sha256sum /etc/suricata/suricata.yaml /etc/suricata/rules/datn.rules
```

Phải thấy UDP new=10/established=15, TCP new=15/established=60/closed=15 và các
emergency timeout nhỏ hơn regular tương ứng. Không để warning timeout đảo ngược. `-T` chỉ
chứng minh cấu hình/rule hợp lệ; G4 còn phải thấy final flow thật sau canary HTTP và DNS.
Theo dõi native trên NET-SENSOR khi Windows chạy canary ở mục 10.4:

```bash
sudo tail -n 0 -F /var/log/suricata/eve.json | jq --unbuffered -c \
  'select(.event_type=="flow" and .src_ip=="10.20.0.10" and .dest_ip=="10.40.0.10") |
   {timestamp,flow_id,proto,src_ip,dest_ip,src_port,dest_port,flow}'
```

Dừng bằng Ctrl+C sau khi đã thấy TCP và UDP final flow. Đối chiếu lại cùng flow_id
tại Archives trên SOC-AI. Cần đo độ trễ thực tế EVE → Archives nhỏ hơn grace 60 giây.
Nếu không đạt, sửa đường log/tài nguyên/timeout và chạy lại pilot; không tăng grace
sau khi đã thu chính thức hoặc điền byte=0. Flow kéo qua hai bucket bị báo thiếu
độ chính xác; dùng HTTP request đóng connection và thu lại trong bucket sạch.

Nguồn: https://docs.suricata.io/en/suricata-8.0.7/configuration/suricata-yaml.html


### 8.2 Wazuh Agent chuyển EVE JSON

```bash
sudo apt-get install -y gnupg apt-transport-https curl
set -euo pipefail
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/datn-wazuh-signing.asc
WAZUH_SIGNING_FPR=0DCFCA5547B19D2A6099506096B3EE5F29111145
ACTUAL_FPR=$(gpg --show-keys --with-colons /tmp/datn-wazuh-signing.asc | awk -F: '$1=="fpr" && !seen {print $10; seen=1}')
test "$ACTUAL_FPR" = "$WAZUH_SIGNING_FPR"
sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import /tmp/datn-wazuh-signing.asc
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
WAZUH_VERSION=4.14.9-1
sudo env WAZUH_MANAGER="192.168.58.147" WAZUH_AGENT_NAME="NET-SENSOR" \
  apt-get install -y "wazuh-agent=$WAZUH_VERSION"
sudo apt-mark hold wazuh-agent
dpkg-query -W -f='${Version}\n' wazuh-agent | grep -Fx "$WAZUH_VERSION"
```

Sao lưu `/var/ossec/etc/ossec.conf`, đếm location EVE và chỉ chèn block trong
`config/wazuh-suricata-localfile.xml` nếu count đang bằng 0. Sau khi chèn, count phải
bằng đúng 1. Cho Wazuh đọc được EVE hiện tại và file tạo sau rotate:

```bash
read -rp 'SOC-AI SSH username: ' SOC_USER
SOC_HOME=$(ssh "${SOC_USER}@192.168.58.147" 'printf %s "$HOME"') || exit 1
SOC_REPO="$SOC_HOME/datn-ai-soar-development-3day"
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/config/wazuh-suricata-localfile.xml" /tmp/
sudo cp -a /var/ossec/etc/ossec.conf \
  "/var/ossec/etc/ossec.conf.bak.$(date -u +%Y%m%dT%H%M%SZ)"
sudo grep -cF '<location>/var/log/suricata/eve.json</location>' \
  /var/ossec/etc/ossec.conf || true
sudoedit /var/ossec/etc/ossec.conf
test "$(sudo grep -cF '<location>/var/log/suricata/eve.json</location>' \
  /var/ossec/etc/ossec.conf)" -eq 1
sudo setfacl -m u:wazuh:rx /var/log/suricata
sudo setfacl -m u:wazuh:r /var/log/suricata/eve.json
sudo setfacl -d -m u:wazuh:rx /var/log/suricata
sudo getfacl /var/log/suricata /var/log/suricata/eve.json
sudo /var/ossec/bin/wazuh-logcollector -t
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent
sudo -u wazuh test -r /var/log/suricata/eve.json
sudo systemctl is-active wazuh-agent
```

Tạo một request từ Windows tới Kali, rồi trên SOC-AI:

```bash
sudo /var/ossec/bin/agent_control -l | grep NET-SENSOR
sudo jq -c 'select(.agent.name=="NET-SENSOR")' \
  /var/ossec/logs/archives/archives.json | tail -n 3
```

Đạt G 4 chỉ khi Archives có event từ cả hai agent. Có event trên NET-SENSOR nhưng không
có ở Archives nghĩa là cấu hình Wazuh/ACL chưa đạt.

## 9. Cài dịch vụ mô phỏng trên Kali

```bash
sudo apt update
sudo apt install -y python3 dnsmasq curl jq dnsutils smbclient nftables
sudo install -d -m 0755 /srv/datn/benign/api /srv/datn/beacon /srv/datn/stage
printf 'ok\n' | sudo tee /srv/datn/benign/health
printf '{"status":"ok"}\n' | sudo tee /srv/datn/benign/api/status
printf 'DATN-BENIGN-PAYLOAD\n' | sudo tee /srv/datn/benign/payload-benign.txt
printf 'beacon-ok\n' | sudo tee /srv/datn/beacon/beacon
sudo dd if=/dev/zero of=/srv/datn/stage/stage.bin bs=1024 count=64 status=none
```

Trước khi khởi động dịch vụ, lấy module HTTP mới từ checkout GitHub đã pin trên
SOC-AI. Không lấy http.server cũ để phục vụ workflow POST mới:

```bash
set -euo pipefail
mkdir -p "$HOME/datn-tools"
read -rp 'SOC SSH username: ' SOC_USER
[[ "$SOC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
SOC_REPO=datn-ai-soar-development-3day
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/ml/http_workflow.py" "$HOME/datn-tools/http_workflow.py"
REMOTE_HASH=$(ssh "${SOC_USER}@192.168.58.147" "sha256sum '$SOC_REPO/ml/http_workflow.py'" | awk '{print $1}')
test "$(sha256sum "$HOME/datn-tools/http_workflow.py" | awk '{print $1}')" = "$REMOTE_HASH"
```

Khởi động ba dịch vụ tạm thời; chạy lại sau mỗi reboot. Lab đã có unit8081 cũ:
chỉ khi không còn run active, lưu systemctl cat/journal của unit, dừng unit cũ
và kiểm ss không còn listener8081 trước khi tạo unit mới; không kill tiến trình
mù quáng. Unit cũ có thể còn loaded sau stop; dùng systemctl reset-failed và xác
nhận trạng thái trước khi dùng systemd-run, không chạy hai server cùng port:


```bash
sudo systemd-run --unit=datn-http-benign --property=Restart=on-failure \
  --working-directory=/srv/datn/benign \
  /usr/bin/python3 -m http.server 8080 --bind 10.40.0.10
sudo systemd-run --unit=datn-http-beacon --property=Restart=on-failure \
  /usr/bin/python3 "$HOME/datn-tools/http_workflow.py" --bind 10.40.0.10 --port 8081
sudo systemd-run --unit=datn-http-stage --property=Restart=on-failure \
  --working-directory=/srv/datn/stage \
  /usr/bin/python3 -m http.server 9001 --bind 10.40.0.10
systemctl is-active datn-http-benign datn-http-beacon datn-http-stage
ss -lntp | grep -E ':8080|:8081|:9001'
```

Tạo file bằng quyền root; thay `eth1` đúng NIC VMnet2 trước khi lưu:

```bash
sudoedit /etc/dnsmasq.d/datn-lab.conf
```

Nội dung đầy đủ của `/etc/dnsmasq.d/datn-lab.conf`:

```text
interface=eth1
listen-address=10.40.0.10
bind-interfaces
no-resolv
domain-needed
bogus-priv
local=/datn.test/
address=/www.datn.test/10.40.0.10
address=/beacon.datn.test/10.40.0.10
```

Thay `eth1` đúng NIC VMnet2. Cấu hình cố ý **không có DNS upstream**: hai tên lab
được trả lời cục bộ, các truy vấn khác thất bại thay vì thoát ra Internet. Sau đó:

```bash
sudo dnsmasq --test
sudo systemctl restart dnsmasq
test "$(systemctl is-active dnsmasq)" = active
ss -lunp | grep -E '10\.40\.0\.10:53\b'
test "$(dig +short @10.40.0.10 www.datn.test A)" = 10.40.0.10
test "$(dig +short @10.40.0.10 r01.beacon.datn.test A)" = 10.40.0.10
```

### 9.1 Đồng bộ giờ nội bộ trước khi cô lập Internet

Thực hiện sau khi IP management ổn định, trước snapshot telemetry/pilot. SOC-AI làm
nguồn giờ cho ba VM còn lại qua VMnet8. Nó đồng bộ UTC từ Internet trước buổi thu;
trong collection mode nó giữ giờ nội bộ bằng chrony local stratum 10. Đây là đồng bộ
lab khi mất upstream, không phải chứng nhận UTC độc lập. Mỗi buổi phải lưu phép đo
UTC trước cô lập và đo skew thực giữa bốn máy ở mục 10.3/11. Không chỉnh giờ, suspend,
restore snapshot hoặc chạy `makestep` giữa run.

Cả ba Linux VM — cài khi còn Internet:

```bash
sudo apt update
sudo apt install -y chrony
sudo systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
sudo cp -a /etc/chrony/chrony.conf "/etc/chrony/chrony.conf.before-datn.$(date -u +%Y%m%dT%H%M%SZ)"
```

Chỉ SOC-AI — cấu hình đầy đủ cho lab (không nối thêm vào file cũ):

```bash
sudo tee /etc/chrony/chrony.conf >/dev/null <<'EOF'
pool ntp.ubuntu.com iburst maxsources 4
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
allow 192.168.58.132/32
allow 192.168.58.148/32
allow 192.168.58.150/32
local stratum 10
logdir /var/log/chrony
EOF
sudo chronyd -p -f /etc/chrony/chrony.conf
sudo systemctl enable --now chrony
sudo systemctl restart chrony
sudo chronyc waitsync 60 0.1
chronyc sources -v
chronyc tracking
```

Trước cô lập, SOC-AI phải có upstream được chọn (`^*`), leap Normal và ngày UTC đúng;
local stratum 10 không thay thế điều kiện này. Nếu UFW trên SOC-AI đang active, thêm
rule UDP 123 từ từng `.132`, `.148`, `.150` tới `.147`; giữ các port Wazuh 1514/TCP,
1515/TCP và quản trị cần thiết. Ví dụ một rule, lặp cho đúng hai IP còn lại:

```bash
sudo ufw allow from 192.168.58.132 to 192.168.58.147 port 123 proto udp
sudo ufw allow from 192.168.58.148 to 192.168.58.147 port 123 proto udp
sudo ufw allow from 192.168.58.150 to 192.168.58.147 port 123 proto udp
sudo ufw status verbose
```

Chỉ NET-SENSOR và Kali — client trỏ về SOC-AI, không có nguồn giờ Internet thứ hai:

```bash
sudo tee /etc/chrony/chrony.conf >/dev/null <<'EOF'
server 192.168.58.147 iburst minpoll 4 maxpoll 6
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
sudo chronyd -p -f /etc/chrony/chrony.conf
sudo systemctl enable --now chrony
sudo systemctl restart chrony
sudo chronyc waitsync 60 0.1
chronyc sources -v
chronyc tracking
```

Windows PowerShell Administrator — dùng NTP client mode tới SOC-AI:

```powershell
$ErrorActionPreference = 'Stop'
Set-Service W32Time -StartupType Automatic
Start-Service W32Time
w32tm /config /manualpeerlist:"192.168.58.147,0x8" /syncfromflags:MANUAL /update
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure lab NTP peer' }
Restart-Service W32Time
Start-Sleep -Seconds 5
w32tm /resync /rediscover
if ($LASTEXITCODE -ne 0) { throw 'Windows cannot synchronize to SOC-AI' }
w32tm /query /source
w32tm /query /status
w32tm /stripchart /computer:192.168.58.147 /dataonly /samples:5
if ($LASTEXITCODE -ne 0) { throw 'Lab NTP measurement failed' }
```

Nguồn Windows phải là `192.168.58.147`, hai client Linux phải có `^* 192.168.58.147`.
VMware Tools > Options > VMware Tools > Synchronize guest time with host phải tắt
periodic sync nếu nó tranh chấp chrony/W32Time; sau resume/reboot chạy preflight lại.
Nếu mất sync, mở NAT khi không có run, sync lại rồi cô lập; không đặt ngày bằng tay
để qua gate. Lưu `chronyc tracking`, `w32tm /query /status` và clock YAML cùng buổi thu.

Nguồn chính thức: https://ubuntu.com/server/docs/how-to/networking/serve-ntp-with-chrony/
và https://chrony-project.org/doc/4.5/chrony.conf.html ; W32Time:
https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/Windows-Time-Service-Tools-and-Settings


### 9.2 Driver SMB trên Kali

```bash
set -euo pipefail
sudo apt update
sudo apt install -y python3-impacket openssh-client
/usr/bin/python3 -c 'from impacket.smbconnection import SMBConnection, SessionError; import inspect; print(inspect.signature(SMBConnection.login))'
mkdir -p "$HOME/datn-tools"
read -rp 'SOC-AI SSH username: ' SOC_USER
[[ "$SOC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
scp "${SOC_USER}@192.168.58.147:datn-ai-soar-development-3day/scripts/run_training_account_remote.py" "$HOME/datn-tools/"
REMOTE_HASH=$(ssh "${SOC_USER}@192.168.58.147" 'sha256sum "$HOME/datn-ai-soar-development-3day/scripts/run_training_account_remote.py"' | awk '{print $1}')
test "$(sha256sum "$HOME/datn-tools/run_training_account_remote.py" | awk '{print $1}')" = "$REMOTE_HASH"
dpkg-query -W python3-impacket | tee "$HOME/datn-tools/impacket-version.txt"
```

login phải hỗ trợ ntlmFallback; driver tắt fallback, một auth/attempt, đóng session.
Giữ version Kali/dependency sau pilot, không pip vào system Python.
Chỉ IPC auth tới target445, không thực thi command/payload trên target.

## 10. Preflight bắt buộc trước mỗi buổi


### 10.1 Chuyển lab sang collection mode cô lập Internet

Chỉ thực hiện sau khi đã cài hết package và hoàn tất chrony/W32Time mục 9.1.
SOC-AI phải vừa có upstream UTC thật; chụp/lưu nguồn đó trước khi cắt NAT. Sau khi
cô lập, local stratum 10 duy trì giờ lab, ba client vẫn lấy từ `.147`. **Trước khi xóa route**, đồng bộ giờ khi
management/NAT còn hoạt động. Trên từng Linux VM:

```bash
sudo systemctl is-active chrony
chronyc sources -v
chronyc tracking
for attempt in $(seq 1 12); do
  test "$(timedatectl show -p NTPSynchronized --value)" = yes && break
  sleep 5
done
test "$(timedatectl show -p NTPSynchronized --value)" = yes
```

Trên Windows PowerShell Administrator:

```powershell
$ErrorActionPreference = 'Stop'
w32tm /resync | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Windows time resync failed' }
$timeSource = (w32tm /query /source | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $timeSource -match 'Local CMOS Clock') {
  throw "Invalid Windows time source: $timeSource"
}
```

### 10.1.1 Cô lập management giữa peer VMnet8 (Kali)

VMnet8 là cùng L 2: xóa default route và UFW route trên sensor không chặn peer.
Kali thực thi ACL OUTPUT riêng, không flush hay thay policy firewall toàn máy.
Bảng cho phép: Kali → SOC `192.168.58.147` UDP/123 (NTP); SOC khởi tạo
TCP/22 tới Kali và Kali trả lời trên kết nối established; Windows/Sensor → SOC
Wazuh 1514 và enrollment theo cấu hình tiếp tục hoạt động. Kali không được chủ
động tới dịch vụ management SOC hoặc Sensor `192.168.58.150`, kể cả SSH,
HTTPS, Wazuh và API. Không chặn traffic dữ liệu VMnet2/VMnet3. IPv6 trên NIC
management bị chặn OUTPUT để tránh đường vòng; trả lời SSH IPv 4 established vẫn
được phép. Chỉ áp dụng trên lab cô lập, với console VMware mở sẵn.

Trước khi áp dụng: xác nhận MAC/NIC bằng `ip -br link`, `ip -br address`,
`ip route get 192.168.58.147` và đối chiếu VMware; xác nhận IP SOC/Sensor như
bảng địa chỉ. Nếu sai, dừng và sửa theo lab. Đảm bảo `nft` và SSH server đã cài,
SOC có thể SSH vào Kali, và không có policy hiện hữu chặn NTP/SSH; lưu
`sudo nft list ruleset` và `sudo iptables-save`/`sudo ip6tables-save` ra file
root-only ngoài repo. Kiểm `sudo nft list table inet datn_kali_mgmt`: nếu bảng
đã tồn tại hoặc có service firewall khác quản lý bảng này thì dừng, không ghi đè.
Nếu `/etc/datn/kali-mgmt.nft` hoặc service cùng tên đã tồn tại, dừng và đối chiếu,
sao lưu rồi xử lý có kiểm soát; không dùng các lệnh tạo mới bên dưới để ghi đè.
Không áp dụng qua SSH duy nhất. Quy tắc sau dùng `eth0` làm ví dụ: thay bằng NIC
VMnet8 đã đối chiếu MAC, và giữ IP đúng thực tế.

```bash
sudo install -d -m 700 /etc/datn
sudo tee /etc/datn/kali-mgmt.nft >/dev/null <<'NFT'
table inet datn_kali_mgmt {
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "eth0" ip daddr 192.168.58.147 udp dport 123 accept
    oifname "eth0" ip daddr 192.168.58.147 tcp sport 22 ct state established accept
    oifname "eth0" ip daddr { 192.168.58.147, 192.168.58.150 } counter reject
    oifname "eth0" meta nfproto ipv6 counter reject
  }
}
NFT
sudo nft -c -f /etc/datn/kali-mgmt.nft
sudo nft -f /etc/datn/kali-mgmt.nft
sudo nft list table inet datn_kali_mgmt
```

Quy tắc `accept` tại chain này không vượt qua firewall khác: kiểm thực tế các
ngoại lệ sau khi áp dụng. Để nạp lại sau reboot, tạo service riêng, không sửa
`/etc/nftables.conf` hay flush ruleset:

```bash
sudo tee /etc/systemd/system/datn-kali-mgmt.service >/dev/null <<'UNIT'
[Unit]
Description=DATN Kali management egress isolation
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/datn/kali-mgmt.nft
ExecStop=/usr/sbin/nft delete table inet datn_kali_mgmt
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
# Bảng đã được nạp ở trên; bật service sau reboot, không start lại ngay.
sudo systemctl enable datn-kali-mgmt.service
```

Sau reboot kiểm lại MAC, tên NIC, route, `systemctl status datn-kali-mgmt` và
bảng nft trước thu; nếu tên NIC đã đổi hoặc bất kỳ kiểm tra thất bại
thì dừng. Trên console, rollback riêng bằng `sudo systemctl disable --now
datn-kali-mgmt.service` khi service đang active. Nếu mới nạp thủ công nhưng unit đã được tạo/enable, chạy
`sudo systemctl disable datn-kali-mgmt.service` trước, rồi
`sudo nft delete table inet datn_kali_mgmt`; nếu chưa tạo unit thì chỉ xóa bảng.
Kiểm `systemctl is-enabled datn-kali-mgmt.service` phải disabled hoặc not-found và
`sudo nft list table inet datn_kali_mgmt` phải báo không tồn tại, kể cả sau reboot
rollback. Không khôi phục toàn ruleset cũ mù
quáng. Nếu mất SSH dùng console VMware và rollback, không thay firewall khác.

Nghiệm thu thật sau khi áp dụng và sau reboot: từ Kali đo NTP tới SOC; từ SOC
SSH vào Kali và chạy lệnh; từ Kali thử TCP 22/443/1514/1515 tới SOC và Sensor
phải thất bại, quan sát counter/log hoặc packet capture xác nhận bị ACL chặn,
không coi timeout do dịch vụ tắt là bằng chứng. Kiểm IPv6 link-local/global qua
NIC management cũng bị chặn; SSH dùng IPv 4. Từ Windows và Sensor
kiểm agent connected và SOC nhận event Wazuh mới qua 1514; kiểm lại canary qua
hai mạng dữ liệu. Ghi thời gian, IP/MAC, ruleset, lệnh và kết quả bốn VM; mọi
phép thử âm phải có dịch vụ đích hoặc listener được xác nhận đang nghe trước đó.
Không đánh dấu đạt khi chưa có pilot thật.
Sau khi bốn máy đã đồng bộ, trên ba Linux VM xóa default route tạm thời; trên Windows
xóa default route của phiên hiện tại. Kết nối nội bộ cùng VMnet8 và các route
`10.20/10.40` vẫn hoạt động. Reboot sẽ khôi phục route để bảo trì; trước buổi thu sau phải
lặp lại toàn bộ bước đồng bộ rồi cô lập này.

```bash
sudo ip route del default 2>/dev/null || true
sudo ip -6 route del default 2>/dev/null || true
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
# Chặn DNS ra ngoài nhưng vẫn cho phép DNS lab 10.40.0.10.
sudo iptables -C OUTPUT -p udp --dport 53 ! -d 10.40.0.10 -j REJECT 2>/dev/null || \
  sudo iptables -I OUTPUT 1 -p udp --dport 53 ! -d 10.40.0.10 -j REJECT
sudo iptables -C OUTPUT -p tcp --dport 53 ! -d 10.40.0.10 -j REJECT 2>/dev/null || \
  sudo iptables -I OUTPUT 1 -p tcp --dport 53 ! -d 10.40.0.10 -j REJECT
sudo ip6tables -C OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || \
  sudo ip6tables -I OUTPUT 1 -p udp --dport 53 -j REJECT
sudo ip6tables -C OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null || \
  sudo ip6tables -I OUTPUT 1 -p tcp --dport 53 -j REJECT
if timeout 3 curl -fsS --connect-timeout 2 https://1.1.1.1/ >/dev/null 2>&1; then
  echo 'FAIL: public IPv4 is still reachable' >&2; exit 1
fi
```

```powershell
$ErrorActionPreference = 'Stop'
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
  -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' `
  -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
if (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
  -ErrorAction SilentlyContinue) { throw 'Internet default route still exists' }
if (Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' `
  -ErrorAction SilentlyContinue) { throw 'IPv6 Internet default route still exists' }
Get-NetAdapter | Where-Object Status -eq Up | ForEach-Object {
  Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex `
    -ServerAddresses '10.40.0.10'
}
if ((Test-NetConnection 1.1.1.1 -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded) {
  throw 'Public IPv4 is still reachable'
}
Clear-DnsClientCache
try {
  Resolve-DnsName example.com -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null
  throw 'Public DNS resolution is still available'
} catch {
  if ($_.Exception.Message -eq 'Public DNS resolution is still available') { throw }
}
```

Nếu cần Internet để cập nhật, dừng thu, đóng run đang mở, reboot/khôi phục route, cập nhật
xong rồi chạy lại toàn bộ preflight. Không revert snapshot chứa dataset/cursor cũ;
giữ evidence/bucket reservation đã thu và backup trước mọi thay đổi. Không cập nhật trong cửa sổ run.


### 10.2 Kiểm tra fail-closed từng VM

SOC-AI:

```bash
set -euo pipefail
test "$(sudo systemctl is-active wazuh-manager)" = active
AGENTS=$(sudo /var/ossec/bin/agent_control -l)
printf '%s\n' "$AGENTS" | grep -E 'Name: WIN11-TARGET,.*Active'
printf '%s\n' "$AGENTS" | grep -E 'Name: NET-SENSOR,.*Active'
ARCHIVE=/var/ossec/logs/archives/archives.json
sudo test -s "$ARCHIVE"
# Không mở run trong vùng 23:45-00:15 UTC vì Archives có thể rotate qua ngày.
UTC_HHMM=$(date -u +%H%M)
test "$UTC_HHMM" -lt 2345
test "$UTC_HHMM" -gt 0015
test "$(timedatectl show -p NTPSynchronized --value)" = yes
AVAILABLE_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
FREE_KB=$(df -Pk /var/ossec | awk 'NR==2 {print $4}')
test "$AVAILABLE_KB" -ge 2097152
test "$FREE_KB" -ge 10485760
cd "$HOME/datn-ai-soar-development-3day"
test -z "$(git status --porcelain)"
COLLECTION_TAG=development-collection-v1.0.0-candidate.1
.venv-ml/bin/python -m scripts.collection_release candidate --tag "$COLLECTION_TAG" > operator-logs/releases/candidate-current.json
cmp operator-logs/releases/candidate.json operator-logs/releases/candidate-current.json
mkdir -p evidence/scenario-runs
test ! -e evidence/scenario-runs/.active-run.json
while IFS= read -r -d '' STATE; do
  jq -e 'type=="object" and (.status=="FINALIZED" or .status=="ABORTED")' "$STATE" >/dev/null
done < <(find evidence/scenario-runs -mindepth 2 \
  -name .collection_state.json -print0)
.venv-ml/bin/python -m scripts.scenario_session --help >/dev/null
.venv-ml/bin/python -m ml.development_dataset --help >/dev/null
.venv-ml/bin/python - <<'PY'
import json
from pathlib import Path
import yaml
source = yaml.safe_load(Path('config/development-sources.yaml').read_text())
schema = json.loads(Path('ml/feature_schema.json').read_text())
for key in ('require_clean_bucket','require_flow_counters','require_online_parity'):
    if source.get(key) is not True:
        raise SystemExit('Source gate disabled: ' + key)
if source.get('late_arrival_grace_seconds') != 60:
    raise SystemExit('Unexpected grace; use the reviewed release')
if schema.get('version') != 'features-v3' or len(schema.get('required',[])) != 24:
    raise SystemExit('Wrong feature schema; do not collect with features-v2')
print('SOURCE_CAPTURE_CONTRACT=PASS')
PY
echo 'SOC_PREFLIGHT=PASS'
```

NET-SENSOR:

```bash
set -euo pipefail
test "$(sudo systemctl is-active suricata)" = active
test "$(sudo systemctl is-active wazuh-agent)" = active
sudo suricata --init-errors-fatal -T -c /etc/suricata/suricata.yaml
sudo suricata --dump-config -c /etc/suricata/suricata.yaml \
  | grep -F '/etc/suricata/rules/datn.rules'
sudo -u wazuh test -r /var/log/suricata/eve.json
ip -4 route show 10.40.0.0/24 | grep -q 'scope link'
ip -4 route show 10.20.0.0/24 | grep -q 'scope link'
if nc -z -w 2 -s 10.20.0.1 10.20.0.10 445; then
  echo 'FAIL: NET-SENSOR can reach SMB; Windows rule is too broad' >&2
  exit 1
fi
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
test "$(timedatectl show -p NTPSynchronized --value)" = yes
echo 'SENSOR_PREFLIGHT=PASS'
```

Kali:

```bash
set -euo pipefail
for service in datn-http-benign datn-http-beacon datn-http-stage dnsmasq; do
  test "$(systemctl is-active "$service")" = active
done
for port in 53 8080 8081 9001; do
  ss -lntup | grep -Eq ":${port}\\b"
done
ip route get 10.20.0.10 | grep -q 'via 10.40.0.1'
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
test "$(timedatectl show -p NTPSynchronized --value)" = yes
echo 'KALI_PREFLIGHT=PASS'
```

Windows PowerShell (Administrator):

```powershell
$ErrorActionPreference = 'Stop'
$services = Get-Service Sysmon64,WazuhSvc
if ($services.Where({$_.Status -ne 'Running'})) { throw 'Sysmon/Wazuh is not running' }
$route = Get-NetRoute -DestinationPrefix '10.40.0.0/24' -ErrorAction Stop
if (-not $route.Where({$_.NextHop -eq '10.20.0.1'})) { throw 'Wrong data route' }
if (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
  -ErrorAction SilentlyContinue) { throw 'Internet default route still exists' }
if (Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' `
  -ErrorAction SilentlyContinue) { throw 'IPv6 Internet default route still exists' }
foreach ($port in 8080,8081,9001) {
  $test = Test-NetConnection 10.40.0.10 -Port $port -WarningAction SilentlyContinue
  if (-not $test.TcpTestSucceeded) { throw "Kali TCP $port is unreachable" }
}
foreach ($name in 'www.datn.test','beacon.datn.test') {
  $answer = Resolve-DnsName $name -Server 10.40.0.10 -Type A
  if ('10.40.0.10' -notin $answer.IPAddress) { throw "Wrong DNS answer for $name" }
}
$timeSource = (w32tm /query /source | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $timeSource -match 'Local CMOS Clock') {
  throw "Invalid Windows time source: $timeSource"
}
'WINDOWS_PREFLIGHT=PASS'
```


### 10.3 Đo clock không tính thời gian nhập mật khẩu

Mục 7.4 phải hoàn tất trước. Các lệnh sau dùng đúng key chuyên dụng, IP cụ thể và
`BatchMode=yes`; không dùng alias chưa khai báo. Trên SOC-AI:

```bash
set -euo pipefail
MAX_CLOCK_SKEW_SECONDS=5
MAX_SSH_ROUNDTRIP_SECONDS=4
CLOCK_KEY="$HOME/.ssh/id_ed25519_datn_clock"
test -f "$CLOCK_KEY"
read -rp 'NET-SENSOR SSH username: ' SENSOR_USER
read -rp 'Kali SSH username: ' KALI_USER
[[ "$SENSOR_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$KALI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
for ENDPOINT in \
  "${SENSOR_USER}@192.168.58.150" \
  "${KALI_USER}@192.168.58.132"; do
  BEFORE=$(date -u +%s)
  REMOTE=$(ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
    "$ENDPOINT" 'date -u +%s')
  AFTER=$(date -u +%s)
  RTT=$((AFTER - BEFORE))
  MID=$(((BEFORE + AFTER) / 2))
  SKEW=$((MID - REMOTE)); SKEW=${SKEW#-}
  printf '%s roundtrip=%s skew=%s\n' "$ENDPOINT" "$RTT" "$SKEW"
  test "$RTT" -le "$MAX_SSH_ROUNDTRIP_SECONDS"
  test "$SKEW" -le "$MAX_CLOCK_SKEW_SECONDS"
done

BEFORE=$(date -u +%s)
TARGET_EPOCH=$(ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  datn_clock@192.168.58.148 powershell.exe -NoProfile -NonInteractive -Command \
  "[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()" | tr -d '\r')
AFTER=$(date -u +%s)
[[ "$TARGET_EPOCH" =~ ^[0-9]+$ ]]
RTT=$((AFTER - BEFORE)); MID=$(((BEFORE + AFTER) / 2))
SKEW=$((MID - TARGET_EPOCH)); SKEW=${SKEW#-}
printf 'WIN11-TARGET roundtrip=%s skew=%s\n' "$RTT" "$SKEW"
test "$RTT" -le "$MAX_SSH_ROUNDTRIP_SECONDS"
test "$SKEW" -le "$MAX_CLOCK_SKEW_SECONDS"
echo 'CLOCK_SSH_PREFLIGHT=PASS'
```


### 10.4 Canary end-to-end mới, không dùng dữ liệu cũ

Trên SOC-AI, ghi byte cursor tại đúng ranh giới dòng:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
test ! -e evidence/scenario-runs/.active-run.json
CANARY_ID="pf$(date -u +%s)${RANDOM}"
printf '%s\n' "$CANARY_ID" | tee /tmp/datn-preflight.id
date -u --iso-8601=seconds > /tmp/datn-preflight.start-utc
mkdir -p "operator-logs/preflight/$CANARY_ID"
ARCHIVE=/var/ossec/logs/archives/archives.json
CURSOR=$(sudo stat -c %s "$ARCHIVE")
test "$CURSOR" -gt 0
test "$(sudo dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$((CURSOR - 1))" count=1 status=none | od -An -t u1 | tr -d ' ')" = 10
sudo stat -c '%d:%i' "$ARCHIVE" > /tmp/datn-preflight.identity
printf '%s\n' "$CURSOR" | tee /tmp/datn-preflight.cursor
sudo head -c "$CURSOR" "$ARCHIVE" | sha256sum | awk '{print $1}' > /tmp/datn-preflight.prefix
```

Ngay sau đó trên Windows PowerShell chạy canary an toàn và bắt mọi lỗi HTTP:

```powershell
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'WIN11-TARGET') { throw 'Run only on WIN11-TARGET VM' }
$CanaryId = Read-Host 'Paste exact CANARY_ID printed by SOC-AI'
if ($CanaryId -notmatch '^pf[0-9]{11,20}$') { throw 'Invalid canary ID' }
New-Item -ItemType Directory -Path C:\DATN\logs -Force | Out-Null
$canaryStartUtc = [DateTimeOffset]::UtcNow
$canaryStartRecord = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1).RecordId
foreach ($uri in @(
  "http://10.40.0.10:8080/health?preflight=$CanaryId",
  "http://10.40.0.10:8081/beacon?preflight=$CanaryId",
  "http://10.40.0.10:9001/stage.bin?preflight=$CanaryId"
)) {
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw "Canary failed: $uri" }
}
$dnsScript = 'C:\DATN\run_dns_scenario.ps1'
$expectedHash = (Get-Content -LiteralPath "$dnsScript.sha256.txt" -Raw).Trim()
if ($expectedHash -notmatch '^[0-9a-f]{64}$' -or
    (Get-FileHash -LiteralPath $dnsScript -Algorithm SHA256).Hash.ToLower() -ne $expectedHash) {
  throw 'Pinned DNS script is missing or changed; return to 7.2'
}
foreach ($suffix in 'www.datn.test','beacon.datn.test') {
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $dnsScript `
    -RunNonce $CanaryId -DomainSuffix $suffix -Count 2 -GapsCsv '1' `
    -VariantIndex 0 -DnsServer 10.40.0.10
  if ($LASTEXITCODE -ne 0) { throw "DNS canary failed: $suffix" }
}
Start-Sleep -Seconds 3
$canaryEndRecord = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1).RecordId
$canaryEndUtc = [DateTimeOffset]::UtcNow
# Read by record number as well as time: an old/stale SystemTime must not make
# a newly written bad event disappear from the diagnostic query.
$events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,22} |
    Where-Object { $_.RecordId -gt $canaryStartRecord -and $_.RecordId -le $canaryEndRecord })
$clockXml = "C:\DATN\logs\$CanaryId-sysmon-raw.xml.txt"
$events | ForEach-Object { $_.ToXml() } | Set-Content -LiteralPath $clockXml -Encoding UTF8
Get-Date -Format o
Get-Service W32Time,Sysmon64,WazuhSvc | Format-Table Name,Status,StartType
& w32tm.exe /query /status /verbose
if ($LASTEXITCODE -ne 0) { throw 'Cannot read W32Time status' }
& w32tm.exe /query /source
if ($LASTEXITCODE -ne 0) { throw 'Cannot read W32Time source' }
$rows = @($events | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $systemRaw = [string]$xml.Event.System.TimeCreated.SystemTime
    $utcNodes = @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'UtcTime' })
    if ([string]::IsNullOrWhiteSpace($systemRaw) -or $utcNodes.Count -ne 1) { throw "Missing/duplicate time field in record $($_.RecordId)" }
    $utcRaw = [string]$utcNodes[0].InnerText
    if ([string]::IsNullOrWhiteSpace($utcRaw)) { throw "Missing UtcTime in record $($_.RecordId)" }
    if ($systemRaw -notmatch '(Z|[+-]\d{2}:\d{2})$') { throw 'SystemTime lacks an explicit timezone' }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $systemUtc = [DateTimeOffset]::Parse($systemRaw,[Globalization.CultureInfo]::InvariantCulture,$styles)
    $eventUtc = [DateTimeOffset]::Parse($utcRaw,[Globalization.CultureInfo]::InvariantCulture,$styles)
    [pscustomobject]@{Id=$_.Id; RecordId=$_.RecordId; SystemTime=$systemRaw; UtcTime=$utcRaw;
        DeltaSeconds=[Math]::Abs(($systemUtc-$eventUtc).TotalSeconds);
        Fresh=($systemUtc -ge $canaryStartUtc -and $systemUtc -le $canaryEndUtc -and $eventUtc -ge $canaryStartUtc -and $eventUtc -le $canaryEndUtc)}
})
$rows | Sort-Object RecordId | Format-Table -AutoSize
$clockCsv = "C:\DATN\logs\$CanaryId-sysmon-time.csv"
$rows | Export-Csv -LiteralPath $clockCsv -NoTypeInformation -Encoding UTF8
foreach ($id in 1,3,22) { if (@($rows | Where-Object {$_.Id -eq $id}).Count -eq 0) { throw "FAIL: missing canary Event ID $id" } }
if (@($rows | Where-Object { $_.DeltaSeconds -gt 5 -or -not $_.Fresh }).Count -gt 0) { throw 'FAIL: time mismatch or event outside this canary window' }
'PASS: fresh Event IDs 1/3/22 present; all checked deltas <= 5 seconds'
# Save real console output/transcript outside any frozen dataset/checksum tree.
# No successful output is supplied here: the displayed rows come from this host.

```

Phải có đủ Event 1/3/22 mới trong khoảng RecordId vừa ghi. Bảng phải có cả
SystemTime/UtcTime và độ lệch không quá 5 giây. Đọc bằng RecordId để một SystemTime
cũ bất thường không bị loại khỏi phép kiểm chỉ vì lọc theo StartTime. Hai file CSV/XML
là output thật, cần giữ cùng ảnh toàn màn hình. Microsoft mô tả Sysmon ghi thời gian
UTC: https://learn.microsoft.com/sysinternals/downloads/sysmon ; lệnh đọc event:
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1

Nếu lệch lớn như 107 phút của bộ 20 run: dừng ngay, lưu XML và output W 32 Time,
kiểm đúng NTP SOC-AI, VMware time sync/snapshot/resume và đường xuất log. Raw XML
được lưu trước khi parse; nếu field hỏng thì CSV có thể chưa tạo, vẫn giữ XML và
log lỗi. Không chạy bước copy CSV/PASS khi bước kiểm trước đã lỗi. Sau khi
sửa nguồn giờ, có thể reboot **WIN11-TARGET** ngoài mọi run rồi đo lại; reboot/resync
không tự chứng minh lỗi đã hết. Chỉ canary mới với cả hai trường thời gian đúng mới
cho phép tiếp tục. Không clear Event Log, chỉnh raw hoặc trừ một offset để qua gate.
Sau reboot phải quay lại 10.1, tạo CANARY_ID/cursor mới; không dùng lại capture cũ.

Trước khi sign out, chép CSV/XML thật sang SOC-AI (chỉ quản trị, ngoài mọi run):

```powershell
$SocUser = Read-Host 'SOC-AI SSH username'
if ($SocUser -notmatch '^[a-z_][a-z0-9_-]*$') { throw 'Invalid SOC username' }
$SocHome = (ssh "$SocUser@192.168.58.147" 'printf %s "$HOME"').Trim()
if ($LASTEXITCODE -ne 0 -or $SocHome -notmatch '^(/home/[a-z_][a-z0-9_-]*|/root)$') {
  throw 'Cannot determine SOC home'
}
$SocEvidence = "$SocHome/datn-ai-soar-development-3day/operator-logs/preflight/$CanaryId"
ssh "$SocUser@192.168.58.147" "mkdir -p '$SocEvidence'"
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare SOC evidence directory' }
scp $clockCsv $clockXml "${SocUser}@192.168.58.147:${SocEvidence}/"
if ($LASTEXITCODE -ne 0) { throw 'Cannot copy native time evidence' }
```

Tại console Windows, **đăng xuất (Sign out)** phiên hiện tại. Thực hiện **đăng nhập mới**
bằng mật khẩu của `datn_benign`: nhập sai đúng một lần rồi nhập đúng một lần.
Không thay bước này bằng mở khóa phiên hoặc nhập PIN; cần logon console type 2.
Canary xong chờ final flow về, giữ tách khỏi bucket pilot; preflight không tính quota.
Kiểm quyền đăng nhập của tài khoản trước khi thu, không chỉ trạng thái Enabled.
Trên Kali, tạo một SMB canary thất bại có chủ đích rồi một
canary thành công cho `datn_attack`. Đây là preflight trước mọi run, không phải mẫu train:

```bash
set -euo pipefail
if smbclient '//10.20.0.10/IPC$' \
  -U 'WIN11-TARGET\datn_attack%INTENTIONALLY-WRONG-DATN-PREFLIGHT' \
  -c 'quit'; then
  echo 'FAIL: intentionally wrong SMB password unexpectedly succeeded' >&2
  exit 1
fi
smbclient '//10.20.0.10/IPC$' -U 'WIN11-TARGET\datn_attack' -c 'quit'
echo 'SMB_COMMAND_PREFLIGHT=PASS'
```

Trở lại SOC-AI; vòng lặp chỉ PASS khi **event mới sau cursor** có cả Sysmon và Suricata
đúng nguồn `10.20.0.10`:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
ARCHIVE=/var/ossec/logs/archives/archives.json
CURSOR=$(cat /tmp/datn-preflight.cursor)
CANARY_ID=$(cat /tmp/datn-preflight.id)
CANARY_SINCE=$(cat /tmp/datn-preflight.start-utc)
FRESH="operator-logs/preflight/$CANARY_ID/archives-fresh.jsonl"
CHECK_LOG="operator-logs/preflight/$CANARY_ID/channel-check.txt"
mkdir -p "$(dirname "$FRESH")"
test ! -e "$FRESH"
PASS=0
for attempt in $(seq 1 36); do
  test "$(sudo stat -c '%d:%i' "$ARCHIVE")" = "$(cat /tmp/datn-preflight.identity)"
  test "$(sudo stat -c %s "$ARCHIVE")" -ge "$CURSOR"
  test "$(sudo head -c "$CURSOR" "$ARCHIVE" | sha256sum | awk '{print $1}')" = "$(cat /tmp/datn-preflight.prefix)"
  ATTEMPT_FILE="operator-logs/preflight/$CANARY_ID/attempt-$attempt.jsonl"
  ATTEMPT_REPORT="operator-logs/preflight/$CANARY_ID/attempt-$attempt-report.txt"
  sudo tail -c "+$((CURSOR + 1))" "$ARCHIVE" > "$ATTEMPT_FILE"
  if .venv-ml/bin/python -m scripts.verify_preflight --capture "$ATTEMPT_FILE" \
      --canary-id "$CANARY_ID" --since "$CANARY_SINCE" > "$ATTEMPT_REPORT" 2>&1; then
    cp -- "$ATTEMPT_FILE" "$FRESH"
    cp -- "$ATTEMPT_REPORT" "$CHECK_LOG"
    PASS=1; break
  fi
  printf 'Canary pending %s/36; inspect %s\n' "$attempt" "$ATTEMPT_REPORT"
  sleep 5
done
test "$PASS" -eq 1
cat "$CHECK_LOG"
(cd "$(dirname "$FRESH")" && sha256sum archives-fresh.jsonl channel-check.txt > capture.sha256)
(cd "$(dirname "$FRESH")" && sha256sum --check capture.sha256)
echo 'END_TO_END_PREFLIGHT=PASS'
```

Verifier đọc raw thật: Security4624/4625 console/SMB đúng source, Sysmon1/3/22
nonce/nativeclock, ba HTTP port, bốn DNS request/response, mọi connection có final
flow/counter đúng tuple. Report chứa capture_started_at/checked_at, acceptance
replay lại; file PASS tự viết không hợp lệ. JSON dở ở đuôi file đang tăng chỉ làm
attempt pending; giữ nguyên rồi đọc lại, không cắt/sửa raw. Hết36lần chưaPASS thì
giữ lỗi, sửa nguồn, tạo CANARY_ID mới. Không chạy bù action vào capture cũ.
Mọi SSH/chẩn đoán phải ngoài action bucket.


### 10.5 Enrollment riêng và kiểm rebuild

Enrollment là lịch sử trước run, không phải nhãn benign. Cả hai nhãn dùng cùng 3 user
và endpoint. Không lấy raw đã gán nhãn để tạo “quá khứ”. SOC mở cursor:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
test ! -e evidence/scenario-runs/.active-run.json
ENROLL_ID="ENROLL-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
ENROLL_DIR="$PWD/operator-logs/enrollment/$ENROLL_ID"
test ! -e "$ENROLL_DIR"
mkdir -p "$ENROLL_DIR"
ARCHIVE=/var/ossec/logs/archives/archives.json
test -r "$ARCHIVE"
START_BYTE=$(stat -c %s "$ARCHIVE")
test "$START_BYTE" -gt 0
test "$(dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$((START_BYTE - 1))" count=1 status=none | od -An -t u1 | tr -d ' ')" = 10
stat -c '%d:%i' "$ARCHIVE" > "$ENROLL_DIR/archive.identity"
printf '%s\n' "$START_BYTE" > "$ENROLL_DIR/start-byte.txt"
head -c "$START_BYTE" "$ARCHIVE" | sha256sum | awk '{print $1}' > "$ENROLL_DIR/prefix.sha256"
date -u --iso-8601=seconds > "$ENROLL_DIR/start-utc.txt"
printf '%s\n' "$ENROLL_ID"
```

Windows đã copy/kiểm hash runner. Nhập credential thật tại prompt, nhấn Enter
enrollment sau khi cursor mở; không gọi begin-action:

```powershell
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'WIN11-TARGET') { throw 'Wrong VM' }
$EnrollmentNonce=Read-Host 'Paste exact ENROLL_ID'
& C:\DATN\run_training_account.ps1 `
 -AccountsCsv 'datn_lab01,datn_lab02,datn_lab03' `
 -AttemptsCsv 'datn_lab01:success,datn_lab02:success,datn_lab03:success' `
 -GapsCsv '3,3' -RunNonce $EnrollmentNonce -Enrollment
curl.exe --fail --silent --show-error --output NUL 'http://10.40.0.10:8081/beacon?enrollment=1'
if ($LASTEXITCODE -ne 0) { throw 'HTTP enrollment failed' }
Resolve-DnsName enrollment.www.datn.test -Server 10.40.0.10 -Type A -DnsOnly
```

Kali, cùng ENROLL_ID, đúng mật khẩu cho cả 3 user:

```bash
set -euo pipefail
read -rp 'ENROLL_ID: ' ENROLL_ID
/usr/bin/python3 "$HOME/datn-tools/run_training_account_remote.py" \
 --accounts-csv datn_lab01,datn_lab02,datn_lab03 \
 --attempts-csv datn_lab01:success,datn_lab02:success,datn_lab03:success \
 --gaps-csv 3,3 --run-nonce "$ENROLL_ID" --enrollment
```

SOC chờ log tới, lấy snapshot hữu hạn.120 s là thời gian khởi điểm, không đảm bảo
mọi log đã tới. Boundary phải newline, source/inode/prefix giữ nguyên:

```bash
set -euo pipefail
sleep 120
test "$(stat -c '%d:%i' "$ARCHIVE")" = "$(cat "$ENROLL_DIR/archive.identity")"
START_BYTE=$(cat "$ENROLL_DIR/start-byte.txt")
END_BYTE=$(stat -c %s "$ARCHIVE")
test "$END_BYTE" -gt "$START_BYTE"
test "$(head -c "$START_BYTE" "$ARCHIVE" | sha256sum | awk '{print $1}')" = "$(cat "$ENROLL_DIR/prefix.sha256")"
test ! -e "$ENROLL_DIR/archives-capture.jsonl"
dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$START_BYTE" count="$((END_BYTE - START_BYTE))" status=none > "$ENROLL_DIR/archives-capture.jsonl"
test "$(stat -c '%d:%i' "$ARCHIVE")" = "$(cat "$ENROLL_DIR/archive.identity")"
test "$(wc -c < "$ENROLL_DIR/archives-capture.jsonl")" -eq "$((END_BYTE - START_BYTE))"
test "$(tail -c 1 "$ENROLL_DIR/archives-capture.jsonl" | od -An -t u1 | tr -d ' ')" = 10
printf '%s\n' "$END_BYTE" > "$ENROLL_DIR/end-byte.txt"
date -u --iso-8601=seconds > "$ENROLL_DIR/end-utc.txt"
jq -e . "$ENROLL_DIR/archives-capture.jsonl" >/dev/null
jq -c '
 select(.agent.name=="WIN11-TARGET") |
 (.data.win.system.eventID|tostring) as $id | .data.win.eventdata as $d |
 select(
 ($id=="4624" and (["datn_lab01","datn_lab02","datn_lab03"] |
    index(($d.targetUserName//""|ascii_downcase))) != null) or
 ($id=="3" and ($d.initiated|tostring|ascii_downcase)=="true" and
    $d.sourceIp=="10.20.0.10" and $d.destinationIp=="10.40.0.10" and
    ($d.destinationPort|tostring)=="8081") or
 ($id=="22" and (($d.queryName//""|ascii_downcase)|endswith(".www.datn.test")))
 )' "$ENROLL_DIR/archives-capture.jsonl" > "$ENROLL_DIR/approved-enrollment.jsonl"
test -s "$ENROLL_DIR/approved-enrollment.jsonl"
(cd "$ENROLL_DIR" && sha256sum archives-capture.jsonl approved-enrollment.jsonl > capture.sha256)
(cd "$ENROLL_DIR" && sha256sum --check capture.sha256)
```

Đọc approved capture, đủ3user local type2 và SMB type3 từ10.40.0.10, HTTP/DNS
vừa tạo; raw trước lọc giữ nguyên. Thiếu thì giữ capture lỗi, làm enrollment mới,
không thêm event/history tay. Không có run active khi thay baseline:

```bash
set -euo pipefail
test ! -e evidence/scenario-runs/.active-run.json
if [ -f evidence/context-baseline.json ]; then
 OLD_SHA=$(sha256sum evidence/context-baseline.json | awk '{print $1}')
 test ! -e "$ENROLL_DIR/prior-context-$OLD_SHA.json"
 mv -- evidence/context-baseline.json "$ENROLL_DIR/prior-context-$OLD_SHA.json"
fi
.venv-ml/bin/python -m scripts.enroll_context_baseline \
 --capture "$ENROLL_DIR/approved-enrollment.jsonl" --revision "$ENROLL_ID" \
 --ttl-hours 24 --dns-suffix datn.test --approved-enrollment \
 --output evidence/context-baseline.json
.venv-ml/bin/python - <<'PY'
from pathlib import Path
from ml.context import BaselineSnapshot, verify_baseline_capture, verify_lab_enrollment
b = BaselineSnapshot.model_validate_json(Path("evidence/context-baseline.json").read_text())
raw = (Path("evidence/context-captures") / (b.source_capture_sha256 + ".jsonl")).read_bytes()
verify_baseline_capture(b, raw, windows_agent_name="WIN11-TARGET")
verify_lab_enrollment(b, raw)
print("ENROLLMENT_REBUILD_AND_INVENTORY=PASS")
PY
cp -- evidence/context-baseline.json "$ENROLL_DIR/context-baseline.json"
(cd "$ENROLL_DIR" && sha256sum context-baseline.json > baseline.sha256)
```

Kiểm rebuild chính xác history, không tự điền known_sources hay đổi loopback thành
nguồn giả. DNS suffix datn.test là inventory đã khai báo trước, cần DNS thật.
Domain quen không đồng nghĩa mọi traffic benign. TTL 24 h đủ một buổi; hết hạn dừng,
enrollment/revision mới trước run tiếp theo, không sửa valid_until. Cả hai nhãn
trong pair phải cùng history AVAILABLE/known. Không revert snapshot/clear log giữa
run; baseline frozen của run cũ không bị đổi theo baseline active.

## 11. Đăng ký lịch và context thật trước G7

Trên SOC-AI sau mục 4–10. Mỗi family có 12 slot; template tự đặt bốn slot/ngày,
ba ngày UTC liên tiếp. Cả bucket phải thuộc ngày khai báo. Không mở run qua vùng
23:45–00:15 UTC. Chọn ngày 1 còn đủ thời gian cho G7 và 16 run.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
mkdir -p operator-logs run-drafts
read -rp 'Ngày UTC đầu tiên (YYYY-MM-DD): ' FIRST_TRAIN_DAY
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml registration-template \
 --start-date "$FIRST_TRAIN_DAY" --operator Kien \
 --output operator-logs/development-registration.json
nano operator-logs/development-registration.json
```

Đây chỉ là metadata, không sinh log. Điền mọi TODO bằng điều kiện thật:
environment_id (image/build/config), application_context (ứng dụng/session thực),
reset_reference (snapshot/reset thật, hoặc ghi rõ không reset và lý do), operator.
Giữ hostname, cohort_id và partition=train; giữ ba ngày đã chọn. Không viết nhãn
vào context, không tạo 12 ngày/12 máy giả. Cả hai nhãn trong mỗi context dùng
cùng điều kiện nền. Không revert SOC/Sensor chứa cursor/evidence; reset Windows
chỉ ngoài run và phải kiểm giờ/Agent/enrollment lại. Giữ và khai báo log/history.

```bash
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml plan \
 --registration operator-logs/development-registration.json --seed 42 \
 --output operator-logs/development-plan.json
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml verify-plan \
 --plan operator-logs/development-plan.json
sha256sum operator-logs/development-registration.json operator-logs/development-plan.json
jq '[.runs[]|.partition]|group_by(.)|map({partition:.[0],units:length})' operator-logs/development-plan.json
jq '[.runs[]|{day:.context.collection_date,family,label}]|sort_by(.day,.family,.label)|group_by([.day,.family,.label])|map({day:.[0].day,family:.[0].family,label:.[0].label,units:length})' operator-logs/development-plan.json
jq '[.runs[]|{family,template_id,label}]|sort_by(.family,.template_id,.label)|group_by([.family,.template_id,.label])|map({family:.[0].family,template:.[0].template_id,label:.[0].label,units:length})' operator-logs/development-plan.json
```

Phải PLAN_VERIFIED, 48 đơn vị TRAIN, 12 mỗi nhóm; ba ngày, mỗi ngày bốn mỗi nhóm.
Mỗi đơn vị có ba attempt/seed riêng. Không sửa plan sau tạo; ghi hash và gửi
Thịnh kiểm trước G7. Thiếu ngày thật/TODO sẽ bị từ chối. Khi cần lập lại lịch,
dừng trước thu, giữ kế hoạch cũ và lý do; không chắp quota các kế hoạch khác.
Chỉ có 3 host/day/family dù 12 context/family; không diễn giải thành 12 nhóm độc lập.

## 12. Bốn pilot mới, không thuộc quota train

G7 sử dụng console account benign, SMB account malicious, DNS benign và HTTP
malicious có cả GET/POST v2. Giữ đủ bốn transport. Trên SOC-AI:

```bash
set -euo pipefail
PILOT_PLAN="operator-logs/pilot-plan-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan \
 --catalog config/development-catalog.yaml --kind pilot --output "$PILOT_PLAN"
jq -r '.runs[]|[.ordinal,.scenario_id,.run_id,.purpose,.collection_seed]|@tsv' "$PILOT_PLAN"
sha256sum "$PILOT_PLAN"
```

Chạy từng dòng qua quy trình mục 14. Với pilot, chọn RUN_ID, SCENARIO,
COLLECTION_SEED chính xác từ pilot plan; RUN_PURPOSE=pilot. Draft pilot dùng
scripts.create_run_draft với catalog mới, không dùng draft trainable của kế hoạch
48 đơn vị. Pilot không có campaign_plan trong draft; acceptance sẽ gắn kế hoạch.
Nếu pilot hỏng, abort, giữ toàn bộ evidence, ghi run thay thế/seed mới trong nhật
ký và dùng đúng bốn ID FINALIZED thực tế khi accept. Không đổi tên/thay raw của
pilot cũ để tạo pilot mới.

## 13. Backup/restore và acceptance G7 v3

Tất cả bốn pilot phải FINALIZED, validate VALID và RUN_EVIDENCE_CHECK_PASS. Không
còn active run. Plan ở mục 11 phải có trong operator-logs trước khi backup:

```bash
set -euo pipefail
COLLECTION_TAG=development-collection-v1.0.0-candidate.1
BACKUP_ID="DEV3-PILOT-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
.venv-ml/bin/python -m scripts.collection_release backup \
 --tag "$COLLECTION_TAG" --output-directory "$BACKUP_DIR" \
 > "operator-logs/$BACKUP_ID-report.json"
cat "operator-logs/$BACKUP_ID-report.json"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
```

Phải BACKUP_RESTORED_AND_VALIDATED từ giải nén/validate thật tại thư mục khác.
Không tự gõ PASS. Ghi bốn ID thành công vào bốn prompt sau; không lấy cả run lỗi:

```bash
read -rp 'Pilot console benign FINALIZED ID: ' P_CONSOLE
read -rp 'Pilot SMB malicious FINALIZED ID: ' P_SMB
read -rp 'Pilot DNS benign FINALIZED ID: ' P_DNS
read -rp 'Pilot HTTP v2 malicious FINALIZED ID: ' P_HTTP
PREFLIGHT_DIR="$PWD/operator-logs/preflight/$(cat /tmp/datn-preflight.id)"
test -d "$PREFLIGHT_DIR"
test ! -e evidence/development-acceptance.json
.venv-ml/bin/python -m scripts.collection_release accept --tag "$COLLECTION_TAG" \
 --pilot "$P_CONSOLE" --pilot "$P_SMB" --pilot "$P_DNS" --pilot "$P_HTTP" \
 --backup-dir "$BACKUP_DIR" --preflight-dir "$PREFLIGHT_DIR" \
 --source-config config/development-sources.yaml \
 --output evidence/development-acceptance.json
jq '{version,status,record_sha256,campaign_registration}' evidence/development-acceptance.json
.venv-ml/bin/python -m scripts.collection_release authorize \
 --source-config config/development-sources.yaml
```

Phải collection-acceptance-v3, đúng kế hoạch, COLLECTION_AUTHORIZED. Giữ nguyên
accepted backup directory, preflight, source/runtime và acceptance trên SOC-AI:
mỗi start trainable tái kiểm. Backup mới sau G7 cũng phải chứa development-acceptance.json.
Copy dữ liệu sang máy khác không tự cấp quyền vận hành tiếp: receipt có source và
đường dẫn lab. Khi đổi topology/runtime/source cần xem lại acceptance, không sửa hash.

## 14. Quy trình MỖI run — làm đúng thứ tự

### 14.1 Chọn một attempt đến hạn

SOC-AI, trước mỗi buổi lặp lại toàn bộ mục 10: dịch vụ, clock, canary, enrollment
24 giờ còn hạn. Không chạy mạng/authentication chẩn đoán trong action bucket.
Đăng ký ứng dụng/context thực đúng plan, không đổi để hợp thức hóa sau thu.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
PLAN=operator-logs/development-plan.json
SOURCE=config/development-sources.yaml
DAY=$(date -u +%F)
PROGRESS="operator-logs/schedule-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml progress \
 --plan "$PLAN" --date "$DAY" > "$PROGRESS"
jq '{utc_date,planned_units,finalized_attempts,active_attempts,exhausted_units}' "$PROGRESS"
jq -r '.due[] | [.run_id,.family,.label,.context.collection_date,.template_id] | @tsv' "$PROGRESS"
read -rp 'RUN_ID từ danh sách due (không tự tạo): ' RUN_ID
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$ ]]
test ! -e "run-drafts/$RUN_ID.yaml"
```

progress chỉ là lịch, không phải audit raw hoặc giấy nghiệm thu. Nếu có active
attempt, xử lý nó trước. Không thu sai ngày rồi đổi timestamp. Đã dùng hết ba
attempt hoặc lỡ ngày thì dừng, gửi state cho Thịnh; không thêm attempt ngoài plan.

Với pilot, thay khối chọn due bằng việc chọn một dòng pilot plan ở mục 12 và đặt
SCENARIO/COLLECTION_SEED/RUN_ID/RUN_PURPOSE=pilot. Các bước còn lại giữ nguyên.

Kiểm Windows trước START: ba user datn_lab01/02/03 tồn tại, không disabled/locked;
net accounts báo lockout Never/0 theo mục 7.1. Không dùng tài khoản cá nhân.
Chuẩn bị console actor; không mở RDP/UAC hoặc thao tác auth khác trong bucket.

### 14.2 Đo clock và START ngay

Thực hiện khối đo clock chi tiết ở phụ lục A ngay bên dưới cho RUN_ID hiện tại.
Nó tạo CLOCK_FILE và MEASUREMENTS mới, dùng SSH key/BatchMode và ghi RTT ba thời
điểm, không dùng giờ tự gõ. Sau khi tạo clock file, START trong hạn 120 giây.
Thực hiện một trong hai nhánh sau trên SOC-AI:

Trainable:

```bash
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml draft \
 --plan "$PLAN" --run-id "$RUN_ID" --clock-preflight "$CLOCK_FILE" \
 --source-config "$SOURCE" \
 --execution-log "operator-logs/$RUN_ID-action.txt" --output "run-drafts/$RUN_ID.yaml"
.venv-ml/bin/python -m scripts.scenario_session start \
 --draft "run-drafts/$RUN_ID.yaml" --source-config "$SOURCE"
```

Pilot:

```bash
.venv-ml/bin/python -m scripts.create_run_draft \
 --catalog config/development-catalog.yaml --scenario "$SCENARIO" --run-id "$RUN_ID" \
 --operator Kien --purpose pilot --collection-seed "$COLLECTION_SEED" \
 --clock-preflight "$CLOCK_FILE" --source-config config/development-sources.yaml \
 --execution-log "operator-logs/$RUN_ID-action.txt" --output "run-drafts/$RUN_ID.yaml"
.venv-ml/bin/python -m scripts.scenario_session start \
 --draft "run-drafts/$RUN_ID.yaml" --source-config config/development-sources.yaml
```

Phải STARTED và lưu start-contract/cursor/context/profile. Không sửa draft/state
sau START. Nếu clock quá hạn trước START, giữ file cũ, tạo đo mới với tên suffix
mới và dùng CLOCK_FILE mới; không ghi đè bằng chứng.

### 14.3 Xuất tham số đóng băng, chuyển file và kiểm SHA

SOC-AI tạo cả wrapped export dùng dispatcher v1 và flat export dùng HTTP v2:

```bash
set -euo pipefail
EXPORT_DIR="$PWD/evidence/operator-parameter-exports"
mkdir -p "$EXPORT_DIR"
WRAPPED="$EXPORT_DIR/$RUN_ID-wrapped.json"
FLAT="$EXPORT_DIR/$RUN_ID-flat.json"
test ! -e "$WRAPPED"
.venv-ml/bin/python -m scripts.export_run_parameters --run-id "$RUN_ID" --format json > "$WRAPPED"
.venv-ml/bin/python -m scripts.supplemental_collection --design config/development-design.yaml parameters --run-id "$RUN_ID" --output "$FLAT"
jq '.scenario_parameters|{transport,execution_profile_version,expected_action_count}' "$WRAPPED"
sha256sum "$WRAPPED" "$FLAT"
```

Không copy/sửa schedule bằng tay. File hash vận chuyển khác hash canonical
frozen_parameters_sha256; đối chiếu đúng hash SHA256 của file tải.

Windows PowerShell: HTTP v2 dùng FLAT, console/DNS v1 dùng WRAPPED. Chọn đúng file:

```powershell
$ErrorActionPreference='Stop'
$RunId=Read-Host 'RUN_ID'
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$') { throw 'Bad run ID' }
$Kind=Read-Host 'flat for HTTP v2; wrapped for console/DNS'
if ($Kind -notin @('flat','wrapped')) { throw 'Bad export kind' }
$SocUser=Read-Host 'SOC SSH username'
if ($SocUser -notmatch '^[a-z_][a-z0-9_-]*$') { throw 'Bad SOC user' }
$ExpectedHash=(Read-Host 'Exact file SHA256 from SOC').ToLowerInvariant()
if ($ExpectedHash -notmatch '^[0-9a-f]{64}$') { throw 'Bad hash' }
$ParametersFile="C:\DATN\$RunId-$Kind.json"
if (Test-Path -LiteralPath $ParametersFile) { throw 'Destination already exists' }
scp "${SocUser}@192.168.58.147:datn-ai-soar-development-3day/evidence/operator-parameter-exports/$RunId-$Kind.json" $ParametersFile
if ($LASTEXITCODE -ne 0) { throw 'Copy failed' }
if ((Get-FileHash -LiteralPath $ParametersFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) { throw 'Transport hash mismatch' }
$ActorLog="C:\DATN\$RunId-action.txt"
if (Test-Path -LiteralPath $ActorLog) { throw 'Actor log already exists' }
```

Console/DNS, gọi wrapper và dừng ở ACCOUNT_READY/ACTION_READY, chưa nhấn Enter:

```powershell
& C:\DATN\run_frozen_windows.ps1 -ParametersFile $ParametersFile -ExpectedFileSha256 $ExpectedHash |
 Tee-Object -FilePath $ActorLog
if (-not $?) { throw 'Actor failed; preserve evidence and abort' }
```

HTTP v2: không dùng dispatcher v1 hoặc run_training_http.ps1 cũ. Kiểm version
rồi dừng tại prompt; chỉ nhấn Enter khi SOC begin-action đã thành công:

```powershell
$p=Get-Content -LiteralPath $ParametersFile -Raw | ConvertFrom-Json
if ($p.execution_profile_version -ne 'lab-http-workflow-v2') { throw 'Wrong HTTP profile' }
Read-Host 'Wait for successful SOC begin-action, then press Enter' | Out-Null
Start-Sleep -Milliseconds ([int][Math]::Ceiling([double]$p.pre_action_delay_seconds*1000))
& C:\DATN\run_supplemental_http.ps1 -ParametersPath $ParametersFile | Tee-Object -FilePath $ActorLog
if (-not $?) { throw 'HTTP actor failed; preserve evidence and abort' }
```

SMB chạy Kali bằng wrapped export. Sao chép đúng ID/hash trước begin-action:

```bash
set -euo pipefail
read -rp 'RUN_ID: ' RUN_ID
read -rp 'SOC username: ' SOC_USER
read -rp 'SHA256 wrapped export: ' EXPORT_SHA
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$ ]]
[[ "$SOC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$EXPORT_SHA" =~ ^[0-9a-f]{64}$ ]]
JSON_FILE="$HOME/datn-tools/$RUN_ID-wrapped.json"
test ! -e "$JSON_FILE"
scp "${SOC_USER}@192.168.58.147:datn-ai-soar-development-3day/evidence/operator-parameter-exports/$RUN_ID-wrapped.json" "$JSON_FILE"
test "$(sha256sum "$JSON_FILE" | awk '{print $1}')" = "$EXPORT_SHA"
ACTOR_LOG="$HOME/datn-tools/$RUN_ID-action.txt"
test ! -e "$ACTOR_LOG"
/usr/bin/python3 "$HOME/datn-tools/run_training_account_remote.py" \
 --frozen-file "$JSON_FILE" "$EXPORT_SHA" | tee "$ACTOR_LOG"
```

Nhập credential đúng vào prompt riêng, không qua argv/log. Dừng tại ACCOUNT_READY.
Driver tự thực hiện kết quả fail/success theo schedule; không tạo thêm action.

### 14.4 Begin → hành động thật → complete → finalize

SOC-AI:

```bash
.venv-ml/bin/python -m scripts.scenario_session begin-action --run-id "$RUN_ID" --wait-for-window
```

Chỉ khi thành công mới nhấn Enter tại actor đang sẵn sàng. Không đo clock/SSH
Windows/curl kiểm mạng hoặc chạy actor khác trong bucket. Đợi actor hoàn tất không
lỗi; lưu output thật ra operator-logs, không có credential. Quay về SOC:

```bash
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id "$RUN_ID"
STATE="evidence/scenario-runs/$RUN_ID/.collection_state.json"
END_UTC=$(jq -er '.execution_receipt.aggregation_window_end' "$STATE")
GRACE=$(jq -er '.source.late_arrival_grace_seconds' "$STATE")
CLOSE_EPOCH=$(( $(date -u -d "$END_UTC" +%s) + GRACE ))
while [ "$(date -u +%s)" -lt "$CLOSE_EPOCH" ]; do
 date -u --iso-8601=seconds
 sleep 15
done
```

Sau khi bucket + grace đã đóng, chuyển log actor thật về đúng đường dẫn đã khai
báo trong draft. Việc chờ tránh traffic quản trị mới trong bucket hành động. Không
gõ lại nội dung log, không tạo file rỗng để finalize. Chỉ stdout được Tee ở trên;
credential prompt không lưu vào file. Nếu phát hiện thông tin bí mật, giữ tách
bằng chứng an toàn và dừng để xử lý, không chỉnh raw đã niêm phong.

Windows actor (console/DNS/HTTP), sau khi SOC báo đã qua close epoch:

```powershell
if (-not (Test-Path -LiteralPath $ActorLog)) { throw 'Actor log missing' }
if ((Get-Item -LiteralPath $ActorLog).Length -eq 0) { throw 'Actor log empty' }
$RemoteLog="datn-ai-soar-development-3day/operator-logs/$RunId-action.txt"
ssh "${SocUser}@192.168.58.147" "test ! -e '$RemoteLog'"
if ($LASTEXITCODE -ne 0) { throw 'SOC destination already exists' }
scp $ActorLog "${SocUser}@192.168.58.147:$RemoteLog"
if ($LASTEXITCODE -ne 0) { throw 'Actor log transfer failed' }
$RemoteLine=ssh "${SocUser}@192.168.58.147" "sha256sum '$RemoteLog'"
if ($LASTEXITCODE -ne 0) { throw 'Remote actor log hash failed' }
if ((Get-FileHash -LiteralPath $ActorLog -Algorithm SHA256).Hash.ToLowerInvariant() -ne ($RemoteLine -split '\s+')[0]) { throw 'Actor log hash mismatch' }
```

Kali actor (SMB), chỉ dùng nhánh này thay nhánh Windows:

```bash
set -euo pipefail
test -s "$ACTOR_LOG"
REMOTE_LOG="datn-ai-soar-development-3day/operator-logs/$RUN_ID-action.txt"
ssh "${SOC_USER}@192.168.58.147" "test ! -e '$REMOTE_LOG'"
scp "$ACTOR_LOG" "${SOC_USER}@192.168.58.147:$REMOTE_LOG"
REMOTE_HASH=$(ssh "${SOC_USER}@192.168.58.147" "sha256sum '$REMOTE_LOG'" | awk '{print $1}')
test "$(sha256sum "$ACTOR_LOG" | awk '{print $1}')" = "$REMOTE_HASH"
```

SOC-AI kiểm file đúng ID rồi mới finalize:

```bash
set -euo pipefail
test -s "operator-logs/$RUN_ID-action.txt"
sha256sum "operator-logs/$RUN_ID-action.txt"
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID" --wait-for-window
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.verify_run_evidence --run-id "$RUN_ID"
(cd "evidence/scenario-runs/$RUN_ID" && sha256sum --check checksums.sha256)
```

Không đóng finalize vì đang chờ watermark. Mất SSH: status trước, không start/run
actor lại. FINALIZED chưa thay cho VALID và evidence PASS. Raw tạo tự động trong
data/raw/RUN_ID/scenario_manifest.json và incidents.jsonl. Capture gốc và snapshot
nằm evidence/scenario-runs/RUN_ID. Không chỉ gửi hai file JSON cuối.

### 14.5 Đối chiếu từng run và xử lý lỗi

Phải đúng run/scenario/purpose, context AVAILABLE, observation_quality COMPLETE,
24 feature gốc đầy đủ, clock/cursor/hash/parity nguyên vẹn. C2 cần từng Sysmon3
được chứng minh ProcessGuid/Event1/5, từng transaction HTTP đúng method/nonce/
ordinal/status/response length và final flow đúng tuple/direction. Không chỉ đếm
tổng event. HTTP.length là response, flow byte gồm header, không dùng chúng để
tuyên bố xác minh chính xác request body. Request body được runner tạo vô hại.

Nếu ERROR/PARTIAL/REVIEW: giữ nguyên raw/state/checksum, ghi lý do và thông báo
Thịnh kèm cả thư mục. Không ghép log từ hai lần chạy, cắt đuôi JSON, sửa clock,
thêm Event1 giả, sửa ID hay đổi label. Actor đã thực hiện thì không thực hiện lần
nữa trên cùng RUN_ID. Lỗi đã xác định không thể finalize an toàn thì:

```bash
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
read -rp 'Nguyên nhân abort cụ thể: ' ABORT_REASON
.venv-ml/bin/python -m scripts.scenario_session abort --run-id "$RUN_ID" --reason "$ABORT_REASON"
```

Run FINALIZED nhưng lỗi được phát hiện sau: dùng quarantine --reason, giữ nguyên
evidence và dừng; không tự mở một attempt thứ hai khi đã có finalized. Thịnh điều
tra trước khi cho tiếp tục. Với attempt ABORTED, progress có thể chọn attempt kế
tiếp cùng đơn vị và đúng ngày. Ba lần lỗi/qua ngày cần quyết định thiết kế mới,
không tự thay plan. Raw của attempt không có state là lỗi, không bỏ qua thư mục.

## 15. Kiểm kê mỗi buổi và điều kiện đủ bộ

Sau khi hoàn tất hai thành viên của cặp template đầu tiên, sau mỗi block bốn run
và cuối buổi, chạy replay sớm trên SOC-AI. Không có run active khi kiểm. Lệnh
này kiểm lại raw/evidence và dựng đủ feature của các run đã hoàn tất; không chỉ
đếm thư mục hay nhìn status FINALIZED. Không đổi Python/source đang thu.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-development-3day"
EARLY_REPORT="operator-logs/development-progress-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM.json"
.venv-ml/bin/python -m ml.development_dataset review-progress \
 --input-project "$PWD" --plan operator-logs/development-plan.json --output "$EARLY_REPORT"
jq '{status,utc_date,dataset_ready,blocking_issues,uncollected_units,template_coverage}' "$EARLY_REPORT"
```

DEVELOPMENT_PROGRESS_REPLAY_IN_PROGRESS chỉ nói đã replay phần thu xong, còn
đơn vị chưa thu đúng lịch. Báo cáo giữ nguyên full_audit và mọi issue: thiếu đơn
vị của hôm nay/ngày sau được liệt kê uncollected, không giả là đủ dataset. Thiếu
đơn vị của ngày UTC đã qua, raw lỗi, clock/parity lỗi, active run hoặc vector hai
nhãn trùng nhau đều BLOCKED với exit khác0: dừng xử lý, không bỏ lệnh cho qua.
Sau đủ48, inspector có thể COMPLETE nhưng dataset_ready vẫn false; còn cần
audit/build/exact review mục17. Kiểm template_coverage với ma trận mục0.1.

Không còn active run. Dùng progress ở mục 14.1 rồi đối chiếu từng ID với validate,
verify_run_evidence và checksum. Kết thúc ngày 1 cần 16, ngày 2 lũy kế 32, ngày 3
lũy kế 48. Mỗi ngày phải bốn run hợp lệ cho từng nhóm; không bù ngày cũ bằng run
ngày khác. progress đủ quota không tự cấp READY. Mỗi buổi phải backup mục 16.

Đủ bộ khi có 48 đơn vị/12 mỗi nhóm, mỗi đơn vị chỉ một FINALIZED hợp lệ, mọi
attempt trước đã ABORTED đúng lý do, không orphan raw/state, tất cả cùng nguồn,
G7, plan, ngày UTC và context đã đăng ký. Raw24/parity/clock/cursor không thay;
56 feature dẫn xuất có chứng cứ HTTP/flow/process-context đúng. Giữ pilot, retry
và challenge riêng; không dùng bù quota. Không trộn bộ 40 hoặc 216 vào đợt này.
Nếu mẫu TRAIN hai nhãn có đầu vào mô hình giống nhau, Thịnh phải báo xung đột;
không sửa nhãn/feature để ép điểm đẹp. Không có validation/test để báo nghiệm thu.

## 16. Backup thật và gói bàn giao cho Thịnh

Không active run. Giữ backup đã gắn G7, tạo backup mới sau mỗi buổi:

```bash
set -euo pipefail
BACKUP_ID="DEV3-DATA-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
.venv-ml/bin/python -m scripts.collection_release backup \
 --tag development-collection-v1.0.0-candidate.1 --output-directory "$BACKUP_DIR" \
 > "operator-logs/$BACKUP_ID-report.json"
cat "operator-logs/$BACKUP_ID-report.json"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
```

Chỉ bàn giao khi BACKUP_RESTORED_AND_VALIDATED. Gửi nguyên backup directory:
archive, descriptor, restore report, checksums. Gửi thêm backup pilot đã gắn G7,
candidate/tag/full SHA/runtime inventory, development registration/plan,
preflight/enrollment, journal attempt và ảnh toàn màn hình. Rà descriptor để xác
nhận development-acceptance.json, raw, evidence, operator-logs và plan thật có
trong archive. Khóa/mật khẩu/.env/credential không gửi. File ngoài phạm vi backup
phải đóng gói/checksum riêng, không tự khẳng định đã có trong archive.

Trên máy Windows nhận dữ liệu, lấy verifier từ đúng tag GitHub, dùng
scripts/verify_collection_backup.ps1 -Directory <đường dẫn backup đã tải>.
Phải hash khớp sau chuyển file; verifier Windows chỉ xác minh vận chuyển/receipt,
không thay raw replay hoặc chứng minh đã chạy lab. Thịnh chỉ nạp dữ liệu, code
luôn checkout GitHub đúng SHA; không cần gửi code offline.

## 17. Thịnh: audit → build → exact review → stage

Chỉ chạy checkout sạch đúng tag mới và runtime có inventory trong
config/development-training-review.json. Runtime collector Kiên được G7 ghi
riêng. Builder hiện có D:\Repo\.venv-codex; không pip upgrade hoặc tự thêm hash
runtime cho qua. Input là root restore có data/raw, evidence và operator-logs,
không chỉ thư mục scenario-runs hay tám file đầu ra cuối. Giữ nguyên cả backup.

Trên máy Thịnh, checkout tag từ GitHub trong D:\Repo sau khi đảm bảo không có
thay đổi đang làm. Môi trường .venv-codex được giữ; dữ liệu cũ giữ riêng.

```powershell
$ErrorActionPreference='Stop'
Set-Location D:\Repo
git status --short
if (git status --porcelain --untracked-files=all) { throw 'Source checkout is dirty' }
git fetch origin tag development-collection-v1.0.0-candidate.1
if ($LASTEXITCODE -ne 0) { throw 'Fetch failed' }
git switch --detach development-collection-v1.0.0-candidate.1
if ($LASTEXITCODE -ne 0) { throw 'Checkout failed' }
$Python='D:\Repo\.venv-codex\Scripts\python.exe'
$InputProject=Read-Host 'Full restored input-project path'
$Plan=Join-Path $InputProject 'operator-logs\development-plan.json'
$Stamp=Get-Date -Format yyyyMMddTHHmmss
$Audit="D:\development-audit-$Stamp.json"
& $Python -B -X utf8 -m ml.development_dataset audit --input-project $InputProject --plan $Plan --output $Audit
if ($LASTEXITCODE -ne 0) { throw 'Raw audit failed; preserve report' }
& $Python -B -X utf8 -m ml.development_dataset build --input-project $InputProject --plan $Plan --output D:\Repo\data\processed-development-v1
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
$ReviewProposal="D:\development-review-$Stamp.json"
& $Python -B -X utf8 -m ml.development_dataset propose-review --input-project $InputProject --plan $Plan --processed D:\Repo\data\processed-development-v1 --output $ReviewProposal
if ($LASTEXITCODE -ne 0) { throw 'Exact review proposal failed' }
```

Build chỉ báo DEVELOPMENT_BUILT_REQUIRES_EXACT_REVIEW. propose-review replay
raw lần nữa, kiểm đúng manifest/partition và ghi đề xuất, không tự cấp quyền.
Chủ repo đọc audit, xác nhận scope/dữ liệu, commit chính xác đề xuất vào
config/development-training-review.json với status READY, merge GitHub.
Chỉ review phát triển này thay đổi; không sửa policy bộ 40 hoặc formal216.
Chưa có raw mới thì không điền READY/approved_manifest_sha256. Lưu SHA review
READY do chủ repo phê duyệt làm EXPECTED_TRAINING_COMMIT; không tự lấy SHA do
manifest bất kỳ cung cấp. Review dataset khác với COLLECTION_READY cho source.

Sau khi commit review READY đã merge, checkout detached SHA đó thật sạch:

```powershell
$ApprovedSha=Read-Host 'Owner-approved full READY review SHA'
if ($ApprovedSha -notmatch '^[0-9a-f]{40}$') { throw 'Invalid owner SHA' }
git fetch origin main
if ($LASTEXITCODE -ne 0) { throw 'Fetch failed' }
git switch --detach $ApprovedSha
if ($LASTEXITCODE -ne 0) { throw 'Checkout failed' }
$Stage="D:\DATN-DEVELOPMENT-COLAB-$Stamp"
& $Python -B -X utf8 -m ml.development_dataset stage --processed D:\Repo\data\processed-development-v1 --output $Stage
if ($LASTEXITCODE -ne 0) { throw 'Safe staging failed' }
Get-ChildItem -LiteralPath $Stage
```

Chỉ ba file: train.jsonl, dataset_manifest.json, colab-upload.sha256. Dẫn xuất
chứa đúng 48 TRAIN row, không tạo validation/test rỗng hoặc giả. Stage không
được ghi đè; giữ bộ cũ riêng. Không copy raw, credential, backup lên Colab.

## 18. Google Colab và đọc kết quả đúng scope

Upload ba file staging vào
MyDrive/DATN/development-3day-data/processed-development-v1.
Mở notebooks/development_train_colab.ipynb từ đúng SHA review READY trên GitHub,
sao chép Drive, điền SHA đó, chọn CPU và phiên mới. Không dùng week3/stream/
supplemental notebook cho bộ 48 này. Chạy từng cell theo thứ tự: kiểm checksum/
source/manifest trước cài, CPython3.12.15 cô lập, dependency lock, EDA TRAIN,
Ruff/toàn bộ pytest có log tiến độ, grouped development training, đọc metric,
xuất artifact. Không ngắt chỉ vì bước kiểm chạy lâu; xem tên test đang chạy và log thật.

Model so sánh Logistic Regression, Random Forest và XGBoost, grouped theo đúng
ba host/day. Account có 24 row; C2 có 24 row. OOF threshold là lựa chọn trên
TRAIN, không báo là test/validation độc lập; CI null và external NOT_COLLECTED.
Đọc PR-AUC/precision/recall/FPR/F1/Brier/ECE, fold-selected models, đối chiếu
baseline và xung đột đầu vào. Đủ quota hoặc train thành công không chứng minh
khả năng vận hành an toàn. Không giảm gate/đổi split để sửa điểm.

Notebook lưu archive riêng development-model-<model_version>.tar.gz và SHA256
vào MyDrive/DATN/development-3day-results; chứa development_model.joblib,
metadata, metrics_development, schema, EDA và log, không chứa raw/locked.
Chỉ mở joblib tự mình tạo và đã đối chiếu hash. Artifact offline này không phải
production model-package, không freeze_model/đưa vào /predict/http/n8n response.
Không có chỉ tiêu automation đạt trong đợt này; giữ false ở mọi tầng báo cáo.
Thu external validation/test độc lập là công việc sau nếu cần nghiệm thu vận hành.

API/caches HTTP hiện hữu vẫn giữ nguyên tính năng. Trong đợt thu không thay n8n
production hoặc gắn artifact phát triển vào API. Không cần OpenAI key/GPU để thu.

## 19. Chụp minh chứng thật và checklist bàn giao

Trên laptop Windows chụp bằng Win+PrtScn toàn desktop đang hiển thị VMware hoặc
công cụ thật. Giữ thanh VMware, viền cửa sổ và taskbar như mẫu của Thịnh; không
cắt, zoom/resize, ghép nội dung hay chụp script PowerShell in PASS giả. Diagonal
16 inch không quyết định kích thước pixel: giữ nguyên độ phân giải màn hình gốc.
Ảnh gốc lưu D:\Tài liệu\Đồ án\Ảnh báo cáo\Development-3day-20261123, tên thứ tự,
UTC/VM/run/bước. Thịnh sẽ cắt sau. Không chụp credential/key/.env.

Chụp từng pha: inventory/NIC/routes; dịch vụ Wazuh/Sysmon/Suricata; native event
và EVE thật; canary/clock/enrollment; đăng ký plan/hash; mỗi pilot từ start đến
validate; backup restore/G7; từng run từ START/action thật/finalize/validate;
tiến độ/abort/retry; final audit; chuyển file/checksum; Colab EDA/quality/metrics/
export. Dùng lệnh chuẩn hostnamectl, ip -br a, systemctl status, ss, journalctl,
Get-Service, Get-WinEvent và công cụ UI thật; không dựng màn hình bằng printf.

Checklist: đúng4VM/source/runtime;48đơn vị/12mỗi nhóm/3ngày;UTC/context/role đúngplan;
không orphan/raw thiếu state;mọi attempt đủ evidence;24gốc/parity giữ nguyên;
56mới có chứng cứ;4pilot/G7v3/backuprestore thật;không dùng pilot bùquota;
không tạo validation/test giả;exact reviewREADY mới;chỉ3file stage;artifact offline/hash/ảnh.
Không ghi nhận hoàn thành một mục khi chưa có bằng chứng thực.

## Phụ lục A. Đo clock chuẩn cho từng RUN_ID

Trên SOC-AI, RUN_ID đã chọn, SSH key và user đúng theo mục7.4. Đặt CLOCK_FILE,
MEASUREMENTS mới. Sau khối này thực hiện ngay draft/start mục14.2:

```bash
set -euo pipefail
CLOCK_FILE="run-drafts/$RUN_ID-clock.yaml"
# Nhập user thật; placeholder bị từ chối.
read -rp 'NET-SENSOR SSH username: ' SENSOR_USER
read -rp 'Kali SSH username: ' KALI_USER
CLOCK_KEY="$HOME/.ssh/id_ed25519_datn_clock"
[[ "$SENSOR_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$KALI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
test "$SENSOR_USER" != sensor-user
test "$KALI_USER" != kali-user

# Lưu ba thời điểm thật cho từng máy; không so sánh các lần đọc nối tiếp.
mkdir -p run-drafts
MEASUREMENTS="run-drafts/$RUN_ID-clock-measurements.json"
.venv-ml/bin/python - "$MEASUREMENTS" <<'PY'
import json, sys
with open(sys.argv[1], 'x', encoding='utf-8') as handle:
    json.dump({}, handle)
PY
measure_clock() {
  local host="$1" before remote after
  shift
  before=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
  remote=$("$@" | tr -d '\r')
  after=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
  .venv-ml/bin/python - "$MEASUREMENTS" "$host" "$before" "$remote" "$after" <<'PY'
import json, sys
from pathlib import Path
path, host, before, remote, after = sys.argv[1:]
data = json.loads(Path(path).read_text(encoding='utf-8'))
if host in data:
    raise SystemExit('Duplicate host measurement; use a new run ID')
data[host] = dict(controller_before=before, remote_utc=remote, controller_after=after)
Path(path).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
PY
}
measure_clock controller date -u +%Y-%m-%dT%H:%M:%S.%NZ
measure_clock target ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  datn_clock@192.168.58.148 powershell.exe -NoProfile -NonInteractive -Command \
  "[DateTimeOffset]::UtcNow.ToString('o')"
measure_clock wazuh date -u +%Y-%m-%dT%H:%M:%S.%NZ
measure_clock sensor ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${SENSOR_USER}@192.168.58.150" date -u +%Y-%m-%dT%H:%M:%S.%NZ
measure_clock attacker ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${KALI_USER}@192.168.58.132" date -u +%Y-%m-%dT%H:%M:%S.%NZ
cat "$MEASUREMENTS"
.venv-ml/bin/python -m scripts.build_clock_preflight \
  --measurements "$MEASUREMENTS" --maximum-skew-seconds 5 \
  --maximum-roundtrip-seconds 4 --output "$CLOCK_FILE"

```

## Phụ lục B. Nguồn chính thức và cách đọc bằng chứng

- Wazuh OS hỗ trợ: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html
- Gói Wazuh: https://documentation.wazuh.com/current/installation-guide/packages-list.html
- Source installer pin: https://github.com/wazuh/wazuh-installation-assistant/tree/v4.14.9
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Suricata EVE8: https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html
- sklearn grouped CV: https://scikit-learn.org/stable/modules/cross_validation.html

Trang current có thể đổi; phiên bản bất biến và inventory thực của lab là bằng
chứng tái lập. Không lấy một ảnh Active để thay toàn bộ log/clock/parity. Không
khẳng định không thể có lỗi vận hành: các gate dùng để phát hiện và dừng an toàn,
giữ dữ liệu để điều tra thay vì che mất lỗi. Bản phần mềm cần Kiên chạy nghiệm
thu thật trên bốn VM; máy của Thịnh không chứa lab này.
