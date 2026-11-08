# HƯỚNG DẪN THU DATASET SOC–AI–SOAR — 4 VM
Bản vận hành 08/11/2026. Mọi code/resource lấy từ GitHub:
https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.2

## 0. Phạm vi và trạng thái

Kiên vận hành lab, giữ raw/evidence; Thịnh kiểm dataset và huấn luyện. Làm từng
khối trên đúng VM ghi trong tiêu đề. Bash dùng user thường có sudo; Windows dùng
Windows PowerShell 5.1 64-bit Administrator. Biến terminal không tồn tại qua phiên
mới: mất SSH phải đọc lại plan/state, không start lại run đang có.

Đây là phần mềm ứng viên đã kiểm thử, cần nghiệm thu thật trên bốn VM của Kiên.
Không tuyên bố các VM đó đã chạy bản này. Bốn pilot cũ giữ làm tham chiếu, không
đổi purpose/source/hash để biến thành trainable. Không cần code offline, OpenAI
key, model đã train hay Atomic Red Team để thu dữ liệu.

Cần thu mới account-benign, account-malicious, c 2-benign, c 2-malicious. Mỗi nhóm
5 scenario/5 cohort ×2 run =10, tổng40. Khuyến nghị48: lần thứ ba cho cả hai
scenario thuộc PAIR-01/02 ở mỗi family, phân bố3-3-2-2-2 =12/nhóm.
Pilot, challenge, enrollment, ABORTED/quarantine không tính quota. Không lặp một
scenario 10 lần để thay năm cohort.

24 feature học profile hoạt động lab đã khai báo: số lượng, nhịp, kết quả, độ
phân tán. Ý định không quan sát được không thể suy ra chắc chắn. 40–48 run đủ mở
thí nghiệm ban đầu theo quota phần mềm, không đảm bảo phát hiện tổng quát.
Chỉ một cohort validation/nhãn chưa đủ uncertainty: phải giữ insufficient/null,
automation_eligible=false và SHADOW/ASSISTED.

Không clear log, sửa raw clock, trim event gây fail, thêm dữ liệu bằng tay, đổi
nhãn sau quan sát hoặc mở locked_test để chọn model. Không đưa mật khẩu, .env,
private key vào lệnh, ảnh, Git hoặc dataset.

## 1. Lộ trình và đầu ra bắt buộc

1. Hardware/snapshot/NIC (4–5); cài công cụ và GitHub candidate (6–9).
2. Isolation, dịch vụ, measured clock, canary thật (10.1–10.4).
3. Enrollment riêng, kiểm rebuild baseline (10.5).
4. Bốn pilot mới theo mục 11 (10.6); backup restore +acceptance (10.7).
5. Một kế hoạch40/48 và challenge riêng, mục11 cho từng run (12).
6. Final audit, build/Colab (13); backup/checksum/bàn giao/ảnh (14–16).

Một run đạt cần FINALIZED, validate VALID, RUN_EVIDENCE_CHECK_PASS, context
AVAILABLE, observation_quality COMPLETE, đủ 24 feature, checksum và full-capture
parity. Collector tự tạo scenario_manifest.json/incidents.jsonl sau finalize.
Không tạo file mẫu rồi coi là dữ liệu train.

Candidate.2 kiểm từng hành động Sysmon với transaction EVE và final flow, cùng
HTTP endpoint/sequence/status và DNS query status/answer. Thiếu một transaction
hoặc sai response không được xem là COMPLETE dù số event còn lại đủ min gate.
Không bỏ dòng gây lỗi; giữ evidence, abort đúng quy trình và chạy mới theo retry plan.
Auditor lấy quota/repetition từ collection design; không hạ tham số để ép READY.
Seed mỗi run phải duy nhất toàn bộ bốn nhóm và cả pilot/challenge, không chỉ trong
từng nhãn. Mục tiêu48 phải thêm đúng PAIR-01/02; không chuyển lần thứ ba sang
PAIR-03/04 để ép TARGET_MET.

## 2. Kiến trúc cố định

| VM | Hostname | Management VMnet8 | Data NIC |
|---|---|---|---|
| Kali | ATTACK-LAB |192.168.58.132|10.40.0.10/24 VMnet2|
| Windows11 | WIN11-TARGET |192.168.58.148|10.20.0.10/24 VMnet3|
| Ubuntu Wazuh+Collector | SOC-AI |192.168.58.147|Không cần|
| Ubuntu Suricata/router | NET-SENSOR |192.168.58.150|10.40.0.1 VMnet2;10.20.0.1 VMnet3|

Data đi qua NET-SENSOR; VMnet2/3 không DHCP/NAT/bridge/host adapter.
Management chỉ Wazuh/SSH/NTP, chặn peer theo10.1. Không cần DC/VMthứ5.
Không dùng IP 192.168.149.128 của VM cũ. Nếu lab khác inventory phải chốt source
mới trước nghiệm thu, không thay giữa đợt.

## 3. Cổng kiểm soát

G0: VM/NIC/isolation/disk. G1: annotated tag/fullSHA/clean tree/runtime.
G2: hai Agent Active và Archives thật. G3: Sysmon/Security/EVE/canary/final flow.
G4: measured clock và native SystemTime/UtcTime<=5s. G5: enrollment đủ3neutraluser
local+SMB/HTTP8081/DNS. G6:4pilot mới VALID/PASS+backup restore. G7:acceptance
tái kiểm source/design/preflight/pilots/restore. G8:40–48trainable,audit/build.

collection-design.yaml ghi thiết kế đã triển khai, lab acceptance pending; không
sửa file này để mở G7. Record riêng evidence/collection-acceptance.json là gate
thực thi cho lab. Pilot được phép trước G7, trainable bị chặn nếu thiếu/hỏng/không
khớp source/runtime/evidence. Record là integrity hash, không phải chữ ký hay
chứng nhận độc lập. Mỗi start trainable tái kiểm; không bypass bằng CLI/API khác.


## 4. Chuẩn bị và snapshot

Khuyến nghị SOC-AI và NET-SENSOR dùng Ubuntu Server 24.04 LTS x86_64 vì đây là bản
Ubuntu nằm trong danh sách hỗ trợ của Wazuh 4.14. Không dùng dữ liệu cá nhân hoặc tài
khoản thật trong lab.

Tài nguyên khởi điểm:

- SOC-AI: tối thiểu 4 vCPU, 8 GB RAM, 80 GB disk cho Wazuh all-in-one; khuyến nghị
  12–16 GB RAM nếu chạy đồng thời Docker, n 8 n và API. Trong lúc thu dữ liệu nên dừng
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

Kế hoạch FINAL P 49 ghi 4.14.7; quyết định kỹ thuật đề xuất cho bản bàn giao này
là **4.14.9** theo quyết định kỹ thuật duy trì bản bàn giao; ghi sai khác với kế hoạch
trong evidence pilot. Ma trận đích: manager, indexer, dashboard
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
PROJECT_ROOT="$HOME/datn-ai-soar-v4"
COLLECTION_TAG=collection-v4.0.0-candidate.2
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
cd "$HOME/datn-ai-soar-v4"
id
test -r /var/ossec/logs/archives/archives.json
stat -c '%U %G %a %n' /var/ossec/logs/archives/archives.json
```

Không chmod777, chạy repo bằng root hay tạo Archives giả/rỗng. Kiểm quyền sau
logrotate. Không mở run qua vùng 23:45–00:15 UTC.

### 6.3 Bảo trì nguồn

Không git pull trong checkout đang thu. Đóng/abort run có lý do, backup rồi dùng
checkout/tag mới nếu cần thay code/config. Không ghép raw các release vào quota
mới. a 82705 d, pilot-v 3.8, data-collection-v 2 là lịch sử. Tài liệu phục hồi pilot
lịch sử không thay quy trình hiện hành mục 11.


### 6.4 API/n8n là phần kiểm tích hợp, tách khỏi việc chuẩn bị dữ liệu

Collector đọc Archives trực tiếp; dựng lab, enrollment và thu pilot không cần model
đã train hoặc API/n8n đang chạy. Vì vậy tránh vòng lặp “phải có model mới thu được data”.

Đây là mục TÙY CHỌN kiểm tích hợp, không chạy trong lúc thu. Chỉ khi Thịnh đã cung
cấp package v3 đã freeze, `.env` qua kênh riêng với signing key khớp package, đúng
N8N_PUBLIC_HOST=192.168.58.147, N8N_BIND_ADDRESS=127.0.0.1, VT_MODE=mock và
NOTIFICATION_MODE=log, mới deploy. Không tự sinh signing key khác để xác minh package
của Thịnh; không đưa `.env` vào backup dataset hoặc ảnh:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$(id -un)"
```

Mở phiên mới để group Docker có hiệu lực rồi chạy:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
docker version
docker compose version
test -s evidence/context-baseline.json
test -f ml/model-package/FROZEN.json
test -f .env
chmod 600 .env
bash scripts/deploy_week2.sh
bash scripts/verify_week2.sh
curl -fsS http://127.0.0.1:8000/health | jq .
curl -fsS http://127.0.0.1:8000/ready | jq .
curl -fsS http://127.0.0.1:5678/healthz
```

Không train hoặc đóng gói một model giả để vượt bước này. Package schema v 2 không
được dùng với vector v3. Baseline được mount chỉ đọc vào API; thiếu/hết hạn phải xử lý
trước deploy. Ingest online là tạm thời/REVIEW; kết quả cửa sổ cuối cần endpoint
`/features/wazuh/finalize-window` sau watermark. Workflow hiện chưa tự đóng window.
Không yêu cầu nhập OpenAI API key vào hộp Assistant của n 8 n để chạy collector hay ML.


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
scp "${SocUser}@192.168.58.147:datn-ai-soar-v4/scripts/Test-DatnWindowsPreflight.ps1" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw 'Cannot copy the Windows preflight helper' }
Get-FileHash C:\DATN\Test-DatnWindowsPreflight.ps1 -Algorithm SHA256
```

Đối chiếu hash với `sha256sum scripts/Test-DatnWindowsPreflight.ps1` trên SOC-AI.
Helper chỉ đọc trạng thái; quyền sửa user/firewall nằm ở các bước riêng bên dưới.

Từ SOC-AI, chạy sha256sum cho config/sysmon-datn.xml và
config/wazuh-windows-localfile.xml; trên Windows dùng Get-FileHash từng file vừa
copy và đối chiếu hai SHA trước khi cài. Sai một byte thì dừng, copy lại từ checkout
đã pin. Tương tự helper Test-DatnWindowsPreflight.ps1 phải khớp SHA hiển thị ở SOC.


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
$SocRepo = "$SocHome/datn-ai-soar-v4"
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
foreach ($runnerName in 'run_training_http.ps1','run_training_account.ps1',
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
SOC_REPO="$SOC_HOME/datn-ai-soar-v4"
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
SOC_REPO="$SOC_HOME/datn-ai-soar-v4"
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

Khởi động ba dịch vụ tạm thời; chạy lại sau mỗi reboot:

```bash
sudo systemd-run --unit=datn-http-benign --property=Restart=on-failure \
  --working-directory=/srv/datn/benign \
  /usr/bin/python3 -m http.server 8080 --bind 10.40.0.10
sudo systemd-run --unit=datn-http-beacon --property=Restart=on-failure \
  --working-directory=/srv/datn/beacon \
  /usr/bin/python3 -m http.server 8081 --bind 10.40.0.10
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


### 9.3 Driver SMB trên Kali

```bash
set -euo pipefail
sudo apt update
sudo apt install -y python3-impacket openssh-client
/usr/bin/python3 -c 'from impacket.smbconnection import SMBConnection, SessionError; import inspect; print(inspect.signature(SMBConnection.login))'
mkdir -p "$HOME/datn-tools"
read -rp 'SOC-AI SSH username: ' SOC_USER
[[ "$SOC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
scp "${SOC_USER}@192.168.58.147:datn-ai-soar-v4/scripts/run_training_account_remote.py" "$HOME/datn-tools/"
REMOTE_HASH=$(ssh "${SOC_USER}@192.168.58.147" 'sha256sum "$HOME/datn-ai-soar-v4/scripts/run_training_account_remote.py"' | awk '{print $1}')
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
cd "$HOME/datn-ai-soar-v4"
test -z "$(git status --porcelain)"
COLLECTION_TAG=collection-v4.0.0-candidate.2
.venv-ml/bin/python -m scripts.collection_release candidate --tag "$COLLECTION_TAG" > operator-logs/releases/candidate-current.json
cmp operator-logs/releases/candidate.json operator-logs/releases/candidate-current.json
mkdir -p evidence/scenario-runs
test ! -e evidence/scenario-runs/.active-run.json
while IFS= read -r -d '' STATE; do
  jq -e 'type=="object" and (.status=="FINALIZED" or .status=="ABORTED")' "$STATE" >/dev/null
done < <(find evidence/scenario-runs -mindepth 2 \
  -name .collection_state.json -print0)
.venv-ml/bin/python -m scripts.scenario_session --help >/dev/null
.venv-ml/bin/python -m scripts.audit_dataset --help >/dev/null
.venv-ml/bin/python - <<'PY'
import json
from pathlib import Path
import yaml
source = yaml.safe_load(Path('config/collection-sources.yaml').read_text())
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
cd "$HOME/datn-ai-soar-v4"
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
$SocEvidence = "$SocHome/datn-ai-soar-v4/operator-logs/preflight/$CanaryId"
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
cd "$HOME/datn-ai-soar-v4"
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
cd "$HOME/datn-ai-soar-v4"
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

### 10.6 Bốn pilot mới

```bash
set -euo pipefail
PLAN="run-drafts/pilot-plan-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan --kind pilot --output "$PLAN"
sha256sum "$PLAN"
jq -r '.runs[]|[.ordinal,.scenario_id,.run_id,.purpose,.collection_seed]|@tsv' "$PLAN"
```

Plan phủ console account benign hai sai rồi đúng, SMB malicious sáu sai, DNS
benign, HTTP beacon malicious. Plan chỉ metadata, zero telemetry. Chạy mục 11
ordinal1..4. Mỗi pilot phải VALID/PASS; failed giữ nguyên, ID không tái dùng.

### 10.7 Backup restore thật, tạo acceptance G 7

```bash
set -euo pipefail
COLLECTION_TAG=collection-v4.0.0-candidate.2
BACKUP_ID="PILOT-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
.venv-ml/bin/python -m scripts.collection_release backup \
 --tag "$COLLECTION_TAG" --output-directory "$BACKUP_DIR" > "operator-logs/$BACKUP_ID-report.json"
cat "operator-logs/$BACKUP_ID-report.json"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
mapfile -t PILOTS < <(jq -r '.runs[].run_id' "$PLAN")
test "${#PILOTS[@]}" -eq 4
PREFLIGHT_DIR="$PWD/operator-logs/preflight/$(cat /tmp/datn-preflight.id)"
test ! -e evidence/collection-acceptance.json
.venv-ml/bin/python -m scripts.collection_release accept --tag "$COLLECTION_TAG" \
 --pilot "${PILOTS[0]}" --pilot "${PILOTS[1]}" --pilot "${PILOTS[2]}" --pilot "${PILOTS[3]}" \
 --backup-dir "$BACKUP_DIR" --preflight-dir "$PREFLIGHT_DIR" \
 --output evidence/collection-acceptance.json > "operator-logs/$BACKUP_ID-acceptance.json"
cat evidence/collection-acceptance.json
sha256sum evidence/collection-acceptance.json
```

Backup phải BACKUP_RESTORED_AND_VALIDATED: đã giải nén root tạm khác, validate và
đối chiếu protected files thực. Không dùng file PASS tự gõ.
Bốn ID phải là pilot VALID mới cùng candidate/strata; nếu retry, lấy ID thay thế
thật trong nhật ký, không dùng lại failed từ plan gốc. Acceptance replay cả raw
preflight/report, source/runtime, thiết kế, pilot và restore. Thiếu phải ERROR.
Giữ nguyên backup/preflight directory: mỗi start trainable kiểm lại. Không dọn
artifact đã gắn acceptance; không sửa path/hash khi copy sang máy khác.

## 11. Quy trình chuẩn cho MỖI run

### 11.1 Chọn dòng plan, kiểm account trước start

SOC giữ PLAN đúng pilot/minimum/preferred/challenge. Không tạo nhiều plan để lựa
theo outcome. Mỗi lần chọn ordinal kế tiếp:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v4"
read -rp 'Ordinal: ' ORDINAL
[[ "$ORDINAL" =~ ^[1-9][0-9]*$ ]]
RUN_ID=$(jq -er --argjson n "$ORDINAL" '.runs[]|select(.ordinal==$n)|.run_id' "$PLAN")
SCENARIO=$(jq -er --argjson n "$ORDINAL" '.runs[]|select(.ordinal==$n)|.scenario_id' "$PLAN")
RUN_PURPOSE=$(jq -er --argjson n "$ORDINAL" '.runs[]|select(.ordinal==$n)|.purpose' "$PLAN")
COLLECTION_SEED=$(jq -er --argjson n "$ORDINAL" '.runs[]|select(.ordinal==$n)|.collection_seed' "$PLAN")
printf '%s %s %s %s\n' "$RUN_ID" "$SCENARIO" "$RUN_PURPOSE" "$COLLECTION_SEED"
UTC_HHMM=$(date -u +%H%M)
test "$UTC_HHMM" -lt 2345
test "$UTC_HHMM" -gt 0015
test ! -e "evidence/scenario-runs/$RUN_ID"
test ! -e "data/raw/$RUN_ID"
```

Windows trước start, chỉ target workgroup lab:

```powershell
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'WIN11-TARGET') { throw 'Wrong VM' }
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Disposable workgroup only' }
net accounts
$labAccountNames=@('datn_lab01','datn_lab02','datn_lab03')
foreach ($name in $labAccountNames) {
 $user = [ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $name)
 $user.IsAccountLocked = $false
 $user.SetInfo()
}
$labAccounts=@(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
 Where-Object { $_.Name -in $labAccountNames })
$labAccounts | Select-Object Name,Disabled,Lockout
$invalidAccounts=@($labAccounts | Where-Object { $_.Disabled -or $_.Lockout })
if ($labAccounts.Count -ne 3) { throw 'Missing lab accounts' }
if ($invalidAccounts) { throw 'Disabled/locked lab account' }
```

Lockout phải Never/0 theo7.1; không giảm attempt. WinNT ADSI/CIM có tài liệu:
https://learn.microsoft.com/windows/win32/adsi/winnt-account-lockout
Chuẩn bị sẵn console/terminal. Không mở RDP/SSHWindows/runas/UAC hay auth khác
trong action bucket. Console runner dùng LogonUser LogonType=2, SMB LogonType=3.
Không thay bằng mở khóa type 7, PIN hoặc cached session.

### 11.2 Đo clock, draft và start ngay

SOC dùng key đã cấu hình7.4. RTT<=4s, skew uncertainty<=5s, evidence<=120s.
Chạy nguyên khối rồi start ngay:


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

.venv-ml/bin/python -m scripts.create_run_draft \
 --scenario "$SCENARIO" --run-id "$RUN_ID" --operator Kien --purpose "$RUN_PURPOSE" \
 --collection-seed "$COLLECTION_SEED" --clock-preflight "$CLOCK_FILE"
.venv-ml/bin/python -m scripts.scenario_session start --draft "run-drafts/$RUN_ID.yaml"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
```

Phải STARTED. Start frozen cursor/config/context/seed/profile/candidate/acceptance
trong start-contract bất biến. Không sửa state/hash. SSH đo clock đã xong trước
action bucket, không đo lại trong action.

### 11.3 Xuất JSON frozen và chuyển đúng byte

SOC, trước begin-action:

```bash
set -euo pipefail
EXPORT_DIR="$PWD/evidence/operator-parameter-exports"
mkdir -p "$EXPORT_DIR"
EXPORT_JSON="$EXPORT_DIR/$RUN_ID.json"
test ! -e "$EXPORT_JSON"
.venv-ml/bin/python -m scripts.export_run_parameters --run-id "$RUN_ID" --format json > "$EXPORT_JSON"
jq '{run_id,scenario_id,purpose,scenario_parameters}' "$EXPORT_JSON"
sha256sum "$EXPORT_JSON"
```

File SHA vận chuyển khác frozen_parameters_sha256 của canonical payload.
Console/HTTP/DNS chạy trên Windows, không gõ lại schedule:

```powershell
$ErrorActionPreference='Stop'
$RunId=Read-Host 'RUN_ID'
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$') { throw 'Invalid ID' }
$ExpectedHash=(Read-Host 'SHA256 export JSON from SOC').ToLowerInvariant()
if ($ExpectedHash -notmatch '^[0-9a-f]{64}$') { throw 'Invalid hash' }
$SocUser=Read-Host 'SOC SSH username'
if ($SocUser -notmatch '^[a-z_][a-z0-9_-]*$') { throw 'Invalid username' }
$ParametersFile="C:\DATN\$RunId.json"
if (Test-Path -LiteralPath $ParametersFile) { throw 'Destination exists' }
scp "${SocUser}@192.168.58.147:datn-ai-soar-v4/evidence/operator-parameter-exports/$RunId.json" $ParametersFile
if ($LASTEXITCODE -ne 0) { throw 'Copy failed' }
if ((Get-FileHash -LiteralPath $ParametersFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) { throw 'Hash mismatch' }
& C:\DATN\run_frozen_windows.ps1 -ParametersFile $ParametersFile -ExpectedFileSha256 $ExpectedHash
```

Account nhập mật khẩu đúng vào credential prompt trước; runner dừng ở
ACCOUNT_READY/ACTION_READY, CHƯA nhấn Enter. HTTP/DNS tương tự.
DNS dispatcher tạo child powershell.exe mang RunNonce trên command line, không
paste Resolve-DnsName trong shell đã mở để thay thế.

SMB chỉ chạy Kali:

```bash
set -euo pipefail
read -rp 'RUN_ID: ' RUN_ID
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$ ]]
read -rp 'SOC SSH username: ' SOC_USER
[[ "$SOC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
read -rp 'SHA256 export JSON from SOC: ' EXPORT_SHA
[[ "$EXPORT_SHA" =~ ^[0-9a-f]{64}$ ]]
JSON_FILE="$HOME/datn-tools/$RUN_ID.json"
test ! -e "$JSON_FILE"
scp "${SOC_USER}@192.168.58.147:datn-ai-soar-v4/evidence/operator-parameter-exports/$RUN_ID.json" "$JSON_FILE"
test "$(sha256sum "$JSON_FILE" | awk '{print $1}')" = "$EXPORT_SHA"
/usr/bin/python3 "$HOME/datn-tools/run_training_account_remote.py" --frozen-file "$JSON_FILE" "$EXPORT_SHA"
```

Nhập mật khẩu đúng các neutraluser được hỏi rồi dừng ở ACCOUNT_READY.
Driver tạo sai password trong RAM, kiểm expected lỗi logon; guest/policy/network
khác phải fail. Không truyền password qua argv, không lưu credential.

### 11.4 Begin-action, thực thi, complete và finalize

SOC:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session begin-action --run-id "$RUN_ID" --wait-for-window
```

Chỉ sau khi lệnh trả receipt STARTED thành công mới nhấn Enter trên actor sẵn
sàng. Runner tự chờ frozen pre_action_delay_seconds; không sleep thêm ở SOC.
Không đổi count/gap hoặc chạy bù. Đợi ACTION_COMPLETE thật không lỗi, về SOC ngay:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID" --wait-for-window
```

Giữ finalize tới hết. Window 300 s và grace 60 s không đổi. Capture bắt đầu trước
bucket sạch kế tiếp nên thường gần10phút/run, không chỉ thời gian action.
40–48run khoảng7–8giờ cộng pilot/challenge/nghỉ/thao tác; có thể chia buổi nhưng
kiểm TTL/enrollment. Grace chỉ chờ log đến muộn, không kéo dài action window.

### 11.5 Kiểm từng run và tiến độ

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.verify_run_evidence --run-id "$RUN_ID"
(cd "evidence/scenario-runs/$RUN_ID" && sha256sum --check checksums.sha256)
jq '{run_id,scenario_id,purpose,cohort_id,label,family}' "data/raw/$RUN_ID/scenario_manifest.json"
jq '{incident_id,context_status,observation_quality,features}' "data/raw/$RUN_ID/incidents.jsonl"
mkdir -p operator-logs/progress
.venv-ml/bin/python -m scripts.audit_dataset --mode progress --output "operator-logs/progress/$RUN_ID.json"
```

Progress thiếu quota có thể IN_PROGRESS nếu không integrity ERROR.
Final audit READY/TARGET_MET mới cho build. Không chỉ gửi8file output: raw,
context, clock, checkpoint, receipt, source/contract/checksum đều cần.
Ghi nhật ký ordinal/ID/UTC/operator/status/lỗi/ảnh ngoài frozen evidence; không
sửa predicted label thành ground truth.

### 11.6 Lỗi và phục hồi

Mất SSH: đọc RUN_ID từ plan/thư mục, status trước, không start/create lại mù quáng.
Không xóa active-run/state/reservation/checkpoint bằng tay.

- Checkpoint đã sealed trước lỗi bước tạo feature/output: có thể retry finalize
  cùng ID, nguồn/evidence nguyên trạng, không chạy lại action.
- Chưa từng chạy intake trước cutoff: finalize muộn báo thiếu checkpoint hợp lệ;
  không kéo cutoff/rehash/thêm log. Abort rồi ID/seed mới.
- Rotate/truncate/prefix đổi, partial/conflict identity, thiếu flow, extra auth,
  sai count/gap/context/clock: giữ raw/lỗi; sửa nguồn, không trim/dedup bằng
  Wazuh wrapper ID đơn lẻ.
- Actor đã lỗi thì không complete cho xong. Ghi nguyên nhân thật:

```bash
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
.venv-ml/bin/python -m scripts.scenario_session abort --run-id "$RUN_ID" --reason "Nguyen nhan that va bang chung"
```

Run FINALIZED phát hiện sai dùng quarantine, không xóa:

```bash
.venv-ml/bin/python -m scripts.scenario_session quarantine --run-id "$RUN_ID" --reason "Sai sot that va bang chung"
```

Retry khai báo dòng bổ sung trước chạy, ID/seed mới, giữ plan gốc và failure ledger.
Không tái sử dụng raw hoặc ID, không sửa plan để che failed.

## 12. Thu chính thức và challenge

Chỉ sau acceptance, chọn MỘT plan:

```bash
set -euo pipefail
PLAN="run-drafts/train-plan-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan --kind preferred --output "$PLAN"
sha256sum "$PLAN"
jq -r '.runs[]|[.ordinal,.cohort_id,.scenario_id,.run_id,.purpose,.collection_seed]|@tsv' "$PLAN"
```

preferred 48 hoặc đổi minimum 40 ngay trước thu; không chạy cả hai để chọn outcome.
Làm mục 11 từng ordinal. Plan random thứ tự, seed độc lập, jitter cùng distribution
cả hai nhãn. Base schedule/ý nghĩa pair tại docs/collection-training-design.md và
execution_profile catalog; JSON frozen là lịch thực tế.

Account cùng datn_lab01/02/03; HTTP cùng curl.exe và http://10.40.0.10:8081/beacon
body vô hại; DNS cùng childPowerShell/www.datn.test/resolver10.40.0.10.
beacon.datn.test chỉ canary chẩn đoán, không nhãn train. STAGED-TRANSFER là tên
profile, không tải executable, thực thi payload hoặc exfiltrate.

Kế hoạch challenge riêng, khai báo trước đánh giá:

```bash
set -euo pipefail
CHALLENGE_PLAN="run-drafts/challenge-plan-$(date -u +%Y%m%dT%H%M%SZ).json"
.venv-ml/bin/python -m scripts.make_collection_plan --kind challenge --output "$CHALLENGE_PLAN"
sha256sum "$CHALLENGE_PLAN"
PLAN="$CHALLENGE_PLAN"
jq -r '.runs[]|[.ordinal,.scenario_id,.run_id,.purpose]|@tsv' "$PLAN"
```

8challenge chạy mục11, không quota/train/validation/lockedtest/tuning.
Hai nhãn mỗi pair có cùng profile danh nghĩa; raw/jitter/nonce từng run riêng,
không hứa vector chắc chắn giống hệt. Expected REVIEW là tiêu chí sau freeze,
không cam kết runtime hiện tại luôn REVIEW. Tự tin suy ý định không quan sát
được phải ghi challenge failure, giữ SHADOW, không giấu/đổi nhãn.

## 13. Final audit, build, Google Colab

Không active run, xử lý ERROR bằng sửa nguồn và thu mới, không sửa evidence:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.audit_dataset --mode final --output evidence/dataset-audit.json
jq '{status,total_valid_runs,invalid_run_count,error_count,warning_count,group_key,strata}' evidence/dataset-audit.json
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml
jq '{group_key,locked_test_status,stratum_run_counts,partition_counts,collection_audit,provenance}' data/processed/dataset_manifest.json
```

minimum READY/preferred TARGET_MET; có thể audit --require-target. Đủ4strata,
5scenario/5cohort mỗi stratum. Forbidden/nuisance marginal+joint/crosslabel vector
collision vẫn ERROR. Behavioral separation là WARNING phải review, không đổi
role sau khi xem dữ liệu. Cohort split3/1/1 giữ cảpair cùng partition.
Repeats không tăng số cohort độc lập.

Build trên SOC-AI với đúng source và runtime đã nghiệm thu. Máy Thịnh có thể
validate evidence đóng băng trên bản sao; builder sẽ từ chối source/runtime khác,
không sửa receipt để vượt gate. Dùng processed do SOC build để chuyển Colab.

Giữ locked_test.jsonl và challenge.jsonl ở SOC. Chỉ upload đúng4file:

```bash
set -euo pipefail
UPLOAD_DIR="$HOME/datn-colab-upload-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$UPLOAD_DIR"
mkdir "$UPLOAD_DIR"
cp -- data/processed/train.jsonl data/processed/validation.jsonl data/processed/dataset_manifest.json "$UPLOAD_DIR/"
(cd "$UPLOAD_DIR" && sha256sum train.jsonl validation.jsonl dataset_manifest.json > colab-upload.sha256)
(cd "$UPLOAD_DIR" && sha256sum --check colab-upload.sha256)
jq -r '.provenance.builder_git_commit' "$UPLOAD_DIR/dataset_manifest.json"
```

Upload train.jsonl,validation.jsonl,dataset_manifest.json,colab-upload.sha256 vào
MyDrive/DATN/week3-data/processed. Mở notebooks/week3_train_colab.ipynb cùng
candidate SHA/tag. CPU đủ cho tabular nhỏ này, GPU không bắt buộc.
EXPECTED_TRAINING_COMMIT=full40SHA builder vừa in, đối chiếu accepted source receipt,
không tin SHA từ file lạ. Notebook kiểm checksum/source/config/schema/design/cohort.
FileNotFoundError: kiểm đã build và đúng Drive, không tạo file rỗng hoặc dùng data cũ.
Train chỉ TRAIN/VALIDATION; không mở lockedtest hoặc challenge trước freeze.
Báo precision/recall/PR-AUC/calibration/REVIEW coverage/sốcohort theo family;
uncertainty insufficient giữ null, automation false.
Quy trình package: docs/week3-model-training-runbook.md.

## 14. Backup và bàn giao

Không active run. Backup mới sau mỗi buổi, không ghi đè backup gắn acceptance:

```bash
set -euo pipefail
COLLECTION_TAG=collection-v4.0.0-candidate.2
BACKUP_ID="DATASET-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
.venv-ml/bin/python -m scripts.collection_release backup --tag "$COLLECTION_TAG" \
 --output-directory "$BACKUP_DIR" > "operator-logs/$BACKUP_ID-report.json"
cat "operator-logs/$BACKUP_ID-report.json"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
find "$BACKUP_DIR" -maxdepth 1 -type f -printf '%f\n'
```

Gửi toàn backup directory: archive+descriptor+restore report+checksums; cả
accepted pilot backup, preflight/toolchain/source receipt. Backup gồm raw/evidence/
context/plans/logs, không .env/private key/venv/source tree. Source lấy GitHub.
ABORTED/quarantine vẫn giữ. NativeXML/EVTX, phiên bản/config Kali/Windows, ảnh
ngoài repo gom gói riêng có checksum, ghi rõ đường dẫn; không hứa backup tự có
file ngoài phạm vi nó quét. Không sửa path trong acceptance khi copy sang máy nhận.

Host Windows nhận gói, ngoài run:

```powershell
$ErrorActionPreference='Stop'
$SocUser=Read-Host 'SOC username'
$BackupId=Read-Host 'BACKUP_ID'
if ($SocUser -notmatch '^[a-z_][a-z0-9_-]*$' -or $BackupId -notmatch '^[A-Za-z0-9_-]+$') { throw 'Invalid input' }
$Destination="D:\DATN-HANDOFF\$BackupId"
if (Test-Path -LiteralPath $Destination) { throw 'Destination exists' }
New-Item -ItemType Directory -Force (Split-Path $Destination) | Out-Null
scp -r "${SocUser}@192.168.58.147:datn-backups/$BackupId" $Destination
if ($LASTEXITCODE -ne 0) { throw 'Copy failed' }
$CollectionTag='collection-v4.0.0-candidate.2'
git --version
if ($LASTEXITCODE -ne 0) { throw 'Install Git for Windows, reopen PowerShell, then retry verification' }
$Tools="D:\DATN-TOOLS\$CollectionTag-$BackupId"
if (Test-Path -LiteralPath $Tools) { throw 'Choose a fresh tools directory; do not reuse an unverified checkout' }
New-Item -ItemType Directory -Force (Split-Path $Tools) | Out-Null
git clone --depth 1 --branch $CollectionTag https://github.com/lethinhlord/Repo.git $Tools
if ($LASTEXITCODE -ne 0) { throw 'GitHub tools checkout failed' }
$ToolCommit=(git -C $Tools rev-parse HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot read tools commit' }
$SourceCommit=(Get-Content -LiteralPath (Join-Path $Destination 'git-commit.txt') -Raw).Trim()
if ($ToolCommit -cne $SourceCommit) { throw 'Backup commit differs from the selected GitHub tag' }
powershell.exe -NoProfile -NonInteractive -File "$Tools\scripts\verify_collection_backup.ps1" -Directory $Destination
if ($LASTEXITCODE -ne 0) { throw 'Host backup verification failed; keep evidence and stop handoff' }
```

Thịnh kiểm trên bản sao với cùng GitHubSHA, không sửa dataset gốc Kiên bàn giao.
Host cần Git for Windows và OpenSSH Client. Nếu thiếu Git, cài từ
https://git-scm.com/download/win hoặc chạy
winget install --id Git.Git --exact --source winget rồi mở PowerShell mới.
Không tải script từ gói data hoặc copy code offline: lấy đúng GitHub tag bên trên.
Verifier bắt buộc archive, 4 descriptor, restore report, checksum đầy đủ/không trùng,
run inventory không rỗng và source metadata khớp. File checksum rỗng không đạt.
Chỉ tiếp tục khi script trả exit code 0 và HOST_BACKUP_VERIFY=PASS.
Đây là kiểm tra chuyển file; việc restore/validate raw thực do backup collector làm.
Raw và evidence đi cùng nhau, không chỉ8file output. Layout events_raw.jsonl/
WIN11-01 cũ là incompatible raw dataset layout: giữ ngoài checkout mới, thu lại,
không convert nhãn để đủquota.

## 15. Chụp ảnh và nhật ký

Ảnh toàn desktop laptop ở độ phân giải gốc (vd 1920 × 1200 nếu đang dùng), có viền
VMware/taskbar/công cụ thật, không crop/zoom dựng console bằng script. Inch không
quy định pixel; kiểm DisplaySettings. PrintScreen hoặc SnippingTool Fullscreen,
không Window/Rectangle. Xem Properties ảnh, tênUTC_VM_bước_RUNID.
Lưu D:\Tài liệu\Đồ án\Ảnh báo cáo trên máy Thịnh; Kiên gom tương tự trong handoff.

Chụp:4VM/NIC;routes;candidateSHA;service/version;Wazuhagents;nativeclock/canary;
baseline;plan;STARTED/export/hash;actorREADY;beginreceipt;outputaction;finalize;
VALID/supplementary;progress/finalaudit;backuprestore/checksum;processedmanifest;
Colab khi chạy thật. Không chụp password/.env/key/tài khoản cá nhân.
Lệnh chuẩn systemctl status --no-pager, journalctl, ss, ip, dpkg-query, Get-Service,
Get-WinEvent chứng minh dịch vụ. Helper kiểm contract/thu/phân tích thật, không
tự in PASS thay trạng thái. Thịnh tự cắt ảnh sau.

## 16. Checklist

- GitHub tag/fullSHA, clean tree/runtime, runnerhash cả actor.
- Inventory4VM/routes/firewall/time/version thực.
- Canary raw/report/nativeCSV/XML/checksum; enrollmentraw/approved/baseline.
- 4pilotmới+acceptance+acceptedbackup/restore/preflight nguyên path.
- Plan40/48+retryledger;40/48VALIDtrainable;8challenge riêng.
- Raw/evidence/checkpoint/receipt/frozencontract/checksum kể cả failed.
- FinalauditREADY/TARGET_MET,warnings giải thích,cohortsplit,lockedtestUNOPENED.
- Backuprestore+checksum máy nhận,ảnh/nhật ký thật.
- Khôngsecret/data cũ/fakeevents; bước lab chưa chạy ghi NOT YET EXECUTED.


## 17. Tài liệu chính thức
- Wazuh assistant source v4.14.9: https://github.com/wazuh/wazuh-installation-assistant/tree/8739c47527bf18563eba44140db9a5e36568cee0
- Official assistant builder: https://github.com/wazuh/wazuh-installation-assistant#build-the-scripts
- Impacket SMB API: https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py
 đã đối chiếu

- Wazuh Quickstart 4.14: https://documentation.wazuh.com/current/quickstart.html
- Wazuh Windows/Linux agent: https://documentation.wazuh.com/current/installation-guide/
- Wazuh package list 4.14.9: https://documentation.wazuh.com/current/installation-guide/packages-list.html
- Wazuh Archives: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- Wazuh localfile: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Wazuh kiểm tra cấu hình: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html
- Wazuh Windows default channels: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html
- Microsoft Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft OpenSSH Client/Server: https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse
- Microsoft audit GUID constants: https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
- Microsoft WinNT account unlock (`IADsUser.IsAccountLocked`): https://learn.microsoft.com/windows/win32/adsi/winnt-account-lockout
- Microsoft `Win32_UserAccount`: https://learn.microsoft.com/windows/win32/cimwin32prov/win32-useraccount
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Suricata rule-files/default-rule-path: https://docs.suricata.io/en/latest/configuration/suricata-yaml.html
- Atomic Red Team: https://www.atomicredteam.io/docs/invoke-atomicredteam

## 18. Danh mục thực thi đầy đủ

Các giá trị dưới đây lấy trực tiếp từ catalog của bản này, trước jitter. Lịch
thực tế phải dùng JSON frozen; không gõ lại gap hoặc count từ bảng này. F=fail,
S=success; console chạy WIN11-TARGET, SMB chạy Kali, HTTP/DNS chạy Windows.
Cả hai nhãn dùng chung neutral account/endpoint/tool theo mục 12.

| Cohort | Scenario | Purpose | Transport | Số action | Gaps base (giây) |
|---|---|---|---|---:|---|
| ACCOUNT-PAIR-01 | ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS | trainable | console | 3 | 20,20 |
| ACCOUNT-PAIR-01 | ACCOUNT-MALICIOUS-BURST-THEN-SUCCESS | trainable | console | 9 | 2,2,2,2,2,2,2,2 |
| ACCOUNT-PAIR-02 | ACCOUNT-BENIGN-REMOTE-SESSIONS | trainable | smb | 6 | 2,3,7,11,17 |
| ACCOUNT-PAIR-02 | ACCOUNT-MALICIOUS-REPEATED-FAILURES-6 | trainable | smb | 6 | 2,3,7,11,17 |
| ACCOUNT-PAIR-03 | ACCOUNT-BENIGN-MULTIACCOUNT-MAINTENANCE | trainable | console | 3 | 15,15 |
| ACCOUNT-PAIR-03 | ACCOUNT-MALICIOUS-PASSWORD-SPRAY | trainable | console | 4 | 4,4,4 |
| ACCOUNT-PAIR-04 | ACCOUNT-BENIGN-STALE-CREDENTIAL | trainable | smb | 6 | 30,30,30,30,30 |
| ACCOUNT-PAIR-04 | ACCOUNT-MALICIOUS-RAPID-GUESSING | trainable | smb | 6 | 2,2,2,2,2 |
| ACCOUNT-PAIR-05 | ACCOUNT-BENIGN-MULTIACCOUNT-RECOVERY | trainable | smb | 6 | 8,8,8,8,8 |
| ACCOUNT-PAIR-05 | ACCOUNT-MALICIOUS-MULTIACCOUNT-GUESSING | trainable | smb | 12 | 3,3,3,3,3,3,3,3,3,3,3 |
| C2-PAIR-01 | C2-BENIGN-HEALTH-POLL | trainable | http | 8 | 25,25,25,25,25,25,25 |
| C2-PAIR-01 | C2-MALICIOUS-HTTP-BEACON | trainable | http | 8 | 15,15,15,15,15,15,15 |
| C2-PAIR-02 | C2-BENIGN-SINGLE-DOWNLOAD | trainable | http | 1 | không có (1 action) |
| C2-PAIR-02 | C2-MALICIOUS-STAGED-TRANSFER | trainable | http | 8 | 2,2,2,2,2,2,2 |
| C2-PAIR-03 | C2-BENIGN-DNS | trainable | dns | 4 | 7,19,11 |
| C2-PAIR-03 | C2-MALICIOUS-DNS-BEACON | trainable | dns | 8 | 15,15,15,15,15,15,15 |
| C2-PAIR-04 | C2-BENIGN-IRREGULAR-API | trainable | http | 4 | 10,35,20 |
| C2-PAIR-04 | C2-MALICIOUS-JITTER-BEACON | trainable | http | 8 | 8,21,13,30,11,24,17 |
| C2-PAIR-05 | C2-BENIGN-API-BURST | trainable | http | 6 | 2,2,2,2,2 |
| C2-PAIR-05 | C2-MALICIOUS-STAGED-TRANSFER-RETRY | trainable | http | 3 | 20,20 |
| ACCOUNT-PAIR-01 | ACCOUNT-CHALLENGE-LOW-NOISE-BENIGN | challenge | smb | 2 | 3 |
| ACCOUNT-PAIR-01 | ACCOUNT-CHALLENGE-LOW-NOISE-MALICIOUS | challenge | smb | 2 | 3 |
| ACCOUNT-PAIR-04 | ACCOUNT-CHALLENGE-FAST-RETRIES-BENIGN | challenge | smb | 6 | 2,2,2,2,2 |
| ACCOUNT-PAIR-04 | ACCOUNT-CHALLENGE-FAST-RETRIES-MALICIOUS | challenge | smb | 6 | 2,2,2,2,2 |
| C2-PAIR-01 | C2-CHALLENGE-POLL-INTENT-BENIGN | challenge | http | 8 | 15,15,15,15,15,15,15 |
| C2-PAIR-01 | C2-CHALLENGE-POLL-INTENT-MALICIOUS | challenge | http | 8 | 15,15,15,15,15,15,15 |
| C2-PAIR-02 | C2-CHALLENGE-DOWNLOAD-INTENT-BENIGN | challenge | http | 1 | không có (1 action) |
| C2-PAIR-02 | C2-CHALLENGE-DOWNLOAD-INTENT-MALICIOUS | challenge | http | 1 | không có (1 action) |

Account chạy đúng thứ tự tài khoản/kết quả sau (trước jitter):

- ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS: datn_lab01:fail,datn_lab01:fail,datn_lab01:success
- ACCOUNT-MALICIOUS-BURST-THEN-SUCCESS: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:success
- ACCOUNT-BENIGN-REMOTE-SESSIONS: datn_lab01:success,datn_lab01:success,datn_lab01:success,datn_lab01:success,datn_lab01:success,datn_lab01:success
- ACCOUNT-MALICIOUS-REPEATED-FAILURES-6: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail
- ACCOUNT-BENIGN-MULTIACCOUNT-MAINTENANCE: datn_lab01:success,datn_lab02:success,datn_lab03:success
- ACCOUNT-MALICIOUS-PASSWORD-SPRAY: datn_lab01:fail,datn_lab02:fail,datn_lab03:fail,datn_lab03:success
- ACCOUNT-BENIGN-STALE-CREDENTIAL: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail
- ACCOUNT-MALICIOUS-RAPID-GUESSING: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail
- ACCOUNT-BENIGN-MULTIACCOUNT-RECOVERY: datn_lab01:fail,datn_lab01:success,datn_lab02:fail,datn_lab02:success,datn_lab03:fail,datn_lab03:success
- ACCOUNT-MALICIOUS-MULTIACCOUNT-GUESSING: datn_lab01:fail,datn_lab02:fail,datn_lab03:fail,datn_lab01:fail,datn_lab02:fail,datn_lab03:fail,datn_lab01:fail,datn_lab02:fail,datn_lab03:fail,datn_lab01:success,datn_lab02:success,datn_lab03:success
- ACCOUNT-CHALLENGE-LOW-NOISE-BENIGN: datn_lab01:fail,datn_lab01:success
- ACCOUNT-CHALLENGE-LOW-NOISE-MALICIOUS: datn_lab01:fail,datn_lab01:success
- ACCOUNT-CHALLENGE-FAST-RETRIES-BENIGN: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail
- ACCOUNT-CHALLENGE-FAST-RETRIES-MALICIOUS: datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail,datn_lab01:fail
