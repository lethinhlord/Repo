# QUY TRÌNH CHUẨN THU THẬP DỮ LIỆU TRAIN TRÊN LAB 4 VM

Phiên bản: 1.1 — 16/10/2026
Phạm vi: dữ liệu `account-benign`, `account-malicious`, `c2-benign`,
`c2-malicious` cho nhánh `feature/week3-model-training`.

## 1. Kết quả bắt buộc

Mỗi lần chạy kịch bản là **một mẫu độc lập**, có một `run_id`, một nhãn được khai báo
trước khi chạy, bằng chứng gốc và checksum. Không coi từng dòng log là một mẫu.

| Nhóm | Tối thiểu để bắt đầu train | Mục tiêu nên thu |
|---|---:|---:|
| account-benign | 10 run hợp lệ | 12 |
| account-malicious | 10 run hợp lệ | 12 |
| c2-benign | 10 run hợp lệ | 12 |
| c2-malicious | 10 run hợp lệ | 12 |

Mỗi nhóm dùng đủ **năm** kịch bản trong `config/scenario-catalog.yaml`. Ở mốc 10,
mỗi kịch bản chạy đúng hai lần. Ở mốc 12, chọn hai kịch bản khác nhau để chạy lần thứ
ba; do đó không kịch bản nào vượt 25% số run của nhóm. Không nhân bản file để tăng số
mẫu.

## 2. Kiến trúc 4 VM

| VM | Management/NAT | Mạng dữ liệu | Vai trò |
|---|---|---|---|
| Kali `ATTACK-LAB` | `192.168.58.132/24` | `10.40.0.10/24` | dịch vụ mô phỏng và máy phát hoạt động kiểm thử |
| Windows 11 `WIN11-TARGET` | `192.168.58.148/24` | `10.20.0.10/24` | Sysmon, Security log, Wazuh Agent |
| Ubuntu `SOC-AI` | `192.168.58.147/24` | — | Wazuh all-in-one, repo, collector, auditor, API/n8n |
| Ubuntu `NET-SENSOR` | `192.168.58.150/24` | `10.40.0.1/24`, `10.20.0.1/24` | router quan sát, Suricata, Wazuh Agent |

Hai VM đầu có thêm NIC dữ liệu; NET-SENSOR có ba NIC. Mọi traffic C2 phải dùng địa
chỉ `10.40.0.10`, nhờ vậy đường đi bắt buộc qua NET-SENSOR. Không thu C2 qua IP
management vì traffic cùng VMnet có thể đi tắt và Suricata không nhìn thấy.

## 3. Cổng kiểm soát theo thứ tự

Không chuyển sang cổng sau nếu cổng trước chưa đạt:

1. `G0`: đúng tên máy, IP, giờ và snapshot sạch.
2. `G1`: Windows → NET-SENSOR → Kali định tuyến được.
3. `G2`: Wazuh nhận cả `WIN11-TARGET` và `NET-SENSOR`.
4. `G3`: Sysmon có Event ID 1, 3, 22; Security có 4624/4625.
5. `G4`: Suricata tạo EVE JSON và Wazuh chuyển EVE về Archives.
6. `G5`: một pilot account và một pilot C2 finalize/validate được.
7. `G6`: thu đủ 10–12 run mỗi nhóm; auditor báo `READY` hoặc `TARGET_MET`.
8. `G7`: build dataset thành công, locked test vẫn `UNOPENED`.

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

1. Tải ISO từ trang chính thức, lưu cả SHA-256 và kiểm tra bằng
   `Get-FileHash <ISO> -Algorithm SHA256` trên host.
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
sudo apt install -y open-vm-tools openssh-server curl git jq
sudo systemctl enable --now ssh
grep '^PRETTY_NAME=' /etc/os-release
```

Hai VM Ubuntu phải hiện `Ubuntu 24.04 LTS`. Nếu đang là Ubuntu 26.04 hoặc một bản chưa
nằm trong ma trận hỗ trợ hiện hành của Wazuh, dừng và cài lại 24.04; không cố cài Wazuh
rồi dùng kết quả lỗi làm dữ liệu.

Đặt hostname:

```bash
# Chạy đúng lệnh tương ứng trên từng VM Linux
sudo hostnamectl set-hostname SOC-AI
sudo hostnamectl set-hostname NET-SENSOR
sudo hostnamectl set-hostname ATTACK-LAB
```

Trên Windows PowerShell (Administrator), đặt tên rồi reboot:

```powershell
Rename-Computer -NewName WIN11-TARGET -Restart
```

Sau reboot, chụp `hostname` và IP management. Dùng DHCP reservation của VMnet8 hoặc IP
tĩnh để giữ `132/147/148/150`; trước khi đặt tĩnh phải kiểm tra không trùng bằng ping và
bảng DHCP. Management gateway/DNS lấy đúng giá trị hiển thị trong Virtual Network
Editor, không giả định máy nào cũng dùng cùng gateway VMware.

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
- VMnet2: Host-only `10.40.0.0/24`, tắt DHCP.
- VMnet3: Host-only `10.20.0.0/24`, tắt DHCP.

Gắn NIC:

- Kali: VMnet8 + VMnet2.
- Windows: VMnet8 + VMnet3.
- SOC-AI: VMnet8.
- NET-SENSOR: VMnet8 + VMnet2 + VMnet3.

Sau khi boot, dùng `ip -br link` trên Linux và `Get-NetAdapter` trên Windows để ghi
đúng tên interface. Trong các ví dụ dưới đây, NET-SENSOR dùng `ens37` phía Kali và
`ens38` phía Windows; phải thay bằng tên thật nếu khác.

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

```bash
sudo netplan generate
sudo netplan try
ip -br address
ip route
```

Sau `netplan try`, xác nhận default route vẫn chỉ đi qua NIC management/VMnet8 và hai
NIC dữ liệu không có default route. Mất SSH hoặc xuất hiện hai default route thì từ chối
apply và phục hồi bản sao lưu.

Bật chuyển tiếp IPv4:

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
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv6.method disabled
else
  sudo nmcli connection add type ethernet ifname "$DATA_IF" con-name ATTACK-LAB \
    ipv4.method manual ipv4.addresses 10.40.0.10/24 \
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv6.method disabled
fi
sudo nmcli connection up ATTACK-LAB
ip route get 10.20.0.10
```

### 5.4 Windows 11

Thay `Ethernet 2` bằng NIC VMnet3 thực tế. Khối dưới kiểm tra trạng thái trước để
không tạo IP/route trùng khi chạy lại:

```powershell
$DataIf = "Ethernet 2"
if (-not (Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object IPAddress -eq "10.20.0.10")) {
  New-NetIPAddress -InterfaceAlias $DataIf -IPAddress 10.20.0.10 -PrefixLength 24
}
if (-not (Get-NetRoute -DestinationPrefix "10.40.0.0/24" `
  -InterfaceAlias $DataIf -ErrorAction SilentlyContinue | `
  Where-Object NextHop -eq "10.20.0.1")) {
  New-NetRoute -DestinationPrefix 10.40.0.0/24 -InterfaceAlias $DataIf `
    -NextHop 10.20.0.1 -PolicyStore PersistentStore
}
Get-NetRoute -DestinationPrefix 10.40.0.0/24
Test-NetConnection 10.40.0.10
tracert -d 10.40.0.10
```

Đạt G1 khi `tracert` đi qua `10.20.0.1`, sau đó tới `10.40.0.10`. Nếu đi qua
management hoặc không có hop NET-SENSOR thì dừng, sửa mạng trước khi cài collector.

## 6. Cài SOC-AI

### 6.1 Wazuh all-in-one 4.14

```bash
sudo apt update
sudo apt install -y curl git jq python3 python3-venv python3-pip openssh-server
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
```

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

### 6.2 Repo, môi trường Python và Week 2 services

```bash
LAB_USER="$(id -un)"
PROJECT_ROOT="$HOME/datn-ai-soar"
if [ -d "$PROJECT_ROOT/.git" ]; then
  git -C "$PROJECT_ROOT" fetch --prune origin
  git -C "$PROJECT_ROOT" switch feature/week3-model-training
  git -C "$PROJECT_ROOT" pull --ff-only origin feature/week3-model-training
else
  git clone --branch feature/week3-model-training --single-branch \
    https://github.com/lethinhlord/Repo.git "$PROJECT_ROOT"
fi
cd "$PROJECT_ROOT"
git branch --show-current
git status --short
test "$(git rev-parse HEAD)" = \
  "$(git rev-parse origin/feature/week3-model-training)"
chmod +x scripts/bootstrap_ml.sh scripts/deploy_week2.sh scripts/verify_week2.sh
./scripts/bootstrap_ml.sh
.venv-ml/bin/python -m pytest -q \
  tests/test_scenario_collection.py \
  tests/test_dataset_audit.py \
  tests/test_collection_configuration.py
```

Kết quả chuẩn là toàn bộ test pass. Nếu cần API/n8n Week 2 trên cùng VM:

```bash
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$LAB_USER"
```

Thoát SSH, đăng nhập lại để group có hiệu lực, rồi:

```bash
cd "$HOME/datn-ai-soar"
docker version
./scripts/deploy_week2.sh
./scripts/verify_week2.sh
curl -fsS http://127.0.0.1:8000/ready | jq .
curl -fsS http://127.0.0.1:5678/healthz
```

Cho user vận hành quyền đọc Archives rồi đăng nhập lại SSH:

```bash
LAB_USER="$(id -un)"
sudo usermod -aG wazuh "$LAB_USER"
id "$LAB_USER"
sudo -u "$LAB_USER" test -r /var/ossec/logs/archives/archives.json
```

Sau khi thêm group, thoát toàn bộ phiên SSH rồi đăng nhập lại. `git status --short` phải
rỗng; nếu có thay đổi cục bộ, không `reset --hard`, không ghi đè mà phải bàn giao cho
người phụ trách repo xử lý trước khi thu.

Không đổi `config/collection-sources.yaml` nếu agent vẫn mang đúng hai tên
`WIN11-TARGET` và `NET-SENSOR`.

## 7. Cài WIN11-TARGET

### 7.1 Tài khoản lab và audit policy

Mở PowerShell bằng quyền Administrator. Tạo các tài khoản **chỉ dùng trong lab** bằng
`New-LocalUser`; không ghi mật khẩu vào hướng dẫn, Git hoặc manifest:

```powershell
$p = Read-Host "Password for datn_benign" -AsSecureString
New-LocalUser -Name datn_benign -Password $p -Description "DATN benign lab account"
$p = Read-Host "Password for datn_attack" -AsSecureString
New-LocalUser -Name datn_attack -Password $p -Description "DATN attack decoy"
1..3 | ForEach-Object {
  $name = "datn_spray{0:D2}" -f $_
  $p = Read-Host "Password for $name" -AsSecureString
  New-LocalUser -Name $name -Password $p -Description "DATN spray decoy"
}
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /get /subcategory:"Logon"
```

Ghi ngưỡng lockout hiện tại:

```powershell
net accounts
```

Không chạy 6/10 lần sai nếu ngưỡng khóa tài khoản thấp hơn. Điều chỉnh trong lab hoặc
dùng ít attempt hơn và ghi lại biến thể; sau thí nghiệm phải khôi phục policy.

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
$SocRepo = "$SocHome/datn-ai-soar"
New-Item -ItemType Directory -Force C:\DATN | Out-Null
scp "${SocUser}@192.168.58.147:${SocRepo}/config/sysmon-datn.xml" C:\DATN\
scp "${SocUser}@192.168.58.147:${SocRepo}/config/wazuh-windows-localfile.xml" C:\DATN\
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip `
  -OutFile C:\DATN\Sysmon.zip
Expand-Archive C:\DATN\Sysmon.zip C:\DATN\Sysmon -Force
C:\DATN\Sysmon\Sysmon64.exe -accepteula -i C:\DATN\sysmon-datn.xml
C:\DATN\Sysmon\Sysmon64.exe -c
Get-Service Sysmon64
```

Config repo bật ProcessCreate (ID 1), NetworkConnect (ID 3) và DnsQuery (ID 22). Tạo
traffic kiểm tra qua management (chưa dùng làm dữ liệu train), sau đó xác nhận:

```powershell
Test-NetConnection 192.168.58.147 -Port 443
Resolve-DnsName example.com
Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c whoami' -Wait
1,3,22 | ForEach-Object {
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
msiexec.exe /i C:\DATN\wazuh-agent-4.14.9-1.msi /q `
  WAZUH_MANAGER="192.168.58.147" `
  WAZUH_REGISTRATION_SERVER="192.168.58.147" `
  WAZUH_AGENT_NAME="WIN11-TARGET" /l*v C:\DATN\wazuh-agent-install.log
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

## 8. Cài NET-SENSOR

### 8.1 Suricata

```bash
sudo apt update
sudo apt install -y software-properties-common jq curl gnupg acl
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
suricata --build-info | head -n 20
```

Trong `/etc/suricata/suricata.yaml`:

- đặt `HOME_NET` là `[10.20.0.0/24]`;
- cấu hình `af-packet` nghe **chỉ NIC phía Kali** (ví dụ `ens37`) để tránh đếm đôi;
- trong `eve-log.types` bật `alert`, `dns`, `http`, `tls`, `flow`;
- thêm `datn.rules` vào `rule-files`.

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
        - dns
        - http
        - tls
        - flow

rule-files:
  - suricata.rules
  - datn.rules
```

Chuyển rule từ SOC-AI:

```bash
read -rp 'SOC-AI SSH username: ' SOC_USER
SOC_HOME=$(ssh "${SOC_USER}@192.168.58.147" 'printf %s "$HOME"') || exit 1
SOC_REPO="$SOC_HOME/datn-ai-soar"
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/config/suricata-datn.rules" /tmp/
sudo install -m 0644 /tmp/suricata-datn.rules /etc/suricata/rules/datn.rules
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
sudo systemctl is-active suricata
sudo tail -n 5 /var/log/suricata/eve.json | jq -c .
```

Ba SID local: 900001 HTTP beacon độc hại, 900002 DNS beacon độc hại và 900004 DNS
canary hợp lệ. Hai kịch bản staged-transfer cố ý chỉ tạo flow/HTTP, không có local alert,
để `suricata_alert_count` không trở thành feature làm lộ nhãn. Nếu
`suricata -T` báo lỗi, dừng; không chạy collector bằng ruleset lỗi.

### 8.2 Wazuh Agent chuyển EVE JSON

```bash
sudo apt-get install -y gnupg apt-transport-https curl
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo env WAZUH_MANAGER="192.168.58.147" WAZUH_AGENT_NAME="NET-SENSOR" \
  apt-get install -y wazuh-agent
```

Sao lưu `/var/ossec/etc/ossec.conf`, đếm location EVE và chỉ chèn block trong
`config/wazuh-suricata-localfile.xml` nếu count đang bằng 0. Sau khi chèn, count phải
bằng đúng 1. Cho Wazuh đọc được EVE hiện tại và file tạo sau rotate:

```bash
read -rp 'SOC-AI SSH username: ' SOC_USER
SOC_HOME=$(ssh "${SOC_USER}@192.168.58.147" 'printf %s "$HOME"') || exit 1
SOC_REPO="$SOC_HOME/datn-ai-soar"
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
sudo /var/ossec/bin/wazuh-logcollector -t
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo -u wazuh test -r /var/log/suricata/eve.json
sudo systemctl is-active wazuh-agent
```

Tạo một request từ Windows tới Kali, rồi trên SOC-AI:

```bash
sudo /var/ossec/bin/agent_control -l | grep NET-SENSOR
sudo jq -c 'select(.agent.name=="NET-SENSOR")' \
  /var/ossec/logs/archives/archives.json | tail -n 3
```

Đạt G4 chỉ khi Archives có event từ cả hai agent. Có event trên NET-SENSOR nhưng không
có ở Archives nghĩa là cấu hình Wazuh/ACL chưa đạt.

## 9. Cài dịch vụ mô phỏng trên Kali

```bash
sudo apt update
sudo apt install -y python3 dnsmasq curl jq
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

Tạo `/etc/dnsmasq.d/datn-lab.conf`:

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
dig @10.40.0.10 www.datn.test
dig @10.40.0.10 r01.beacon.datn.test
```

## 10. Preflight bắt buộc trước mỗi buổi thu

SOC-AI:

```bash
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/agent_control -l | grep -E 'WIN11-TARGET|NET-SENSOR'
sudo test -s /var/ossec/logs/archives/archives.json
df -h /var/ossec
free -h
timedatectl show -p NTPSynchronized --value
cd "$HOME/datn-ai-soar"
git status --short
.venv-ml/bin/python -m scripts.scenario_session --help
.venv-ml/bin/python -m scripts.audit_dataset --help
```

NET-SENSOR:

```bash
sudo systemctl is-active suricata wazuh-agent
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo -u wazuh test -r /var/log/suricata/eve.json
ip route
timedatectl show -p NTPSynchronized --value
```

Windows:

```powershell
Get-Service Sysmon64,WazuhSvc
Test-NetConnection 10.40.0.10 -Port 8080
Resolve-DnsName www.datn.test -Server 10.40.0.10
w32tm /resync
w32tm /query /status
```

Kali:

```bash
systemctl is-active datn-http-benign datn-http-beacon datn-http-stage dnsmasq
ss -lntup | grep -E ':53|:8080|:8081|:9001'
timedatectl show -p NTPSynchronized --value
```

Ba máy Linux phải trả về `yes` cho `NTPSynchronized`; Windows phải resync thành công và
không dùng `Local CMOS Clock` làm source. Chấp nhận host key SSH và xác nhận đăng nhập
giữa các máy **trước** cửa sổ thu. Trên SOC-AI, đo độ lệch NET-SENSOR và Kali so với
SOC-AI; nhập đúng user SSH của từng máy:

```bash
MAX_CLOCK_SKEW_SECONDS=5
read -rp 'NET-SENSOR SSH username: ' SENSOR_USER
read -rp 'Kali SSH username: ' KALI_USER
for ENDPOINT in "${SENSOR_USER}@192.168.58.150" "${KALI_USER}@192.168.58.132"; do
  LOCAL_EPOCH=$(date -u +%s)
  REMOTE_EPOCH=$(ssh -o ConnectTimeout=5 "$ENDPOINT" 'date -u +%s') || {
    echo "FAIL: cannot read clock from $ENDPOINT" >&2
    exit 1
  }
  SKEW=$((LOCAL_EPOCH - REMOTE_EPOCH))
  SKEW=${SKEW#-}
  printf '%s clock_skew_seconds=%s\n' "$ENDPOINT" "$SKEW"
  test "$SKEW" -le "$MAX_CLOCK_SKEW_SECONDS" || exit 1
done
```

Trên Windows, đo Windows so với SOC-AI:

```powershell
$SocUser = Read-Host "SOC-AI SSH username"
$MaxClockSkewSeconds = 5
$SocEpochText = ssh "${SocUser}@192.168.58.147" "date -u +%s"
if ($LASTEXITCODE -ne 0) { throw "Cannot read SOC-AI clock" }
$SocEpoch = [int64]($SocEpochText | Select-Object -Last 1)
$WindowsEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$ClockSkew = [Math]::Abs($WindowsEpoch - $SocEpoch)
"SOC-AI/Windows clock_skew_seconds=$ClockSkew"
if ($ClockSkew -gt $MaxClockSkewSeconds) { throw "Clock skew exceeds 5 seconds" }
```

Tất cả độ lệch phải `<= 5` giây. Nếu một lệnh hoặc cổng thời gian không đạt, không bắt
đầu run. Ghi lỗi, sửa, rồi chạy lại toàn bộ preflight. Nếu SOC-AI còn dưới 2 GB RAM
available hoặc filesystem `/var/ossec` còn dưới 10 GB, dừng Docker/n8n/API hoặc tăng
tài nguyên trước.

## 11. Quy trình chuẩn cho MỖI run

Thực hiện đúng thứ tự; không gộp hai kịch bản trong một cửa sổ.

### Bước 1 — Chọn run và khai báo ground truth trước

Quy ước ID:

```text
<SCENARIO-ID>-R<01..03>-<YYYYMMDD>
```

Ví dụ trên SOC-AI:

```bash
cd "$HOME/datn-ai-soar"
date -u --iso-8601=seconds
timedatectl show -p NTPSynchronized --value
RUN_ID=C2-MALICIOUS-HTTP-BEACON-R01-20261016
.venv-ml/bin/python -m scripts.create_run_draft \
  --scenario C2-MALICIOUS-HTTP-BEACON \
  --run-id "$RUN_ID" \
  --operator Kien
sed -n '1,120p' "run-drafts/$RUN_ID.yaml"
```

Ngay trước khi tạo draft, lưu output của kiểm tra độ lệch định lượng ở mục 10. Không
start nếu bất kỳ máy nào lệch quá 5 giây hoặc nguồn thời gian lỗi. Metadata và event
window phụ thuộc trực tiếp vào điều kiện này.

Không sửa `family` hoặc `label` sau khi chạy. Nếu chọn sai, chưa start thì xóa draft và
tạo lại; đã start thì dùng lệnh `abort`, không tái sử dụng `run_id`.

### Bước 2 — Start collector trước hoạt động

```bash
.venv-ml/bin/python -m scripts.scenario_session start \
  --draft "run-drafts/$RUN_ID.yaml"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
```

Phải thấy `STARTED`. Lệnh này chụp cursor của Archives, taxonomy và ground truth. Chỉ
sau đó mới thao tác trên Windows/Kali.

### Bước 3 — Chạy đúng một kịch bản

Đọc entry tương ứng trong `config/scenario-catalog.yaml`. Các câu lệnh C2 chuẩn nằm ở
mục 12. Với account, chỉ thao tác các tài khoản lab đã khai báo. Ghi giờ bắt đầu/kết thúc
và mọi sai lệch vào nhật ký vận hành.

### Bước 4 — Chờ pipeline chuyển log

Sau khi hoạt động kết thúc, chờ 90 giây nhưng không tạo traffic khác tới destination của
kịch bản:

```bash
sleep 90
```

Kiểm tra nhanh Archives có byte mới, không sửa file:

```bash
sudo tail -n 20 /var/ossec/logs/archives/archives.json | jq -c \
  'select(.agent.name=="WIN11-TARGET" or .agent.name=="NET-SENSOR")'
```

### Bước 5 — Finalize fail-closed

```bash
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID"
```

Collector chỉ nhận log nằm trong cửa sổ, đúng agent và đúng account/process/IP/port/DNS
đã khai báo. C2 bắt buộc có cả Sysmon network/DNS và Suricata. Thiếu một nguồn thì
finalize lỗi và không tạo mẫu cuối.

Nếu lỗi chỉ cho biết log đang đến chậm (`no Wazuh Archive bytes`, dòng JSON chưa hoàn
chỉnh, hoặc chưa thấy nguồn dự kiến), giữ nguyên run ở trạng thái `STARTED`, không tạo
thêm traffic và không bắt đầu run khác. Chờ 30 giây rồi **retry finalize** cùng `RUN_ID`;
có thể lặp tối đa ba lần, tức tối đa 180 giây tính từ lúc kết thúc hoạt động. Nếu vẫn
không đạt, dùng `abort`, sửa pipeline và thu lại với ID mới. Các lỗi attribution sai,
checksum, rotate/truncate hoặc quality gate sai không được retry để hợp thức hóa dữ liệu.

### Bước 6 — Validate run

```bash
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
find "data/raw/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
find "evidence/scenario-runs/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
```

Phải thấy `VALID`; `data/raw/$RUN_ID` có `scenario_manifest.json` và `incidents.jsonl`;
evidence có Archives, Windows events, Suricata EVE, metadata và SHA-256. Không chỉnh
tay file đã finalize. Nếu sai, loại run và chạy lại với ID mới.

### Bước 7 — Audit toàn dataset

```bash
.venv-ml/bin/python -m scripts.audit_dataset \
  --raw-dir data/raw \
  --evidence-dir evidence/scenario-runs \
  --minimum-runs 10 \
  --target-runs 12 \
  --output evidence/dataset-audit.json
echo "audit_exit=$?"
```

Trước khi đủ 10 mỗi nhóm, exit `1` và `NOT_READY` là đúng; báo cáo phải cho biết chính
xác thiếu nhóm nào. Không được bỏ qua `RUN_INVALID`, `SURICATA_MISSING`, duplicate,
checksum, thiếu đủ năm scenario hoặc concentration >30%.

### Bước 8 — Cleanup và khoảng nghỉ

Thực hiện cleanup trong catalog, chờ ít nhất 60 giây, kiểm tra không còn loop PowerShell,
xóa file tạm. Không chạy hai run đồng thời. Không tái dùng `run_id`.

Nếu thao tác sai giữa run:

```bash
.venv-ml/bin/python -m scripts.scenario_session abort \
  --run-id "$RUN_ID" --reason "ghi ro ly do"
```

Sau đó cleanup, chờ pipeline yên, tạo run mới với ID mới.

## 12. Thực thi scenario trên Windows

### 12.1 Account scenarios

Chạy tại màn hình console của `WIN11-TARGET`, không qua tài khoản thật và chỉ sau khi
collector đã `STARTED`. Trước từng run, dùng `net accounts` để xác nhận ngưỡng lockout
cao hơn số lần sai của scenario; nếu không, thay policy lab có kiểm soát hoặc không chạy.

| Scenario | Thao tác chính xác |
|---|---|
| `ACCOUNT-BENIGN-NORMAL-LOGON` | đăng xuất, đăng nhập `datn_benign` đúng một lần bằng mật khẩu đúng |
| `ACCOUNT-BENIGN-TYPO-THEN-SUCCESS` | nhập sai đúng 1 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS` | nhập sai đúng 2 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-BENIGN-RUNAS` | tại CMD chạy `runas /user:.\\datn_benign "cmd /c whoami"`, nhập đúng mật khẩu một lần |
| `ACCOUNT-BENIGN-THREE-TYPOS-THEN-SUCCESS` | nhập sai đúng 3 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-3` | nhập sai đúng 3 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-6` | nhập sai đúng 6 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-10` | nhập sai đúng 10 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-PASSWORD-SPRAY` | nhập sai đúng 1 lần lần lượt cho `datn_spray01`, `02`, `03` |
| `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS` | nhập sai đúng 5 lần cho `datn_attack`, sau đó nhập đúng 1 lần |

Không tạo thêm lần thử ngoài bảng trong cùng cửa sổ. Kết thúc run benign/malicious có
success thì sign out; run chỉ có failure thì quay lại desktop quản trị mà không đăng nhập
đúng tài khoản decoy. Sau 90 giây mới finalize; quality gate sẽ đối chiếu chính xác số
4624/4625 và thứ tự failure → success.

### 12.2 C2 scenarios

Chạy PowerShell thường trong `WIN11-TARGET`; chỉ chạy sau `start`.

### C2-BENIGN-HEALTH-POLL

```powershell
1..5 | ForEach-Object {
  curl.exe -s -o NUL http://10.40.0.10:8080/health
  if ($_ -lt 5) { Start-Sleep -Seconds 30 }
}
```

### C2-BENIGN-SINGLE-DOWNLOAD

```powershell
curl.exe http://10.40.0.10:8080/payload-benign.txt `
  -o $env:TEMP\payload-benign.txt
Get-FileHash $env:TEMP\payload-benign.txt -Algorithm SHA256
```

### C2-BENIGN-IRREGULAR-API

```powershell
$gaps = @(10,35,20)
for ($i=0; $i -lt 4; $i++) {
  curl.exe -s -o NUL http://10.40.0.10:8080/api/status
  if ($i -lt 3) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-BENIGN-DNS

```powershell
$gaps = @(7,23,11)
for ($i=0; $i -lt 4; $i++) {
  $name = "b{0:D2}.www.datn.test" -f ($i + 1)
  Resolve-DnsName $name -Server 10.40.0.10
  if ($i -lt 3) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-BENIGN-API-BURST

```powershell
1..6 | ForEach-Object {
  curl.exe -s -o NUL http://10.40.0.10:8080/api/status
  if ($_ -lt 6) { Start-Sleep -Seconds 2 }
}
```

### C2-MALICIOUS-HTTP-BEACON

```powershell
1..8 | ForEach-Object {
  curl.exe -s -o NUL "http://10.40.0.10:8081/beacon?run=$($_)"
  if ($_ -lt 8) { Start-Sleep -Seconds 15 }
}
```

### C2-MALICIOUS-JITTER-BEACON

```powershell
$gaps = @(8,21,13,30,11,24,17)
for ($i=0; $i -lt 8; $i++) {
  curl.exe -s -o NUL "http://10.40.0.10:8081/beacon?run=$($i+1)"
  if ($i -lt 7) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-MALICIOUS-DNS-BEACON

```powershell
1..8 | ForEach-Object {
  $name = "r{0:D2}.beacon.datn.test" -f $_
  Resolve-DnsName $name -Server 10.40.0.10
  if ($_ -lt 8) { Start-Sleep -Seconds 15 }
}
```

### C2-MALICIOUS-STAGED-TRANSFER

```powershell
curl.exe http://10.40.0.10:9001/stage.bin -o $env:TEMP\stage.bin
Get-FileHash $env:TEMP\stage.bin -Algorithm SHA256
```

### C2-MALICIOUS-STAGED-TRANSFER-RETRY

```powershell
1..3 | ForEach-Object {
  $out = Join-Path $env:TEMP ("stage-{0:D2}.bin" -f $_)
  curl.exe http://10.40.0.10:9001/stage.bin -o $out
  if ($_ -lt 3) { Start-Sleep -Seconds 20 }
}
Get-FileHash $env:TEMP\stage-*.bin -Algorithm SHA256
```

Cleanup:

```powershell
Remove-Item $env:TEMP\payload-benign.txt -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\stage.bin -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\stage-*.bin -ErrorAction SilentlyContinue
Get-Process curl,powershell,pwsh -ErrorAction SilentlyContinue
```

Đây là mô phỏng traffic an toàn trong lab, không tạo reverse shell, persistence, mã độc
hoặc kết nối ra Internet.

## 13. Lịch 10–12 run mỗi nhóm

Catalog có đúng năm scenario cho mỗi nhóm. Ở mốc tối thiểu 10, chạy mỗi scenario hai
lần: phân bố `2-2-2-2-2`. Ở mốc mục tiêu 12, chọn hai scenario khác nhau theo vòng
luân phiên và chạy thêm một lần: phân bố `3-3-2-2-2`. Tổng toàn bộ là 40 run ở mốc
READY hoặc 48 run ở mốc TARGET_MET; tỷ lệ lớn nhất lần lượt là 20% hoặc 25%.

Không chạy toàn bộ benign rồi mới malicious. Dùng lịch xen kẽ:

1. account-benign S1, c2-malicious S1, account-malicious S1, c2-benign S1;
2. đổi S1 thành S2, rồi S3, S4, S5;
3. lặp vòng thứ hai ở thời điểm khác, sau cleanup/preflight;
4. nếu cần đủ 12, chọn hai scenario khác nhau trong từng nhóm cho vòng thứ ba.

Mỗi lần lặp phải là thực thi mới, không copy thư mục run cũ.

## 14. Kiểm tra cuối và tạo dữ liệu Colab

Mốc 10 run/nhóm:

```bash
cd "$HOME/datn-ai-soar"
chmod +x scripts/verify_collection_dataset.sh
./scripts/verify_collection_dataset.sh
```

Phải báo `READY`, 40 valid run, 0 invalid. Mốc 12:

```bash
REQUIRE_TARGET=1 ./scripts/verify_collection_dataset.sh
```

Phải báo `TARGET_MET`, 48 valid run, 0 invalid. Sau đó mới build:

Collector vẫn lưu `suspicious_process` để truy vết telemetry, nhưng schema chủ động loại
feature này khỏi model C2 vì taxonomy chứa chính chuỗi lệnh của scenario và có thể làm
lộ nhãn. Auditor đồng thời từ chối bất kỳ feature model nào có khoảng giá trị benign và
malicious tách rời hoàn toàn trong cùng family. Không bỏ qua cổng này để ép train.

```bash
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml
jq . data/processed/dataset_manifest.json
wc -l data/processed/train.jsonl data/processed/validation.jsonl
grep -n 'locked_test_status' data/processed/dataset_manifest.json
```

Không mở hoặc upload nội dung `data/processed/locked_test.jsonl` hoặc `ml/splits/test.txt`
để xem kết quả trước Week 6. Tạo checksum ngay trên SOC-AI:

```bash
cd data/processed
sha256sum train.jsonl validation.jsonl dataset_manifest.json \
  | tee colab-upload.sha256
sha256sum --check colab-upload.sha256
cd ../..
```

Chỉ đưa bốn file sau lên đúng thư mục Google Drive
`MyDrive/DATN/week3-data/processed/` mà notebook cấu hình:

```text
data/processed/train.jsonl
data/processed/validation.jsonl
data/processed/dataset_manifest.json
data/processed/colab-upload.sha256
```

Không đổi tên file hoặc tạo thêm tầng `processed/processed`. Notebook tự từ chối nếu
thiếu file, checksum sai, `group_key` không phải `scenario_id`, scenario xuất hiện ở cả
TRAIN và VALIDATION, hoặc phát hiện `locked_test.jsonl`.

## 15. Sao lưu và bàn giao dữ liệu gốc

`data/raw/` và `evidence/scenario-runs/` bị Git bỏ qua có chủ đích; `git push` **không
phải bản sao lưu dataset**. Sau mỗi bốn run hợp lệ và cuối mỗi buổi, chỉ sao lưu khi
không còn run `STARTED`:

```bash
cd "$HOME/datn-ai-soar"
ACTIVE_RUNS=$(find evidence/scenario-runs -type f -name .collection_state.json \
  -print0 2>/dev/null | xargs -0 -r jq -r \
  'select(.status == "STARTED") | .run_id')
if [ -n "$ACTIVE_RUNS" ]; then
  printf 'FAIL: finalize/abort these runs before backup:\n%s\n' "$ACTIVE_RUNS" >&2
  exit 1
fi

mkdir -p data/raw evidence/scenario-runs run-drafts operator-logs
BACKUP_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
ARCHIVE="$BACKUP_DIR/collection-$BACKUP_ID.tar.gz"
mkdir -p "$BACKUP_DIR"
git rev-parse HEAD > "$BACKUP_DIR/git-commit.txt"
tar --create --gzip --file "$ARCHIVE" \
  data/raw evidence run-drafts operator-logs \
  config/scenario-catalog.yaml config/collection-sources.yaml \
  config/suspicious-process-taxonomy.yaml ml/feature_schema.json
(
  cd "$BACKUP_DIR"
  sha256sum "$(basename "$ARCHIVE")" git-commit.txt > checksums.sha256
  sha256sum --check checksums.sha256
)
tar -tzf "$ARCHIVE" | grep -q '^data/raw/'
tar -tzf "$ARCHIVE" | grep -q '^evidence/scenario-runs/'
printf 'BACKUP_ID=%s\n' "$BACKUP_ID"
```

Kiểm tra giải nén vào thư mục tạm, tuyệt đối không đè lên repo đang thu:

```bash
RESTORE_CHECK=$(mktemp -d)
trap 'rm -rf -- "$RESTORE_CHECK"' EXIT
tar -xzf "$ARCHIVE" -C "$RESTORE_CHECK"
test -d "$RESTORE_CHECK/data/raw"
test -d "$RESTORE_CHECK/evidence/scenario-runs"
find "$RESTORE_CHECK/data/raw" -name scenario_manifest.json | wc -l
```

Ngay sau đó sao chép cả thư mục backup ra ổ host Windows; nhập đúng `BACKUP_ID` vừa
in ra. Bản nằm cùng datastore VMware không được tính là bản sao thứ hai:

```powershell
$SocUser = Read-Host "SOC-AI SSH username"
$BackupId = Read-Host "BACKUP_ID from SOC-AI"
$BackupRoot = "D:\SOC_AI_SOAR_backups"
$SocHome = ssh "${SocUser}@192.168.58.147" 'printf %s "$HOME"'
if ($LASTEXITCODE -ne 0 -or -not $SocHome) { throw "Cannot resolve SOC-AI HOME" }
New-Item -ItemType Directory -Force $BackupRoot | Out-Null
scp -r "${SocUser}@192.168.58.147:${SocHome}/datn-backups/${BackupId}" $BackupRoot
Get-ChildItem "$BackupRoot\$BackupId" -File | Get-FileHash -Algorithm SHA256
```

Không đưa mật khẩu, API key, `.env` hoặc Wazuh credential vào archive. Khi bàn giao,
gửi archive, `checksums.sha256`, `git-commit.txt` và báo cáo audit cùng nhau.

## 16. Xử lý lỗi

| Lỗi | Nguyên nhân thường gặp | Xử lý bắt buộc |
|---|---|---|
| `no Wazuh Archive bytes` | agent chưa gửi hoặc log đang đến chậm | không tạo traffic mới; chờ 30 giây và retry finalize cùng ID, tối đa ba lần; sau đó abort |
| `does not end with a complete JSON line` | Wazuh đang ghi dở dòng cuối | không sửa Archives; chờ 30 giây rồi retry finalize cùng ID |
| `rotated or truncated` | Archives rotate trong run | abort, tránh giờ rotate, chạy ID mới |
| `no attributable Windows...` | sai agent/account/process/IP/port/DNS | đối chiếu draft với lệnh thật, chạy mới |
| `no attributable Suricata...` | traffic đi tắt hoặc EVE chưa forward | kiểm tra route, interface, ACL, Wazuh Agent |
| checksum mismatch | file evidence/generated bị sửa | loại run; không sửa checksum để hợp thức hóa |
| concentration >30% | lặp một scenario quá nhiều | thu thêm scenario khác; không copy mẫu |
| duplicate incident/run | tái sử dụng dữ liệu hoặc ID | loại bản trùng và chạy mới |
| `FEATURE_LABEL_SEPARATION` | một feature của model phân tách hoàn hảo nhãn trong cùng family | bổ sung scenario để khoảng giá trị benign/malicious chồng lấn; không train trước khi audit đạt |
| audit `NOT_READY` | thiếu hoặc có run invalid | đọc `ISSUES` và `shortage`, xử lý đúng nhóm |

Không dùng lệnh sửa trực tiếp `incidents.jsonl`, `scenario_manifest.json` hoặc
`checksums.sha256`. Dữ liệu hỏng phải được thu lại.

## 17. Ảnh minh chứng

Chụp toàn màn hình VMware Workstation, có thanh tiêu đề, Library, toàn bộ desktop 16 inch
và đồng hồ. Không chỉ chụp vùng terminal.

Ảnh bắt buộc:

1. sơ đồ NIC của bốn VM và `ip -br address`/`Get-NetIPConfiguration`;
2. `tracert` Windows → Kali qua NET-SENSOR;
3. Wazuh Dashboard có hai agent Active;
4. Sysmon config và Event Viewer ID 1/3/22;
5. Security Event Viewer 4624/4625;
6. Suricata `-T` success và EVE JSON;
7. Wazuh Archives có `WIN11-TARGET` và `NET-SENSOR`;
8. màn hình `start`, hoạt động thật, `finalize`, `VALID` của một account run;
9. tương tự cho một C2 run, kèm Suricata alert/flow;
10. auditor ở mốc `READY`/`TARGET_MET` và dataset manifest.

Tên ảnh: `W3-DATA-<nn>-<noi-dung>-<run-id>.png`. Không chụp mật khẩu, API key, token,
cookie hoặc nội dung `.env`.

## 18. Tiêu chí bàn giao

Chỉ bàn giao khi tất cả đều đúng:

- [ ] 4 VM đúng tên và traffic C2 bắt buộc qua NET-SENSOR.
- [ ] thời gian đồng bộ; hai Wazuh Agent Active.
- [ ] ID 1/3/22 và 4624/4625 tồn tại trong Archives.
- [ ] EVE flow/DNS/HTTP và alert local tồn tại trong Archives.
- [ ] mỗi run có ground truth trước hoạt động, evidence, metadata, checksum.
- [ ] 10–12 run hợp lệ cho mỗi trong bốn nhóm.
- [ ] đủ 5 scenario/nhóm; không scenario nào >30%.
- [ ] auditor báo 0 invalid; build dataset thành công.
- [ ] dataset manifest ghi `group_key=scenario_id`, locked test `UNOPENED`.
- [ ] ảnh minh chứng không lộ bí mật.

Mốc 10–12 run/nhóm đủ cho benchmark đồ án và kiểm thử pipeline, nhưng vẫn là dataset
nhỏ; không được mô tả là đủ để triển khai production. Chất lượng phụ thuộc vào đa dạng
kịch bản, tính độc lập, bằng chứng đầy đủ và việc không làm rò nhãn vào feature.

## 19. Atomic Red Team không thuộc đợt thu v1

Không cài hoặc chạy Atomic Red Team trong 40–48 run của tài liệu này. Catalog v1 đã có
20 scenario kiểm soát được; thêm Atomic giữa đợt sẽ thay đổi phân phối dữ liệu, làm mất
tính lặp lại và có thể để lại trạng thái ngoài dự kiến trên Windows.

Nếu nhóm mở rộng ở phiên bản sau, phải lập kế hoạch thay đổi riêng: chọn chính xác test,
đọc attack/cleanup command, duyệt payload, khóa release/commit cụ thể, kiểm tra SHA-256
trước khi chạy, snapshot riêng, ghi execution log và tạo scenario/catalog mới. Không dùng
lệnh tải script từ nhánh `master` rồi thực thi trực tiếp, không dùng Atomic để bù số run,
và không trộn dữ liệu mở rộng vào dataset v1.

## 20. Tài liệu chính thức đã đối chiếu

- Wazuh Quickstart 4.14: https://documentation.wazuh.com/current/quickstart.html
- Wazuh Windows/Linux agent: https://documentation.wazuh.com/current/installation-guide/
- Wazuh Archives: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- Wazuh localfile: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Wazuh kiểm tra cấu hình: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html
- Wazuh Windows default channels: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html
- Microsoft Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft OpenSSH Client: https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Atomic Red Team: https://www.atomicredteam.io/docs/invoke-atomicredteam

Atomic Red Team chỉ là hướng mở rộng sau khi dataset v1 đã được đóng và bàn giao; không
phải điều kiện để hoàn thành 48 run trong catalog.
