# QUY TRÌNH CHUẨN THU THẬP DỮ LIỆU TRAIN TRÊN LAB 4 VM

Phiên bản: 1.0 — 16/10/2026
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

Mỗi nhóm dùng đủ bốn kịch bản trong `config/scenario-catalog.yaml`; ở mốc 12 run,
mỗi kịch bản chạy ba lần. Không nhân bản file để tăng số mẫu.

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

- SOC-AI: 4 vCPU, 8 GB RAM, 80 GB disk.
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
```

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

Tạo `/etc/netplan/60-datn-data.yaml` (thay đúng tên NIC; giữ cấu hình management đang
hoạt động trong file netplan hiện hữu):

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
```

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

Thay `eth1` bằng NIC VMnet2 thực tế:

```bash
sudo nmcli connection add type ethernet ifname eth1 con-name ATTACK-LAB \
  ipv4.method manual ipv4.addresses 10.40.0.10/24 \
  ipv4.routes "10.20.0.0/24 10.40.0.1" ipv6.method disabled
sudo nmcli connection up ATTACK-LAB
ip route get 10.20.0.10
```

### 5.4 Windows 11

Thay `Ethernet 2` bằng NIC VMnet3 thực tế:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 10.20.0.10 -PrefixLength 24
New-NetRoute -DestinationPrefix 10.40.0.0/24 -InterfaceAlias "Ethernet 2" `
  -NextHop 10.20.0.1 -PolicyStore PersistentStore
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

Mở `/var/ossec/etc/ossec.conf`, trong khối `<global>` đặt:

```xml
<logall>no</logall>
<logall_json>yes</logall_json>
```

Sau đó:

```bash
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
cd /home/lethinh
git clone --branch feature/week3-model-training \
  https://github.com/lethinhlord/Repo.git datn-ai-soar
cd /home/lethinh/datn-ai-soar
git status --short
git branch --show-current
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
sudo usermod -aG docker lethinh
newgrp docker
./scripts/deploy_week2.sh
./scripts/verify_week2.sh
curl -fsS http://127.0.0.1:8000/ready | jq .
curl -fsS http://127.0.0.1:5678/healthz
```

Cho user vận hành quyền đọc Archives rồi đăng nhập lại SSH:

```bash
sudo usermod -aG wazuh lethinh
id lethinh
sudo -u lethinh test -r /var/ossec/logs/archives/archives.json
```

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

Từ SOC-AI chuyển config vào Windows:

```powershell
New-Item -ItemType Directory -Force C:\DATN | Out-Null
scp lethinh@192.168.58.147:/home/lethinh/datn-ai-soar/config/sysmon-datn.xml C:\DATN\
scp lethinh@192.168.58.147:/home/lethinh/datn-ai-soar/config/wazuh-windows-localfile.xml C:\DATN\
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

Chèn hai block trong `config/wazuh-windows-localfile.xml` vào bên trong
`<ossec_config>` của `C:\Program Files (x86)\ossec-agent\ossec.conf`, rồi:

```powershell
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
scp lethinh@192.168.58.147:/home/lethinh/datn-ai-soar/config/suricata-datn.rules /tmp/
sudo install -m 0644 /tmp/suricata-datn.rules /etc/suricata/rules/datn.rules
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
sudo systemctl is-active suricata
sudo tail -n 5 /var/log/suricata/eve.json | jq -c .
```

Ba SID local: 900001 HTTP beacon, 900002 DNS beacon, 900003 staged transfer. Nếu
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

Chèn block trong `config/wazuh-suricata-localfile.xml` vào `<ossec_config>` của
`/var/ossec/etc/ossec.conf`. Cho Wazuh đọc được EVE hiện tại và file tạo sau rotate:

```bash
scp lethinh@192.168.58.147:/home/lethinh/datn-ai-soar/config/wazuh-suricata-localfile.xml /tmp/
sudo setfacl -m u:wazuh:rx /var/log/suricata
sudo setfacl -m u:wazuh:r /var/log/suricata/eve.json
sudo setfacl -d -m u:wazuh:rx /var/log/suricata
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
server=1.1.1.1
address=/www.datn.test/10.40.0.10
address=/beacon.datn.test/10.40.0.10
```

Thay `eth1` đúng NIC VMnet2, rồi:

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
cd /home/lethinh/datn-ai-soar
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
```

Windows:

```powershell
Get-Service Sysmon64,WazuhSvc
Test-NetConnection 10.40.0.10 -Port 8080
Resolve-DnsName www.datn.test -Server 10.40.0.10
```

Kali:

```bash
systemctl is-active datn-http-benign datn-http-beacon datn-http-stage dnsmasq
ss -lntup | grep -E ':53|:8080|:8081|:9001'
```

Nếu một lệnh không đạt, không bắt đầu run. Ghi lỗi, sửa, chạy lại toàn bộ preflight.

## 11. Quy trình chuẩn cho MỖI run

Thực hiện đúng thứ tự; không gộp hai kịch bản trong một cửa sổ.

### Bước 1 — Chọn run và khai báo ground truth trước

Quy ước ID:

```text
<SCENARIO-ID>-R<01..03>-<YYYYMMDD>
```

Ví dụ trên SOC-AI:

```bash
cd /home/lethinh/datn-ai-soar
RUN_ID=C2-MALICIOUS-HTTP-BEACON-R01-20261016
.venv-ml/bin/python -m scripts.create_run_draft \
  --scenario C2-MALICIOUS-HTTP-BEACON \
  --run-id "$RUN_ID" \
  --operator Kien
sed -n '1,120p' "run-drafts/$RUN_ID.yaml"
```

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
checksum, thiếu diversity hoặc concentration >40%.

### Bước 8 — Cleanup và khoảng nghỉ

Thực hiện cleanup trong catalog, chờ ít nhất 60 giây, kiểm tra không còn loop PowerShell,
xóa file tạm. Không chạy hai run đồng thời. Không tái dùng `run_id`.

Nếu thao tác sai giữa run:

```bash
.venv-ml/bin/python -m scripts.scenario_session abort \
  --run-id "$RUN_ID" --reason "ghi ro ly do"
```

Sau đó cleanup, chờ pipeline yên, tạo run mới với ID mới.

## 12. Câu lệnh thực thi C2 trên Windows

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
  curl.exe -s -o NUL http://10.40.0.10:8080/api-status
  if ($i -lt 3) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-BENIGN-DNS

```powershell
$gaps = @(7,23,11)
for ($i=0; $i -lt 4; $i++) {
  Resolve-DnsName www.datn.test -Server 10.40.0.10
  if ($i -lt 3) { Start-Sleep -Seconds $gaps[$i] }
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

Cleanup:

```powershell
Remove-Item $env:TEMP\payload-benign.txt -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\stage.bin -ErrorAction SilentlyContinue
Get-Process curl,powershell,pwsh -ErrorAction SilentlyContinue
```

Đây là mô phỏng traffic an toàn trong lab, không tạo reverse shell, persistence, mã độc
hoặc kết nối ra Internet.

## 13. Lịch 12 run mỗi nhóm

Với mỗi nhóm, chạy S1, S2, S3, S4, rồi lặp lại ba vòng. Catalog đã sắp bốn scenario
theo thứ tự. Tổng 48 mẫu. Nếu dừng ở 10, phân bố nên là 3-3-2-2; không để một scenario
chiếm hơn 40%.

Không chạy toàn bộ benign rồi mới malicious. Dùng lịch xen kẽ:

1. account-benign S1, c2-malicious S1, account-malicious S1, c2-benign S1;
2. đổi S1 thành S2, rồi S3, S4;
3. lặp vòng hai và vòng ba ở thời điểm khác, sau cleanup/preflight.

Mỗi lần lặp phải là thực thi mới, không copy thư mục run cũ.

## 14. Kiểm tra cuối và tạo dữ liệu Colab

Mốc 10 run/nhóm:

```bash
cd /home/lethinh/datn-ai-soar
chmod +x scripts/verify_collection_dataset.sh
./scripts/verify_collection_dataset.sh
```

Phải báo `READY`, 40 valid run, 0 invalid. Mốc 12:

```bash
REQUIRE_TARGET=1 ./scripts/verify_collection_dataset.sh
```

Phải báo `TARGET_MET`, 48 valid run, 0 invalid. Sau đó mới build:

```bash
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml
jq . data/processed/dataset_manifest.json
wc -l data/processed/train.jsonl data/processed/validation.jsonl
grep -n 'locked_test_status' data/processed/dataset_manifest.json
```

Không mở hoặc upload nội dung `data/processed/locked_test.jsonl` hoặc `ml/splits/test.txt`
để xem kết quả trước Week 6. Chỉ đưa ba file sau lên thư mục Drive mà notebook cấu hình:

```text
data/processed/train.jsonl
data/processed/validation.jsonl
data/processed/dataset_manifest.json
```

Sau khi upload, đối chiếu SHA-256 ở SOC-AI và Colab trước khi train.

## 15. Xử lý lỗi

| Lỗi | Nguyên nhân thường gặp | Xử lý bắt buộc |
|---|---|---|
| `no Wazuh Archive bytes` | agent chưa gửi hoặc chờ chưa đủ | abort, sửa agent, chạy ID mới |
| `rotated or truncated` | Archives rotate trong run | abort, tránh giờ rotate, chạy ID mới |
| `no attributable Windows...` | sai agent/account/process/IP/port/DNS | đối chiếu draft với lệnh thật, chạy mới |
| `no attributable Suricata...` | traffic đi tắt hoặc EVE chưa forward | kiểm tra route, interface, ACL, Wazuh Agent |
| checksum mismatch | file evidence/generated bị sửa | loại run; không sửa checksum để hợp thức hóa |
| concentration >40% | lặp một scenario quá nhiều | thu thêm scenario khác; không copy mẫu |
| duplicate incident/run | tái sử dụng dữ liệu hoặc ID | loại bản trùng và chạy mới |
| audit `NOT_READY` | thiếu hoặc có run invalid | đọc `ISSUES` và `shortage`, xử lý đúng nhóm |

Không dùng lệnh sửa trực tiếp `incidents.jsonl`, `scenario_manifest.json` hoặc
`checksums.sha256`. Dữ liệu hỏng phải được thu lại.

## 16. Ảnh minh chứng

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

## 17. Tiêu chí bàn giao

Chỉ bàn giao khi tất cả đều đúng:

- [ ] 4 VM đúng tên và traffic C2 bắt buộc qua NET-SENSOR.
- [ ] thời gian đồng bộ; hai Wazuh Agent Active.
- [ ] ID 1/3/22 và 4624/4625 tồn tại trong Archives.
- [ ] EVE flow/DNS/HTTP và alert local tồn tại trong Archives.
- [ ] mỗi run có ground truth trước hoạt động, evidence, metadata, checksum.
- [ ] 10–12 run hợp lệ cho mỗi trong bốn nhóm.
- [ ] ít nhất 3 scenario/nhóm; không scenario nào >40%.
- [ ] auditor báo 0 invalid; build dataset thành công.
- [ ] dataset manifest ghi `group_key=run_id`, locked test `UNOPENED`.
- [ ] ảnh minh chứng không lộ bí mật.

Mốc 10–12 run/nhóm đủ cho benchmark đồ án và kiểm thử pipeline, nhưng vẫn là dataset
nhỏ; không được mô tả là đủ để triển khai production. Chất lượng phụ thuộc vào đa dạng
kịch bản, tính độc lập, bằng chứng đầy đủ và việc không làm rò nhãn vào feature.

## 18. Tùy chọn Atomic Red Team (không bắt buộc cho catalog v1)

Chỉ cài khi nhóm đã duyệt test cụ thể. Catalog v1 cố ý dùng mô phỏng kiểm soát được để
nhãn và attribution ổn định; Atomic không được chạy hàng loạt hoặc dùng để “bù số run”.

Trên Windows PowerShell (Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force -noPayloads
$PSDefaultParameterValues = @{
  "Invoke-AtomicTest:PathToAtomicsFolder" = "C:\AtomicRedTeam\atomics"
}
```

Với `$Technique` và `$TestNumber` đã được nhóm duyệt, luôn xem chi tiết và kiểm tra điều
kiện trước:

```powershell
Invoke-AtomicTest $Technique -TestNumbers $TestNumber -ShowDetails
Invoke-AtomicTest $Technique -TestNumbers $TestNumber -CheckPrereqs
```

Khi tạo draft trên SOC-AI, khai báo trước vị trí execution log sẽ nhận về:

```bash
mkdir -p operator-logs
.venv-ml/bin/python -m scripts.create_run_draft \
  --scenario "$SCENARIO_ID" --run-id "$RUN_ID" --operator Kien \
  --execution-log "operator-logs/atomic-$RUN_ID.csv"
.venv-ml/bin/python -m scripts.scenario_session start \
  --draft "run-drafts/$RUN_ID.yaml"
```

Chỉ sau khi collector đã `STARTED` mới execute; trên Windows đặt đúng `RUN_ID` và ghi
log vào file riêng:

```powershell
$env:RUN_ID = "ID-giong-het-draft-tren-SOC-AI"
$log = "C:\DATN\atomic-$env:RUN_ID.csv"
Invoke-AtomicTest $Technique -TestNumbers $TestNumber -ExecutionLogPath $log
Invoke-AtomicTest $Technique -TestNumbers $TestNumber -Cleanup
Get-FileHash $log -Algorithm SHA256
scp $log lethinh@192.168.58.147:/home/lethinh/datn-ai-soar/operator-logs/
```

Trên SOC-AI, xác nhận file tồn tại rồi mới `finalize`; collector sẽ từ chối nếu draft đã
khai báo log nhưng file chưa được chuyển về. Nếu cleanup lỗi, abort run và restore
snapshot. Không chạy test credential dumping, persistence, destructive impact hoặc test
có payload chưa được rà soát.

## 19. Tài liệu chính thức đã đối chiếu

- Wazuh Quickstart 4.14: https://documentation.wazuh.com/current/quickstart.html
- Wazuh Windows/Linux agent: https://documentation.wazuh.com/current/installation-guide/
- Wazuh Archives: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- Wazuh localfile: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Microsoft Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Atomic Red Team: https://www.atomicredteam.io/docs/invoke-atomicredteam

Atomic Red Team là tùy chọn mở rộng, không phải điều kiện để hoàn thành 48 run trong
catalog. Nếu sử dụng, phải đọc test, chạy `-CheckPrereqs`, ghi execution log, cleanup và
chỉ chạy test đã được phê duyệt trong Windows lab; không thay ground truth bằng cảnh báo.
