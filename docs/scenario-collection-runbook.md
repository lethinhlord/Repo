# QUY TRÌNH CHUẨN THU THẬP DỮ LIỆU TRAIN TRÊN LAB 4 VM

Phiên bản: 2.2 — hoàn tất ngày 28/10/2026
Phạm vi: dữ liệu `account-benign`, `account-malicious`, `c2-benign`,
`c2-malicious` cho nhánh `feature/week3-model-training`.

Baseline sửa lỗi bắt buộc: người bàn giao ghi **commit SHA đã được merge** vào
`COLLECTION_BASELINE_COMMIT`; SHA đó phải là ancestor của commit đang chạy. Không chỉ
kiểm tra tên branch và không dùng một tag có thể bị force-move.

## 1. Kết quả bắt buộc

Mỗi lần chạy kịch bản là **một mẫu độc lập**, có một `run_id`, một nhãn được khai báo
trước khi chạy, bằng chứng gốc và checksum. Không coi từng dòng log là một mẫu.

Mỗi code block Bash là một phiên lệnh fail-closed. Nếu block không lặp lại dòng khởi tạo,
phải chạy `set -euo pipefail` trong cùng shell trước khi chạy; dừng ngay ở exit code khác
0, không copy riêng các dòng sau lỗi và không thêm `|| true` ngoài vị trí đã ghi rõ.

| Nhóm | Tối thiểu để bắt đầu train | Mục tiêu nên thu |
|---|---:|---:|
| account-benign | 10 run hợp lệ | 12 |
| account-malicious | 10 run hợp lệ | 12 |
| c2-benign | 10 run hợp lệ | 12 |
| c2-malicious | 10 run hợp lệ | 12 |

Mỗi nhóm dùng đủ **năm** kịch bản trong `config/scenario-catalog.yaml`. Ở mốc 10,
mỗi kịch bản chạy đúng hai lần. Ở mốc 11, chọn một kịch bản để chạy lần thứ ba; ở mốc
12, chọn thêm một kịch bản khác để chạy lần thứ ba. Vì vậy phân bố luôn cân bằng và
không kịch bản nào vượt 27,3% số run của nhóm. Không nhân bản file để tăng số mẫu.

## 1.1 Cổng chuyển đổi bắt buộc khỏi bộ thu cũ

Thư mục host `D:\SOC_AI_SOAR_dataset_v2\SOC_Dataset_v2` là **evidence tham khảo của
quy trình cũ**, không phải đầu vào hợp lệ của pipeline này. Sáu run đang có không được
tính vào mốc 40–48 vì dùng schema `metadata.json`/`events_raw.jsonl`, agent
`WIN11-01`/`net-sensor`, traffic C2 trên mạng management và scenario ngoài catalog v1.
Không xóa bộ cũ, không đổi tên file để hợp thức hóa và không copy `Benign`/`C2` vào
`data/raw/`.

Trước khi thu run mới, phải hoàn tất cả bốn chuyển đổi sau:

| Thành phần cũ | Trạng thái bắt buộc cho dataset mới |
|---|---|
| Windows/Wazuh `WIN11-01` | hostname và Wazuh Agent đều là `WIN11-TARGET` |
| Wazuh Agent `net-sensor` | hostname và Wazuh Agent đều là `NET-SENSOR` |
| C2 `192.168.58.148 → 192.168.58.132` | `10.20.0.10 → 10.40.0.10` qua NET-SENSOR |
| `metadata.json` + `events_raw.jsonl` | collector tạo `scenario_manifest.json`, `incidents.jsonl`, evidence và checksum |

Nếu Dashboard còn agent tên cũ, bảo toàn evidence cần thiết rồi xóa đăng ký cũ trong
Dashboard và cài/enroll lại agent theo mục 7.3/8.2; không sửa tên trực tiếp trong log đã
thu. Xác nhận trên SOC-AI:

```bash
set -euo pipefail
AGENTS=$(sudo /var/ossec/bin/agent_control -l)
printf '%s\n' "$AGENTS" | grep -E 'Name: WIN11-TARGET,.*Active'
printf '%s\n' "$AGENTS" | grep -E 'Name: NET-SENSOR,.*Active'
if printf '%s\n' "$AGENTS" | grep -E 'Name: (WIN11-01|net-sensor),'; then
  echo 'FAIL: legacy Wazuh agent registration remains' >&2
  exit 1
fi
```

Trong checkout mới trên SOC-AI, `data/raw/` phải rỗng hoặc chỉ chứa run mới đã finalize.
Kiểm tra chỉ đọc; lệnh phải không in đường dẫn nào:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar"
if [ -d data/raw ]; then
  LEGACY_MARKERS=$(find data/raw -type f \
    \( -name events_raw.jsonl -o -name metadata.json \) -print)
  test -z "$LEGACY_MARKERS" || {
    printf 'FAIL: legacy files found:\n%s\n' "$LEGACY_MARKERS" >&2
    exit 1
  }
  while IFS= read -r RUN_DIR; do
    test -f "$RUN_DIR/scenario_manifest.json"
    test -f "$RUN_DIR/incidents.jsonl"
    .venv-ml/bin/python -m scripts.scenario_session validate \
      --run-id "$(basename "$RUN_DIR")" >/dev/null
  done < <(find data/raw -mindepth 1 -maxdepth 1 -type d -print)
fi
echo 'LEGACY_DATASET_NOT_ACCEPTED=PASS'
```

Lệnh `scenario_session start` cũng từ chối fail-closed với lỗi
`incompatible raw dataset layout` nếu phát hiện marker cũ hoặc run trước không còn
validate được đầy đủ cả raw/evidence/checksum. Nếu bị từ chối, không xóa dữ liệu tại chỗ:
sao lưu, xác minh checksum rồi chuyển toàn bộ bộ cũ ra ngoài repo dưới tên riêng. Chỉ sau
đó mới chạy lại preflight và hai pilot ở G5.

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
$ErrorActionPreference = 'Stop'
$DataIf = "Ethernet 2"
$unexpectedIp = Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -ne '10.20.0.10' -and $_.PrefixOrigin -ne 'WellKnown'
  }
if ($unexpectedIp) { throw "Unexpected IPv4 address exists on $DataIf" }
if (-not (Get-NetIPAddress -InterfaceAlias $DataIf -AddressFamily IPv4 `
  -ErrorAction SilentlyContinue | Where-Object IPAddress -eq "10.20.0.10")) {
  New-NetIPAddress -InterfaceAlias $DataIf -IPAddress 10.20.0.10 -PrefixLength 24
}
$routes = @(Get-NetRoute -DestinationPrefix "10.40.0.0/24" `
  -ErrorAction SilentlyContinue)
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
dpkg-query -W -f='${Package}=${Version}\n' \
  wazuh-manager wazuh-indexer wazuh-dashboard | tee wazuh-package-versions.txt
grep -E '^wazuh-(manager|indexer|dashboard)=4\.14\.' wazuh-package-versions.txt
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard
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
set -euo pipefail
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
test "$(git branch --show-current)" = "feature/week3-model-training"
test -z "$(git status --porcelain)" || {
  echo 'FAIL: repository has local changes' >&2
  exit 1
}
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/feature/week3-model-training)"
: "${COLLECTION_BASELINE_COMMIT:?Nhap commit SHA da duoc merge do nguoi ban giao cung cap}"
[[ "$COLLECTION_BASELINE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
git cat-file -e "$COLLECTION_BASELINE_COMMIT^{commit}"
git merge-base --is-ancestor "$COLLECTION_BASELINE_COMMIT" HEAD || {
  echo "FAIL: repository is older than $COLLECTION_BASELINE_COMMIT" >&2
  exit 1
}
git rev-parse HEAD | tee evidence/collection-source-commit.txt
chmod +x scripts/bootstrap_ml.sh scripts/deploy_week2.sh scripts/verify_week2.sh
./scripts/bootstrap_ml.sh
.venv-ml/bin/python -m pytest -q \
  tests/test_scenario_collection.py \
  tests/test_dataset_audit.py \
  tests/test_collection_configuration.py \
  tests/test_export_run_parameters.py \
  tests/test_ml_dataset.py
echo 'REPOSITORY_PREFLIGHT=PASS'
```

Kết quả chuẩn là toàn bộ test pass. Nếu cần API/n8n Week 2 trên cùng VM:

```bash
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$LAB_USER"
```

Thoát SSH, đăng nhập lại để group có hiệu lực, rồi:

```bash
set -euo pipefail
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
}
Ensure-DatnLabUser datn_benign 'DATN benign lab account'
Ensure-DatnLabUser datn_attack 'DATN attack decoy'
1..3 | ForEach-Object {
  Ensure-DatnLabUser ("datn_spray{0:D2}" -f $_) 'DATN spray decoy'
}
$LogonAuditGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
auditpol /set /subcategory:$LogonAuditGuid /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) { throw 'Cannot enable Logon audit policy' }
auditpol /get /subcategory:$LogonAuditGuid
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify Logon audit policy' }
```

GUID làm cho lệnh không phụ thuộc ngôn ngữ Windows. Xuất policy gốc, sau đó vô hiệu hóa
lockout **chỉ trên VM target dùng riêng cho lab** để các run 6/10 lần sai không bị phụ
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

Kịch bản `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS` dùng SMB từ duy nhất Kali
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
  -RemoteAddress 10.40.0.10 -Profile Any | Out-Null
Get-NetFirewallRule -Name DATN-SMB-From-Kali | Format-List Name,Enabled,Action
$wideSmbRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Where-Object Name -ne 'DATN-SMB-From-Kali' | ForEach-Object {
    $port = $_ | Get-NetFirewallPortFilter
    $address = $_ | Get-NetFirewallAddressFilter
    if (($port.LocalPort -contains '445' -or $port.LocalPort -eq 'Any') -and
        ($address.RemoteAddress -contains 'Any' -or
         $address.RemoteAddress -contains 'LocalSubnet')) { $_ }
  }
if ($wideSmbRules) {
  $wideSmbRules | Select-Object Name,DisplayName
  throw 'Broad inbound SMB allow rule exists; disable it before collection'
}
```

Sau khi đóng dataset, khôi phục policy gốc bằng snapshot `01-TELEMETRY-READY` hoặc lệnh
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
$SocRepo = "$SocHome/datn-ai-soar"
New-Item -ItemType Directory -Force C:\DATN | Out-Null
scp "${SocUser}@192.168.58.147:${SocRepo}/config/sysmon-datn.xml" C:\DATN\
scp "${SocUser}@192.168.58.147:${SocRepo}/config/wazuh-windows-localfile.xml" C:\DATN\
scp "${SocUser}@192.168.58.147:${SocRepo}/scripts/run_dns_scenario.ps1" C:\DATN\
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
C:\DATN\Sysmon\Sysmon64.exe -accepteula -i C:\DATN\sysmon-datn.xml
C:\DATN\Sysmon\Sysmon64.exe -c
Get-Service Sysmon64
```

Config repo bật ProcessCreate (ID 1), NetworkConnect (ID 3) và DnsQuery (ID 22). Không
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
$wazuhSignature = Get-AuthenticodeSignature C:\DATN\wazuh-agent-4.14.9-1.msi
if ($wazuhSignature.Status -ne 'Valid') { throw 'Invalid Wazuh MSI signature' }
Get-FileHash C:\DATN\wazuh-agent-4.14.9-1.msi -Algorithm SHA256 |
  Format-List | Out-File C:\DATN\wazuh-agent-4.14.9-1.msi.sha256.txt -Encoding ascii
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
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  datn_clock@192.168.58.148 powershell.exe -NoProfile -NonInteractive -Command \
  "[DateTimeOffset]::UtcNow.ToString('o')"
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${SENSOR_USER}@192.168.58.150" date -u --iso-8601=seconds
ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${KALI_USER}@192.168.58.132" date -u --iso-8601=seconds
```

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
suricata --build-info | head -n 20
```

Trong `/etc/suricata/suricata.yaml`:

- đặt `HOME_NET` là `[10.20.0.0/24]`;
- cấu hình `af-packet` nghe **chỉ NIC phía Kali** (ví dụ `ens37`) để tránh đếm đôi;
- trong `eve-log.types` bật `alert`, `dns`, `http`, `tls`, `flow`;
- thêm đường dẫn tuyệt đối `/etc/suricata/rules/datn.rules` vào `rule-files`.

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
  - /etc/suricata/rules/datn.rules
```

Đây là các mục cần sửa **trong các section sẵn có**, không dán thêm một bộ khóa
`vars`/`af-packet`/`outputs`/`rule-files` ở cuối file. Trước khi lưu, dùng
`grep -nE '^(vars:|af-packet:|outputs:|rule-files:)'` và bảo đảm mỗi khóa cấp cao nhất chỉ
có một lần. Nếu không xác định được đúng vị trí, phục hồi backup và nhờ người phụ trách
kiểm tra; không đoán thứ tự YAML.

Chuyển rule từ SOC-AI:

```bash
read -rp 'SOC-AI SSH username: ' SOC_USER
SOC_HOME=$(ssh "${SOC_USER}@192.168.58.147" 'printf %s "$HOME"') || exit 1
SOC_REPO="$SOC_HOME/datn-ai-soar"
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/config/suricata-datn.rules" /tmp/
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

Đạt G4 chỉ khi Archives có event từ cả hai agent. Có event trên NET-SENSOR nhưng không
có ở Archives nghĩa là cấu hình Wazuh/ACL chưa đạt.

## 9. Cài dịch vụ mô phỏng trên Kali

```bash
sudo apt update
sudo apt install -y python3 dnsmasq curl jq dnsutils smbclient
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

## 10. Preflight bắt buộc trước mỗi buổi thu

### 10.1 Chuyển lab sang collection mode cô lập Internet

Chỉ thực hiện sau khi đã cài hết package. **Trước khi xóa route**, đồng bộ giờ khi
management/NAT còn hoạt động. Trên từng Linux VM:

```bash
sudo timedatectl set-ntp true
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
xong rồi quay lại snapshot và chạy lại toàn bộ preflight. Không cập nhật trong cửa sổ run.

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
cd "$HOME/datn-ai-soar"
test -z "$(git status --porcelain)"
test "$(git branch --show-current)" = feature/week3-model-training
: "${COLLECTION_BASELINE_COMMIT:?Missing merged collection baseline SHA}"
[[ "$COLLECTION_BASELINE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
git merge-base --is-ancestor "$COLLECTION_BASELINE_COMMIT" HEAD
test ! -e evidence/scenario-runs/.active-run.json
while IFS= read -r -d '' STATE; do
  jq -e . "$STATE" >/dev/null
  test "$(jq -r '.status' "$STATE")" != STARTED
done < <(find evidence/scenario-runs -mindepth 2 \
  -name .collection_state.json -print0)
.venv-ml/bin/python -m scripts.scenario_session --help >/dev/null
.venv-ml/bin/python -m scripts.audit_dataset --help >/dev/null
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
ARCHIVE=/var/ossec/logs/archives/archives.json
test "$(sudo tail -c 1 "$ARCHIVE" | od -An -t u1 | tr -d ' ')" = 10
sudo stat -c %s "$ARCHIVE" | tee /tmp/datn-preflight.cursor
```

Ngay sau đó trên Windows PowerShell chạy canary an toàn và bắt mọi lỗi HTTP:

```powershell
$ErrorActionPreference = 'Stop'
foreach ($uri in @(
  'http://10.40.0.10:8080/health?preflight=1',
  'http://10.40.0.10:8081/beacon?preflight=1',
  'http://10.40.0.10:9001/stage.bin'
)) {
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw "Canary failed: $uri" }
}
Resolve-DnsName preflight.www.datn.test -Server 10.40.0.10 | Out-Null
Resolve-DnsName preflight.beacon.datn.test -Server 10.40.0.10 | Out-Null
```

Tại console Windows, khóa màn hình, nhập sai mật khẩu `datn_benign` đúng một lần rồi
đăng nhập đúng một lần. Trên Kali, tạo một SMB canary thất bại có chủ đích rồi một
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
ARCHIVE=/var/ossec/logs/archives/archives.json
CURSOR=$(cat /tmp/datn-preflight.cursor)
FRESH=/tmp/datn-preflight-fresh.jsonl
PASS=0
for attempt in $(seq 1 18); do
  sudo tail -c "+$((CURSOR + 1))" "$ARCHIVE" > "$FRESH"
  if jq -e 'select(.agent.name=="WIN11-TARGET" and
      ((.data.win.system.eventID//"")|tostring)=="1")' "$FRESH" >/dev/null 2>&1 \
    && jq -e 'select(.agent.name=="WIN11-TARGET" and
      ((.data.win.system.eventID//"")|tostring)=="3")' "$FRESH" >/dev/null 2>&1 \
    && jq -e 'select(.agent.name=="WIN11-TARGET" and
      ((.data.win.system.eventID//"")|tostring)=="22")' "$FRESH" >/dev/null 2>&1 \
    && jq -e 'select(.agent.name=="NET-SENSOR") |
      (.full_log|fromjson?) | select(.src_ip=="10.20.0.10" and
      .dest_ip=="10.40.0.10")' "$FRESH" >/dev/null 2>&1 \
    && jq -e 'select(.agent.name=="NET-SENSOR") |
      (.full_log|fromjson?) |
      select(.event_type=="alert" and
      (.alert.signature_id==900001 or .alert.signature_id==900002 or
       .alert.signature_id==900004))' "$FRESH" >/dev/null 2>&1 \
    && jq -e 'select(.agent.name=="WIN11-TARGET" and
      ((.data.win.system.eventID//"")|tostring)=="4624" and
      ((.data.win.eventdata.targetUserName//"")|ascii_downcase)=="datn_attack" and
      ((.data.win.eventdata.logonType//"")|tostring)=="3" and
      ((.data.win.eventdata.ipAddress//"")|endswith("10.40.0.10")))' \
      "$FRESH" >/dev/null 2>&1; then
    PASS=1; break
  fi
  sleep 5
done
test "$PASS" -eq 1
for EVENT_ID in 4624 4625; do
  jq -e --arg id "$EVENT_ID" 'select(.agent.name=="WIN11-TARGET" and
    ((.data.win.system.eventID//"")|tostring)==$id and
    ((.data.win.eventdata.targetUserName//"")|ascii_downcase)=="datn_benign" and
    ((.data.win.eventdata.logonType//"")|tostring)=="2")' \
    "$FRESH" >/dev/null
  jq -e --arg id "$EVENT_ID" 'select(.agent.name=="WIN11-TARGET" and
    ((.data.win.system.eventID//"")|tostring)==$id and
    ((.data.win.eventdata.targetUserName//"")|ascii_downcase)=="datn_attack" and
    ((.data.win.eventdata.logonType//"")|tostring)=="3")' \
    "$FRESH" >/dev/null
done
for SID in 900001 900002 900004; do
  jq -e --argjson sid "$SID" 'select(.agent.name=="NET-SENSOR") |
    (.full_log|fromjson?) |
    select(.event_type=="alert" and .alert.signature_id==$sid)' \
    "$FRESH" >/dev/null
done
echo 'END_TO_END_PREFLIGHT=PASS'
```

Nếu bất kỳ block nào không in `PASS`, không bắt đầu run. Sửa nguyên nhân rồi chạy lại
từ 10.1; không dùng event cũ, không tạo file Archives giả và không hạ ngưỡng kiểm tra.

### 10.5 Pilot collector bắt buộc sau khi cài mới hoặc đổi code/config

Chạy trọn quy trình mục 11 cho đúng hai pilot sau, gồm `start`, export tham số bất biến,
`begin-action`, hành động, `complete-action`, `finalize` và `validate`:

1. `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS` để kiểm đường SMB, LogonType 3 và chuỗi
   4625→4624;
2. `C2-MALICIOUS-HTTP-BEACON` để kiểm Event 1/3, nonce, ProcessGuid, timing, HTTP EVE
   và SID 900001.

Hai pilot phải in `VALID`. Sau khi chụp bằng chứng, loại khỏi dataset train bằng lệnh
`quarantine` với lý do `installation-pilot`; không đổi tên pilot thành run thật. Canary
mục 10.4 đã phủ thêm console 4624/4625, DNS benign/malicious SID 900004/900002,
HTTP benign và staged-transfer. Vì vậy toàn bộ đường thu đã được kiểm trước run thật.

## 11. Quy trình chuẩn cho MỖI run

Thực hiện đúng thứ tự; không gộp hai kịch bản trong một cửa sổ.

### Bước 1 — Chọn run và khai báo ground truth trước

Quy ước ID:

```text
<SCENARIO-ID>-R<01..99>-<YYYYMMDD>
```

Ví dụ trên SOC-AI:

```bash
cd "$HOME/datn-ai-soar"
set -euo pipefail
date -u --iso-8601=seconds
timedatectl show -p NTPSynchronized --value
RUN_DATE=$(date -u +%Y%m%d)
RUN_ID="C2-MALICIOUS-HTTP-BEACON-R01-$RUN_DATE"
CLOCK_FILE="run-drafts/$RUN_ID-clock.yaml"

# Nhập user thật; placeholder bị từ chối.
read -rp 'NET-SENSOR SSH username: ' SENSOR_USER
read -rp 'Kali SSH username: ' KALI_USER
CLOCK_KEY="$HOME/.ssh/id_ed25519_datn_clock"
[[ "$SENSOR_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$KALI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
test "$SENSOR_USER" != sensor-user
test "$KALI_USER" != kali-user

# Các kết nối dùng SSH key/BatchMode, không nhập mật khẩu giữa phép đo.
CONTROLLER_UTC=$(date -u --iso-8601=seconds)
TARGET_UTC=$(ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  datn_clock@192.168.58.148 powershell.exe -NoProfile -NonInteractive -Command \
  "[DateTimeOffset]::UtcNow.ToString('o')" | tr -d '\r')
WAZUH_UTC=$(date -u --iso-8601=seconds)
SENSOR_UTC=$(ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${SENSOR_USER}@192.168.58.150" date -u --iso-8601=seconds)
ATTACKER_UTC=$(ssh -i "$CLOCK_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
  "${KALI_USER}@192.168.58.132" date -u --iso-8601=seconds)
.venv-ml/bin/python -m scripts.build_clock_preflight \
  --controller "$CONTROLLER_UTC" --target "$TARGET_UTC" \
  --wazuh "$WAZUH_UTC" --sensor "$SENSOR_UTC" --attacker "$ATTACKER_UTC" \
  --maximum-skew-seconds 5 --output "$CLOCK_FILE"

.venv-ml/bin/python -m scripts.create_run_draft \
  --scenario C2-MALICIOUS-HTTP-BEACON \
  --run-id "$RUN_ID" \
  --operator Kien \
  --clock-preflight "$CLOCK_FILE"
sed -n '1,120p' "run-drafts/$RUN_ID.yaml"
```

Lệnh `build_clock_preflight` từ chối file có bất kỳ máy nào lệch quá 5 giây và không
ghi đè bằng chứng cũ. Draft đóng băng `collection_seed`, `scenario_parameters`, danh
sách observable và toàn bộ clock evidence. Không sửa các trường này bằng tay.

Không sửa `family` hoặc `label` sau khi chạy. Nếu chọn sai, chưa start thì xóa draft và
tạo lại; đã start thì dùng lệnh `abort`, không tái sử dụng `run_id`.

### Bước 2 — Start collector trước hoạt động

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session start \
  --draft "run-drafts/$RUN_ID.yaml"
.venv-ml/bin/python -m scripts.scenario_session status --run-id "$RUN_ID"
```

Phải thấy `STARTED`. Lệnh này đối chiếu draft với catalog, chụp cursor/snapshot, tạo
`start-contract.json` ràng buộc nguồn runtime + cursor với cấu hình tại thời điểm start,
và tạo khóa toàn cục; một lệnh `start` thứ hai sẽ bị từ chối. Không sửa state, cursor,
snapshot hoặc start contract bằng tay. Chỉ sau đó mới thao tác trên Windows/Kali.

### Bước 3 — Chạy đúng một kịch bản

Đọc entry tương ứng trong `config/scenario-catalog.yaml`. Các câu lệnh C2 chuẩn nằm ở
mục 12. Với account, chỉ thao tác các tài khoản lab đã khai báo. Ghi giờ bắt đầu/kết thúc
và mọi sai lệch vào nhật ký vận hành. Trước khi chạy, xuất tham số đã đóng băng; không
đọc rồi gõ lại từng số bằng trí nhớ:

```bash
set -euo pipefail
mkdir -p evidence/operator-parameter-exports
.venv-ml/bin/python -m scripts.export_run_parameters \
  --project-root . --run-id "$RUN_ID" --format powershell \
  | tee "evidence/operator-parameter-exports/$RUN_ID.ps1"
.venv-ml/bin/python -m scripts.export_run_parameters \
  --project-root . --run-id "$RUN_ID" --format bash \
  | tee "evidence/operator-parameter-exports/$RUN_ID.env"
```

Với C2, copy nguyên output PowerShell vào `WIN11-TARGET`, rồi chạy block khởi tạo ở mục
12.2; URL/DNS nonce và toàn bộ khoảng nghỉ sẽ dùng đúng tham số đó. Với account, source
file Bash trong shell SOC-AI để chờ `DATN_PRE_ACTION_DELAY_SECONDS` trước tín hiệu bắt
đầu thao tác. Riêng `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS`, source cùng file trên Kali để
dùng chính xác `DATN_ATTEMPT_DELAY_SECONDS`. Chuyển file đó từ SOC-AI bằng key đã cấu
hình (thay đúng username Kali):

```bash
set -euo pipefail
read -rp 'Kali SSH username: ' KALI_USER
[[ "$KALI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
test "$KALI_USER" != kali-user
scp -i "$HOME/.ssh/id_ed25519_datn_clock" \
  "evidence/operator-parameter-exports/$RUN_ID.env" \
  "${KALI_USER}@192.168.58.132:/tmp/datn-current-run.env"
ssh -i "$HOME/.ssh/id_ed25519_datn_clock" \
  "${KALI_USER}@192.168.58.132" chmod 600 /tmp/datn-current-run.env
.venv-ml/bin/python -m scripts.scenario_session begin-action \
  --run-id "$RUN_ID" --wait-for-window
```

Hai file export không chứa mật khẩu. Xóa `/tmp/datn-current-run.env` trên Kali khi cleanup.
Trước `begin-action`, phải pre-stage cả hai console: console SOC-AI đã có lệnh trên; console
Windows/Kali đã load file `.ps1`/`.env`, block dùng chung và lệnh scenario ngắn nhưng
**chưa chạy hành động**. Không copy file, paste block dài, sửa lệnh hoặc chờ prompt mới sau
khi receipt được tạo. `--wait-for-window` kiểm tra budget của schedule đóng băng gồm
pre-delay, toàn bộ interval và 10 giây cho thao tác/cleanup. Nó không bắt đầu trước đầu
bucket cộng `clock_preflight.maximum_skew_seconds`; nếu phần còn lại của bucket không đủ, nó chỉ
sleep từng nhịp tối đa 30 giây và chưa tạo receipt. Nếu budget không thể vừa trong bất kỳ
bucket đã guard nào, lệnh fail ngay; không chờ vô hạn. Nếu bỏ `--wait-for-window`,
`begin-action` từ chối ngay khi cửa sổ hiện tại không đủ. Thông báo chờ đi ra stderr;
receipt JSON cuối cùng đi ra stdout. Khi receipt `status=STARTED` trả về, đọc
`action_started_at` và `action_deadline`, rồi chạy ngay lệnh đã pre-stage ở console thao tác.
`action_deadline` là cuối bucket UTC trừ clock-skew guard. `begin-action` tạo receipt bắt
buộc, gắn hành động với SHA-256 của tham số đóng băng; không chạy lần hai và không dùng
file export của run khác.

`pre_action_delay_seconds`, dải jitter và cách sinh nonce giống nhau giữa benign và
malicious. Không thay tham số theo cảm tính, không sử dụng giá trị của run trước và không
thay kích thước hai payload cố định; SHA-256 của payload là cổng an toàn bắt buộc.

### Bước 4 — Đóng receipt rồi chờ pipeline chuyển log

Ngay khi hoạt động và cleanup kết thúc, phải chạy `complete-action` **trước**
`action_deadline`, rồi chờ 90 giây; không tạo traffic khác tới destination của kịch bản:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id "$RUN_ID"
sleep 90
```

Nếu quá deadline hoặc `complete-action` từ chối vì đã ra ngoài aggregation window, chạy
`abort`, cleanup và tạo run ID mới. Không sửa `action_deadline`, timestamp hoặc receipt để
hợp thức hóa run. `finalize` cũng từ chối nếu timestamp nguồn thô của bất kỳ record đã chọn
nằm ngoài đúng bucket UTC ghi trong receipt; clock-skew tolerance không cho phép kéo record
từ bucket liền kề vào run.

Kiểm tra nhanh Archives có byte mới, không sửa file:

```bash
set -euo pipefail
sudo tail -n 20 /var/ossec/logs/archives/archives.json | jq -c \
  'select(.agent.name=="WIN11-TARGET" or .agent.name=="NET-SENSOR")'
```

### Bước 5 — Finalize fail-closed

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID"
```

Collector chỉ nhận log trong cửa sổ receipt (cộng dung sai clock đã khai báo), đúng
agent và đúng account/process/IP/port/DNS. C2 còn bắt buộc nonce trong command/URI/DNS,
ProcessGuid thống nhất, tương quan thời gian Sysmon–Suricata, đúng số hành động và nhịp
đã đóng băng. Thiếu một nguồn hoặc receipt thì finalize lỗi và không tạo mẫu cuối.

Nếu lỗi chỉ cho biết log đang đến chậm (`no Wazuh Archive bytes`, dòng JSON chưa hoàn
chỉnh, hoặc chưa thấy nguồn dự kiến), giữ nguyên run ở trạng thái `STARTED`, không tạo
thêm traffic và không bắt đầu run khác. Chờ 30 giây rồi **retry finalize** cùng `RUN_ID`;
có thể lặp tối đa ba lần, tức tối đa 180 giây tính từ lúc kết thúc hoạt động. Nếu vẫn
không đạt, dùng `abort`, sửa pipeline và thu lại với ID mới. Các lỗi attribution sai,
checksum, rotate/truncate hoặc quality gate sai không được retry để hợp thức hóa dữ liệu.

### Bước 6 — Validate run

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
find "data/raw/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
find "evidence/scenario-runs/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
```

Phải thấy `VALID`; `data/raw/$RUN_ID` có `scenario_manifest.json` và `incidents.jsonl`;
evidence có Archives, Windows events, Suricata EVE, metadata và SHA-256. Không chỉnh
tay file đã finalize. Nếu validate sai, bảo toàn dữ liệu hỏng để điều tra rồi đưa cả cặp
raw/evidence ra khỏi dataset bằng lệnh duy nhất:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session quarantine \
  --run-id "$RUN_ID" --reason "ghi ro loi validate"
```

Phải thấy `QUARANTINED`, hai thư mục nguồn không còn và dữ liệu được giữ trong
`data/quarantine/$RUN_ID` cùng `evidence/quarantine/$RUN_ID`. Sau đó mới chạy lại với ID
mới. Không xóa một phía và không tự sửa checksum.

### Bước 7 — Audit toàn dataset

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.audit_dataset \
  --raw-dir data/raw \
  --evidence-dir evidence/scenario-runs \
  --scenario-catalog config/scenario-catalog.yaml \
  --minimum-runs 10 \
  --target-runs 12 \
  --output evidence/dataset-audit.json
```

Trước khi đủ 10 mỗi nhóm, exit `1` và `NOT_READY` là đúng; báo cáo phải cho biết chính
xác thiếu nhóm nào. Không được nối `|| true` hoặc chạy tiếp sau exit `1`. Không được bỏ
qua `RUN_INVALID`, `RUN_STATE_INVALID`, `SCENARIO_CATALOG_MISMATCH`,
`SURICATA_MISSING`, duplicate, checksum, thiếu/sai năm scenario, phân bố lệch hoặc hơn
12 run/nhóm.

### Bước 8 — Cleanup và khoảng nghỉ

Thực hiện cleanup trong catalog, chờ ít nhất 60 giây, kiểm tra không còn PID của chính
vòng lặp đã chạy và xóa file tạm. Collector tự chặn hai run đồng thời; nếu báo active lock,
phải finalize/abort/quarantine run đang sở hữu khóa. Không xóa file lock bằng tay và không
tái dùng `run_id`.

Nếu thao tác sai giữa run:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session abort \
  --run-id "$RUN_ID" --reason "ghi ro ly do"
```

Sau đó cleanup, chờ pipeline yên, tạo run mới với ID mới.

## 12. Thực thi scenario trên Windows

### 12.1 Account scenarios

Chạy tại màn hình console của `WIN11-TARGET`, không qua tài khoản thật và chỉ sau khi
collector đã `STARTED`. Trước từng run account, PowerShell Administrator phải xác nhận
policy lab chưa lockout và mở khóa các tài khoản dùng riêng cho lab:

```powershell
net accounts
$labAccountNames = @(
  'datn_benign','datn_attack','datn_spray01','datn_spray02','datn_spray03'
)
$labAccountNames | ForEach-Object {
  $name = $_
  $user = [ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $name)
  $user.IsAccountLocked = $false
  $user.SetInfo()
}
$labAccounts = @(
  Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object {
    $_.Name -in $labAccountNames
  }
)
$labAccounts | Select-Object Name,Disabled,Lockout
if ($labAccounts.Count -ne $labAccountNames.Count) {
  throw 'One or more DATN lab accounts do not exist on WIN11-TARGET'
}
$invalidAccounts = @(
  $labAccounts | Where-Object { $_.Disabled -or $_.Lockout }
)
if ($invalidAccounts) {
  $invalidAccounts | Select-Object Name,Disabled,Lockout
  throw 'A DATN lab account is disabled or still locked'
}
```

Block dùng thuộc tính `IADsUser.IsAccountLocked` của WinNT ADSI để mở khóa, rồi dùng
`Win32_UserAccount` qua CIM để xác nhận. Mọi dòng phải có `Disabled=False`,
`Lockout=False`. Nếu khác, dừng và sửa trước `start`; không mở khóa giữa cửa sổ run vì
sẽ tạo thêm event. Sau khi collector báo `STARTED`, trên
SOC-AI chờ đúng pre-action delay rồi mới ra tín hiệu cho người thao tác Windows/Kali:

```bash
set -euo pipefail
set -a
# File do export_run_parameters tạo ở Bước 3; không dùng file của run khác.
source "evidence/operator-parameter-exports/$RUN_ID.env"
set +a
test "$DATN_RUN_ID" = "$RUN_ID"
sleep "$DATN_PRE_ACTION_DELAY_SECONDS"
echo 'ACCOUNT_ACTION_MAY_START'
```

Collector dùng `LogonType=2` (interactive) cho chín scenario console/`runas`. **Ngoại lệ
duy nhất** là `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS`: catalog khóa `LogonType=3` và bắt
buộc hai lần SMB từ cùng Kali `10.40.0.10`. Logon nền kiểu network/service khác bị loại
để một hoạt động không bị đếm thành nhiều lần. Không tự đổi console thành SMB hoặc đổi
SMB thành console, WinRM, RDP hay scheduled task.

| Scenario | Thao tác chính xác |
|---|---|
| `ACCOUNT-BENIGN-NORMAL-LOGON` | đăng xuất, đăng nhập `datn_benign` đúng một lần bằng mật khẩu đúng |
| `ACCOUNT-BENIGN-TYPO-THEN-SUCCESS` | nhập sai đúng 1 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS` | nhập sai đúng 2 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-BENIGN-RUNAS` | tại CMD chạy `runas /user:.\datn_benign "cmd /c whoami"`, nhập đúng mật khẩu một lần |
| `ACCOUNT-BENIGN-THREE-TYPOS-THEN-SUCCESS` | nhập sai đúng 3 lần, sau đó nhập đúng 1 lần |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-3` | nhập sai đúng 3 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-6` | nhập sai đúng 6 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-REPEATED-FAILURES-10` | nhập sai đúng 10 lần cho `datn_attack`, không đăng nhập đúng |
| `ACCOUNT-MALICIOUS-PASSWORD-SPRAY` | nhập sai đúng 1 lần lần lượt cho `datn_spray01`, `02`, `03`, sau đó đăng nhập đúng đúng 1 lần vào `datn_spray03`; thứ tự này tạo mẫu spray có một credential compromise nhưng vẫn chồng lấp hợp lệ với benign ở các feature success/logon type |
| `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS` | trên Kali chạy đúng block SMB bên dưới: sai 1 lần, chờ delay trong draft, đúng 1 lần từ cùng nguồn; đây là mẫu low-noise nhưng có ngữ cảnh network-logon phân biệt được |

Không tạo thêm lần thử ngoài bảng trong cùng cửa sổ. Kết thúc run benign/malicious có
success thì sign out; run chỉ có failure thì quay lại desktop quản trị mà không đăng nhập
đúng tài khoản decoy. Sau 90 giây mới finalize; quality gate sẽ đối chiếu chính xác số
4624/4625 và thứ tự failure → success.

Chỉ với `ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS`, trên Kali chạy block sau. Người vận hành
nhập một mật khẩu **cố ý sai** ở prompt đầu và mật khẩu lab đúng ở prompt thứ hai. Lệnh
không lưu mật khẩu vào history, process list hoặc file:

```bash
set -euo pipefail
set -a
source /tmp/datn-current-run.env
set +a
test "$DATN_SCENARIO_ID" = ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS
if smbclient '//10.20.0.10/IPC$' -U 'WIN11-TARGET\datn_attack' -c 'quit'; then
  echo 'FAIL: first SMB authentication unexpectedly succeeded' >&2
  exit 1
else
  echo 'EXPECTED_FIRST_AUTH_FAILURE'
fi
sleep "$DATN_ATTEMPT_DELAY_SECONDS"
smbclient '//10.20.0.10/IPC$' -U 'WIN11-TARGET\datn_attack' -c 'quit'
echo 'EXPECTED_SECOND_AUTH_SUCCESS'
rm -f /tmp/datn-current-run.env
```

Nếu prompt đầu nhập nhầm mật khẩu đúng, prompt thứ hai nhập sai, SMB không truy cập được,
hoặc có thêm attempt, lập tức `abort` run; không sửa manifest để hợp thức hóa.

### 12.2 C2 scenarios

Chạy PowerShell thường trong `WIN11-TARGET`; chỉ chạy sau `start`. Trước mỗi run, copy
nguyên output `.ps1` đã tạo ở Bước 3 vào cửa sổ này, rồi chạy block dùng chung dưới đây.
Block sẽ từ chối thiếu tham số, sai hướng jitter hoặc giá trị ngoài dải:

```powershell
$ErrorActionPreference = 'Stop'
if (-not $DatnRunId -or -not $DatnScenarioId -or -not $DatnParameters -or
    $DatnParametersSha256 -notmatch '^[0-9a-f]{64}$') {
  throw 'Paste the current run parameter export first'
}
foreach ($key in 'pre_action_delay_seconds','interval_jitter_percent',
  'interval_jitter_direction','variant_index','run_nonce',
  'expected_action_count','expected_intervals_seconds') {
  if (-not $DatnParameters.ContainsKey($key)) { throw "Missing run parameter: $key" }
}
if ($DatnParameters.interval_jitter_percent -lt 10 -or
    $DatnParameters.interval_jitter_percent -gt 30 -or
    $DatnParameters.interval_jitter_direction -notin -1,1) {
  throw 'Invalid frozen jitter parameters'
}
function Get-DatnGap([double]$BaseSeconds) {
  $factor = 1.0 + ($DatnParameters.interval_jitter_direction *
    $DatnParameters.interval_jitter_percent / 100.0)
  return [Math]::Max(1, [int][Math]::Round($BaseSeconds * $factor))
}
function Start-DatnScenario([string]$ExpectedScenario) {
  if ($DatnScenarioId -ne $ExpectedScenario) {
    throw "Draft is $DatnScenarioId, command is $ExpectedScenario"
  }
  Start-Sleep -Milliseconds ([int][Math]::Round(
    1000 * $DatnParameters.pre_action_delay_seconds))
  $script:DatnOperatorPid = $PID
}
function Start-DatnDnsScenario(
  [string]$ExpectedScenario,
  [ValidateSet('www.datn.test','beacon.datn.test')][string]$DomainSuffix
) {
  $dnsScript = 'C:\DATN\run_dns_scenario.ps1'
  $powershellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path -LiteralPath $dnsScript -PathType Leaf)) {
    throw "Missing pinned DNS runner: $dnsScript"
  }
  $expectedHash = (Get-Content -LiteralPath "$dnsScript.sha256.txt" -Raw).Trim()
  if ($expectedHash -notmatch '^[0-9a-f]{64}$' -or
      (Get-FileHash -LiteralPath $dnsScript -Algorithm SHA256).Hash.ToLower() -ne $expectedHash) {
    throw 'DNS runner changed after installation; restore the pinned copy before collection'
  }
  Start-DatnScenario $ExpectedScenario
  $arguments = @(
    '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',$dnsScript,
    '-RunNonce',[string]$DatnParameters.run_nonce,
    '-DomainSuffix',$DomainSuffix,
    '-Count',[string]$DatnParameters.expected_action_count,
    '-GapsCsv',[string]$DatnParameters.expected_intervals_seconds,
    '-VariantIndex',[string]$DatnParameters.variant_index,
    '-DnsServer','10.40.0.10'
  )
  $process = Start-Process -FilePath $powershellExe -ArgumentList $arguments `
    -NoNewWindow -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "DNS runner failed with exit code $($process.ExitCode)"
  }
}
```

Không sửa hàm để tạo timing theo nhãn. `run_nonce` và `variant_index` phải xuất hiện
trong URL hoặc DNS name. Collector đối chiếu nonce, số hành động và khoảng nghỉ với
contract đã đóng băng; tự gõ một giá trị khác sẽ làm run bị từ chối. Hai scenario DNS
phải chạy `run_dns_scenario.ps1` trong đúng một child `powershell.exe`: Sysmon Event 1
nhờ đó chứa nonce, domain, count và interval CSV trên command line, còn Event 22 mang
cùng ProcessGuid. Không chạy `Resolve-DnsName` trực tiếp trong PowerShell operator.
Giữ đúng policy `RemoteSigned` riêng cho child như block trên; không dùng policy Bypass
hoặc Unrestricted và không chạy `Set-ExecutionPolicy`. Nếu policy chặn file đã pin thì
abort run và xử lý trust/signing ngoài cửa sổ thu thập, không tiếp tục để lấy mẫu thiếu DNS.

### C2-BENIGN-HEALTH-POLL

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-BENIGN-HEALTH-POLL'
$gap = Get-DatnGap 30
1..8 | ForEach-Object {
  $uri = "http://10.40.0.10:8081/beacon?mode=health&run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$_"
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw 'health request failed' }
  if ($_ -lt 8) { Start-Sleep -Seconds $gap }
}
```

### C2-BENIGN-SINGLE-DOWNLOAD

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-BENIGN-SINGLE-DOWNLOAD'
$uri = "http://10.40.0.10:8080/payload-benign.txt?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)"
curl.exe --fail --silent --show-error $uri `
  -o $env:TEMP\payload-benign.txt
if ($LASTEXITCODE -ne 0) { throw 'benign download failed' }
$hash = (Get-FileHash $env:TEMP\payload-benign.txt -Algorithm SHA256).Hash.ToLower()
if ($hash -ne 'd3aad3cdd62be01b41e8004813eb7fb60c78590cfa520764f783f581f951c2e3') {
  throw "Unexpected benign payload hash: $hash"
}
```

### C2-BENIGN-IRREGULAR-API

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-BENIGN-IRREGULAR-API'
$gaps = @(10,35,20) | ForEach-Object { Get-DatnGap $_ }
for ($i=0; $i -lt 4; $i++) {
  $uri = "http://10.40.0.10:8080/api/status?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$i"
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw 'API request failed' }
  if ($i -lt 3) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-BENIGN-DNS

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnDnsScenario -ExpectedScenario 'C2-BENIGN-DNS' `
  -DomainSuffix 'www.datn.test'
```

### C2-BENIGN-API-BURST

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-BENIGN-API-BURST'
$gap = Get-DatnGap 2
1..6 | ForEach-Object {
  $uri = "http://10.40.0.10:8080/api/status?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$_"
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw 'API burst request failed' }
  if ($_ -lt 6) { Start-Sleep -Seconds $gap }
}
```

### C2-MALICIOUS-HTTP-BEACON

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-MALICIOUS-HTTP-BEACON'
$gap = Get-DatnGap 15
1..8 | ForEach-Object {
  curl.exe --fail --silent --show-error --output NUL `
    "http://10.40.0.10:8081/beacon?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$_"
  if ($LASTEXITCODE -ne 0) { throw 'beacon request failed' }
  if ($_ -lt 8) { Start-Sleep -Seconds $gap }
}
```

### C2-MALICIOUS-JITTER-BEACON

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-MALICIOUS-JITTER-BEACON'
$gaps = @(8,21,13,30,11,24,17) | ForEach-Object { Get-DatnGap $_ }
for ($i=0; $i -lt 8; $i++) {
  curl.exe --fail --silent --show-error --output NUL `
    "http://10.40.0.10:8081/beacon?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$i"
  if ($LASTEXITCODE -ne 0) { throw 'jitter beacon request failed' }
  if ($i -lt 7) { Start-Sleep -Seconds $gaps[$i] }
}
```

### C2-MALICIOUS-DNS-BEACON

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnDnsScenario -ExpectedScenario 'C2-MALICIOUS-DNS-BEACON' `
  -DomainSuffix 'beacon.datn.test'
```

### C2-MALICIOUS-STAGED-TRANSFER

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-MALICIOUS-STAGED-TRANSFER'
$expectedStageHash = 'de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31'
$uri = "http://10.40.0.10:9001/stage.bin?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)"
curl.exe --fail --silent --show-error $uri `
  -o $env:TEMP\stage.bin
if ($LASTEXITCODE -ne 0) { throw 'staged transfer failed' }
$hash = (Get-FileHash $env:TEMP\stage.bin -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $expectedStageHash) { throw "Unexpected stage hash: $hash" }
```

### C2-MALICIOUS-STAGED-TRANSFER-RETRY

```powershell
$ErrorActionPreference = 'Stop'
Start-DatnScenario 'C2-MALICIOUS-STAGED-TRANSFER-RETRY'
$expectedStageHash = 'de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31'
$gap = Get-DatnGap 20
1..3 | ForEach-Object {
  $out = Join-Path $env:TEMP ("stage-{0:D2}.bin" -f $_)
  $uri = "http://10.40.0.10:9001/stage.bin?run=$($DatnParameters.run_nonce)&v=$($DatnParameters.variant_index)&n=$_"
  curl.exe --fail --silent --show-error $uri -o $out
  if ($LASTEXITCODE -ne 0) { throw "staged retry $_ failed" }
  $hash = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $expectedStageHash) { throw "Unexpected stage hash: $hash" }
  if ($_ -lt 3) { Start-Sleep -Seconds $gap }
}
Get-FileHash $env:TEMP\stage-*.bin -Algorithm SHA256
```

Cleanup:

```powershell
$children = Get-CimInstance Win32_Process | Where-Object {
  $_.ParentProcessId -eq $DatnOperatorPid -and
    $_.Name -in 'curl.exe','powershell.exe'
}
if ($children) {
  $children | Select-Object ProcessId,Name,CommandLine
  throw 'A child from this scenario is still running; abort this run'
}
Remove-Item $env:TEMP\payload-benign.txt -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\stage.bin -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\stage-*.bin -ErrorAction SilentlyContinue
Clear-DnsClientCache
Remove-Variable DatnRunId,DatnScenarioId,DatnParameters,DatnParametersSha256 `
  -ErrorAction SilentlyContinue
```

Chỉ hoàn tất `complete-action` sau khi block cleanup không báo lỗi. Không kết luận bằng
danh sách process toàn máy vì có thể nhầm PowerShell của người vận hành khác.

Đây là mô phỏng traffic an toàn trong lab, không tạo reverse shell, persistence, mã độc
hoặc kết nối ra Internet.

## 13. Lịch 10–12 run mỗi nhóm

Catalog có đúng năm scenario cho mỗi nhóm. Ở mốc tối thiểu 10, chạy mỗi scenario hai
lần: phân bố `2-2-2-2-2`. Ở mốc 11, chọn một scenario để chạy thêm một lần:
`3-2-2-2-2`. Ở mốc mục tiêu 12, chọn một scenario **khác** chạy thêm một lần:
`3-3-2-2-2`. Tổng toàn bộ có thể là 40–47 run ở trạng thái READY; chỉ đủ đúng 48 run,
12 cho từng nhóm, mới là TARGET_MET.

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
set -euo pipefail
REQUIRE_TARGET=1 ./scripts/verify_collection_dataset.sh
```

Phải báo `TARGET_MET`, 48 valid run, 0 invalid. Sau đó mới build:

Collector lưu `suspicious_process` như một tín hiệu hành vi, nhưng không được
gán nó trực tiếp từ nhãn scenario. Giá trị phải được suy ra từ telemetry Sysmon
và taxonomy đã đóng băng. Auditor từ chối feature đơn hoặc cặp feature
low-cardinality phân tách hoàn hảo nhãn trong cùng family; nếu cổng này
thất bại thì phải sửa kịch bản/thu lại dữ liệu, không được bỏ qua.

```bash
set -euo pipefail
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml
jq '{dataset_hash_sha256,feature_schema_version,group_key,locked_test_status,
  partition_counts,record_counts,stratum_run_counts,collection_audit,
  split_assignment_commitment_sha256}' data/processed/dataset_manifest.json
jq -e '.collection_audit.status == "READY" or
  .collection_audit.status == "TARGET_MET"' data/processed/dataset_manifest.json >/dev/null
test -z "$(jq -r 'keys[]' data/processed/dataset_manifest.json \
  | grep '^fold_by_run$' || true)"
wc -l data/processed/train.jsonl data/processed/validation.jsonl
grep -n 'locked_test_status' data/processed/dataset_manifest.json
```

Không mở hoặc upload nội dung `data/processed/locked_test.jsonl` hoặc `ml/splits/test.txt`
để xem kết quả trước Week 6. Tạo checksum ngay trên SOC-AI:

```bash
set -euo pipefail
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
set -euo pipefail
cd "$HOME/datn-ai-soar"
mkdir -p data/raw evidence/scenario-runs run-drafts operator-logs
LOCK=evidence/scenario-runs/.active-run.json
if ! (set -o noclobber; printf '{"run_id":"BACKUP"}\n' > "$LOCK") 2>/dev/null; then
  echo 'FAIL: a collection run or another backup holds the active lock' >&2
  exit 1
fi
cleanup_backup_lock() { rm -f -- "$LOCK"; }
trap cleanup_backup_lock EXIT HUP INT TERM
while IFS= read -r -d '' STATE; do
  jq -e . "$STATE" >/dev/null
  STATUS=$(jq -r '.status' "$STATE")
  if [ "$STATUS" = STARTED ]; then
    echo "FAIL: active state in $STATE" >&2
    exit 1
  fi
done < <(find evidence/scenario-runs -mindepth 2 -name .collection_state.json -print0)

BACKUP_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
ARCHIVE="$BACKUP_DIR/collection-$BACKUP_ID.tar.gz"
mkdir -p "$BACKUP_DIR"
git rev-parse HEAD > "$BACKUP_DIR/git-commit.txt"
git bundle create "$BACKUP_DIR/source.bundle" --all
git bundle verify "$BACKUP_DIR/source.bundle"
RAW_COUNT=$(find data/raw -mindepth 2 -maxdepth 2 -name scenario_manifest.json | wc -l)
tar --create --gzip --file "$ARCHIVE" \
  --exclude='evidence/scenario-runs/.active-run.json' \
  --exclude='evidence/operator-parameter-exports' \
  --exclude='*.env' --exclude='*.ps1' \
  data/raw evidence run-drafts \
  config/scenario-catalog.yaml config/collection-sources.yaml \
  config/suspicious-process-taxonomy.yaml ml/feature_schema.json
(
  cd "$BACKUP_DIR"
  sha256sum "$(basename "$ARCHIVE")" git-commit.txt source.bundle > checksums.sha256
  sha256sum --check checksums.sha256
)
tar -tzf "$ARCHIVE" > "$BACKUP_DIR/archive.list"
grep -q '^data/raw/' "$BACKUP_DIR/archive.list"
grep -q '^evidence/scenario-runs/' "$BACKUP_DIR/archive.list"
! grep -Eq '(^|/)([^/]*\.env|[^/]*\.ps1)$' "$BACKUP_DIR/archive.list"
ARCHIVE_RUNS=$(grep -c '/scenario_manifest.json$' "$BACKUP_DIR/archive.list")
test "$ARCHIVE_RUNS" -eq "$RAW_COUNT"
cleanup_backup_lock
trap - EXIT HUP INT TERM
printf 'BACKUP_ID=%s\n' "$BACKUP_ID"
```

Kiểm tra giải nén vào thư mục tạm, tuyệt đối không đè lên repo đang thu:

```bash
set -euo pipefail
read -rp 'BACKUP_ID cần kiểm tra: ' BACKUP_ID
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
ARCHIVE="$BACKUP_DIR/collection-$BACKUP_ID.tar.gz"
test -f "$ARCHIVE"
test -f "$BACKUP_DIR/archive.list"
(cd "$BACKUP_DIR" && sha256sum --check checksums.sha256)
RAW_COUNT=$(grep -c '/scenario_manifest.json$' "$BACKUP_DIR/archive.list")
RESTORE_CHECK=$(mktemp -d)
trap 'rm -rf -- "$RESTORE_CHECK"' EXIT
tar -xzf "$ARCHIVE" -C "$RESTORE_CHECK"
test -d "$RESTORE_CHECK/data/raw"
test -d "$RESTORE_CHECK/evidence/scenario-runs"
RESTORED_RUNS=$(find "$RESTORE_CHECK/data/raw" -name scenario_manifest.json | wc -l)
test "$RESTORED_RUNS" -eq "$RAW_COUNT"
while IFS= read -r -d '' CHECKSUM; do
  (cd "$(dirname "$CHECKSUM")" && sha256sum --check checksums.sha256)
done < <(find "$RESTORE_CHECK/evidence/scenario-runs" -name checksums.sha256 -print0)
echo 'RESTORE_DRY_RUN=PASS'
```

Khôi phục thật vào checkout mới, không đè repo đang thu:

```bash
set -euo pipefail
read -rp 'BACKUP_ID cần khôi phục: ' BACKUP_ID
BACKUP_DIR="$HOME/datn-backups/$BACKUP_ID"
ARCHIVE="$BACKUP_DIR/collection-$BACKUP_ID.tar.gz"
test -f "$ARCHIVE"
test -f "$BACKUP_DIR/git-commit.txt"
test -f "$BACKUP_DIR/source.bundle"
RESTORE_ROOT="$HOME/datn-ai-soar-restored-$BACKUP_ID"
test ! -e "$RESTORE_ROOT"
COMMIT=$(cat "$BACKUP_DIR/git-commit.txt")
git clone "$BACKUP_DIR/source.bundle" "$RESTORE_ROOT"
git -C "$RESTORE_ROOT" checkout --detach "$COMMIT"
tar -xzf "$ARCHIVE" -C "$RESTORE_ROOT"
cd "$RESTORE_ROOT"
./scripts/bootstrap_ml.sh
for RUN_PATH in data/raw/*; do
  test -d "$RUN_PATH" || continue
  .venv-ml/bin/python -m scripts.scenario_session validate \
    --run-id "$(basename "$RUN_PATH")"
done
echo 'RESTORE_VALIDATION=PASS'
```

Với backup giữa buổi chưa đủ 40 run, audit toàn dataset có thể vẫn `NOT_READY`; điều đó
không làm restore sai. Điều kiện restore là tất cả run hiện có `VALID`, checksum đúng và
số manifest bằng bản gốc.

Ngay sau đó sao chép cả thư mục backup ra ổ host Windows; nhập đúng `BACKUP_ID` vừa
in ra. Bản nằm cùng datastore VMware không được tính là bản sao thứ hai:

```powershell
$ErrorActionPreference = 'Stop'
$SocUser = Read-Host "SOC-AI SSH username"
$BackupId = Read-Host "BACKUP_ID from SOC-AI"
$BackupRoot = "D:\SOC_AI_SOAR_backups"
$SocHome = ssh "${SocUser}@192.168.58.147" 'printf %s "$HOME"'
if ($LASTEXITCODE -ne 0 -or -not $SocHome) { throw "Cannot resolve SOC-AI HOME" }
New-Item -ItemType Directory -Force $BackupRoot | Out-Null
if (Test-Path "$BackupRoot\$BackupId") { throw 'Backup destination already exists' }
scp -r "${SocUser}@192.168.58.147:${SocHome}/datn-backups/${BackupId}" $BackupRoot
if ($LASTEXITCODE -ne 0) { throw 'SCP backup failed' }
$LocalBackup = "$BackupRoot\$BackupId"
foreach ($line in Get-Content "$LocalBackup\checksums.sha256") {
  if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Bad checksum line: $line" }
  $expected = $Matches[1]
  $file = Join-Path $LocalBackup $Matches[2]
  $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected) { throw "Checksum mismatch: $file" }
}
tar -tzf (Get-ChildItem "$LocalBackup\collection-*.tar.gz").FullName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Copied archive is unreadable' }
'HOST_BACKUP_VERIFY=PASS'
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
| `no attributable Suricata...` | traffic đi tắt, sai `src_ip`, rule/interface hoặc EVE chưa forward | không retry bằng traffic mới trong cùng run; abort, sửa route/rule/ACL, chạy pilot mới |
| checksum/`RUN_STATE_INVALID` | file bị sửa hoặc finalize bị gián đoạn | dùng `quarantine`, không sửa checksum/state để hợp thức hóa; thu ID mới |
| `active run...` | còn run STARTED hoặc backup đang giữ khóa | đọc owner, finalize/abort/quarantine đúng run; không xóa `.active-run.json` bằng tay |
| `execution receipt...` | chưa `begin-action`/`complete-action`, receipt bị sửa hoặc dùng export sai run | abort nếu hành động chưa hoàn tất; không tự sửa state/receipt; tạo run ID mới nếu đã thao tác sai |
| `frozen action count`/`interval contract` | chạy thừa/thiếu request hoặc sai khoảng nghỉ | abort và thu run mới; không thêm traffic khi run đã kết thúc |
| `collection contract` | catalog/schema/taxonomy/source config khác snapshot lúc start | quarantine run, đồng bộ đúng commit, chạy lại pilot rồi thu ID mới |
| `SCENARIO_CATALOG_MISMATCH` | draft/manifest không thuộc catalog hoặc sai family/label | quarantine run, cập nhật repo đúng commit, tạo draft mới từ CLI |
| `SCENARIO_IMBALANCE`/`STRATUM_EXCESS` | năm scenario lệch nhau quá 1 run hoặc nhóm đã quá 12 | không copy/xóa tùy tiện; dừng thu, bàn giao audit để người phụ trách quyết định dataset version mới |
| duplicate incident/run | tái sử dụng dữ liệu hoặc ID | quarantine bản trùng và chạy mới |
| `FEATURE_LABEL_SEPARATION`/`JOINT_FEATURE_LABEL_SEPARATION` | feature đơn/cặp feature phân tách hoàn hảo nhãn | bổ sung/chỉnh catalog có hành vi chồng lấn rồi thu dataset version mới; không train trước khi audit đạt |
| audit `NOT_READY` | thiếu hoặc có run invalid | đọc `ISSUES` và `shortage`, xử lý đúng nhóm |

Không dùng lệnh sửa trực tiếp `incidents.jsonl`, `scenario_manifest.json` hoặc
`checksums.sha256`. Dữ liệu hỏng phải được quarantine và thu lại.

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
- [ ] đúng 5 scenario/nhóm; số run của hai scenario bất kỳ trong cùng nhóm lệch tối đa 1
  (`2-2-2-2-2`, `3-2-2-2-2` hoặc `3-3-2-2-2`).
- [ ] auditor báo 0 invalid; build dataset thành công.
- [ ] dataset manifest ghi `group_key=scenario_id`, collection audit `READY`/`TARGET_MET`,
  locked test `UNOPENED` và không chứa `fold_by_run`.
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

Atomic Red Team chỉ là hướng mở rộng sau khi dataset v1 đã được đóng và bàn giao; không
phải điều kiện để hoàn thành 48 run trong catalog.
