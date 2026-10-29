# HƯỚNG DẪN BÀN GIAO KIÊN — LAB 4 VM VÀ THU DỮ LIỆU V3

Phiên bản tài liệu: 3.1 — ngày 29/10/2026.
Máy thực hiện: máy của Kiên có VMware; các thao tác bên dưới không yêu cầu Thịnh
truy cập trực tiếp vào máy đó. Người thực hiện ghi kết quả thật, không đánh dấu đạt sẵn.

TRẠNG THÁI BÀN GIAO HIỆN TẠI

- Có thể dùng tài liệu để dựng/kiểm lại 4 VM, cấu hình telemetry, enrollment context,
  chạy pilot bằng collector v3, kiểm tra, sao lưu và gửi evidence cho Thịnh.
- Chưa mở đợt thu 40–48 mẫu train chính thức. Catalog đối chứng/cohort/taxonomy và
  challenge G01–G07 đang hoàn thiện; nhánh triển khai chưa được chốt thành baseline
  thu train. Cổng G7 dưới đây chủ động dừng nếu các điều kiện đó chưa đạt.
- Không lấy pilot, smoke test, dữ liệu cũ hoặc JSON viết tay để bù quota. Khi Thịnh
  gửi baseline thu chính thức đã kiểm, Kiên mới thực hiện phần thu chính thức.
- 10–12 run/nhóm là quota thu ban đầu, không bảo đảm accuracy hoặc đủ điều kiện
  phản ứng tự động. Model/policy thiếu bằng chứng phải REVIEW; hệ thống giữ SHADOW.

Nguồn pilot đã rà soát: nhánh `fix/handoff-context-v3` của
https://github.com/lethinhlord/Repo.
Dùng bản Kiên.txt 3.1 này làm hướng dẫn thao tác. Hướng dẫn có revision tài liệu riêng;
checkout mã pilot có thể chứa bản runbook lịch sử, không dùng bản lịch sử đó để thực hiện.
`REVIEWED_SOURCE_COMMIT` được ghi bằng SHA đầy đủ ở mục 6.2. Đây là revision pilot,
không phải tag/commit baseline thu train. Không dùng lại tag `data-collection-v2.0.0`
hoặc tự chọn commit theo tên nhánh.

## 0. Cách thực hiện và trách nhiệm

1. Kiên: dựng/kiểm 4 VM, mạng, giờ, dịch vụ, capture thật, pilot, backup/restore,
   ảnh và nhật ký. Nếu hệ thống đã cài đúng, kiểm tra các mục tương ứng trước khi thay đổi.
2. Thịnh: chốt code/schema/catalog/cohort/context contract, xử lý sai lệch pilot,
   phát hành baseline thu chính thức; audit/build/Colab và đánh giá model.
3. Từng khối lệnh có tên máy ngay trước khối. Không chạy lệnh Windows trên Ubuntu,
   hoặc lệnh NET-SENSOR trên SOC-AI. Dùng console VMware khi đổi mạng.
4. Bash: mở `bash`, dùng `set -euo pipefail` cho phiên thao tác. PowerShell: mở
   Windows PowerShell 64-bit, dùng Administrator ở các mục cài đặt/cấu hình.
5. Giữ console SOC-AI và console hành động đang mở xuyên suốt một run. Nếu mất phiên,
   dùng `scenario_session status` xác định trạng thái rồi phục hồi đúng RUN_ID;
   không tạo run khác hoặc đoán lại tham số.
6. Mỗi bước có điều kiện đạt. Sai điều kiện thì giữ log/evidence, dừng bước phụ thuộc,
   sửa nguyên nhân rồi chạy lại phép kiểm. Không sửa timestamp, nhãn, nonce, hash,
   receipt hoặc giảm gate để hợp thức hóa một run.
7. Dùng checkout mới `~/datn-ai-soar-v3`, tách khỏi repo/dataset cũ. Dữ liệu cũ có thể
   giữ ở nơi lưu trữ riêng để tham khảo, không nhập vào checkout này.

Chỉ cần 4 VM cho phạm vi này: Windows 11 là endpoint; SOC-AI gộp Wazuh và collector;
NET-SENSOR gộp router và Suricata; Kali phát hoạt động mô phỏng. Không dựng Domain
Controller trong đợt này. Các account scenario hiện dùng local account trên Windows 11.

Thứ tự thao tác: đọc mục 0–3 để hiểu contract; thực hiện 4–9 để cài/kiểm; quay lại
bảng chuyển đổi 1.1; làm 10.1–10.5; theo mục 11–12 chạy bốn pilot 10.6; làm backup
15 và bàn giao 18.1. Mục 10.7/13/14/18.2 chỉ dùng sau khi G7 được mở.

Sản phẩm Kiên gửi sau pilot: source SHA, cấu hình/phiên bản thực tế, baseline + capture,
raw/evidence của các pilot, báo cáo progress, backup đã restore kiểm tra và ảnh nguyên
màn hình. Mục 15/18 quy định chi tiết. Không chỉ gửi ảnh hoặc một file CSV đã tách log.


## 1. Kết quả bắt buộc

Mỗi lần thực thi mới là **một run/đơn vị thu**; các run cùng cohort vẫn có thể tương quan. Mỗi run có một `run_id`, một nhãn được khai báo
trước khi chạy, bằng chứng gốc và checksum. Không coi từng dòng log là một mẫu.

Mỗi code block Bash là một phiên lệnh fail-closed. Nếu block không lặp lại dòng khởi tạo,
phải chạy `set -euo pipefail` trong cùng shell trước khi chạy; dừng ngay ở exit code khác
0, không copy riêng các dòng sau lỗi và không thêm `|| true` ngoài vị trí đã ghi rõ.

| Nhóm | Quota tối thiểu để kiểm đợt thu | Mục tiêu nên thu |
|---|---:|---:|
| account-benign | 10 run hợp lệ | 12 |
| account-malicious | 10 run hợp lệ | 12 |
| c2-benign | 10 run hợp lệ | 12 |
| c2-malicious | 10 run hợp lệ | 12 |

Chỉ sau G7 mới áp dụng quota: mỗi nhóm trainable dùng đủ **năm** kịch bản trong `config/scenario-catalog.yaml`. Ở mốc 10,
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

Đây là bảng kiểm SAU cài đặt mục 4–9, không chạy lệnh ở mục 1.1 trên VM chưa cài
Wazuh/repo/agent. Trước pilot mới phải hoàn tất cả bốn chuyển đổi sau:

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
cd "$HOME/datn-ai-soar-v3"
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
đó mới chạy lại preflight và pilot tại G6.

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

Không chuyển sang bước phụ thuộc khi cổng trước chưa đạt:

| Cổng | Điều kiện và bằng chứng |
|---|---|
| G0 | đúng source pilot/release, OS, tên máy, IP/MAC, giờ, snapshot và disk |
| G1 | Windows → NET-SENSOR → Kali đúng route; management phục vụ quản trị/Wazuh |
| G2 | Wazuh có WIN11-TARGET và NET-SENSOR Active |
| G3 | Security 4624/4625 và Sysmon 1/3/22 mới xuất hiện tại manager |
| G4 | EVE alert/DNS/HTTP/final flow về Archives; timeout/độ trễ đáp ứng grace |
| G5 | enrollment riêng trước pilot, baseline hợp lệ/TTL/hash và đủ history |
| G6 | pilot cả bốn nhóm VALID, parity, backup/restore và evidence được Thịnh kiểm |
| G7 | baseline thu chính thức + cohort/catalog/taxonomy/challenge đã freeze |
| G8 | quota mới đạt; final audit READY/TARGET_MET, không còn run hỏng |
| G9 | build thành công, hash/split đúng, locked test UNOPENED; gói Colab đúng bốn file |

Hiện chỉ triển khai tới G6. G7 chưa được xác nhận. Đủ ảnh, dịch vụ Active hoặc một
pilot VALID không tự động mở G7 và không chứng minh model đã phân biệt tốt hai nhãn.

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
sudo apt install -y open-vm-tools openssh-server curl git jq
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
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv4.gateway "" \
+    ipv4.never-default yes ipv4.ignore-auto-dns yes ipv6.method disabled
else
  sudo nmcli connection add type ethernet ifname "$DATA_IF" con-name ATTACK-LAB \
    ipv4.method manual ipv4.addresses 10.40.0.10/24 \
    ipv4.routes "10.20.0.0/24 10.40.0.1" ipv4.gateway "" \
+    ipv4.never-default yes ipv4.ignore-auto-dns yes ipv6.method disabled
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

### 6.2 Repo và môi trường Python trên SOC-AI

Dùng checkout mới để tránh đưa nhầm dataset/venv/config cũ vào đợt v3. Có Internet
ở giai đoạn cài đặt; collection mode chỉ bật sau khi cài và tải tài nguyên xong.

```bash
set -euo pipefail
test "$(id -u)" -ne 0 # Repo dung user thuong co sudo, khong dung root
LAB_USER="$(id -un)"
PROJECT_ROOT="$HOME/datn-ai-soar-v3"
REVIEWED_SOURCE_COMMIT=d06d04034f0d1c996907365841f21cdb874e4d5a
if [ ! -e "$PROJECT_ROOT" ]; then
  git clone --branch fix/handoff-context-v3 --single-branch \
    https://github.com/lethinhlord/Repo.git "$PROJECT_ROOT"
fi
test -d "$PROJECT_ROOT/.git"
cd "$PROJECT_ROOT"
test -z "$(git status --porcelain --untracked-files=all)" || {
  echo 'STOP: checkout has local changes; preserve them and resolve before collection' >&2
  exit 1
}
git fetch origin fix/handoff-context-v3
git cat-file -e "$REVIEWED_SOURCE_COMMIT^{commit}"
git checkout --detach "$REVIEWED_SOURCE_COMMIT"
test "$(git rev-parse HEAD)" = "$REVIEWED_SOURCE_COMMIT"
mkdir -p evidence operator-logs run-drafts
git rev-parse HEAD | tee evidence/collection-source-commit.txt
bash scripts/bootstrap_ml.sh
.venv-ml/bin/python -m pip check
# Tai wheel truoc collection mode de restore/validate offline cung OS/Python/architecture.
mkdir -p operator-logs/wheelhouse
.venv-ml/bin/python -m pip download --only-binary=:all: --dest operator-logs/wheelhouse \
  --requirement requirements.lock --requirement requirements-ml.lock
(cd operator-logs/wheelhouse && sha256sum ./* > ../wheelhouse.sha256)
.venv-ml/bin/python -m pytest -q \
  tests/test_scenario_collection.py tests/test_dataset_audit.py \
  tests/test_collection_configuration.py tests/test_collection_windows.py \
  tests/test_bucket_reservations.py tests/test_handoff_regressions.py \
  tests/test_progress_audit.py tests/test_context_baseline.py \
  tests/test_context_enrollment.py tests/test_context_dns_suffix.py \
  tests/test_context_feature_contract.py tests/test_dataset_purposes.py \
  tests/test_cohort_dataset_build.py tests/test_feature_window_closure.py
.venv-ml/bin/python -m scripts.create_run_draft --help
.venv-ml/bin/python -m scripts.scenario_session finalize --help
.venv-ml/bin/python -m scripts.enroll_context_baseline --help
```

Các test phải đạt trên môi trường Linux, các CLI phải có `--purpose`,
`finalize --wait-for-window`, enrollment `--dns-suffix`. Không lấy con số test đã chạy
trên máy Windows của Thịnh làm bằng chứng Ubuntu của Kiên đã đạt.

Cho user vận hành đọc Archives rồi mở phiên SSH mới:

```bash
set -euo pipefail
LAB_USER="$(id -un)"
sudo usermod -aG wazuh "$LAB_USER"
id "$LAB_USER"
```

Thoát SSH, đăng nhập lại; sau khi agent đã gửi event, kiểm:

```bash
set -euo pipefail
id
test -r /var/ossec/logs/archives/archives.json
stat -c '%U %G %a %n' /var/ossec/logs/archives/archives.json
```

Nếu vẫn Permission denied, kiểm group/ACL và logrotate trên SOC-AI. Không `chmod 777`
và không chạy cả repo bằng root để che lỗi quyền. Không tạo Archives rỗng để vượt kiểm.

### 6.3 API/n8n là phần kiểm tích hợp, tách khỏi việc chuẩn bị dữ liệu

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
cd "$HOME/datn-ai-soar-v3"
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

Không train hoặc đóng gói một model giả để vượt bước này. Package schema v2 không
được dùng với vector v3. Baseline được mount chỉ đọc vào API; thiếu/hết hạn phải xử lý
trước deploy. Ingest online là tạm thời/REVIEW; kết quả cửa sổ cuối cần endpoint
`/features/wazuh/finalize-window` sau watermark. Workflow hiện chưa tự đóng window.
Không yêu cầu nhập OpenAI API key vào hộp Assistant của n8n để chạy collector hay ML.

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
scp "${SocUser}@192.168.58.147:datn-ai-soar-v3/scripts/Test-DatnWindowsPreflight.ps1" C:\DATN\
if ($LASTEXITCODE -ne 0) { throw 'Cannot copy the Windows preflight helper' }
Get-FileHash C:\DATN\Test-DatnWindowsPreflight.ps1 -Algorithm SHA256
```

Đối chiếu hash với `sha256sum scripts/Test-DatnWindowsPreflight.ps1` trên SOC-AI.
Helper chỉ đọc trạng thái; quyền sửa user/firewall nằm ở các bước riêng bên dưới.

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
$SocRepo = "$SocHome/datn-ai-soar-v3"
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
        - dns
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
SOC_REPO="$SOC_HOME/datn-ai-soar-v3"
scp "${SOC_USER}@192.168.58.147:${SOC_REPO}/config/suricata-datn.rules" /tmp/
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
SID không phải ground truth của ý định; một canary/health hợp lệ cũng có thể trúng rule. Hai kịch bản staged-transfer cố ý chỉ tạo flow/HTTP, không có local alert,
để `suricata_alert_count` không trở thành feature làm lộ nhãn. Nếu
`suricata -T` báo lỗi, dừng; không chạy collector bằng ruleset lỗi.



#### 8.1.1 Final flow phải về trước hạn thu

Collector v3 yêu cầu final flow counter. Suricata 8.0.7 mặc định có UDP established
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
SOC_REPO="$SOC_HOME/datn-ai-soar-v3"
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

## 10. Preflight bắt buộc trước mỗi buổi thu

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
cd "$HOME/datn-ai-soar-v3"
test -z "$(git status --porcelain)"
COLLECTION_MODE=pilot # Chi dung trainable sau khi G7 duoc nghiem thu
if [ "$COLLECTION_MODE" = pilot ]; then
  EXPECTED_SOURCE_COMMIT=d06d04034f0d1c996907365841f21cdb874e4d5a
elif [ "$COLLECTION_MODE" = trainable ]; then
  : "${COLLECTION_BASELINE_COMMIT:?Can baseline thu chinh thuc do Thinh cung cap}"
  EXPECTED_SOURCE_COMMIT="$COLLECTION_BASELINE_COMMIT"
else
  echo 'Unknown collection mode' >&2; exit 1
fi
[[ "$EXPECTED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_COMMIT"
mkdir -p evidence/scenario-runs
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
CURSOR=$(sudo stat -c %s "$ARCHIVE")
test "$CURSOR" -gt 0
test "$(sudo dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$((CURSOR - 1))" count=1 status=none | od -An -t u1 | tr -d ' ')" = 10
sudo stat -c '%d:%i' "$ARCHIVE" > /tmp/datn-preflight.identity
printf '%s\n' "$CURSOR" | tee /tmp/datn-preflight.cursor
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
ARCHIVE=/var/ossec/logs/archives/archives.json
CURSOR=$(cat /tmp/datn-preflight.cursor)
FRESH=/tmp/datn-preflight-fresh.jsonl
PASS=0
for attempt in $(seq 1 18); do
  test "$(sudo stat -c '%d:%i' "$ARCHIVE")" = "$(cat /tmp/datn-preflight.identity)"
  test "$(sudo stat -c %s "$ARCHIVE")" -ge "$CURSOR"
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
for TYPE in dns http; do
  jq -e --arg type "$TYPE" 'select(.agent.name=="NET-SENSOR") |
    (.full_log|fromjson?) | select(.event_type==$type and
    .src_ip=="10.20.0.10" and .dest_ip=="10.40.0.10")' "$FRESH" >/dev/null
done
for PROTO in TCP UDP; do
  jq -e --arg proto "$PROTO" 'select(.agent.name=="NET-SENSOR") |
    (.full_log|fromjson?) | select(.event_type=="flow" and .proto==$proto and
    .src_ip=="10.20.0.10" and .dest_ip=="10.40.0.10" and
    .flow.start!=null and .flow.end!=null and
    (.flow.bytes_toserver|type)=="number" and
    (.flow.bytes_toclient|type)=="number")' "$FRESH" >/dev/null
done
echo 'END_TO_END_PREFLIGHT=PASS'
```

Nếu bất kỳ block nào không in `PASS`, không bắt đầu run. Sửa nguyên nhân rồi chạy lại
từ 10.1; không dùng event cũ, không tạo file Archives giả và không hạ ngưỡng kiểm tra.

### 10.5 Enrollment context riêng trước pilot và trước đợt thu

Baseline là lịch sử đã quan sát trước sự kiện, không phải danh sách nhãn benign.
Giữ riêng capture enrollment, pilot, trainable và challenge. Chưa mở run trong lúc
enrollment; không dùng lại raw của các run đã gán nhãn để tạo lịch sử quá khứ.

SOC-AI — mở một terminal và giữ phiên này tới hết bước capture:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v3"
test ! -e evidence/scenario-runs/.active-run.json
ENROLL_ID="ENROLL-$(date -u +%Y%m%dT%H%M%SZ)"
ENROLL_DIR="$PWD/operator-logs/enrollment/$ENROLL_ID"
mkdir -p "$ENROLL_DIR"
ARCHIVE=/var/ossec/logs/archives/archives.json
test -r "$ARCHIVE"
stat -c '%d:%i' "$ARCHIVE" > "$ENROLL_DIR/archive.identity"
START_BYTE=$(stat -c %s "$ARCHIVE")
test "$START_BYTE" -gt 0
test "$(dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$((START_BYTE - 1))" count=1 status=none | od -An -t u1 | tr -d ' ')" = 10
printf '%s\n' "$START_BYTE" > "$ENROLL_DIR/start-byte.txt"
date -u --iso-8601=seconds > "$ENROLL_DIR/start-utc.txt"
```

Windows — đăng nhập thành công các account lab để ghi lịch sử local hợp lệ. Có thể
dùng `runas` lần lượt, nhập đúng mật khẩu tại prompt thật; không dùng `/savecred`:

```powershell
runas /user:.\datn_benign "cmd /c whoami"
runas /user:.\datn_attack "cmd /c whoami"
runas /user:.\datn_spray01 "cmd /c whoami"
runas /user:.\datn_spray02 "cmd /c whoami"
runas /user:.\datn_spray03 "cmd /c whoami"
```

Kali — enrollment remote là hoạt động quản trị được phê duyệt trước, làm với cả
account mang tên benign và attack, không suy nguồn tin cậy từ nhãn sau này:

```bash
set -euo pipefail
for USER_NAME in datn_benign datn_attack datn_spray01 datn_spray02 datn_spray03; do
  smbclient '//10.20.0.10/IPC$' -W WIN11-TARGET -U "$USER_NAME" -c 'quit'
done
```

Windows — tạo lịch sử các dịch vụ lab được chuẩn bị sẵn. Đây là thao tác enrollment
được ghi riêng, không phải run C2 và không tính quota:

```powershell
$ErrorActionPreference = 'Stop'
foreach ($uri in @(
  'http://10.40.0.10:8080/health?enrollment=1',
  'http://10.40.0.10:8081/beacon?enrollment=1',
  'http://10.40.0.10:9001/stage.bin?enrollment=1'
)) {
  curl.exe --fail --silent --show-error --output NUL $uri
  if ($LASTEXITCODE -ne 0) { throw "Enrollment request failed: $uri" }
}
Resolve-DnsName enrollment.www.datn.test -Server 10.40.0.10 -Type A -DnsOnly
Resolve-DnsName enrollment.beacon.datn.test -Server 10.40.0.10 -Type A -DnsOnly
```

SOC-AI — chờ agent chuyển log (theo độ trễ đã đo ở G4), rồi đóng capture ở ranh giới
dòng. Nếu `tail` cuối chưa là newline, chờ và kiểm lại, không lấy JSON dở:

```bash
set -euo pipefail
sleep 30
test "$(stat -c '%d:%i' "$ARCHIVE")" = "$(cat "$ENROLL_DIR/archive.identity")"
START_BYTE=$(cat "$ENROLL_DIR/start-byte.txt")
END_BYTE=$(stat -c %s "$ARCHIVE")
test "$END_BYTE" -gt "$START_BYTE"
dd if="$ARCHIVE" iflag=skip_bytes,count_bytes skip="$START_BYTE" \
  count="$((END_BYTE - START_BYTE))" status=none > "$ENROLL_DIR/archives-capture.jsonl"
test "$(stat -c '%d:%i' "$ARCHIVE")" = "$(cat "$ENROLL_DIR/archive.identity")"
test "$(wc -c < "$ENROLL_DIR/archives-capture.jsonl")" -eq "$((END_BYTE - START_BYTE))"
test "$(tail -c 1 "$ENROLL_DIR/archives-capture.jsonl" | od -An -t u1 | tr -d ' ')" = 10
printf '%s\n' "$END_BYTE" > "$ENROLL_DIR/end-byte.txt"
date -u --iso-8601=seconds > "$ENROLL_DIR/end-utc.txt"
jq -e . "$ENROLL_DIR/archives-capture.jsonl" >/dev/null
jq -c '
  select(.agent.name=="WIN11-TARGET") |
  (.data.win.system.eventID|tostring) as $id |
  .data.win.eventdata as $d |
  select(
    ($id=="4624" and
      (["datn_benign","datn_attack","datn_spray01","datn_spray02","datn_spray03"] |
       index(($d.targetUserName//""|ascii_downcase))) != null) or
    ($id=="3" and ($d.initiated|tostring|ascii_downcase)=="true" and
       $d.sourceIp=="10.20.0.10" and $d.destinationIp=="10.40.0.10") or
    ($id=="22" and (($d.queryName//""|ascii_downcase)|endswith(".datn.test")))
  )' "$ENROLL_DIR/archives-capture.jsonl" > "$ENROLL_DIR/approved-enrollment.jsonl"
test -s "$ENROLL_DIR/approved-enrollment.jsonl"
(cd "$ENROLL_DIR" && sha256sum archives-capture.jsonl approved-enrollment.jsonl > capture.sha256)
(cd "$ENROLL_DIR" && sha256sum --check capture.sha256)
```

Kiểm lại `approved-enrollment.jsonl` chứa đúng các thao tác vừa làm. Bản đầy đủ trước
lọc vẫn giữ trong `archives-capture.jsonl`. Nếu thiếu user/nguồn/dịch vụ, tạo capture
enrollment mới và thực hiện lại phần còn thiếu; không viết thêm event hoặc history bằng tay.

Khi đã có baseline trước đó, không ghi đè. Chỉ chuyển bản cũ ra kho revision khi không
có run đang hoạt động; context của run cũ vẫn nằm trong evidence đóng băng:

```bash
set -euo pipefail
test ! -e evidence/scenario-runs/.active-run.json
if [ -f evidence/context-baseline.json ]; then
  OLD_SHA=$(sha256sum evidence/context-baseline.json | awk '{print $1}')
  test ! -e "$ENROLL_DIR/prior-context-$OLD_SHA.json"
  mv -- evidence/context-baseline.json "$ENROLL_DIR/prior-context-$OLD_SHA.json"
fi
.venv-ml/bin/python -m scripts.enroll_context_baseline \
  --capture "$ENROLL_DIR/approved-enrollment.jsonl" \
  --revision "$ENROLL_ID" --ttl-hours 24 \
  --dns-suffix datn.test --approved-enrollment \
  --output evidence/context-baseline.json
jq '{version,revision,captured_at,observed_through,valid_until,source_capture_sha256,
     accounts,destinations}' evidence/context-baseline.json
jq -e '([.accounts[].account]|sort) ==
 ["datn_attack","datn_benign","datn_spray01","datn_spray02","datn_spray03"]' \
  evidence/context-baseline.json >/dev/null
jq -e 'all(.accounts[]; (.known_sources|index("10.40.0.10")) != null and
 ((.known_sources|index("local-console")) != null or (.known_sources|index("-")) != null))' \
  evidence/context-baseline.json >/dev/null
for PORT in 8080 8081 9001; do
  jq -e --argjson port "$PORT" 'any(.destinations[];
   .destination=="10.40.0.10" and .port==$port)' evidence/context-baseline.json >/dev/null
done
jq -e '[.destinations[] | select(.match=="dns_suffix" and
 .destination=="datn.test" and .port==53)] | length>0' \
  evidence/context-baseline.json >/dev/null
CAPTURE_SHA=$(jq -r .source_capture_sha256 evidence/context-baseline.json)
test "$(sha256sum "evidence/context-captures/$CAPTURE_SHA.jsonl" | awk '{print $1}')" = "$CAPTURE_SHA"
cp -- evidence/context-baseline.json "$ENROLL_DIR/context-baseline.json"
cmp -- evidence/context-baseline.json "$ENROLL_DIR/context-baseline.json"
(cd "$ENROLL_DIR" && sha256sum context-baseline.json > baseline.sha256)
(cd "$ENROLL_DIR" && sha256sum --check baseline.sha256)
```

`--dns-suffix datn.test` là inventory lab được khai báo trước, phải có truy vấn thật
trong enrollment. Nó tránh coi mỗi run nonce trong FQDN là một đích mới. Đây không
phải khẳng định mọi truy vấn trong domain đều lành tính; C2 vẫn có thể dùng domain quen.
Không thêm suffix Internet rộng hoặc sửa snapshot JSON. Thiếu/stale/future history
phải UNKNOWN/PARTIAL/REVIEW, không tự thay bằng 0 và ghi COMPLETE.

TTL phải đủ cho toàn bộ buổi thu. Nếu hết hạn, dừng đợt, tạo enrollment/revision mới
trước các run tiếp theo và gửi Thịnh đối chiếu; không sửa `valid_until`. Nếu API đang
chạy với baseline cũ, phải deploy/restart có kiểm soát và kiểm đúng context revision.

### 10.6 Pilot collector bắt buộc sau khi cài mới hoặc đổi code/config

Thực hiện mục 11 với `RUN_PURPOSE=pilot`. Chạy riêng bốn pilot sau, một run một bucket:

1. ACCOUNT-BENIGN-NORMAL-LOGON — console type 2, mật khẩu đúng;
2. ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS — SMB type 3, sai rồi đúng từ Kali;
3. C2-BENIGN-DNS — child PowerShell, nonce, DNS/EVE/final UDP flow;
4. C2-MALICIOUS-HTTP-BEACON — ProcessGuid, network/HTTP/SID/final TCP flow.

Mỗi pilot phải FINALIZED rồi VALID; context phải AVAILABLE, observation_quality
COMPLETE và đủ nguyên liệu full-capture parity. `purpose=pilot` được đóng băng từ
draft, auditor loại khỏi quota train mà vẫn kiểm integrity. Không đổi purpose sau
khi xem prediction, không đổi tên thư mục pilot thành trainable.

Chạy progress audit sau mỗi pilot, backup và thử restore khác root. Gửi toàn bộ
bundle/evidence cho Thịnh kiểm G6. Nếu chỉ một pilot đạt, chưa kết luận toàn bộ hệ thống
đạt. Canary trước đó chỉ kiểm đường log; nó không thay cho pilot collector/restore.

### 10.7 Cổng G7 trước thu chính thức

Tại revision pilot hiện tại, cổng này còn khóa. Chỉ thực hiện khi Thịnh đã bàn giao
baseline thu chính thức sau khi sửa/đối chiếu catalog, cohort, taxonomy và challenge.
Không tự nhập `136bb754`, không chọn SHA của model smoke hoặc bỏ gate để đủ 40 mẫu.

Kiên cần nhận: SHA commit đầy đủ 40 ký tự; catalog/contract đã freeze; lịch scenario
và cohort; danh sách challenge tách riêng; biên bản pilot; hướng dẫn tương ứng với
SHA đó. Checkout release phải sạch và đúng SHA, không chỉ là descendant ngẫu nhiên.

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v3"
: "${COLLECTION_BASELINE_COMMIT:?Thinh chua cung cap baseline thu chinh thuc}"
[[ "$COLLECTION_BASELINE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$COLLECTION_BASELINE_COMMIT"
test -z "$(git status --porcelain --untracked-files=all)"
.venv-ml/bin/python - <<'PY'
from pathlib import Path
import yaml
from ml.scenario_collection import ScenarioCatalog
catalog = ScenarioCatalog.model_validate(yaml.safe_load(Path('config/scenario-catalog.yaml').read_text()))
config = yaml.safe_load(Path('ml/training_config.yaml').read_text())
taxonomy = yaml.safe_load(Path('config/suspicious-process-taxonomy.yaml').read_text())
errors = []
if config['data']['group_key'] != 'cohort_id':
    errors.append('Production split chua chuyen sang cohort_id')
if any(x.purpose == 'trainable' and not x.cohort_id for x in catalog.scenarios):
    errors.append('Trainable catalog chua co cohort day du')
if not any(x.purpose == 'challenge' for x in catalog.scenarios):
    errors.append('Chua co challenge doi chung duoc dong bang truoc thu')
terms = [str(term).casefold() for rule in taxonomy['rules']
         for term in rule.get('command_contains_any', [])]
if any(marker in term for term in terms
       for marker in ('/beacon','/stage.bin','beacon.datn.test','payload-benign')):
    errors.append('Taxonomy van dung fingerprint chuoi lab lam tin hieu doc lap')
if errors:
    raise SystemExit('G7 CHUA MO:\n- ' + '\n- '.join(errors))
print('G7 SOURCE CONTRACT CHECK=PASS; van can bien ban pilot thuc te')
PY
```

Các kiểm tra trên bổ sung cho biên bản nghiệm thu, không thay thế review G01–G07.
Nếu báo G7 CHƯA MỞ, dừng thu chính thức và gửi log cho Thịnh. Kiên vẫn có thể giữ
lab ổn định, chạy pilot được yêu cầu và sao lưu; không tự sửa catalog/nhãn để vượt gate.

## 11. Quy trình chuẩn cho MỖI run

Thực hiện đúng thứ tự; không gộp hai kịch bản trong một cửa sổ.

### Bước 1 — Chọn run và khai báo ground truth trước

Quy ước ID:

```text
<PILOT-hoac-TRAINABLE>-<SCENARIO-ID>-R<01..99>-<YYYYMMDD>
```

Ví dụ trên SOC-AI:

```bash
cd "$HOME/datn-ai-soar-v3"
set -euo pipefail
date -u --iso-8601=seconds
timedatectl show -p NTPSynchronized --value
RUN_PURPOSE=pilot # Chuyen thanh trainable chi sau khi G7 da dat
RUN_DATE=$(date -u +%Y%m%d)
RUN_ID="${RUN_PURPOSE^^}-C2-MALICIOUS-HTTP-BEACON-R01-$RUN_DATE"
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
  --scenario C2-MALICIOUS-HTTP-BEACON \
  --run-id "$RUN_ID" \
  --operator Kien --purpose "$RUN_PURPOSE" \
  --clock-preflight "$CLOCK_FILE"
sed -n '1,120p' "run-drafts/$RUN_ID.yaml"
```

Lệnh `build_clock_preflight` kiểm khoảng trước/sau của từng lần đọc, giới hạn RTT
4 giây và sai lệch có thể có giữa các máy tối đa 5 giây; không lấy chênh lệch giữa
hai lần đọc nối tiếp làm clock skew. Đo local controller và Wazuh tại cùng SOC-AI.
Không nhập mật khẩu trong phép đo. Nếu RTT/độ bất định quá lớn, xử lý mạng/giờ rồi
tạo bộ đo mới bằng run ID mới; không tăng ngưỡng hoặc sửa timestamp cho qua gate.
File measurements và YAML là bằng chứng thật cần lưu trong backup. YAML không bị ghi
đè; draft đóng băng `collection_seed`, `scenario_parameters`, observable và clock
evidence. Không sửa các trường này bằng tay. Tạo draft rồi start ngay; evidence quá
120 giây sẽ bị từ chối. Không bước/đổi giờ hoặc resume VM giữa một run.

Cho ba pilot khác, thay đồng thời `--scenario` và phần scenario trong RUN_ID bằng
đúng ID tại 10.6; tăng R01 thành R02 nếu ID đã từng dùng, kể cả run abort. Không sửa
family/label trực tiếp. Khi mất phiên SSH, khai báo lại RUN_ID đúng từ thư mục hiện
có rồi dùng status, không chạy lại create/start một cách mù quáng.

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

Trước `begin-action`, sign out/pre-stage account như mục 12.1; không làm việc đó
sau receipt. Với C2, copy nguyên output PowerShell vào `WIN11-TARGET`, rồi chạy block khởi tạo ở mục
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

Giữ target yên trong toàn bộ bucket: không đăng nhập quản trị mới, không tạo request
canary hay chạy lại scenario để bù log. Ngay khi hoạt động và cleanup kết thúc, chạy
`complete-action` **trước**
`action_deadline`, rồi chuyển ngay sang Bước 5 **trước hạn nhận log**. Không chờ hết
bucket mới gọi finalize. Không tạo traffic lab khác trong phần còn lại của bucket:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id "$RUN_ID"
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
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id "$RUN_ID" --wait-for-window
```

Gọi lệnh ngay sau `complete-action`, trong khi vẫn còn thời gian trước cuối bucket
UTC cộng grace 60 giây. Giữ terminal/phiên SSH chạy đến khi lệnh kết thúc. Collector
đọc Archives tăng dần và ghi thời điểm **đọc xong** từng đoạn byte. Chỉ dòng JSON hoàn
chỉnh đã được đọc xong không muộn hơn cutoff mới được nhận. Không chỉ ngủ hết grace
rồi đọc tất cả log đang có.

Nó lưu `archive_capture.jsonl` nguyên byte trước lọc và `intake_checkpoint.json`
đóng băng phạm vi nhận, cursor nguồn, hash và thời điểm đọc. Sau đó replay toàn bộ
bucket bằng source/taxonomy/context đóng băng. Tài khoản nền có danh tính OS xác
định được giữ thành unknown/PARTIAL, không thêm count vào tài khoản người dùng;
thiếu trường định danh cũng phải unknown/PARTIAL, không đoán thành benign.
C2 bắt buộc nonce, ProcessGuid, thời gian, tuple IP/cổng/giao thức và transaction
Suricata khớp. Final flow không có transaction hợp lệ, tuple thiếu/sai hoặc DNS
khớp nhiều socket không được nâng thành COMPLETE. Thiếu nguồn/receipt hoặc
vector/quality không tái hiện được thì không tạo mẫu cuối.

Thời điểm collector đọc log không chứng minh thời điểm Wazuh Manager sinh log hay
API nhận log. Replay ở đây kiểm tính nhất quán feature; nghiệm thu độ trễ/received_at
online phải dùng bằng chứng API thực riêng. `validate` từ bản backup có thể xác minh
checkpoint/raw đã lưu mà không truy cập Archives gốc; không chứng minh thêm log
chưa từng được đóng băng. Khi finalize/retry còn trên SOC-AI, nguồn gốc và tail thật
được kiểm tra lại.

**Xử lý lỗi và mất phiên:**

- Chưa từng chạy intake trước cutoff: finalize muộn báo thiếu checkpoint hợp lệ.
  Giữ evidence, abort và thu run ID mới; không đổi giờ hay nới grace.
- Mất phiên/lệnh bị ngắt khi checkpoint còn `capturing`, thiếu checkpoint hoặc có
  dòng JSON dở: không xóa file để chạy lại; giữ evidence, abort, sửa đường log và
  thu mới. Lệnh `status` vẫn cần dùng để xác định run đang sở hữu khóa.
- Checkpoint đã sealed trước lỗi bước tạo feature/output: chỉ retry cùng RUN_ID
  với nguyên evidence sau khi xử lý nguyên nhân được phép. Retry không nhận thêm
  byte vào capture đã đóng băng. Nếu file tạm/trạng thái không rõ, dùng quarantine
  theo Bước 6 thay vì sửa state bằng tay.
- Có input thuộc bucket gốc xuất hiện sau cutoff, rotate/truncate, hash lệch hoặc
  clock chạy lùi: fail closed; không retry để bổ sung log cho run cũ. Byte tới muộn
  được giữ riêng ở `archive_capture-late.jsonl` nếu có; giữ cả file này và gửi lỗi.
- Không sinh thêm traffic để bù event, không copy log cũ, không giảm quality gate.
  Sau abort/quarantine, bucket cũ vẫn được giữ quyền; run mới dùng bucket mới.

### Bước 6 — Validate run

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
find "data/raw/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
find "evidence/scenario-runs/$RUN_ID" -maxdepth 1 -type f -printf '%f\n' | sort
```

Phải thấy `VALID`; `data/raw/$RUN_ID` có `scenario_manifest.json` và `incidents.jsonl`;
evidence có Archives nguyên byte, intake checkpoint, Windows events, Suricata EVE,
metadata và SHA-256. Giữ cả late capture nếu có. Không chỉnh
tay file đã finalize. Nếu validate sai, bảo toàn dữ liệu hỏng để điều tra rồi đưa cả cặp
raw/evidence ra khỏi dataset bằng lệnh duy nhất:

```bash
set -euo pipefail
.venv-ml/bin/python -m scripts.scenario_session quarantine \
  --run-id "$RUN_ID" --reason "ghi ro loi validate"
```

Phải thấy `QUARANTINED`, hai thư mục nguồn không còn và dữ liệu được giữ trong
`data/quarantine/$RUN_ID` cùng `evidence/quarantine/$RUN_ID`. Sau đó mới thu bằng ID
và bucket mới. Không xóa một phía và không tự sửa checksum.

Nếu finalize bị ngắt ở `FINALIZING`, output tạm `.RUN_ID.tmp` cũng phải được bảo
toàn. Lệnh quarantine chuyển nó sang `data/quarantine/.RUN_ID.tmp`, ghi
`staged_raw_preserved`/`staged_raw_path` trong `quarantine.json`. Nếu cả output cuối
và output tạm cùng tồn tại, giữ cả hai; không chọn/xóa một bản bằng tay. Backup cả
`data/quarantine`, kể cả thư mục ẩn. Không để `.RUN_ID.tmp` cũ trong `data/raw` để
tính quota hoặc tiếp tục train.

Nếu execution receipt hỏng, collector chỉ phục hồi **quyền sở hữu bucket** từ state,
start contract, metadata/checksum và reservation độc lập còn khớp. Original hỏng vẫn
được giữ; `bucket_recovery.json` ghi nguồn phục hồi, không sửa mẫu hỏng thành VALID.
Receipt thiếu, chứng cứ không đủ/xung đột hoặc reservation gốc mất khi receipt hỏng:
`cannot recover collection bucket` phải dừng. Khôi phục cả bộ bằng backup đã xác
minh, giữ nguyên bản hỏng ngoài checkout để điều tra, rồi audit trước khi thu tiếp.
Không xóa thư mục quarantine/reservation để né lỗi. Hash kiểm tính toàn vẹn, không
chống được người có quyền ghi thay đồng thời toàn bộ chứng cứ; gửi checksum/backup
cho Thịnh qua kênh độc lập sau mỗi buổi.

### Bước 7 — Audit tiến độ toàn dataset

SOC-AI — mode progress cho phép tiếp tục khi chỉ thiếu quota; mọi lỗi integrity vẫn chặn:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v3"
.venv-ml/bin/python -m scripts.audit_dataset \
  --raw-dir data/raw --evidence-dir evidence/scenario-runs \
  --scenario-catalog config/scenario-catalog.yaml \
  --source-config config/collection-sources.yaml \
  --taxonomy config/suspicious-process-taxonomy.yaml \
  --minimum-runs 10 --target-runs 12 --mode progress \
  --output evidence/dataset-audit.json
jq '{status,audit_mode,total_valid_runs,excluded_purpose_counts,invalid_run_count,
     error_count,strata,pending_issues,issues}' evidence/dataset-audit.json
```

COLLECTING + exit 0 nghĩa là chưa đủ quota/coverage, có thể thu tiếp theo lịch. Pilot
không tính quota, vì vậy nhiều pilot VALID vẫn có thể báo COLLECTING/0 trainable.
`pending_issues` không phải đã vượt gate cuối. NOT_READY + exit khác 0 vì run hỏng,
checksum/provenance sai, collision, bucket trùng hoặc vấn đề integrity phải dừng.
Không thêm `|| true`. Final audit ở mục 14 dùng mode final và phải đạt trước build.

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

Thao tác account tại console WIN11-TARGET. Toàn bộ chuẩn bị quản trị bên dưới phải
xong TRƯỚC start/begin-action. Trước từng run account, PowerShell Administrator xác nhận
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
sẽ tạo thêm event. Với scenario console, sign out phiên quản trị trước `start`, để
Windows sẵn ở màn hình Other user/Password; không dùng Lock, PIN, Windows Hello hoặc
Fast User Switching thay cho đăng nhập mới. Với RUNAS, chuẩn bị CMD ở phiên quản trị
trước start và chỉ chạy đúng runas sau tín hiệu. SMB không cần đăng nhập console mới.

Sau `begin-action --wait-for-window` trả receipt STARTED (chưa phải chỉ `start`),
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

Không tạo thêm lần thử ngoài bảng trong cùng cửa sổ. Scenario console có success thì
sign out chính phiên vừa đăng nhập; failure-only giữ nguyên màn hình đăng nhập. RUNAS
để child `cmd /c whoami` kết thúc, không chạy thêm runas. SMB đóng IPC$ sau mỗi lệnh.
Không đăng nhập quản trị, mở Event Viewer, thử thêm mật khẩu, hoặc kiểm target bằng SSH
trong bucket đang thu. Đợi `complete-action` rồi `finalize --wait-for-window` và VALID
trên SOC-AI mới quay lại desktop/đọc log. Đăng nhập quản trị giữa bucket có thể gây
full-capture parity mismatch dù collector đã lọc account kịch bản. Quality gate kiểm
đúng số 4624/4625 và thứ tự failure → success; thiếu type 2/3 thì abort, không sửa log.

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

### 12.3 Đầu ra thật của collector — không tạo mẫu JSON bằng tay

Collector tự ghi, không yêu cầu Kiên nhập từng dòng feature. Sau VALID kiểm trực tiếp
trên SOC-AI (vẫn cùng RUN_ID):

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v3"
jq . "data/raw/$RUN_ID/scenario_manifest.json"
jq . "data/raw/$RUN_ID/incidents.jsonl"
jq . "evidence/scenario-runs/$RUN_ID/collection_metadata.json"
jq . "evidence/scenario-runs/$RUN_ID/execution_receipt.json"
find "evidence/scenario-runs/$RUN_ID" -type f -printf '%P\n' | sort
.venv-ml/bin/python -m scripts.scenario_session validate --run-id "$RUN_ID"
```

Cấu trúc chính (snapshot và tên file chi tiết do đúng revision collector quyết định):

```text
data/raw/<RUN_ID>/
  scenario_manifest.json          # scenario/family/label/purpose, times, provenance
  incidents.jsonl                # observation + vector features-v3 được tính từ raw
evidence/scenario-runs/<RUN_ID>/
  .collection_state.json          # state, không sửa/xóa tay
  execution_receipt.json          # begin/complete cùng frozen parameters hash
  collection_metadata.json        # origin/cursor/contract/file hashes
  archive_capture.jsonl          # bytes đọc trước lọc để replay toàn bucket
  intake_checkpoint.json         # phạm vi nhận đã sealed, cutoff và read ledger
  archive_capture-late.jsonl     # nếu có: bytes muộn; không nhập vào capture đã sealed
  checksums.sha256               # danh sách bằng chứng và checksum
  ...                            # Archives chọn lọc, Windows/EVE và frozen snapshots
evidence/bucket-reservations/     # quyền bucket bền vững, vẫn giữ sau abort/quarantine
evidence/context-baseline.json   # baseline hiện hành; bản mỗi run đã freeze riêng
evidence/context-captures/       # approved enrollment raw theo content hash
operator-logs/enrollment/        # raw đầy đủ/cursor/identity/enrollment kiểm được
run-drafts/                      # clock-measurements JSON, clock YAML và draft trước hành động
```

Nhãn chỉ ở manifest/record theo schema, không nhét scenario ID, username, IP, port,
nonce hoặc nội dung URI vào vector làm đáp án. Features-v3 có 24 trường bắt buộc
trong ml/feature_schema.json; không tự thêm/bớt cột hoặc fill missing=0. Không dùng
JSON mẫu/fixture trong repo như data thật. `validate` và auditor là phép kiểm chính;
`jq` chỉ giúp xem cấu trúc. Ảnh chụp output này phải ghi RUN_ID thật.

## 13. Lịch 10–12 run mỗi nhóm

Chỉ áp dụng sau G7. Bốn pilot kỹ thuật ở mục 10.6 không nằm trong 40–48 run trainable.
Lịch chính thức phải kèm cohort đã freeze; không tự chia cùng scenario thành cohort
khác nhau để đủ fold. Challenge chạy theo catalog riêng, không tính quota/fit/train.
Nếu catalog release thay số scenario hoặc quota, dừng đối chiếu hướng dẫn đúng SHA;
không tự áp bảng 20 scenario của bản pilot sang release khác.

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

Chỉ sau G7 và đã có đủ trainable mới chạy phần này. Bàn giao pilot không đòi READY
hoặc build dataset; progress COLLECTING là trạng thái hợp lệ khi chỉ thiếu quota.

Mốc 10 run/nhóm:

```bash
cd "$HOME/datn-ai-soar-v3"
chmod +x scripts/verify_collection_dataset.sh
./scripts/verify_collection_dataset.sh
```

Ở mốc tối thiểu phải báo `READY`, 40 trainable hợp lệ, 0 invalid (pilot/challenge thống kê riêng). Mốc 12:

```bash
set -euo pipefail
REQUIRE_TARGET=1 ./scripts/verify_collection_dataset.sh
```

Phải báo `TARGET_MET`, 48 trainable hợp lệ, 0 invalid (pilot/challenge không bù quota). Sau đó mới build:

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
jq -e '(.collection_audit.status == "READY" or .collection_audit.status == "TARGET_MET")
  and .feature_schema_version=="features-v3" and .group_key=="cohort_id"
  and .locked_test_status=="UNOPENED"' data/processed/dataset_manifest.json >/dev/null
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
thiếu file, checksum sai, schema không phải features-v3, group/cohort không hợp lệ, scenario xuất hiện ở cả
TRAIN và VALIDATION, hoặc phát hiện `locked_test.jsonl`.

## 15. Sao lưu và bàn giao dữ liệu gốc

`data/raw/` và `evidence/scenario-runs/` bị Git bỏ qua có chủ đích; `git push` **không
phải bản sao lưu dataset**. Sau mỗi bốn run hợp lệ và cuối mỗi buổi, chỉ sao lưu khi
không còn run `STARTED`:

```bash
set -euo pipefail
cd "$HOME/datn-ai-soar-v3"
mkdir -p data/raw data/quarantine evidence/scenario-runs evidence/quarantine run-drafts operator-logs
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
git bundle create "$BACKUP_DIR/source.bundle" --all HEAD
git bundle verify "$BACKUP_DIR/source.bundle"
RAW_COUNT=$(find data/raw -mindepth 2 -maxdepth 2 -name scenario_manifest.json | wc -l)
tar --create --gzip --file "$ARCHIVE" \
  --exclude='evidence/scenario-runs/.active-run.json' \
  --exclude='evidence/operator-parameter-exports' \
  --exclude='*.env' --exclude='*.ps1' \
  data/raw data/quarantine evidence run-drafts operator-logs \
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
ARCHIVE_RUNS=$(grep -Ec '^data/raw/[^/]+/scenario_manifest.json$' "$BACKUP_DIR/archive.list")
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
RAW_COUNT=$(grep -Ec '^data/raw/[^/]+/scenario_manifest.json$' "$BACKUP_DIR/archive.list")
RESTORE_CHECK=$(mktemp -d)
trap 'rm -rf -- "$RESTORE_CHECK"' EXIT
tar -xzf "$ARCHIVE" -C "$RESTORE_CHECK"
test -d "$RESTORE_CHECK/data/raw"
test -d "$RESTORE_CHECK/evidence/scenario-runs"
while IFS= read -r -d '' ENROLL_CHECKSUM; do
  (cd "$(dirname "$ENROLL_CHECKSUM")" && sha256sum --check "$(basename "$ENROLL_CHECKSUM")")
done < <(find "$RESTORE_CHECK/operator-logs/enrollment" \
  -type f \( -name capture.sha256 -o -name baseline.sha256 \) -print0)
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
RESTORE_ROOT="$HOME/datn-ai-soar-v3-restored-$BACKUP_ID"
test ! -e "$RESTORE_ROOT"
COMMIT=$(cat "$BACKUP_DIR/git-commit.txt")
git clone "$BACKUP_DIR/source.bundle" "$RESTORE_ROOT"
git -C "$RESTORE_ROOT" checkout --detach "$COMMIT"
tar -xzf "$ARCHIVE" -C "$RESTORE_ROOT"
cd "$RESTORE_ROOT"
# Khong can Internet tren SOC dang collection mode. Dung wheelhouse da tai truoc.
(cd operator-logs/wheelhouse && sha256sum --check ../wheelhouse.sha256)
python3 -m venv .venv-ml
.venv-ml/bin/python -m pip install --no-index --find-links operator-logs/wheelhouse \
  --requirement requirements.lock --requirement requirements-ml.lock
.venv-ml/bin/python -m pip check
for RUN_PATH in data/raw/*; do
  test -d "$RUN_PATH" || continue
  .venv-ml/bin/python -m scripts.scenario_session validate \
    --run-id "$(basename "$RUN_PATH")"
done
echo 'RESTORE_VALIDATION=PASS'
```

Với backup giữa buổi chưa đủ 40 run, audit progress có thể vẫn `COLLECTING` (final vẫn `NOT_READY`); điều đó
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
| `no Wazuh Archive bytes` | chưa nhận đủ nguồn trong cutoff | giữ evidence; abort, sửa pipeline và thu mới; không bổ sung log sau cutoff |
| partial/incomplete JSON lúc cutoff | dòng chưa được nhận trọn đúng hạn | giữ capture/checkpoint; abort và thu mới; không xóa checkpoint hoặc nối dòng bằng tay |
| `rotated or truncated` | Archives rotate trong run | abort, tránh giờ rotate, chạy ID mới |
| `no attributable Windows...` | sai agent/account/process/IP/port/DNS | đối chiếu draft với lệnh thật, chạy mới |
| `no attributable Suricata...` | traffic đi tắt, sai `src_ip`, rule/interface hoặc EVE chưa forward | không retry bằng traffic mới trong cùng run; abort, sửa route/rule/ACL, chạy pilot mới |
| checksum/`RUN_STATE_INVALID` | file bị sửa hoặc finalize bị gián đoạn | dùng `quarantine`, không sửa checksum/state để hợp thức hóa; thu ID mới |
| `active run...` | còn run STARTED hoặc backup đang giữ khóa | đọc owner, finalize/abort/quarantine đúng run; không xóa `.active-run.json` bằng tay |
| `execution receipt...` | chưa `begin-action`/`complete-action`, receipt bị sửa hoặc dùng export sai run | abort nếu hành động chưa hoàn tất; không tự sửa state/receipt; tạo run ID mới nếu đã thao tác sai |
| `frozen action count`/`interval contract` | chạy thừa/thiếu request hoặc sai khoảng nghỉ | abort và thu run mới; không thêm traffic khi run đã kết thúc |
| `past intake deadline` / checkpoint `capturing` | chưa có bằng chứng nhận đúng hạn | abort và thu mới; gọi finalize --wait ngay sau complete-action, giữ terminal mở |
| `late original-window input` | input của bucket cũ xuất hiện sau hạn | giữ late capture, sửa độ trễ/forwarding, thu lại; không nới grace theo run |
| `cannot recover collection bucket` | không đủ chứng cứ để xác định quyền bucket | bảo toàn dữ liệu hỏng, restore bộ backup đã kiểm, không xóa quarantine/reservation |
| `collection contract` | catalog/schema/taxonomy/source config khác snapshot lúc start | quarantine run, đồng bộ đúng commit, chạy lại pilot rồi thu ID mới |
| `SCENARIO_CATALOG_MISMATCH` | draft/manifest không thuộc catalog hoặc sai family/label | quarantine run, cập nhật repo đúng commit, tạo draft mới từ CLI |
| `SCENARIO_IMBALANCE`/`STRATUM_EXCESS` | năm scenario lệch nhau quá 1 run hoặc nhóm đã quá 12 | không copy/xóa tùy tiện; dừng thu, bàn giao audit để người phụ trách quyết định dataset version mới |
| duplicate incident/run | tái sử dụng dữ liệu hoặc ID | quarantine bản trùng và chạy mới |
| `FEATURE_LABEL_SEPARATION`/`JOINT_FEATURE_LABEL_SEPARATION` | feature đơn/cặp feature phân tách hoàn hảo nhãn | bổ sung/chỉnh catalog có hành vi chồng lấn rồi thu dataset version mới; không train trước khi audit đạt |
| audit `COLLECTING` ở progress | mới chỉ thiếu quota/coverage | tiếp tục đúng lịch; không coi là READY |
| audit `NOT_READY` | integrity sai, hoặc final còn thiếu điều kiện | đọc issues/pending_issues, dừng bước phụ thuộc; không thêm `|| true` |
| context MISSING/STALE/FUTURE/UNKNOWN | chưa enrollment, TTL hết, giờ sai hoặc thiếu history | giữ evidence, sửa clock/enrollment ngoài run, chạy pilot mới; không điền context bằng tay |
| full-capture parity mismatch | có traffic/logon nền trong cùng bucket | abort/quarantine; giữ target yên, pre-stage trước begin-action; không lọc bớt raw |
| final flow thiếu hoặc cross-window | timeout/log delay hoặc connection vượt bucket | kiểm EVE gốc và Archives, sửa timeout/path ngoài run; thu bucket mới, không zero-fill |
| G7 CHƯA MỞ | catalog/cohort/taxonomy/challenge chưa release | chỉ bàn giao pilot; Thịnh hoàn tất code/release trước thu chính thức |

Không dùng lệnh sửa trực tiếp `incidents.jsonl`, `scenario_manifest.json` hoặc
`checksums.sha256`. Dữ liệu hỏng phải được quarantine và thu lại.

## 17. Chụp ảnh minh chứng đúng yêu cầu báo cáo

Ảnh phải là toàn bộ màn hình laptop đang hiển thị công cụ thật. 16 inch là kích
thước vật lý, không phải độ phân giải: giữ nguyên độ phân giải native của host,
không ép 1920x1080, không crop hay chỉ chụp vùng terminal.

1. Mở VMware Workstation ở chế độ cửa sổ maximized, giữ thanh tiêu đề, menu, Library,
   guest desktop và taskbar/đồng hồ Windows host trong khung như mẫu của Thịnh.
2. Thực hiện lệnh/chức năng thật trên Ubuntu terminal, Windows Event Viewer, Wazuh
   Dashboard hoặc công cụ đang kiểm. Không dùng script in dòng PASS giả để chụp.
3. Trên host Windows nhấn Print Screen. Nếu phím này mở Snipping Tool, chọn chế độ
   Full screen và màn hình laptop; lưu PNG gốc. Có thể dùng Win+PrtScn nếu chỉ bật
   một màn hình, rồi chép PNG từ Pictures\Screenshots. Kiểm ảnh vừa lưu có đủ mép.
4. Lưu `D:\Tài liệu\Đồ án\Ảnh báo cáo` trên host; máy Kiên không có ổ D thì dùng
   thư mục thực tế và gửi cả thư mục ảnh để Thịnh chép vào đường dẫn trên.
5. Tên `W3-DATA-<nn>-<buoc>-<RUN_ID-hoac-PREFLIGHT>-<UTC>.png`. Giữ bản gốc chưa cắt;
   ghi tên ảnh, bước, hostname, RUN_ID, SHA source và kết luận thật vào nhật ký.
6. Ảnh lộ mật khẩu/token thì không gửi; chụp lại màn hình an toàn, giữ provenance
   của ảnh thay thế. Chụp ảnh không thay thế raw log, receipt, checksum hoặc audit.

Các mốc cần ảnh (chụp từng bước, không chỉ ảnh cuối):

- VM Settings của bốn máy: CPU/RAM/disk/NIC/MAC; `ip -br address` và Windows IP.
- Route Windows→Kali, Suricata interface; chronyc/W32Time và ngày giờ.
- Wazuh Dashboard hai agent Active; dịch vụ thật `systemctl status`/Get-Service.
- Sysmon cấu hình 1/3/22, Event Viewer Security 4624/4625 sau canary, trước pilot.
- Suricata `-T`, EVE HTTP/DNS/alert/final flow; cùng event/flow_id tại Archives.
- Enrollment riêng: các thao tác, baseline revision/TTL/history và hash thật.
- Mỗi pilot: draft/clock, start, begin-action receipt, thao tác thật, complete-action,
  finalize, VALID, progress audit; không mở desktop quản trị giữa bucket account.
- Backup SHA, bản chép host, restore checkout khác root và VALID.
- Sau G7 mới có ảnh quota READY/TARGET_MET, build manifest và bốn file upload Colab.

## 18. Checklist bàn giao theo giai đoạn

### 18.1 Bàn giao pilot ngay ở revision hiện tại

- [ ] 4 VM đúng tên/IP/MAC; route dữ liệu qua NET-SENSOR, collection mode cô lập.
- [ ] Nguồn giờ nội bộ hoạt động, skew thực trong giới hạn; không có step/resume giữa run.
- [ ] Hai agent Active; Security/Sysmon/EVE và final TCP/UDP flow mới có tại Archives.
- [ ] Repo sạch đúng SHA pilot; cấu hình/version và hash được ghi lại.
- [ ] Enrollment riêng có đủ local/remote history của cả năm account, ba port lab,
      DNS suffix quan sát thật, TTL hợp lệ, raw capture và hash tồn tại.
- [ ] Bốn pilot ở mục 10.6 đều FINALIZED/VALID, context AVAILABLE, quality COMPLETE,
      full-capture parity; pilot không tính vào quota trainable.
- [ ] Progress audit chỉ còn shortage/design pending, không lỗi integrity/collision.
- [ ] Backup nguyên liệu đã chép host, SHA đúng, restore khác root validate toàn bộ.
- [ ] Ảnh PNG gốc toàn màn hình và nhật ký có tên bước/RUN_ID/UTC/SHA thật.
- [ ] Gửi Thịnh bundle source + tar dataset/evidence + checksums + progress report +
      nhật ký/ảnh. Không gửi password/key; chưa đánh dấu G7 hoặc model sẵn sàng train.

### 18.2 Bàn giao dataset chính thức sau khi được mở G7

- [ ] Có SHA baseline thu chính thức/biên bản pilot và catalog/cohort/challenge freeze.
- [ ] 10–12 trainable run mới cho mỗi nhóm; năm scenario/nhóm đúng phân bố hiện hành;
      pilot/challenge tách riêng, không reuse dataset cũ.
- [ ] Final audit READY/TARGET_MET, 0 invalid; builder thành công, không hạ gate.
- [ ] Manifest features-v3/group_key=cohort_id, collection audit đạt, locked test
      UNOPENED, không đưa locked test hoặc mapping fold nhạy cảm lên Colab.
- [ ] Chỉ đúng train.jsonl, validation.jsonl, dataset_manifest.json, colab-upload.sha256
      tại MyDrive/DATN/week3-data/processed; kiểm hash trước/sau upload.
- [ ] Context/provenance/receipt/raw/final flow và challenge đủ evidence kiểm lại.

10–12 run/nhóm là quota khởi đầu; chưa chứng minh model phân biệt intent hoặc đủ độ
tin cậy cho phản ứng tự động. Báo cáo phải nêu số cohort độc lập, CI và vùng chưa quan
sát được; thiếu bằng chứng giữ REVIEW/SHADOW, không biến xác suất cao thành bảo đảm.

## 19. Atomic Red Team và phạm vi mở rộng

Không cài hoặc chạy Atomic Red Team trong 40–48 run của tài liệu này. Catalog pilot hiện có
20 scenario kiểm soát được; thêm Atomic giữa đợt sẽ thay đổi phân phối dữ liệu, làm mất
tính lặp lại và có thể để lại trạng thái ngoài dự kiến trên Windows.

Nếu nhóm mở rộng ở phiên bản sau, phải lập kế hoạch thay đổi riêng: chọn chính xác test,
đọc attack/cleanup command, duyệt payload, khóa release/commit cụ thể, kiểm tra SHA-256
trước khi chạy, snapshot riêng, ghi execution log và tạo scenario/catalog mới. Không dùng
lệnh tải script từ nhánh `master` rồi thực thi trực tiếp, không dùng Atomic để bù số run,
và không trộn dữ liệu mở rộng vào cùng đợt dataset đã freeze.

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

Atomic Red Team chỉ là hướng mở rộng sau khi đợt dataset đã được đóng và bàn giao; không
phải điều kiện để hoàn thành 48 run trong catalog.
