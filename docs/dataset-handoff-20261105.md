# Đối chiếu timestamp và dataset bàn giao 04–05/11/2026

158 file đã được kiểm hash trước/sau; bản gốc không thay đổi. Tám output mới trong
`DATN_8_FILE_JSON_GUI_THINH/data/raw` khớp cả tám SHA-256 ghi trong metadata evidence.
Phần thiếu output đã được bổ sung; không còn ghi đó là lỗi chưa giải quyết.

## Hai phép đo thời gian khác nhau

Phản hồi của Kiên về độ trễ Wazuh khoảng 0,6 giây phù hợp hai record dưới đây.
Finding còn lại so sánh hai trường **ngay trong cùng sự kiện Sysmon**, không so
đồng hồ của hai máy hoặc thời gian Wazuh nhận log.

| Record | Wazuh `.timestamp` | `data.win.system.systemTime` | `data.win.eventdata.utcTime` |
|---|---|---|---|
| DNS R06, Event22, record149398 | 2026-11-04T14:35:12.645+0000 | 2026-11-04T14:35:12.0254694Z | 2026-11-03 22:42:19.330 |
| HTTP R03, Event3, record150153 | 2026-11-04T16:10:14.227+0000 | 2026-11-04T16:10:13.6110075Z | 2026-11-03 23:34:12.883 |

- DNS: Wazuh − SystemTime = **0,6195306 giây**; SystemTime − UtcTime =
  **57.172,6954694 giây**, tức 15:52:52,6954694.
- HTTP: Wazuh − SystemTime = **0,6159925 giây**; SystemTime − UtcTime =
  **59.760,7280075 giây**, tức 16:36:00,7280075.

`data.win.system.message` cũng có dòng `UtcTime` giống trường eventdata nói trên.
Mỗi record xuất hiện nhất quán trong `windows_events.jsonl`, `wazuh_archives.jsonl`
và `archive_capture.jsonl`; không phải field do script báo cáo tạo ra.
Đã parse riêng JSON trong **`full_log`** của cả hai record: `win.system.systemTime`
và `win.eventdata.utcTime` vẫn đúng hai giá trị trong bảng. Vì vậy mâu thuẫn không
chỉ nằm ở việc chọn trường `data.win` hoặc cách hiển thị báo cáo. Chưa có native
EVTX để kết luận agent, endpoint hay chặng nào trước export đã tạo ra chênh lệch.

Đường dẫn tương đối trong gói:

- `evidence/PILOT-C2-BENIGN-DNS-R06-20261104/windows_events.jsonl`, dòng2.
- `evidence/PILOT-C2-MALICIOUS-HTTP-BEACON-R03-20261104/windows_events.jsonl`, dòng9.

Hai digest của chính các file này lần lượt:

```text
a6cb5a668e5cde9a85381866e75665a2ebb4d7094411e8fac74c566f98557918
937f5fc167112f0fd3db732e93e3c1e76726fa9d49e7ce5f6b71499f9e38d51b
```

Trên SOC-AI, xem trực tiếp hai record, không chạy finalize hay sửa dữ liệu:

```bash
cd "$HOME/datn-ai-soar-v3"
jq -c 'select(.data.win.system.eventRecordID=="149398") |
 {id, timestamp, systemTime:.data.win.system.systemTime,
 utcTime:.data.win.eventdata.utcTime, message:.data.win.system.message}' \
 evidence/scenario-runs/PILOT-C2-BENIGN-DNS-R06-20261104/windows_events.jsonl
jq -c 'select(.data.win.system.eventRecordID=="150153") |
 {id, timestamp, systemTime:.data.win.system.systemTime,
 utcTime:.data.win.eventdata.utcTime, message:.data.win.system.message}' \
 evidence/scenario-runs/PILOT-C2-MALICIOUS-HTTP-BEACON-R03-20261104/windows_events.jsonl
```

Runbook yêu cầu Sysmon native clocks lệch không quá5 giây; cấu hình mỗi draft cũng
đặt maximum_skew_seconds=5. Không dùng phép đo arrival lag để thay gate này.
Sysmon lưu timestamp event theo UTC, theo
[tài liệu Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon);
không tự cộng/trừ timezone hiển thị cho `UtcTime` để làm hai giá trị khớp nhau.
Event1 tạo process trong cùng run có hai timestamp gần nhau; chưa thể từ đó kết
luận timestamp nào của Event3/22 sai hoặc nguyên nhân là NTP, Sysmon, VM pause/resume,
replay hay transform. Không sửa raw để chọn một đồng hồ theo giả định.

## Tiêu chí full-capture parity

`ml.scenario_collection._verify_full_capture_parity` thực hiện:

1. Giữ từng occurrence raw trong `archive_capture.jsonl`, không xóa native ID trùng.
2. Chọn tất cả record của hai configured agent trong bucket UTC5 phút của action;
   không dùng nhãn, scenario nonce hoặc allowlist action để lọc background.
3. Replay qua chính `aggregate_wazuh_alerts` với frozen source/taxonomy/baseline.
4. Với asset/family của incident phải có một candidate; 24feature, context status,
   revision và observation quality phải tái tạo đúng.

Code gốc3.7 tạo thêm account group từ Windows background do decoder fallback.
Patch phân family Kiên gửi giải quyết nguyên nhân này: cả hai account capture
đã PASS parity khi áp dụng quy tắc đã review. Bản sửa hiện hành giữ raw và đưa các
record authentication thiếu thông tin vào account PARTIAL; không xóa record để PASS.

Hai account có1 và2 selected Windows events; Suricata bằng0 là phù hợp kịch bản
Security4624/4625. Không yêu cầu thêm EVE vào account chỉ để đủ số dòng.

Chữ `VALID`/`COMPLETE` do source cũ tạo không chứng minh supplementary native-clock
gate đã chạy. Bản sửa kiểm clock ở C2 được quy thuộc và dữ liệu destination history
dùng để enroll. Background Sysmon của family khác vẫn được bảo toàn; không tự biến
nó thành count account hoặc kết luận các Security event đúng đã hỏng.

## Thu bằng chứng native để định vị nguyên nhân

Chưa có EVTX native trong gói, nên chưa thể phân biệt lỗi phát sinh trên endpoint
với lỗi forwarding/decoder/export. Sau cập nhật source đã pin, copy helper
`scripts/Export-DatnSysmonClockEvidence.ps1` từ đúng commit, kiểm hash như các runner.
Trên Windows11 PowerShell Administrator, chọn thư mục mới mỗi lần:

```powershell
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$command = "& 'C:\DATN\Export-DatnSysmonClockEvidence.ps1' " +
  "-OutputDirectory 'C:\DATN\clock-forensics-$stamp' " +
  "-EventRecordIds @(149398,150153) -MaxEvents 100"
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command $command
if ($LASTEXITCODE -ne 0) { throw 'Forensic export incomplete; preserve partial output and error' }
```

Helper chỉ đọc event/service/clock; giữ XML native, EVTX được chọn, timestamp gốc,
record IDs và digest. Không xóa event log, không sửa clock, không restart dịch vụ.
Nếu record đã rotate, giữ trạng thái thiếu và tìm EVTX backup; không tạo record thay.
EVTX được export theo chính các ID đã đọc, chia lô16 ID và kiểm lại XML/ID sau export,
không dùng một query rộng khác với bộ đã kiểm. Việc chia lô giữ query trong giới hạn
compound XPath của [Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events).

Đối chiếu cùng recordID + provider + ProcessGuid:

- Native XML đã có hai timestamp mâu thuẫn: điều tra endpoint/Sysmon/VM chronology.
- Native XML thống nhất nhưng Archives khác: so từng chặng agent → manager → decoder
  → export; giữ cấu hình và raw trước/sau ở mỗi chặng.
- RecordID trùng nhưng provider/GUID khác: chưa phải cùng record; đối chiếu đúng
  channel/host và lần reset log trước khi kết luận.

Chỉ đổi cấu hình/restart/cập nhật sau khi đã lưu bằng chứng và kết thúc run active.
Sau xử lý, tạo event mới chứng minh clocks thống nhất, enrollment revision mới và
pilot ID/bucket mới. Không ghi lùi metadata hoặc sửa hash của evidence cũ.

Bốn run là purpose pilot, không phải quota trainable. Sửa source và bổ sung tám
file không tự mở G7 hoặc chứng nhận model có thể phân biệt đầy đủ benign/malicious.
