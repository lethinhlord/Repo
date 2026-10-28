# Phương án xử lý lỗi và vùng xám trước bàn giao Kiên

Ngày lập: 28/10/2026. Repo đối chiếu: `D:\Repo`.
Baseline được rà soát: `ee7f4f6a56c355ff855802671db4d9aabc5412fe`.
Trạng thái: **phương án triển khai và nghiệm thu; chưa phải bản sửa đã hoàn tất**.
Task list: `tasks/todo.md` trong cùng thư mục tài liệu này. Không ghi đè kế hoạch cũ
trong `D:\Repo\tasks`, không thay `Kiên.txt` hoặc commit baseline trong lượt tổng hợp.

## 1. Kết quả cần đạt

Có 7 lỗi kỹ thuật H01–H07 đã xác nhận và 7 khoảng thiếu/giới hạn G01–G07 trong thiết
kế kịch bản. Hai nhóm cần cách xử lý khác nhau:

1. Lỗi phần mềm phải có test tái hiện, bản sửa và test hồi quy đạt.
2. Thiếu dữ liệu hoặc context phải bổ sung nguồn quan sát thật, thu lại và đánh giá.
3. Nếu hai ý định vẫn có cùng toàn bộ thông tin mà hệ thống quan sát được, kết quả
   đúng về vận hành là REVIEW/chưa đủ bằng chứng. Không thể hứa loại bỏ mọi vùng xám
   bằng thêm run, thêm model hoặc tăng ngưỡng xác suất.

Mục tiêu nghiệm thu là dữ liệu đúng, feature offline/online thống nhất, khả năng
phân biệt được đo trung thực và quyết định thiếu bằng chứng được chặn trước phản ứng
mạnh. Giữ hệ thống SHADOW trong giai đoạn này.

## 2. Sửa bảy lỗi kỹ thuật

### H01 — Quyền sử dụng bucket và tính thống nhất của cửa sổ quan sát

**Phạm vi:** collector, feature state, auditor và hướng dẫn.

- Dùng chung định nghĩa cửa sổ UTC và khóa aggregation với online. Khóa hiện hành
  có asset, family và source discriminator cho account; không tự bỏ discriminator.
- Ghi reservation bền vững, có thao tác chiếm chỗ nguyên tử; không chỉ nhớ trong RAM.
  Trong lab có thể áp dụng chính sách chặt hơn: một hoạt động thu trên target trong
  mỗi bucket 5 phút. Tiền kiểm/canary cũng phải kết thúc trước bucket thu chính thức.
- `begin-action --wait-for-window` đợi bucket sạch kế tiếp nếu bucket đã dùng. Một
  run đã bắt đầu hành động rồi abort/quarantine vẫn làm bucket đó bị sử dụng; không
  trả bucket cho run mới vì telemetry cũ còn tồn tại trên online.
- Khôi phục reservation từ receipt hợp lệ sau restart; trạng thái mất/hỏng phải được
  phát hiện. Auditor phát hiện hai run/nhãn cùng chiếm cửa sổ không hợp lệ.
- Bổ sung capture toàn cửa sổ và replay cùng event set qua collector và pipeline
  online. Nonce dùng nhận diện kịch bản/ground truth, không được giúp offline loại
  traffic mà online vẫn tính. Có traffic nền ảnh hưởng vector thì phải kiểm chứng
  cách xử lý hoặc loại run theo lý do rõ ràng.

**Nghiệm thu:** ca hai run cách 175 giây phải đợi sang bucket mới; restart, abort,
quarantine, canary và hai process tranh reservation không tạo va chạm. Cùng raw
capture có cùng số incident, vector và quality flags ở offline/online. Không nghiệm
thu chỉ bằng fixture đã lọc sẵn theo nonce.

### H02 — Backup di động và provenance bất biến

- Tách thông tin nguồn lúc chạy (máy, absolute path, cursor, inode/device, commit)
  khỏi tham chiếu nội dung portable (snapshot và SHA-256).
- Validator offline kiểm lại contract gốc theo origin đã ghi nhận, rồi resolve file
  evidence trong thư mục restore. Không resolve origin theo home mới rồi so sai.
- Kiểm path nằm trong gói được phép, snapshot/schema/taxonomy/catalog/receipt và raw
  hash; không nới checksum hay tự viết lại source contract khi restore.
- Contract mới có revision; không trộn dữ liệu/contract cũ vào đợt thu mới.

**Nghiệm thu:** restore sang thư mục khác, user home khác và bản sao trên máy khác
vẫn VALID; đổi raw hoặc snapshot một byte bị từ chối. Không yêu cầu source Archives
đang tồn tại ở máy khôi phục offline. Số run và checksum sau restore bằng bản gốc.

### H03 — Canary đúng thao tác và đúng LogonType

- Hướng dẫn đăng xuất rồi đăng nhập mới bằng mật khẩu của đúng local user cho
  LogonType 2. Nếu màn hình hiện phiên khóa thì quay về quy trình sign-out, không
  coi unlock/PIN là phép thử tương đương.
- Canary SMB kiểm riêng LogonType 3, source Kali, user đích và cả lần sai/lần đúng.
- Kiểm membership/quyền logon hiệu lực và trạng thái lockout trước khi chạy; Enabled
  chưa đủ. Ghi lý do đăng nhập bị từ chối thay vì chẩn đoán nhầm agent.
- Dùng cursor và thời gian sự kiện mới để ngăn lấy log cũ làm bằng chứng.

**Nghiệm thu:** Event Viewer/Get-WinEvent và Wazuh Archives cùng xác nhận 4624/4625,
đúng user/type/source sau cursor. Log unlock type 7 không được tính thành console
type 2. Quy ước dựa trên [Microsoft Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).

### H04 — Kiểm tra hiệu lực firewall đối với TCP 445

- Lọc đúng protocol TCP hoặc Any thực sự bao gồm TCP, port/range chứa 445; xét
  application, service, profile, interface và địa chỉ đích/nguồn hiệu lực.
- Xử lý cả CIDR/range địa chỉ, không chỉ chuỗi Any hoặc LocalSubnet. Không coi rule
  UDP/protocol 41 hay ứng dụng không phục vụ SMB là bằng chứng broad SMB.
- Kiểm trạng thái firewall và cấu hình đang áp dụng; giữ rule hẹp cho Kali trên
  mạng lab. Trường hợp tĩnh chưa xác định được trả INCONCLUSIVE để kiểm thực tế.
- Bổ sung phép thử kết nối TCP 445 từ Kali được phép và nguồn không được phép, tới
  cả IP data/management liên quan. Không tắt hàng loạt rule để vượt preflight.

**Nghiệm thu:** UDP/protocol 41 không báo nhầm; broad TCP 445 thật bị chặn; Kali được
phép, nguồn khác bị chặn. Có bằng chứng Windows Firewall GUI/cấu hình và kết nối thật.

### H05 — Chuẩn hóa IP trước mọi phép tính feature

- Dùng chung `normalize_ip` tại lúc tạo observation cho cả collector và inference,
  bao gồm source/destination, mapped IPv6 và các dạng IPv6 tương đương.
- Giữ nguyên raw log; hash và canonicalization của envelope không thay cho normalize
  đối tượng mạng trước khi đếm. Không chuẩn hóa bằng cách sửa chứng cứ gốc.

**Nghiệm thu:** run bốn kết nối xen IPv4/mapped IPv6 có cùng một đích ở cả hai đường;
mọi feature và missing/quality flags khớp. IP sai kiểu bị từ chối theo contract.

### H06 — Counter flow, liên kết DNS và thời gian đến muộn

- Tạo phép hợp nhất dùng chung theo sensor instance/capture epoch + flow_id, kiểm
  thêm tuple/protocol để tránh gộp flow khi sensor restart/tái sử dụng ID.
- Alert/http/dns/flow của một flow là nhiều record liên quan; counter tích lũy phải
  lấy một lần theo quy tắc counter cuối hợp lệ, không cộng mọi snapshot counter.
- DNS query/response được liên kết tới flow_id; flow cuối không cần chứa lại rrname.
  Counter reset/bất nhất, thiếu chiều trả lời hoặc thiếu final flow có quality flag.
- Tách thời gian hoạt động `flow.start/end` khỏi timestamp phát log và ingest_time.
  Flow cuối đến muộn nhưng chứng minh hoạt động trong cửa sổ phải cập nhật đúng
  cửa sổ gốc; không tạo thêm incident thuộc bucket phát log.
- Giữ raw capture trước lọc và bảng tham chiếu record được chọn/lý do chọn, kèm hash
  và cursor. Gói evidence phải đủ dựng lại phép chọn, không chỉ lưu phần đã giữ.
- Chốt grace period bằng độ trễ đo trên pilot, có giới hạn. Trước khi đủ bằng chứng,
  decision là PARTIAL/REVIEW. Revision đến muộn phải đi qua dedup/outbox đúng revision.
- Với flow kéo qua nhiều bucket, tổng counter cuối không cho biết chính xác byte
  từng bucket. Cần snapshot/delta đủ thông tin hoặc đánh dấu feature thiếu. Nếu chưa
  giải quyết được trước đợt thu, bỏ feature byte đó khỏi vector train mới theo schema
  đã version hóa; giữ counter raw để nghiên cứu. Không điền 0 rồi báo COMPLETE.

**Nghiệm thu:** PCAP audit HTTP=654 byte và DNS=202 byte, không cộng 1.146/93 như cũ;
alert lặp, record đảo thứ tự, DNS response, final-flow đến muộn và sensor restart đều
được kiểm. Flow kéo qua bucket không nhận tổng lifetime vào hai bucket. Cách liên kết dựa
trên [Suricata 8.0.7 EVE](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html).

### H07 — Tách audit tiến độ khỏi gate nghiệm thu cuối

- Bổ sung hai chế độ rõ ràng, ví dụ `--mode progress` và `--mode final`; đây là CLI
  đề xuất, chưa có trong baseline hiện tại.
- Progress: chỉ tiếp tục khi integrity/provenance của run hiện có đều đạt. Thiếu
  quota hoặc coverage dự kiến trả COLLECTING; các kiểm định thống kê chưa đủ coverage
  phải ghi PENDING, không giả vờ đã đạt hoặc dừng vô hạn trước khi đủ mẫu.
- Final: thiếu quota/coverage, run hỏng, collision hoặc kiểm định chưa giải quyết đều
  chặn READY/TARGET_MET và builder. Lỗi checksum không bao giờ thành thiếu quota.
- Viết nhánh xử lý exit/status đúng cho Bash `set -e`; không dùng `|| true` bao trùm.

**Nghiệm thu:** sau một run VALID có thể cleanup và thu tiếp; sửa checksum phải dừng;
chế độ final trên cùng tập thiếu quota vẫn thất bại. Cổng cuối có đủ test mới, không
chỉ chạy danh sách test cũ trong verify script.

## 3. Xử lý bảy vùng xám bằng dữ liệu và context

Các nội dung dưới đây là thay đổi thiết kế cần kiểm chứng, không phải bảy tỉ lệ sai
đã đo của model. Ground truth mô phỏng được ghi riêng trước run; input ML chỉ lấy
những gì hệ thống thực tế quan sát được ở thời điểm quyết định.

| Mã | Vấn đề | Sửa kịch bản/thu thập | Bằng chứng cần thêm hoặc cách xử lý |
|---|---|---|---|
| G01 | Benign remote typo giống compromise SMB | Thêm remote benign có 1 sai → 1 đúng và các cặp malicious có count/nhịp tương đương | Lịch sử user–source–host, context thiết bị, chuỗi sau logon; nếu vẫn cùng quan sát thì REVIEW |
| G02 | Người quên mật khẩu/bỏ cuộc giống brute-force | Thêm benign 3/6 lần sai không success; malicious có nhịp chậm và nhiều mức count | Nhịp dài hạn, fan-out, nguồn, lịch sử; không gán malicious chỉ vì thiếu 4624 |
| G03 | Mật khẩu hợp lệ đúng ngay giống chủ tài khoản | Thêm valid-credential simulation không có thất bại và benign đăng nhập từ nguồn mới | Context truy cập và hậu đăng nhập; một 4624 thiếu context không đủ kết luận |
| G04 | Helpdesk nhiều user giống password spray | Thêm tác vụ quản trị nhiều tài khoản và spray có độ phủ tương đương | Hồ sơ công việc độc lập, nguồn thực hiện, lịch sử user–host; manifest approval không là feature |
| G05 | Health polling giống HTTP beacon | Cho hai nhãn cùng có nhịp nhanh/chậm/không đều, count chồng lấp, shared endpoint/path/tool | Process provenance, parent-child và context đích; không dùng nhịp 15/30 giây làm đại diện cho ý định |
| G06 | DNS hợp lệ giống DNS beacon | Biến thiên count/nhịp/độ dài/tỉ lệ query độc nhất ở cả nhãn, tránh suffix dành riêng cho nhãn | Process chain, query/response metadata và context domain; chuỗi “beacon” và SID lab chỉ phục vụ mô phỏng/định tuyến thu |
| G07 | Tải file/retry hợp lệ giống staged-transfer | Cùng công cụ, tên file trung tính, port/payload size cân bằng; thêm retry hợp lệ | Context trước/sau tải và nguồn gốc tiến trình; download marker đơn lẻ giữ là mô phỏng hành vi, chưa chứng minh C2 |

Tài khoản hợp lệ có thể bị lạm dụng và C2 có thể hòa vào traffic ứng dụng thông
thường: [MITRE T1078](https://attack.mitre.org/techniques/T1078/),
[T1071](https://attack.mitre.org/techniques/T1071/). Tải file trong hoạt động đối thủ
được mô tả ở [T1105](https://attack.mitre.org/techniques/T1105/); mô phỏng tải marker
không tự chứng minh nội dung file hoặc ý định là độc hại.

### Nguyên tắc tránh tạo vùng xám/leakage mới

- Dùng pool tài khoản lab có vai trò thay đổi/cân bằng, không dùng riêng một username,
  host, IP, filename, domain, port, script path hay nonce cho một nhãn trong ML.
- Đưa cả hai nhãn qua các mức count/nhịp/payload/endpoint tương đương; giữ ràng buộc
  an toàn lab và provenance, không phải làm mọi giá trị feature giống nhau.
- Taxonomy `/beacon`, `/stage.bin`, `beacon.datn.test` hiện là chỉ dấu chuỗi lab.
  Gỡ chúng khỏi vai trò chứng cứ độc lập của ý định; feature hành vi mới phải có nguồn
  đo và đối chứng. Việc bỏ chuỗi không đồng nghĩa bỏ log hoặc mất attribution.
- Baseline/context phải được thu độc lập trước các run được gán nhãn và đóng băng
  revision. Không dùng nhãn của run, kết quả tương lai hoặc locked test để làm baseline.
- Không thêm `authorized=true` vào mọi benign và `false` vào mọi malicious từ manifest
  rồi gọi đó là feature giải quyết vùng xám. Context phê duyệt chỉ dùng khi có nguồn
  quản trị độc lập, tồn tại trước sự kiện và cũng sẵn có trong inference thực tế.

## 4. Contract dữ liệu và feature phải sửa đồng bộ

Đề xuất chốt một revision feature mới, ví dụ `features-v3`, trước thu chính thức.
Tên này là đề xuất, chưa được triển khai. Thay đổi ngữ nghĩa/count/field phải kéo theo
schema, manifest, collector, API, trainer, model package, notebook và tài liệu tương ứng.

| Thành phần đề xuất | Nguồn đo | Thiếu nguồn thì xử lý |
|---|---|---|
| `new_source_for_user`, `new_host_for_user` | Lịch sử user–host–source đã đóng băng, as-of trước sự kiện | UNKNOWN, không coi mặc định là mới hay lành |
| Thống kê authentication theo cửa sổ ngắn/dài | Security log đủ thời gian, trạng thái lịch sử cùng thuật toán online | PARTIAL nếu thiếu lịch sử; không dựng thông tin quá khứ từ seed/label |
| Process lineage và nguồn gốc script/binary | Sysmon Event 1 có ProcessGuid/ParentProcessGuid; nguồn chữ ký/hash nếu đã cấu hình và kiểm chứng | Không suy chữ ký từ tên file; thiếu trường bắt buộc → REVIEW |
| Context destination/domain/process | Inventory/baseline độc lập, phiên bản và TTL rõ ràng | UNKNOWN không bằng malicious hay benign |
| Metadata DNS/HTTP và counter flow | EVE thật đã correlation/dedup theo contract | Thiếu/mâu thuẫn được thể hiện qua validity mask/quality flags |
| Chuỗi hành vi trước/sau sự kiện | Liên kết user/logon/process/network theo khóa nguồn thực tế | Không nối hai tiến trình/sự kiện chỉ vì gần thời gian |

Đây là danh sách ứng viên, không thêm tất cả vô điều kiện. Mỗi feature phải có:
định nghĩa, nguồn, đơn vị, cửa sổ/as-of, cách tính chung, quy tắc missing và test parity.
Chỉ đưa vào model sau khi pilot đo được và kiểm chứng giá trị trên validation.

Tách bốn phần dữ liệu:

1. **Raw capture:** nguyên bản, cursor, SHA-256 và bảo quản đủ để replay.
2. **Context snapshot:** nguồn/revision/thời điểm tồn tại, tính toàn vẹn và TTL.
3. **Derived features:** schema/version/order, validity và tham chiếu raw/context.
4. **Ground truth:** nhãn, mục đích kịch bản, operator/approval record; tách khỏi input ML.

Không dùng model features-v2 với vector mới. Model package sai revision hoặc context
không phù hợp phải bị từ chối/REVIEW; không fallback sang model cũ để làm xanh health.
Train và serving phải dùng cùng phép biến đổi như nguyên tắc của
[scikit-learn](https://scikit-learn.org/stable/common_pitfalls.html).

## 5. Dataset, auditor và đánh giá phải hỗ trợ ca khó

### Tách dữ liệu theo mục đích ngay từ trước khi chạy

- **Baseline enrollment:** tạo context tin cậy; không dùng nhãn tương lai.
- **Trainable:** có nguồn quan sát đã xác định và phục vụ bài toán nhị phân đã công bố.
- **Ambiguity challenge:** cặp ý định khác nhau nhưng quan sát giống/khó phân biệt;
  giữ ground truth riêng để kiểm hành vi REVIEW và báo cáo hạn chế.
- **Pilot nghiệm thu:** kiểm đường thu/restore/parity; không copy làm dữ liệu train.

Purpose được đóng băng và kiểm provenance. Không chuyển mẫu model đoán sai sang
challenge sau khi xem kết quả để nâng metric. Runtime không được đọc purpose/nhãn
để biết phải REVIEW; quyết định phải dựa vào quan sát/context/quality có thật.

### Điều chỉnh auditor có kiểm soát

- Giữ kiểm integrity/provenance, duplicate, quota, schema, parity và bucket như gate cứng.
- Cặp khác nhãn trùng vector trong trainable phải dừng để kiểm ground truth/feature;
  không tự đổi nhãn hoặc thêm nonce/ID làm feature để phá collision.
- Challenge có thể giữ cặp không phân biệt được ở bộ riêng, có thống kê và kỳ vọng
  REVIEW; builder không âm thầm đưa chúng vào train hoặc xóa khỏi báo cáo.
- Phân tách hoàn hảo một feature trên pilot nhỏ là dấu hiệu phải điều tra, không tự
  chứng minh leakage. Phân biệt feature hợp lệ có nguồn độc lập với fingerprint của
  kịch bản. Nếu cần đổi gate hiện tại, phải có ADR, counterfactual và holdout chứng
  minh; không thêm cờ bỏ qua để làm dataset READY. Cho tới khi chốt bằng chứng, gate
  cuối vẫn chặn. Mẫu bị loại/ngoại lệ phải xuất hiện trong báo cáo.

### Split và metric

- Giữ các lần lặp cùng scenario, cùng session và biến thể ghép cặp gần nhau trong
  cùng partition bằng cohort/group rõ ràng. Nếu cohort chứa cả hai nhãn, sửa thuật
  toán chia group tương ứng; không giả định mỗi cohort chỉ có một stratum như code cũ.
- Fit encoder/scaler/imputer và học baseline từ train hoặc nguồn enrollment độc lập
  hợp lệ, không từ validation/locked test. Context của sự kiện không đọc dữ liệu tương lai.
- Dùng validation chọn feature/threshold và kiểm calibration; locked test giữ nguyên
  UNOPENED đến mốc kế hoạch. Tập challenge dùng phát triển khác tập nghiệm thu cuối.
- Báo precision/recall/FPR/FNR theo từng family và scenario, CI theo đơn vị group độc
  lập, confusion matrix, calibration, latency và tỷ lệ REVIEW/coverage. Không báo
  accuracy cao bằng cách review mọi mẫu hoặc bỏ mọi mẫu khó.
- Phân biệt lỗi dự đoán ML và quyết định policy. REVIEW không được tự tính là dự đoán
  benign đúng; policy không hành động không có nghĩa model FPR=0.
- Giữ các ngưỡng cấu hình hiện tại khi chưa có quyết định có bằng chứng để thay:
  precision tối thiểu 0,90; Brier tối đa 0,20; ECE tối đa 0,15. Thiếu group/CI thì
  chưa kết luận đủ điều kiện automation, không biến thiếu dữ liệu thành CI=0.

## 6. Policy xử lý phần vùng xám còn lại

- Tái sử dụng đường REVIEW hiện có và mở rộng lý do: context_missing/stale,
  observation_insufficient, ambiguous_behavior, feature_mismatch, incomplete_flow,
  unsupported_profile hoặc model chưa đủ bằng chứng.
- Quyết định phải lưu raw/context/model/feature/policy revision và lý do có thể kiểm
  tra lại. Probability cao không được vượt qua missing context hoặc provenance sai.
- Record đến muộn hoặc context đổi tạo revision có kiểm soát; replay không gửi lại
  thông báo cũ, feedback không tính trùng và không gắn vào dự đoán revision khác.
- Giữ `strong_actions_enabled=false`. Context allowlisted không mặc định an toàn;
  vẫn kiểm hành vi bất thường vì nguồn/tài khoản được tin cậy có thể bị lạm dụng.

## 7. Thứ tự triển khai

1. **Chốt contract và phạm vi:** nguồn raw/context, bucket, flow time, revision,
   purpose/cohort và điều kiện REVIEW; giữ bản tái hiện RED.
2. **Sửa nền thu:** H01/H02/H05/H06; kiểm replay/parity, late arrival và backup.
3. **Sửa vận hành:** H03/H04/H07; chứng minh chạy tiếp được khi đang thu và chặn dữ
   liệu hỏng. Sau checkpoint này mới chạy pilot kỹ thuật.
4. **Bổ sung context + scenario đối chứng:** G01–G07, feature revision mới, taxonomy
   trung tính và baseline enrollment. Cập nhật trainer/runtime/notebook đồng bộ.
5. **Sửa auditor/builder/REVIEW:** purpose/cohort, challenge, version gates và metric;
   kiểm end-to-end n8n/API/outbox/feedback.
6. **Nghiệm thu bốn VM:** canary, console account, SMB, HTTP, DNS hai nhãn, restore
   và thiếu context/telemetry. Lưu minh chứng thật trước khi chốt baseline thu mới.
7. **Bàn giao bản đã nghiệm thu:** merge thay đổi đã kiểm, đồng bộ Kiên.txt/runbook
   cùng hash, ghi SHA mới; sau đó thu chính thức, audit final và build Colab.

Các chặng 1–5 là công việc triển khai; không đánh dấu hoàn tất chỉ vì có tài liệu này.

Phân công theo vai trò đã thống nhất: Thịnh phụ trách contract/feature, code AI/SOAR,
auditor, training/Colab và bộ kiểm; Kiên phụ trách cấu hình bốn VM, telemetry thật,
pilot, thu dữ liệu và evidence. Thịnh chuẩn bị công cụ đã test cùng hướng dẫn; Kiên
không phải tự đoán cách sửa Python hoặc tự sửa schema/hash khi công cụ báo lỗi.
Kết quả pilot và SHA triển khai được hai bên đối chiếu trước thu chính thức.

## 8. Số lượng dữ liệu và tài nguyên

- Bốn VM hiện có vẫn đủ cho phạm vi thu lab: Kali, Windows 11 target, Wazuh/SOC-AI,
  Suricata. Bổ sung feature không tự yêu cầu thêm DC; bài toán domain/AD là phạm vi
  khác và phải công bố chưa được bao phủ nếu chưa triển khai.
- 10–12 run/nhóm là pilot 40–48 trainable run khi catalog vẫn phù hợp quota hiện tại.
  Baseline, pilot kỹ thuật và challenge bổ sung được thống kê riêng.
- Nếu tăng số scenario hoặc cần thêm group độc lập, phải tính lại quota và split,
  không nhét nhiều hành vi khác nhau vào một scenario_id để lách yêu cầu diversity.
  Chưa có dữ liệu mới nên chưa thể bảo đảm 40–48 run đủ đánh giá hiệu năng thật.
- Thu mới hoàn toàn theo yêu cầu của Thịnh; không nhập dataset cũ vào tập mới và
  không ghi đè chứng cứ cũ đã lưu để điều tra.

## 9. Điều kiện chốt bàn giao

1. H01–H07 có test hồi quy và bằng chứng đóng; năm probe lỗi cũ chuyển từ fail sang
   pass mà không hạ chất lượng assertion. Toàn suite, lint, dependency/schema đạt.
2. Source capture → feature offline/online → Colab input cùng revision; schema/model
   không phù hợp bị chặn. Raw/context hash và immutable origin được kiểm khi restore.
3. Pilot thật trên bốn VM chứng minh từng kênh; missing context/late flow/ambiguous
   input được REVIEW đúng lý do. Ảnh toàn màn hình host có VMware/công cụ thật, không
   cắt cửa sổ, có hostname/đồng hồ và file gốc theo yêu cầu báo cáo của Thịnh.
4. Kiên.txt, runbook, script và baseline commit đồng bộ; tài liệu ghi rõ câu lệnh
   hiện có và câu lệnh đã triển khai, không đưa lệnh đề xuất chưa có vào quy trình.
5. Thu chính thức bắt đầu sau các cổng trên; dataset final đạt quota/integrity và
   builder ra manifest có purpose/cohort/hash đúng. Chỉ TRAIN/VALIDATION và manifest
   được gửi Colab theo quy trình; locked test giữ tại nơi tin cậy.

Kết quả bàn giao cần gồm bản source có SHA chốt, hướng dẫn chuẩn, danh sách công cụ/
phiên bản, bộ test kiểm dataset, catalog + baseline/context spec, gói minh chứng pilot,
biên bản backup/restore và báo cáo những profile vẫn chưa đủ bằng chứng phân biệt.

## 10. Căn cứ và vị trí triển khai

Lỗi đã tái hiện và phạm vi probe:
`D:\DataCodex\2026-10-05\c\outputs\handoff-audit-20261028\BAO_CAO_RASOAT_BAN_GIAO_KIEN.md`.
Phân tích G01–G07:
`D:\DataCodex\2026-10-05\c\outputs\handoff-audit-20261028\VUNG_XAM_BON_NHOM_KICH_BAN.md`.

Module hiện có: `ml/scenario_collection.py`, `ml/telemetry.py`,
`ml/behavior_features.py`, `ml/feature_pipeline.py`, `ml/dataset_audit.py`,
`ml/build_dataset.py`, `ml/dataset.py`, `ml/training.py`, `ml/models.py`,
`api/app/feature_state.py`, `api/app/contracts.py`, `api/app/risk_policy.py`.
CLI/notebook: `scripts/scenario_session.py`, `scripts/audit_dataset.py`,
`scripts/verify_collection_dataset.sh`, `scripts/export_week2_contracts.py`,
`notebooks/week3_train_colab.ipynb`.

Các tên CLI/field/revision mới trong bản này là thiết kế đề xuất. Tài liệu này không
khẳng định chúng đã tồn tại ở baseline được rà soát.
