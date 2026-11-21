# Huấn luyện với bộ 40 run hiện có — cập nhật 21/11/2026

## Phạm vi

Bản cập nhật dành cho đúng bốn file đã đưa lên Drive từ candidate.8. Không thu
lại, đổi nhãn, xóa mẫu, chia lại dữ liệu hoặc sửa manifest/checksum cũ. Dữ liệu
vẫn do commit `16b19887c65b850db38199bad79e7b8e50c0b8db` xử lý; mã huấn luyện
được phát hành riêng. Dùng SHA đầy đủ của bản train được bàn giao, không lấy SHA
builder cũ điền vào notebook mới. Tag của bản train là `training-v1.1.0`;
SHA đầy đủ và link Colab cố định theo SHA được ghi trong bộ bàn giao đã xác minh.

Model Colab ngày 20/11 đã train và export đúng, nhưng chưa đạt chất lượng AUTO.
Archive gốc có SHA-256
`f8997667c6a310a4ef7e552d884ba9e60eefc0643bf0492090ec4746b51ef443`.
Giữ bản đó làm mốc so sánh; đây không phải thông báo đã cải thiện độ chính xác C2.

## Các thay đổi phần mềm

1. **Log trực tiếp và lưu đầy đủ.** Hiện tên giai đoạn, phiên bản runtime, từng
   test và từng candidate/model fit. Output stdout/stderr được giữ đúng thứ tự.
   Lỗi command, pytest hoặc train dừng quy trình. Ngắt trên Colab kết thúc nhóm
   tiến trình thay vì để test/train tiếp tục chạy ngầm.
2. **Môi trường cùng phiên bản với triển khai.** Kernel Colab chỉ mount Drive và
   hiển thị. Kiểm dữ liệu, EDA, Ruff, toàn bộ pytest và train dùng cùng CPython
   3.12.15 cô lập, cùng các gói và hash trong `requirements-runtime.lock`. Không
   nâng/hạ thư viện toàn cục của kernel để cố tải model. Metadata mới lưu inventory
   thư viện, hash inventory và runtime lock, SciPy, joblib và threadpoolctl.
3. **Giữ đủ nguyên nhân không đạt.** `minimum_precision_not_met` được báo riêng.
   `threshold_selection_reason` giữ kết quả chọn ngưỡng ban đầu; precision-only
   failure không bị ghi sai thành lỗi calibration. Các cổng giữ nguyên giới hạn.
4. **So với baseline đơn giản.** Bảng validation có thêm baseline xác suất từ tỷ
   lệ malicious trong TRAIN. Baseline không học từ nhãn validation. F1 khoảng
   0,667 cần được đọc cùng precision/FPR và baseline, không tự coi là kết quả tốt.
5. **Tách danh tính dữ liệu và trainer.** Source mới chỉ chấp nhận manifest cũ
   nếu đúng toàn bộ digest đã được review, đúng Git ancestor/source/policy và
   không đổi row/feature, collection contract, config, schema hay split. Giữ nguyên
   certificate/builder cũ trong metadata và ghi riêng SHA trainer thực thi. Chế độ
   v2 cũ vẫn kiểm builder/trainer như trước. Không có cờ bỏ kiểm source.

Log chất lượng và train dùng cùng entry `evidence/week3-colab-training.log` trong
archive; không chỉ giữ ba dòng báo hoàn tất. Cấu trúc model package và chín file
model bắt buộc được giữ, cùng ba candidate LR/RF/XGBoost và schema 24 feature.

## Thao tác trên Colab

1. Giữ archive/bản notebook của phiên cũ trước khi chạy một phiên mới.
2. Giữ nguyên bốn file trong `MyDrive/DATN/week3-data/processed/`:

   ```text
   train.jsonl
   validation.jsonl
   dataset_manifest.json
   colab-upload.sha256
   ```

   Không đưa `locked_test.jsonl`, raw, `.env` hoặc khóa ký lên Colab.
3. Mở notebook từ link SHA đầy đủ trong bàn giao mới và sao chép vào Drive. Dùng
   runtime Colab CPU Linux x86_64 mới; không dùng lại môi trường đang train dở.
4. Trong cell cấu hình, đặt `BRANCH = "training-v1.1.0"` và
   `EXPECTED_TRAINING_COMMIT` bằng SHA trainer mới được cung cấp. Các đường dẫn
   Drive và `RANDOM_SEED = 42` giữ nguyên. Không sửa SHA trong manifest cũ.
5. Chạy theo thứ tự. Bootstrap xác minh SHA source, checksum và manifest trước
   khi cài dependency; bản mới nhận biết đúng manifest candidate.8 được review.
6. Chờ cài môi trường. Cell in CPython **3.12.15**, core package versions và hash
   runtime lock. Nếu khác hoặc checksum không khớp, dừng; không bỏ assertion.
7. Dataset preflight phải nhận **24 TRAIN / 8 VALIDATION**, leakage audit PASS,
   locked test `UNOPENED`. EDA chỉ đọc TRAIN. Histogram được tạo trong môi trường
   cô lập và hiển thị trong notebook.
8. Cell chất lượng vẫn chạy Ruff và toàn bộ pytest. Tên test/giai đoạn xuất hiện
   trực tiếp; phần thu 40/48 run tổng hợp trong test suite có thể chạy nhiều phút.
   Không bỏ cell này hoặc chạy đồng thời nhiều lần. Train chỉ được chạy sau gate
   thành công. Nếu chủ động ngắt, đợi tiến trình kết thúc trước khi chạy lại gate.
9. Train báo từng family/candidate, calibration và nested grouped stability.
   Kết quả validation phải đọc cùng prior baseline và các gate, không chỉ F1.
10. Export archive vào `MyDrive/DATN/week3-results/model-package-week3.tar.gz`.
    Lưu SHA-256, tải archive và notebook đã chạy về thư mục phiên mới. Tên archive
    trên Drive giống phiên cũ, nên cần giữ phiên cũ riêng trước khi export mới.

Nếu bootstrap môi trường bị ngắt hoặc báo thư mục môi trường đã tồn tại, bắt đầu
runtime mới. Không sửa script để dùng một môi trường chỉ cài được một phần.
Log còn lại của phiên lỗi là bằng chứng chẩn đoán, không phải chứng nhận PASS.

## Kết quả kiểm tra và thử nghiệm C2

12 run C2 thuộc TRAIN đã replay và kiểm tra evidence trong một checkout chỉ chứa
12 run đó. Không có thư mục validation/test trong bản sao này. Cả 12 đạt kiểm tra;
chưa có bằng chứng lỗi mất log hoặc checksum gây ra kết quả model kém.

Các actor HTTP của cả hai nhãn cùng dùng curl và đường dẫn `/beacon`. Đây là dữ
liệu profile lab, không đủ để suy ra ý định chỉ từ tên chương trình hay URL.
Không đưa tên scenario, nonce, run ID hoặc parent command chứa nhãn vào feature
để tạo một classifier đạt điểm cao giả. Feature cửa sổ hành vi có thể gồm cả DNS
hợp lệ trong cửa sổ; không xóa background hợp lệ chỉ để metric đẹp hơn.

Đã khai báo trước một thí nghiệm gồm 10 cấu hình trên TRAIN, nested grouped CV
theo ba cohort. Không đọc validation/test trong thí nghiệm. Bộ candidate mở rộng
cho AP của dự đoán nested-calibrated khoảng 0,463 so với 0,433 của portfolio gốc;
FPR vẫn 1 ở ngưỡng fallback, Brier vẫn không đạt. Đây không phải bằng chứng đủ
mạnh để thay model. Các giá trị này dùng quy trình nested-calibrated khác với AP
0,547 của logistic trong inner CV đã in ở phiên cũ; không so trực tiếp hai loại.

Vì vậy không thay ba thuật toán/config đang dùng bằng một model được chọn sau
khi nhìn validation. Bản sửa cải thiện độ tái lập, khả năng quan sát, kiểm source
và sự đầy đủ của báo cáo; không tuyên bố đã sửa xong khả năng phân biệt C2.

## Điều kiện nghiệm thu vẫn còn

Split cũ có một validation cohort cho mỗi family, dưới mức ba cohort mỗi nhãn
mà cổng hiện tại yêu cầu. Chạy thêm bản lặp trong cùng scenario, đổi seed hoặc
đổi tên run không tạo nhóm độc lập. Confidence interval chưa đủ vẫn để `null` và
`automation_eligible=false`. Không đổi các điều kiện đó để tạo PASS.

Nếu tiếp tục nghiên cứu mô hình, chỉ chọn thay đổi bằng bằng chứng trên TRAIN và
giữ ranh giới đánh giá. Cần có tín hiệu/ngữ cảnh phân biệt đáng tin cậy cho C2 và
đánh giá trên đủ nhóm độc lập trước khi đề nghị tự động khóa/chặn. Tập test khóa
không dùng để chọn feature, thuật toán hoặc threshold. Bản cập nhật này không
cấp G7 mới, ký model, triển khai dịch vụ hoặc phê duyệt AUTO.

Quy trình tạo lại bộ bốn file ban đầu khi thực sự cần đối chiếu nằm tại
[hướng dẫn xử lý 40 run](training-existing-40-runs.md); không cần chạy lại quy
trình đó chỉ để dùng notebook train mới.

## Kiểm chứng bản cập nhật

Kết quả ngày 21/11/2026:

- Windows: 1,258 test đạt, 2 test bỏ qua theo nền tảng,
  không lỗi. Các nhóm bị ngắt qua đêm được chạy tiếp; nhóm test có thay đổi được
  chạy lại. Đây là báo cáo gộp các nhóm, không giả định một phiên duy nhất.
- Linux: toàn bộ cell backend thực tế của notebook tại commit
  `9289c889ceabe60770de453a1671d4fd7147ce74` đã chạy lần lượt: kiểm source,
  bootstrap, kiểm runtime, stage, preflight/EDA, Ruff, toàn bộ pytest, train,
  kiểm metadata/metric và export. 1,193 test đạt, 60 test bỏ qua theo nền tảng,
  không lỗi. Không bỏ hoặc nới assertion để đạt kết quả này.
- Môi trường Linux thử nghiệm dùng đúng image API đã pin, CPython 3.12.15 và
  31 dependency runtime đúng lock. Bản thử ban đầu thiếu `/dev/shm` đã được giữ
  log lỗi; lần chạy đầy đủ sau bổ sung mount chuẩn đã đạt. Đây là sửa harness
  kiểm chứng, không thay logic hoặc assertion của sản phẩm.
- Mount Drive, Git transport và hiển thị native kernel được thay bằng thư mục,
  bản clone và giao diện hiển thị cục bộ. Preflight, test và fit chạy thật bằng
  interpreter cô lập; không coi đây là phiên Google Colab thực tế.
- Kiểm chéo độc lập xác minh policy/source tại đúng commit trên, giữ lịch sử và
  metadata bản Colab người dùng đã lưu. Kiểm manifest thật nhận 24/8 mẫu, các
  trường hợp biến đổi metadata bị từ chối, không mở file test khóa.
- Đối chiếu lại 889 file handoff gốc, 12 file model cũ và bốn file staging:
  nguyên vẹn. Gói model gốc không bị ghi đè. Thuật toán, feature schema, cấu hình,
  nhãn, cohort, split và cổng AUTO giữ nguyên.

Báo cáo bàn giao ghi riêng SHA đã chạy toàn bộ notebook và SHA phát hành cuối.
Nếu merge/chốt tài liệu tạo SHA mới, chỉ train lại từ chính checkout mới và ghi
SHA thực thi thật; không sửa metadata của model đã xuất để đổi danh tính nguồn.
