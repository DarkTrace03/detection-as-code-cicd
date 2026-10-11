# Testing Runbook — Sigma → Sysmon → Splunk

## 1. Phạm vi

Rule mẫu phát hiện tiến trình PowerShell có command line chứa các switch encoded thường gặp. Đây là tín hiệu đáng điều tra, không tự nó chứng minh hành vi độc hại.

MITRE ATT&CK mapping: **T1059.001 — PowerShell**.

## 2. Kiểm tra nguồn log

Trước khi test, xác nhận:

- Sysmon đã được cài và cấu hình thu thập Process Create (Event ID 1).
- Splunk Universal Forwarder hoặc phương thức ingest khác chuyển Sysmon Operational log về Splunk.
- Event có các field tương ứng như `Image`, `CommandLine`, `ParentImage`, `User`.
- Sourcetype và index thực tế được xác định. Không giả định tên index/sourcetype giống mọi lab.

Ví dụ truy vấn thăm dò (thay `index`/`sourcetype` theo môi trường):

```spl
index=<your_index> sourcetype=<your_sysmon_sourcetype> EventCode=1
| table _time host Image CommandLine ParentImage User
| head 20
```

## 3. Chạy test có kiểm soát

Dùng một Windows VM riêng được phép kiểm thử. Đọc mô tả Atomic Red Team cho T1059.001 trước khi chạy bất kỳ test nào; xem prerequisite, input, attack command và cleanup. Không chạy trên máy production.

- Ghi lại thời gian bắt đầu và hostname test.
- Chọn test PowerShell phù hợp với mục tiêu; tránh test có tác động không cần thiết.
- Chạy test theo tài liệu Atomic Red Team.
- Xác nhận Sysmon Event ID 1 được tạo và Splunk ingest được.
- Chạy SPL đã chuyển đổi từ CI hoặc tái hiện logic detection bằng field mapping của môi trường.
- Lưu bằng chứng đã làm sạch thông tin nhạy cảm: event mẫu, kết quả SPL, thời gian, host, rule ID, kết luận.

## 4. Tiêu chí nghiệm thu

| Kiểm tra | Bằng chứng |
|---|---|
| YAML/metadata hợp lệ | CI xanh |
| Có MITRE technique tag | Validator/PR review |
| Fixture dương match | Pytest pass |
| Fixture âm không match | Pytest pass |
| pySigma chuyển đổi được | Artifact `.spl` trong Actions |
| Telemetry runtime tồn tại | Event Sysmon trong Splunk |
| SPL runtime trả kết quả kỳ vọng | Search result đã kiểm tra |
| Cleanup hoàn tất | Ghi nhận trong test report |

## 5. Lưu ý

- Fixture test là evaluator tối giản dành riêng cho rule mẫu, không phải parser/evaluator Sigma tổng quát.
- Sigma field names có thể cần processing pipeline hoặc field mapping theo schema thực tế.
- Không triển khai alert chỉ dựa vào việc convert thành công. Kiểm tra false positives, time range, index, sourcetype và hiệu năng SPL trước khi production.
- Không lưu token, mật khẩu, API key, dữ liệu khách hàng hoặc raw logs nhạy cảm lên GitHub.
