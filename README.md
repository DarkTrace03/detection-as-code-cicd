# Detection-as-Code CI/CD Pipeline

Pipeline mẫu kiểm thử Sigma detection rules và chuyển đổi sang Splunk SPL bằng GitHub Actions + pySigma.

> **Trạng thái:** starter lab. CI kiểm tra cấu trúc YAML, metadata, logic fixture đơn giản và khả năng chuyển đổi Sigma → SPL. Đây chưa phải bằng chứng rule phát hiện được trên Splunk thực tế.

## Mục tiêu

- Quản lý detection rule dưới dạng code, review bằng Pull Request.
- Kiểm tra YAML và metadata bắt buộc.
- Kiểm tra tag MITRE ATT&CK theo quy ước Sigma (`attack.t####`).
- Chạy unit test trên dữ liệu fixture dương/âm.
- Chuyển đổi Sigma sang Splunk SPL với pySigma.
- Lưu kết quả kiểm thử và bằng chứng validation trong GitHub Actions.

## Kiến trúc

`Sigma YAML → GitHub Actions → validation + fixture tests → pySigma/Splunk backend → SPL artifact`

Luồng kiểm chứng runtime nên được thực hiện trong lab riêng:

`Atomic Red Team (authorized test host) → Sysmon → Splunk → chạy SPL → xác nhận alert/hit → lưu report`

Không chạy Atomic Red Team trên GitHub-hosted runner. Một số atomic test thay đổi hệ thống và cần quyền quản trị; chỉ chạy trên máy lab được phép và đọc hướng dẫn cleanup trước khi thực thi.

## Cấu trúc repository

```text
detection-as-code-cicd/
├── .github/
│   └── workflows/
│       └── detection-ci.yml
├── rules/
│   └── windows/
│       └── proc_creation_suspicious_powershell.yml
├── tests/
│   ├── fixtures/
│   │   ├── powershell_positive.json
│   │   └── powershell_negative.json
│   └── test_rules.py
├── scripts/
│   └── validate_rules.py
├── docs/
│   └── TESTING-RUNBOOK.md
├── .gitignore
├── requirements-dev.txt
└── README.md
```

## Yêu cầu

- Python 3.11+
- Git
- GitHub account
- (Giai đoạn runtime) Windows lab có Sysmon và Splunk nhận được telemetry phù hợp

## Chạy local trên Windows CMD

Mở CMD tại thư mục repository:

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python scripts\validate_rules.py
pytest -q
sigma plugin install splunk
sigma convert -t splunk -p sysmon rules\windows\proc_creation_suspicious_powershell.yml
```

Nếu máy chưa có Python 3.11, cài Python 3.11 hoặc dùng phiên bản Python được các package cài đặt hỗ trợ. Nếu lệnh `sigma plugin install splunk` báo backend đã cài, có thể bỏ qua.

## Quy trình GitHub

1. Tạo repository mới tên `detection-as-code-cicd` trên GitHub.
2. Đặt repository ở chế độ Public nếu muốn dùng làm portfolio; kiểm tra kỹ không commit secrets, log nội bộ hoặc dữ liệu nhạy cảm.
3. Giải nén bộ project, mở CMD trong thư mục `detection-as-code-cicd`.
4. Chạy các lệnh:

```bat
git init
git add .
git commit -m "feat: add detection-as-code CI pipeline"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/detection-as-code-cicd.git
git push -u origin main
```

Thay `<YOUR_GITHUB_USERNAME>` bằng username GitHub của bạn. Nếu remote đã tồn tại, không chạy lại `git remote add origin`; dùng `git remote -v` để kiểm tra.

Sau khi push, mở tab **Actions** trên GitHub và xem workflow `Detection-as-Code CI` đã chạy chưa.

## CI kiểm tra gì?

| Gate | Ý nghĩa | Giới hạn |
|---|---|---|
| YAML + metadata | File parse được, có title/id/logsource/detection/condition | Chưa chứng minh logic detection đúng |
| MITRE tags | Có tag kỹ thuật `attack.t####` | Chưa xác minh kỹ thuật có phù hợp nội dung rule |
| Fixture test | Event dương khớp và event âm không khớp với logic mẫu | Fixture dùng evaluator đơn giản, không thay thế Splunk |
| pySigma conversion | Backend chuyển rule thành SPL được | Không chứng minh SPL chạy đúng trên index thực tế |
| Runtime validation | Chạy SPL trên telemetry do test tạo ra | Thực hiện riêng trong lab, cần bằng chứng kết quả |

## Lộ trình mở rộng

1. Thêm Sigma rules cho PowerShell, Scheduled Task, service creation, SMB và Kerberos.
2. Thêm test fixture sát schema sự kiện Sysmon/Windows thực tế.
3. Chuyển đổi rule thành file SPL artifact và lưu làm GitHub Actions artifact.
4. Tạo runbook Atomic Red Team theo technique ID, có bước prerequisite, execution, cleanup và expected telemetry.
5. Thêm kiểm thử runtime với Splunk lab qua self-hosted runner được cô lập, không expose Splunk credentials trong repository.
6. Thêm phê duyệt thủ công trước khi deploy saved search/alert vào Splunk.

## Tài liệu tham khảo

- Sigma rule specification: https://github.com/SigmaHQ/sigma-specification
- Sigma CLI: https://github.com/SigmaHQ/sigma-cli
- pySigma Splunk backend: https://github.com/SigmaHQ/pySigma-backend-splunk
- Atomic Red Team: https://www.atomicredteam.io/docs/atomic-red-team
