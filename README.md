# ??? AWS Cloud Governance & Cost Optimization Engine (Python + Boto3)

An enterprise-grade cloud automation CLI tool built with **Python 3** and the **AWS SDK (Boto3)** to perform automated cloud financial governance (FinOps), security audits, and regulatory compliance checks across AWS infrastructure.

---

## ?? Key Architectural Capabilities

### 1. ?? FinOps Cost Optimization (Unattached EBS Volumes)
* Scans the target AWS region for Elastic Block Store (EBS) volumes with status `available` (unattached to any EC2 instance).
* Calculates estimated monthly financial waste based on provisioned storage gigabytes.
* Helps engineering teams clean up orphaned disks after instance termination to cut AWS monthly bills.

### 2. ?? Security & Data Leak Prevention (S3 Bucket Public Access)
* Inspects all Amazon S3 buckets for the **Public Access Block** configuration.
* Audits the 4 critical security flags: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.
* Flags unsecured or partially configured buckets before data exfiltration occurs.

### 3. ?? Identity & Access Governance (IAM Access Key Age)
* Audits all IAM users for long-lived programmatic access keys.
* Calculates the exact age in days from creation date.
* Enforces the **CIS AWS Benchmark 90-Day Rotation Rule** by flagging keys older than 90 days as `CRITICAL (Needs Immediate Rotation)`.

### 4. ?? Automated Executive Reporting
* Renders real-time formatted ASCII status tables in the terminal.
* Generates a persistent, timestamped Markdown audit report (`aws_cloud_audit_report.md`).

---

## ??? Tech Stack
* **Language:** Python 3.12+
* **Cloud SDK:** AWS Boto3
* **Target Cloud:** Amazon Web Services (AWS)
* **Libraries:** `tabulate`, `datetime`, `argparse`

---

## ?? How to Run Locally

### 1. Prerequisites
* Python 3.10+ installed.
* AWS CLI configured with administrative read permissions (`aws configure`).

### 2. Clone the Repository
```bash
git clone https://github.com/PraveenDwivedi16/aws-cloud-auditor-boto3.git
cd aws-cloud-auditor-boto3
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Execute Cloud Audit
```bash
# Audit default region (us-east-1)
python aws_cloud_auditor.py

# Audit a specific target region
python aws_cloud_auditor.py --region us-east-1
```

---

## ?? Sample Terminal Output
```text
===================================================================
?? AWS Cloud Governance & Cost Optimization Engine (Python + Boto3)
Target Region: us-east-1
===================================================================
Connected to AWS Account: 3888****9463 (Masked for Security)

🔍 [1/3] Auditing Unattached EBS Volumes (Cost Optimization)...
🔍 [2/3] Auditing S3 Buckets for Public Exposure (Security Audit)...
🔍 [3/3] Auditing IAM Access Key Rotation (Compliance Check)...

============================================================
📊 COST AUDIT: UNATTACHED EBS VOLUMES
============================================================
✅ Clean! Zero unattached EBS volumes found. No wasted cost.

============================================================
📊 COMPLIANCE AUDIT: IAM ACCESS KEY ROTATION
============================================================
+------------+-------------------+----------+--------+---------------------+
| IAM User   | Key ID (Masked)   | Status   | Age    | Compliance          |
+============+===================+==========+========+=====================+
| cloud_user | AKIA****IJM6      | Active   | 0 Days | COMPLIANT (Healthy) |
+------------+-------------------+----------+--------+---------------------+

?? Executive Report successfully saved to: aws_cloud_audit_report.md
?? Cloud Audit Completed Successfully!
```

---
**Author:** [Praveen Dwivedi](https://www.linkedin.com/in/praveen-dwivedi-devops/) (AWS & RHCSA Certified DevOps Engineer)
