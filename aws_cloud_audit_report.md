# 🛡️ AWS Cloud Governance & Cost Optimization Audit Report

**AWS Account ID:** `3888****9463` (Masked for Privacy)  
**Region Audited:** `us-east-1`  
**Audit Timestamp:** `2026-09-27 16:33:50`  
**Auditor:** Praveen Dwivedi (Senior DevOps Engineer)  

---

## 1. Cost Optimization: Unattached EBS Volumes
* **Total Unattached Storage:** `0 GB`
* **Estimated Monthly Waste:** `$0.0 USD`

✅ **Zero Waste:** All EBS volumes are properly attached to active EC2 instances.


---

## 2. Security Audit: S3 Bucket Public Access

ℹ️ No S3 buckets discovered in this account.


---

## 3. Compliance Audit: IAM Access Key Age (>90 Days Rule)

| IAM User   | Access Key ID   | Status   | Age    | Compliance          |
|------------|-----------------|----------|--------|---------------------|
| cloud_user | AKIA****IJM6    | Active   | 0 Days | COMPLIANT (Healthy) |