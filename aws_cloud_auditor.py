import boto3
from datetime import datetime, timezone
import argparse
from tabulate import tabulate
import sys

# Ensure UTF-8 stdout on Windows console
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def mask_string(val, start=4, end=4):
    """Masks sensitive strings like Account IDs and Access Keys for privacy."""
    if not val or len(val) <= (start + end):
        return "****"
    return f"{val[:start]}****{val[-end:]}"

def audit_unattached_ebs_volumes(ec2_client):
    """Audits unattached EBS volumes wasting money."""
    print("\n🔍 [1/3] Auditing Unattached EBS Volumes (Cost Optimization)...")
    
    response = ec2_client.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    
    volumes = response.get('Volumes', [])
    findings = []
    total_wasted_gb = 0

    for vol in volumes:
        vol_id = vol['VolumeId']
        size = vol['Size']
        vol_type = vol['VolumeType']
        create_time = vol['CreateTime'].strftime("%Y-%m-%d")
        total_wasted_gb += size
        
        # Approximate EBS gp3/gp2 cost: $0.08 per GB-month
        monthly_waste = round(size * 0.08, 2)
        findings.append([vol_id, f"{size} GB", vol_type, create_time, f"${monthly_waste}"])

    return findings, total_wasted_gb

def audit_s3_bucket_security(s3_client):
    """Audits S3 buckets for public access configuration."""
    print("🔍 [2/3] Auditing S3 Buckets for Public Exposure (Security Audit)...")
    
    response = s3_client.list_buckets()
    buckets = response.get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        creation_date = b['CreationDate'].strftime("%Y-%m-%d")
        
        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            config = pab['PublicAccessBlockConfiguration']
            
            # Check if all 4 security shields are enabled
            is_secure = (
                config['BlockPublicAcls'] and
                config['IgnorePublicAcls'] and
                config['BlockPublicPolicy'] and
                config['RestrictPublicBuckets']
            )
            status = "SECURE (Blocked)" if is_secure else "WARNING (Partial)"
        except Exception:
            status = "DANGER (No Block Policy!)"
        
        findings.append([name, creation_date, status])

    return findings

def audit_iam_access_keys(iam_client):
    """Audits IAM access keys older than 90 days (Compliance Audit)."""
    print("🔍 [3/3] Auditing IAM Access Key Rotation (Compliance Check)...")
    
    users = iam_client.list_users().get('Users', [])
    findings = []
    now = datetime.now(timezone.utc)

    for user in users:
        username = user['UserName']
        keys_resp = iam_client.list_access_keys(UserName=username)
        keys = keys_resp.get('AccessKeyMetadata', [])

        for key in keys:
            raw_key_id = key['AccessKeyId']
            # Mask sensitive key ID for screenshots & reports
            masked_key_id = mask_string(raw_key_id, 4, 4)
            status = key['Status']
            created = key['CreateDate']
            age_days = (now - created).days
            
            if age_days > 90 and status == 'Active':
                compliance = "CRITICAL (Over 90 Days!)"
            elif age_days > 60:
                compliance = "WARNING (Rotate Soon)"
            else:
                compliance = "COMPLIANT (Healthy)"

            findings.append([username, masked_key_id, status, f"{age_days} Days", compliance])

    return findings

def generate_markdown_report(ebs_data, total_wasted_gb, s3_data, iam_data, account_id, region):
    """Generates an executive markdown report file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = "aws_cloud_audit_report.md"
    
    monthly_total_cost = round(total_wasted_gb * 0.08, 2)
    masked_acc = mask_string(account_id, 4, 4)
    
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(f"# 🛡️ AWS Cloud Governance & Cost Optimization Audit Report\n\n")
        f.write(f"**AWS Account ID:** `{masked_acc}` (Masked for Privacy)  \n")
        f.write(f"**Region Audited:** `{region}`  \n")
        f.write(f"**Audit Timestamp:** `{timestamp}`  \n")
        f.write(f"**Auditor:** Praveen Dwivedi (Senior DevOps Engineer)  \n\n")
        f.write(f"---\n\n")

        # EBS Section
        f.write(f"## 1. Cost Optimization: Unattached EBS Volumes\n")
        f.write(f"* **Total Unattached Storage:** `{total_wasted_gb} GB`\n")
        f.write(f"* **Estimated Monthly Waste:** `${monthly_total_cost} USD`\n\n")
        if ebs_data:
            f.write(tabulate(ebs_data, headers=["Volume ID", "Size", "Type", "Created", "Monthly Waste"], tablefmt="github"))
        else:
            f.write("✅ **Zero Waste:** All EBS volumes are properly attached to active EC2 instances.\n")
        f.write("\n\n---\n\n")

        # S3 Section
        f.write(f"## 2. Security Audit: S3 Bucket Public Access\n\n")
        if s3_data:
            f.write(tabulate(s3_data, headers=["Bucket Name", "Creation Date", "Security Status"], tablefmt="github"))
        else:
            f.write("ℹ️ No S3 buckets discovered in this account.\n")
        f.write("\n\n---\n\n")

        # IAM Section
        f.write(f"## 3. Compliance Audit: IAM Access Key Age (>90 Days Rule)\n\n")
        if iam_data:
            f.write(tabulate(iam_data, headers=["IAM User", "Access Key ID", "Status", "Age", "Compliance"], tablefmt="github"))
        else:
            f.write("ℹ️ No IAM users found.\n")

    print(f"\n📄 Executive Report successfully saved to: {report_filename}")

def main():
    parser = argparse.ArgumentParser(description="Automated AWS Cloud Cost & Security Auditor")
    parser.add_argument("--region", default="us-east-1", help="Target AWS Region (default: us-east-1)")
    args = parser.parse_args()

    print("===================================================================")
    print("🚀 AWS Cloud Governance & Cost Optimization Engine (Python + Boto3)")
    print(f"Target Region: {args.region}")
    print("===================================================================")

    # Initialize Boto3 Clients
    sts = boto3.client('sts', region_name=args.region)
    raw_account_id = sts.get_caller_identity()['Account']
    masked_account_id = mask_string(raw_account_id, 4, 4)
    print(f"Connected to AWS Account: {masked_account_id} (Masked for Security)")

    ec2 = boto3.client('ec2', region_name=args.region)
    s3 = boto3.client('s3', region_name=args.region)
    iam = boto3.client('iam', region_name=args.region)

    # Run Audits
    ebs_findings, total_wasted_gb = audit_unattached_ebs_volumes(ec2)
    s3_findings = audit_s3_bucket_security(s3)
    iam_findings = audit_iam_access_keys(iam)

    # Print Terminal Tables
    print("\n" + "="*60)
    print("📊 COST AUDIT: UNATTACHED EBS VOLUMES")
    print("="*60)
    if ebs_findings:
        print(tabulate(ebs_findings, headers=["Volume ID", "Size", "Type", "Created", "Monthly Waste"], tablefmt="grid"))
    else:
        print("✅ Clean! Zero unattached EBS volumes found. No wasted cost.")

    print("\n" + "="*60)
    print("📊 SECURITY AUDIT: S3 BUCKET EXPOSURE")
    print("="*60)
    if s3_findings:
        print(tabulate(s3_findings, headers=["Bucket Name", "Created", "Security Status"], tablefmt="grid"))
    else:
        print("ℹ️ No S3 buckets found.")

    print("\n" + "="*60)
    print("📊 COMPLIANCE AUDIT: IAM ACCESS KEY ROTATION")
    print("="*60)
    if iam_findings:
        print(tabulate(iam_findings, headers=["IAM User", "Key ID (Masked)", "Status", "Age", "Compliance"], tablefmt="grid"))
    else:
        print("ℹ️ No IAM users found.")

    # Generate Markdown Report
    generate_markdown_report(ebs_findings, total_wasted_gb, s3_data=s3_findings, iam_data=iam_findings, account_id=raw_account_id, region=args.region)
    print("\n🎉 Cloud Audit Completed Successfully!")

if __name__ == "__main__":
    main()
