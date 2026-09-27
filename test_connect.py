import boto3

sts_client = boto3.client('sts', region_name='us-east-1')
response = sts_client.get_caller_identity()
raw_acc = response['Account']
masked_acc = f"{raw_acc[:4]}****{raw_acc[-4:]}"

masked_arn = response['Arn'].replace(raw_acc, masked_acc)

print("========================================")
print("🎉 Success! Python connected to AWS!")
print("Account ID :", masked_acc)
print("IAM User   :", masked_arn)
print("========================================")
