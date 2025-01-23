# Prerequisites

## Falcon API Credentials

...

# Set Up AWS

The following steps are performed in AWS CloudShell.

## Install Terraform

```
git clone https://github.com/tfutils/tfenv.git ~/.tfenv
mkdir ~/bin
ln -s ~/.tfenv/bin/* ~/bin/
tfenv install 1.10.5
tfenv use 1.10.5
```

## Verify Terraform Installation

```
terraform --version
```

## Clone Repo

```
git clone https://github.com/CrowdStrike/cloud-storage-protection.git
```

## Apply Terraform

```
cd cloud-storage-protection/AWS/demo
terraform init
terraform apply
```

When prompted, enter the following parameters:
- Base URL (eg. https://api.crowdstrike.com, https://api.us-2.crowdstrike.com, https://api.eu-1.crowdstrike.com)
- Falcon API Client ID
- Falcon API Client Secret

When prompted, enter 'yes' to create demo resources.

## Verify Demo Resources

All demo resources will be created with the prefix quikscan-pro-demo.  The following resources are included in the demo:
- S3 Bucket
- Lambda Function
- Lambda Execution Role
- AWS Secret (to securely store Falcon API credentials)

# Scan Files

1. Upload the desired file to the S3 bucket `quickscan-pro-demo-bucket`
2. This will automatically trigger the Lambda function `quikscan-pro-demo-function`
3. Scan Results will be logged in Cloudwatch Logs in the LogGroup `/aws/lambda/quikscan-pro-demo-function`