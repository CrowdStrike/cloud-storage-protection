<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# S3 Bucket Protection demonstration

This demonstration leverages Terraform to provide a functional demonstration of this integration.
All of the necessary resources for using this solution to protect an AWS S3 bucket are implemented for you
as part of the environment configuration process, including sample files and command line helper scripts.

+ [Contents](#contents)
+ [Requirements](#requirements)
+ [Setup the Demo Environment](#setup-the-demo-environment)
+ [Use the Demo Environment](#use-the-demo-environment)
+ [Tearing down the demonstration](#tearing-down-the-demonstration)

## Contents

+ `bucket.tf` - The configuration details for the bucket and it's event triggers.
+ `iam.tf` - The IAM roles and permissions used by the integration and demonstration.
+ `lambda-function.tf` - The S3 Bucket Protection lambda handler configuration.
+ `output.tf` - The values output by Terraform after the stand-up process completes.
+ `provider.tf` - The AWS Provider, configured for Cloudshell. Edit the region variable to change this to another region.
+ `secret.tf` - The AWS Secrets Manager Secret to securely store Falcon API Credentials.
+ `variables.tf` - User customizable values used by the integration and demonstrations.
+ `vpc.tf` - The AWS VPC configuration for the demonstration environment.

> Please note: You should not need to modify these files unless you want to change the region the demonstration is deployed to. The default region for this demonstration is `us-east-1`.

## Requirements

+ AWS account access with appropriate CLI keys and permissions already configured.
+ CrowdStrike Falcon API credentials with the following scopes:
  + **MalQuery** - `READ`, `WRITE` (used to download malware samples)
  + **QuickScan** Pro - `READ`, `WRITE`
  + You will be asked to provide these credentials when the `demo.sh` script executes.
+ `md5sum` (used to generate a unique bucket name)
+ Terraform installed in your environment or the ability to install Terraform.  If running this demo in CloudShell, please see the instructions to install Terraform.

> This demonstration has been tested using AWS CloudShell.

### Demonstration architecture diagram

![Demonstration architecture](../content/aws-demo-arch.png)

## Setup the Demo Environment

From the home folder of your CloudShell environment, execute the following commands:

### Install Terraform

> If Terraform is already installed, please skip to Clone this Repository

```shell
git clone https://github.com/tfutils/tfenv.git ~/.tfenv
mkdir ~/bin
ln -s ~/.tfenv/bin/* ~/bin/
tfenv install 1.10.5
tfenv use 1.10.5
```

### Clone this Repository

```shell
git clone https://github.com/CrowdStrike/cloud-storage-protection.git
```

### Stand Up Environment

```shell
cd /home/cloudshell-user/cloud-storage-protection/AWS/demo
terraform init
terraform apply
```

You will be asked to provide:

+ Your CrowdStrike Cloud.
+ Your CrowdStrike API credentials.
  + These values will not display when entered.

When prompted, type `yes` to apply the Terraform configuration.

## Use The Demo Environment

At this point all components are in place to automatically scan files created in the S3 Bucket `quickscan-pro-demo-bucket`.  Use the following scripts to demonstrate QuickScan Pro with a few example files.

### Setup and Download Example Files

```shell
cd /home/cloudshell-user/cloud-storage-protection/AWS/demo
chmod +x setup-demo.sh
sudo ./setup-demo.sh
```

Example files will be located in `/home/cloudshell-user/cloud-storage-protection/AWS/demo/testfiles` and includes multiple samples named according to the sample's type.

+ 2 safe sample files
+ 3 malware sample files
  + These samples are downloaded from CrowdStrike MalQuery as part of the demonstration instance bootstrap.
  + The [FalconPy](https://github.com/CrowdStrike/falconpy) code sample
    [MalQueryinator](https://github.com/CrowdStrike/falconpy/tree/main/samples/malquery#search-and-download-samples-from-malquery) is leveraged to accomplish this.

### Upload and Scan Example Files

This demo utilizes a trigger on an S3 Bucket to automatically scan uploaded files with Lambda.  Execute the following command to upload testfiles to S3:

```shell
upload
```

### Get Findings

To review findings, view the latest Log Stream for the Lambda Function's Log Group.  Execute the following commands:

```shell
get-findings
```

> Please Note: It may take a few minutes for all scans to complete and scan results to show in findings.  You may run this command multiple times.

#### Example

```shell
Latest findings:

        [INFO]  2025-01-23T21:01:44.842Z        306c17e6-efe6-4085-a845-88481a7448b5    File uploaded to QuickScan Pro.
        [INFO]  2025-01-23T21:01:48.952Z        306c17e6-efe6-4085-a845-88481a7448b5    No threat found in unscannable2.jpg
        [INFO]  2025-01-23T21:02:59.238Z        babc8395-7dea-4b43-a70a-53951e67acf7    File uploaded to QuickScan Pro.
        [INFO]  2025-01-23T21:03:07.120Z        babc8395-7dea-4b43-a70a-53951e67acf7    Threat malicious1.bin removed from bucket quickscan-pro-demo-bucket
```

### List Bucket

List the bucket contents to confirm malicious files were removed by QuickScan Pro.

```shell
aws s3 ls $BUCKET
```

#### Example

```shell
2021-12-22 05:40:10      28904 safe1.bin
2021-12-22 05:40:11    1119957 unscannable1.png
```

---

## Tearing down the demonstration

Simply use Terraform to destroy the Demo environment:

```shell
cd /home/cloudshell-user/cloud-storage-protection/AWS/demo
terraform init
terraform destroy
```

When prompted, type `yes` to destroy the Terraform configuration.
