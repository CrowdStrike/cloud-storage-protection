<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# GCP Cloud Storage Bucket Protection

This repository demonstrates different ways to leverage CrowdStrike's QuickScan Pro APIs to protect GCP Cloud Storage buckets. Through these examples, you'll learn how to implement both real-time and on-demand malware scanning for your cloud storage.

## Prerequisites

+ Have access to GCP w/ permissions to manage resources
+ Create or modify an API Key in the Falcon Console and
Assign the following scopes:
  + **Quick Scan** - `READ`, `WRITE`
  + **Sample Uploads** - `READ`, `WRITE`
  + **Malquery** - `READ`, `WRITE`
    > Used to pull down sample malicious files for demonstration purposes

## Example Implementations

### Real-time Storage Protection

This demonstration leverages Terraform to provide a functional example of real-time storage protection in GCP using the QuickScan Pro APIs. All of the necessary resources for using this solution to protect a GCP Cloud Storage bucket are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Get Started:***

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2FCrowdStrike%2Fcloud-storage-protection&cloudshell_workspace=GCP&cloudshell_tutorial=demo%2Ftutorial.md)

---

### Deploying to an Existing Storage

This demonstration leverages Terraform to provide a functional example of adding protection to an existing GCP bucket with the QuickScan Pro APIs. All of the necessary resources for using this solution to protect an existing GCP Cloud Storage bucket are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Get Started:***

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2FCrowdStrike%2Fcloud-storage-protection&cloudshell_workspace=GCP&cloudshell_tutorial=existing%2Ftutorial.md)

---

### On-demand Scanning

This example provides a stand-alone solution for scanning a Cloud Storage bucket before implementing protection.
While similar to the serverless function, this solution will only scan the bucket's _existing_ file contents.

This solution leverages the same APIs and logic that is implemented by the serverless handler that provides real-time protection.

To read more about this component, review the documentation located [here](on-demand).

***Get Started:***

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2FCrowdStrike%2Fcloud-storage-protection&cloudshell_workspace=GCP%2Fon-demand&cloudshell_tutorial=tutorial.md)
