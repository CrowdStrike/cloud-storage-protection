<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# Azure Cloud Storage Bucket Protection

This repository demonstrates different ways to leverage CrowdStrike's QuickScan Pro APIs to protect Azure Cloud Storage containers. Through these examples, you'll learn how to implement both real-time and on-demand malware scanning for your cloud storage.

## Prerequisites

+ Have access to Azure w/ permissions to manage resources
+ Create or modify an API Key in the Falcon Console and
Assign the following scopes:
  + **Quick Scan** - `READ`, `WRITE`
  + **Sample Uploads** - `READ`, `WRITE`
  + **Malquery** - `READ`, `WRITE`
    > Used to pull down sample malicious files for demonstration purposes

## Example Implementations

### Real-time Storage Protection

This demonstration leverages Terraform to provide a functional example of real-time storage protection in Azure using the QuickScan Pro APIs. All of the necessary resources for using this solution to protect a Azure Cloud Storage container are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Start the demo by following this documentation:***

[Demo](demo)

## Deploying to an existing storage container

This demonstration leverages Terraform to provide a functional example of adding protection to an existing Azure Storage container with the QuickScan Pro APIs. All of the necessary resources for using this solution to protect an existing Azure Cloud Storage container are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Start the demo by following this documentation:***

[Existing](existing)

## On-demand scanning

This example provides a stand-alone solution for scanning a Cloud Storage container before implementing protection.
While similar to the serverless function, this solution will only scan the bucket's *existing* file contents.

This solution leverages the same APIs and logic that is implemented by the serverless handler that provides real-time protection.

The read more about this component, and use it by following this documentation:

[On Demand](on-demand).
