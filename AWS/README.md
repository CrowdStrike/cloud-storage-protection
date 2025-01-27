<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# AWS S3 Bucket Protection

## Overview

This solution demonstrates different ways to leverage CrowdStrike's QuickScan Pro APIs to protect AWS S3 Storage buckets. Through these examples, you'll learn how to implement both real-time and on-demand malware scanning for your cloud storage.

## Prerequisites

+ Have access to AWS w/ permissions to manage resources
+ Create or modify an API Key in the Falcon Console and
Assign the following scopes:
  + **QuickScan Pro** - `READ`, `WRITE`
  + **Malquery** - `READ`, `WRITE`
    > Used to pull down sample malicious files for demonstration purposes

## Example Implementations

### Real-time Storage Protection

This demonstration leverages Terraform to provide a functional example of real-time storage protection in AWS using the QuickScan Pro APIs. All of the necessary resources for using this solution to protect a AWS S3 bucket are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Start the demo by following this documentation:***

[Demo](demo)

## Deploying to an existing S3 bucket

This demonstration leverages Terraform to provide a functional example of adding protection to an existing AWS S3 bucket with the QuickScan Pro APIs. All of the necessary resources for using this solution to protect an existing AWS S3 bucket are implemented for you as part of the environment configuration process, including sample files and command line helper scripts.

***Start the demo by following this documentation:***

[Existing](existing)

## On-demand scanning

This example provides a stand-alone solution for scanning a S3 bucket before implementing protection.
While similar to the serverless function, this solution will only scan the bucket's *existing* file contents.

This solution leverages the same APIs and logic that is implemented by the serverless handler that provides real-time protection.

The read more about this component, and use it by following this documentation:

[On Demand](on-demand).
