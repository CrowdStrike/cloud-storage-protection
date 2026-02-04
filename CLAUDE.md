# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloud Storage Protection demonstrates how to leverage CrowdStrike's QuickScan Pro APIs to protect cloud storage across AWS, Azure, and GCP. It provides event-driven serverless functions that automatically scan files on upload and optionally delete malicious content.

## Repository Structure

```text
AWS/          # S3 bucket protection (Lambda)
Azure/        # Storage container protection (Function App)
GCP/          # Cloud Storage protection (Cloud Function)
```

Each cloud provider directory contains:

- `demo/` - Full demo environment with Terraform
- `existing/` - Add protection to existing storage
- `on-demand/` - Standalone batch scanner for existing content
- `lambda/`, `function-app/`, or `cloud-function/` - Serverless function code

## Python Development Setup

This project uses `uv` for Python environment management. Set up the development environment:

```bash
# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install all dependencies
uv pip install -r requirements.txt
```

Always activate the venv before working with Python files in this repo.

## Common Commands

### Demo Environment (AWS/Azure/GCP)

```bash
# Stand up demo environment (prompts for Falcon API credentials)
./demo.sh up

# Tear down environment
./demo.sh down

# After setup, these commands become available:
upload          # Upload test files to storage
get-findings    # View function logs
list-bucket     # List storage contents (Azure/GCP)
```

### Terraform Operations

```bash
terraform init
terraform apply -var falcon_client_id="..." -var falcon_client_secret="..."
terraform destroy -var falcon_client_id="foo" -var falcon_client_secret="foo"
```

### On-Demand Scanning

```bash
# AWS
python3 quickscan_target.py -r REGION -t s3://BUCKET -k API_KEY -s API_SECRET [-b BATCH] [-w WORKERS]

# Azure
python3 quickscan_target.py -t STORAGE_ACCOUNT/CONTAINER -k API_KEY -s API_SECRET

# GCP
python3 quickscan_target.py -t gs://BUCKET -k API_KEY -s API_SECRET
```

## Architecture

All implementations follow the same pattern:

1. **Storage event trigger** → File uploaded
2. **Serverless function invoked** → Lambda/Function App/Cloud Function
3. **Scan workflow**:
   - Download file from storage (max 256MB)
   - Upload to QuickScan Pro API via `APIHarnessV2.command("UploadFileMixin0Mixin94", ...)`
   - Launch scan with `QuickScanPro.launch_scan(sha256=...)`
   - Poll `QuickScanPro.get_scan_result(ids=...)` until status is "done"
   - Process verdict: `clean`, `unknown`, `suspicious`, `malicious`
4. **Mitigation** → If `MITIGATE_THREATS=TRUE` and malicious/suspicious, delete file
5. **Cleanup** → Remove file from QuickScan Pro with `QuickScanPro.delete_file(ids=...)`

### Key Environment Variables

| Variable | Description | Default |
| ---------- | ------------- | --------- |
| `FALCON_CLIENT_ID` | CrowdStrike API client ID | Required |
| `FALCON_CLIENT_SECRET` | CrowdStrike API secret | Required |
| `MITIGATE_THREATS` | Auto-delete threats | `TRUE` |
| `BASE_URL` | CrowdStrike API URL | `https://api.crowdstrike.com` |

### Secrets Storage

- **AWS**: Secrets Manager
- **Azure**: Key Vault (via env vars)
- **GCP**: Secret Manager

## Dependencies

**Python SDK**: `crowdstrike-falconpy` (installed at runtime in AWS Lambda)

**Cloud SDKs**:

- AWS: `boto3` (pre-installed in Lambda)
- Azure: `azure-functions`, `azurefunctions.extensions.bindings.blob`
- GCP: `google-cloud-storage`, `google-cloud-logging`

## API Requirements

CrowdStrike Falcon API scopes needed:

- **QuickScan Pro**: `READ`, `WRITE`
- **MalQuery**: `READ`, `WRITE` (only for demo malware samples)

## Scan Verdicts

- `clean` - No threats detected
- `unknown` - Unable to scan
- `suspicious` - Potentially malicious
- `malicious` - Confirmed malware

## File Limits

- Maximum scannable file size: **256MB**
- Larger files are automatically skipped
