<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# On-demand Azure Cloud Storage Bucket Scanner

This example provides a stand-alone solution for scanning a Cloud Storage bucket using CrowdStrike's QuickScan Pro API. The solution processes existing files within the bucket using configurable batch sizes and concurrent processing for improved performance.

> This example requires the `azure-storage-blob`, `azure-identity` and `crowdstrike-falconpy` (v1.3.0+) packages.

## Implementation Details

- Utilizes batch processing and concurrent threading for efficient file scanning
- Files are processed in configurable batch sizes
- Each batch is processed using a configurable number of worker threads
- Memory-efficient streaming of files directly from Azure Storage
- Automatic artifact cleanup after processing
- Rotating log file implementation

### Processing Workflow

- Batch Processing:
  - Total files are divided into batches (default: 1000 files per batch)
  - Each batch is processed sequentially

- Worker Threads:
  - Within each batch, files are processed concurrently
  - Number of concurrent operations controlled by max_workers (default: 10)

### Performance Considerations

Performance is influenced by:

- Network bandwidth and latency
- API rate limits
- Number of worker threads
- Batch size configuration

File sizes and quantity

- Recommended deployment in Azure (Container, Virtual Machine, or Function App)
- Files > 256MB are automatically skipped

## Requirements

In order to run this example solution, you will need:

- Name of the target Azure Cloud Storage container
- The Project ID associated with the target bucket
- Access to CrowdStrike API keys with the following scopes:

    | Service Collection | Scope               |
    | :----------------- | :------------------ |
    | QuickScan Pro      | __READ__, __WRITE__ |

### Running the Example

[Launch Cloud Shell](https://shell.azure.com)

Clone this repository by running the following commands

```shell
git clone https://github.com/CrowdStrike/cloud-storage-protection.git
```

In order to run this solution, you will need:

- The URL of the Azure Storage Account container
- access to CrowdStrike API keys with the following scopes:

    | Service Collection | Scope |
    | :---- | :---- |
    | Quick Scan | __READ__, __WRITE__ |
    | Sample Uploads | __READ__, __WRITE__ |

- `Storage Blob Data Contributor` permissions on the existing container

### Install requirements

Change to the cloud-storage-protection/Azure/on-demand directory and run the following command

```shell
python3 -m pip install -r requirements.txt
```

### Execution syntax

The following command will execute the solution against the bucket you specify using default options.

```shell
python3 quickscan_target.py -k CROWDSTRIKE_FALCON_API_KEY -s CROWDSTRIKE_FALCON_API_SECRET -t 'https://<STORAGE_ACCOUNT>.blob.core.windows.net/<STORAGE_CONTAINER>/<PATH>'
```

A small command-line syntax help utility is available using the `-h` flag.

```shell
python3 quickscan_target.py -h
usage: Falcon Quick Scan [-h] [-l LOG_LEVEL] [-d CHECK_DELAY] [-b BATCH] -t TARGET -k KEY -s SECRET

options:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Default log level (DEBUG, WARN, INFO, ERROR)
  -d CHECK_DELAY, --check-delay CHECK_DELAY
                        Delay between checks for scan results
  -b BATCH, --batch BATCH
                        The number of files to include in a volume to scan.
  -w MAX_WORKERS, --workers MAX_WORKERS
                        Maximum number of worker threads to use for scanning (default: 10).
  -t TARGET, --target TARGET
                        Target folder or container to scan. Value must start with 'https://' and have '.blob.core.windows.net' url suffix.
  -k KEY, --key KEY     CrowdStrike Falcon API KEY
  -s SECRET, --secret SECRET
                        CrowdStrike Falcon API SECRET
```

### Example output

```terminal
2025-01-24 13:32:45,595 Quick Scan INFO Process startup complete, preparing to run scan
2025-01-24 13:32:45,595 azure.identity._credentials.environment INFO No environment configuration found.
2025-01-24 13:32:45,596 azure.identity._credentials.managed_identity INFO ManagedIdentityCredential will use Cloud Shell managed identity
2025-01-24 13:32:45,610 azure.identity._credentials.chained INFO DefaultAzureCredential acquired a token from ManagedIdentityCredential
2025-01-24 13:32:45,696 Quick Scan INFO Processing 6 files in batches of 1000 using 10 worker threads
2025-01-24 13:32:45,696 Quick Scan INFO Processing batch 1: files 1 to 6 (6 files)
2025-01-24 13:32:46,722 Quick Scan INFO Uploaded safe1.bin to 0eeae14475aa3e04b21e33cdd9a9b9824f8a9c51c5879e95e98c4f5fd4d26888
2025-01-24 13:32:46,913 Quick Scan INFO Uploaded safe2.bin to 460f1a138e0765b8680ffa511d5320bbce4f9b5218c5f596652fe47307221edd
2025-01-24 13:32:47,009 Quick Scan INFO Uploaded unscannable2.jpg to cdd2e065d9eedf869e2a2444d74ea4e77755bb9c511a23596b2081cc91da4019
2025-01-24 13:32:47,406 Quick Scan INFO Scan a19c217e11e34b11ac68420b0773131f submitted for analysis
2025-01-24 13:32:47,406 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:47,416 Quick Scan INFO Uploaded malicious1.bin to 0ba7c8d22d9865346ce0195e85234382fe607ba5f6b2603e9dd8462a1309d7e9
2025-01-24 13:32:47,563 Quick Scan INFO Scan 4210424e96f54f0caed61b32c91d8c7a submitted for analysis
2025-01-24 13:32:47,563 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:47,708 Quick Scan INFO Uploaded malicious2.bin to 1c17c0970978c61e28757a726773333c455c97ba2d468cfce4465df1f374ad89
2025-01-24 13:32:47,716 Quick Scan INFO Scan 89252e05a16040ba90eba65cf04fefb8 submitted for analysis
2025-01-24 13:32:47,716 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:47,861 Quick Scan INFO Uploaded malicious3.bin to 37c876f70d72baaa55035972d6f54305c5a42b2dce2eb29e639fd49a7d8cb625
2025-01-24 13:32:48,163 Quick Scan INFO Scan 02ea8ab0d1894852830694546a40b426 submitted for analysis
2025-01-24 13:32:48,163 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:48,518 Quick Scan INFO Scan 018a82c4be6748f3b84d9c348eca7d81 submitted for analysis
2025-01-24 13:32:48,518 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:48,570 Quick Scan INFO Scan e9d5cddeb4e649f9868999d733da54f7 submitted for analysis
2025-01-24 13:32:48,570 Quick Scan INFO Waiting for scan results...
2025-01-24 13:32:51,083 Quick Scan INFO Verdict for safe1.bin: clean
2025-01-24 13:32:51,428 Quick Scan INFO Verdict for safe2.bin: clean
2025-01-24 13:32:51,756 Quick Scan INFO Verdict for unscannable2.jpg: clean
2025-01-24 13:32:52,102 Quick Scan WARNING Verdict for malicious1.bin: suspicious
2025-01-24 13:32:52,457 Quick Scan WARNING Verdict for malicious3.bin: suspicious
2025-01-24 13:32:55,499 Quick Scan WARNING Verdict for malicious2.bin: suspicious
2025-01-24 13:32:55,845 Quick Scan INFO Completed batch 1
2025-01-24 13:32:55,845 Quick Scan INFO Completed processing all 6 files
2025-01-24 13:32:55,846 Quick Scan INFO Scan completed
```
