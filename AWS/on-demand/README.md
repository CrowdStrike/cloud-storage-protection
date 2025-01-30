<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# On-demand AWS S3 bucket scanner

This example provides a stand-alone solution for scanning an AWS S3 bucket using CrowdStrike's QuickScan Pro API. The solution processes existing files within the bucket using configurable batch sizes and concurrent processing for improved performance.

> This example requires the `boto3` and `crowdstrike-falconpy` (v1.3.0+) packages.

## Implementation Details

- Utilizes batch processing and concurrent threading for efficient file scanning
- Files are processed in configurable batch sizes
- Each batch is processed using a configurable number of worker threads
- Memory-efficient streaming of files directly from S3
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

- Recommended deployment in AWS (container, EC2 Instance, or Lambda)
- Files > 256MB are automatically skipped

## Requirements

In order to run this example solution, you will need:

- Name of the target AWS S3 bucket
- The AWS Region associated with the target bucket
- Access to CrowdStrike API keys with the following scopes:

| Service Collection | Scope               |
| :----------------- | :------------------ |
| QuickScan Pro      | __READ__, __WRITE__ |

### Installation

```shell
python3 -m pip install boto3 crowdstrike-falconpy
```

### Execution syntax

The following command will execute the solution against the bucket you specify using default options.

```shell
python3 quickscan_target.py -k CROWDSTRIKE_API_KEY -s CROWDSTRIKE_API_SECRET -t s3://TARGET_BUCKET_NAME -r AWS_REGION
```

A small command-line syntax help utility is available using the `-h` flag.

```shell
√ on-demand % piprun quickscan_target.py -h
usage: Falcon Quick Scan [-h] [-l LOG_LEVEL] [-d CHECK_DELAY] [-b BATCH] -r REGION -t TARGET -k KEY -s SECRET

optional arguments:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Default log level (DEBUG, WARN, INFO, ERROR)
  -d CHECK_DELAY, --check-delay CHECK_DELAY
                        Delay between checks for scan results
  -b BATCH, --batch BATCH
                        The number of files to include in a volume to scan (default: 1000).
  -w MAX_WORKERS, --workers MAX_WORKERS
                        Maximum number of worker threads to use for scanning (default: 10).
  -r REGION, --region REGION
                        Region the target bucket resides in
  -t TARGET, --target TARGET
                        Target folder or bucket to scan. Bucket must have 's3://' prefix.
  -k KEY, --key KEY     CrowdStrike Falcon API KEY
  -s SECRET, --secret SECRET
                        CrowdStrike Falcon API SECRET
```

### Usage Example

Basic usage with default settings and batch size set to 3:

```shell
python3 quickscan_target.py -k MYAPIKEY -s MYAPISECRET -r us-east-1 -t s3://my-bucket -b 3
```

```terminal
2025-01-16 14:29:19,933 Quick Scan INFO Process startup complete, preparing to run scan
2025-01-16 14:29:20,696 Quick Scan INFO Processing 7 files in batches of 3 using 10 worker threads
2025-01-16 14:29:20,696 Quick Scan INFO Processing batch 1: files 1 to 3 (3 files)
2025-01-16 14:29:22,959 Quick Scan INFO Uploaded malicious1.bin to 0ba7c8d22d9865346ce0195e85234382fe607ba5f6b2603e9dd8462a1309d7e9
2025-01-16 14:29:23,480 Quick Scan INFO Scan 9765c07c84fa4affbe201239cbcc5b55 submitted for analysis
2025-01-16 14:29:23,481 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:23,548 Quick Scan INFO Uploaded malicious2.bin to 1c17c0970978c61e28757a726773333c455c97ba2d468cfce4465df1f374ad89
2025-01-16 14:29:23,592 Quick Scan INFO Uploaded malicious3.bin to 37c876f70d72baaa55035972d6f54305c5a42b2dce2eb29e639fd49a7d8cb625
2025-01-16 14:29:24,153 Quick Scan INFO Scan 0b699786f8aa48da9a7e389fb8cea0a2 submitted for analysis
2025-01-16 14:29:24,153 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:24,292 Quick Scan INFO Scan 1512547f7cc249d785e56dd09a89bc09 submitted for analysis
2025-01-16 14:29:24,292 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:27,142 Quick Scan WARNING Verdict for malicious1.bin: suspicious
2025-01-16 14:29:27,786 Quick Scan WARNING Verdict for malicious2.bin: suspicious
2025-01-16 14:29:28,133 Quick Scan WARNING Verdict for malicious3.bin: suspicious
2025-01-16 14:29:28,496 Quick Scan INFO Completed batch 1
2025-01-16 14:29:28,496 Quick Scan INFO Processing batch 2: files 4 to 6 (3 files)
2025-01-16 14:29:29,304 Quick Scan INFO Uploaded safe1.bin to 12d09694c952b0634d34ec16d93dad07bce600bb6a34e4d95ddb979cff3831da
2025-01-16 14:29:29,543 Quick Scan INFO Uploaded safe2.bin to 207e6219e9ba3cfeca11fafca3002d0f5a13219d4f4b22ee745df67a71ad6502
2025-01-16 14:29:29,903 Quick Scan INFO Uploaded unscannable1.png to 0b9037a0e350aa10f8affc4757ea54b2bb2c13a68b190c40c5fa2fd2dbe383cb
2025-01-16 14:29:29,959 Quick Scan INFO Scan 6ed874977411453bbf7212179d77bb90 submitted for analysis
2025-01-16 14:29:29,959 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:30,136 Quick Scan INFO Scan a45810e54a834df78bec890a28b9d6fd submitted for analysis
2025-01-16 14:29:30,136 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:30,569 Quick Scan INFO Scan 2e924e004296481381f1f6e7218e4816 submitted for analysis
2025-01-16 14:29:30,569 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:33,604 Quick Scan INFO Verdict for safe1.bin: clean
2025-01-16 14:29:33,943 Quick Scan INFO Verdict for safe2.bin: clean
2025-01-16 14:29:34,283 Quick Scan INFO Verdict for unscannable1.png: clean
2025-01-16 14:29:34,627 Quick Scan INFO Completed batch 2
2025-01-16 14:29:34,627 Quick Scan INFO Processing batch 3: files 7 to 7 (1 files)
2025-01-16 14:29:36,138 Quick Scan INFO Uploaded unscannable2.jpg to cdd2e065d9eedf869e2a2444d74ea4e77755bb9c511a23596b2081cc91da4019
2025-01-16 14:29:36,777 Quick Scan INFO Scan 7039525bce8743a59d387c1259b9b717 submitted for analysis
2025-01-16 14:29:36,777 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:40,417 Quick Scan INFO Verdict for unscannable2.jpg: clean
2025-01-16 14:29:40,749 Quick Scan INFO Completed batch 3
2025-01-16 14:29:40,749 Quick Scan INFO Completed processing all 7 files
2025-01-16 14:29:40,749 Quick Scan INFO Scan completed
```
