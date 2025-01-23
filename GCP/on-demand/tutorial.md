# On-demand GCP Cloud Storage Bucket Scanner Example

This example provides a stand-alone solution for scanning a Cloud Storage bucket before implementing protection.
While similar to the serverless function, this solution will only scan the bucket's _existing_ file contents.

## Select Project

Select the project that contains your target bucket.

<walkthrough-project-setup></walkthrough-project-setup>

## Setup

### Set Cloud Shell Project

```sh
gcloud config set project <walkthrough-project-id/>
```

## Install Python Dependencies

This example requires the `google-cloud-storage` and `crowdstrike-falconpy` (v0.8.7+) packages.

Execute the following command to install the dependencies:

```sh
python3 -m pip install google-cloud-storage crowdstrike-falconpy
```

## Running the program

In order to run this solution, you will need:

+ Name of the target GCP Cloud Storage bucket
+ The Project ID associated with the target bucket
+ access to CrowdStrike API keys with the following scopes:
  + QuickScan Pro - `READ`, `WRITE`

### Execution syntax

The following command will execute the solution against the bucket you specify using default options.

Replace the following variables prior to executing:

+ `CROWDSTRIKE_API_KEY`
+ `CROWDSTRIKE_API_SECRET`
+ `TARGET_BUCKET_NAME`

```sh
python3 quickscan_target.py -k CROWDSTRIKE_API_KEY -s CROWDSTRIKE_API_SECRET -t gs://TARGET_BUCKET_NAME -p <walkthrough-project-id/>
```

*A <walkthrough-editor-spotlight spotlightId="file-explorer">log file</walkthrough-editor-spotlight> is also generated in the current directory*

### Example output

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
2025-01-16 14:29:29,304 Quick Scan INFO Uploaded safe1.bin to
...
...
2025-01-16 14:29:36,777 Quick Scan INFO Waiting for scan results...
2025-01-16 14:29:40,417 Quick Scan INFO Verdict for unscannable2.jpg: clean
2025-01-16 14:29:40,749 Quick Scan INFO Completed batch 3
2025-01-16 14:29:40,749 Quick Scan INFO Completed processing all 7 files
2025-01-16 14:29:40,749 Quick Scan INFO Scan completed
```

---
View the command usage on the next page for more arguments.

## Print Usage

A small command-line syntax help utility is available using the `-h` flag.

```sh
python3 quickscan_target.py -h
```

```terminal
usage: quickscan_target.py [-h] [-l LOG_LEVEL] [-d CHECK_DELAY] [-b BATCH] [-w MAX_WORKERS] -p PROJECT_ID -t TARGET -k KEY -s SECRET

options:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Default log level (DEBUG, WARN, INFO, ERROR)
  -d CHECK_DELAY, --check-delay CHECK_DELAY
                        Delay between checks for scan results
  -b BATCH, --batch BATCH
                        The number of files to include in a volume to scan (default: 1000).
  -w MAX_WORKERS, --workers MAX_WORKERS
                        Maximum number of worker threads to use for scanning (default: 10).
  -p PROJECT_ID, --project PROJECT_ID
                        Project ID the target bucket resides in
  -t TARGET, --target TARGET
                        Target folder or bucket to scan. Bucket must have 'gs://' prefix.
  -k KEY, --key KEY     CrowdStrike Falcon API KEY
  -s SECRET, --secret SECRET
                        CrowdStrike Falcon API SECRET
```
