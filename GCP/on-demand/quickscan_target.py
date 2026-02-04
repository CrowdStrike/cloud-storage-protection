# pylint: disable=W1401
# flake8: noqa
"""Scan a GCP bucket with the CrowdStrike QuickScan Pro API.

Scans a GCP Cloud Storage bucket using the CrowdStrike Falcon QuickScan Pro APIs.
Implements multithreaded processing for improved performance and efficiency.

===== NOTES REGARDING THIS SOLUTION ============================================================

IMPLEMENTATION DETAILS:
- Utilizes batch processing and concurrent threading for efficient file scanning
- Files are processed in configurable batch sizes
- Each batch is processed using a configurable number of worker threads
- Memory-efficient streaming of files directly from GCP Storage
- Automatic artifact cleanup after processing
- Rotating log file implementation

PROCESSING WORKFLOW:
- Phase 1 - Parallel Upload with Auto-Scan:
    * Files are uploaded with scan=True to auto-launch scans
    * Multi-threaded upload using configurable worker threads
    * Scan IDs are collected from upload responses

- Phase 2 - Batch Poll for Results:
    * Single API call to get results for all pending scans
    * Polls until all scans complete

- Phase 3 - Batch Cleanup:
    * Single API call to delete all uploaded files

- Batch Processing:
    * Total files are divided into batches (default: 1000 files per batch)
    * Each batch is processed sequentially through the 3 phases
    * Example: 1500 files with batch=500 creates 3 batches of 500 files each

- Worker Threads:
    * Within each batch, files are uploaded concurrently
    * Number of concurrent operations controlled by max_workers (default: 10)
    * Example: With max_workers=10, up to 10 files from the current batch
      are uploaded simultaneously

PERFORMANCE CONSIDERATIONS:
- Optimized API usage:
    * Upload with scan=True eliminates separate launch_scan() calls
    * Batch result polling reduces API round-trips
    * Batch cleanup reduces delete calls from N to 1
- Performance is influenced by:
    * Network bandwidth and latency
    * API rate limits
    * Number of worker threads
    * Batch size configuration
    * File sizes and quantity
- Recommended deployment in GCP (container, Compute instance, or Cloud Function)
- Files > 256MB are automatically skipped

REQUIREMENTS:
- Target must include "gs://" prefix for bucket scanning
- Requires Google Cloud Storage library and CrowdStrike FalconPy >= v0.8.7
    python3 -m pip install google-cloud-storage crowdstrike-falconpy

CONFIGURATION:
- Batch size (-b, --batch):
    * Controls number of files processed in each batch (default: 1000)
    * Example: batch=500 processes files in groups of 500
- Worker threads (-w, --workers):
    * Controls concurrent operations within each batch (default: 10)
    * Example: workers=5 processes 5 files simultaneously within each batch
- Check delay: Time between scan result checks
- Log level: DEBUG, INFO, WARN, ERROR
- Project ID: GCP project containing target bucket
- API Credentials: CrowdStrike Falcon API key and secret

ERROR HANDLING:
- Comprehensive error handling per file
- Continued processing despite individual file failures
- Detailed logging of all operations and errors
- Automatic cleanup of artifacts regardless of processing outcome

===== USAGE EXAMPLE =========================================================================

python3 quickscan_target.py -p PROJECT_ID -t gs://BUCKET_NAME -k API_KEY -s API_SECRET [-b BATCH_SIZE] [-w WORKERS] [-d CHECK_DELAY] [-l LOG_LEVEL]

Example scenarios:
1. Process 1500 files in batches of 500 using 10 workers:
   python3 quickscan_target.py -p PROJECT_ID -t gs://BUCKET_NAME -k API_KEY -s API_SECRET -b 500 -w 10

2. Default processing (1000 file batches, 10 workers):
   python3 quickscan_target.py -p PROJECT_ID -t gs://BUCKET_NAME -k API_KEY -s API_SECRET
"""

import os
import time
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from google.cloud import storage
from falconpy import APIHarnessV2, QuickScanPro


class Configuration:  # pylint: disable=R0902
    """Class to hold our running configuration."""

    def __init__(self, args):
        self.log_level = logging.INFO
        if args.log_level:
            if args.log_level.upper() in "DEBUG,WARN,ERROR".split(","):
                if args.log_level.upper() == "DEBUG":
                    self.log_level = logging.DEBUG
                elif args.log_level.upper() == "WARN":
                    self.log_level = logging.WARN
                elif args.log_level.upper() == "ERROR":
                    self.log_level = logging.ERROR

        self.batch = 1000
        if args.batch:
            self.batch = int(args.batch)
        self.max_workers = 10
        if args.max_workers:
            self.max_workers = int(args.max_workers)
        self.scan_delay = 3
        if args.check_delay:
            try:
                self.scan_delay = int(args.check_delay)
            except ValueError:
                pass
        self.project = None
        if args.project_id:
            self.project = args.project_id
        if "gs://" in args.target:
            self.target_dir = args.target.replace("gs://", "")
            self.bucket = True
        else:
            self.target_dir = args.target
            self.bucket = False
        self.falcon_client_id = args.key
        self.falcon_client_secret = args.secret


class QuickScanApp:
    """Main application class"""

    def __init__(self):
        self.config = None
        self.logger = None
        self.auth = None
        self.scanner = None

    def initialize(self):
        """Initialize the application components"""
        args = parse_command_line()
        self.config = Configuration(args)
        self.logger = self.enable_logging()
        self.auth = self.load_api_config()
        self.scanner = QuickScanPro(auth_object=self.auth)
        self.logger.info("Process startup complete, preparing to run scan")

    def enable_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=self.config.log_level,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
        log = logging.getLogger("QuickScan Pro")
        rfh = RotatingFileHandler(
            "falcon_quick_scan.log", maxBytes=20971520, backupCount=5
        )
        f_format = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        rfh.setLevel(self.config.log_level)
        rfh.setFormatter(f_format)
        log.addHandler(rfh)
        return log

    def load_api_config(self):
        """Return an instance of the authentication class"""
        return APIHarnessV2(
            client_id=self.config.falcon_client_id,
            client_secret=self.config.falcon_client_secret,
            user_agent="cloud-storage-protection/gcp/on-demand",
        )

    def run(self):
        """Main execution method"""
        try:
            if self.config.bucket:
                self.upload_bucket_samples()
            else:
                raise SystemExit(
                    "Invalid bucket name specified. Please include 'gs://' in your target."
                )
            self.logger.info("Scan completed")
        except Exception as e:
            self.logger.error("Error during scan: %s", str(e))
            raise

    def upload_bucket_samples(self):
        """Retrieve keys from a bucket and then uploads them to the QuickScan Pro API."""
        if not self.config.project:
            self.logger.error(
                "You must specify a project ID in order to scan a bucket target"
            )
            raise SystemExit(
                "Target project ID not specified. Use -p or --project to specify the \
                    target project ID."
            )

        gcs = storage.Client(project=self.config.project)
        try:
            bucket = gcs.get_bucket(self.config.target_dir)
        except Exception as err:
            self.logger.error(
                "Unable to connect to bucket %s. %s", self.config.target_dir, err
            )
            raise SystemExit(
                f"Unable to connect to bucket {self.config.target_dir}. {err}"
            ) from err

        summaries = list(bucket.list_blobs())
        total_files = len(summaries)

        self.logger.info(
            "Processing %d files in batches of %d using %d worker threads",
            total_files,
            self.config.batch,
            self.config.max_workers,
        )

        max_file_size = 256 * 1024 * 1024  # 256MB in bytes

        # Process files in batches using optimized 3-phase workflow
        for i in range(0, total_files, self.config.batch):
            batch_end = min(i + self.config.batch, total_files)
            current_batch = summaries[i:batch_end]
            batch_num = (i // self.config.batch) + 1

            self.logger.info(
                "Processing batch %d: files %d to %d (%d files)",
                batch_num,
                i + 1,
                batch_end,
                len(current_batch),
            )

            # Phase 1: Parallel upload with auto-scan (scan=True)
            uploaded = []
            self.logger.info("Phase 1: Uploading files with auto-scan enabled...")
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                future_to_file = {
                    executor.submit(self.upload_file, item, max_file_size): item
                    for item in current_batch
                }

                completed = 0
                for future in as_completed(future_to_file):
                    result = future.result()
                    completed += 1
                    if completed % 10 == 0:
                        self.logger.info(
                            "Upload progress: %d/%d files", completed, len(current_batch)
                        )
                    if result:
                        uploaded.append(result)

            if not uploaded:
                self.logger.warning("No files were successfully uploaded in batch %d", batch_num)
                continue

            self.logger.info(
                "Phase 1 complete: %d/%d files uploaded successfully",
                len(uploaded),
                len(current_batch),
            )

            # Phase 2: Batch poll for results
            self.logger.info("Phase 2: Polling for scan results...")
            scan_ids = [item["scan_id"] for item in uploaded]
            results = self.poll_batch_results(scan_ids)
            self.logger.info("Phase 2 complete: All scan results received")

            # Phase 3: Report results and batch cleanup
            self.logger.info("Phase 3: Reporting results and cleaning up...")
            for item in uploaded:
                scan_result = results.get(item["scan_id"])
                if scan_result:
                    self.report_single_result({
                        "filename": item["filename"],
                        "full_path": item["full_path"],
                        "sha256": item["sha256"],
                        "results": scan_result,
                    })

            # Batch cleanup - delete all files in one API call
            sha256_list = [item["sha256"] for item in uploaded]
            self.cleanup_batch(sha256_list)

            self.logger.info("Completed batch %d", batch_num)

        self.logger.info("Completed processing all %d files", total_files)

    def upload_file(self, item, max_file_size):
        """Upload a single file with auto-scan enabled. Returns immediately after upload."""
        if item.size > max_file_size:
            self.logger.warning(
                "Skipping %s: File size %d bytes exceeds maximum of %d bytes",
                item.name,
                item.size,
                max_file_size,
            )
            return None

        try:
            filename = os.path.basename(item.name)
            file_data = item.download_as_bytes()

            # Upload file with scan=True to auto-launch scan
            response = self.auth.command(
                "UploadFileMixin0Mixin94",
                files=[("file", (filename, file_data))],
                data={"scan": True},
            )

            if response["status_code"] >= 300:
                if "errors" in response["body"]:
                    self.logger.warning(
                        "%s. Unable to upload file.",
                        response["body"]["errors"][0]["message"],
                    )
                else:
                    self.logger.warning("Rate limit exceeded.")
                return None

            resource = response["body"]["resources"][0]
            sha = resource["sha256"]
            scan_id = resource["scan_id"]
            self.logger.info("Uploaded %s (sha256: %s, scan_id: %s)", filename, sha, scan_id)

            return {
                "filename": filename,
                "full_path": item.name,
                "sha256": sha,
                "scan_id": scan_id,
            }

        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("Error uploading file %s: %s", item.name, str(e))
            return None

    def poll_batch_results(self, scan_ids: list) -> dict:
        """Poll for results of multiple scans using batch API calls."""
        results = {}
        pending = set(scan_ids)

        while pending:
            # Single API call for all pending scans
            response = self.scanner.get_scan_result(ids=list(pending))

            if response["status_code"] >= 300:
                self.logger.warning("Error polling scan results: %s", response)
                time.sleep(self.config.scan_delay)
                continue

            for resource in response["body"].get("resources", []):
                scan_id = resource["id"]
                if resource.get("scan", {}).get("status") == "done":
                    results[scan_id] = resource.get("result", {}).get("file_artifacts", [])
                    pending.discard(scan_id)

            if pending:
                self.logger.debug("Waiting for %d scans to complete...", len(pending))
                time.sleep(self.config.scan_delay)

        return results

    def cleanup_batch(self, sha256_list: list):
        """Delete multiple files in a single API call."""
        if not sha256_list:
            return

        self.logger.info("Cleaning up %d files...", len(sha256_list))
        response = self.scanner.delete_file(ids=sha256_list)

        if response["status_code"] >= 300:
            self.logger.warning("Error during batch cleanup: %s", response)
        else:
            self.logger.info("Batch cleanup complete")

    def report_single_result(self, result):
        """Report results for a single file."""
        for artifact in result["results"]:
            if artifact["sha256"] == result["sha256"]:
                verdict = artifact["verdict"].lower().replace(" ", "_")
                if verdict == "unknown":
                    self.logger.info(
                        "Unscannable/Unknown file %s: verdict %s",
                        result["full_path"],
                        verdict,
                    )
                elif verdict in ("clean", "likely_benign"):
                    self.logger.info(
                        "Verdict for %s: %s", result["full_path"], verdict
                    )
                else:  # suspicious, malicious
                    self.logger.warning(
                        "Verdict for %s: %s", result["full_path"], verdict
                    )


def parse_command_line():
    """Parse any inbound command line arguments and set defaults."""
    parser = argparse.ArgumentParser("quickscan_target.py")
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        help="Default log level (DEBUG, WARN, INFO, ERROR)",
        required=False,
    )
    parser.add_argument(
        "-d",
        "--check-delay",
        dest="check_delay",
        help="Delay between checks for scan results",
        required=False,
    )
    parser.add_argument(
        "-b",
        "--batch",
        dest="batch",
        help="The number of files to include in a volume to scan (default: 1000).",
        required=False,
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="max_workers",
        help="Maximum number of worker threads to use for scanning (default: 10).",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--project",
        dest="project_id",
        help="Project ID the target bucket resides in",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        help="Cloud Storage bucket to scan. Bucket must have 'gs://' prefix.",
        required=True,
    )
    parser.add_argument(
        "-k", "--key", dest="key", help="CrowdStrike Falcon API KEY", required=True
    )
    parser.add_argument(
        "-s",
        "--secret",
        dest="secret",
        help="CrowdStrike Falcon API SECRET",
        required=True,
    )
    return parser.parse_args()


if __name__ == "__main__":
    app = QuickScanApp()
    app.initialize()
    app.run()
