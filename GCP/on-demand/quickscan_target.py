# pylint: disable=W1401
# flake8: noqa
"""Scan a GCP bucket with the CrowdStrike Quick Scan Pro API.

Scans a GCP Cloud Storage bucket using the CrowdStrike Falcon Quick Scan and Sample Uploads APIs.
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
- Batch Processing:
    * Total files are divided into batches (default: 1000 files per batch)
    * Each batch is processed sequentially
    * Example: 1500 files with batch=500 creates 3 batches of 500 files each

- Worker Threads:
    * Within each batch, files are processed concurrently
    * Number of concurrent operations controlled by max_workers (default: 10)
    * Example: With max_workers=10, up to 10 files from the current batch
      are processed simultaneously

PERFORMANCE CONSIDERATIONS:
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
from falconpy import OAuth2, QuickScanPro


class Analysis:
    """Class to hold our analysis and status."""

    def __init__(self):
        self.uploaded = []
        self.files = []
        self.scan_ids = []
        self.scanning = True


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
        log = logging.getLogger("Quick Scan")
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
        return OAuth2(
            client_id=self.config.falcon_client_id,
            client_secret=self.config.falcon_client_secret,
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
        """Retrieve keys from a bucket and then uploads them to the Sandbox API."""
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

        # Process files in batches
        for i in range(0, total_files, self.config.batch):
            batch_end = min(i + self.config.batch, total_files)
            current_batch = summaries[i:batch_end]

            self.logger.info(
                "Processing batch %d: files %d to %d (%d files)",
                (i // self.config.batch) + 1,
                i + 1,
                batch_end,
                len(current_batch),
            )

            # Process current batch using thread pool
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                future_to_file = {
                    executor.submit(self.process_single_file, item, max_file_size): item
                    for item in current_batch
                }

                completed = 0
                for future in as_completed(future_to_file):
                    result = future.result()
                    completed += 1
                    if completed % 10 == 0:  # Log progress every 10 files
                        self.logger.info(
                            "Batch progress: %d/%d files", completed, len(current_batch)
                        )

                    if result:
                        if result.get("results"):
                            self.report_single_result(result)
                        # Clean up the artifact
                        self.scanner.delete_file(ids=result["sha256"])

            self.logger.info("Completed batch %d", (i // self.config.batch) + 1)

        self.logger.info("Completed processing all %d files", total_files)

    def process_single_file(self, item, max_file_size):
        """Process a single file: upload, scan, and get results."""
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

            # Upload file
            response = self.scanner.upload_file(file=file_data, scan=True)
            sha = response["body"]["resources"][0]["sha256"]
            self.logger.info("Uploaded %s to %s", filename, sha)

            # Launch scan
            scanned = self.scanner.launch_scan(sha256=sha)
            if scanned["status_code"] >= 300:
                if "errors" in scanned["body"]:
                    self.logger.warning(
                        "%s. Unable to launch scan for file.",
                        scanned["body"]["errors"][0]["message"],
                    )
                else:
                    self.logger.warning("Rate limit exceeded.")
                return None

            scan_id = scanned["body"]["resources"][0]["id"]
            self.logger.info("Scan %s submitted for analysis", scan_id)

            # Get results
            results = self.scan_uploaded_samples(Analysis(), scan_id)

            return {
                "filename": filename,
                "full_path": item.name,
                "sha256": sha,
                "scan_id": scan_id,
                "results": results,
            }

        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("Error processing file %s: %s", item.name, str(e))
            return None

    def report_single_result(self, result):
        """Report results for a single file."""
        for artifact in result["results"]:
            if artifact["sha256"] == result["sha256"]:
                verdict = artifact["verdict"].lower()
                if verdict == "unknown":
                    self.logger.info(
                        "Unscannable/Unknown file %s: verdict %s",
                        result["full_path"],
                        verdict,
                    )
                else:
                    if verdict == "clean":
                        self.logger.info(
                            "Verdict for %s: %s", result["full_path"], verdict
                        )
                    else:
                        self.logger.warning(
                            "Verdict for %s: %s", result["full_path"], verdict
                        )

    def scan_uploaded_samples(self, analyzer: Analysis, scan_id: str) -> dict:
        """Retrieve a scan using the ID of the scan provided by the scan submission."""
        results = {}
        analyzer.scanning = True
        self.logger.info("Waiting for scan results...")
        while analyzer.scanning:
            scan_results = self.scanner.get_scan_result(ids=scan_id)
            try:
                if scan_results["body"]["resources"][0]["scan"]["status"] == "done":
                    results = scan_results["body"]["resources"][0]["result"][
                        "file_artifacts"
                    ]
                    analyzer.scanning = False
                else:
                    time.sleep(self.config.scan_delay)
            except IndexError:
                pass
        return results


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
        help="Target folder or bucket to scan. Bucket must have 'gs://' prefix.",
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
