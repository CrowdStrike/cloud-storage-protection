import os
import io
import time
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from falconpy import OAuth2, QuickScanPro

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)


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
        if "blob.core.windows" in args.target and "https://" in args.target:
            self.target = args.target
            self.target_prefix = "/".join(self.target.split("/")[4:])
            self.container_name = self.target.split("/")[3]
            self.container = True
            # parse storage account value from target
            self.storage_account = self.target.split("/")[2].split(".")[0]
        else:
            self.container = False
        # CrowdStrike API credentials
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
        return OAuth2(
            client_id=self.config.falcon_client_id,
            client_secret=self.config.falcon_client_secret,
        )

    def run(self):
        """Main execution method"""
        try:
            if self.config.container:
                self.upload_bucket_samples()
            else:
                raise SystemExit(
                    "Invalid storage container url specified. Please include the full url in your target value. Value should be in the format 'https://<storage_account_name>.blob.core.windows.net/<storage_container>/<path>'"
                )
            self.logger.info("Scan completed")
        except Exception as e:
            self.logger.error("Error during scan: %s", str(e))
            raise

    def retrieve_all_items(self, az_container):
        summaries = []

        page = az_container.list_blobs(name_starts_with=self.config.target_prefix)

        for item in page:
            summaries.append(item)

        return summaries

    def upload_bucket_samples(self):
        """Retrieve keys from a container and then uploads them to the QuickScan Pro API."""
        account_url = f"https://{self.config.storage_account}.blob.core.windows.net"
        default_credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(
            account_url, credential=default_credential
        )

        try:
            self.az_container = az_container = blob_service_client.get_container_client(
                container=self.config.container_name
            )
        except Exception as err:
            self.logger.error(
                "Unable to connect to container %s. %s", self.config.target_dir, err
            )
            raise SystemExit(
                f"Unable to connect to container {self.config.container_name}. {err}"
            )

        summaries = self.retrieve_all_items(az_container)
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
            file_data = io.BytesIO(
                self.az_container.get_blob_client(item).download_blob().readall()
            )

            # Upload file
            response = self.scanner.upload_file(file=file_data, scan=True)
            if "errors" in response["body"]:
                if len(response["body"]["errors"]) > 0:
                    self.logger.warning(
                        "There was an error while uploading %s to be scanned: %s",
                        filename,
                        response["body"]["errors"][0]["message"],
                    )
            sha = response["body"]["resources"][0]["sha256"]
            self.logger.info("Uploaded %s to %s", filename, sha)

            # Launch scan
            scanned = self.scanner.launch_scan(sha256=sha)
            if scanned["status_code"] >= 300:
                if "errors" in scanned["body"]:
                    self.logger.warning(
                        "%s. Unable to submit file for scan.",
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
    parser = argparse.ArgumentParser("Falcon QuickScan Pro Pro")
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
        help="The number of files to include in a volume to scan.",
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
        "-t",
        "--target",
        dest="target",
        help="Target folder or container to scan. Value must start with 'https://' and have '.blob.core.windows.net' url suffix.",
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
