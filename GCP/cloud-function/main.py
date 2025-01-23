# pylint: disable=W1401
# flake8: noqa
"""CrowdStrike GCP Cloud Storage Bucket Protection using QuickScan Pro.

This Cloud Function monitors GCP Storage buckets for new file uploads and automatically
scans them for malware using CrowdStrike's QuickScan Pro API. Files exceeding 256MB
are skipped. Based on scan results and configuration, malicious files can be
automatically removed from the bucket.

Requirements:
    - CrowdStrike Falcon API credentials (Client ID and Secret)
    - GCP Service Account with appropriate permissions
    - Python packages: google-cloud-storage, google-cloud-logging, crowdstrike-falconpy

Environment Variables:
    Required:
        FALCON_CLIENT_ID: CrowdStrike API client ID
        FALCON_CLIENT_SECRET: CrowdStrike API client secret

    Optional:
        MITIGATE_THREATS: Boolean flag to enable automatic removal of threats (default: "TRUE")
        BASE_URL: CrowdStrike API base URL (default: "https://api.crowdstrike.com")

File Size Limits:
    Maximum scannable file size: 256MB

Author: cloud-integrations@crowdstrike.com
Created: 2025-01-16
"""

import os
import time
import logging
import urllib.parse
import json
import google.cloud.logging
from google.cloud import storage

# FalconPy SDK - Auth, Sample Uploads and Quick Scan
from falconpy import OAuth2, QuickScanPro  # pylint: disable=E0401

# Maximum file size for scan (256mb)
MAX_FILE_SIZE = 256 * 1024 * 1024

# GCP Logging Client
gcp_logging_client = google.cloud.logging.Client()
# Configure GCP Logging to utilize standard python logging
gcp_logging_client.setup_logging()
log = logging.getLogger()
log.setLevel(logging.INFO)

# GCP Storage handler
gcs = storage.Client()

# Mitigate threats?
MITIGATE = bool(json.loads(os.environ.get("MITIGATE_THREATS", "TRUE").lower()))

# Base URL
BASE_URL = os.environ.get("BASE_URL", "https://api.crowdstrike.com")

# Grab our Falcon API creds from the environment if they exist
try:
    client_id = os.environ["FALCON_CLIENT_ID"]
except KeyError as exc:
    raise SystemExit("FALCON_CLIENT_ID environment variable not set") from exc

try:
    client_secret = os.environ["FALCON_CLIENT_SECRET"]
except KeyError as exc:
    raise SystemExit("FALCON_CLIENT_SECRET environment variable not set") from exc

# Authenticate to the CrowdStrike Falcon API
auth = OAuth2(
    creds={"client_id": client_id, "client_secret": client_secret}, base_url=BASE_URL
)
# Connect to the Quick Scan API
Scanner = QuickScanPro(auth_object=auth)


# Main routine
def cs_bucket_protection(event, _):
    """GCP Cloud Functions entry point"""
    bucket_name = event["bucket"]
    bucket = gcs.get_bucket(bucket_name)
    file_name = urllib.parse.unquote_plus(event["name"], encoding="utf-8")
    upload_file_size = int(event["size"])
    if upload_file_size < MAX_FILE_SIZE:
        # Get the file from GCP
        blob = bucket.blob(file_name)
        blob_data = blob.download_as_bytes()
        # Upload the file to the CrowdStrike Falcon QuickScan Pro
        response = Scanner.upload_file(file=blob_data, scan=True)
        if response["status_code"] > 201:
            error_msg = (
                f"Error uploading object {file_name} from "
                f"bucket {bucket_name} to QuickScan Pro. "
                "Make sure your API key has the correct permissions."
            )
            raise SystemExit(error_msg)
        else:
            log.info("File uploaded to QuickScan Pro.")

        # Quick Scan
        try:
            # Uploaded file unique identifier
            upload_sha = response["body"]["resources"][0]["sha256"]
            # Scan request ID, generated when the request for the scan is made
            scan_id = Scanner.launch_scan(sha256=upload_sha)["body"]["resources"][0][
                "id"
            ]
            scanning = True
            # Loop until we get a result or the function times out
            while scanning:
                # Retrieve our scan using our scan ID
                scan_results = Scanner.get_scan_result(ids=scan_id)
                result = None
                try:
                    if scan_results["body"]["resources"][0]["scan"]["status"] == "done":
                        # Scan is complete, retrieve our results (there will be only one)
                        result = scan_results["body"]["resources"][0]["result"][
                            "file_artifacts"
                        ][0]
                        # and break out of the loop
                        scanning = False
                    else:
                        # Not done yet, sleep for a bit
                        time.sleep(3)
                except IndexError:
                    # Results aren't populated yet, skip
                    pass

            if result["sha256"] == upload_sha:
                verdict = result["verdict"].lower()
                if verdict == "clean":
                    # File is clean
                    scan_msg = f"No threat found in {file_name}"
                    log.info(scan_msg)
                elif verdict == "unknown":
                    # Undertermined scan failure
                    scan_msg = f"Unable to scan {file_name}"
                    log.info(scan_msg)
                elif verdict in ["malicious", "suspicious"]:
                    # Mitigation would trigger from here
                    scan_msg = f"Verdict for {file_name}: {result['verdict']}"
                    log.warning(scan_msg)
                    threat_removed = False
                    if MITIGATE:
                        # Remove the threat
                        try:
                            blob.delete()
                            threat_removed = True
                        except Exception as err:  # pylint: disable=broad-except
                            log.warning(
                                "Unable to remove threat %s from bucket %s",
                                file_name,
                                bucket_name,
                            )
                            print(f"{err}")
                    else:
                        # Mitigation is disabled. Complain about this in the log.
                        log.warning(
                            "Threat discovered (%s). Mitigation disabled, threat persists in %s bucket.",
                            file_name,
                            bucket_name,
                        )

                    if threat_removed:
                        log.info(
                            "Threat %s removed from bucket %s", file_name, bucket_name
                        )
                else:
                    # Unrecognized response
                    scan_msg = f"Unrecognized response ({result['verdict']}) received from API for {file_name}."
                    log.info(scan_msg)

            # Clean up the artifact in the sandbox
            response = Scanner.delete_file(ids=upload_sha)
            if response["status_code"] > 201:
                log.warning(
                    "Could not remove sample (%s) from QuickScan Pro.", file_name
                )

            return scan_msg
        except Exception as err:
            print(err)
            print(
                f"Error getting object {file_name} from bucket {bucket_name}. "
                "Make sure they exist and your bucket is in the same region as this function."
            )
            raise err

    else:
        msg = f"File ({file_name}) exceeds maximum file scan size ({MAX_FILE_SIZE} bytes), skipped."
        log.warning(msg)
        return msg
