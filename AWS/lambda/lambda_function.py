# pylint: disable=W1401
# flake8: noqa
"""CrowdStrike AWS S3 Bucket Protection using QuickScan Pro.

This Lambda Function monitors AWS S3 buckets for new file uploads and automatically
scans them for malware using CrowdStrike's QuickScan Pro API. Files exceeding 256MB
are skipped. Based on scan results and configuration, malicious files can be
automatically removed from the bucket.

Requirements:
    - CrowdStrike Falcon API credentials (Client ID and Secret)
    - AWS CLI configured with appropriate permissions
    - Python packages: boto3, crowdstrike-falconpy

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

import json
import logging
import os
import time
import sys
import base64
import subprocess
import boto3
import urllib
from botocore.exceptions import ClientError

# pip install falconpy package to /tmp/ and add to path
subprocess.call('pip install crowdstrike-falconpy -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sys.path.insert(1, '/tmp/')
# FalconPy SDK - Auth, Sample Uploads and Quick Scan
from falconpy import OAuth2, QuickScanPro  # pylint: disable=E0401

# AWS Secret Vars
SECRET_STORE_NAME = os.environ['SECRET_NAME']
SECRET_STORE_REGION = os.environ['SECRET_REGION']

# Maximum file size for scan (256mb)
MAX_FILE_SIZE = 256 * 1024 * 1024

log = logging.getLogger()
log.setLevel(logging.INFO)

# S3 Client handler
s3 = boto3.client('s3')

# Mitigate threats?
MITIGATE = bool(json.loads(os.environ.get("MITIGATE_THREATS", "TRUE").lower()))

# Base URL
BASE_URL = os.environ.get("BASE_URL", "https://api.crowdstrike.com")

def get_secret():
    """Function to get secret"""
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=SECRET_STORE_REGION
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=SECRET_STORE_NAME
        )
    except ClientError as e:
        raise e
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    else:
        secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    return secret

def falcon_auth(client_id, client_secret):
    # Authenticate to the CrowdStrike Falcon API
    auth = OAuth2(
        creds={"client_id": client_id, "client_secret": client_secret}, base_url=BASE_URL
    )
    # Connect to the Quick Scan API
    Scanner = QuickScanPro(auth_object=auth)
    return Scanner

# Main routine
def lambda_handler(event, _):
    """Function Handler"""
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    upload_file_size = int(event['Records'][0]['s3']['object']["size"])
    try:
        secret_str = get_secret()
        if secret_str:
            secrets_dict = json.loads(secret_str)
            falcon_client_id = secrets_dict['FalconClientId']
            falcon_secret = secrets_dict['FalconSecret']
            auth = OAuth2(
                creds={"client_id": falcon_client_id, "client_secret": falcon_secret}, base_url=BASE_URL
            )
            # Connect to the Quick Scan API
            Scanner = QuickScanPro(auth_object=auth)
        if upload_file_size < MAX_FILE_SIZE:
            # Get the file from S3
            s3.download_file(bucket_name, key, f'/tmp/{key}')
            # Upload the file to the CrowdStrike Falcon QuickScan Pro
            response = Scanner.upload_file(file=f'/tmp/{key}', scan=True)
            if response["status_code"] > 201:
                error_msg = (
                    f"Error uploading object {key} from "
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
                        scan_msg = f"No threat found in {key}"
                        log.info(scan_msg)
                    elif verdict == "unknown":
                        # Undertermined scan failure
                        scan_msg = f"Unable to scan {key}"
                        log.info(scan_msg)
                    elif verdict in ["malicious", "suspicious"]:
                        # Mitigation would trigger from here
                        scan_msg = f"Verdict for {key}: {result['verdict']}"
                        log.warning(scan_msg)
                        threat_removed = False
                        if MITIGATE:
                            # Remove the threat
                            try:
                                s3.delete_object(Bucket=bucket_name,Key=key)
                                threat_removed = True
                            except Exception as err:  # pylint: disable=broad-except
                                log.warning(
                                    "Unable to remove threat %s from bucket %s",
                                    key,
                                    bucket_name,
                                )
                                print(f"{err}")
                        else:
                            # Mitigation is disabled. Complain about this in the log.
                            log.warning(
                                "Threat discovered (%s). Mitigation disabled, threat persists in %s bucket.",
                                key,
                                bucket_name,
                            )

                        if threat_removed:
                            log.info(
                                "Threat %s removed from bucket %s", key, bucket_name
                            )
                    else:
                        # Unrecognized response
                        scan_msg = f"Unrecognized response ({result['verdict']}) received from API for {key}."
                        log.info(scan_msg)

                # Clean up the artifact in the sandbox
                response = Scanner.delete_file(ids=upload_sha)
                if response["status_code"] > 201:
                    log.warning(
                        "Could not remove sample (%s) from QuickScan Pro.", key
                    )

                return scan_msg
            except Exception as err:
                print(f'Error: {err}')
                raise err

        else:
            msg = f"File ({key}) exceeds maximum file scan size ({MAX_FILE_SIZE} bytes), skipped."
            log.warning(msg)
            return msg
    except Exception as err:
        log.info('Demo Failed %s' % err)
