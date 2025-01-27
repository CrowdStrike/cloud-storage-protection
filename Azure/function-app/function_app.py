"""CrowdStrike Azure Storage Account Container Protection with QuickScan.

Based on the work of @jshcodes w/ s3-bucket-protection & @carlos.matos w/ cloud-storage-protection

Creation date: 05.27.24 - gax.theodorio@CrowdStrike
"""

import io
import os
import time
import json
import logging
import azure.functions as func
import azurefunctions.extensions.bindings.blob as blob
from falconpy import OAuth2, QuickScanPro

app = func.FunctionApp()

# Maximum file size for scan (256mb)
MAX_FILE_SIZE = 256 * 1024 * 1024


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

# Connect to the QuickScan Pro API
Scanner = QuickScanPro(auth_object=auth)


@app.blob_trigger(
    arg_name="client",
    path=os.environ.get("quick_scan_container_name", ""),
    connection="azurequickscan_STORAGE",
)
def container_protection(client: blob.BlobClient):
    """Azure Function app entry point"""
    blob_properties = client.get_blob_properties()
    upload_file_size = blob_properties["size"]
    file_name = blob_properties["name"]
    container = blob_properties["container"]
    if upload_file_size < MAX_FILE_SIZE:
        # Get the blob file
        blob_data = io.BytesIO(client.download_blob().read())
        # Upload the file to the CrowdStrike Falcon Sandbox
        response = Scanner.upload_file(
            file=blob_data,
            scan=True,
        )
        if response["status_code"] > 201:
            logging.warning(str(response))
            error_msg = (
                f"Error uploading object {file_name} from "
                f"bucket {container} to QuickScan Pro. "
                "Make sure your API key has the correct permissions."
            )
            raise SystemExit(error_msg)
        else:
            logging.info("File uploaded to CrowdStrike Falcon Sandbox.")

        # QuickScan Pro
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
                    logging.info(scan_msg)
                elif verdict == "unknown":
                    # Undertermined scan failure
                    scan_msg = f"Unable to scan {file_name}"
                    logging.info(scan_msg)
                elif verdict in ["malicious", "suspicious"]:
                    # Mitigation would trigger from here
                    scan_msg = f"Verdict for {file_name}: {result['verdict']}"
                    logging.warning(scan_msg)
                    threat_removed = False
                    if MITIGATE:
                        # Remove the threat
                        try:
                            client.delete_blob()
                            threat_removed = True
                        except Exception as err:
                            logging.warning(
                                "Unable to remove threat %s from bucket %s",
                                file_name,
                                container,
                            )
                            print(f"{err}")
                    else:
                        # Mitigation is disabled. Complain about this in the logging.
                        logging.warning(
                            "Threat discovered (%s). Mitigation disabled, threat persists in %s bucket.",
                            file_name,
                            container,
                        )

                    if threat_removed:
                        logging.info(
                            "Threat %s removed from bucket %s", file_name, container
                        )
                else:
                    # Unrecognized response
                    scan_msg = f"Unrecognized response ({result['verdict']}) received from API for {file_name}."
                    logging.info(scan_msg)

            # Clean up the artifact in the sandbox
            response = Scanner.delete_file(ids=upload_sha)
            if response["status_code"] > 201:
                logging.warning("Could not remove sample %s from sandbox.", file_name)
            else:
                logging.info("Sample %s removed from sandbox.", file_name)
        except Exception as err:
            logging.error(err)
            print(
                f"Error getting object {file_name} from bucket {container}. "
                "Make sure they exist and your bucket is in the same region as this function."
            )
            raise err

    else:
        msg = f"File ({file_name}) exceeds maximum file scan size ({MAX_FILE_SIZE} bytes), skipped."
        logging.warning(msg)
