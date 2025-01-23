#!/bin/bash
set -euo pipefail

# Constants
export TESTS="${HOME}/testfiles"
readonly RD="\033[1;31m"
readonly GRN="\033[1;33m"
readonly NC="\033[0;0m"
readonly LB="\033[1;34m"

# Source the common functions
source ./.functions.sh

# Ensure script is ran in quickscan-pro directory
if [[ ! -d existing ]] || [[ ! -d cloud-function ]]; then
    die "Please run this script from the quickscan-pro root directory"
fi

# Validate command line argument
if [ $# -ne 1 ]; then
    die "Usage: $0 [up|down]"
fi

# Function to handle the 'up' mode
handle_up() {
    local project_id fid fsecret bucket_name response_headers
    project_id=$(gcp_get_project_id)

    echo "--------------------------------------------------"
    echo "Using GCP project ID: ${project_id}"
    echo "--------------------------------------------------"

    read -rsp "CrowdStrike API Client ID: " fid
    echo
    read -rsp "CrowdStrike API Client SECRET: " fsecret
    echo
    read -rp "Bucket name: " bucket_name

    # Validate inputs
    if [[ -z "${fid}" ]] || [[ -z "${fsecret}" ]]; then
        die "You must specify a valid CrowdStrike API Client ID and SECRET"
    fi

    # Verify the CrowdStrike API credentials
    echo "Verifying CrowdStrike API credentials..."
    cs_falcon_cloud="us-1"
    response_headers=$(mktemp)
    trap 'rm -f "${response_headers}"' EXIT

    cs_verify_auth
    cs_set_base_url
    echo "Falcon Cloud URL set to: $(cs_cloud)"

    # Initialize and apply Terraform
    if [[ ! -f existing/.terraform.lock.hcl ]]; then
        terraform -chdir=existing init
    fi

    terraform -chdir=existing apply -compact-warnings \
        --var "falcon_client_id=${fid}" \
        --var "falcon_client_secret=${fsecret}" \
        --var "project_id=${project_id}" \
        --var "base_url=$(cs_cloud)" \
        --var "bucket_name=${bucket_name}" \
        --auto-approve

    echo -e "${GRN}\nPausing for 30 seconds to allow configuration to settle.${NC}"
    sleep 30
    configure_cloud_shell "existing"
}

# Function to handle the 'down' mode
handle_down() {
    local bucket_name success=1
    read -rp "Bucket name: " bucket_name

    while ((success != 0)); do
        if terraform -chdir=existing destroy -compact-warnings \
            --var "bucket_name=${bucket_name}" \
            --var "project_id=${project_id}" \
            --auto-approve; then
            success=0
        else
            echo -e "${RD}\nTerraform destroy failed. Retrying in 5 seconds.${NC}"
            sleep 5
        fi
    done

    # Cleanup
    sudo rm -f /usr/local/bin/{get-findings,upload,list-bucket}
    rm -rf "${TESTS}" /tmp/malicious
    env_destroyed
}

# Main execution
MODE=$(echo "$1" | tr '[:upper:]' '[:lower:]')
case "${MODE}" in
    up)
        handle_up
        ;;
    down)
        handle_down
        ;;
    *)
        die "Invalid command. Use 'up' or 'down'"
        ;;
esac
