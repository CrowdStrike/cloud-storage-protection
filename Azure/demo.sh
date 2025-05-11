#!/bin/bash
# set -euo pipefail

# Constants
export TESTS="${HOME}/testfiles"
readonly RD="\033[1;31m"
readonly GRN="\033[1;33m"
readonly NC="\033[0;0m"
readonly LB="\033[1;34m"
readonly STATE_FILE="./demo/.cs_demo_state"

# Source the common functions
# shellcheck disable=SC1091
source ./.functions.sh

# Ensure script is ran in quickscan-pro directory
if [[ ! -d demo ]] || [[ ! -d function-app ]]; then
    die "Please run this script from the quickscan-pro root directory"
fi

# Validate command line argument
if [ $# -ne 1 ]; then
    die "Usage: $0 [up|down]"
fi

# Save terraform outputs to state file
save_state() {
    # Store terraform output values for later use in teardown
    terraform -chdir=demo output -json > "${STATE_FILE}"
    echo "Created on: $(date)" >> "${STATE_FILE}"
}

# Function to handle the 'up' mode
handle_up() {
    local fid fsecret
    project_id=$(azure_get_subscription_id)
    echo "--------------------------------------------------"
    echo "Using Azure Subscription ID: ${project_id}"
    echo "--------------------------------------------------"

    read -rsp "CrowdStrike API Client ID: " fid
    echo
    read -rsp "CrowdStrike API Client SECRET: " fsecret
    echo

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
    if [[ ! -f demo/.terraform.lock.hcl ]]; then
        terraform -chdir=demo init
    fi

    if ! terraform -chdir=demo apply -compact-warnings \
        --var "falcon_client_id=${fid}" \
        --var "falcon_client_secret=${fsecret}" \
        --var "base_url=$(cs_cloud)" \
        --auto-approve; then
            die "Terraform apply failed. Please check the error messages above."
    fi

    # Save the terraform state for teardown
    save_state

    echo -e "${GRN}\nPausing for 30 seconds to allow configuration to settle.${NC}"

    sleep 30
    configure_environment demo
}

# Function to handle the 'down' mode
handle_down() {
    local success=1

    # Check if state file exists
    if [[ ! -f "${STATE_FILE}" ]]; then
        die "State file not found. Please run 'up' command first."
    fi

    echo "Destroying resources..."

    while ((success != 0)); do
        if terraform -chdir=demo destroy -compact-warnings \
            --auto-approve; then
            success=0
        else
            echo -e "${RD}\nTerraform destroy failed. Retrying in 5 seconds.${NC}"
            sleep 5
        fi
    done

    # Cleanup
    rm -f ~/.local/bin/{get-findings,upload,list-bucket}
    rm -rf "${TESTS}" /tmp/malicious
    rm -f "${STATE_FILE}"
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
