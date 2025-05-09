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

# Function to generate a unique resource group name
generate_resource_group_name() {
    local prefix="cs-storage-protection-demo"
    local random_suffix
    random_suffix=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8)
    echo "${prefix}-${random_suffix}"
}

# Save state information
save_state() {
    echo "RESOURCE_GROUP_NAME=${1}" > "${STATE_FILE}"
    echo "Created on: $(date)" >> "${STATE_FILE}"
}

# Load state information
load_resource_group_name() {
    if [[ -f "${STATE_FILE}" ]]; then
        source "${STATE_FILE}"
        echo "${RESOURCE_GROUP_NAME}"
    else
        die "State file not found. Please run 'up' command first."
    fi
}

# Function to handle the 'up' mode
handle_up() {
    local fid fsecret resource_group_name
    project_id=$(azure_get_subscription_id)
    echo "--------------------------------------------------"
    echo "Using Azure Subscription ID: ${project_id}"
    echo "--------------------------------------------------"

    # Generate a unique resource group name
    resource_group_name=$(generate_resource_group_name)
    echo "Using resource group name: ${resource_group_name}"
    echo "--------------------------------------------------"

    # Save the resource group name for later use
    save_state "${resource_group_name}"

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

    terraform -chdir=demo apply -compact-warnings \
        --var "falcon_client_id=${fid}" \
        --var "falcon_client_secret=${fsecret}" \
        --var "base_url=$(cs_cloud)" \
        --var "resource_group_name=${resource_group_name}" \
        --auto-approve

    echo -e "${GRN}\nPausing for 30 seconds to allow configuration to settle.${NC}"

    sleep 30
    configure_environment demo
}

# Function to handle the 'down' mode
handle_down() {
    local success=1

    # Load the resource group name from state file
    local resource_group_name
    resource_group_name=$(load_resource_group_name)

    echo "Destroying resources in group: ${resource_group_name}"

    while ((success != 0)); do
        if terraform -chdir=demo destroy -compact-warnings \
            --var "resource_group_name=${resource_group_name}" \
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
