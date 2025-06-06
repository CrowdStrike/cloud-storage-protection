#!/bin/bash
# Path: cloud-storage-protection/.functions.sh
# Helper functions for the CrowdStrike Falcon Azure Cloud Storage Protection demo

all_done() {
    echo -e "$LB"
    echo '╭━━━┳╮╱╱╭╮╱╱╱╭━━━┳━━━┳━╮╱╭┳━━━╮'
    echo '┃╭━╮┃┃╱╱┃┃╱╱╱╰╮╭╮┃╭━╮┃┃╰╮┃┃╭━━╯'
    echo '┃┃╱┃┃┃╱╱┃┃╱╱╱╱┃┃┃┃┃╱┃┃╭╮╰╯┃╰━━╮'
    echo '┃╰━╯┃┃╱╭┫┃╱╭╮╱┃┃┃┃┃╱┃┃┃╰╮┃┃╭━━╯'
    echo '┃╭━╮┃╰━╯┃╰━╯┃╭╯╰╯┃╰━╯┃┃╱┃┃┃╰━━╮'
    echo '╰╯╱╰┻━━━┻━━━╯╰━━━┻━━━┻╯╱╰━┻━━━╯'
    echo -e "$NC"
}

env_destroyed() {
    echo -e "$RD"
    echo '╭━━━┳━━━┳━━━┳━━━━┳━━━┳━━━┳╮╱╱╭┳━━━┳━━━╮'
    echo '╰╮╭╮┃╭━━┫╭━╮┃╭╮╭╮┃╭━╮┃╭━╮┃╰╮╭╯┃╭━━┻╮╭╮┃'
    echo '╱┃┃┃┃╰━━┫╰━━╋╯┃┃╰┫╰━╯┃┃╱┃┣╮╰╯╭┫╰━━╮┃┃┃┃'
    echo '╱┃┃┃┃╭━━┻━━╮┃╱┃┃╱┃╭╮╭┫┃╱┃┃╰╮╭╯┃╭━━╯┃┃┃┃'
    echo '╭╯╰╯┃╰━━┫╰━╯┃╱┃┃╱┃┃┃╰┫╰━╯┃╱┃┃╱┃╰━━┳╯╰╯┃'
    echo '╰━━━┻━━━┻━━━╯╱╰╯╱╰╯╰━┻━━━╯╱╰╯╱╰━━━┻━━━╯'
    echo -e "$NC"
}

# Azure get Subscription ID
azure_get_subscription_id() {
    # Get the Azure subscription ID
    # shellcheck disable=SC2005
    echo "$(az account show | json_value "id" 2>/dev/null)"
}
### API FALCON CLOUD LOGIC ###
cs_cloud() {
    case "${cs_falcon_cloud}" in
    us-1) echo "api.crowdstrike.com" ;;
    us-2) echo "api.us-2.crowdstrike.com" ;;
    eu-1) echo "api.eu-1.crowdstrike.com" ;;
    us-gov-1) echo "api.laggar.gcw.crowdstrike.com" ;;
    *) die "Unrecognized Falcon Cloud: ${cs_falcon_cloud}" ;;
    esac
}

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}

die() {
    echo -e "$RD"
    echo "Error: $*" >&2
    echo -e "$NC"
    exit 1
}

cs_verify_auth() {
    if ! command -v curl >/dev/null 2>&1; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi
    token_result=$(echo "client_id=${fid}&client_secret=${fsecret}" |
        curl -X POST -s -L "https://$(cs_cloud)/oauth2/token" \
            -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
            --dump-header "${response_headers}" \
            --data @-)
    token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$token" ]; then
        die "Unable to obtain CrowdStrike Falcon OAuth Token. Response was $token_result"
    fi
}

cs_set_base_url() {
    region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
    if [ -z "${region_hint}" ]; then
        die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, something went wrong."
    fi
    cs_falcon_cloud="${region_hint}"
}

download_malicious_examples() {
    max_retries=3

    wget -O malqueryinator.py https://raw.githubusercontent.com/CrowdStrike/falconpy/main/samples/malquery/malqueryinator.py
    python3 -m pip install urllib3==1.26.15 crowdstrike-falconpy

    success=0
    for ((retry_count = 0; retry_count < max_retries; retry_count++)); do
        python3 malqueryinator.py -v ryuk -t wide -f malicious.zip -e 3 -k "${fid}" -s "${fsecret}"
        ret=$?
        if [ $ret == 0 ]; then
            echo "Malicious files were succesfully downloaded."
            success=1
            break
        else
            echo "Files not successfully downloaded... retrying."
        fi
    done
    if [ "$success" -ne 1 ]; then
        echo "Malicious files failed to download after $max_retries tries. This could be due to a network error. Try rerunning demo."
        exit 1
    fi

}

configure_environment() {
    CHDIR="$1"
    STORAGE_ACCOUNT=$(terraform -chdir="${CHDIR}" output -raw demo_storage_account_name)
    STORAGE_CONTAINER=$(terraform -chdir="${CHDIR}" output -raw demo_storage_container_name)
    STORAGE_ACCOUNT_KEY=$(terraform -chdir="${CHDIR}" output -raw storage_account_key)
    APP_INSIGHTS_APP_ID=$(terraform -chdir="${CHDIR}" output -raw app_insights_app_id)

    # Ensure our variables are not empty
    if [[ -z "$STORAGE_ACCOUNT" || -z "$STORAGE_CONTAINER" || -z "$STORAGE_ACCOUNT_KEY" || -z "$APP_INSIGHTS_APP_ID" ]]; then
        die "Error: Required Terraform outputs are missing."
    fi

    echo -e "\nConfiguring environment for demo...\n"
    [[ -d $TESTS ]] || mkdir "$TESTS"
    # SAFE EXAMPLES
    echo -e "Copying safe sample files...\n"
    wget -q -O $TESTS/unscannable1.png https://www.crowdstrike.com/wp-content/uploads/2023/02/GEN-PANDA_AU_500px-1-300x300.png
    wget -q -O $TESTS/unscannable2.jpg https://www.crowdstrike.com/blog/wp-content/uploads/2018/04/April-Adversary-Stardust.jpg
    cp /usr/bin/whoami "$TESTS"/safe1.bin
    cp /usr/sbin/fdisk "$TESTS"/safe2.bin
    # # MALICIOUS EXAMPLES
    # echo -e "Malicious file prep...\n"
    download_malicious_examples
    unzip -d "$TESTS" -P infected malicious.zip
    C=0
    # shellcheck disable=SC2045
    for f in $(ls "$TESTS" --hide=**.*); do
        ((C = C + 1))
        mv "$TESTS"/"$f" "$TESTS"/malicious$C.bin
    done
    #chown -R ec2-user:ec2-user $TESTS
    rm malicious.zip
    rm malqueryinator.py

    # Helper scripts
    # Create ~/.local/bin if it doesn't exist
    mkdir -p ~/.local/bin

    # Check if .local/bin is already in PATH under any representation
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && [[ ":$PATH:" != *":~/.local/bin:"* ]]; then
        echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> ~/.bashrc
        export PATH="$HOME/.local/bin:$PATH"
        echo "Added ~/.local/bin to PATH"
    fi

    echo -e "Copying helper functions...\n"

    # Process and copy helper scripts
    sed -i "s/APP_INSIGHTS_APP_ID/${APP_INSIGHTS_APP_ID}/g" ./bin/get-findings
    sed -i "s/STORAGE_CONTAINER/${STORAGE_CONTAINER//\//\\/}/g" ./bin/upload
    sed -i "s/STORAGE_ACCOUNT_KEY/${STORAGE_ACCOUNT_KEY//\//\\/}/g" ./bin/upload
    sed -i "s/STORAGE_ACCOUNT/${STORAGE_ACCOUNT//\//\\/}/g" ./bin/upload
    sed -i "s/TESTS_DIR/${TESTS//\//\\/}/g" ./bin/upload
    sed -i "s/STORAGE_ACCOUNT_KEY/${STORAGE_ACCOUNT_KEY//\//\\/}/g" ./bin/list-bucket
    sed -i "s/STORAGE_ACCOUNT/${STORAGE_ACCOUNT//\//\\/}/g" ./bin/list-bucket
    sed -i "s/STORAGE_CONTAINER/${STORAGE_CONTAINER//\//\\/}/g" ./bin/list-bucket

    # Copy files to user's bin directory
    cp ./bin/{get-findings,upload,list-bucket} ~/.local/bin/
    chmod +x ~/.local/bin/{get-findings,upload,list-bucket}

    echo "Helper commands installed in ~/.local/bin"
    # install appication-insights extension
    az extension add --name application-insights

    # Clear screen
    clear
    all_done
    echo -e "Welcome to the CrowdStrike Falcon Azure Storage Account Container Protection demo environment!\n"
    echo -e "The name of your storage account is ${STORAGE_ACCOUNT}.\n"
    echo -e "The name of your storage account container is ${STORAGE_CONTAINER}.\n"
    echo -e "There are test files in the ${TESTS} folder. \nUse these to test the function_app trigger on storage container uploads. \n\nNOTICE: Files labeled \`malicious\` are DANGEROUS!\n"
    echo -e "Use the command \`upload\` to upload all of the test files to your demo storage container.\n"
    echo -e "You can view the contents of your storage container with the command \`list-bucket\`.\n"
    echo -e "Use the command \`get-findings\` to view all findings for your demo storage container.\n"
    echo -e "For the commands to work, you will need to update your path \`export PATH=~/cloud-storage-protection/Azure/bin:\$PATH\`.\n"
    echo -e "You may also need to login by using \`az login \` command to execute the \`get-findings\` command. \n"

}
