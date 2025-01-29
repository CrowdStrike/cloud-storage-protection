#!/bin/bash
DG="\033[1;30m"
RD="\033[0;31m"
NC="\033[0;0m"
LB="\033[1;34m"
all_done(){
    echo -e "$LB"
    echo '  __                        _'
    echo ' /\_\/                   o | |             |'
    echo '|    | _  _  _    _  _     | |          ,  |'
    echo '|    |/ |/ |/ |  / |/ |  | |/ \_|   |  / \_|'
    echo ' \__/   |  |  |_/  |  |_/|_/\_/  \_/|_/ \/ o'
    echo -e "$NC"
}
env_destroyed(){
    echo -e "$RD"
    echo ' ___                              __,'
    echo '(|  \  _  , _|_  ,_        o     /  |           __|_ |'
    echo ' |   ||/ / \_|  /  | |  |  |    |   |  /|/|/|  |/ |  |'
    echo '(\__/ |_/ \/ |_/   |/ \/|_/|/    \_/\_/ | | |_/|_/|_/o'
    echo -e "$NC"
}

# Ensure script is executed from the cloud-storage-protection/demo directory
[[ -d demo ]] && [[ -d lambda ]] || { echo -e "\nThis script should be executed from the cloud-storage-protection/demo directory.\n"; exit 1; }

if [ -z "$1" ]
then
   echo "You must specify 'up' or 'down' to run this script"
   exit 1
fi
MODE=$(echo "$1" | tr [:upper:] [:lower:])
if [[ "$MODE" == "up" ]]
then
	read -sp "CrowdStrike API Client ID: " FID
	echo
	read -sp "CrowdStrike API Client SECRET: " FSECRET
    UNIQUE=$(echo $RANDOM | md5sum | sed "s/[[:digit:].-]//g" | head -c 8)
    ALIAS="quickscan-pro-demo"
    if ! [ -f demo/.terraform.lock.hcl ]; then
        terraform init
    fi
	terraform apply -compact-warnings --var falcon_client_id=$FID \
		--var falcon_client_secret=$FSECRET --var unique_id=$UNIQUE \
        --var env_alias=$ALIAS --auto-approve
    echo -e "$RD\nPausing for 60 seconds to allow configuration to settle.$NC"
    echo "Setting up..."
    TESTS="/home/cloudshell-user/cloud-storage-protection/AWS/demo/testfiles"
    mkdir $TESTS
    echo "export BUCKET=s3://${ALIAS}-bucket-${UNIQUE}" >> /etc/profile
    source /etc/profile
    cp /home/cloudshell-user/cloud-storage-protection/AWS/demo/bin/get-findings.sh /usr/local/bin/get-findings
    cp /home/cloudshell-user/cloud-storage-protection/AWS/demo/bin/upload.sh /usr/local/bin/upload
    chmod +x /usr/local/bin/*

    # GET SAFE EXAMPLES
    echo "Getting safe example files..."
    wget -O $TESTS/safe.png https://www.crowdstrike.com/wp-content/uploads/2023/02/COSMIC-WOLF_AU_500px-300x300.png
    wget -O $TESTS/safe.jpg https://www.crowdstrike.com/blog/wp-content/uploads/2018/04/April-Adversary-Stardust.jpg

    # GET MALICIOUS EXAMPLES
    echo "Getting malicious example files..."
    wget -O malqueryinator.py https://raw.githubusercontent.com/CrowdStrike/falconpy/main/samples/malquery/malqueryinator.py
    python3 -m pip install urllib3==1.26.15 crowdstrike-falconpy
    python3 malqueryinator.py -v ryuk -t wide -f malicious.zip -e 3 -k $FID -s $FSECRET
    unzip -d $TESTS -P infected malicious.zip
    C=0
    for f in $(ls $TESTS --hide=**.*)
    do
        ((C=C+1))
        mv $TESTS/$f $TESTS/malicious$C.bin
    done
    chown -R ec2-user:ec2-user $TESTS
    rm malicious.zip
    rm malqueryinator.py
    echo ""
    echo "Setup complete. Use the upload command to upload and scan files."
    echo ""
    sleep 60
    all_done
	exit 0
fi
if [[ "$MODE" == "down" ]]
then
	terraform destroy -compact-warnings --auto-approve
    rm lambda/quickscan-bucket.zip
    env_destroyed
	exit 0
fi
echo "Invalid command specified."
exit 1

