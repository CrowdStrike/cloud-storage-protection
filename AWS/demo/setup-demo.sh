#!/bin/bash

# READ FALCON API CREDENTIALS
echo "Enter your Falcon Client ID:"
read -s CLIENT_ID
echo "Enter your Falcon Secret:"
read -s SECRET

# SETUP ENVIRONMENT
echo "Setting up..."
TESTS="/home/cloudshell-user/cloud-storage-protection/AWS/demo/testfiles"
mkdir $TESTS
echo "export BUCKET=s3://quickscan-pro-demo-bucket" >> /etc/profile
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
python3 malqueryinator.py -v ryuk -t wide -f malicious.zip -e 3 -k $CLIENT_ID -s $SECRET
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