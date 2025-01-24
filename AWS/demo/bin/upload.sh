#!/bin/bash
echo "Uploading test files, please wait..."
for i in $(ls /home/cloudshell-user/cloud-storage-protection/AWS/demo/testfiles)
do
    aws s3 cp /home/cloudshell-user/cloud-storage-protection/AWS/demo/testfiles/$i $BUCKET/$i
done
echo "Upload complete. Check CloudWatch logs or use the get-findings command for scan results."