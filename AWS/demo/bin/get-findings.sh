#!/bin/bash
LOG_GROUP=/aws/lambda/quikscan-pro-demo-function
LOG_STREAM=`aws logs describe-log-streams --log-group-name $LOG_GROUP --max-items 1 --order-by LastEventTime --descending --query logStreams[].logStreamName --output text | head -n 1`
OUTPUT=`aws logs get-log-events --log-group-name $LOG_GROUP --log-stream-name $LOG_STREAM --query events[].message --output text | grep -v -w "credentials" | grep -e 'INFO' -e 'WARNING'`
echo ""
echo "Latest findings:"
echo ""
echo "$OUTPUT"
echo ""