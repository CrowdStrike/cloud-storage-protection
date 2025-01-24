#!/bin/bash
LOG_GROUP=/aws/lambda/quickscan-pro-demo-function
for i in $(aws logs describe-log-streams --log-group-name $LOG_GROUP --max-items 5 --order-by LastEventTime --descending --query logStreams[].logStreamName --output text | head -n 4); do
  OUTPUT=`aws logs get-log-events --log-group-name $LOG_GROUP --log-stream-name $i --query events[].message --output text 2>&1 | grep -v -w "credentials" | grep -e 'INFO' -e 'WARNING'`
  if [[ $? -eq 0 ]]; then
    echo "$OUTPUT"
  else
    echo "Complete"
  fi
done