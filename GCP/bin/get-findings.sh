#!/bin/sh
printf "Output from Cloud Functions logs:\n"
gcloud functions logs read FUNCTION --min-log-level=info | grep -E 'Threat|Verdict'
