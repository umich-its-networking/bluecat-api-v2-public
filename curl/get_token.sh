#!/bin/bash
# get_token.sh
# reads user and pw from environment variables
x=$(curl $BLUECAT_CURL_OPTIONS -sS -X POST -H "Content-Type: application/json" -d '{"username": "'$BLUECAT_USERNAME'","password": "'$BLUECAT_PASSWORD'"}' http
s://$BLUECAT_SERVER/api/v2/sessions)
basicauth=$(echo $x | jq .basicAuthenticationCredentials | tr -d '"')
echo "export BLUECAT_BASICAUTH=$basicauth"
