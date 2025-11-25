#!/bin/bash
# get_token.sh
# reads user and pw from environment variables
x=$(curl $BLUECAT_CURL_OPTIONS -sS -X POST -H "Content-Type: application/json" -d '{"username": "'$BLUECAT_USERNAME'","password": "'$BLUECAT_PASSWORD'"}' https://$BLUECAT_SERVER/api/v2/sessions)
BLUECAT_BASICAUTH=$(sed -E -e 's/^.*basicAuthenticationCredentials":"([^"]+)".*$/\1/' <<< "$x")
echo "export BLUECAT_BASICAUTH=$BLUECAT_BASICAUTH"

# how to log out at the end of a session:
# x=$(curl -sS -X 'PATCH' 'https://'$BLUECAT_SERVER'/api/v2/sessions/current' -d '{"state": "LOGGED_OUT"}' -H 'Content-Type: application/merge-patch+json' -H 'Authorization: Basic '"$BLUECAT_BASICAUTH")
# if [[ ! ( "$x" =~ LOGGED_OUT ) ]]; then
#   echo "ERROR - failed to log out? $x"
#   exit 2
# fi
