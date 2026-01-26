#!/bin/bash
# get_token.sh
# reads user and pw from environment variables
x=$(curl $BLUECAT_CURL_OPTIONS -sS -X POST -H "Content-Type: application/json" -d '{"username": "'$BLUECAT_USERNAME'","password": "'$BLUECAT_PASSWORD'"}' https://$BLUECAT_SERVER/api/v2/sessions)
BLUECAT_BASICAUTH=$(sed -E -e 's/^.*basicAuthenticationCredentials":"([^"]+)".*$/\1/' <<< "$x")
echo "run this next line to add it to your environment:"
echo "export BLUECAT_BASICAUTH=$BLUECAT_BASICAUTH"

# to end a session, see "logout.sh"
