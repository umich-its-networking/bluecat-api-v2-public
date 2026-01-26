#!/bin/bash
# logout.sh
# logs out the token created in get_token.sh

x=$(curl -sS -X 'PATCH' 'https://'$BLUECAT_SERVER'/api/v2/sessions/current' 
    -d '{"state": "LOGGED_OUT"}' 
    -H 'Content-Type: application/merge-patch+json' 
    -H 'Authorization: Basic '"$BLUECAT_BASICAUTH")
if [[ ! ( "$x" =~ LOGGED_OUT ) ]]; then
  echo "ERROR - failed to log out? $x"
  exit 2
fi
