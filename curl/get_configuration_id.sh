#!/bin/bash
# get_configuration_id.sh [configuration_name]

if [ "X" != "X$1" ]; then
  cfgname=$1
elif [ "X" != "X$BLUECAT_CONFIGURATION" ]; then
  cfgname=$BLUECAT_CONFIGURATION
else
  echo "please put Configuration name in the environment variable $BLUECAT_CONFIGURATION or as an argument on the command line"
  exit 1
fi


# get authentication
#x=$(curl $BLUECAT_CURL_OPTIONS -sS -X POST -H "Content-Type: application/json" -d '{"username": "'$BLUECAT_USERNAME'","password": "'$BLUECAT_PASSWORD'"}' https://$BLUECAT_SERVER/api/v2/sessions)
#BLUECAT_BASICAUTH=$(sed -E -e 's/^.*basicAuthenticationCredentials":"([^"]+)".*$/\1/' <<< "$x")

# get configuration_id
x=$(curl $BLUECAT_CURL_OPTIONS -sS -X 'GET' 'https://'$BLUECAT_SERVER'/api/v2/configurations?fields=id&filter=name%3Aeq%28%27'"$cfgname"'%27%29' -H 'accept: application/hal+json' -H 'Authorization: Basic '$BLUECAT_BASICAUTH)
if [[ "$x" =~ :0, ]]; then
  echo "ERROR - Configuration '$cfgname' Not Found, response: $x"
else
  sed -E -e 's/^.*id":([^}]+)}.*$/\1/' <<< "$x"
fi

# log out
x=$(curl -sS -X 'PATCH' 'https://'$BLUECAT_SERVER'/api/v2/sessions/current' -d '{"state": "LOGGED_OUT"}' -H 'Content-Type: application/merge-patch+json' -H 'Authorization: Basic '"$BLUECAT_BASICAUTH")
if [[ ! ( "$x" =~ LOGGED_OUT ) ]]; then
  echo "ERROR - failed to log out? $x"
  exit 2
fi
