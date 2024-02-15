#!/bin/bash

date=$(date --utc +%FT%T.%3NZ)
AUTHMANAGER_URL=https://api-internal.dev2.mosip.net
KEYMANAGER_URL=https://api-internal.dev2.mosip.net
KEYCLOAK_CLIENT_ID=mosip-pms-client
KEYCLOAK_CLIENT_SECRET=GJQYpUmyLqhQBULI
AUTH_APP_ID=partner

RED='\033[0;31m'
NC='\033[0m'

echo "ENVIRONMENT URL: $AUTHMANAGER_URL"

# Request for authorization
curl $ADD_SSL_CURL -sS -D - \
  -X "POST" \
  "$AUTHMANAGER_URL/v1/authmanager/authenticate/clientidsecretkey" \
  -H "accept: */*" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "string",
    "version": "string",
    "requesttime": "'$date'",
    "metadata": {},
    "request": {
      "clientId": "'$KEYCLOAK_CLIENT_ID'",
      "secretKey": "'$KEYCLOAK_CLIENT_SECRET'",
      "appId": "'$AUTH_APP_ID'"
    }
  }' > temp.txt 2>&1

sleep 1
TOKEN=$(cat temp.txt | awk '/[aA]uthorization:/{print $2}' | sed -E 's/\n//g' | sed -E 's/\r//g')

if [[ -z $TOKEN ]]; then
  echo "Unable to Authenticate with authmanager. \"TOKEN\" is empty; EXITING";
  exit 1;
fi

echo -e "\nGot Authorization token from authmanager"


PARTNER_IDS=$(grep 'PARTNER_ID' partner.properties | cut -d'=' -f2 | tr ',' '\n')

for PARTNER_ID in $PARTNER_IDS; do
  echo -e "\nProcessing partner ID: $PARTNER_ID"


  curl -sS -X "GET" \
    -H "Accept: application/json" \
    --cookie "Authorization=$TOKEN" \
    "https://api-internal.dev2.mosip.net/v1/partnermanager/partners/$PARTNER_ID/certificate" > result.txt

  RESPONSE_COUNT=$(cat result.txt | jq .response)

  if [[ -z $RESPONSE_COUNT || $RESPONSE_COUNT == null ]]; then
    echo "No response from keymanager server for partner ID $PARTNER_ID; Skipping";
    continue;
  fi

  RESULT=$(cat result.txt)
  CERT=$(echo "$RESULT" | jq -r '.response.certificateData' | sed 's/\\n/\n/g')

  if [[ -z $CERT ]]; then
    echo "Unable to read certificate from result.txt for partner ID $PARTNER_ID; Skipping";
    continue;
  fi


  expiration_date=$(echo -n "$CERT" | openssl x509 -inform PEM -noout -enddate | awk -F= '{print $2}')
  current_timestamp=$(date +%s)
  expiration_timestamp=$(date -d "$expiration_date" +%s)

  if [ $current_timestamp -gt $expiration_timestamp ]; then
    echo -e "${RED}Certificate for partner ID $PARTNER_ID has expired on $expiration_date.${NC}"
  else
    echo "Certificate for partner ID $PARTNER_ID is still valid until $expiration_date."
  fi


  rm -f result.txt
done

# Clean up temporary files
rm -f temp.txt
