#!/bin/bash

date=$(date --utc +%FT%T.%3NZ)
AUTHMANAGER_URL=https://api-internal.collab.mosip.net
KEYMANAGER_URL=https://api-internal.collab.mosip.net
KEYCLOAK_CLIENT_ID=mosip-pms-client
KEYCLOAK_CLIENT_SECRET=l8l1ubom47lYakhi
AUTH_APP_ID=partner

RED='\033[0;31m'
NC='\033[0m'

echo "ENVIRONMENT URL: $AUTHMANAGER_URL"

# Request for authorization
response=$(curl -sS -D - \
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
  }')

TOKEN=$(echo "$response" | awk '/[aA]uthorization:/{print $2}' | tr -d '\n\r')

if [[ -z $TOKEN ]]; then
  echo "Failed to obtain token from authmanager response"
  echo "EXITING"
  exit 1
fi

echo -e "\nGot Authorization token from authmanager"

# Clean up temporary files
rm -f temp.txt

PARTNER_IDS=$(grep 'PARTNER_ID' partner.properties | cut -d'=' -f2 | tr ',' '\n')

for PARTNER_ID in $PARTNER_IDS; do
  echo -e "\nProcessing partner ID: $PARTNER_ID"

  # Request certificate information
  response=$(curl -sS -X "GET" \
      -H "Accept: application/json" \
      --cookie "Authorization=$TOKEN" \
      "$KEYMANAGER_URL/v1/partnermanager/partners/$PARTNER_ID/certificate")

  # Extract certificate data from the response
  CERTIFICATE_DATA=$(echo "$response" | jq -r '.response.certificateData')

  # Check if certificate data is null
  if [ "$CERTIFICATE_DATA" == "null" ]; then
      echo "No data available for $PARTNER_ID in keymanager"
      continue
  fi

  # Check if certificate data is present and proceed to check validity
  if [ ! -z "$CERTIFICATE_DATA" ]; then
      # Extract validity end date from the certificate
      VALIDITY_END=$(echo "$CERTIFICATE_DATA" | openssl x509 -noout -enddate | cut -d'=' -f2)
      # Convert validity end date to numeric value
      VALIDITY_END_NUMERIC="$(date -d "$VALIDITY_END" +%s)"

      # Get current date in numeric value
      CURRENT_DATE_NUMERIC=$(date +%s)

      # Check if certificate is expired
      if [ "$VALIDITY_END_NUMERIC" -lt "$CURRENT_DATE_NUMERIC" ]; then
        echo "Certificate for Partner ID: $PARTNER_ID is expired. Validity End: $VALIDITY_END"
      else
        echo "Certificate for Partner ID: $PARTNER_ID is valid. Validity End: $VALIDITY_END"
      fi
  fi

done
