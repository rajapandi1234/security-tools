import os
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from datetime import datetime, timedelta

# Function to read value from bootstrap.properties
def read_bootstrap_properties(key):
    with open('bootstrap.properties', 'r') as file:
        for line in file:
            if line.startswith(key):
                return line.split('=')[1].strip()
    return None

# Function to check if certificate is expired
def is_certificate_expired(expiration_date):
    # Parse expiration date string
    expiration_date = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")
    # Get current date
    current_date = datetime.utcnow()
    # Compare expiration date with current date
    return current_date > expiration_date

# Function to write expired certificates to a text file
def write_to_expired_txt(cert_name):
    with open('expired.txt', 'a') as file:
        file.write(cert_name + '\n')

# Fetching environment variables or values from bootstrap.properties
URL = os.getenv('mosip-api-internal-host')
KEYCLOAK_CLIENT_SECRET = os.getenv('mosip_pms_client_secret')
PRE_EXPIRY_DAYS = read_bootstrap_properties("pre-expiry-days")  # Read pre-expiry days from bootstrap.properties

# Fetching environment variables and if not found then from bootstrap.properties
URL = URL or read_bootstrap_properties("base_url")
KEYCLOAK_CLIENT_SECRET = KEYCLOAK_CLIENT_SECRET or read_bootstrap_properties("pms-client-secret")
KEYCLOAK_CLIENT_ID = "mosip-pms-client"
AUTH_APP_ID = "partner"
date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

# Ensure URL is trimmed of any leading or trailing whitespace characters
URL = URL.strip()

print("ENVIRONMENT URL:", URL)

# Request for authorization
try:
    req = Request(f"https://{URL}/v1/authmanager/authenticate/clientidsecretkey",
                  headers={"Content-Type": "application/json"},
                  method="POST",
                  data=json.dumps({
                      "id": "string",
                      "version": "string",
                      "requesttime": date,
                      "metadata": {},
                      "request": {
                          "clientId": KEYCLOAK_CLIENT_ID,
                          "secretKey": KEYCLOAK_CLIENT_SECRET,
                          "appId": AUTH_APP_ID
                      }}).encode('utf-8'))
    response = urlopen(req)
    response_data = json.loads(response.read().decode('utf-8'))
    TOKEN = response.headers.get('Authorization')  # Extract token from headers
    print(response_data)  # Print the response data
except HTTPError as e:
    print("Failed to obtain token from authmanager response")
    print("EXITING")
    exit(1)

if not TOKEN:
    print("Failed to obtain token from authmanager response")
    print("EXITING")
    exit(1)

print("\nGot Authorization token from authmanager:", TOKEN)

# PARTNER_IDS read from partner.properties
expired_certs = set()  # Set to store unique expired certificates

with open('partner.properties', 'r') as file:
    for line in file:
        if line.startswith('PARTNER_ID'):
            partner_ids = line.strip().split('=')[1].split(',')
            for PARTNER_ID in partner_ids:
                print(f"\nProcessing partner ID: {PARTNER_ID.strip()}")
                # Request certificate information
                try:
                    req = Request(f"https://{URL}/v1/partnermanager/partners/{PARTNER_ID.strip()}/certificate",
                                  headers={
                                      "Content-Type": "application/json",
                                      "Cookie": f"Authorization={TOKEN}"
                                  },
                                  method="GET")
                    response = urlopen(req)
                    response_data = json.loads(response.read().decode('utf-8'))
                    print(response_data)
                    CERTIFICATE_DATA = response_data.get('response', {}).get('certificateData')
                    print (CERTIFICATE_DATA)
                    # Run openssl command to print certificate details
                    openssl_command = f"echo '{CERTIFICATE_DATA}' | openssl x509 -noout -enddate"
                    expiration_date = os.popen(openssl_command).read().split('=')[1].strip()
                    print("Certificate expiration date:", expiration_date)
                    # Check if certificate is expired or pre-expiry
                    if is_certificate_expired(expiration_date) or \
                            (datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()) <= timedelta(days=int(PRE_EXPIRY_DAYS)):
                        expired_certs.add(PARTNER_ID.strip())  # Add to set of expired certificates
                except HTTPError as e:
                    print(f"Error occurred while fetching certificate information for {PARTNER_ID}: {e}")
                    continue

                if not CERTIFICATE_DATA:
                    print(f"No data available for {PARTNER_ID} in keymanager.")
                    continue

# Write expired certificates to expired.txt
with open('expired.txt', 'w') as file:
    for cert_name in expired_certs:
        file.write(cert_name + '\n')

print("Expired certificates have been written to expired.txt file.")
# Open and print the contents of expired.txt
with open('expired.txt', 'r') as file:
    print("Expired certificates:")
    for line in file:
        print(line.strip())