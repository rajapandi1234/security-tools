################THIS IS A WIP,DONT' USE IT#######################################################
import subprocess
import json
from datetime import datetime

# Define environment variables
AUTHMANAGER_URL = "https://api-internal.collab.mosip.net"
KEYMANAGER_URL = "https://api-internal.collab.mosip.net"
KEYCLOAK_CLIENT_ID = "mosip-pms-client"
KEYCLOAK_CLIENT_SECRET = "l8l1ubom47lYakhi"
AUTH_APP_ID = "partner"

RED = '\033[0;31m'
NC = '\033[0m'

def main():
    current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    print("ENVIRONMENT URL:", AUTHMANAGER_URL)

    # Request for authorization
    auth_data = {
        "id": "string",
        "version": "string",
        "requesttime": current_date,
        "metadata": {},
        "request": {
            "clientId": KEYCLOAK_CLIENT_ID,
            "secretKey": KEYCLOAK_CLIENT_SECRET,
            "appId": AUTH_APP_ID
        }
    }
    auth_data_json = json.dumps(auth_data)

    auth_command = [
        "curl", "-sS", "-X", "POST",
        f"{AUTHMANAGER_URL}/v1/authmanager/authenticate/clientidsecretkey",
        "-H", "accept: */*",
        "-H", "Content-Type: application/json",
        "-d", auth_data_json
    ]
    auth_process = subprocess.Popen(auth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    auth_output, auth_error = auth_process.communicate()

    if auth_error:
        print("Error occurred while requesting authorization:")
        print(auth_error.decode())
        return

    auth_response_headers = auth_output.decode()
    token = extract_token_from_headers(auth_response_headers)

    if not token:
        print("Failed to obtain token from authmanager response headers")
        print("EXITING")
        return

    print("\nGot Authorization token from authmanager:", token)

    # Read partner IDs from properties file
    with open("partner.properties", "r") as file:
        partner_ids = file.readline().split("=")[1].strip().split(",")

    for partner_id in partner_ids:
        print(f"\nProcessing partner ID: {partner_id}")

        # Get certificate information
        certificate_command = [
            "curl", "-sS", "-X", "GET",
            "-H", "Accept: application/json",
            "--cookie", f"Authorization={token}",
            f"{KEYMANAGER_URL}/v1/partnermanager/partners/{partner_id}/certificate"
        ]
        certificate_process = subprocess.Popen(certificate_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        certificate_output, certificate_error = certificate_process.communicate()

        if certificate_error:
            print(f"Error occurred while fetching certificate information for partner ID {partner_id}:")
            print(certificate_error.decode())
            continue

        certificate_response = json.loads(certificate_output)
        response_count = certificate_response.get("response")

        if not response_count:
            print(f"No response from keymanager server for partner ID {partner_id}; Skipping")
            continue

        certificate_data = certificate_response.get("response", {}).get("certificateData")

        if not certificate_data:
            print(f"Unable to read certificate from result for partner ID {partner_id}; Skipping")
            continue

        expiration_date = datetime.strptime(certificate_data['enddate'], "%b %d %H:%M:%S %Y %Z")
        current_timestamp = datetime.utcnow()
        if current_timestamp > expiration_date:
            print(f"{RED}Certificate for partner ID {partner_id} has expired on {expiration_date}.{NC}")
        else:
            print(f"Certificate for partner ID {partner_id} is still valid until {expiration_date}")

def extract_token_from_headers(headers):
    token = None
    header_lines = headers.split('\n')
    for line in header_lines:
        if line.startswith("Authorization: Bearer"):
            token = line.split()[1]
            break
    return token

if __name__ == "__main__":
    main()
