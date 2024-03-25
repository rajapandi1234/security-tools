import requests
import json

# Function to authenticate and retrieve the token
def authenticate_and_get_token():
    auth_url = "https://api-internal.csrmbka.mosip.net/v1/authmanager/authenticate/clientidsecretkey"
    headers = {"Content-Type": "application/json"}

    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "ida",
            "clientId": "mosip-deployment-client",
            "secretKey": "ePGsHWmm7RqftEZu"
        },
        "requesttime": "2024-03-25T12:27:47.968Z",
        "version": "string"
    }

    response = requests.post(auth_url, headers=headers, json=auth_data)
    if response.status_code == 200:
        token = response.headers.get("authorization")
        return token
    else:
        print("Authentication failed.")
        return None

# Function to upload certificate with authentication token
def upload_certificate_with_token(token, cert_data, partner_id):
    upload_url = "https://api-internal.csrmbka.mosip.net/v1/partnermanager/partners/certificate/upload"
    headers = {
        "Content-Type": "application/json",
        "Authorization": token
    }

    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": cert_data,
            "partnerDomain": "AUTH",
            "partnerId": partner_id
        },
        "requesttime": "2024-03-25T12:27:47.968Z",
        "version": "string"
    }

    response = requests.post(upload_url, headers=headers, json=upload_data)
    print("Upload API Response:", response.text)

# Authenticate and get the token
token = authenticate_and_get_token()

# Check if token is obtained successfully
if token:
    # Read partner IDs from the expired.txt file
    with open("expired.txt", "r") as file:
        partner_ids = [line.strip() for line in file if line.strip()]

    # Iterate through each partner ID and retrieve certificate data
    for partner_id in partner_ids:
        print(f"Certificate Data for Partner ID: {partner_id}")
        cert_data = retrieve_certificate_data(partner_id)
        if cert_data is not None:
            print(cert_data)
            # Upload certificate with token
            upload_certificate_with_token(token, cert_data, partner_id)
        print("------------------------------------------")

    if not partner_ids:
        print("No partner IDs found in the expired.txt file.")
else:
    print("Token retrieval failed.")
