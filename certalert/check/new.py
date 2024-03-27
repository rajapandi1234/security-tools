import os
import json
import psycopg2
import requests
from configparser import ConfigParser

# Function to format certificate data
def format_certificate(cert_data):
    # Replace line breaks with "\\n"
    formatted_cert_data = cert_data.replace("\n", "\\n")
    return formatted_cert_data

def retrieve_certificate_data(partner_id, db_host, db_port, db_user, db_password):
    try:
        # Connect to the PMS database
        pms_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database="mosip_pms",
            user=db_user,
            password=db_password
        )
        pms_cursor = pms_conn.cursor()

        # Query to retrieve the certificate alias
        sql_query_cert_alias = f"SELECT certificate_alias FROM pms.partner WHERE id = '{partner_id}';"
        pms_cursor.execute(sql_query_cert_alias)
        certificate_alias = pms_cursor.fetchone()[0]

        # Query to retrieve cert_data using the certificate alias
        sql_query_cert_data = f"SELECT cert_data FROM keymgr.partner_cert_store WHERE cert_id = '{certificate_alias}';"

        # Connect to the Keymgr database
        keymgr_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database="mosip_keymgr",
            user=db_user,
            password=db_password
        )
        keymgr_cursor = keymgr_conn.cursor()
        keymgr_cursor.execute(sql_query_cert_data)
        cert_data = keymgr_cursor.fetchone()[0]

        # Format the certificate data
        formatted_cert_data = format_certificate(cert_data)

        # Close connections
        pms_cursor.close()
        pms_conn.close()
        keymgr_cursor.close()
        keymgr_conn.close()

        return formatted_cert_data

    except Exception as e:
        print(f"Error retrieving certificate data for Partner ID {partner_id}: {str(e)}")
        return None

# Function to authenticate and retrieve the token
def authenticate_and_get_token(base_url, client_secret):
    auth_url = f"{base_url}/v1/authmanager/authenticate/clientidsecretkey"
    headers = {"Content-Type": "application/json"}

    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "ida",
            "clientId": "mosip-deployment-client",
            "secretKey": client_secret
        },
        "requesttime": "",  # Generate timestamp in desired format
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
def upload_certificate_with_token(token, cert_data, partner_id, base_url):
    upload_url = f"{base_url}/v1/partnermanager/partners/certificate/upload"
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"Authorization={token}"
    }

    # Format certificate data
    formatted_cert_data = cert_data.replace("\\n", "\n")

    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": formatted_cert_data,
            "partnerDomain": "AUTH",
            "partnerId": partner_id
        },
        "requesttime": "",  # Generate timestamp in desired format
        "version": "string"
    }

    # Log the upload request body
    #print("Upload Request Body:", json.dumps(upload_data))

    response = requests.post(upload_url, headers=headers, json=upload_data)

    # Print both request and response
    print("Upload API Request Body:", upload_data)
    print("Upload API Response:", response.text)

    # Check if "certificateId" is present in the response
    if "certificateId" not in response.text:
        print("Certificate upload failed.")
    else:
        print("Certificate upload successful.")

# Read environment variables
postgres_host = os.environ.get('POSTGRES_HOST')
postgres_port = os.environ.get('POSTGRES_PORT')
postgres_user = os.environ.get('POSTGRES_USER')
postgres_password = os.environ.get('POSTGRES_PASSWORD')
base_url = os.environ.get('BASE_URL')
client_secret = os.environ.get('CLIENT_SECRET')

# If environment variables are not set, read from bootstrap.properties file
if not all([postgres_host, postgres_port, postgres_user, postgres_password, base_url, client_secret]):
    config = ConfigParser()
    config.read('bootstrap.properties')
    postgres_host = config.get('Database', 'db-host', fallback='')
    postgres_port = config.get('Database', 'db-port', fallback='')
    postgres_user = config.get('Database', 'db-user', fallback='')
    postgres_password = config.get('Database', 'db-password', fallback='')
    base_url = config.get('API', 'base-url', fallback='')
    client_secret = config.get('API', 'client-secret', fallback='')

# Authenticate and get the token
token = authenticate_and_get_token(base_url, client_secret)

# Check if token is obtained successfully
if token:
    # Read partner IDs from the expired.txt file
    with open("expired.txt", "r") as file:
        partner_ids = [line.strip() for line in file if line.strip()]

    # Iterate through each partner ID and retrieve certificate data
    for partner_id in partner_ids:
        print(f"Certificate Data for Partner ID: {partner_id}")
        cert_data = retrieve_certificate_data(partner_id, postgres_host, postgres_port, postgres_user, postgres_password)
        if cert_data is not None:
            print(cert_data)
            # Upload certificate with token
            upload_certificate_with_token(token, cert_data, partner_id, base_url)

    if not partner_ids:
        print("No partner IDs found in the expired.txt file.")
else:
    print("Token retrieval failed.")
