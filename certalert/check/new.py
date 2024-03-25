import requests
import json
import psycopg2

# Function to format certificate data
def format_certificate(cert_data):
    # Replace line breaks with "\\n"
    formatted_cert_data = cert_data.replace("\n", "\\n")
    return formatted_cert_data

# Function to retrieve certificate data from database
def retrieve_certificate_data(partner_id):
    # PostgreSQL connection parameters
    db_host = "postgres.csrmbka.mosip.net"
    db_port = "5432"
    db_name_pms = "mosip_pms"
    db_name_keymgr = "mosip_keymgr"
    db_user = "postgres"
    db_password = "S9ONAmKGVL"

    try:
        # Connect to the PMS database
        pms_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name_pms,
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
        keymgr_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name_keymgr,
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
def authenticate_and_get_token():
    auth_url = "https://api-internal.csrmbka.mosip.net/v1/authmanager/authenticate/clientidsecretkey"
    headers = {"Content-Type": "application/json"}

    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "ida",
            "clientId": "mosip-deployment-client",
            "secretKey": "5RmeIL1pUsMcOZzU"
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
        "requesttime": "2024-03-25T12:27:47.968Z",
        "version": "string"
    }

    # Log the upload request body
    print("Upload Request Body:", json.dumps(upload_data))

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
