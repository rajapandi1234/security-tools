from configparser import ConfigParser
from minio import Minio
from minio.error import ResponseError
import psycopg2
from stdnum import verhoeff
from deduce import Deduce
import re
import os

def is_valid_verhoeff(number):
    return verhoeff.is_valid(str(number))

def is_valid_email(email):
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    match = email_pattern.match(str(email))
    return bool(match)

def is_valid_mobile_number(phone_number):
    pattern = re.compile(r'^[9]\d{9}$')
    match = re.match(pattern, str(phone_number))
    return bool(match)

# Print environment variable values
print("Environment Variables:")
for env_var in [
    'db-server', 'db-port', 'db-su-user', 'postgres-password',
    's3-host', 's3-region', 's3-user-key', 's3-user-secret', 's3-bucket-name'
]:
    print(f"{env_var}: {os.environ.get(env_var)}")

# Read connection details from environment variables or db.properties file
db_server = os.environ.get('db-server')
db_port = os.environ.get('db-port')
db_user = os.environ.get('db-su-user')
db_password = os.environ.get('postgres-password')

minio_host = os.environ.get('s3-host')
minio_region = os.environ.get('s3-region')
minio_user_key = os.environ.get('s3-user-key')
minio_user_secret = os.environ.get('s3-user-secret')
minio_bucket_name = os.environ.get('s3-bucket-name')

# If environment variables are not set, read from db.properties file
if not all([db_server, db_port, db_user, db_password, minio_host, minio_user_key, minio_user_secret, minio_bucket_name]):
    config = ConfigParser()
    config.read('db.properties')

    db_server = config.get('PostgreSQL Connection', 'db-host')
    db_port = config.get('PostgreSQL Connection', 'db-port')
    db_user = config.get('PostgreSQL Connection', 'db-su-user')
    db_password = config.get('PostgreSQL Connection', 'postgres-password')

    minio_host = config.get('MinIO Connection', 's3-host')
    minio_region = config.get('MinIO Connection', 's3-region')
    minio_user_key = config.get('MinIO Connection', 's3-user-key')
    minio_user_secret = config.get('MinIO Connection', 's3-user-secret')
    minio_bucket_name = config.get('MinIO Connection', 's3-bucket-name')

    # If environment variables are not set, read from db.properties file
    if not all([db_server, db_port, db_user, db_password, minio_host, minio_region, minio_user_key, minio_user_secret, minio_bucket_name]):
        config = ConfigParser()
        config.read('db.properties')

        db_server = config.get('PostgreSQL Connection', 'db-server')
        db_port = config.get('PostgreSQL Connection', 'db-port')
        db_user = config.get('PostgreSQL Connection', 'db-su-user')
        db_password = config.get('PostgreSQL Connection', 'postgres-password')

        minio_host = config.get('MinIO Connection', 's3-host')
        minio_region = config.get('MinIO Connection', 's3-region')
        minio_user_key = config.get('MinIO Connection', 's3-user-key')
        minio_user_secret = config.get('MinIO Connection', 's3-user-secret')
        minio_bucket_name = config.get('MinIO Connection', 's3-bucket-name')

    # Define the databases list
    databases = [
        {"name": "mosip_esignet", "schema": "esignet"},
        # Add other databases as needed
    ]

    connection = psycopg2.connect(
        host=db_server,
        port=db_port,
        user=db_user,
        password=db_password,
        database="")  # The database name is taken from the script's 'databases' list

    try:
        output_file_path = 'id.txt'
        ignore_columns = ['status', 'cr_by']
        ignore_tables = ['client_detail', 'reg_available_slot', 'batch_job_execution',
                         'batch_job_execution_context', 'batch_job_execution_params', 'batch_job_instance',
                         'batch_step_execution', 'batch_step_execution_context']

        for db_info in databases:
            print(f"\nAnalyzing data in Database: {db_info['name']}\n")
            deduce_sensitive_data(connection, db_info['name'], db_info['schema'], output_file_path, ignore_columns,
                                   ignore_tables)

        print(f"\nDeduced findings saved to {output_file_path}, mails.txt, mobile_numbers.txt")

        # Add the following lines to push reports to MinIO
        s3_host = minio_host
        s3_region = minio_region
        s3_user_key = minio_user_key
        s3_user_secret = minio_user_secret
        s3_bucket_name = minio_bucket_name

        push_reports_to_s3(s3_host, s3_region, s3_user_key, s3_user_secret, s3_bucket_name)

    finally:
        connection.close()

# Call the main function
deduce_sensitive_data_in_databases()
