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

def deduce_sensitive_data(connection, database_name, schema_name, output_file, ignore_columns, ignore_tables):
    deduce_instance = Deduce()

    with connection.cursor() as cursor:
        cursor.execute(f"SET search_path TO {schema_name}")
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (schema_name,))
        tables = [table[0] for table in cursor.fetchall()]

        with open(output_file, 'a') as deduced_file:
            for table_name in tables:
                if ignore_tables and table_name in ignore_tables:
                    print(f"Ignoring Table: {table_name} in Database: {database_name}")
                    continue

                print(f"Currently checking Table: {table_name} in Database: {database_name}")
                deduced_file.write(f"Currently checking Table: {table_name} in Database: {database_name}\n")

                cursor.execute(f'SELECT * FROM {table_name}')
                rows = cursor.fetchall()

                for row in rows:
                    for i, column_value in enumerate(row):
                        column_name = cursor.description[i][0]

                        if ignore_columns and column_name in ignore_columns:
                            continue

                        deduced_result = deduce_instance.deidentify(
                            str(column_value),
                            disabled={'names', 'institutions', 'locations', 'dates', 'ages', 'urls'}
                        )

                        if deduced_result.annotations and is_valid_verhoeff(column_value):
                            deduced_file.write(f"Column: {column_name}, Data: {column_value}\n")
                            deduced_file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                        with open('mobile_numbers.txt', 'a') as file:
                            if deduced_result.annotations and is_valid_mobile_number(column_value):
                                file.write(f"Column: {column_name}, Data: {column_value}\n")
                                file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                        with open('mails.txt', 'a') as file:
                            if deduced_result.annotations and is_valid_email(column_value):
                                file.write(f"Column: {column_name}, Data: {column_value}\n")
                                file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

def push_reports_to_s3(s3_host, s3_region, s3_user_key, s3_user_secret, s3_bucket_name):
    mc = Minio(s3_host,
               access_key=s3_user_key,
               secret_key=s3_user_secret,
               region=s3_region,
               secure=False)  # Set secure=True if using HTTPS

    try:
        if not mc.bucket_exists(s3_bucket_name):
            mc.make_bucket(s3_bucket_name, location=s3_region)

        mc.fput_object(s3_bucket_name, 'reports/id.txt', 'id.txt')
        mc.fput_object(s3_bucket_name, 'reports/mails.txt', 'mails.txt')
        mc.fput_object(s3_bucket_name, 'reports/mobile_numbers.txt', 'mobile_numbers.txt')

        print("\nReports pushed to MinIO")

    except ResponseError as err:
        print(f"MinIO Error: {err}")

def deduce_sensitive_data_in_databases():
    databases = [
       {"name": "mosip_esignet", "schema": "esignet"},
       # ... other databases
    ]

    connection = psycopg2.connect(
        host='postgres.dev.mosip.net',
        port=5432,
        user='postgres',
        password='mQi298ZW7p',
        database=databases[0]['name']
    )

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
        s3_host = "10.3.148.78"  # Update with your MinIO host
        s3_region = ""  # Update with your S3 region
        s3_user_key = "admin"  # Update with your S3 user key
        s3_user_secret = "http://minio.minio:9000"  # Update with your S3 user secret
        s3_bucket_name = "security-testrig"  # Update with your S3 bucket name

        push_reports_to_s3(s3_host, s3_region, s3_user_key, s3_user_secret, s3_bucket_name)

    finally:
        connection.close()

deduce_sensitive_data_in_databases()
