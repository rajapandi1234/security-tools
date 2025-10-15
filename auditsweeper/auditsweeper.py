import os
import sys
import configparser
import psycopg2

# This script performs a cleanup of old log entries from a PostgreSQL database.
# It is designed to be run as a Docker container via a cron job.

def get_db_credentials():
    """
    Attempts to get database credentials from environment variables.
    If not found, falls back to a local.properties file.
    """
    # List of required variables
    required_vars = [
        "db-host", "db-port", "db-su-user",
        "postgres-password", "log-age-days"
    ]

    env_vars = {var: os.getenv(var) for var in required_vars}

    # Check if all environment variables are set
    if all(env_vars.values()):
        print("Using credentials from environment variables.")
        return env_vars
    else:
        print("One or more required environment variables are not set. Checking for local.properties...")
        config = configparser.ConfigParser()
        config_file = "local.properties"

        if not os.path.exists(config_file):
            print(f"Error: Required variables not set and '{config_file}' not found.")
            sys.exit(1)

        try:
            # Read the properties file, assuming a single section
            config.read_string(f"[DEFAULT]\n{open(config_file).read()}")
            props = config['DEFAULT']

            # Populate variables from the properties file
            return {var: props.get(var) for var in required_vars}
        except configparser.Error as e:
            print(f"Error reading local.properties file: {e}")
            sys.exit(1)

def cleanup_db(config):
    """
    Connects to the database and performs the cleanup operation.
    """
    db_name = "mosip_audit"
    try:
        conn = psycopg2.connect(
            host=config["db-host"],
            port=config["db-port"],
            user=config["db-su-user"],
            password=config["postgres-password"],
            dbname=db_name
        )
        cur = conn.cursor()

        print(f"Starting database cleanup for logs older than {config['log-age-days']} days...")
        print(f"Connecting to DB: {config['db-su-user']}@{config['db-host']}:{config['db-port']}/{db_name}")

        # The core DELETE command
        # Use a parameterized query for safety
        delete_query = "DELETE FROM audit.app_audit_log WHERE log_dtimes < NOW() - INTERVAL %s"
        interval_str = f"{config['log-age-days']} days"

        cur.execute(delete_query, (interval_str,))

        # Get the number of rows deleted
        rows_deleted = cur.rowcount
        conn.commit()

        print(f"Successfully deleted {rows_deleted} rows.")

    except psycopg2.OperationalError as e:
        print(f"Database connection or query failed: {e}")
        sys.exit(1)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    db_config = get_db_credentials()
    cleanup_db(db_config)
    print("Database cleanup script finished successfully.")