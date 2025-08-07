# Certificate Renewal Script for MOSIP

This script automates the process of checking and renewing certificates for MOSIP's  partners.

## Features

* The Script Reads partner IDs from either:

    * `PARTNER_IDS_ENV` environment variable when running in a k8s cluster.
    * `partner.properties` file while running  locally.

* Checks certificate expiry and renews if expired or within the `pre-expiry-days` window.
* Uploads renewed certificates to PMS and propagates to dependent systems:

    * **eSignet** for `mpartner-default-esignet`
    * **IDA** for `mpartner-default-auth`
    * **KeyManager** for `mpartner-default-resident` and `mpartner-default-digitalcard`
    * * **PMS** for all other kinds of partners. (including external 3rd party partners)
* Logs actions and results for each partner.

## Configuration

The script reads configuration values from either environment variables or `bootstrap.properties` file.

### Environment Variables (preferred)

| Variable Name                    | Description                                |
| -------------------------------- | ------------------------------------------ |
| `db-host`                        | PostgreSQL host                            |
| `db-port`                        | PostgreSQL port                            |
| `db-su-user`                     | PostgreSQL superuser                       |
| `postgres-password`              | PostgreSQL password                        |
| `mosip-api-internal-host`        | Internal MOSIP API base host               |
| `mosip_deployment_client_secret` | MOSIP PMS client secret for authentication |
| `pre-expiry-days`                | Days before expiry to trigger renewal      |
| `PARTNER_IDS_ENV`                | Comma-separated partner IDs to process     |

### bootstrap.properties (fallback)

Provide the same keys as above in `bootstrap.properties` if environment variables are not set.

Example:

```
db-host=localhost
db-port=5432
db-su-user=postgres
postgres-password=postgres
mosip-api-internal-host=api-internal.mosip.net
mosip_deployment_client_secret=secret-key
pre-expiry-days=30
```

### partner.properties

List of sample partner IDs to process when `PARTNER_IDS_ENV` is not set:

```
PARTNER_ID=mpartner-default-auth,mpartner-default-esignet,mpartner-default-resident
```

## Running the Script

### Python (local)

```bash
python checkupdate.py
```



## Outputs

* Logs certificate renewal process to stdout.
* Writes expired partner IDs to `expired.txt`.
* Automatically uploads renewed certificates to appropriate systems.


## Notes

* Ensure PostgreSQL credentials and MOSIP API host are reachable.
* Certificates are checked for expiry using OpenSSL and renewal occurs if expiring within the configured pre-expiry window.
* The script prints detailed progress and failures for each step.

## WIP 
 * Currently the script can not handle IDA- CRED certificates, team is working towards fixing the same.
