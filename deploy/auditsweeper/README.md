# auditsweeper
Helm chart for installing auditsweeper

## Introduction 
It's a cronjob that  goes through the audit table and cleans up the audit logs after a customisable no of days.

## Install
* Review the `values.yaml` file and ensure that the database parameter values and log_age_days are set according to your environment
* RUN Install script
```
./install.sh
```

# TL;DR
```console
$ helm repo add mosip https://mosip.github.io
$ helm install my-release mosip/auditsweeper
```