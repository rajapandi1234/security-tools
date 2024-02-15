FROM node:lts-alpine3.17
RUN apk --no-cache add curl jq openssl

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# Create user group
RUN addgroup -S ${container_user_group} && \
    adduser -u ${container_user_uid} -S -G ${container_user_group} -s /bin/bash -h /home/${container_user} ${container_user}
RUN chown -R ${container_user}:${container_user} /home/${container_user}
WORKDIR /home/${container_user}
USER ${container_user}

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV ENABLE_INSECURE=false
ENV MODULE=

ENV s3-host=
ENV s3-region=
ENV s3-user-key=
ENV s3-user-secret=
ENV s3-bucket-name=

COPY partner.properties .
COPY certalert.sh .
CMD ["sh", "certalert.sh"]