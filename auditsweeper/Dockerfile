FROM python:3.9

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

# Create the user and set the working directory
RUN groupadd -r ${container_user_group} && useradd -u ${container_user_uid} -r -g ${container_user_group} -s /bin/bash -m -d /home/${container_user} ${container_user}

WORKDIR /home/${container_user}

# Add all files to the correct working directory
ADD . .

# Install kubectl and Python dependencies
RUN apt-get -y update && apt-get install -y curl \
&& curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.sio/release/stable.txt)/bin/linux/amd64/kubectl" \
&& chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl \
&& pip install --no-cache-dir -r requirements.txt \
&& chown -R ${container_user}:${container_user_group} /home/${container_user}

USER ${container_user}

ENV db-server=
ENV db-port=
ENV db-su-user=
ENV postgres-password=

CMD ["python", "auditsweeper.py"]