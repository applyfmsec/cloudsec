# TODO -- move to a non-personal image org.
# Image: jstubbs/cloudsec  (i.e., applyfmsec/cloudsec)

FROM python:3.9-slim-buster

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Install pip requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

# Creates a non-root user with an explicit UID and adds permission to access the /app folder
# For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
RUN adduser -u 4872 --disabled-password --gecos "" cloudsec
USER cloudsec

COPY cloudsec /home/cloudsec/cloudsec

WORKDIR /home/cloudsec/cloudsec