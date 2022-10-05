# Venom Dockerfile
#
# This file is part of Venom
# See LICENSE for license details.

ARG PYTHON_VERSION=3.10

FROM docker.io/python:${PYTHON_VERSION}-slim-bullseye as builder

# Contact info for critical/security issues only
# Use subject title "Venom *critical issue*: short description"
LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

# Install base dependencies
RUN \
 apt-get update -qq && apt-get install -yqq \
    git \
    gcc \
    curl \
    build-essential \
    python3-setuptools \
    python3-dev \
    python3-bs4 \
    ca-certificates \
    libffi-dev \
 && rm -rf /var/lib/apt/lists/*

# Latest Poetry https://install.python-poetry.org
# Set Poetry Version
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --user "poetry==1.2.1"

WORKDIR /opt

# Clone repo & install dependencies
RUN git clone --depth=1 https://github.com/V3n0M-Scanner/V3n0M-Scanner.git ./scan

RUN cd ./scan/

COPY . /opt

# Magic
RUN /root/.local/bin/poetry install

# Use pip for the rest
RUN pip install aiohttp tqdm SocksiPy-branch httplib2 requests bs4 dnspython

WORKDIR /opt/scan/src

# Run Venom
ENTRYPOINT ["python3", "v3n0m.py"]
