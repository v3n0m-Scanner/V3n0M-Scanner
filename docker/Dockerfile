# Dockerfile to spin up fully functional Venom
#
# This file is part of Venom
# See LICENSE for license details.

ARG BASE_IMAGE=python
ARG BASE_TAG=3.10.4-slim-bullseye
ARG OP_IMAGE=${BASE_IMAGE}:${BASE_TAG}
FROM $OP_IMAGE

# Contact info for critical/security issues only
# Use subject title "Venom *critical issue*: short description"
LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

# Install base dependencies
RUN apt-get update && apt-get install -y \
    git gcc curl build-essential python3-setuptools python3-dev \
    python3-bs4 ca-certificates libffi-dev \
    && apt-get clean

# Environment variables for Poetry
ENV USER=venom
ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_PATH=/opt/poetry \
    VENV_PATH=/opt/venv \
    POETRY_VERSION=1.1.12
ENV PATH="$POETRY_PATH/bin:$VENV_PATH/bin:$PATH"

# Add non-root user for running
RUN useradd --create-home --system --shell /bin/false $USER

# Latest Poetry
# https://github.com/python-poetry/poetry
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python - --preview \
    && mv /root/.poetry $POETRY_PATH \
    && python -m venv $VENV_PATH \
    && rm -rf /var/lib/apt/lists/*

ENV WORKDIR=/opt/scan

# Clone repo & install dependencies
RUN git clone --depth=1 https://github.com/V3n0M-Scanner/V3n0M-Scanner.git $WORKDIR
RUN chown $USER:$USER --recursive $WORKDIR
WORKDIR $WORKDIR

# Magic
RUN poetry install

# Use pip for the rest
RUN pip install aiohttp tqdm SocksiPy-branch httplib2 requests bs4

# Switching to non-root user/CHROOT
USER $USER
WORKDIR $WORKDIR/src

# Run Venom
ENTRYPOINT ["python3", "v3n0m.py"]
