# Dockerfile to spin up fully functional Venom
#
# This file is part of Venom
# See LICENSE for license details.
FROM python:3.8.12-slim-bullseye

# Contact info for critical/security issues only
# Use subject title "Venom *critical issue*: short description"
LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

# Harden Dockerfile
ENV USER venom
ENV WORKDIR /usr/src/$USER


# Environment variables for Poetry
ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_PATH=/opt/poetry \
    VENV_PATH=/opt/venv \
    POETRY_VERSION=1.1.12
ENV PATH="$POETRY_PATH/bin:$VENV_PATH/bin:$PATH"

# Add non-root user for running
RUN useradd --create-home --system --shell /bin/false $USER
RUN mkdir --parents $WORKDIR
RUN chown $USER:$USER --recursive $WORKDIR

# Install base dependencies
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y git gcc curl build-essential python3-setuptools python3-dev \
    python3-bs4 ca-certificates libffi-dev

# Download, compile and install Poetry
#  https://github.com/python-poetry/poetry
RUN curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python \
    && mv /root/.poetry $POETRY_PATH \
    && python -m venv $VENV_PATH \
    && rm -rf /var/lib/apt/lists/*

# Clone repo & install dependencies
RUN git clone --recursive https://github.com/vittring/V3n0M-Scanner.git $WORKDIR/scan
WORKDIR $WORKDIR/scan

# Magic
RUN poetry install

# Use pip for the rest
RUN pip install aiohttp tqdm SocksiPy-branch httplib2 requests bs4

# Switching to non-root user/CHROOT
USER $USER
WORKDIR $WORKDIR/scan/src

# Run Venom
ENTRYPOINT ["python3", "v3n0m.py"]
