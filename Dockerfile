FROM python:3.8.12-slim-bullseye

LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

## Environment variables for Poetry (Don't Edit)
ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_PATH=/opt/poetry \
    VENV_PATH=/opt/venv \
    POETRY_VERSION=1.1.12
ENV PATH="$POETRY_PATH/bin:$VENV_PATH/bin:$PATH"

## Add user & install build deps
RUN groupadd venom && \
    useradd --no-log-init -g venom venom && \
    mkdir /home/venom && \
    chown -R venom:venom /home/venom && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git \
    gcc \
    curl \
    build-essential \
    python3-setuptools \
    python3-dev \
    python3-bs4 \
    ca-certificates \
    libffi-dev

#Install poetry & cleanup
RUN apt-get clean && \
    rm -rf -- /var/lib/apt/lists/* /var/cache/* && \
    chown venom /opt && \
    # install Poetry
    curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python && \
    mv /root/.poetry $POETRY_PATH && \
    python -m venv $VENV_PATH && \
    rm -rf /var/lib/apt/lists/*

## Clone repo & install deps with Pip & Poetry
#  https://github.com/python-poetry/poetry
RUN git clone https://github.com/vittring/V3n0M-Scanner.git scan/
WORKDIR scan/src
RUN pip install aiohttp tqdm SocksiPy-branch httplib2 requests bs4
RUN poetry install

ENTRYPOINT ["python3", "v3n0m.py"]
