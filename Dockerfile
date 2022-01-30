FROM python:3.8.12-slim-bullseye

LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

# Environment variables
ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_PATH=/opt/poetry \
    VENV_PATH=/opt/venv \
    POETRY_VERSION=1.1.12
ENV PATH="$POETRY_PATH/bin:$VENV_PATH/bin:$PATH"

RUN apt-get update && apt-get install -y \
    # deps for installing poetry
    git \
    gcc \
    curl \
    # deps for building python deps
    build-essential \
    python3-setuptools \
    ca-certificates \
    && curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python \
    && mv /root/.poetry $POETRY_PATH \
    && python -m venv $VENV_PATH \
    && rm -rf /var/lib/apt/lists/*

COPY poetry.lock pyproject.toml .

# Clone repo
RUN git clone https://github.com/vittring/V3n0M-Scanner.git \
    && python3.8 -m pip install aiohttp \
    asyncio \
    bs4 \
    DateTime \
    dnspython \
    httplib2 \
    requests \
    SocksiPy-branch \
    termcolor \
    tqdm

WORKDIR V3n0M-Scanner/src

ADD . /src

# CHROOT!
RUN adduser app -h /app -u 1000 -g 1000 -DH
USER 1000

# Init
ENTRYPOINT ["python3.8", "v3n0m.py"]
