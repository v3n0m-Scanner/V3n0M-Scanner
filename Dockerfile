# This project is LIVE

FROM python:3.8.12-slim-bullseye

LABEL maintainer="Architect" \
      email="scissortail@riseup.net"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        gcc \
        build-essential \
        python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN python3 -m pip install --upgrade pip

# Clone repo
RUN git clone https://github.com/vittring/V3n0M-Scanner.git
WORKDIR V3n0M-Scanner

# Install requirements
COPY requirements.txt src/
Workdir src/
RUN pip3 install -r requirements.txt --no-cache-dir

# Setup
WORKDIR ../
RUN python3 setup.py install --user

# Start
WORKDIR src/
ENTRYPOINT ["python3", "v3n0m.py"]
