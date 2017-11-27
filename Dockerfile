FROM python:3.6-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        gcc \
        build-essential \
        python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/v3n0m-Scanner/V3n0M-Scanner.git

WORKDIR /V3n0M-Scanner

RUN python3 setup.py install --user

WORKDIR src

ENTRYPOINT ["python", "v3n0m.py"]