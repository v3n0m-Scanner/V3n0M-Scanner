FROM python:3.6-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        gcc \
        build-essential \
        python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/vittring/V3n0M-Scanner.git
WORKDIR /V3n0M-Scanner
COPY requirements.txt /src
WORKDIR /src
RUN pip3 install -r requirements.txt --no-cache-dir
RUN python3 setup.py install --user
ENTRYPOINT ["python3", "v3n0m.py"]