#!/bin/bash
# This file is part of v3n0m
# See LICENSE for license details.
# ParrotSec Install Script
set -e

# Alternatively, anything >=3.6 will work but async might argue.
PKG_NAME=V3n0m-Scanner/V3n0M-Scanner
_PKG_NAME=v3n0m
PY_VER=3.9.7
PY_ARCHIVE=Python-${PY_VER}.tgz
ENV=~/.local/src
PY_URL=https://www.python.org/ftp/python/${PY_VER}/${PY_ARCHIVE}.tgz
PKG_INST_DIR=${ENV}/venom

# Get Python & compile
wget -O $PY_ARCHIVE $PY_URL
tar -xvf $PY_ARCHIVE
cd Python-${PY_VER}
./configure --enable-optimizations --with-ensurepip=install
make -j $(nproc)
make altinstall
cd

# Now requires OpenSSL >=1.1.1
# https://peps.python.org/pep-0644/
# $ openssl version
# OpenSSL 1.1.1l  24 Aug 2021
apt-get install openssl

# Install pip
curl -sSL https://bootstrap.pypa.io/get-pip.py | python3

# Clone venom
git clone https://github.com/${PKG_NAME}.git ${ENV}/${_PKG_NAME}

# Install Poetry
# https://github.com/python-poetry/poetry
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python - --preview

# Install v3n0m
cd ${ENV}/${_PKG_NAME}
python -m venv .
source bin/activate

# $ python v3n0m.py
