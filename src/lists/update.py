#!/usr/bin/python3
# -*- coding: latin-1 -*-
# This file is part of v3n0m
# See LICENSE for license details.

import os
import sys
import urllib.request
import zipfile


def progressBar(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (
            percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
    if readsofar >= totalsize:  # near the end
        sys.stderr.write("\n")


def download(url, file, progressBar=None):
    print('Downloading %s' % url)
    urllib.request.urlretrieve(url, file, progressBar)


def unzip(file):
    with zipfile.ZipFile(file+'.zip', 'w') as myzip:
        myzip.write(file)
    os.remove(file+'.zip')

downloads = [
    ['https://www.cloudflare.com/ips-v4', 'lists/ips-v4', None],
    ['https://www.cloudflare.com/ips-v6', 'lists/ips-v6', None],
    ['http://crimeflare.net:82/domains/ipout.zip',
        'lists/ipout.zip',
     progressBar]
]

for d in downloads:
    download(d[0], d[1], d[2])

unzip('lists/ipout')

print('Everything up to date!')
