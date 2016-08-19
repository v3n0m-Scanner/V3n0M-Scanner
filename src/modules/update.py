import urllib.request
import zipfile
import os
import sys


def progressbar(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (
            percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
    if readsofar >= totalsize:  # near the end
        sys.stderr.write("\n")


def download(url, file, progressbar=None):
    print('Downloading %s' % url)
    urllib.request.urlretrieve(url, file, progressbar)


def unzip(file):
    with zipfile.ZipFile(file+'.zip', 'w') as myzip:
        myzip.write(file)
    os.remove(file+'.zip')

downloads = [
    ['https://www.cloudflare.com/ips-v4', 'lists/ips-v4', None],
    ['https://www.cloudflare.com/ips-v6', 'lists/ips-v6', None],
    ['http://crimeflare.net:82/domains/ipout.zip',
        'lists/ipout.zip',
        progressbar]
]

for d in downloads:
    download(d[0], d[1], d[2])

unzip('lists/ipout')

print('Everything up to date!')
