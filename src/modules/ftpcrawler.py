#!/usr/bin/python
# This file is part of v3n0m
# See LICENSE for license details.


try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs
    from signal import SIGINT, signal
    from codecs import lookup, register
    from random import SystemRandom

except:
    print(" please make sure you have all of the following modules: asyncio, aiohttp, codecs, requests")
    print(" httplib2, signal, itertools")
    print("Error a module was not found,  'sudo pip3 install <package name>' to install")
    exit()

import ftplib
from ftplib import FTP
from os import getpid, kill, path
from sys import argv, stdout
from threading import Thread, Lock


msf_Vulns = [line.strip() for line in open("vuln-ftp-checklist.txt", 'r')]
honeypot_ranges = str(line.rsplit('\n') for line in open("honeypot_ranges.txt", 'r'))


def killpid(signum=0, frame=0):
    print("\r\x1b[K")
    os.kill(os.getpid(), 9)

signal(SIGINT, killpid)

class myThread(Thread):
    def __init__(self, threadID, name, q):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q

    def run(self):
        ftpscan(self.name, self.q)


class Timer:
    def __enter__(self):
        self.start = time.time()

    def __exit__(self, *args):
        taken = time.time() - self.start
        seconds = int(time.strftime('%S', time.gmtime(taken)))
        minutes = int(time.strftime('%M', time.gmtime(taken)))
        hours = int(time.strftime('%H', time.gmtime(taken)))
        if minutes > 0:
            if hours > 0:
                print(" [*] Time elapsed " + str(hours) + " hours, " + str(minutes) + " minutes and " + str(
                    seconds) + " seconds at " + str(round(len(IPList) / taken, 2)) + " scans per second.")
            else:
                print(" [*] Time elapsed " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(
                    round(len(IPList) / taken, 2)) + " scans per second.")
        else:
            print(" [*] Time elapsed " + str(seconds) + " seconds at " + str(
                round(len(IPList) / taken, 2)) + " scans per second.")


class Printer:
    def __init__(self, data):
        stdout.write("\r\x1b[K" + data.__str__())
        stdout.flush()


def writeLog(iLogIP, wlcmMsg, anon):
    if anon == 1:
        anon = "Anonymous login allowed!\n\n---------------------------------------"
        FTPLogFile = open('FTPAnonLogFile.txt', 'a')
        FTPLogFile.write('\nFTP found dbg 2 @' + iLogIP + '\n' + 'Welcome message from FTP:\n' + wlcmMsg + '\n' + anon)
        FTPLogFile.close()
    if anon == 0:
        anon = "Anonymous login NOT allowed!\n\n---------------------------------------"
        FTPLogFile = open('FTPPrivateLogFile.txt', 'a')
        FTPLogFile.write('\nFTP found dbg 3 @' + iLogIP + '\n' + 'Welcome message from FTP:\n' + wlcmMsg + '\n' + anon)
        FTPLogFile.close()


def writeheaders(header):
    headerlog = open('headers.txt', 'a')
    headerlog.write(header)
    headerlog.close()


def makeips(amt):
    global headersl
    headersl = []
    IPPart = 0
    IPString = ""
    for num in range(amt):
        while IPPart != 4:
            IPS = random.randint(0, 255)
            if IPPart == 0:
                if IPS == 0:
                    while IPS == 0:
                        IPS = random.randint(1, 255)
                IPString = str(IPS)
            else:
                IPString += "." + str(IPS)
            IPPart += 1
        IPPart = 0
        IPList.append(IPString)


def ftpscan(threadName, q):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            data = q.get()
            queueLock.release()
            loginftp = False
            progdone = len(IPList) - workQueue.qsize()
            livelog = " [>] Trying " + str(progdone) + "/" + str(len(IPList)) + " " + data
            Printer(livelog)
            try:
                connection = FTP(data, timeout=3)
                wlcmMsg = connection.getwelcome()
                wlcmMsg2 = str(wlcmMsg.split('\n', 1)[0])
                loginftp = True
                FTPs.append(data)
                FCheck = False
                iphead = str(data) + "%" + str(wlcmMsg2)
                headers.append(str(iphead))
                tagget = str(wlcmMsg2) in msf_Vulns
                if tagget >=0:
                    vulns_got = str("True")
                else:
                    vulns_got = str("False")
                print("\r\x1b[K [*] Found FTP @ " + O + str(data) + B + "  >  " + str(wlcmMsg2) +  " & Possible Vuln Detected=" + str(vulns_got))
                IPNumX = connection.retrlines(vulns_got)
                if loginftp:
                    try:
                        connection.login()
                        FCheck = True
                        if FCheck:
                            anon = 1
                            writeLog(IPList[IPNumX], wlcmMsg, anon)
                    except ftplib.error_perm:
                        anon = 0
                        writeLog(IPList[IPNumX], wlcmMsg, anon)
                        connection.quit()
            except:
                pass
        else:
            queueLock.release()


def killpid(signum=0, frame=0):
    print("\r\x1b[K")
    kill(getpid(), 9)


def log(result, ip, banner):
    output = open('logo-output.txt', 'a')
    output.write('IP: %s\nBanner: %s\nExploits: \n' % (ip, banner))
    for r in result:
        output.write('\t' + r + '\n')
    output.write('-----------------  NEXT  ------------------------\n')
    output.close()


def scan_string(header):
    result = []
    pwd = path.join(path.dirname(str(path.realpath(__file__))), 'metasploit-vulns.txt')
    vuln_banners = open(pwd, 'r')
    for banner in vuln_banners:
        b = banner.split('\t')
        payload = 'microsoft'
        try:
            if any("/driver/" in s for s in b):
                c = b[0].split('/driver/')
                payload = str(c[1]).split('_')[0]
            if not any("/driver/" in s for s in b):
                c = b[0].split('/ftp/')
                payload = str(c[1]).split('_')[0]
        except:
            pass
            if payload == 'ms09':
                if payload.lower() in header.lower():
                    result.append(banner)
    return result


# noinspection PyBroadException
def vulnscan(queries):
    global banner
    for query in queries:
        try:
            results = []
            queryls = []
            queryls = query.split('%')
            ip = queryls[0]
            banner = queryls[1]
            results = scan_string(banner)
            if results:
                log(results, ip, banner)
                print(R + 'Banner: ' + O + banner)
                print(B + 'IP: ' + O + ip)
                print(O + "\n[+]" + B + " Bingo! Found (possible) matching exploits for " + O + str(ip) + B)
                for r in results:
                    print(R + r)
                print('-----------------  NEXT  ------------------------\n')
            else:
                pass
        except:
            pass


parser = argparse.ArgumentParser(prog='ftpscanner', usage='ftpscanner [options]')
parser.add_argument('-t', "--threads", type=int, help='number of threads (default: 1000)')
parser.add_argument('-i', "--ips", type=int, help='number of random ips to scan')
args = parser.parse_args()

print('''  __ _
 / _| |_ _ __  ___  ___ __ _ _ __  _ __   ___ _ __
| |_| __| '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
|  _| |_| |_) \__ \ (_| (_| | | | | | | |  __/ |
|_|  \__| .__/|___/\___\__,_|_| |_|_| |_|\___|_|
        |_| Original By Sam & d4rkcat
        V3n0M Metasploitable Scanner Version 1.0
              Python3 Recode&Upgrade: By NovaCygni
''')

if len(argv) == 1:
    parser.print_help()
    exit()


queueLock = Lock()
IPList = []
threads = []
FTPs = []
exitFlag = 0
chekhed = 0
threadID = 1
maxthreads = 800
W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"
headers = []

if args.threads:
    maxthreads = args.threads

if args.ips:
    print("[*] Generating " + str(args.ips) + " IPs..")
    makeips(args.ips)
else:
    parser.print_help()
    exit()

print("[*] Starting scan")
print()
workQueue = queue.Queue(len(IPList))

queueLock.acquire()
for ip in IPList:
    workQueue.put(ip)
queueLock.release()

while threadID <= maxthreads:
    tname = str("Thread-") + str(threadID)
    thread = myThread(threadID, tname, workQueue)
    thread.start()
    threads.append(thread)
    threadID += 1

with Timer():
    while not workQueue.empty():
        pass

    for t in threads:
        t.join()

print("\r\x1b[K\n [*] All threads complete, " + str(len(FTPs)) + " IPs found.. Starting Vuln Scan..")

if FTPs:
    vulnscan(headers)
