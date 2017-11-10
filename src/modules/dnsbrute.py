#!/usr/bin/python3
# This file is part of v3n0m
# See LICENSE for license details.

import argparse
import gzip
import json
import subprocess
import time as time2
from os import getpid, kill
from queue import Queue
from signal import SIGINT, signal
from socket import *
from socket import gethostbyaddr
from sys import argv, stdout
from threading import Thread, Lock

import dns.resolver


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
        process_data(self.name, self.q)


class Printer:
    def __init__(self, data):
        stdout.write("\r\x1b[K" + data.__str__())
        stdout.flush()


class Timer:
    def __enter__(self):
        self.start = time2.time()

    def __exit__(self, *args):
        seconds = int(time2.strftime('%S', time2.gmtime(taken)))
        minutes = int(time2.strftime('%M', time2.gmtime(taken)))
        hours = int(time2.strftime('%H', time2.gmtime(taken)))
        if minutes > 0:
            if hours > 0:
                print(" [*] Time elapsed " + str(hours) + " hours, " + str(minutes) + " minutes and " + str(
                        seconds) + " seconds at " + str(round(len(subdomains) / taken, 2)) + " lookups per second.")
            else:
                print(" [*] Time elapsed " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(
                        round(len(subdomains) / taken, 2)) + " lookups per second.")
        else:
            print(" [*] Time elapsed " + str(seconds) + " seconds at " + str(
                    round(len(subdomains) / taken, 2)) + " lookups per second.")


def killpid():
    writeout("bad")
    kill(getpid(), 9)


def writeout(state):
    logfile = open("logs/" + domain + ".log", 'w')
    for item in found:
        logfile.write("%s\n" % item)
    if state == "good":
        print()
        print(" [*] All threads complete, " + str(len(found)) + " subdomains found.")
    else:
        print()
        print(
                " [*] Scan aborted, " + str(progdone) + " lookups processed and " + str(len(found)) + " subdomains found.")
    print(" [*] Results saved to logs/" + domain + ".log")


def process_data(threadName, q):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            data = q.get()
            queueLock.release()
            host = data.strip() + '.' + domain.strip()
            try:
                answers = resolver.query(host)
                try:
                    output = gethostbyaddr(host)
                    if len(host) < 16:
                        stdout.write("\r\x1b[K")
                        stdout.flush()
                        print("\r" + str(host) + "\t\t" + str(output[0]) + " " + str(output[2]))
                        found.append(str(host) + "\t\t" + str(output[0]) + " " + str(output[2]))
                    else:
                        stdout.write("\r\x1b[K")
                        stdout.flush()
                        print("\r" + str(host) + "\t" + str(output[0]) + " " + str(output[2]))
                        found.append(str(host) + "\t" + str(output[0]) + " " + str(output[2]))
                except:
                    stdout.write("\r\x1b[K")
                    stdout.flush()
                    print("\r" + str(host))
                    found.append(str(host))
            except:
                pass
        else:
            queueLock.release()


parser = argparse.ArgumentParser(prog='dnsbrute', usage='dnsbrute [options]')
parser.add_argument('-u', "--url", type=str, help='url eg. target.com')
parser.add_argument("-w", "--wordlist", type=str, help="wordlist")
parser.add_argument('-t', "--threads", type=int, help='number of threads')
parser.add_argument('-att', "--att", type=str, help='att')
args = parser.parse_args()


if len(argv) == 1:
    parser.print_help()
    exit()

maxthreads = 500

if args.threads:
    maxthreads = args.threads


dnsservers = ["8.8.8.8", "8.8.4.4", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6", "4.2.35.8",
              "4.2.49.4", "4.2.49.3", "4.2.49.2", "209.244.0.3", "209.244.0.4", "208.67.222.222", "208.67.220.220",
              "192.121.86.114", "192.121.121.14", "216.111.65.217", "192.76.85.133", "151.202.0.85"]
signal(SIGINT, killpid)
domain = args.url
maked = "mkdir -p logs"
process = subprocess.Popen(maked.split(), stdout=subprocess.PIPE)
poutput = process.communicate()[0]
subdomains = [line.strip() for line in open(args.wordlist, 'r')]
if args.att:
    with gzip.GzipFile(open("lists/DNSCached.txt.gz"), 'r') as CacheClose:        # 4. gzip
        json_bytes = CacheClose.read()                          # 3. bytes (i.e. UTF-8)
        json_str = json_bytes.decode('utf-8')            # 2. string
        data = json.loads(json_str)                      # 1. dat
        dnsservers = data

resolver = dns.resolver.Resolver()
resolver.nameservers = dnsservers
queueLock = Lock()
workQueue = Queue(len(subdomains))
found = []
threads = []
exitFlag = 0
threadID = 1


print(" [*] Starting " + str(maxthreads) + " threads to process " + str(len(subdomains)) + " subdomains.")
print()

queueLock.acquire()
for work in subdomains:
    workQueue.put(work)
queueLock.release()

while threadID <= maxthreads:
    tname = str("Thread-") + str(threadID)
    thread = myThread(threadID, tname, workQueue)
    thread.start()
    threads.append(thread)
    threadID += 1

startcnt = time2.time()
progstart = time2.time()

with Timer():
    while not workQueue.empty():
        countprog = 0.3
        progress = time2.time() - progstart
        if progress >= countprog:
            progdone = len(subdomains) - workQueue.qsize()
            token = time2.time() - startcnt
            rate = round(progdone / token, 2)
            percent = round(float(100.00) / len(subdomains) * progdone, 2)
            eta = round(token / percent * 100 - token, 2)
            printoutput = " [*] " + str(percent) + "% complete, " + str(progdone) + "/" + str(
                    len(subdomains)) + " lookups at " + str(rate) + " lookups/second. ETA: " + str(
                    time2.strftime('%H:%M:%S', time2.gmtime(eta)))
            Printer(printoutput)
            progstart = time2.time()
        else:
            pass

    taken = time2.time() - startcnt
    stdout.write("\r\x1b[K")
    stdout.flush()

    for t in threads:
        t.join()

    writeout("good. All possible DNS Servers resolved.")
