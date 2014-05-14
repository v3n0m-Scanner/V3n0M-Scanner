#!/usr/bin/python

import dns.resolver, signal, Queue, subprocess, time, argparse
from threading import Thread, Lock
from sys import argv, stdout
from os import getpid, kill
from socket import gethostbyaddr

class myThread (Thread):
    def __init__(self, threadID, name, q):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q
    def run(self):
        process_data(self.name, self.q)
        
class Printer():
    def __init__(self,data):
        stdout.write("\r\x1b[K"+data.__str__())
        stdout.flush()
        
class Timer():
	def __enter__(self): self.start = time.time()
	def __exit__(self, *args):
		seconds = int(time.strftime('%S', time.gmtime(taken)))
		minutes = int(time.strftime('%M', time.gmtime(taken)))
		hours = int(time.strftime('%H', time.gmtime(taken)))
		if minutes > 0:
			if hours > 0:
				print " [*] Time elapsed " + str(hours) + " hours, " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(round(len(subdomains) / taken,2)) + " lookups per second."
			else:
				print " [*] Time elapsed " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(round(len(subdomains) / taken,2)) + " lookups per second."
		else:
			print " [*] Time elapsed " + str(seconds) + " seconds at " + str(round(len(subdomains) / taken,2)) + " lookups per second."

def killpid(signum = 0, frame = 0):
	writeout("bad")
	kill(getpid(), 9)
    
def writeout(state):
	logfile = open("logs/" + domain + ".log", 'w') 	
	for item in found:
		logfile.write("%s\n" % item)
	if state == "good":
		print
		print " [*] All threads complete, " + str(len(found)) + " subdomains found."
	else:
		print
		print " [*] Scan aborted, " + str(progdone) + " lookups processed and " + str(len(found)) + " subdomains found."
	print " [*] Results saved to logs/" + domain + ".log"

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
						print "\r" + str(host) + "\t\t" +  str(output[0]) + " " + str(output[2])
						found.append(str(host) + "\t\t" +  str(output[0]) + " " + str(output[2]))
					else:
						stdout.write("\r\x1b[K")
						stdout.flush()
						print "\r" + str(host) + "\t" +  str(output[0]) + " " + str(output[2])
						found.append(str(host) + "\t" +  str(output[0]) + " " + str(output[2]))
				except:
					stdout.write("\r\x1b[K")
					stdout.flush()
					print "\r" + str(host)
					found.append(str(host))
            except:
				pass
        else:
            queueLock.release()

parser = argparse.ArgumentParser(prog='dnsbrute', usage='dnsbrute [options]')
parser.add_argument('-u', "--url", type=str, help='url eg. target.com')
parser.add_argument("-w", "--wordlist", type=str, help="wordlist")
parser.add_argument('-t', "--threads", type=int, help='number of threads')
args = parser.parse_args()
	
print '''     _           _                _       
  __| |_ __  ___| |__  _ __ _   _| |_ ___ 
 / _` | '_ \/ __| '_ \| '__| | | | __/ _ \ 
| (_| | | | \__ \ |_) | |  | |_| | ||  __/ 
 \__,_|_| |_|___/_.__/|_|   \__,_|\__\___|

			By d4rkcat
'''

if len(argv) == 1:
	parser.print_help()
	exit()

maxthreads = 40

if args.threads:
	maxthreads = args.threads

signal.signal(signal.SIGINT, killpid)
domain = args.url
maked = "mkdir -p logs"
process = subprocess.Popen(maked.split(), stdout=subprocess.PIPE)
poutput = process.communicate()[0]
subdomains = [line.strip() for line in open(args.wordlist, 'r')]
dnsservers = ["8.8.8.8", "8.8.4.4", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6", "4.2.35.8", "4.2.49.4", "4.2.49.3", "4.2.49.2", "209.244.0.3", "209.244.0.4", "208.67.222.222", "208.67.220.220", "192.121.86.114", "192.121.121.14", "216.111.65.217", "192.76.85.133", "151.202.0.85" ]
resolver = dns.resolver.Resolver()
resolver.nameservers = dnsservers
queueLock = Lock()
workQueue = Queue.Queue(len(subdomains))
found = []
threads = []
exitFlag = 0
threadID = 1

print " [*] Starting " + str(maxthreads) + " threads to process " + str(len(subdomains)) + " subdomains."
print

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

startcnt = time.time()
progstart = time.time()

with Timer():
	while not workQueue.empty():
		countprog = 0.3
		progress = time.time() - progstart
		if progress >= countprog:
			progdone = len(subdomains) - workQueue.qsize()
			token = time.time() - startcnt
			rate = round(progdone / token,2)
			percent = round(float(100.00) / len(subdomains) * progdone,2)
			eta = round(token / percent * 100 - token,2)
			printoutput = " [*] " + str(percent) + "% complete, " + str(progdone) + "/" + str(len(subdomains)) + " lookups at " + str(rate) + " lookups/second. ETA: " + str(time.strftime('%H:%M:%S', time.gmtime(eta)))
			Printer(printoutput)
			progstart = time.time()
		else:
			pass
	
	taken = time.time() - startcnt	
	stdout.write("\r\x1b[K")
	stdout.flush()
	exitFlag = 1

	for t in threads:
		t.join()

	writeout("good")
