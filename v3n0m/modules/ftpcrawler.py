#!/usr/bin/python

import argparse, subprocess, signal, Queue, time, random
from threading import Thread, Lock
from sys import argv, stdout
from os import getpid, kill, system, path
from ftplib import FTP
from re import findall

class myThread (Thread):
    def __init__(self, threadID, name, q):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q
    def run(self):
        ftpscan(self.name, self.q)

class Timer():
    def __enter__(self): 
        self.start = time.time()
    def __exit__(self, *args):
	    taken = time.time() - self.start
	    seconds = int(time.strftime('%S', time.gmtime(taken)))
	    minutes = int(time.strftime('%M', time.gmtime(taken)))
	    hours = int(time.strftime('%H', time.gmtime(taken)))
	    if minutes > 0:
		    if hours > 0:
			    print " [*] Time elapsed " + str(hours) + " hours, " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(round(len(IPList) / taken,2)) + " scans per second."
		    else:
			    print " [*] Time elapsed " + str(minutes) + " minutes and " + str(seconds) + " seconds at " + str(round(len(IPList) / taken,2)) + " scans per second."
	    else:
		    print " [*] Time elapsed " + str(seconds) + " seconds at " + str(round(len(IPList) / taken,2)) + " scans per second."

class Printer():
    def __init__(self,data):
        stdout.write("\r\x1b[K"+data.__str__())
        stdout.flush()

def writeLog(iLogIP, wlcmMsg, anon):
 
    if anon == 1:
        anon = "Anonymous login allowed!\n\n---------------------------------------"
        FTPLogFile = open('FTPAnonLogFile.txt', 'a')
        FTPLogFile.write('\nFTP found @' + iLogIP + '\n' + 'Welcome message from FTP:\n' + wlcmMsg + '\n' + anon)
        FTPLogFile.close()    
    if anon == 0:
        anon = "Anonymous login NOT allowed!\n\n---------------------------------------"
        FTPLogFile = open('FTPPrivateLogFile.txt', 'a')
        FTPLogFile.write('\nFTP found @' + iLogIP + '\n' + 'Welcome message from FTP:\n' + wlcmMsg + '\n' + anon)
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
	for num in xrange(amt):
		while IPPart != 4:
			IPS = random.randint(0, 255)
			if IPPart == 0:
				if IPS == 0:
					while IPS == 0:
						IPS = random.randint(1, 255)
				IPString = str(IPS)
			else:
				IPString +=  "." + str(IPS)  
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
				connection = FTP(data, timeout=2)
				wlcmMsg = connection.getwelcome()
				wlcmMsg2 = wlcmMsg.split('\n', 1)[0]
				loginftp = True
				FTPs.append(data)
				FCheck = False
				iphead = str(data) + "%" + str(wlcmMsg2)
				headers.append(str(iphead))
				print "\r\x1b[K [*] Found FTP @ " + O + str(data) + B + "  >  " + str(wlcmMsg2)
				if loginftp:
					try:
						connection.login()
						tmpVar3 = ""
						tmpVar3 = connection.retrlines('LIST')
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

def killpid(signum = 0, frame = 0):
	print "\r\x1b[K"
	kill(getpid(), 9)
	

def log(result, ip, banner):
    output = open('banner-output.txt', 'a')
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
		try:
			if any("/driver/" in s for s in b):  
				c = b[0].split('/driver/')
      			if not any("/driver/" in s for s in b):    
                		c = b[0].split('/ftp/')
        	except:
        		pass
        	payload = str(c[1]).split('_')[0]
        	if payload == 'ms09':
            		payload = 'microsoft'
        	if payload.lower() in header.lower():
            		result.append(banner)
	return result


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
				print R + 'Banner: ' + O + banner
				print B + 'IP: ' + O + ip
				print O + "\n[+]" + B + " Bingo! Found (possible) matching exploits for " + O + str(ip) + B
				for r in results:
					print R + r
				print '-----------------  NEXT  ------------------------\n'
			else:
				pass
		except:
			pass

parser = argparse.ArgumentParser(prog='ftpscanner', usage='ftpscanner [options]')
parser.add_argument('-t', "--threads", type=int, help='number of threads (default: 1000)')
parser.add_argument('-i', "--ips", type=int, help='number of random ips to scan')
args = parser.parse_args()

print '''  __ _                                             
 / _| |_ _ __  ___  ___ __ _ _ __  _ __   ___ _ __ 
| |_| __| '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
|  _| |_| |_) \__ \ (_| (_| | | | | | | |  __/ |   
|_|  \__| .__/|___/\___\__,_|_| |_|_| |_|\___|_|   
        |_|                                        
                                                        
                                          By Sam & d4rkcat
'''

if len(argv) == 1:
	parser.print_help()
	exit()

signal.signal(signal.SIGINT, killpid)
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
	print "[*] Generating " + str(args.ips) + " IPs.."
	makeips(args.ips)
else:
	parser.print_help()
	exit()

print "[*] Starting scan"
print
workQueue = Queue.Queue(len(IPList))

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

	exitFlag = 1

	for t in threads:
		t.join()

print "\r\x1b[K\n [*] All threads complete, " + str(len(FTPs)) + " IPs found. Starting Vuln Scan.."

if FTPs:
	vulnscan(headers)

