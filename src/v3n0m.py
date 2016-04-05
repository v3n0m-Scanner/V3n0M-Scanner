#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.4.0.2c
#   --- Redo entire search engine function to run 100 checks per engine at once
#   - Fixed All Side Modules > adminfinder, dnsbrute, ftpcrawler
#   --- Re-Add LFI/RFI options
#   --- Add parsing options
#   --- add piping for SQLMap
#   -- add scans for known Metasploitable Vulns (* dork based and Nmap style *)
#   - Add Proxy and Tor support back
#   -- Recode admin page finder, go for asyncio based crawler.
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

except:
    print(" please make sure you have all of the following modules: asyncio, aiohttp, codecs, requests")
    print(" httplib2, signal, itertools")
    print("Error a module was not found,  'sudo pip3 install <package name>' to install")
    exit()


# Banner
def logo():
    print(R + "\n|----------------------------------------------------------------|")
    print("|     V3n0mScanner.py                                            |")
    print("|     Release Date 03/04/2016  - Release Version V.4.0.3         |")
    print("|         Socks4&5 Proxy Enabled Support                         |")
    print("|             " + B + "        NovaCygni  Architect    " + R + "                   |")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_|  Release       |")
    print("|   " + G + "   Release Notes: All features now working with Python3     " + R + " |")
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
            except(KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def classicinj(url):
    aug_url = url + "'"
    try:
        resp = urllib.request.urlopen(aug_url)
        Hits = str(resp.read())
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
        else:
            pass
    except(urllib.error.URLError, socket.gaierror, socket.error, socket.timeout):
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
    global maxc
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
    sites = input("\nChoose your target(domain)   : ")
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
    numthreads = input('\nEnter no. of threads : ')
    maxc = input('Enter no. of pages   : ')

    print("\nNumber of SQL errors :", "26")
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(loaded_Dorks))
    print("Pages           :", maxc)
    print("Timeout         :", timeout)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(search(maxc))
    vulnscan()

def det_Neph():
    print("")

def det_Honeyd():
    print("")

def det_Kippo():
    print("")


def vulnscan():
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


async def search(maxc):
    urls = []
    urls_len_last = 0
    for site in sitearray:
        dark = 0
        for dork in loaded_Dorks:
            dark += 1
            page = 0
            while page < int(maxc):
                query = dork + "+site:" + site
                futures=[]
                loop = asyncio.get_event_loop()
                for i in range(3):
                    results_web = 'http://www.bing.com/search?q=' +query+ '&go=Submit&first=' + str((page+i)*50+1) + '&count=50'
                    futures.append(loop.run_in_executor(None, requests.get, results_web))
                page += 3
                stringreg = re.compile('(?<=href=")(.*?)(?=")')
                names=[]
                for future in futures:
                    names.extend(stringreg.findall((await future).text))

                for name in names:
                    if name not in urls:
                        if re.search(r'\(', name) or re.search(r'<', name) or re.search(r'\A/',
                         name) or re.search(r'\A(http://)\d', name):
                            continue
                        elif name.find(search_Ignore)>=0:
                            continue
                        elif name.find(site)>=0:
                            urls.append(name)

                darklen = len(loaded_Dorks)
                percent = int((1.0 * dark / int(darklen)) * 100)
                urls_len = len(urls)
                sys.stdout.write(
                    "\r\x1b[KSite: %s | Collected urls: %s | D0rks: %s/%s | Percent Done: %s | Current page no.: <%s> | Dork: %s" % (
                    site, repr(urls_len), dark, darklen, repr(percent), repr(page), dork))
                sys.stdout.flush()
                if urls_len == urls_len_last:
                    page = int(maxc)
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

        except:
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
    print("[6] Remote Honeypot Detection::::NOT IMPLEMENTED")
    print("[7] TCP Scanner::::NOT IMPLEMENTED")
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

    elif chce == '3':
        randips = input("How many IP addresses do you want to scan: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        ftpcrawl = subprocess.Popen(pwd + "/modules/ftpcrawler.py -i " + str(randips), shell=True)
        ftpcrawl.communicate()

    elif chce == '4':
        dnstarg = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(pwd + "/modules/dnsbrute.py -w modules/subdomainsmid.txt -u " + str(dnstarg),
                                    shell=True)
        dnsbrute.communicate()

    elif chce == '5':
        print(W + "")
        enable_proxy()

    elif chce == '6':
        det_Kippo()

    elif chce == '7':
        tcp_scan(ips, ports, randomize=True)


    elif chce == '0':
        print(R + "\n Exiting ...")
        print(W)
        sys.exit(0)


signal(SIGINT, killpid)
d0rk = [line.strip() for line in open("statics/d0rks", 'r')]
header = [line.strip() for line in open("statics/header", 'r')]
xsses = [line.strip() for line in open("statics/xsses", 'r')]
lfis = [line.strip() for line in open("statics/lfi", 'r')]
search_Ignore = str(line.rsplit('\n') for line in open("statics/search_ignore", 'r'))
random.shuffle(d0rk)
random.shuffle(header)
random.shuffle(lfis)
ProxyEnabled = False
parser = argparse.ArgumentParser(prog='v3n0m', usage='v3n0m [options]')
parser.add_argument('-p', "--proxy", type=str, help='Proxy must be in the form of type:host:port')
args = parser.parse_args()


def enable_proxy():
    print("Please select Proxy Type - Options = socks4, socks5 ")
    proxytype = input()
    print(" Please enter Proxy IP address - ie. 127.0.0.66")
    proxyip = input()
    print(" Please enter Proxy Port - ie. 1076")
    proxyport = input(int)
    if proxytype == "socks4":
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
        socket.socket = socks.socksocket
        print(" Socks 4 Proxy Support Enabled")
        time.sleep(3)
    elif proxytype == "socks5":
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
        socket.socket = socks.socksocket
        print(" Socks 5 Proxy Support Enabled")
        time.sleep(3)
    else:
        print("Error Unknown proxy type: " + str(proxytype))
        socket.socket = socks.socksocket
        socket.create_connection = enable_proxy
        socket.setdefaulttimeout(8)
        exit()


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
socket.setdefaulttimeout(timeout)
menu = True

while True:
    fmenu()
