#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.4.0.4c
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



import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
    time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs, dns
from signal import SIGINT, signal
from bs4 import BeautifulSoup
from codecs import lookup, register
from random import SystemRandom
from socket import *
from datetime import *


socks.socket.setdefaulttimeout(8)
dnsmapdir = 'dnsmap'  # Edit to change dnsmap directory


# Used to escape >1 loops at once
class End(Exception):
    pass


class Bruteforce(object):
    def __init__(self, domain):
        if domain.startswith('www.'):
            domain = re.sub('www.', '', domain)
        self.domain = domain
        self.ips = {}
        self.subs = ['direct', 'direct-connect', 'cpanel', 'admin', 'ftp', 'pop', 'imap', 'mail', 'webmail', 'forum',
                     'admin', 'portal', 'beta']
        self.tlds = ['.com', '.net', '.info', '.org', '.biz', '.cc', '.ru', '.co.uk', '.us', '.su']

    # Tests for common subdomains which haven't been configured with CloudFlare
    def fast(self):
        print("\n-- Testing common subdomains for misconfiguration --")
        for sub in self.subs:
            subdomain = sub + '.' + self.domain
            response = dns.query(subdomain)
            if response:  # If subdomain exists
                # Prevent  errors if >1 ip returned for domain
                if type(response) == list:
                    for ip in response:
                        self.ips[subdomain] = ip
                else:
                    pass

        # Checks if the discovered domains are behind cloudflare
        for domain, ip in self.ips.iteritems():
            if dns.query(ip):
                print(output("%s is hosted at %s" % (domain, ip)))
                if ip not in iplist:
                    iplist.append(ip)

    # Checks common tlds which may have been registered for domain
    def tld(self):
        print("\n-- Testing common tlds --")
        tmp = re.split('\..*', self.domain)  # Removes current tld

        for i in self.tlds:
            testDomain = tmp[0] + i
            response = dns.query(testDomain)
            if response:
                if type(response) == list:  # If >1 ips returned
                    for ip in response:
                        if dns.query(ip):
                            print(output("%s is hosted at %s" % (testDomain, ip)))
                            if ip not in iplist:
                                iplist.append(ip)
                else:
                    if dns.query(ip):
                        print(output("%s is hosted at %s" % (testDomain, ip)))
                        if ip not in iplist:
                            iplist.append(ip)

    def dnsmap(self):
        result = subprocess.check_output([dnsmapdir + '/dnsmap', self.domain])  # Executes dnsmap
        # Formats output
        out = re.split('IP address #.: ', result)
        domain = re.split('\n', out)
        domain = domain[5]  # Stores first domain found
        store = ''  # Stores previous domain name if >1 ip returned
        for i in out:
            if i.startswith('\n'):
                pass
            else:
                ip = re.split('\n', i)
                if ip[0].startswith('dnsmap'):  # Filters out dnsmap messages
                    pass
                else:
                    if dns.query(ip[0]):
                        if ip[0] in iplist:
                            pass
                        else:
                            iplist.append(ip[0])
                        print(output("%s is hosted at %s" % (domain, ip[0])))

                    # Fixes errors when >1 ip returned for 1 subdomain
                    try:
                        if ip[0] == '127.0.0.1':  # prevents errors by dnsmap warning
                            domain = ip[3]
                        else:
                            domain = ip[2]
                    except:
                        domain = ''
                    if domain == '':
                        domain = store
                    else:
                        store = ip[2]


class DnsMisc:
    def __init__(self, domain):
        self.cfip = []
        self.cfip = self.nslookup(domain)

    # Returns ip(s) of a domain
    @staticmethod
    def nslookup(domain):
        try:
            ipaddr = socket.getaddrinfo(domain, 80)
        except:
            ipaddr = ''
        ip = []
        for i in range(0, len(ipaddr)):
            a = ipaddr[i][4][0]  # Extracts ip from returned info
            if a not in ip:
                ip.append(a)
        return ip  # Returns a list with ips

    # Checks ip is not cloudflare ip
    def check(self, ip):
        if ip not in self.cfip and ip != '127.0.0.1':
            return ip


def info(domain):
    print("\n-- Checking for php info() files --")
    # Common php info files
    files = ['info.php', 'php.php', 'phpinfo.php', 'php-info.php', '/']
    for infofile in files:
        url = 'http://%s/%s' % (domain, infofile)
        try:
            response = urllib.request.urlopen(url)
            save = response.readlines()
            if "PHP Version" in '.'.join(save):  # Check if php info file
                for line in save:
                    if "SERVER_ADDR" in line:  # SERVER_ADDR == server ip variable
                        # Extracting server ip :)
                        tmp = re.split('class="v">', line)
                        tmp = re.split('<', tmp[1])
                        ip = tmp[0]
                        print(output("Found ip: %s in phpinfo file: %s" % (ip, infofile)))
                        if ip not in iplist:
                            iplist.append(ip)
        except:
            pass


# Checks dns history of domain
def dnsHistory(domain):
    rows = ''
    print("\n-- Checking dns history --")
    url = 'http://toolbar.netcraft.com/site_report?url=' + domain
    try:
        request = urllib.request.urlopen(url)
        html = request.read()
    except:
        html = ''
    soup = BeautifulSoup(''.join(html))
    tables = soup.findAll(attrs={'class': 'TBtable'})
    try:
        table = tables[1]
    except:
        table = ''  # Prevents errors if no history returned
        rows = ''
    if table:
        rows = soup.table.findAll('tr')  # Need to edit out again
    x = -1
    try:
        for tr in rows:
            columns = tr.findAll('td')
            for td in columns:
                text = ''.join(td.find(text=True))
                if x % 5 == 0:  # Only ip addresses are checked
                    if dns.query(text):  # Finds last ip thats not CloudFlare
                        print(output("The last known ip address is: %s" % text))
                        if text not in iplist:
                            iplist.append(text)
                        raise End  # Breaks from multiple loops
                x += 1
    except End:
        pass
    print("\n#" + "-" * 77 + "#")


def verify(ip, directory, keyword):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 80))
        request = "GET " + directory + " HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; rv:10.0) Gecko/20100101 Firefox/10.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: None\r\nConnection: keep-alive\nDNT: 1\r\n\r\n"
        s.sendall(request)
        data = s.recv(4096)
        s.close()
    except socket.error:
        data = ''
    try:
        server = re.split('Server: ', data)
        server = re.split('\r\n', server[1])
        server = server[0]
    except:
        server = ''
    if 'cloudflare' in server:  # Cloudflare always returns cloudflare in server meta tag
        pass
    else:
        if keyword.lower() in data.lower():
            print(output(domain + " is confirmed at " + ip))


def logo():
    print(R + "\n|----------------------------------------------------------------|")
    print("|     V3n0mScanner.py                                            |")
    print("|     Release Date 11/04/2016  - Release Version V.4.0.4c        |")
    print("|         Socks4&5 Proxy Support                                 |")
    print("|             " + B + "        NovaCygni  Architect    " + R + "                   |")
    print("|                    _____       _____                           |")
    print("|          " + G + "         |____ |     |  _  |    " + R + "                      |")
    print("|             __   __   / /_ __ | |/' |_ _" + G + "_ ___             " + R + "     |")
    print("|             \ \ / /  " + G + " \ \ '" + R + "_ \|  /| | '_ ` _ \                 |")
    print("|              \ V" + G + " /.___/ / | | \ |_" + R + "/ / | | | | |                |")
    print("|    Official   \_/" + G + " \____/|_" + R + "| |_|" + G + "\___/|_| |_| " + R + "|_|  Release       |")
    print("|                   CloudFlare IP Resolver V.0.1                 |")
    print("|----------------------------------------------------------------|\n" + W)


W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"
logo()
iplist = []  # Stores all retrieved ip addresses
output = lambda out: "[x] " + out  # Makes the output look nice
domain = input("Enter target domain: ")
brute = Bruteforce(domain)  # Prepares domain for bruteforcing

# Attempt to find possible ips
brute.fast()
brute.tld()
info(domain)
dnsHistory(domain)

extra = input("\nWould you like to use dnsmap to find subdomains Y/N: ")
if extra.lower() == 'y':
    print("This may take a while, please be patient")
    brute.dnsmap()

extra = input("\nWould you like to confirm the results Y/N: ")
if extra.lower() == 'y':
    directory = input("Enter a file known to exist (eg /index.php): ")
    if directory.startswith('/'):
        pass
    else:
        directory = '/' + directory
    keyword = input("Enter a keyword only found on the target page: ")
    print("\n-- Confirming results --")
    for ip in iplist:
        verify(ip, directory, keyword)

print("\nFinished! All results must be verified manually")
print("If this script has been unsuccessful find a way to get the target to email you")
print("The server ip will be in the mail header")
