#!/usr/bin/python3
# -*- coding: latin-1 -*-
# This file is part of v3n0m
# See LICENSE for license details.


try:
    import re, random, threading, socket, urllib.request, urllib.error, urllib.parse, http.cookiejar, subprocess, \
        time, sys, os, math, itertools, queue, asyncio, aiohttp, argparse, socks, httplib2, requests, codecs
    from signal import SIGINT, signal
    import pprint
    from aiohttp import ClientSession
    from codecs import lookup, register
    from random import SystemRandom
    import ftplib, tqdm
    from ftplib import FTP
    from os import getpid, kill, path
    from sys import argv, stdout
    from random import randint
    from aiohttp import web
    import async_timeout
    import inspect
    from functools import wraps

except:
    exit()


def killpid(signum=0, frame=0):
    print("\r\x1b[K")
    os.kill(os.getpid(), 9)


W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"
msf_Vulns = [line.strip() for line in open("lists/vuln-ftp-checklist.txt", 'r')]
global LoadedIPCache


def banner():
    print('''       NovaCygni's
        .---..----..-..-..-..-..-.
        `| |'| || | >  < | || .` |
         `-' `----''-'`-``-'`-'`-'
           V3n0M Metasploitable Scanner Version 0.1.2

    ''')



class IPChecker:
    """A class to check if an IP is in a range of IPs"""
    ipdict = {}
    fulls = [{}, {}, {}]

    def __init__(self):
        # Create dictionaries for rest of ip sequences for caching
        for i in range(0, 256):
            self.fulls[0][i] = True
        for i in range(0, 256):
            self.fulls[1][i] = self.fulls[0]
        for i in range(0, 256):
            self.fulls[2][i] = self.fulls[1]

    def loadIPs(self, filename):
        with open(filename, 'r', encoding='utf-8') as f:
            i = 0
            for line in f:
                i += 1
                try:
                    ip = line.split("#")[0].strip()
                except:
                    raise ValueError("Error while parsing line: \"" + line + "\"")
                if len(ip) == 0:
                    continue
                if not re.match("^[0-9\*-]+\.[0-9\*-]+\.[0-9\*-]+\.[0-9\*-]+$", ip):
                    raise ValueError("Error in format while parsing line: \"" + line + "\"")
                added = self.addIP(ip)
                if added != 0:
                    raise ValueError(str(added) + ": Error while parsing IP on line: \"" + line + "\"")

    def generateValidIP(self):
        ip = ""
        curdict = self.ipdict
        for i in range(0,4):
            randip = randint(0,255)
            while (randip in curdict.keys()) and ((i!=3 and (len(curdict[randip].keys())>=255)) or i==3):
                randip = randint(0,255)
            if randip in curdict.keys():
                curdict = curdict[randip]
            else:
                curdict = {}
            ip += str(randip)
            if i!=3:
                ip += "."
            else:
                ip += ""
        return ip

    def addIP(self, ipstr):
        parts = re.findall("[0-9\*-]+", ipstr)
        return self.addFirstPart(self.ipdict, parts)

    def addFirstPart(self, partDict, parts):
        if parts[0] == "*":
            return self.addRange(partDict, parts, 0, 255)
        elif len(parts[0].split("-")) == 2:
            first = int(parts[0].split("-")[0])
            second = int(parts[0].split("-")[1])
            return self.addRange(partDict, parts, first, second)
        elif len(parts[0].split("-")) == 1:
            only = int(parts[0])
            return self.addRange(partDict, parts, only)
        else:
            return -1

    def addRange(self, partDict, parts, first, second=-1):
        if second == -1:
            second = first
        if not first in partDict.keys():
            nextDict = {}
        else:
            nextDict = partDict[first]
        for i in range(first, second + 1):
            if not i in partDict.keys():
                partDict[i] = nextDict
            elif first != second:
                return -2
            if len(parts) != 1:
                rest = True
                for j in range(0, len(parts)):
                    if parts[j] != "*":
                        rest = False
                if rest:
                    partDict[i] = self.fulls[len(parts) - 1]
                else:
                    self.addFirstPart(partDict[i], parts[1:])
            else:
                partDict[i] = True
        return 0

    def checkIP(self, ip):
        if not re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", ip):
            raise ValueError("Error in format while parsing ip: " + str(ip))
        parts = re.findall("[0-9]+", ip)
        parts[0] = int(parts[0])
        parts[1] = int(parts[1])
        parts[2] = int(parts[2])
        parts[3] = int(parts[3])
        if parts[0] in self.ipdict:
            if parts[1] in self.ipdict[parts[0]]:
                if parts[2] in self.ipdict[parts[0]][parts[1]]:
                    if parts[3] in self.ipdict[parts[0]][parts[1]][parts[2]]:
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return False


def makeips(amount):
    IPList = []
    c = IPChecker()
    # Path to Honeypot file with IP's and Ranges that should NOT be generated. Only a retard wouldnt do this!
    c.loadIPs("lists/honeypot_ranges.txt")
    amt = int(amount)
    for i in range(0, amt):
        ip = c.generateValidIP()
        try:
            assert (c.checkIP(ip) == False)
        except:
            print(ip + " Failed to generate")
            raise
        IPList.append(ip)

    print("Ips Generated: " + str(len(IPList)))
    print("[1] Save IP addresses to file")
    print("[2] Print IP addresses")
    print("[3] Return to Toxins Menu")
    print("[4] Setup Port specific attacks")
    print("[0] Exit Toxin Module")
    # Create a secondry Log file for working with without corrupting main IP List.
    log = "IPLogList.txt"
    logfile = open(log, "a")
    for t in IPList:
        logfile.write("ftp://" + t + ":21" + "\n")
    logfile.close()
    chce = input("Option: ")
    if chce == '1':
        print("Save IP addresses?")
        listname = input("Filename: ")
        try:
            print("Saving valid Ip Addresses")
            list_name = open(listname, "a")
            IPList.sort()
            for t in IPList:
                list_name.write(t + "\n")
            list_name.close()
            print("Urls saved, please check", listname)
        except:
            print("Failed to save")
    if chce == '2':
        pp = pprint.PrettyPrinter(width=66, compact=True)
        pp.pprint(IPList)
        print("Do you wish to start Toxin again or Exit to V3n0M")
        print("[1] Stay within Toxin")
        print("[2] Exit to V3n0M")
        chc = input("Option: ")
        if chc == '1':
            menu()
        if chc == '2':
            exit()
    if chce == '3':
        menu()
    if chce == '4':
        print("[1] Launch FTP Checks")
        print("[0] Exit")
        choice = input("Which Option:")
        if choice == '1':
            print("")

        if choice == '0':
            exit()
    if chce == '0':
        exit()



def menu():
    banner()
    global IPList
    amount = input("How many IP addresses do you want to scan: ")
    makeips(amount)


while True:
        menu()
