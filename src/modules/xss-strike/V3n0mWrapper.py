"""TODO:
    finish list optiond
    add single url options
    finish adding fuzz in list options
"""

import subprocess, os
from colorama import Fore, init

init(convert=True)
W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"


def logo():
    print(
        B
        + """
      ___  ___  ______ _______/  |________|__|  | __ ____  
      \  \/  / /  ___//  ___/\   __\_  __ \  |  |/ // __ \ 
       >    <  \___ \ \___ \  |  |  |  | \/  |    <\  ___/ 
      /__/\_ \/____  >____  > |__|  |__|  |__|__|_ \\___  >
            \/     \/     \/                      \/    \/"""
    )


logo()
print(G + "[1] List Options")
print("[2] Single URL Options")
choice = input("Enter Choice: ")
if choice == "1":
    logo()
    print("[1] Scan For DOM XSS From List Of URL'S")
    print("[2] Crawl Each Site in List For Potential XSS Vulns")
    print("[3] Fuzz Each Site in List")
    ListChoices = input("Enter Choice: ")
    if ListChoices == "1":
        XssList = input("Enter List: ")
        list1 = [
            line.strip()
            for line in open(XssList, "r", errors="ignore", encoding="utf-8")
        ]
        for line in list1:
            print(O + "\n" + "Testing " + R + line)
            xss = subprocess.Popen(
                "python "
                + "xsstrike.py -u "
                + line
                + " --file-log-level INFO  --log-file xss.txt",
                shell=True,
            )
            xss.communicate()
            subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
    if ListChoices == "2":
        XssList = input("Enter List: ")
        list1 = [
            line.strip()
            for line in open(XssList, "r", errors="ignore", encoding="utf-8")
        ]
        for line in list1:
            print(O + "\n" + "Testing " + R + line)
            xss = subprocess.Popen(
                "python "
                + "xsstrike.py -u "
                + line
                + " --crawl"
                + " --file-log-level INFO --log-file xss.txt",
                shell=True,
            )
            xss.communicate()
            subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
    if ListChoices == "3":
        XssList = input("Enter List: ")
        list1 = [
            line.strip()
            for line in open(XssList, "r", errors="ignore", encoding="utf-8")
        ]
        for line in list1:
            print(O + "\n" + "Testing " + R + line)
            xss = subprocess.Popen(
                "python " + "xsstrike.py -u " + line + " --fuzz"
                " --file-log-level INFO --log-file xss.txt",
                shell=True,
            )
            xss.communicate()
            subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
if choice == "2":
    print("[1] Scan For DOM XSS")
    print("[2] Crawl Site")
    print("[3] Fuzzer")
    chce2 = input("Enter Choice: ")
    if chce2 == "1":
        url = input("Enter URL: ")
        print(O + "\n" + "Testing " + R + url)
        xss = subprocess.Popen(
            "python "
            + "xsstrike.py -u "
            + url
            + " --file-log-level INFO  --log-file xss.txt",
            shell=True,
        )
        xss.communicate()
        subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
    if chce2 == "2":
        url = input("Enter URL: ")
        print(O + "\n" + "Testing " + R + url)
        xss = subprocess.Popen(
            "python "
            + "xsstrike.py -u "
            + chce2
            + " --crawl"
            + " --file-log-level INFO --log-file xss.txt",
            shell=True,
        )
        xss.communicate()
        subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
    if chce2 == "3":
        url = input("Enter URL: ")
        print(O + "\n" + "Testing " + R + url)
        xss = subprocess.Popen(
            "python " + "xsstrike.py -u " + url + " --fuzz"
            " --file-log-level INFO --log-file xss.txt",
            shell=True,
        )
        xss.communicate()
        subprocess._cleanup()
        print("Finished Check /modules/xss-strike/xss.txt")
