Latest News: LFI, RFI and XSS Features re-added, Automated basic GET based SQL injection re-added
+ All bug reports are appreciated, some features havnt been tested yet due to lack of free time.

Current Version: Release 407
![v3n0m Scanner](http://i.imgur.com/A96CipT.png "V3n0M-Scanner")
![Example of SQLi Dorker](http://s29.postimg.org/rytx5r0af/Screenshot_from_2016_04_09_10_28_19.png "Example of Dorker")



[Live Project - All features fully working in Python3.5]

V3n0M is a free and open source scanner. Evolved from baltazar's scanner, it has adapted several new features that improve fuctionality and usability. It is __mostly__ experimental software.

This program is for finding and executing various vulnerabilities. It scavenges the web using dorks and organizes the URLs it finds.
**Use at your own risk.**

## Very useful for executing:

+ Metasploit Modules Scans
+ LFI, RFI and XSS Scanning[LFI/RFI/XSS]
+ SQL Injection Vuln Scanner[SQLi]
+ Extremely Large D0rk Target Lists
+ FTP Crawler
+ DNS BruteForcer
+ Python3.5 Asyncio based scanning

## What You Hold:

**The official adoption of darkd0rker heavily recoded, updated, expanded and improved upon**
+ Brand new, just outta the box!
+ Largest and most powerful d0rker online, 18k+d0rks searched over ~ Engines at once.
+ Free and Open /src/
+ CrossPlatform Python based toolkit
+ Release 407 Released on 15th August 2016
+ Licensed under GPLv2
+ Tested on: ArchLinux 4.6.5-1, Ubuntu, Debian, Windows, MacOS

##Module Deps

+ Install pip3 if you don't have it already: **sudo apt-get install python3-pip**
+ Then install these modules with pip3: **sudo pip3 install dnspython3 aiohttp httplib2 socksipy-branch requests url**
+ Now cd into src and run v3n0m.py

## Usage:

    root@bt:~# python3 v3n0m.py

    Now you may follow the simple prompts.

    [0x100] Choose your target (domain) :
            Example : .com
            AND
            it is necessary to add you can also use a specific website (www.example.com)

    [0x200] Choose the number of random dorks (0 for all.. may take awhile!) :
            Example : 0 = This will choose all of the XSS, File Inclusion, RCE and SQLi dorks

    [0x300] Choose the number of threads :
            Example : 50

    [0x400] Enter the number of pages to search through :
            Example : 50

        The program will print out your desired settings and start searching.
        It then creates files for the collected and valid URLs for later.
        It takes a while to scan because it utilizes either TOR, which you can specify
        if you wish to do so, or regular HTTP requests over a long period of time.

        After a while, it will feed you the percentage of the scan until completion.
        At this point, it will have saved the valid URLs in the files it created earlier.
        The program utilizes over 10k dorks now, be careful how you use them!
        Enjoy. :]
                                                                ~/ Dev Team

## Contact Information:

    [ NovaCygni ] - <novacygni@hotmail.co.uk>
    [ Architect ] - <t3h4rch1t3ct@riseup.net>

## Original Header:

    - This was written for educational purpose and pentest only. Use it at your own risk.
    - Author will be not responsible for any damage!
    - !!! Special greetz for my friend sinner_01 !!!
    - Toolname        : darkd0rk3r.py
    - Coder           : baltazar a.k.a b4ltazar <b4ltazar@gmail.com>
    - Version         : 1.0
    - greetz for all members of ex darkc0de.com, ljuska.org



====================================

##Make Love and Smoke Trees...

