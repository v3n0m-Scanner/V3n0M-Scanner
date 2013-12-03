![v3n0m Scanner](http://i.imgur.com/A96CipT.png "hax")
v3n0m is a free and open source scanner. Evolved from baltazar's scanner, it has adapted several new features that improve fuctionality and usability. It is _mostly_ experimental software.<br />

This program is for finding and executing various vulnerabilities. It scavenges the web using dorks and organizes the URLs it finds.<br />

**Use at your own risk.**<br />

## Very useful for executing:
+ Cross Site Scripting [XSS]
+ Remote Code Execution [RCE]
+ Local File Inclusion [LFI]
+ SQL Injection [SQLi]

## What You Hold:

**A modified smartd0rk3r**
+ Brand new, just outta the box!
+ Free and Open /src/
+ Linux Edition :]
+ 10/23/2013 - v3.2.1
+ Licensed under GPLv2
+ Tested on: Linux 3.2.6 Ubuntu/Debian, CentOS 6 (with some errors)

## Usage:

    root@bt:~# python2.7 Linux-v3n0m.py

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

    [ levi      ] - <l3v1athan@tormail.org>
    [ baltazar  ] - <b4ltazar@gmail.com>
    [ NovaCygni ] - <novacygni@hotmail.co.uk>
    [ Architect ] - <t3h4rch1t3ct@riseup.net>
    [ d4rkcat   ] - <d4rkcat@yandex.com>
    
**Website**: Visit b4ltazar.us for prev. versions
**IRC**: irc.rootd.it +6697 (SSL) #rootd.it

## Original Header:

    - This was written for educational purpose and pentest only. Use it at your own risk.
    - Author will be not responsible for any damage!
    - !!! Special greetz for my friend sinner_01 !!!
    - Toolname        : darkd0rk3r.py
    - Coder           : baltazar a.k.a b4ltazar <b4ltazar@gmail.com>
    - Version         : 1.0
    - greetz for all members of ex darkc0de.com, ljuska.org

## New To This Addition:
    ---To be Done --Partially implemented -Done
      -Fix engines search parameters
    ---Increase LFI/RFI/XSS Lists if possible
    ---Implement SQL Database dumping tweaks
    ---Implement SQLi Post Method attack
      -Removed ToRSledgehammer attack. Only skids DoS
     --Update Banner
     --Generalised "Tweaks" required
    ---Build and Implement Admin page finder
    ---Commenting
    ---Improve Md5 check to not use Static method
    ---Prepare code for Hash cracking feature
    ---Live logging
     --Prepare coding for Admin page finder
    ---Pause Scanning option
    ---Add MD5 and SHA1 Detection/Cracking
    ---Add code to skip all payloads once positive if found
    
