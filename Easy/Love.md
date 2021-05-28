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
[WARN] Caught keyboard interrupt (Ctrl-C)

```

And we get new web-page *http://staging.love.htb/*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/l4.PNG)


# Explotation



# Privilege Escalation



# Resources

1. https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html
2. 

