# Introduction

[![Horizontall](https://www.hackthebox.eu/storage/avatars/e4ec7d8504fdb58b5e6b7ddc82aafc77.png)](https://app.hackthebox.eu/machines/Horizontall)

| Point | Description |
| :------:| :------: |
| Name | Horizontall |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 28 Aug 2021   |
| IP | 10.10.11.105   |
| Owned | 03 Sep 2021 |

# Short retelling

* Enumeration and find directories
* 

# Enumeration

## Nmap

Recon host 10.10.11.105 with Nmap and Add horizontall.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali]
└─# nmap -T4 -A -p- --min-rate 500 10.10.11.105
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-03 03:13 EDT
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/3%OT=22%CT=1%CU=44731%PV=Y%DS=2%DC=T%G=Y%TM=6131CBB3
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54BST11NW7%O2=M54BST11NW7%O3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BST11
OS:NW7%O6=M54BST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   203.27 ms 10.10.16.1
2   94.32 ms  horizontall.htb (10.10.11.105)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.03 seconds
```
Checking 80 http service

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/h1.PNG)

We see just one-page site without any links

## Gobuster

Let's try to find some directories

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# gobuster dir -e -u http://horizontall.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x .php,.txt,.htm,.html,.phtml,.js,.zip,.rar,.tar -t 100    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://horizontall.htb/
[+] Threads:        100
[+] Wordlist:       /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     js,zip,rar,tar,htm,html,phtml,php,txt
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/09/03 03:21:05 Starting gobuster
===============================================================
http://horizontall.htb/css (Status: 301)
http://horizontall.htb/favicon.ico (Status: 200)
http://horizontall.htb/img (Status: 301)
http://horizontall.htb/index.html (Status: 200)
http://horizontall.htb/index.html (Status: 200)
http://horizontall.htb/js (Status: 301)
===============================================================
2021/09/03 03:21:54 Finished
===============================================================
```
Ok, nothing interesting

## Ffuf

Enumerate subdomains

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://horizontall.htb/ -H "Host:FUZZ.horizontall.htb" -fw 7 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 7
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20]
:: Progress: [114441/114441] :: Job [1/1] :: 983 req/sec :: Duration: [0:01:53] :: Errors: 0 ::
```

We find `api-prod` subdomain. Add api-prod.horizontall.htb to /etc/hosts.

Checking api-prod.horizontall.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/h2.PNG)

# Explotation


# Privilege Escalation


# Resources

1. 

