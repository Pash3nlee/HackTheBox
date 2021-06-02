# Introduction

[![Knife](https://www.hackthebox.eu/storage/avatars/110fe6608793064cf171080150ebd0dc.png)](https://app.hackthebox.eu/machines/347)

| Point | Description |
| :------:| :------: |
| Name | Knife |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 22 May 2021   |
| IP | 10.10.10.242   |
| Owned | 31 May 2021 |

# Short retelling
* Find vulearable version of CMS
* 

# Enumeration

## Nmap

Recon host 10.10.10.242 with nmap. Add knife.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# nmap -sV -A -p- --min-rate 5000 10.10.10.242                                                                                                                                                                                     130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-01 21:40 EDT
Nmap scan report for knife.htb (10.10.10.242)
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/1%OT=22%CT=1%CU=35740%PV=Y%DS=2%DC=T%G=Y%TM=60B6E1CC
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
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

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   205.68 ms 10.10.16.1
2   94.97 ms  knife.htb (10.10.10.242)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.91 seconds
```

Ports 80 and 22 are open

Let's check http://knife.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/k1.PNG)

And we see just one page without links.

## ffuf

Let's enumerate directories and sub domains

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://knife.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://knife.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/big.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessphp            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesszip            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessjs             [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessphtml          [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesshtm            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesstxt            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesshtml           [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessrar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesstar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdphp            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdtxt            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdhtm            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdphtml          [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdhtml           [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdjs             [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdzip            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdrar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdtar            [Status: 403, Size: 274, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10]
:: Progress: [204750/204750] :: Job [1/1] :: 818 req/sec :: Duration: [0:03:57] :: Errors: 0 ::
```

And no results, let's check subdomains

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://knife.htb/ -H "Host:FUZZ.knife.htb" -fw 646

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://knife.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.knife.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 646
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 387 req/sec :: Duration: [0:05:30] :: Errors: 0 ::
```

# Explotation



# Privilege Escalation



# Resources

1. https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html
2. https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py
3. https://0xdf.gitlab.io/2019/02/13/playing-with-dirty-sock.html
4. https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/
5. https://medium.com/@briskinfosec/drupal-core-remote-code-execution-vulnerability-cve-2019-6340-35dee6175afa
6. https://github.com/pimps/CVE-2018-7600
7. https://github.com/dreadlocked/Drupalgeddon2
