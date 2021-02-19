# Introduction

[![Doctor](https://www.hackthebox.eu/storage/avatars/256280ee1fb4fd4d7610881c209a2b5e.png)](https://app.hackthebox.eu/machines/278)

| Point | Description |
| :------:| :------: |
| Name | Doctor   |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 26 Sep 2020   |
| IP | 10.10.10.209   |
| Owned | 18 Feb 2021 |

# Short retelling
* Find another virtual host
* Find service in beta-test
* Use SSTI to get Reverse Shell
* Find password in logs
* Get user.txt
* Use vuln in outdate software to privilage escalation
* Get root.txt

# Enumeration

## Nmap

Let's start reconing machine "Doctor" 10.10.10.209 with Nmap

```
┌──(root💀kali)-[/home/kali/HTB/Doctor]
└─# nmap -sV -sC -p- 10.10.10.209                                                                              1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-18 23:14 EST
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.16s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 573.16 seconds
```

There are three open ports 22 (SSH), 80 (HTTP) and 8089 (Splunkd).

Let's start analyzing web-server and add doctor.htb to /etc/hosts and check site.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d1.PNG)

The hyperlinks on the pages are leading to nothing. But we find new vhost *doctors.htb*, add it too.

We find out that web site was made with *template form*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d2.PNG)

On web page doctors.htb we can see service *Doctor Secure Messaging*. There are "Login" and "Register" forms.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d3.PNG)

So let's register and try to find something interesting.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d4.PNG)

We can write massages... Ok, let's find more.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d6.PNG)

Check source code of pages doctor.htb and doctors.htb.

In the source code of the page doctor.htb there isn't a somethimg interesting, but in the source code of the page doctors.htb we find reference about beta-tsting archive in direcory /archive.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d5.PNG)

I should we need to bruteforce direcories of pages doctor.hrb and doctors.htb.

And we remember about *Splunk* on https://10.10.10.209:8089/. Let's check it.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d7.PNG)

And we find out *version* of Splunk `Splunk build: 8.0.5`. Try to open some links and we get authorization form.
Ok, we dont have any credentials.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d8.PNG)

## FuFF

At first we will enumerate directories of doctor.htb

```
──(root💀kali)-[/home/kali/HTB/Doctor]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u http://doctor.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -mc 200,302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://doctor.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/common.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

index.html              [Status: 200, Size: 19848, Words: 5808, Lines: 504]
:: Progress: [46820/46820] :: Job [1/1] :: 231 req/sec :: Duration: [0:03:31] :: Errors: 0 ::
```
No results. Next step is doctors.htb

```
┌──(root💀kali)-[/home/kali/HTB/Doctor]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u http://doctors.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -mc 200,302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://doctors.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/common.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

account                 [Status: 302, Size: 251, Words: 22, Lines: 4]
archive                 [Status: 200, Size: 101, Words: 7, Lines: 6]
home                    [Status: 302, Size: 245, Words: 22, Lines: 4]
login                   [Status: 200, Size: 4204, Words: 1054, Lines: 95]
logout                  [Status: 302, Size: 217, Words: 22, Lines: 4]
register                [Status: 200, Size: 4493, Words: 1171, Lines: 101]
:: Progress: [46820/46820] :: Job [1/1] :: 228 req/sec :: Duration: [0:03:25] :: Errors: 0 ::
```

And we find direcory */archive*. Let's open it. And we have a blank page.

Checking the source code:

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d9.PNG)

# Explotation#1




# Explotation#2


# Privilege Escalation



# Result and Resources

1. https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
2. https://netsec.ws/?p=337
3. https://xakep.ru/2020/05/26/gitlab-exploit/
4. https://forum.reverse4you.org/t/radare-2/1113
5. https://medium.com/quiknapp/fuzz-faster-with-ffuf-c18c031fc480
6. https://docs.gitlab.com/12.10/ee/security/reset_root_password.html
