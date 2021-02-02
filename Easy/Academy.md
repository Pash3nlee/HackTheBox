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
NMAP
NMAP
NMAP
```

Ports 80 and 22 are open. 

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
And find interesting hidden string win roleid in *http://academy.htb/register.php*.

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


# Privilege Escalation#1

# Privilege Escalation#2

# Privilege Escalation#3

