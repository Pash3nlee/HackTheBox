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

* Enumeration and find subdomain
* 

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

Ok, we have 6 http services on 80/tcp, 5000/tcp, 5040/tcp, 5985/tcp, 5986/tcp, 47001/tcp, MySQL server on 3306/tcp and SMB on 445/tcp.


## ffuf







# Explotation



# Privilege Escalation



# Resources

1. https://portswigger.net/web-security/ssrf
2. 

