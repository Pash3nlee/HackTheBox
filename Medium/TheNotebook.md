# Introduction

[![](https://www.hackthebox.eu/storage/avatars/7295ea27df8a46144ed5f939b96ffaae.png](https://app.hackthebox.eu/machines/320)

| Point | Description |
| :------:| :------: |
| Name | TheNotebook  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 06 Mar 2021   |
| IP | 10.10.10.230   |
| Owned | 16 Mar 2021 |

# Short retelling

* Find RCE for YAML
* 

# Enumeration

## Nmap

Let's start reconing machine "Ophiuchi" 10.10.10.227 with Nmap

```
└─# nmap -sV -sC -p- 10.10.10.227                                                                                                                                    130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 01:03 EST
Stats: 0:22:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 94.40% done; ETC: 01:26 (0:01:19 remaining)
Nmap scan report for ophiuchi.htb (10.10.10.227)
Host is up (0.31s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6d:fc:68:e2:da:5e:80:df:bc:d0:45:f5:29:db:04:ee (RSA)
|   256 7a:c9:83:7e:13:cb:c3:f9:59:1e:53:21:ab:19:76:ab (ECDSA)
|_  256 17:6b:c3:a8:fc:5d:36:08:a1:40:89:d2:f4:0a:c6:46 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.38
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1508.80 seconds
```
We find 8080/tcp and 22/tcp ports, so lets add *ophiuchi.htb* to /etc/hosts and website http://ophiuchi.htb:8080.

![Ophiuchi](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-23_130611.png)

We see *Online YAML Parser*. 

When we are clicked on button *parse*, we will get redirect to the another page with information about error. 

![Ophiuchi](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-23_131153.png)

And I start searching about exploits for *Online YAML Parser*:

* https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
* https://github.com/mbechler/marshalsec
* https://github.com/artsploit/yaml-payload

# Explotation



# Privilege Escalation#1



# Privilege Escalation#2



# Result and Resources

1. https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
2. https://github.com/mbechler/marshalsec
3. https://github.com/artsploit/yaml-payload
4. https://habr.com/ru/company/ruvds/blog/454518/
5. https://webassembly.github.io/wabt/demo/wasm2wat/
6. https://webassembly.github.io/wabt/demo/wat2wasm/

