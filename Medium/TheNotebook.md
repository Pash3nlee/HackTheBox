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

We get *typ: "JWT"* and understand that this web server is using jason web token for authorization.

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


# Privilege Escalation#1



# Privilege Escalation#2



# Result and Resources

1. https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
2. https://github.com/mbechler/marshalsec
3. https://github.com/artsploit/yaml-payload
4. https://habr.com/ru/company/ruvds/blog/454518/
5. https://webassembly.github.io/wabt/demo/wasm2wat/
6. https://webassembly.github.io/wabt/demo/wat2wasm/

