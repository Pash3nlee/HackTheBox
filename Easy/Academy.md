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
* Find "key", that helps to login as admin
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
![](IMAGE)

We can see that there is two options available for login & Register.
Lets try to reqister.

Redirect, and we can see a new page home.php, surfing, find out username **egre55** (probably admin). But we find nothing more interesting.
Check source code.. and find nothing too.

## Gobuster

So lets enumerate webserver path and files.

```
GOBUSTER
GOBUSTER
```

And we see new page - **admin.php** and directory - **images**.

![](image)

Admin.php looks like login.php

No ideas, let's chec

