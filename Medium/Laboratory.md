# Introduction

[![Laboratory](https://1.bp.blogspot.com/-QMNR6LckGZA/X7p-gYNZYxI/AAAAAAAAGnU/P6yFx9-cXdcml-USeeaTRU4FsSCti-RTgCLcBGAsYHQ/s0/infocard.png)](https://www.hackthebox.eu/home/machines/profile/298)

| Point | Description |
| :------:| :------: |
| Name | Laboratory   |
| OS   | Linux  |
| Difficulty Ratings| Medium   |
| Release | 14 Nov 2020   |
| IP | 10.10.10.216   |

# Short retelling
* Using Nmap and find new subdomain
* Register on this site and find version of service
* Find CVE for this kind of web-server
* Checking CVE
* Run Docker same version
* Configure it and create explotation of RCE
* Upload reverse shell comand to web-server and run it
* Connected to machine
* Trying to escape from docker use git railway-console
* Change password of administration git
* Sign in with admin login and our new password
* Find in_rsa in folder /.ssh
* SSH coonect to the host and find user.txt
* Find bin programm
* Check it with radare 2
* And find way to use the path hijacking
* Get root.txt
