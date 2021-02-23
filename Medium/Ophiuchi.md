# Introduction

[![Ophiuchi](https://www.hackthebox.eu/storage/avatars/82b3289bbabf88da886bc9f45802ac17.png)](https://app.hackthebox.eu/machines/315)

| Point | Description |
| :------:| :------: |
| Name | Ophiuchi  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 13 Feb 2021   |
| IP | 10.10.10.227   |
| Owned | 20 Feb 2021 |

# Short retelling

* Find RCE for YAML
* Upload reverse shell
* Find password in logs
* Get User.txt
* Edit .wasm file
* Create new .sh file
* Get reverse shell
* Get Root.txt

# Enumeration

## Nmap

Let's start reconing machine "Ophiuchi" 10.10.10.227 with Nmap

```

```
We find 8080/tcp and 22/tcp ports, so lets add *ophiuchi.htb* to /etc/hosts and website http://ophiuchi.htb:8080.

![Ophiuchi](https://github.com/Pash3nlee/HackTheBox/raw/main/images/%D0%B8%D0%B7%D0%BE%D0%B1%D1%80%D0%B0%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5_2021-02-23_130611.png)





# Explotation



# Privilege Escalation#1



# Privilege Escalation#2



# Result and Resources

### Root flag was a difficult for me and I used many hints. I have fully analyzed the solution, that was very interesting. I enjoyed this box.

1. https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed
2. https://medium.com/@cvignesh28/aws-s3-bucket-misconfiguration-c11e8f86e9a7
3. https://blog.securelayer7.net/hands-on-aws-s3-bucket-vulnerabilities/
4. https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html
5. https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html
6. https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html
7. https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
8. https://docs.aws.amazon.com/cli/latest/userguide/cli-services-dynamodb.html
