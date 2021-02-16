# Introduction

![Bucket](https://www.hackthebox.eu/storage/avatars/3f07dd46f3ff7d287d2f736b18c6ded7.png)

| Point | Description |
| :------:| :------: |
| Name | Bucket  |
| OS   | Linux  |
| Difficulty Rating| Medium   |
| Release | 12 Dec 2020   |
| IP | 10.10.10.220   |
| Owned | 17 Oct 2020 |

# Short retelling

* Find a subdomain
* Enamuration services
* Recon DynamoDB with AWS CLI
* Find buckets in S3 AWS
* Upload a php reverse shell
* Get the user.txt
* Create the table with RCE in DynamoDB
* Get root's ia_rsa and root.txt

# Enumeration

## Nmap

Lets start reconing machine "Bucket" 10.10.10.212 with Nmap

```
┌──(root💀kali)-[/home/kali]
└─# nmap -sV -sC -p- 10.10.10.212
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-15 04:49 EST
Stats: 0:07:31 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 72.44% done; ETC: 04:59 (0:02:51 remaining)
Nmap scan report for bucket.htb (10.10.10.212)
Host is up (0.29s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We find 80/tcp and 22/tcp ports, so lets check website http://bucket.htb.

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/10.PNG)

The hyperlinks on the pages are leading to nothing.

Enumerating directories gives no results.

Lets analyze source code of the page.

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/11.PNG)

We found out subdomain **s3.bucket.htb**. Add it to /etc/hosts and check http://s3.bucket.htb webpage.

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/12.PNG)

We see just ‘{“status”: “running”}’ on the webpage.


## FuFF

Next step will be enumerating directories of s3.bucket.htb.

```
┌──(root💀kali)-[/home/kali]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://s3.bucket.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -mc 200,302 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://s3.bucket.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/big.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

health                  [Status: 200, Size: 54, Words: 5, Lines: 1]
shell                   [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [204750/204750] :: Job [1/1] :: 109 req/sec :: Duration: [0:32:40] :: Errors: 40 ::                                                                          
```

We find two directories: *s3.bucket.htb/health* ans *s3.bucket.htb/shell*.

Lets visit the http://s3.bucket.htb/health

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/13.PNG)

URL http://s3.bucket.htb/shell redirect us to to http://444af250749d:4566/shell/. That's fine. Checking hints on HTB forum and find out about extra slash “/” added at the end of the URL.

Lets visit the http://s3.bucket.htb/shell/

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/14.PNG)

# Explotation

Ok, we have two services *s3* and *dynamodb* and we have *DynamoDB JavaScript Shell* of amazon web services.

Let's use google to get more information.

>>> An Amazon S3 bucket is a public cloud storage resource available in Amazon Web Services' (AWS) Simple Storage Service (S3), an object storage offering. Amazon S3 buckets, which are similar to file folders, store objects, which consist of data and its descriptive metadata.

>>> A bucket is a container for objects stored in Amazon S3. Every object is contained in a bucket. For example, if the object named photos/puppy.jpg is stored in the awsexamplebucket1 bucket in the US West (Oregon) Region, then it is addressable using the URL https://awsexamplebucket1.s3.us-west-2.amazonaws.com/photos/puppy.jpg. 

>>> DynamoDB is a key-value, noSQL database developed by Amazon. It’s unlike some other products offered by Amazon and other vendors in that it’s not just an open source system, like Spark, hosted on the vendor’s platform. Amazon wrote this for their own internal needs and now they make it available to their customers.

We need to find hacking tricks with AWS Simple Storage Service.

* https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed
* https://medium.com/@cvignesh28/aws-s3-bucket-misconfiguration-c11e8f86e9a7
* https://blog.securelayer7.net/hands-on-aws-s3-bucket-vulnerabilities/

Ok, in every exploits is using AWS CLI on host, but we have web-shell *DynamoDB JavaScript Shell*.

We find how to check tables in dynamodb with javascript [here](https://stackoverflow.com/questions/57988963/how-to-access-dynamodb-local-using-dynamodb-javascript-shell).

```
var params = {
    TableName: 'my-table',
    Limit: 10
};
dynamodb.scan(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});
```

We guess about table's names. And table name 'users' gets true result.

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/15.PNG)

We find out about credetials (three usernames and three passwords).

```
Mgmt: Management@#1@#
Cloudadm: Welcome123!
Sysadm: n2vM-<_K_Q:.Aa2
```

Try to use the credentials to get an SSH shell, but it’s not working. We need to do more enumeration to get a shell on this box or a reverse shell.



# Privilege Escalation#1

# Privilege Escalation#2


```

# Result and Resources

1. https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
2. https://github.com/dotPY-hax/gitlab_RCE
3. https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat
4. https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1
5. https://habr.com/ru/post/56049/
6. https://docs.gitlab.com/ee/administration/troubleshooting/gitlab_rails_cheat_sheet.html
