# hfuzz (HTTP fuzzer)

Simple and dirty http fuzzer for pentesting without dependencies. It's simple enough to extend it with the functionalities you need. 

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

The http fuzzer should run on any UNIX/Linux box. You only need a relatively modern gcc compiler.

### Installing

Download a copy of the project from github: 

```
$ git clone https://github.com/joseigbv/hfuzz.git
```

Edit 'hfuzz.c' and change configuration.

```
#define HOSTNAME "testphp.vulnweb.com"
#define PORT 80
...
                // url, cookies, posts, ...
                sprintf(url, "/userinfo.php");
                sprintf(post, "uname=test&pass=%s", urlenc);
                sprintf(cookie, "login=test%%2F%s", urlenc);
                sprintf(referer, "http://testphp.vulnweb.com/login.php");

...
                sprintf(psn, "%sHost: %s\r\n", psn, HOSTNAME);
                sprintf(psn, "%sUser-Agent: %s\r\n", psn, USER_AGENT);
                sprintf(psn, "%sReferer: %s\r\n", psn, referer);
                sprintf(psn, "%sCookie: %s\r\n", psn, cookie);
                sprintf(psn, "%sContent-Type: application/x-www-form-urlencoded\r\n", psn);
                sprintf(psn, "%sContent-Length: %d\r\n", psn, (int) strlen(post));
                sprintf(psn, "%s\r\n", psn);
                sprintf(psn, "%s%s\r\n", psn, post);
...
```

Compile (-DHTTP11 for HTTP1.1):

```
$ gcc -Wall -O2 -DHTTP11 -lpthread fuzz.c -o fuzz
```

### Usage 

The command line is very simple:

```
$ hfuzz < words.txt 2> hfuzz.err | tee hfuzz.out 
40      password        302     244 bytes       130 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
18      prueba  302     244 bytes       130 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
5       passw   302     244 bytes       129 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
48      passwd  302     244 bytes       131 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
56      clave   302     244 bytes       132 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
66      guest   302     244 bytes       133 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
14      ftp     302     244 bytes       134 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
35      12345   302     244 bytes       135 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html
52      test    200     5389 bytes      255 ms  POST    /userinfo.php   HTTP/1.1 200 OK text/html
3       root    302     244 bytes       491 ms  POST    /userinfo.php   HTTP/1.1 302 Found      text/html

$ cat hfuz.err
...
--------------------------------------------

>>> id: 40 <<<

POST /userinfo.php HTTP/1.1
Host: testphp.vulnweb.com
User-Agent: Mozilla/5.0 (Windows NT 6.0; rv:12.0)
Referer: http://testphp.vulnweb.com/login.php
Cookie: login=test%2Fpassword
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

uname=test&pass=password

HTTP/1.1 302 Found
Server: nginx/1.4.1
Date: Wed, 10 Jul 2013 07:51:32 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/5.3.10-1~lucid+2uwsgi2
Location: login.php

e
you must login
0

--------------------------------------------
...
```

Combined with 'delegate' for HTTPS:

```
$ delegated -P80 SERVER=http MOUNT="/ * https://www.micorp.com/ *" STLS=fsv:https
...
````

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details




