# HTTP头

## Accept

```
请求头引导（）客户端可以处理的服务器类型，这种内容类型使用ME类型来
能够接受的回应内容类型（Content-Types）
```

### 语法

```
Accept: <MIME_type>/<MIME_subtype>
Accept: <MIME_type>/*
Accept: */*
```

### 示例

```
Accept: text/html
Accept: image/*
Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8
```

## Accept-CH

```
客户端应由客户端提示设置，以指定客户端应由服务器提示头设置。
```

### 语法

```
Accept-CH: <list of client hints>
```

### 示例

```
Accept-CH-Lifetime: <age>
```

## Accept-Charset

```
Accept-Charset 请求头用来告知（服务器）客户端可以处理的字符集类型。
```

### 语法

```
Accept-Charset: <charset>
```

### 示例

```
Accept-Charset: iso-8859-1

Accept-Charset: utf-8, iso-8859-1;q=0.5

Accept-Charset: utf-8, iso-8859-1;q=0.5, *;q=0.1
```

## Accept-Encoding

```
HTTP 请求头 Accept-Encoding 会将客户端能够理解的内容编码方式——通常是某种压缩算法——进行通知（给服务端）。通过内容协商的方式，服务端会选择一个客户端提议的方式，使用并在响应头 Content-Encoding 中通知客户端该选择。
```

### 语法

```
Accept-Encoding: gzip	表示采用Lempel-Ziv coding (LZ77) 压缩算法,以及32位CRC 校验的编码方式。			
Accept-Encoding: compress 采用 Lempel-Ziv-Welch (LZW) 压缩算法。
Accept-Encoding: deflate 采用 zlib 结构和 deflate 压缩算法。
Accept-Encoding: br 表示采用 Brotli 算法的编码方式。
Accept-Encoding: identity 用于指代自身（例如：未经过压缩和修改）。除非特别指明，这个标记始终可以被接受。
Accept-Encoding: * 匹配其他任意未在该请求头字段中列出的编码方式。
```

### 示例

```
Accept-Encoding: gzip

Accept-Encoding: gzip, compress, br

Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1
```

## Accept-Language

```
Accept-Language 请求头允许客户端声明它可以理解的自然语言，以及优先选择的区域方言
```

### 语法

```
Accept-Language: <language>
Accept-Language: *

*
任意语言；"*" 表示通配符（wildcard）。

;q= (q-factor weighting)
此值代表优先顺序，用相对质量价值表示，又称为权重。
```

### 示例

```
Accept-Language: de

Accept-Language: de-CH

Accept-Language: en-US,en;q=0.5

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
```

### Accept-Patch

```
服务器使用 HTTP 响应头 Accept-Patch 通知浏览器请求的媒体类型 (media-type) 可以被服务器理解。
```

### 语法

```
Accept-Patch: application/example, text/example
Accept-Patch: text/example;charset=utf-8
Accept-Patch: application/merge-patch+json
```

### 示例

```
Accept-Patch: application/example, text/example

Accept-Patch: text/example;charset=utf-8

Accept-Patch: application/merge-patch+json
```

## Accept-Ranges

```
服务器使用 HTTP 响应头 Accept-Ranges 标识自身支持范围请求 (partial requests)。字段的具体值用于定义范围请求的单位。
当浏览器发现 Accept-Ranges 头时，可以尝试继续中断了的下载，而不是重新开始。
```

### 语法

```
Accept-Ranges: bytes
Accept-Ranges: none
```

### 示例

```
Accept-Ranges: bytes
```

## Access-Control-Allow-Credentials

```
Access-Control-Allow-Credentials 响应头表示是否可以将对请求的响应暴露给页面。返回 true 则可以，其他值均不可以。
```

### 语法

```
Access-Control-Allow-Credentials: true
```

### 示例

```
Access-Control-Allow-Credentials: true
```

## Access-Control-Allow-Headers

```
响应首部 Access-Control-Allow-Headers 用于 preflight request（预检请求）中，列出了将会在正式请求的 Access-Control-Request-Headers 字段中出现的首部信息。
如果请求中含有 Access-Control-Request-Headers 字段，那么这个首部是必要的。
```

### 语法

```
Access-Control-Allow-Headers: <header-name>[, <header-name>]*
Access-Control-Allow-Headers: *
```

### 示例

```
Access-Control-Allow-Headers: X-Custom-Header
```

## Access-Control-Allow-Methods

```
响应首部 Access-Control-Allow-Methods 在对 preflight request.（预检请求）的应答中明确了客户端所要访问的资源允许使用的方法或方法列表。
```

### 语法

```
Access-Control-Allow-Methods: <method>, <method>, ...
```

### 示例

```
Access-Control-Allow-Methods: POST, GET, OPTIONS
```

## Access-Control-Allow-Origin

```
Access-Control-Allow-Origin 响应头指定了该响应的资源是否被允许与给定的origin共享。
```

### 语法

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: <origin>
```

### 示例

```
如需允许所有资源都可以访问您的资源，您可以如此设置：
Access-Control-Allow-Origin: *

如需允许https://developer.mozilla.org访问您的资源，您可以设置：
Access-Control-Allow-Origin: https://developer.mozilla.org
```



## Access-Control-Expose-Headers

```
响应首部 Access-Control-Expose-Headers 列出了哪些首部可以作为响应的一部分暴露给外部。
默认情况下，只有七种 simple response headers（简单响应首部）可以暴露给外部：

Cache-Control
Content-Language
Content-Length
Content-Type
Expires
Last-Modified
Pragma
```

### 语法

```
Access-Control-Expose-Headers: <header-name>, <header-name>, ...
```

### 示例

```
想要暴露一个非简单响应首部，可以这样指定：
Access-Control-Expose-Headers: Content-Length
```

## Access-Control-Max-Age

```
The Access-Control-Max-Age 这个响应头表示 preflight request  （预检请求）的返回结果（即 Access-Control-Allow-Methods 和Access-Control-Allow-Headers 提供的信息） 可以被缓存多久。
```

### 语法

```
Access-Control-Max-Age: <delta-seconds>
```

### 示例

```
将预检请求的结果缓存 10 分钟：
Access-Control-Max-Age: 600 
```

## Connection

```
Connection 头（header） 决定当前的事务完成后，是否会关闭网络连接。如果该值是“keep-alive”，网络连接就是持久的，不会关闭，使得对同一个服务器的请求可以继续在该连接上完成。
```

### 语法

```
Connection: keep-alive
Connection: close
```

## Content-Location

```
Content-Location 首部指定的是要返回的数据的地址选项。最主要的用途是用来指定要访问的资源经过内容协商后的结果的 URL。
```

### 语法

```
Content-Location: <url>
```

### 示例

```
Content-Location: /index.html
```

## Content-Security-Policy

```
HTTP 响应头Content-Security-Policy允许站点管理者控制用户代理能够为指定的页面加载哪些资源。
```

### 语法

```
Content-Security-Policy: <policy-directive>; <policy-directive>
```

## Content-Security-Policy-Report-Only

```
HTTP Content-Security-Policy-Report-Only响应头允许 web 开发人员通过监测 (但不强制执行) 政策的影响来尝试政策
```

### 语法

```
Content-Security-Policy-Report-Only: <policy-directive>; <policy-directive>
```

### 示例

```
Content-Security-Policy-Report-Only: default-src https:; report-uri /csp-violation-report-endpoint/
```

## Content-Type

```
Content-Type 实体头部用于指示资源的 MIME 类型 media type 。
```

### 语法

```
Content-Type: text/html; charset=utf-8
Content-Type: multipart/form-data; boundary=something
```

### 示例

```
<form action="/" method="post" enctype="multipart/form-data">
  <input type="text" name="description" value="some text">
  <input type="file" name="myFile">
  <button type="submit">Submit</button>
</form>
```

## Cookie

```
Cookie 是一个请求首部，其中含有先前由服务器通过 Set-Cookie  首部投放并存储到客户端的 HTTP cookies。
```

### 语法

```
Cookie: <cookie-list>
Cookie: name=value
Cookie: name=value; name2=value2; name3=value3
```

### 示例

```
Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;
```

## Cross-Origin-Embedder-Policy

```
HTTP Cross-Origin-Embedder-Policy (COEP) 响应标头可防止文档加载未明确授予文档权限 (通过 CORP或者 CORS) 的任何跨域资源 。
```

### 语法

```
Cross-Origin-Embedder-Policy: unsafe-none | require-corp
```

### 示例

```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

## Cross-Origin-Resource-Policy

```
Cross-Origin-Resource-Policy 响应头会指示浏览器阻止对指定资源的无源跨域/跨站点请求。
```

### 语法

```
Cross-Origin-Resource-Policy: same-site | same-origin
```

### 示例

```
Cross-Origin-Resource-Policy: same-origin
```

## Forwarded

```
Forwarded 首部中包含了代理服务器的客户端的信息，即由于代理服务器在请求路径中的介入而被修改或丢失的信息。
```

### 语法

```
Forwarded: by=<identifier>; for=<identifier>; host=<host>; proto=<http|https>
```

### 示例

```
Forwarded: for="_mdn"

# 大小写不敏感
Forwarded: For="[2001:db8:cafe::17]:4711"

# for proto by 之间可用分号分隔
Forwarded: for=192.0.2.60; proto=http; by=203.0.113.43

# 多值可用逗号分隔
Forwarded: for=192.0.2.43, for=198.51.100.17
```

## Keep-Alive

```
Keep-Alive 是一个通用消息头，允许消息发送者暗示连接的状态，还可以用来设置超时时长和最大请求数。
```

### 语法

```
Keep-Alive: parameters
```

### 示例

```
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Type: text/html; charset=utf-8
Date: Thu, 11 Aug 2016 15:23:13 GMT
Keep-Alive: timeout=5, max=1000
Last-Modified: Mon, 25 Jul 2016 04:32:39 GMT
Server: Apache

(body)
```

## Location

```
Location 首部指定的是需要将页面重新定向至的地址。一般在响应码为 3xx 的响应中才会有意义。
```

语法

```
Location: <url>
```

## Origin

```
请求标头 Origin 表示了请求的来源（协议、主机、端口）。
```

### 语法

```
Origin: null
Origin: <scheme>://<hostname>
Origin: <scheme>://<hostname>:<port>
```

### 示例

```
Origin: https://developer.mozilla.org
Origin: http://developer.mozilla.org:80
```

## Proxy-Authenticate

```
The HTTP Proxy-Authenticate 是一个响应首部，指定了获取 proxy server（代理服务器）上的资源访问权限而采用的身份验证方式。
```

### 语法

```
Proxy-Authenticate: <type> realm=<realm>
```

### 示例

```
Proxy-Authenticate: Basic

Proxy-Authenticate: Basic realm="Access to the internal site"
```

## Proxy-Authorization

```
Proxy-Authorization 是一个请求首部，其中包含了用户代理提供给代理服务器的用于身份验证的凭证。
```

### 语法

```
Proxy-Authorization: <type> <credentials>
```

### 示例

```
Proxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l
```

## Referer

```
Referer 请求头包含了当前请求页面的来源页面的地址，即表示当前页面是通过此来源页面里的链接进入的。服务端一般使用 Referer 请求头识别访问来源，可能会以此进行统计分析、日志记录以及缓存优化等。
```

### 语法

```
Referer: <url>
```

### 示例

```
Referer: https://developer.mozilla.org/en-US/docs/Web/JavaScript
```

## Referrer-Policy

```
Referrer-Policy 首部用来监管哪些访问来源信息——会在 Referer  中发送——应该被包含在生成的请求当中。
```

### 语法

```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```

## Set-Cookie

```
响应首部 Set-Cookie 被用来由服务器端向客户端发送 cookie。
```

### 语法

```
Set-Cookie: <cookie-name>=<cookie-value>
Set-Cookie: <cookie-name>=<cookie-value>; Expires=<date>
Set-Cookie: <cookie-name>=<cookie-value>; Max-Age=<non-zero-digit>
Set-Cookie: <cookie-name>=<cookie-value>; Domain=<domain-value>
Set-Cookie: <cookie-name>=<cookie-value>; Path=<path-value>
Set-Cookie: <cookie-name>=<cookie-value>; Secure
Set-Cookie: <cookie-name>=<cookie-value>; HttpOnly

Set-Cookie: <cookie-name>=<cookie-value>; SameSite=Strict
Set-Cookie: <cookie-name>=<cookie-value>; SameSite=Lax
```

### 示例

会话期 cookie

```
Set-Cookie: sessionid=38afes7a8; HttpOnly; Path=/
```

持久化cookie

```
Set-Cookie: id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure; HttpOnly
```

## User-Agent

```
User-Agent 首部包含了一个特征字符串，用来让网络协议的对端来识别发起请求的用户代理软件的应用类型、操作系统、软件开发商以及版本号。
```

### 语法

```
User-Agent: <product> / <product-version> <comment>
```

### 示例

```
Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0
```

## X-Content-Type-Options

```
X-Content-Type-Options HTTP 消息头相当于一个提示标志，被服务器用来提示客户端一定要遵循在 Content-Type 首部中对  MIME 类型 的设定，而不能对其进行修改。
```

### 语法

```
X-Content-Type-Options: nosniff
```

## X-Forwarded-For

```
X-Forwarded-For (XFF) 在客户端访问服务器的过程中如果需要经过 HTTP 代理或者负载均衡服务器，可以被用来获取最初发起请求的客户端的 IP 地址，这个消息首部成为事实上的标准。
```

### 语法

```
X-Forwarded-For: <client>, <proxy1>, <proxy2>
```

### 示例

```
X-Forwarded-For: 2001:db8:85a3:8d3:1319:8a2e:370:7348

X-Forwarded-For: 203.0.113.195

X-Forwarded-For: 203.0.113.195, 70.41.3.18, 150.172.238.178
```

# HTTP请求方法

```
GET
GET 方法请求一个指定资源的表示形式，使用 GET 的请求应该只被用于获取数据。
```

```
HEAD
HEAD 方法请求一个与 GET 请求的响应相同的响应，但没有响应体。
```

```
POST
POST 方法用于将实体提交到指定的资源，通常导致在服务器上的状态变化或副作用。
```

```
PUT
PUT 方法用请求有效载荷替换目标资源的所有当前表示。
```

```
DELETE
DELETE 方法删除指定的资源。
```

```
CONNECT
CONNECT 方法建立一个到由目标资源标识的服务器的隧道。
```

```
OPTIONS
OPTIONS 方法用于描述目标资源的通信选项。
```

```
TRACE
TRACE 方法沿着到目标资源的路径执行一个消息环回测试。
```

```
PATCH
PATCH 方法用于对资源应用部分修改。
```

# 状态码

## 1xx消息

### 100

```
Continue   继续，客户端应该继续请求
```

## 101

```
Switching Protocols	 切换协议。服务器根据客户端的请求切换协议。只能切换到更高级的协议，例如，切换到HTTP的新版本协议
```

## 102

```
Processing 该代码表示服务器已经收到并正在处理请求，但无响应可用
```

## 103

```
Early Hints 用来在最终的HTTP消息之前返回一些响应头
```

## 2xx成功

### 200

```
ok   请求成功
```

### 201

```
Created 服务器接受请求，而且有一个新的资源已经依据请求的需要而创建且其URI已经随Location头信息返回
```

### 202

```
Accepted 服务器已接受请求，但尚未处理。最终该请求可能会也可能不会被执行，并且可能在处理发生时被禁止。
```

### 203

```
Non-Authoritative Information 服务器是一个转换代理服务器
```

### 204

```
No Content 服务器成功处理了请求，没有返回任何内容
```

### 205

```
Reset Content 服务器成功处理了请求，但没有返回任何内容
```

### 206

```
Partial Content 服务器已经成功处理了部分GET请求。类似于FlashGet或者迅雷这类的HTTP下载工具都是使用此类响应实现断点续传或者将一个大文档分解为多个下载段同时下载
```

### 207

```
 Multi-Status 代表之后的消息体将是一个XML消息，并且可能依照之前子请求数量的不同，包含一系列独立的响应代码			
```

### 208

```
Already Reported DAV绑定的成员已经在（多状态）响应之前的部分被列举，且未被再次包含。
```

### 209

```
IM Used 服务器已经满足了对资源的请求，对实体请求的一个或多个实体操作的结果表示
```

## 3xx重定向

### 300

```
Multiple Choices 多种选择。请求的资源可包括多个位置，相应可返回一个资源特征与地址的列表用于用户终端（例如：浏览器）选择
```

### 301

```
Moved Permanently 永久移动。请求的资源已被永久的移动到新URI，返回信息会包括新的URI，浏览器会自动定向到新URI
```

### 302

```
Found  临时移动。与301类似。但资源只是临时被移动。客户端应继续使用原有URI
```

### 303

```
See Other 查看其它地址。与301类似。使用GET和POST请求查看 
```

### 304

```
Not Modified  未修改。所请求的资源未修改，服务器返回此状态码时，不会返回任何资源。客户端通常会缓存访问过的资源，通过提供一个头信息指出客户端希望只返回在指定日期之后修改的资源
```

### 305

```
Use Proxy 使用代理。所请求的资源必须通过代理访问
```

### 307

```
Temporary Redirect   临时重定向。与302类似。使用GET请求重定向
```

### 308

```
Permanent Redirect  请求和所有将来的请求应该使用另一个URI重复。 307和308重复302和301的行为，但不允许HTTP方法更改
```

## 4xx客户端错误

### 400

```
Bad Request  由于明显的客户端错误（例如，格式错误的请求语法，太大的大小，无效的请求消息或欺骗性路由请求），服务器不能或不会处理该请求。
```

### 401

```
Unauthorized 请求要求用户的身份认证 
```

### 402

```
Payment Required  保留，将来使用
```

### 403

```
Forbidden  服务器已经理解请求，但是拒绝执行它。
```

### 404

```
Not Found 服务器无法根据客户端的请求找到资源（网页）。通过此代码，网站设计人员可设置"您所请求的资源无法找到"的个性页面
```

### 405

```
Method Not Allowed 客户端请求中的方法被禁止
```

### 406

```
Not Acceptable  服务器无法根据客户端请求的内容特性完成请求
```

### 407

```
Proxy Authentication Required  请求要求代理的身份认证，与401类似，但请求者应当使用代理进行授权
```

### 408

```
Request Time-out  服务器等待客户端发送的请求时间过长，超时
```

### 409

```
Conflict 服务器完成客户端的 PUT 请求时可能返回此代码，服务器处理请求时发生了冲突
```

### 410

```
Gone  客户端请求的资源已经不存在。410不同于404，如果资源以前有现在被永久删除了可使用410代码，网站设计人员可通过301代码指定资源的新位置
```

### 411

```
Length Required  服务器无法处理客户端发送的不带Content-Length的请求信息
```

### 412

```
Precondition Failed 客户端请求信息的先决条件错误 
```

### 413

```
Request Entity Too Large 由于请求的实体过大，服务器无法处理，因此拒绝请求。为防止客户端的连续请求，服务器可能会关闭连接。如果只是服务器暂时无法处理，则会包含一个Retry-After的响应信息
```

### 414

```
Request-URI Too Large 请求的URI过长（URI通常为网址），服务器无法处理
```

### 415

```
Unsupported Media Type  服务器无法处理请求附带的媒体格式
```

### 416

```
Requested range not satisfiable 客户端请求的范围无效
```

### 417

```
Expectation Failed 服务器无法满足Expect的请求头信息
```

### 421

```
该请求针对的是无法产生响应的服务器（例如因为连接重用）。
```

## 5xx服务器错误

### 500

```
Internal Server Error 服务器内部错误，无法完成请求
```

### 501

```
Not Implemented        服务器不支持请求的功能，无法完成请求
```

### 502

```
Bad Gateway       作为网关或者代理工作的服务器尝试执行请求时，从远程服务器接收到了一个无效的响应
```

### 503

```
Service Unavailable      由于超载或系统维护，服务器暂时的无法处理客户端的请求。延时的长度可包含在服务器的Retry-After头信息中 
```

### 504

```
Gateway Time-out    充当网关或代理的服务器，未及时从远端服务器获取请求
```

### 505

```
HTTP Version not supported      服务器不支持请求的HTTP协议的版本，无法完成处理
```

### 506

```
Variant Also Negotiates 代表服务器存在内部配置错误
```

### 507

```
Insufficient Storage 服务器无法存储完成请求所必须的内容。这个状况被认为是临时的
```

### 508

```
Loop Detected 服务器在处理请求时陷入死循环 
```

### 510

```Not Extended
Not Extended              获取资源所需要的策略并没有被满足
```

### 511

```
Network Authentication Required 客户端需要进行身份验证才能获得网络访问权限，旨在限制用户群访问特定网络
```

# MIME

| `text`        | 表明文件是普通文本，理论上是人类可读                         | `text/plain`, `text/html`, `text/css, text/javascript`       |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `image`       | 表明是某种图像。不包括视频，但是动态图（比如动态gif）也使用image类型 | `image/gif`, `image/png`, `image/jpeg`, `image/bmp`, `image/webp`, `image/x-icon`, `image/vnd.microsoft.icon` |
| `audio`       | 表明是某种音频文件                                           | `audio/midi`, `audio/mpeg, audio/webm, audio/ogg, audio/wav` |
| `video`       | 表明是某种视频文件                                           | `video/webm`, `video/ogg`                                    |
| `application` | 表明是某种二进制数据                                         | `application/octet-stream`, `application/pkcs12`, `application/vnd.mspowerpoint`, `application/xhtml+xml`, `application/xml`, `application/pdf` |

| 媒体类型                                                     | 文件扩展名             | 说明                                                         |
| :----------------------------------------------------------- | :--------------------- | :----------------------------------------------------------- |
| **application/msword**                                       | doc                    | 微软 Office Word 格式（Microsoft Word 97 - 2004 document）   |
| **application/vnd.openxmlformats-officedocument.wordprocessingml.document** | docx                   | 微软 Office Word 文档格式                                    |
| **application/vnd.ms-excel**                                 | xls                    | 微软 Office Excel 格式（Microsoft Excel 97 - 2004 Workbook   |
| **application/vnd.openxmlformats-officedocument.spreadsheetml.sheet** | xlsx                   | 微软 Office Excel 文档格式                                   |
| **application/vnd.ms-powerpoint**                            | ppt                    | 微软 Office PowerPoint 格式（Microsoft PowerPoint 97 - 2003 演示文稿） |
| **application/vnd.openxmlformats-officedocument.presentationml.presentation** | pptx                   | 微软 Office PowerPoint 文稿格式                              |
| **application/x-gzip**                                       | gz, gzip               | GZ 压缩文件格式                                              |
| **application/zip**                                          | zip, 7zip              | ZIP 压缩文件格式                                             |
| **application/rar**                                          | rar                    | RAR 压缩文件格式                                             |
| **application/x-tar**                                        | tar, tgz               | TAR 压缩文件格式                                             |
| **application/pdf**                                          | pdf                    | PDF 是 Portable Document Format 的简称，即便携式文档格式     |
| **application/rtf**                                          | rtf                    | RTF 是指 Rich Text Format，即通常所说的富文本格式            |
| **image/gif**                                                | gif                    | GIF 图像格式                                                 |
| **image/jpeg**                                               | jpg, jpeg              | JPG(JPEG) 图像格式                                           |
| **image/jp2**                                                | jpg2                   | JPG2 图像格式                                                |
| **image/png**                                                | png                    | PNG 图像格式                                                 |
| **image/tiff**                                               | tif, tiff              | TIF(TIFF) 图像格式                                           |
| **image/bmp**                                                | bmp                    | BMP 图像格式（位图格式）                                     |
| **image/svg+xml**                                            | svg, svgz              | SVG 图像格式                                                 |
| **image/webp**                                               | webp                   | WebP 图像格式                                                |
| **image/x-icon**                                             | ico                    | ico 图像格式，通常用于浏览器 Favicon 图标                    |
| **application/kswps**                                        | wps                    | 金山 Office 文字排版文件格式                                 |
| **application/kset**                                         | et                     | 金山 Office 表格文件格式                                     |
| **application/ksdps**                                        | dps                    | 金山 Office 演示文稿格式                                     |
| **application/x-photoshop**                                  | psd                    | Photoshop 源文件格式                                         |
| **application/x-coreldraw**                                  | cdr                    | Coreldraw 源文件格式                                         |
| **application/x-shockwave-flash**                            | swf                    | Adobe Flash 源文件格式                                       |
| **text/plain**                                               | txt                    | 普通文本格式                                                 |
| **application/x-javascript**                                 | js                     | Javascript 文件类型                                          |
| **text/javascript**                                          | js                     | 表示 Javascript 脚本文件                                     |
| **text/css**                                                 | css                    | 表示 CSS 样式表                                              |
| **text/html**                                                | htm, html, shtml       | HTML 文件格式                                                |
| **application/xhtml+xml**                                    | xht, xhtml             | XHTML 文件格式                                               |
| **text/xml**                                                 | xml                    | XML 文件格式                                                 |
| **text/x-vcard**                                             | vcf                    | VCF 文件格式                                                 |
| **application/x-httpd-php**                                  | php, php3, php4, phtml | PHP 文件格式                                                 |
| **application/java-archive**                                 | jar                    | Java 归档文件格式                                            |
| **application/vnd.android.package-archive**                  | apk                    | Android 平台包文件格式                                       |
| **application/octet-stream**                                 | exe                    | Windows 系统可执行文件格式                                   |
| **application/x-x509-user-cert**                             | crt, pem               | PEM 文件格式                                                 |
| **audio/mpeg**                                               | mp3                    | mpeg 音频格式                                                |
| **audio/midi**                                               | mid, midi              | mid 音频格式                                                 |
| **audio/x-wav**                                              | wav                    | wav 音频格式                                                 |
| **audio/x-mpegurl**                                          | m3u                    | m3u 音频格式                                                 |
| **audio/x-m4a**                                              | m4a                    | m4a 音频格式                                                 |
| **audio/ogg**                                                | ogg                    | ogg 音频格式                                                 |
| **audio/x-realaudio**                                        | ra                     | Real Audio 音频格式                                          |
| **video/mp4**                                                | mp4                    | mp4 视频格式                                                 |
| **video/mpeg**                                               | mpg, mpe, mpeg         | mpeg 视频格式                                                |
| **video/quicktime**                                          | qt, mov                | QuickTime 视频格式                                           |
| **video/x-m4v**                                              | m4v                    | m4v 视频格式                                                 |
| **video/x-ms-wmv**                                           | wmv                    | wmv 视频格式（Windows 操作系统上的一种视频格式）             |
| **video/x-msvideo**                                          | avi                    | avi 视频格式                                                 |
| **video/webm**                                               | webm                   | webm 视频格式                                                |
| **video/x-flv**                                              | flv                    | 一种基于 flash 技术的视频格式                                |