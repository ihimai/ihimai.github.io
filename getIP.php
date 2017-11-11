<?php
/*ansic码-Url码表： http://www.w3school.com.cn/tags/html_ref_urlencode.html

-----------------------------------------------------------------------------------------------------------------

1、验证过滤用户的输入

         即使是最普通的字母数字输入也可能是危险的，列举几个容易引起安全问题的字符：

         ! $ ^ & * ( ) ~ [ ] \ | { } ' " ; < > ? - `

         在数据库中可能有特殊意义的字符：

         ' " ; \

         还有一些非打印字符：

         字符\x00或者说ASCII 0，NULL或FALSE

         字符\x10和\x13，或者说ASCII 10和13，\n \r

         字符\x1a或者说ASCII 26，表示文件的结束

         输入错误的参数类型，也可能导致程序出现意想不到的错误。

         输入过多的参数值，可能导致溢出等错误。

2、对于文件的路径与名称的过滤

         文件名中不能包含二进制数据，否则可能引起问题。

         一些系统允许Unicode多字节编码的文件名，但是尽量避免，应当使用ASCII的字符。

         虽然Unix系统几乎可以在文件名设定中使用任何符号，但是应当尽量使用 - 和 _ 避免使用其他字符。

         同时需要限定文件名的长度。

3、防止SQL注入

         检查用户输入的类型，当用户输入的为数字时可以使用如下方式：

         使用is_int()函数（或is_integer()或is_long()函数）

         使用gettype()函数

         使用intval()函数

         使用settype()函数

         检查用户输入字符串的长度使用strlen()函数。

         检查日期或时间是否是有效的，可以使用strtotime()函数

4、防止XSS攻击

         xss攻击一个常用的方法就是注入HTML元素执行js脚本，php中已经内置了一些防御的函数（如htmlentities或者htmlspecialchars）

5、过滤用户提交的URL

         如果允许用户输入一个URL用来调用一个图片或者链接，你需要保证他不传入javascript:或者vbscript:或data:等非http协议。

         可以使用php的内置函数parse_url()函数来分割URL，然后做判断。

6、防止远程执行--下表列出了跟Shell相关的一些字符：

         远程执行通常是使用了php代码执行如eval()函数，或者是调用了命令执行如exec()，passthru()，proc_open()，shell_exec()，system()或popen()。

         注入php代码：php为开发者提供了非常多的方法可以来调用允许php脚本，我们就需要注意对用户可控的数据进行过滤。

7、Shell命令执行

         PHP提供了一些可以直接执行系统命令的函数，如exec()函数或者 `（反引号）。

         PHP的安全模式会提供一些保护，但是也有一些方式可以绕过安全模式：

         1、上传一个Perl脚本，或者Python或Ruby等，服务器支持的环境，来执行其他语言的脚本可绕过PHP的安全模式。

         2、利用系统的缓冲溢出漏洞，绕过安全模式。

                   跟Shell相关的一些字符：

                   名称        字符        ASCII       16进制 URL编码         HTML编码

                   换行                           10             \x0a        %0a                   &#10

                   感叹号   !                33             \x21         %21                  &#33

                   双引号   "               34             \x22         %22                  &#34或&quot

                   美元符号 $             36             \x24         %24                  &#36

                   连接符   &              38             \x26         %26                  &#38或&#amp

                   单引号   '                39             \x27         %27                  &#39

                   左括号   (                40             \x28         %28                  &#40

                   右括号   )                41             \x29         %29                  &#41

                   星号        *               42             \x2a        %2a                   &#42

                   连字符号 -              45             \x2d         %2d                  &#45

                   分号        ;                59             \x3b        %3b                   &#59

                   左尖括号 <             60             \x3c         %3c                  &#60

                   右尖括号 >             62             \x3e         %3e                  &#62

                   问号        ?               63             \x3f         %3f                    &#63

                   左方括号 [              91             \x5b         %5b                  &#91

                   反斜线   \                92             \x5c         %5c                  &#92

                   右方括号 ]              93             \x5d         %5d                  &#93

                   插入符   ^               94             \x5e         %5e                  &#94

                   反引号   `                96             \x60         %60                  &#96

                   左花括号 {              123          \x7b         %7b                  &#123

                   管道符   |               124          \x7c         %7c                  &#124

                   右花括号 }              125          \x7d         %7d                  &#125

                   波浪号   ~               126          \x7e         %7e                  &#126

-----------------------------------------------------------------------------------------------------------------

安全过滤函数代码*/

 

/**

* 安全过滤输入[jb]

*/

function check_str($string, $isurl = false)

{

         $string = preg_replace('/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]/','',$string); //去掉控制字符

         $string = str_replace(array("\0","%00","\r"),'',$string); //\0表示ASCII 0x00的字符，通常作为字符串结束标志；这三个都是可能有害字符

         empty($isurl) && $string = preg_replace("/&(?!(#[0-9]+|[a-z]+);)/si",'&',$string); //HTML里面可以用&#xxx;来对一些字符进行编码，比如 (空格), ? Unicode字符等，A(?!B) 表示的是A后面不是B,所以作者想保留 ?类似的 HTML编码字符，去掉其他的问题字符

         $string = str_replace(array("%3C",'<'),'<',$string); //ascii的'<'转成'<';

         $string = str_replace(array("%3E",'>'),'>',$string);

         $string = str_replace(array('"',"'","\t",' '),array('“','‘',' ',' '),$string);

         return trim($string);

}

 

/**

* 安全过滤类-过滤javascript,css,iframes,object等不安全参数 过滤级别高

* @param  string $value 需要过滤的值

* @return string

*/

function fliter_script($value) {

         $value = preg_replace("/(javascript:)?on(click|load|key|mouse|error|abort|move|unload|change|dblclick|move|reset|resize|submit)/i","&111n\\2",$value);

         $value = preg_replace("/(.*?)<\/script>/si","",$value);

         $value = preg_replace("/(.*?)<\/iframe>/si","",$value);

         $value = preg_replace ("//iesU", '', $value);

         return $value;

}

 

/**

* 安全过滤类-过滤HTML标签

* @param  string $value 需要过滤的值

* @return string

*/

function fliter_html($value) {

         if (function_exists('htmlspecialchars')) return htmlspecialchars($value);

         return str_replace(array("&", '"', "'", "<", ">"), array("&", "\"", "'", "<", ">"), $value);

}

 

/**

* 安全过滤类-对进入的数据加下划线 防止SQL注入

* @param  string $value 需要过滤的值

* @return string

*/

function fliter_sql($value) {

         $sql = array("select", 'insert', "update", "delete", "\'", "\/\*","\.\.\/", "\.\/", "union", "into", "load_file", "outfile");

         $sql_re = array("","","","","","","","","","","","");

         return str_replace($sql, $sql_re, $value);

}

 

/**

* 安全过滤类-通用数据过滤

* @param string $value 需要过滤的变量

* @return string|array

*/

function fliter_escape($value) {

         if (is_array($value)) {

                   foreach ($value as $k => $v) {

                            $value[$k] = self::fliter_str($v);

                   }

         } else {

                   $value = self::fliter_str($value);

         }

         return $value;

}

 

/**

* 安全过滤类-字符串过滤 过滤特殊有危害字符

* @param  string $value 需要过滤的值

* @return string

*/

function fliter_str($value) {

         $badstr = array("\0", "%00", "\r", '&', ' ', '"', "'", "<", ">", "   ", "%3C", "%3E");

         $newstr = array('', '', '', '&', ' ', '"', ''', "<", ">", "   ", "<", ">");

         $value  = str_replace($badstr, $newstr, $value);

         $value  = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $value);

         return $value;

}

 

/**

* 私有路劲安全转化

* @param string $fileName

* @return string

*/

function filter_dir($fileName) {

         $tmpname = strtolower($fileName);

         $temp = array(':/',"\0", "..");

         if (str_replace($temp, '', $tmpname) !== $tmpname) {

                   return false;

         }

         return $fileName;

}

 

/**

* 过滤目录

* @param string $path

* @return array

*/

public function filter_path($path) {

         $path = str_replace(array("'",'#','=','`','$','%','&',';'), '', $path);

         return rtrim(preg_replace('/(\/){2,}|(\\\){1,}/', '/', $path), '/');

}

 

/**

* 过滤PHP标签

* @param string $string

* @return string

*/

public function filter_phptag($string) {

         return str_replace(array(''), array('<?', '?>'), $string);

}

 

/**

* 安全过滤类-返回函数

* @param  string $value 需要过滤的值

* @return string

*/

public function str_out($value) {

         $badstr = array("<", ">", "%3C", "%3E");

         $newstr = array("<", ">", "<", ">");

         $value  = str_replace($newstr, $badstr, $value);

         return stripslashes($value); //下划线

}