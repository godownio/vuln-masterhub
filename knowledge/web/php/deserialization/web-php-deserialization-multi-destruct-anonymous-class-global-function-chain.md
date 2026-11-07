---
id: web-php-deserialization-multi-destruct-anonymous-class-global-function-chain
title: PHP 多对象析构顺序链：new 匿名类 → 注册全局函数 → 调用 include 读文件或 php://filter RCE
type: scenario
domain: web
path: web/php/deserialization
technique: php-multi-destruct-anonymous-class-global-function-chain
aliases:
- 多对象析构链
- 匿名类反序列化
- 全局函数注册链
- class@anonymous 利用
- 析构顺序利用
tags:
- php
- deserialization
- destruct
- anonymous-class
- globals
- include
- filter-chain
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:45:20+08:00'
  notes: '已对照原文核对：test::__destruct 的 key=class/func 分派、匿名类名 class@anonymous\0/var/www/html/index.php(1) : eval()''d code:1$0（长度 62）、A→B→C 三对象析构顺序、include($GLOBALS[''file'']) 与 php://filter 链均与原文及代码一致；09.png 显示 flag 预览成功。未验证点：PoC 未在本机复跑；原文为 CTF 题，无组件版本；frontmatter 无 sources/source_url。'
---

## 一句话结论

当 `unserialize` 的类把“动态实例化 / 动态函数调用”放在 `__destruct` 里，并用 `key`、`f` 等属性做分派时，攻击者可以提交一个有序对象数组：第一个对象触发 `new` 创建内部匿名类并写入 `$GLOBALS['file']`，第二个对象调用匿名类方法注册一个全局函数，第三个对象调用该全局函数执行 `include($GLOBALS['file'])`，从而读取任意文件，或配合 `php://filter` 过滤器链升级为无文件 RCE。

## 原理

- **析构顺序可控**：反序列化一个对象数组时，数组元素按顺序销毁（本题 i0→i1→i2），每个对象的 `__destruct` 依次执行，形成“三步走”的执行计划。
- **动态分派原语**：`test::__destruct()` 读取 `$this->key`：`key=='class'` 时执行 `new $func()`，`key=='func'` 时执行 `$func()`。`$func` 来自 `$this->f`，完全由攻击者控制。
- **匿名类与全局状态**：`test::__construct()` 创建一个匿名类实例并赋给 `$this->readflag`；匿名类构造函数把 `$_GET['file']` 写入 `$GLOBALS['file']`，其 `readflag()` 方法定义全局函数 `readflag(){ include($GLOBALS['file']); }`。
- **三步链**：
  1. `key=class, f="test"` → `new test()`，触发构造函数，匿名类就位，`$GLOBALS['file']` 被设置为攻击者可控路径。
  2. `key=func, f=[匿名类名, "readflag"]` → 调用匿名类的 `readflag()`，注册全局函数 `readflag`。
  3. `key=func, f="readflag"` → 调用全局函数，执行 `include($GLOBALS['file'])`。
- **匿名类名可预测**：PHP 匿名类名形如 `class@anonymous\0<file>(<line>) : eval()'d code:<n>$0`；本题代码经 `eval()` 执行，名称为 `class@anonymous\0/var/www/html/index.php(1) : eval()'d code:1$0`，长度 62，可直接写入序列化字符串。
- **`__wakeup` 不阻断**：`test::__wakeup()` 只是把 `f` 数组里的字符串 `strval`、对象 `clone`，不改变 `key`/`f` 的分派语义；匿名类的 `__wakeup()` 仅调用 `phpinfo()`。
- **危害升级**：`include` 可控路径可直接包含上传的 SVG/图片（非预期），也可用 `php://filter/convert.iconv.../resource=/etc/passwd` 读文件；若配合 PHP Filter Chain 生成任意字节（预先存在同类技术），可进一步执行任意 PHP 代码。

## 触发条件

- 存在 `unserialize` 入口，且传入数据可控（本题 `$_GET['land']`）。
- 可反序列化的类在 `__destruct`/`__wakeup` 中执行 `new $var`、`$var()`、`call_user_func` 等动态调用。
- 存在把用户输入写入 `$GLOBALS`、静态属性或全局函数的路径。
- `include`/`require` 的路径可由全局变量或对象属性控制，且未限制 `php://` 等封装协议。
- 攻击者能预测匿名类名（文件路径、行号、eval 上下文）或可枚举。

## 利用步骤

1. 审计目标类：找 `__destruct`/`__wakeup` 中的动态 `new`/函数调用、`$GLOBALS` 写入、`include` sink。
2. 确认析构顺序：构造对象数组，按希望执行的顺序排列 A、B、C。
3. 计算匿名类名：从源码/报错/`phpinfo()` 获取文件路径与行号，拼成 `class@anonymous\0<path>(<line>) : eval()'d code:<n>$0`。
4. 构造 A：`key='class'`、`f='test'`，触发 `new test()` 与匿名类构造函数，设置 `$GLOBALS['file']`。
5. 构造 B：`key='func'`、`f=[匿名类名, 'readflag']`，调用匿名类方法注册全局函数。
6. 构造 C：`key='func'`、`f='readflag'`，调用全局函数执行 `include($GLOBALS['file'])`。
7. 通过 `$_GET['file']` 指定目标路径：可包含上传的 SVG/图片，或用 `php://filter` 链读取源码/执行代码。
8. 若目标无 `open_basedir`，可直接包含上传文件；否则用 filter chain 生成 payload。

## PoC

```php
<?php
class test {
    public $readflag;
    public $f;
    public $key;
}

$anon = "class@anonymous\0/var/www/html/index.php(1) : eval()'d code:1\$0";

$a = new test();
$a->f = 'test';
$a->key = 'class'; // 先 new，设置 $GLOBALS['file']

$b = new test();
$b->f = [$anon, 'readflag'];
$b->key = 'func'; // 注册全局函数 readflag

$c = new test();
$c->f = 'readflag';
$c->key = 'func';  // 调用 readflag() -> include($GLOBALS['file'])

echo urlencode(serialize([$a, $b, $c]));
```

目标端关键逻辑：

```php
public function __destruct(){
    $func=$this->f;
    $GLOBALS['filename']=$this->readflag;
    if($this->key=='class'){ new $func(); }
    else if($this->key=='func'){ $func(); }
    else{ echo base64_encode(file_get_contents('index.php')); }
}
```

原文通过 `land` 参数传入上述序列化数组，并用 `file=php://filter/...` 或上传 SVG 路径完成包含；未在本机复跑。

## 变体与关联

- **分派变体**：`new $class`、`$func()`、`call_user_func`、`array_map`、反射调用；属性名/值可被 `__wakeup` 改写但仍可控。
- **匿名类名变体**：普通文件中的匿名类名包含文件路径与行号；可通过报错、`phpinfo()`、源码泄漏或爆破获得。
- **include 变体**：直接包含上传文件（无 `open_basedir`）、`php://filter` 读源码、Filter Chain 生成任意代码。
- **关联**：[[web-php-file-inclusion-filter-chain-fileless-rce]]（filter chain 生成字节）、[[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]（反序列化过滤器绕过）；本卡重点是“多对象析构顺序 + 匿名类 + 全局函数注册”的组合。

## 检测与防御

- 禁止对不可信输入调用 `unserialize`；必须使用时用 `allowed_classes` 白名单并禁用匿名类/动态调用。
- 审计 `__destruct`/`__wakeup` 中的 `new $var`、`$var()`、`include`/`require` 与 `$GLOBALS` 写入，移除动态分派。
- `include` 路径使用白名单与 `realpath`，禁用 `php://`、`data://` 等封装协议；设置 `open_basedir`。
- 检测：序列化数据中出现 `class@anonymous`、数组嵌套对象、`key=class/func` 分派属性；请求参数含 `php://filter`；include 路径指向上传目录。
