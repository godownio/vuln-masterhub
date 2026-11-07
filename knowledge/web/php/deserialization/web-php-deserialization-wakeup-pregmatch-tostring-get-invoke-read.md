---
id: web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read
title: PHP POP 链：__wakeup 的 preg_match 把对象转字符串，经 __toString→__get→is_callable→__invoke 读取任意文件
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-wakeup-tostring-get-invoke-file-read
aliases:
- __wakeup 触发 __toString
- preg_match 对象转换
- __get 调用 __invoke
- is_callable 魔术链
- 数字古墓
- highlight_file 文件读取
tags:
- php
- deserialization
- pop-chain
- magic-methods
- wakeup
- tostring
- get
- invoke
- file-read
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:16:05+08:00'
  notes: 已对照原文源码核对：GateSentinel.__wakeup 的 preg_match 触发 __toString、tool[blade]->object 触发 Keystone.__get、center 白名单加 is_callable 触发 RitualEngine.__invoke、callback 数组经 view->run 映射调用、run 的正则/realpath/highlight_file 与原文一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当 `__wakeup()` 对属性执行 `preg_match()`、`__toString()` 访问对象的不存在属性、`__get()` 对属性做 `is_callable()` 并调用时，可以把对象属性按 `GateSentinel.__wakeup → GateSentinel.__toString → Keystone.__get → RitualEngine.__invoke → RitualEngine.run` 串成 POP 链，最终用 `highlight_file()` 读取任意允许后缀的本地文件；把文件名藏在深层属性中，还能绕过 `__wakeup()` 对 `..|flag|etc` 的字符串过滤。

## 原理

- 起点：`GateSentinel::__wakeup()` 执行
  ```php
  if (preg_match("/\.\.|flag|etc/i", $this->object)) {
      $this->object = "index.html";
  }
  ```
  `preg_match()` 的第一个参数需要字符串；如果 `$this->object` 是对象，PHP 会调用该对象的 `__toString()` 做类型转换。于是“过滤”本身成了触发点。
- 第二跳：`GateSentinel::__toString()` 执行 `$this->tool['blade']->object;`。`tool['blade']` 指向 `Keystone` 对象，而 `Keystone` 没有 `object` 属性，访问未定义属性触发 `Keystone::__get('object')`。
- 第三跳：`Keystone::__get()` 取 `$this->center`，先检查它是对象且类名在 `['RitualEngine','GateSentinel','RuneScribe','Chronicler','Keystone']` 白名单中，再执行 `is_callable($processor)`；`RitualEngine` 实现了 `__invoke()`，因此 `is_callable()` 为真，`$processor()` 触发 `RitualEngine::__invoke()`。
- 第四跳：`RitualEngine::__invoke()` 对 `$this->callback` 做 `unserialize()`，要求结果是长度为 2 的数组 `[$obj, $method]`，且 `$obj instanceof self`、`$method` 是字符串；随后通过 `$map = ['view' => 'run']` 把 `view` 映射为 `run`，调用 `$obj->run()`。
- 终点：`RitualEngine::run()` 取 `$name = $file ?: $this->target`；用 `/^[A-Za-z0-9_-]+\.txt$/` 限制文件名，拼接 `__DIR__` 后 `realpath()`，确认仍在当前目录下，且 `is_file()`、`filesize() < 2048`，最后 `highlight_file($real)` 输出文件内容。
- 绕过点：最外层 `GateSentinel->object` 放的是内层 `GateSentinel` 对象，不是文件名；`preg_match()` 的过滤发生在对象转字符串阶段，真正要读的文件名在 `RitualEngine->target` 里，不在被过滤的属性上。文件名 `W3f82KD9.txt` 也不含 `..`、`flag`、`etc`，且符合 `run()` 的正则。
- 根因是“魔术方法自动触发 + 属性访问/可调用判断把对象图串起来”，攻击者只需控制反序列化后的属性指向，不需要目标显式调用业务方法。

## 触发条件

- 存在 `unserialize($_POST['data'])` 等用户可控入口，且允许实例化目标类（本题 `allowed_classes` 包含这些类）。
- 类中同时存在可串联的魔术方法：`__wakeup`/`__destruct`（起点）、`__toString`（字符串化）、`__get`（未定义属性）、`__invoke`（可调用对象）。
- 魔术方法内部有属性访问、`is_callable()`、动态方法调用等可被对象图控制的逻辑。
- 终点存在文件读取 sink（`highlight_file`、`file_get_contents`、`include`）且路径限制可被满足（后缀白名单、目录限制）。
- 入口过滤只检查外层属性，未检查深层属性或对象类型。

## 利用步骤

1. 审计源码，列出所有魔术方法及其属性访问；从 `__wakeup`/`__destruct` 开始画调用图。
2. 找到 `__wakeup` 中对属性做字符串函数（`preg_match`、`strlen`、`strpos`）的位置，确认传入对象可触发 `__toString`。
3. 找 `__toString` 中访问对象属性的位置，指向一个没有该属性的类，触发 `__get`。
4. 找 `__get` 中 `is_callable()` + `$processor()` 的位置，放入实现了 `__invoke` 的对象。
5. 构造 `__invoke` 需要的 callback 数组（通常是 `[另一个同类对象, '方法名']`），让映射走到文件读取方法。
6. 按类定义在本地生成序列化串，提交到入口；观察文件内容回显。

## PoC

按目标类定义生成 payload：

```php
class RitualEngine {
    protected $settings;
    public $target;
    public $callback;
}
class GateSentinel {
    public $object;
    public $tool;
}
class Keystone {
    public $center;
}

$reader = new RitualEngine();
$reader->target = 'W3f82KD9.txt';          // 目标文件名，需符合 run() 的正则
$action = serialize([$reader, 'view']);     // __invoke 中反序列化的 callback

$invoker = new RitualEngine();
$invoker->callback = $action;               // 触发 run()

$key = new Keystone();
$key->center = $invoker;                    // __get 中 is_callable -> __invoke

$inner = new GateSentinel();
$inner->tool = ['blade' => $key];           // __toString 访问 ->object -> __get

$outer = new GateSentinel();
$outer->object = $inner;                    // __wakeup 的 preg_match 触发 __toString

echo serialize($outer);
```

提交：

```http
POST /mechanism_chamber.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

data=<上述序列化串 URL 编码>
```

## 变体与关联

- **起点变体**：`__destruct`、`__wakeup`、`__toString`、`__invoke` 都可作为链头；`__wakeup` 中对对象做字符串函数是本题最关键的触发技巧。
- **中间跳变体**：`__get`/`__call`/`__set`/`__isset` 都可能由属性访问或方法调用触发；`is_callable()` 对实现 `__invoke` 的对象返回真。
- **终点变体**：`highlight_file`、`file_get_contents`、`include`、`eval`、`system`；本题是受限目录 + 后缀白名单的“受限文件读取”，可通过其它链跳到命令执行。
- **过滤绕过变体**：把敏感文件名放在深层属性、用对象代替字符串、用 `__toString` 返回无害值、利用 `realpath` 与白名单后缀。
- **关联**：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（`__destruct` 起步、`__toString/__get/__call` 到 eval 的通用 POP 链）；[[web-php-deserialization-str-replace-length-shortening-escape]]（本题第一关的字符逃逸）。
- **边界**：若 `allowed_classes` 只允许无害类、`__wakeup` 直接校验属性类型、`run()` 使用固定文件名白名单或禁用 `highlight_file`，本链失效。

## 检测与防御

- **检测**：请求体出现 `O:`、`a:2:` 等序列化结构，类名与业务无关（`GateSentinel`、`Keystone`、`RitualEngine`）；属性中出现 `callback`、`center`、`tool`、`target` 等链式字段；反序列化后出现 `highlight_file`/文件读取。
- **防御**：禁止对用户输入 `unserialize`，改用 JSON/显式字段；必须反序列化时使用 `allowed_classes` 白名单并校验属性类型；删除魔术方法中的动态调用与文件读取 sink。
- **加固**：文件读取使用固定白名单与 `realpath` + 前缀校验；禁用 `highlight_file` 等调试函数；Web 进程降权并限制敏感文件权限。
