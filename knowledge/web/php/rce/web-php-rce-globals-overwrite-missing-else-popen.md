---
id: web-php-rce-globals-overwrite-missing-else-popen
title: PHP 全局变量覆盖 + if/elseif 缺 else：请求参数直达 popen 的命令执行审计技巧
type: scenario
domain: web
path: web/php/rce
technique: php-globals-overwrite-missing-else-popen
aliases:
- GLOBALS 覆盖
- 全局变量注入 RCE
- 缺 else 分支
- popen 命令执行
- 变量未赋值绕过
tags:
- php
- rce
- popen
- globals
- variable-overwrite
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T17:06:56+08:00'
  notes: 已对照原文与图15-23逐张核对：cmd.php include ../include/JSON.php、foreach( as $k=>$v) $GLOBALS[$k]=$v(图17)、$ip/$port/exec、if($type==1)/else if($type==2)缺else、popen($cmd,"r")(图16/18)、调试中$cmd=whoami未被覆盖(图19-21)、fgets回显laptop-bfit5lp4\asus(图22)、浏览器/index.php?cmd=whoami成功(图23)均一致。未验证点：PoC未复跑。无sources/文章ID/长段摘录，path web/php/rce合法；dedup候选($$key覆盖/eval超全局)非同链；dup-scan早于建卡无pair。
---

## 一句话结论

审计 PHP 代码时，若公共文件把请求参数逐个写入 `$GLOBALS`（如 `foreach($_REQUEST as $k=>$v){ $GLOBALS[$k]=$v; }`），随后业务代码用 `if($type==1)... else if($type==2)...` 给 `$cmd` 赋固定命令、再 `popen($cmd,"r")` 执行，攻击者只要不传 `type` 让两个分支都不命中，`$cmd` 就保持为请求参数 `?cmd=<任意命令>`，从而用 `?cmd=whoami` 直接命令执行——开发者以为 `$cmd` 只会是两个固定值，忽略了“变量未赋值时保留外部全局值”和“缺 else 分支”的组合。

## 原理

- **全局变量覆盖**：`foreach ($_REQUEST as $k => $v) { $GLOBALS[$k] = $v; }` 会把每个请求参数注册为同名全局变量；之后函数/脚本里任何未初始化的 `$cmd`、`$ip`、`$type` 都可能直接取到请求值。这等价于打开了 register_globals。
- **缺 else 分支**：代码 `if ($type == 1) { $cmd = "ping ..."; } else if ($type == 2) { $cmd = "vmstat ..."; }` 没有最后的 `else`，所以 `$type` 不是 1/2（或不传）时，`$cmd` 不会被重新赋值。
- **变量保留**：由于 `$cmd` 已被 `$GLOBALS` 覆盖为请求参数，缺 else 时它保持 `whoami` 等攻击者值；`popen($cmd, "r")` 把这个值交给 shell 执行，输出通过 `fgets`/`echo` 回显。
- **为什么开发者没发现**：代码里 `popen` 看起来只可能执行两个固定命令；`$type` 被假设“总会被赋值”，`$cmd` 被假设“只由上面分支赋值”。全局覆盖 + 分支覆盖不全打破了这两个假设。
- **同类模式**：`extract($_REQUEST)`、`parse_str` 到当前作用域、`$$var` 动态变量等也会造成变量注入；审计时要追踪“用户可控的全局变量”到 sink 的路径。

## 触发条件

- 应用存在请求参数到 `$GLOBALS`（或 `extract`/`parse_str`）的批量覆盖。
- 后续有基于未初始化变量的分支赋值，且分支不完整（缺 else/默认值）。
- 该变量最终进入 `popen`/`system`/`exec` 等命令执行 sink。
- 攻击者可发送任意请求参数（GET/POST 均可）。

## 利用步骤

1. 在公共文件/入口中搜索 `$GLOBALS`、`extract(`、`parse_str(`、`foreach($_REQUEST` 等批量覆盖写法。
2. 找到后续使用但未初始化的变量（如 `$cmd`、`$type`、`$command`），检查分支赋值是否完整。
3. 构造请求：不传或传非 1/2 的 `type`，让分支跳过；同时传 `cmd=<命令>`。
4. 观察 `popen` 执行的输出是否回显；若命令无回显，改用带外/写文件命令。
5. 结合 `$ip`/`$port` 等其它被覆盖的全局变量，可影响前置 `exec` 命令的参数，进一步扩大利用面。

## PoC

```http
GET /index.php?cmd=whoami HTTP/1.1
Host: target
```

```php
// 漏洞代码形态（简化）
foreach ($_REQUEST as $k => $v) { $GLOBALS[$k] = $v; }   // 请求参数变全局
$ip = $_SERVER['REMOTE_ADDR'];
exec("sh test.sh $ip ...");                               // 前置命令
if ($type == 1)      { $cmd = "ping 8.8.8.8"; }
else if ($type == 2) { $cmd = "vmstat -w 1"; }
// 没有 else：$type 未传 -> $cmd 保持 $_REQUEST['cmd']
$fp = popen($cmd, "r");
while ($line = fgets($fp, 2048)) { echo $line; }
```

```text
预期输出：whoami 的结果（如 laptop-xxxx\asus）
```

## 变体与关联

- `extract($_GET)`/`parse_str($str)` 到当前作用域同样可覆盖 `$cmd`；`$$name` 动态变量可定向覆盖。
- 分支完整但默认值使用了可覆盖变量（如 `else { $cmd = $default_cmd; }` 且 `$default_cmd` 可控）也可利用。
- 关联：[[web-php-rce-no-param-get-defined-vars]]（无参数时用 `get_defined_vars` 取变量）、[[web-php-rce-eval-var-dump-superglobal-variable-function]]（超全局变量进入 eval）、[[web-php-deserialization-extract-overwrite-gate-undefined-global-null-compare]]（extract 覆盖与未定义全局变量判断）。

## 检测与防御

- **修复**：禁止 `$GLOBALS`/`extract` 批量导入请求参数；所有命令变量显式初始化，分支补全 `else` 默认拒绝；命令使用白名单/参数化（`escapeshellarg` 不够，优先白名单）。
- **检测**：请求中出现与业务无关的参数名（`cmd`、`command`、`type` 等）；`popen`/`system` 执行非预期命令；页面回显命令输出。
- **加固**：生产关闭详细报错；PHP 以低权限运行；WAF 对 `?cmd=` 等参数名与命令关键字告警（仅缓解）。
