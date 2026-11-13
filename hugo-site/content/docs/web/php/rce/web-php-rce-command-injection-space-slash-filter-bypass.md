---
id: web-php-rce-command-injection-space-slash-filter-bypass
title: 命令注入空格与斜杠过滤绕过：${IFS}/重定向/花括号/$'\x20' 替代空格，${HOME:0:1}/tr 重建斜杠
type: scenario
domain: web
path: web/php/rce
technique: command-injection-space-slash-filter-bypass
tags:
- php
- rce
- command-injection
- filter-bypass
- shell
- ifs
- slash
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T14:58:57+08:00'
  notes: 已对照原文与截图核对：${IFS}/$IFS$9/$IFS$1(图28)、cat</<>(图29)、{cat,flag.txt}(图30)、X=$'cat\x20...'(图31)、换行续行(图32)、${HOME:0:1}(图33)、tr '!-0' '"-1'(图34)均一致。已修正触发条件，注明花括号展开/ANSI-C引用/${HOME:0:1}子串展开为bash/ksh扩展。未验证点：PoC未在目标环境重放。
url: /docs/web/php/rce/web-php-rce-command-injection-space-slash-filter-bypass/
draft: false
kb_aliases:
- 空格过滤绕过
- ${IFS} 绕过空格
- 斜杠过滤绕过
- ${HOME:0:1} 代替斜杠
- tr 生成斜杠
- cat<file 绕过空格
---

## 一句话结论

命令注入防护如果只过滤空格或斜杠字符，可以用 shell 的等价语法替代：空格用 `${IFS}`、`$IFS$9`、输入重定向 `<`/`<>`、花括号 `{cat,file}`、`$'\x20'` 或换行/反斜杠续行代替；斜杠用 `${HOME:0:1}`（HOME 首字符）或 `$(echo . | tr '!-0' '"-1')` 现场生成，从而绕过字符级黑名单继续执行命令。

## 原理

- **空格的作用与替代**：shell 分词依赖 IFS（Internal Field Separator，默认空格/Tab/换行）。`${IFS}` 展开为默认分隔符，可替代命令名与参数之间的空格；`$IFS$9`/`$IFS$1` 在 `$9`/`$1` 为空时同样是分隔符，且原文不含空格字符。
- **重定向即分隔**：`cat<flag.txt` 中 `<` 同时完成「参数分隔」与「标准输入重定向」，不需要空格；`cat<>flag.txt` 为读写重定向。
- **花括号展开**：`{cat,flag.txt}` 在 shell 展开为两个词 `cat` 与 `flag.txt`，以逗号代替空格。
- **ANSI-C 引用**：`$'cat\x20/etc/passwd'` 中 `\x20` 在 ANSI-C 引用内解码为空格，赋值后再执行，原文无空格。
- **换行/续行**：换行本身是命令分隔符（`%0a`），在 URL/表单中可注入；`\` 后接换行实现续行（`cat\` 换行 `flag.txt`）。
- **斜杠的作用与替代**：`/` 只是路径分隔符，shell 可现场计算：`${HOME:0:1}` 取 `$HOME`（如 `/home/ubuntu`）第 0 位起的 1 个字符，即 `/`；`$(echo . | tr '!-0' '"-1')` 把字符 `.`（ASCII 0x2E）在 `!`-`0` 范围内平移为 `/`（0x2F）输出。
- **共同根因**：过滤器在 shell 解析前做字符黑名单，shell 的展开机制能生成被禁字符或等价分隔效果；只要最终命令语义不变，就能绕过。

## 触发条件

- 存在命令注入 sink，且过滤规则只针对空格和/或斜杠（如 `preg_match('/ /')`、`str_replace('/','')`）。
- 目标 shell 为 bash 或兼容 shell，支持 `${IFS}`、重定向、花括号展开、ANSI-C 引用与命令替换；花括号展开、`$'...'` 与 `${HOME:0:1}` 子串展开属 bash/ksh 扩展（纯 POSIX sh 下不可用），`${IFS}`、重定向与命令替换为 POSIX 能力。
- 目标系统有 `tr`（斜杠替代方案）或 `$HOME` 已定义（通常成立）。
- 过滤器未对整条命令做规范化/白名单校验。

## 利用步骤

1. 用 `;id`、`|id` 等确认注入点，再单独测试空格：含空格的命令被拒、无空格命令可执行，说明只过滤空格。
2. 空格绕过优先尝试 `${IFS}`（最通用），其次 `$IFS$9`、`<`、`{cmd,arg}`、`$'\x20'`、换行。
3. 若斜杠被过滤，用 `${HOME:0:1}` 替换每个 `/`，如 `cat ${HOME:0:1}etc${HOME:0:1}passwd`；不行再用 `$(echo . | tr '!-0' '"-1')`。
4. 组合两种手段（如 `cat${IFS}${HOME:0:1}etc${HOME:0:1}passwd`）构造完整路径并验证回显。
5. 记录绕过 payload 与回显，确认等价命令生效。

## PoC

```bash
# 空格替代
cat${IFS}flag.txt
cat${IFS}$1flag.txt
cat$IFS$9flag.txt
cat<flag.txt
cat<>flag.txt
{cat,flag.txt}
X=$'cat\x20/etc/passwd'&&$X

# 斜杠替代
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

以上命令未在目标环境执行，仅作语法等价示意。

## 变体与关联

- 变体：过滤 Tab/换行时同样可用 `${IFS}`；过滤 `$` 时改用重定向/花括号等不含变量的方式。
- 变体：空格与斜杠同时过滤时组合使用（`cat${IFS}${HOME:0:1}etc${HOME:0:1}passwd`）。
- 关联：[[web-php-rce-command-name-blacklist-equivalent-rewrites]]（命令名黑名单改写）、[[web-php-rce-four-char-command-length-bypass]]（长度限制下同样用 `${IFS}`）、[[web-php-blind-rce-time-oracle-ifs-base64-char-bruteforce]]（盲注场景中的 $IFS$9/base64）。
- 边界：若过滤在 shell 层之外还做了 `escapeshellarg`/白名单校验，字符替代无效；若目标不是 POSIX shell（如 Windows cmd），需换用 `%COMSPEC%` 等对应技巧。

## 检测与防御

- 防御：使用参数化调用与白名单校验，禁止把用户输入拼进 shell；无法避免时用 `escapeshellarg` 并对参数做严格格式校验（如 IP/域名）。
- 防御：不要在应用层用「过滤空格/斜杠」冒充安全措施；应使用语言内置 API 替代系统命令。
- 检测：请求中出现 `${IFS}`、`$IFS$9`、`$'\x20'`、`${HOME:0:1}`、`tr '!-0'`、`{cmd,arg}`、`cat<` 等特征；命令日志中出现无空格拼接的异常命令。
