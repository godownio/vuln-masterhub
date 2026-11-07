---
id: web-php-file-inclusion-filter-chain-cp037-double-urlencode
title: PHP filter chain + CP037 编码绕过：convert.iconv.ASCII.CP037 隐藏 base64/flag 关键字，双重 URL 编码过黑名单
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-chain-cp037-ebcdic-blacklist-bypass
tags:
- php
- file-inclusion
- php-filter
- filter-chain
- cp037
- ebcdic
- iconv
- blacklist-bypass
- urlencode
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:08:06+08:00'
  notes: 已对照原文核对；PoC/CP037 解码已本地复算一致（flag{a5fbd777-974e-489f-bade-f3375ec780c8}）；未在目标复跑。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-filter-chain-cp037-double-urlencode/
draft: false
kb_aliases:
- CP037 filter chain
- convert.iconv.ASCII.CP037
- PHP filter chain 绕过
- 双重 URL 编码绕过
- ez_chain
- php://filter base64 CP037
- EBCDIC 编码绕过
---

## 一句话结论

当文件读取点过滤 `/`、`:`、`php`、`base64`、`filter`、`flag` 等关键字，并对输出循环 `base64_decode`、要求解码结果不含 `f` 时，可以用 `php://filter/convert.base64-encode|convert.iconv.ASCII.CP037/resource=/flag` 读取 flag：先 base64 编码，再把 base64 文本的 ASCII 字节转成 CP037（EBCDIC）字节，使输出既不含明文 `flag` 也不是可直接识别的 base64；攻击者拿到原始字节后按 CP037 解码得到 base64 字符串，再 base64 解码即得 flag。整个 payload 再经过双重 URL 编码即可绕过关键字黑名单。

## 原理

- **php://filter 过滤器链**：`php://filter` 允许在读取资源前串联多个过滤器，语法为 `php://filter/<filter1>|<filter2>/resource=<path>`。`convert.base64-encode` 把资源内容编码成 base64；`convert.iconv.ASCII.CP037` 用 iconv 把 ASCII 字节转换为 CP037（IBM EBCDIC）编码字节。
- **为什么先 base64 再 CP037**：直接读 `/flag` 会输出 `flag{...}`，命中黑名单/内容检查；先 base64 得到 `ZmxhZ3...`（仍含 `f`、`base64` 相关字符），再经 `convert.iconv.ASCII.CP037` 后，每个 ASCII 字节变成对应的 EBCDIC 字节（如 `Z` 0x5A -> 0xE9），输出是二进制/十六进制形式，不再含可读的 `flag`/`f`。
- **应用的循环 base64 解码**：题目对读取结果循环 `base64_decode` 并检查解码内容不含 `f`；CP037 字节序列不是标准 base64 文本，应用侧的解码不会得到明文 flag，从而通过检查。攻击者则反过来：先对原始输出做 `CP037` 解码，得到 `ZmxhZ3...Cg==`，再做一次 base64 解码得到 flag。
- **双重 URL 编码**：黑名单在某一层解码后匹配 `php`、`base64`、`filter`、`/`、`:` 等；把 payload 先 URL 编码一次、再对 `%` 编码一次（`%25`），经过两层解码后才还原成 `php://filter/...`，从而在过滤层看到的是普通字符/百分号而不是关键字。原文给出的 payload 即整串 `%25` 形式。
- **为什么成立**：黑名单是“关键字匹配”，而 PHP 的过滤器/编码组合可以生成不含这些关键字的等价语义；iconv 编码把敏感字符串变成不可读字节，绕过了内容检查。根因是输入过滤没有做规范化/白名单，且允许 `php://filter` 与 `iconv` 过滤器。

## 触发条件

- 存在 `include`/`file_get_contents`/`readfile` 等文件读取点，参数可控制且未使用 `basename`/路径白名单。
- `php://filter` 未被 `allow_url_include`/`open_basedir`/禁用函数拦截；`convert.iconv.*` 过滤器可用（iconv 扩展启用）。
- 过滤逻辑只做关键字黑名单，且可通过 URL 编码/多重解码绕过；或应用在过滤后又做了一次解码。
- 目标文件（如 `/flag`）可读；输出会回显或被写入响应。
- 应用对输出做循环 base64 解码/内容检查，但没有对 CP037/其它编码做还原。

## 利用步骤

1. 确认文件读取点与过滤：提交 `?file=php://filter/resource=/flag` 观察被哪个关键字拦截；测试 `/`、`:`、`php`、`base64`、`filter`、`flag` 是否分别命中。
2. 构造过滤器链：`php://filter/convert.base64-encode|convert.iconv.ASCII.CP037/resource=/flag`。
3. 对整串做两次 URL 编码：第一次把所有特殊字符编码为 `%XX`，第二次把 `%` 编码为 `%25`；得到类似 `%2570%2568%2570%253a%252f%252f...` 的 payload。
4. 提交 `?file=<double-encoded>`，保存响应中的十六进制/原始字节（若页面以 hex 显示，先转回 bytes）。
5. 用 Python `bytes.fromhex(...).decode('cp037')` 得到 `ZmxhZ3...`，再 `base64.b64decode` 得到 flag。
6. 若 CP037 解码结果不是 base64，尝试 `cp500`、`cp1047`、`ibm037` 等 EBCDIC 变体；若过滤器被禁，改用其它 iconv 编码链或 `convert.base64-decode` 组合。

## PoC

Payload（原文形式，双重 URL 编码）：

```text
/?file=%2570%2568%2570%253a%252f%252f%2566%2569%256c%2574%2565%2572%252f%2563%256f%256e%2576%2565%2572%2574%252e%2562%2561%2573%2565%2536%2534%252d%2565%256e%2563%256f%2564%2565%257c%2563%256f%256e%2576%2565%2572%2574%252e%2569%2563%256f%256e%2576%252e%2541%2553%2543%2549%2549%252e%2543%2550%2530%2533%2537%252f%2572%2565%2573%256f%2575%2572%2563%2565%253d%252f%2566%256c%2561%2567
```

等价的明文过滤器链：

```text
php://filter/convert.base64-encode|convert.iconv.ASCII.CP037/resource=/flag
```

CP037 解码脚本（把响应中的 hex 字节转为 base64，再解 flag）：

```python
import base64

hex_string = "E9 94 A7 88 E9 F3 A3 88 D5 E6 E9 89 E9 C4 83 F3 D5 A8 F0 F5 D5 A9 D9 93 D3 E3 D8 F4 D6 E6 E8 A3 E8 94 C6 92 E9 E2 F1 94 D4 A9 D4 F3 D5 E6 E5 91 D5 A9 87 A6 E8 A9 88 F9 C3 87 7E 7E"
raw = bytes.fromhex(hex_string.replace(" ", ""))
b64 = raw.decode('cp037')
print(b64)                      # ZmxhZ3thNWZiZDc3Ny05NzRlLTQ4OWYtYmFkZS1mMzM3NWVjNzgwYzh9Cg==
print(base64.b64decode(b64))    # b'flag{...}\n'
```

## 变体与关联

- 变体：把 `convert.iconv.ASCII.CP037` 换成 `convert.iconv.UTF-8.UTF-16`、`convert.iconv.ISO-2022-CN`、`convert.quoted-printable-encode` 等，制造不可读/不同编码的输出以绕过内容检查。
- 变体：用 `convert.base64-decode` 做反向链，或先 `zlib.deflate` 再 base64，构造更复杂的 filter chain。
- 变体：不只读 `/flag`，也可读源码/配置：`php://filter/convert.base64-encode/resource=index.php`；若 `flag` 关键字被拦，用编码链隐藏。
- 关联：[[web-php-file-inclusion-filter-chain-file-write-webshell]]（filter chain 写 webshell）、[[web-php-file-inclusion-filter-chain-fileless-rce]]（filter chain 无文件 RCE）、[[web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass]]（iconv 编码绕过 WAF）、[[web-php-file-inclusion-php-filter-insert-bypass]]（filter 关键字绕过）、[[web-php-rce-glibc-iconv-iso2022cn-ext-heap-overflow-cve-2024-2961]]（iconv 扩展漏洞）。
- 边界：`php://filter` 被禁用、`iconv`/`convert.iconv` 不可用、参数经过 `basename`/白名单、或对输入只解码一次且黑名单覆盖所有编码形式时，该链不成立。

## 检测与防御

- **修复**：文件读取参数使用固定 ID/白名单映射，禁止用户传入协议/路径；`basename()` + 后缀白名单只是补充，不能替代白名单。
- **PHP 配置**：设置 `open_basedir` 限制可读目录；禁用 `allow_url_include`；在业务层禁用 `php://filter`（检查输入是否包含 `://` 或 `php` 协议）；必要时用 `disable_functions` 限制 `iconv` 相关风险（注意兼容性）。
- **输入处理**：只做一次 URL 解码，拒绝二次编码/异常 `%25`；对参数做规范化后匹配白名单，而不是仅匹配黑名单关键字。
- **检测**：监控请求中出现 `php://filter`、`convert.iconv`、`convert.base64-encode`、多重 `%25` 编码、`resource=/flag` 等特征；对文件读取接口的异常编码参数告警；WAF 规则应覆盖编码链而不只是关键字。
- **响应**：若已泄露，轮换敏感文件/密钥，检查是否进一步写入 webshell 或读取源码；修复文件读取接口并审计同类参数。
