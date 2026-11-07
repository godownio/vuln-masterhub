---
id: web-generic-ssrf-php-preview-line-case-filter-lfi
title: PHP 友链预览 SSRF 两层校验不一致：换行把 FILE:// 藏到第二行 + 大写 scheme 绕过过滤读取本地文件
type: scenario
domain: web
path: web/generic/ssrf
technique: php-preview-line-case-filter-inconsistency-lfi
tags:
- php
- ssrf
- lfi
- filter-bypass
- newline
- case-sensitivity
- file-get-contents
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:35:38+08:00'
  notes: 已对照原文 web2 源码核对：do_preview 先 rawurldecode 再按行切分、黑名单 stripos 只查第一行、first 为空短路、file_get_contents 使用整串、raw_head 前 8192 字节回显、payload url=%0AFILE:///flag 均与原文一致。注意原文给出的 eof.php 只含第一层（first 黑名单），第二层整串 strpos 仅见于作者文字分析，卡内已标注以实际附件源码为准；仅第一层换行绕过已成立，FILE:// 大写用于应对作者所述第二层。未验证点：未搭 PHP 环境复跑。
url: /docs/web/generic/ssrf/web-generic-ssrf-php-preview-line-case-filter-lfi/
draft: false
kb_aliases:
- 友链预览 LFI
- rawurldecode 换行绕过
- FILE:// 大小写绕过
- 第一行校验绕过
- file_get_contents SSRF
- 预览功能本地文件读取
---

## 一句话结论

PHP 友链预览接口先 `rawurldecode` 再按换行切分，只对第一行做不区分大小写的危险 scheme 黑名单，同时对整个输入还有一层区分大小写的 `file://` 匹配；用 `%0A` 让第一行为空、把 `FILE:///flag` 放到第二行，即可同时绕过两层检查，最终 `file_get_contents()` 以大小写不敏感的流 wrapper 读取任意本地文件并回显前 8192 字节。

## 原理

- **输入先解码再切行**：`do_preview($raw_input)` 里 `$decoded = rawurldecode($raw_input)`，随后 `preg_split("/\r\n|\n|\r/", $decoded)`，取 `$first = $lines[0]`。解码发生在切行之前，因此 `%0A` 会在服务端变成真实换行，把攻击者控制的危险 scheme 推到第二行。
- **第一层只检查第一行**：`$blacklist = ['file://','php://','data://','gopher://','dict://']`，用 `stripos($first, $bad)` 不区分大小写匹配。若第一行为空，`stripos('', 'file://')` 为 false，黑名单全部通过；同时 `if ($first !== '' && !preg_match('/^https?:\/\//i', $first))` 因为 `$first === ''` 被短路，也不会要求 http/https。
- **第二层区分大小写**：按原文分析，服务还对整个解码后的字符串做一次 `strpos($decoded, 'file://')` 检查（代码片段展示了第一层，第二层以实际附件源码为准）。小写 `file://` 会被命中，但 `FILE://`/`FiLe://` 不会；PHP 的流 wrapper 在解析 scheme 时大小写不敏感，`FILE:///flag` 仍会被 `file_get_contents` 当作本地文件读取。
- **最终 sink 使用整串**：`file_get_contents($target, false, $ctx)` 的 `$target` 是完整 `$decoded`，不是 `$first`；前面两层检查与实际使用对象不一致，这是绕过成立的根本原因。
- **回显**：函数把 `mb_substr($html, 0, 8192)` 放进 JSON 的 `raw_head` 字段返回，本地文件内容直接出现在响应里；即使没有 `raw_head`，也可通过标题/描述提取间接回显。
- **根因**：校验与使用对象不一致（第一行 vs 整串）、大小写处理不一致（stripos vs strpos）、scheme 黑名单而非 http/https 白名单。

## 触发条件

- PHP 应用存在“URL 预览/友链抓取”功能，用户可控制 URL 并调用 `file_get_contents`/cURL。
- `allow_url_fopen=On`（PHP 默认），且未禁用 `file://` 等 wrapper。
- 过滤器按行拆分或只检查首个 token，或对 scheme 做大小写敏感匹配。
- 响应会把抓取内容（或标题/描述/头部片段）返回给用户。

## 利用步骤

1. 找到预览接口（原文为后台友链 `eof.php` 的 POST `url` 参数），确认它会抓取并回显内容。
2. 用普通 http URL 确认功能正常，再用 `file:///etc/passwd` 测试是否被拦截，判断过滤层。
3. 若小写被拦，构造 `url=%0AFILE:///flag`：解码后为换行 + `FILE:///flag`，第一行为空绕过第一层，第二层大小写敏感检查不命中。
4. 提交后读取 JSON 的 `raw_head`（或 title/description）字段，获取 `/flag` 前 8192 字节。
5. 需要读取其他文件时替换路径（如 `/etc/passwd`、源码、配置）；也可尝试 `php://filter`、`data://` 等变体，视黑名单而定。

## PoC

```http
POST /eof.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=%0AFILE:///flag&id=1
```

原文返回的 `raw_head` 中直接包含 `/flag` 内容（截图见原文 web2 复现）。也可用 curl：

```bash
curl -s -X POST 'http://target/eof.php' --data-urlencode 'url=
FILE:///flag' -d 'id=1'
```

## 变体与关联

- 换行变体：`%0A`、`%0D%0A`、`%0D`、多个空行；把危险 scheme 放到任意后续行。
- 大小写变体：`FILE://`、`FiLe://`、`fIlE://`；若目标用 `stripos` 则此变体无效，需改用其他编码/协议。
- 协议变体：`php://filter/convert.base64-encode/resource=/flag`、`data://text/plain,...`、`gopher://`、`dict://`；黑名单常漏 `compress.zlib://`、`expect://` 等。
- 入口变体：友链预览、RSS 抓取、图片 URL 导入、URL 元信息解析、Webhook 测试。
- 关联卡片：[[web-generic-ssrf-php-curl-get-file-scheme-config-read]]、[[web-generic-ssrf-multi-layer-decode-dword-waf-bypass]]、[[web-generic-ssrf-ip-notation-blacklist-bypass]]、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]。
- 边界：若服务端禁用 `allow_url_fopen`、只允许 http/https 白名单、或对整串做大小写不敏感 scheme 校验，本手法失效。

## 检测与防御

- **校验与使用同一对象**：解码后先规范化（去除控制字符/换行），对完整字符串做一次检查，再交给 `file_get_contents`；禁止先切行只查第一行。
- **scheme 白名单**：只允许 `http`/`https`，用 `parse_url()` 取 scheme 后统一小写比较；拒绝 `file`、`php`、`data`、`gopher`、`dict`、`expect` 等。
- **禁止本地路径**：解析后校验 host 非空、解析 IP 并阻断内网/回环/元数据地址；必要时用独立代理服务抓取。
- **关闭危险能力**：生产环境 `allow_url_fopen=Off` 或禁用危险 wrapper，抓取用 cURL 并设置协议白名单。
- **输出控制**：不要原样返回抓取内容；只提取标题/描述并做长度与类型限制。
