---
id: web-generic-ssrf-url-userinfo-prefix-allowlist-bypass
title: URL userinfo 混淆：用 user:pass@host 绕过前缀白名单 SSRF 与 WAF 关键词检测
type: scenario
domain: web
path: web/generic/ssrf
technique: url-userinfo-confusion
aliases:
- URL Credentials 绕过
- userinfo 混淆
- '@ 前缀白名单绕过'
- URL 用户信息 SSRF
tags:
- web
- ssrf
- url-parsing
- allowlist-bypass
- waf-bypass
- userinfo
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:37:53+08:00'
  notes: 已对照原文并核对2张图：图01/02仅演示浏览器地址栏隐藏userinfo而document.URL仍含https://foo:bar@example.com/，未对真实SSRF/WAF目标验证。核对确认核心机制正确：RFC3986 authority中最后一个@前为userinfo、@后为host，字符串前缀白名单可被https://trusted@evil.com绕过，Python urlparse的username/hostname分离描述正确。已修正原文及卡内误导的DOM XSS示例：给window.location赋含<script>的URL只会跳转evil.com，不会执行；DOM XSS需未编码地写入HTML/JS上下文。原文无affected_versions，frontmatter无sources/source_url。
---

## 一句话结论

URL 的 `user:password@host` 中 `@` 前是用户信息、其后才是真实主机；只做字符串前缀或关键词匹配的白名单/WAF 会把可信域名误当成目标，而请求实际发往攻击者主机。

## 原理

RFC 3986 的 authority 结构为 `[userinfo@]host[:port]`：最后一个 `@` 之前全部是 userinfo，不属于主机名。浏览器与 HTTP 客户端连接的是 `@` 之后的 host，但很多校验代码用 `url.startswith("https://internal.company.com")` 或简单正则提取“看起来像域名”的片段，看到前缀匹配就放行。

- SSRF 白名单：`https://internal.company.com@evil.com/data` 通过前缀检查，实际连接 `evil.com`；
- WAF 关键词：`https://<script>alert(1)</script>@evil.com` 中恶意串位于 userinfo，若 WAF 只匹配 path/query 或对 `@` 前内容跳过，则放行；
- 日志：完整 URL 被记录，攻击者可写入 `https://admin:admin123@evil.com` 制造凭据泄露假象。

现代浏览器出于反钓鱼会隐藏或阻止带 userinfo 的顶层跳转，但这不影响服务端解析、SSRF 客户端和基于原始字符串的校验逻辑；前端若把原始 URL 写入 DOM（如 `document.URL`、错误页、日志展示），payload 仍可能落地。

## 触发条件

- 服务端用字符串前缀/后缀/正则做 URL 白名单，而不是解析后比较 hostname；
- SSRF 客户端（curl、requests、HttpClient）接受带 userinfo 的 URL 并正常连接 `@` 后主机；
- 或 WAF/过滤器只扫描 URL 的 path/query，忽略 userinfo；
- DOM XSS 变体还要求页面把完整 URL 拼接进 HTML/JS。

## 利用步骤

1. 找到 URL 参数（redirect、webhook、图片代理、URL 预览）；
2. 用可信域名做 userinfo、攻击者域名做 host 测试是否放行；
3. 观察请求是否到达攻击者服务器（DNS/HTTP 日志），确认 SSRF；
4. 若目标是 WAF，把 XSS/SQLi 关键词放进 userinfo，观察是否仍被拦截；
5. 若前端回显 URL，检查是否形成 DOM XSS。

## PoC

SSRF 前缀白名单绕过：

```text
https://internal.company.com@evil.com/data
```

等价写法（带密码）：

```text
https://internal.company.com:443@evil.com/data
```

WAF 关键词绕过：

```text
https://<script>alert(1)</script>@evil.com
```

DOM 拼接型（有条件，非直接执行）：

```javascript
// 注意：window.location = "https://<script>alert(1)</script>@evil.com"
// 只会解析并跳转到 @ 后的 evil.com，userinfo 中的 <script> 不会执行。
// DOM XSS 需要页面把原始 URL 字符串写入 HTML/JS 上下文且未编码，
// 例如模板将 url 原样拼进 <a href="...">、document.write() 或未转义的 innerHTML。
```

Python 解析对照（3.9+ 行为一致，userinfo 与 host 分离）：

```python
from urllib.parse import urlparse
u = urlparse("https://internal.company.com@evil.com/data")
print(u.username)  # internal.company.com
print(u.hostname)  # evil.com
```

## 变体与关联

- 多个 `@`：解析器通常取最后一个 `@` 作为分隔，`https://trusted@evil.com@attacker` 需按目标解析器确认；
- 反斜杠/编码混淆：`https://trusted.com\@evil.com`、`%40` 等，配合解析器差异（见 URL 解析器分歧卡）；
- 日志/取证干扰：把伪造凭据放进 userinfo，诱导应急人员误判；
- 关联：SSRF 白名单绕过、开放重定向、DOM XSS、WAF 绕过。

## 检测与防御

- 检测：URL 中出现 `@` 且 userinfo 含域名/脚本关键词；同一参数先出现可信域名再出现外站 host；DNS 解析到非白名单 IP；
- 防御：解析 URL 后只比较规范化 hostname（拒绝 userinfo、非标准端口、非 http/https）；对 URL 做 DNS 解析并校验 IP 段；重定向每跳都重新校验；
- WAF：对 userinfo 与 host 分别解码检测，不能只匹配 path/query；拒绝含 `@` 的外链参数；
- 日志：记录前剥离 userinfo 或掩码为 `***:***@`，避免伪造凭据污染取证。
