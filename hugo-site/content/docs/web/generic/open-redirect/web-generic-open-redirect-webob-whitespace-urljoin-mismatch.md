---
id: web-generic-open-redirect-webob-whitespace-urljoin-mismatch
title: WebOb <1.8.11 开放重定向：前导空白 + 协议相对 URL 绕过校验（CVE-2026-54770）
type: scenario
domain: web
path: web/generic/open-redirect
technique: webob-whitespace-urljoin-open-redirect
tags:
- python
- webob
- open-redirect
- url-normalization
- urljoin
- cve-2026-54770
- oauth
- phishing
cve:
- CVE-2026-54770
severity: medium
confidence: high
affected_versions: WebOb < 1.8.11（修复版本 1.8.11）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:57:09+08:00'
  notes: 已对照原文全文与10张图核对：旧版 _make_location_absolute 的 SCHEME_RE/startswith("//") 检查原始串、urllib urljoin 前导 C0/空格剥离造成语义翻转；Response.location/HTTPFound/relative_url 三入口与 1.8.10 vs 1.8.11 的库层/HTTP 层对照结果（图03-09）一致；修复收口到 webob.util.urljoin 的描述与原文一致。原文明确 WebOb < 1.8.11 受影响，已 set-versions。PoC 为结构化复现，未在本机执行。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-webob-whitespace-urljoin-mismatch/
draft: false
kb_aliases:
- WebOb 开放重定向
- CVE-2026-54770
- WebOb open redirect
- '%20//evil.example 绕过'
- urljoin 前导空格
- Response.location 越站跳转
- HTTPFound location 绕过
---

## 一句话结论

WebOb < 1.8.11 在把 `Location` 目标绝对化时，安全判断看的是未经规范化的原始字符串，而 `urllib.parse.urljoin()` 会先剥离前导 C0 控制字符与空格；因此 `%20//evil.example/poc`（解码后为 ` //evil.example/poc`）能绕过 `startswith("//")` 检查，随后被 `urljoin` 解释成协议相对 URL，形成越站跳转。`Response.location`、`HTTPFound` 等重定向异常、`Request.relative_url()` 三条路径均受影响。

## 原理

- **同一输入在两个阶段有不同词法含义**：旧版 `Response._make_location_absolute()` 先用 `SCHEME_RE` 判断是否显式带 scheme，再用 `value.startswith("//")` 判断是否协议相对 URL；两者都针对原始字符串。检查完却把值交给 `urljoin(_request_uri(environ), value)`。
- **标准库会改写输入**：CPython 的 `urlsplit()`（`urljoin` 内部调用）在解析前执行 `url.lstrip(_WHATWG_C0_CONTROL_OR_SPACE)`，即剥离开头的 0x00–0x20（含普通空格、tab 等），并删除部分不安全字节。于是 `" //evil.example/poc"` 在检查阶段首字符是空格、不满足 `startswith("//")`；进入 `urljoin` 后前导空格被剥离，`//evil.example/poc` 被识别为 `scheme=None, netloc=evil.example, path=/poc`，最终返回 `http://evil.example/poc`。
- **三条 sink 的实现差异**：
  - `Response.location`：赋值时只拒绝 CR/LF 等会破坏头部结构的控制字符，不判断站内/站外；直到 `Response.__call__` 的 `_abs_headerlist()` 才调用 `_make_location_absolute()`，触发上述检查与解析错位。
  - `HTTPFound` / `_HTTPMove`：旧版 `__call__` 直接 `urljoin(req.path_url, self.location)`，连前置的 `startswith("//")` 检查都没有，因此 `//evil.example/poc` 原样即可离站，是三条路径中最短的。
  - `Request.relative_url()`：旧版同样直接 `urljoin(self.path_url, other_url)`；它不立即返回 302，但会把脏输入加工成“看起来已被框架规整”的绝对 URL，适合二阶利用（例如结果再写入 `Location`、模板或邮件链接）。
- **为什么这是结构性问题**：三个入口共享“前置检查/后续解析不是同一份规范化结果”的假设。只要业务层相信“看起来不像外链”的判断，或相信 helper 返回值已被框架处理，就会把攻击者输入平滑送入跳转 sink。
- **修复思路**：1.8.11 引入 `webob.util.urljoin()`，其 `_split_uri_reference()` 明确不删除输入中的任何字符（docstring：Unlike `urllib.parse.urlsplit()`, no characters are ever removed），让 authority/path 的分类基于同一份原始字符流；同时把 `Response._make_location_absolute()`、`BaseRequest.relative_url()`、`_HTTPMove.__call__` 统一收敛到该实现。`" //evil.example/poc"` 因此保持首字符为空格，被当作相对路径合并为 `http://host/ //evil.example/poc`。

## 触发条件

- 目标使用 WebOb < 1.8.11（受影响版本明确；1.8.11 修复）。
- 应用把用户可控值送入 `res.location`、`exc.HTTPFound/HTTPSeeOther/HTTPTemporaryRedirect/HTTPPermanentRedirect(location=...)` 或 `req.relative_url()`，常见参数名为 `next`、`return_to`、`redirect`、`continue`。
- 该值最终进入响应 `Location` 头，或被业务层当作“已绝对化的安全 URL”继续复用；若只是计算但不使用，则不构成实际跳转。
- 客户端/浏览器会跟随 302，或代理/调试工具按标准 URL 语义解释 `Location`。
- `%20https://evil.example/poc` 这类显式绝对 URL 变体在旧版响应头中会保留前导空格，部分客户端仍会跟随；是否成立取决于客户端解析，不能只看响应头形态。

## 利用步骤

1. 枚举跳转参数：登录后的 `next`、认证回调 `return_to`、下载/邀请/支付完成页的返回地址等。
2. 先试显式外链 `https://evil.example/poc` 和协议相对 `//evil.example/poc`，确认参数是否原样进入 `Location`。
3. 若被拒，加前导空白：`%20//evil.example/poc`；空格可换成 `%09`（tab）等 C0 字符，标准库会一并剥离。
4. 观察响应：旧版 `Location` 变为 `http://evil.example/poc`；修复版回收到站内绝对路径。
5. 对 `relative_url()` 类 helper，检查其返回值是否被下游继续用于跳转或模板渲染，构造二阶利用。
6. 结合可信首跳做钓鱼/SSO 中继：用户先访问官方域名，再被送到攻击者页面。

## PoC

标准库行为（Python 3.10+）：

```python
from urllib.parse import urljoin
urljoin("http://localhost/", "//evil.example/poc")    # http://evil.example/poc
urljoin("http://localhost/", " //evil.example/poc")   # http://evil.example/poc（前导空格被剥离）
urljoin("http://localhost/", "\t//evil.example/poc")  # http://evil.example/poc
```

WebOb 应用入口：

```http
GET /response?next=%20//evil.example/poc HTTP/1.1
Host: target
```

- WebOb 1.8.10 响应：`302 Found`，`Location: http://evil.example/poc`
- WebOb 1.8.11 响应：`302 Found`，`Location: http://target/ //evil.example/poc`

`HTTPFound` 路径更短：

```http
GET /exception?next=//evil.example/poc HTTP/1.1
Host: target
```

- 1.8.10：`Location: http://evil.example/poc`
- 1.8.11：`Location: http://target/%2fevil.example/poc`

库层最小验证：

```python
from webob import Response, exc
from webob.request import Request

req = Request.blank("/")
res = Response()
res.location = " //evil.example/poc"
print(req.get_response(res).location)      # 1.8.10: http://evil.example/poc
print(req.relative_url(" //evil.example/poc"))  # 1.8.10: http://evil.example/poc
```

说明：以上为结构化复现，未在本会话执行；实际主机名与路径按目标替换。

## 变体与关联

- 变体（控制字符）：除 `%20` 外，`%09`（tab）、其他 C0 字符（0x00–0x1F）在 `urlsplit` 预处理中也会被剥离，可用于绕过只检查首字符的黑名单。
- 变体（显式绝对 URL）：`%20https://evil.example/poc` 在旧版 `Location` 中保留前导空格，但客户端仍可能按绝对 URL 跳转；需以客户端实际行为为准。
- 变体（二阶）：`safe_next = req.relative_url(req.params["next"]); raise HTTPFound(location=safe_next)` 把 helper 输出当安全值，实际上已被加工成离站 URL。
- 关联：[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]（同类“不同组件对同一 URL 的规范化理解不一致”问题，可互相参照审计思路）。
- 通用化：任何“先对原始字符串做 `startswith('//')`/scheme 白名单，再交给会做 `lstrip`/规范化的解析器”的实现，都可能有同样的检查-解析错位；审计时以最终解析器行为为准。
- 边界：WebOb ≥ 1.8.11、业务层对跳转目标做显式 allowlist、或值只计算不用于跳转/渲染时，本链不成立。

## 检测与防御

- 检测：30x 响应的 `Location` 是否包含用户输入；请求参数出现 `%20//`、`%09//`、`%00//` 等前导编码空白加协议相对 URL 的组合；`next`、`return_to`、`redirect`、`continue` 参数被原样回显到 `Location`。
- 检测：代码审计搜索 `res.location =`、`HTTPFound(`、`HTTPSeeOther(`、`HTTPTemporaryRedirect(`、`HTTPPermanentRedirect(`、`relative_url(`，并判断值是否来自请求参数。
- 防御：升级 WebOb 到 1.8.11 或更高版本；不要直接把用户原始输入作为跳转目标。
- 防御：对允许跳转的地址做服务端显式 allowlist（scheme + host + path 前缀），在规范化之后比较，而不是只检查原始字符串前缀。
- 防御：更推荐传站内路由名、固定 key 或一次性短 token，由服务端映射到目标 URL；即使框架已修复，业务层 allowlist 仍应保留。
- 防御：对 `relative_url()` 等 helper 的返回值不要默认可信，下游进入 `Location`/模板/邮件前仍需校验。
