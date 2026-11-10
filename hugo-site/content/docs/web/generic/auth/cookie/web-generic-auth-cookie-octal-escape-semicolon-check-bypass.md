---
id: web-generic-auth-cookie-octal-escape-semicolon-check-bypass
title: Cookie 八进制转义 \073 解码成分号：绕过 user.lower()=='adm;n' 校验并写入 admin session
type: scenario
domain: web
path: web/generic/auth/cookie
technique: cookie-octal-escape-semicolon-check-bypass
tags:
- cookie
- http
- python
- http-cookies
- octal-escape
- auth-bypass
- session
- sanic
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:16:54+08:00'
  notes: 已对照原文与图01/13核对：Cookie user="adm\073n" 解码为adm;n通过login并下发session一致；已用Python http.cookies实测\073解码为分号。未实机打靶。
url: /docs/web/generic/auth/cookie/web-generic-auth-cookie-octal-escape-semicolon-check-bypass/
draft: false
kb_aliases:
- adm\073n
- Cookie 八进制转义
- RFC2068 cookie 转义
- 分号截断绕过
- Sanic session 登录绕过
- http.cookies _unquote
---

## 一句话结论

当服务端用 Python `http.cookies`（或等价的 RFC2068 风格解析器）读取 Cookie，并把值与包含分号的字符串比较（如 `user.lower() == 'adm;n'`）时，攻击者发送 `Cookie: user="adm\073n"`：八进制转义 `\073` 在引号包围的 cookie 值里被解码为 `;`，应用拿到的值就是 `adm;n`，而原始头部里并不存在裸分号，因此不会被 Cookie 的分号分隔规则截断，从而通过校验并写入管理员 session。

## 原理

- **Cookie 的分号语义**：RFC6265 中 `;` 是 cookie-pair 的分隔符。若直接发送 `Cookie: user=adm;n`，解析器会在 `;` 处结束 `user` 的值，应用只能看到 `adm`，`user.lower() == 'adm;n'` 永远不成立。
- **RFC2068 的 quoted-string 转义**：旧版 HTTP 规范允许 cookie 值用双引号包围，并在引号内用反斜杠转义；`\ooo` 形式的八进制转义在 Python 的 `http.cookies.SimpleCookie` 中被 `_unquote()` 解码。实测 `SimpleCookie().load('user="adm\\073n"')` 得到 `c['user'].value == 'adm;n'`。
- **解析顺序**：Cookie 解析器先在原始头部按 `;` 切分 cookie-pair（此时 `adm\073n` 中没有裸分号），再对引号内的值做反转义，得到 `adm;n` 交给应用。应用看到的字符串满足比较条件，但报文层面没有任何未转义的分号。
- **后果**：本例 `/login` 在比较成功后执行 `request.ctx.session['admin'] = True`，攻击者拿到带 admin 标记的 session，随后可访问 `/admin` 的 pydash 写入接口（见关联卡），把一次登录绕过扩展为任意文件读取。
- 该技巧并非 Python 独有：任何实现了 quoted-string/八进制（或 `\xNN`）反转义的 Cookie 解析栈都可能出现“报文里没有分隔符、应用里却出现分隔符”的解析差异；关键是应用把分隔符当作值的一部分来比较。

## 触发条件

- 服务端 Cookie 解析器支持引号包围与反斜杠/八进制转义（Python `http.cookies` 满足；Sanic 等基于它的框架同样如此）。
- 应用比较的 Cookie 值包含 `;`（或其它会被 Cookie 语法截断的字符），且比较发生在 `request.cookies.get()` 之后。
- 服务端不会对反斜杠/八进制序列做二次拒绝或规范化。
- 攻击者能自行设置该 Cookie（本例是普通 `user` Cookie，不受 HttpOnly 影响）。

## 利用步骤

1. 确认 Cookie 解析器与比较逻辑：`request.cookies.get('user')` 返回值直接与含分号的字符串比较（源码或报错可确认）。
2. 用八进制 `\073`（`;` 的 ASCII 0x3B = 八进制 073）替换值中的分号，并整体用双引号包围：`user="adm\073n"`。
3. 发送请求到 `/login`，服务端解析出的值为 `adm;n`，比较通过。
4. 服务端设置 `session['admin']=True` 并返回 `Set-Cookie`；携带该 session Cookie 访问受保护路由（本例 `/admin`）。

## PoC

```http
GET /login HTTP/1.1
Host: target
Cookie: user="adm\073n"
```

服务端响应：

```http
HTTP/1.1 200 OK
Set-Cookie: session=<...>; Path=/; HttpOnly
Content-Type: text/plain; charset=utf-8

login success
```

对比直接发送裸分号（会被截断为 `adm`，校验失败）：

```http
Cookie: user=adm;n
```

## 变体与关联

- 变体：其它需要“值里出现分隔符/引号”的比较，可尝试 `\"`、`\\`、`\ooo`（0-3 开头的三位八进制）等转义；不同解析器（Werkzeug、Node cookie、Go net/http）支持程度不同，需要按目标栈验证。
- 变体：若 Cookie 值还要经过签名/加密，八进制技巧仍适用于“未签名部分”或解析后再校验的环节。
- 关联：[[web-python-framework-sanic-static-handler-keywords-pollution]] 是拿到 admin session 后使用的 pydash 静态目录污染链。

## 检测与防御

- 检测：Cookie 比较逻辑中出现 `;`、`,` 等分隔字符；请求 Cookie 含 `\` 或 `\ooo`；登录成功但原始 Cookie 值在报文层不匹配预期。
- 防御：不要在 Cookie 值里使用 Cookie 语法保留字符，也不要用带分号的硬编码值做认证；使用服务端会话与签名 token；对 Cookie 值做严格字符白名单并拒绝反斜杠转义；认证判断不要依赖客户端可控 Cookie 的字符串内容。
