---
id: web-generic-csrf-json-text-plain-form-enctype
title: JSON 接口 CSRF：enctype=text/plain 表单直发 JSON 并利用 Referer 校验失效
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-json-text-plain-form-enctype
aliases:
- JSON CSRF
- text/plain CSRF
- enctype text/plain
- 表单发送 JSON
- Referer 校验绕过
- CSRF POC 构造
tags:
- csrf
- json
- text-plain
- form-enctype
- referer
- same-origin
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:14:02+08:00'
  notes: 已对照原文2.5.0节核对：接口要求 text/plain 且 hostOrRefererDifferentHost 对缺失/跨站 Referer 返回 true 形成反向放行；POC 用 enctype=text/plain + name 内 'value=' 吸收浏览器追加的 =，WebWolf 挂载后成功提交 JSON。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

当 JSON 接口只接受 `Content-Type: text/plain` 的原始请求体、且 Referer/Origin 校验在缺失或跨站时反而放行，攻击者可用 `enctype="text/plain"` 的 HTML 表单从任意站点直接提交一段 JSON（利用浏览器自动追加的 `=` 使其仍为合法 JSON），以受害者身份执行操作。

## 原理

- 普通 HTML 表单默认 `application/x-www-form-urlencoded`，会把 JSON 中的 `{`、`"`、`:` 等字符 URL 编码，后端无法按 JSON 解析；设置 `enctype="text/plain"` 后，浏览器按 `name=value` 原样拼接请求体，不做 URL 编码，Content-Type 也变成 `text/plain`，正好满足“只收 text/plain”的接口。
- 表单序列化会在每个字段名后追加 `=`（即使没有 value）。因此请求体末尾会多一个 `=`，破坏 JSON。构造 POC 时把 `'value='` 放到 name 属性中，利用 HTML 属性解析与序列化的差异，让浏览器生成的 `=` 落在 JSON 字符串值内部，最终请求体仍是合法 JSON。
- 跨站表单可以携带受害者的 Cookie（取决于 SameSite）；若 Cookie 为 `SameSite=Lax`，POST 跨站默认不发送，需要目标使用 `SameSite=None` 或旧浏览器；若为 `SameSite=Strict` 则不成立。
- Referer 校验的常见错误：函数 `hostOrRefererDifferentHost()` 在 Referer 缺失时返回 true（视为安全），或在 Referer 不含 Host 时返回 true；调用方又把 true 当作“继续处理”，于是外部站点 Referer 或空 Referer 反而通过，同源 Referer 被拒。这是判定方向写反，不是简单的“校验太弱”。
- 攻击者只需让受害者访问挂有 POC 的页面，表单可自动提交（`<body onload>` 或脚本 click），无需受害者交互。

## 触发条件

- 目标接口接受 `text/plain` 请求体，并按 JSON 解析（常见于 `@RequestBody String` + 手动 `ObjectMapper.readValue`）。
- 接口只依赖 Cookie 会话鉴权，没有 CSRF Token 或自定义请求头校验。
- Referer/Origin 校验缺失、可置空绕过，或方向写反（跨站/空 Referer 放行）。
- Cookie 的 SameSite 配置允许跨站 POST（None，或浏览器默认 Lax 但通过顶层导航/旧浏览器等条件）。

## 利用步骤

1. 抓取目标 JSON 请求，确认方法、路径、请求体 JSON 结构与必须字段。
2. 测试服务端接受的 Content-Type：改成 `text/plain` 是否仍能解析。
3. 测试 Referer/Origin：同源、跨站、置空三种情况下的响应差异，确认是否 fail-open。
4. 构造 `enctype="text/plain"` 的表单，把 JSON 放进 `name` 属性，按需插入 `'value='` 吸收多余的 `=`。
5. 将页面挂到攻击者站点，诱导/自动提交，观察目标是否以受害者身份执行。
6. 若被 URL 编码破坏，检查 enctype 是否生效、JSON 是否被多加了 `=`；必要时调整 token 位置。

## PoC

```html
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.example/api/feedback/message" method="POST" enctype="text/plain">
  <input type="hidden" name='{"name":"attacker","email":"a@b.c","content":"Web'value='Goat is the best!!"}'>
</form>
</body>
</html>
```

```text
# 浏览器实际发送（Content-Type: text/plain）：
# {"name":"attacker","email":"a@b.c","content":"Web=Goat is the best!!"}=
# 其中末尾的 = 被设计成落在 JSON 字符串内部/由解析器容忍，后端仍能解析为合法 JSON。
# 目标以受害者 Cookie 身份处理该请求。
```

## 变体与关联

- 变体：XML 接口同理，把 XML 放进 name 属性，用 `version'value='` 吸收多余的 `=`（经典的 text/plain XML CSRF）。
- 变体：`fetch` + `Content-Type: text/plain` 的“简单请求”可绕过预检，但受 CORS 限制无法带凭证读取响应；表单方式不需要 CORS。
- 变体：利用 302/307 重定向、`window.open`、`<img>`/`<script>` 触发的 GET 型 CSRF。
- 关联：[[web-generic-csrf-rpo-css-selector-side-channel]]（CSRF 与 CSS 选择器侧信道结合读取页面内容）。
- 关联：[[web-generic-auth-password-reset-host-header-poisoning]]（另一种利用请求头/链接的账户接管链）。
- 边界：目标强制 CSRF Token、校验 Origin 且严格拒绝空/跨站、或 Cookie 为 SameSite=Strict 时，该方式不成立。

## 检测与防御

- 修复：所有状态变更接口使用 CSRF Token（同步器令牌或双提交 Cookie），并校验 `Origin`/`Referer` 必须存在且与本站精确匹配；缺失时拒绝。
- 修复：JSON 接口只接受 `application/json`，拒绝 `text/plain`；同时要求自定义头（如 `X-Requested-With`）并做服务端校验。
- 加固：会话 Cookie 设置 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`；敏感操作二次确认。
- 检测：状态变更请求 Content-Type 为 text/plain、Referer/Origin 缺失或跨站、请求体为 JSON 但由表单提交；异常来源页面与高频操作。
