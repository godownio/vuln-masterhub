---
id: web-generic-xss-request-header-html-attribute-breakout
title: HTTP 请求头（Referer 等）回显未转义导致 XSS：隐藏 input value 属性闭合注入事件处理器
type: scenario
domain: web
path: web/generic/xss
technique: request-header-html-attribute-breakout
aliases:
- Referer 头 XSS
- 请求头注入 XSS
- 隐藏 input 属性闭合
- value 属性逃逸
- 后台日志 XSS
tags:
- web
- xss
- reflected-xss
- http-header
- referer
- attribute-breakout
- admin-panel
severity: medium
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

当服务端把 Referer、User-Agent 等请求头的值未经 HTML 实体编码直接回显进页面（如 `<input name="t_ref" value="...">` 的 value 属性或管理后台日志页），攻击者用 `type="test" onclick="alert(1)` 这类不含尖括号的 payload 闭合 value 属性并注入事件处理器即可触发 XSS。

## 原理

请求头由客户端完全可控，许多应用会把 Referer/User-Agent 写入隐藏表单域、统计页或管理后台日志展示页。这些输出点通常对 `<` `>` 做了过滤或开发者认为头注入需要尖括号，但 HTML 属性值内的双引号闭合并不需要尖括号：payload `type="test" onclick="alert('test')` 进入 `value="..."` 后，第一个 `"` 提前结束 value 属性，随后 `type`、`onclick` 被解析为该 input 的新属性，浏览器加载解析该元素时 onclick 即执行。对后台日志类场景，头被持久化存储，管理员浏览日志时在高权限上下文触发，等效存储型 XSS。

## 触发条件

1. 目标页面将某个请求头（Referer/User-Agent/X-Forwarded-For 等）的值直接拼入 HTML（属性值或正文）且未做 HTML 编码；
2. 攻击者可诱导受害者（或管理员）携带恶意请求头访问该页面——可通过发起跨站请求自动携带 Referer、或直接对记录日志的接口发恶意请求；
3. 后台日志场景还需管理员浏览日志页这一步骤。

## 利用步骤

1. 定位回显点：观察响应 HTML 中哪个字段取自请求头（如 hidden input 的 value）；
2. 构造不含尖括号的属性闭合 payload，例如 Referer: `type="test" onclick="alert('test')`；
3. 发出携带该头的请求（Referer 可由受害用户点击构造链接或 `<img>` 等自动触发）；
4. 受害者/管理员浏览到含注入的页面，事件处理器执行，可进一步外带 Cookie 或以管理员身份执行操作。

## PoC

```
Referer: type="test" onclick="alert('test')"
```

注入后页面出现 `<input name="t_ref" value=""type="test" onclick="alert('test')" type="hidden">`，onclick 触发弹窗（靶场 xss-labs level11 实测验证）。

## 变体与关联

- JS 字符串上下文变体：头拼入 `location.href='...'` 或 JS 变量时用 `';alert(1);//` 闭合，见同库 Referer 头反射型 XSS 卡；
- X-Forwarded-For/Username 写入日志后台形成的存储型 XSS（管理员查看时触发）；
- User-Agent 注入管理后台日志页同理；
- 与 CSRF 组合可将事件处理器替换为自动提交敏感操作的 fetch。

## 检测与防御

- 检测：对所有请求头回显点 fuzz 含双引号但不含尖括号的 payload；在后台日志页重点检查；
- 防御：请求头写入 HTML 前一律做上下文相关的 HTML 实体编码（至少 `& " ' < >`）；hidden input 改用服务端 session 存储来源而非法从客户端头回显；后台日志展示页启用输出编码与 CSP。
