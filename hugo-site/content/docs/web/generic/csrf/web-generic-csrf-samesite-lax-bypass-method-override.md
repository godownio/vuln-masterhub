---
id: web-generic-csrf-samesite-lax-bypass-method-override
title: SameSite=Lax 绕过：顶级 GET 导航 + _method 方法重写执行状态变更
type: scenario
domain: web
path: web/generic/csrf
technique: samesite-lax-method-override-bypass
tags:
- web
- csrf
- samesite
- lax
- method-override
- get
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:07+08:00'
  notes: 已对照原文 Lax 绕过方法 1 正文核对（该节截图均为远程未下载）：GET 被拒后追加 _method=POST 重写成功，location 顶级 GET 导航载荷；卡片与原文一致。PoC 未执行。
url: /docs/web/generic/csrf/web-generic-csrf-samesite-lax-bypass-method-override/
draft: false
kb_aliases:
- SameSite Lax 绕过
- _method 方法重写 CSRF
- 顶级导航 GET CSRF
- samesite lax bypass method override
---

## 一句话结论

`SameSite=Lax` 的 Cookie 只在顶级 GET 导航时随跨站请求发送；如果敏感接口接受 GET，或框架支持 `_method` 参数重写请求方法（如 Symfony 的表单 `_method`），攻击者用顶级导航发起 GET、并附加 `_method=POST`（或反向）即可让 Lax Cookie 随请求到达服务端并完成状态变更。

## 原理

- **Lax 的放行条件**：浏览器只在“GET + 顶级导航”时给跨站请求附带 Lax Cookie；跨站 POST、iframe、img、XHR 等不携带。因此攻击者要让请求表现为顶级 GET 导航（`document.location`、链接、GET 表单）。
- **方法重写**：不少框架支持用参数覆盖 HTTP 方法（Symfony 表单 `_method`、Spring `HiddenHttpMethodFilter`、通用 `_method`/`X-HTTP-Method-Override`）。服务端路由看到的是重写后的方法，但浏览器实际发送的仍是 GET，于是 Lax 判定按 GET 顶级导航放行。
- **两种组合**：
  - 目标接口本身用 GET 完成写操作：直接 `location = ".../change-email?email=..."`
  - 目标接口要求 POST，但接受 `_method=POST`：`GET /change-email?email=...&_method=POST`
  - Symfony 表单路由要求 GET，但表单以 POST 提交并带 `_method=GET`：POST 会被 Lax 拦截，需配合其它条件；更常见的是上述 GET+`_method=POST`。
- **为什么成立**：SameSite 只看浏览器实际发出的方法与导航类型，框架再按重写后的方法执行业务；两层语义不一致导致防御被绕过。

## 触发条件

- 会话 Cookie 为 `SameSite=Lax` 或未显式设置（Chrome 默认 Lax）。
- 状态变更接口接受 GET，或框架启用 `_method`/`X-HTTP-Method-Override` 且未限制参数来源。
- 接口无 CSRF Token 或 Token 校验可按上述条件绕过。
- 攻击使用顶级导航（`location`、链接、GET 表单）。

## 利用步骤

1. 抓取正常修改请求，确认没有 CSRF Token；确认登录 Set-Cookie 未显式设置 SameSite（默认 Lax）。
2. 把请求改成 GET 发送；若被拒绝，尝试追加 `_method=POST`（或 `_method=PUT/DELETE`），观察是否 302/成功。
3. 构造攻击页：`location = "https://victim/change-email?email=attacker@evil.example&_method=POST"`。
4. 投递给已登录受害者；浏览器发起顶级 GET 导航，Lax Cookie 随请求发送，服务端按重写方法执行。
5. 验证：数据被修改；失败时检查 Cookie 是否真的 Lax、框架是否开启方法重写、是否限制 `_method` 只能来自表单。

## PoC

```html
<script>
  location = "https://victim.example/my-account/change-email?email=attacker@evil.example&_method=POST";
</script>
```

Symfony 表单方法重写（服务端要求 GET 时）示意：

```html
<form action="https://victim.example/account/transfer" method="POST">
  <input type="hidden" name="_method" value="GET">
  <input type="hidden" name="recipient" value="attacker">
  <input type="hidden" name="amount" value="1000000">
</form>
<script>document.forms[0].submit();</script>
```

注意：后一种跨站 POST 在 Lax 下通常不带 Cookie，仅在 Cookie 为 None/默认 Lax 的 120 秒窗口等条件下可用。

## 变体与关联

- [[web-generic-csrf-samesite-lax-120s-cookie-refresh-post-window]]：Lax 的另一条绕过（Chrome 顶级 POST 120 秒窗口）。
- [[web-generic-csrf-token-validation-request-method-get-bypass]]：服务端 GET 分支不校验 Token 的基础。
- [[web-generic-csrf-samesite-strict-bypass-client-side-redirect]]：Strict 场景下的同站第二跳思路。
- 变体：`X-HTTP-Method-Override`、`_method`、`method` 表单参数等框架差异；不同框架对重写方法的参数位置/大小写要求不同。
- 边界：Cookie 显式 `SameSite=Strict`、仅接受 POST 且禁用方法重写、校验 Origin/Referer 时链断。

## 检测与防御

- 检测：日志中出现带 `_method`/`X-HTTP-Method-Override` 的 GET 状态变更；框架方法重写过滤器开启且作用域过宽。
- 防御：状态变更只接受 POST/PUT/DELETE 并禁用或严格限制方法重写；所有写请求校验 CSRF Token；Cookie 显式设置 `SameSite=Lax/Strict`；校验 Origin/Referer。
- 响应：排查通过 GET/重写方法执行的写操作记录。
