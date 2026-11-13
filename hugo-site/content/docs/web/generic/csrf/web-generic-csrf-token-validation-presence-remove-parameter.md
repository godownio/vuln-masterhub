---
id: web-generic-csrf-token-validation-presence-remove-parameter
title: CSRF Token 仅在参数存在时校验：整体删除 csrf 参数即可绕过
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-token-validation-presence-dependent
tags:
- web
- csrf
- token
- parameter-removal
- session
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:32:49+08:00'
  notes: 已对照原文《CSRF Token 2》节与图16-23核对：改 csrf 值报 Invalid、csrf= 置空报 Missing parameter、整体删除 csrf 键后 302 成功并解题；空值与缺参区分准确。PoC 未执行。
url: /docs/web/generic/csrf/web-generic-csrf-token-validation-presence-remove-parameter/
draft: false
kb_aliases:
- CSRF Token 存在性绕过
- 删除 csrf 参数
- token validation depends on token being present
- 缺失参数跳过校验
---

## 一句话结论

当应用只在请求中存在 `csrf` 参数时才校验其值、参数整体缺失时直接跳过校验（例如 `token != null && !valid(token)` 才拒绝），攻击者从跨站表单中完全省略该字段即可让受害者的会话执行状态变更。

## 原理

- **存在性判断缺陷**：典型代码为 `String token = request.getParameter("csrf"); if (token != null && !token.equals(sessionToken)) reject();`——`null` 时条件短路，校验被跳过。框架层也可能只在检测到 Token 字段时启用校验。
- **与“空值”的区别**：空值 `csrf=` 通常仍会进入校验并报 “Missing parameter”；而“参数名整体不存在”在 Servlet API 中返回 `null`，走的正是跳过分支。因此绕过方法不是置空，而是删除整个键值对。
- **为什么成立**：CSRF Token 防御必须“默认拒绝”：没有令牌即视为非法；实现成“有令牌才检查”等于把防御变成可选。
- **验证要点**：分别测试“篡改 Token 值”“空值”“删除整个参数”三种情况，确认只有删除参数时返回 302/成功。

## 触发条件

- 状态变更接口依赖会话 Cookie 鉴权，CSRF 校验逻辑对参数存在性敏感（缺失即跳过）。
- 攻击者能构造不包含该参数的跨站请求（表单中不写该 input 即可）。
- 无其它令牌/Origin/Referer 强校验；Cookie 的 SameSite 不阻止该请求（POST 跨站需 Lax 例外或 None）。

## 利用步骤

1. 抓取正常 POST 请求，将其中的 `csrf` 值改错，确认返回 “Invalid CSRF token”。
2. 将 `csrf=` 置空，确认返回 “Missing parameter”。
3. 删除整个 `csrf=...` 键值对后重放，观察是否 302/成功且数据被修改。
4. 构造不含 csrf 字段的自动提交表单，托管后投递给受害者。
5. 验证：受害者数据被修改；失败时检查服务端是否对所有请求强制要求 Token、是否有 Origin 校验。

## PoC

```html
<html>
  <body>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

## 变体与关联

- [[web-generic-csrf-token-validation-request-method-get-bypass]]：另一类条件校验缺陷（只校验 POST）。
- [[web-generic-csrf-token-not-bound-to-session-cross-account-reuse]]：Token 存在也校验，但未绑定会话。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：完全无 Token 的基础场景。
- 变体：把参数名改成大小写变体/重复参数，观察解析器差异；某些框架将空数组/空字符串视为“未提供”。
- 边界：服务端对所有请求强制 Token（缺失即拒绝）时失效；SameSite=Strict 且无同站 gadget 时跨站 POST 不带 Cookie。

## 检测与防御

- 检测：代码审计搜索 `getParameter("csrf") != null`、`if (token != null && ...)` 等存在性分支；测试缺失参数是否改变响应。
- 防御：默认拒绝——请求缺少 Token 直接拒绝；Token 绑定会话、一次性或高熵；所有状态变更方法统一校验；配合 SameSite 与 Origin/Referer 校验。
- 响应：检查是否有缺少 Token 的成功写操作日志。
