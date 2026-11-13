---
id: web-generic-csrf-token-not-bound-to-session-cross-account-reuse
title: CSRF Token 未绑定会话：用攻击者账户的合法 Token 为受害者构造 CSRF
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-token-not-tied-to-user-session
tags:
- web
- csrf
- token
- session-binding
- cross-account
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:32:51+08:00'
  notes: 已对照原文《CSRF Token 3》节与图24-27核对：两账户 csrf 互换后 302 成功，证明 Token 未与会话绑定；全局 Token 池描述与原文一致。PoC 未执行。
url: /docs/web/generic/csrf/web-generic-csrf-token-not-bound-to-session-cross-account-reuse/
draft: false
kb_aliases:
- CSRF Token 未绑定会话
- 跨账户复用 CSRF Token
- 全局 Token 池
- token not tied to user session
---

## 一句话结论

当服务端维护一个全局已签发 Token 池、只校验请求里的 Token 属于该池而不校验它是否与当前会话绑定，攻击者可以登录自己的账户取得一个合法 Token，再把它放进针对受害者的跨站表单中，从而通过校验完成 CSRF。

## 原理

- **绑定缺失**：正确的 CSRF Token 应在生成时写入用户会话，并在校验时与会话中的值比较；缺陷实现只检查 `tokenPool.contains(token)` 或只在服务端全局缓存中查 Token 是否存在，任何账户签发的 Token 都有效。
- **攻击者视角**：攻击者拥有自己的低权限账户，可以正常获得 Token；该 Token 对任何会话都有效，因为它不与会话数据关联。CSRF 表单由受害者浏览器提交，携带的是受害者的会话 Cookie，Token 来自攻击者账户。
- **为什么成立**：CSRF 防御依赖“攻击者无法获知受害者会话对应的令牌”。一旦令牌跨会话通用，攻击者可以自给自足，防御退化为“是否有合法令牌”而不是“是否是受害者本人的令牌”。
- **验证要点**：准备两个账户，用账户 B 的 Token 替换账户 A 的请求 Token，若能成功修改账户 A 数据，即证明未绑定。

## 触发条件

- 应用有 CSRF Token，但校验时未与会话/用户绑定（全局池或仅校验签名/格式）。
- 攻击者可自行注册或拥有一个账户以取得合法 Token。
- 状态变更接口只依赖会话 Cookie 识别受害者，且无 Origin/Referer 强校验。
- 跨站请求能携带受害者 Cookie（Lax/None 或顶级导航）。

## 利用步骤

1. 注册/登录攻击者账户，打开同一状态变更表单，抓包取得 `csrf` 值。
2. 登录受害者账户（测试时用自己的第二个账户模拟），抓取修改请求，把 `csrf` 换成攻击者账户的值后重放。
3. 若返回 302/成功且数据被修改，说明 Token 未绑定会话。
4. 构造跨站表单：`email` 为攻击者想要的值，`csrf` 填攻击者账户的合法 Token，自动提交。
5. 投递给已登录受害者，受害者浏览器带会话 Cookie + 攻击者 Token，服务端校验通过并执行。
6. 验证：受害者数据被修改；失败时检查 Token 是否与会话绑定、是否一次性、是否有其它校验。

## PoC

```html
<html>
  <body>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
      <!-- 攻击者自己账户申请到的合法 token -->
      <input type="hidden" name="csrf" value="ATTACKER_VALID_TOKEN">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

## 变体与关联

- [[web-generic-csrf-token-validation-presence-remove-parameter]]、[[web-generic-csrf-token-validation-request-method-get-bypass]]：其它条件校验缺陷。
- [[web-generic-csrf-token-non-session-cookie-set-cookie-injection]]：Token 绑定到非会话 Cookie 的变体，需要配合 Cookie 注入。
- 变体：Token 绑定到用户 ID 但不绑定会话（同一用户多会话通用）；Token 可预测/可伪造时也可归入此类。
- 边界：Token 与会话严格绑定且一次性、服务端校验 Origin/Referer、Cookie 为 Strict 时链断。

## 检测与防御

- 检测：两个账户的 Token 能否互换；服务端是否只做全局池/格式校验；日志中出现同一 Token 跨多个会话使用。
- 防御：Token 生成时写入会话，校验时与当前会话值比较；Token 一次性或短有效期；所有状态变更统一校验；配合 SameSite 与 Origin/Referer 校验。
- 响应：检查跨会话 Token 复用记录，评估受影响账户范围。
