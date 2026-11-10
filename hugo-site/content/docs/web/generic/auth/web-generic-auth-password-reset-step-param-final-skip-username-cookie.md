---
id: web-generic-auth-password-reset-step-param-final-skip-username-cookie
title: 密码找回多步流程把进度放在客户端：把请求里的 step 直接改成最后一步（如 4）跳过短信/邮箱校验，并篡改 USERNAME_COOKIE（可能 base64）指到受害者，即可改他人密码
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-client-step-param-skip-username-cookie-tamper
tags:
- web
- auth
- password-reset
- business-logic
- step-bypass
- cookie-tampering
- account-takeover
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:08+08:00'
  notes: 已对照原文核对；案例 4「跳过验证」的三种形态——记住最后设置新密码页面 URL 直接回访、修改 USERNAME_COOKIE（正文注明可能经过 base64 编码）、把请求里的 step 参数改成最后一步（示例 4）——与正文逐条对应；卡片把「跳过 steps」与「身份标识指向受害者」分开验证再组合的写法，也与正文「改密码页面抓包，修改其中的 USERNAME_COOKIE 为其他用户，提交即可修改其他用户密码」一致；本次核对未读取图片，16 张图（含 img/14 抓包截图）未读图核对；原文未给出接口路径、参数名以外的字段与回显，卡片 PoC 中的 /user/resetPassword、字段名为示意占位，故保留 confidence=low；未对文中任何目标发包或访问 URL
url: /docs/web/generic/auth/web-generic-auth-password-reset-step-param-final-skip-username-cookie/
draft: false
kb_aliases:
- step 参数跳过验证
- 跳过找回密码验证步骤
- 直接访问设置新密码页面
- USERNAME_COOKIE 篡改
- 流程跳过类漏洞
- 多步重置流程无服务端状态
---

## 一句话结论

当「找回密码」被实现成纯前端驱动的多步向导（输入账号 → 校验短信/邮箱 → 设置新密码），而服务端不在会话里记录「当前进行到第几步」、只按请求里的 `step` 字段决定执行哪个分支时，攻击者跳过前面的校验步骤：把最后一次提交里的 `step` 直接改成最终步骤编号（示例为 `4`），或者先正常走完一遍记下「设置新密码」页面的 URL，再用受害者的账号重新发起流程后直接访问该 URL；如果流程还用 `USERNAME_COOKIE` 这类客户端可写的 Cookie 标识待重置用户（有时只是 base64），把它的值换成受害者用户名即可把重置落到他人账号上。

## 原理

- **步骤状态放在客户端**：多步表单通常用 `step=1/2/3/4` 之类字段告诉后端「这次请求属于哪一步」。如果后端只是 `switch(step)` 分发处理逻辑、却不校验「该会话是否真的完成了前面几步」，那么任何一步都可以被单独调用，等价于把校验步骤全部删除。
- **为什么必须服务端持有状态**：`step` 是请求参数，属于攻击者完全可控的输入。真正的进度必须由服务端在会话/数据库中推进（例如只在短信校验成功后把 `reset_stage` 置为「已通过」），并且最终设置密码时只读这个服务端状态，而不读请求里的 `step`。
- **「记住最终页面 URL 再回访」是同一个缺陷的另一种触发面**：第 4 步（设置新密码）页面本身如果只凭 URL 里的会话/参数就能打开，且该页面提交时不重新校验前序步骤，那么即使不做参数篡改，直接用已知 URL 也能直达。这类「跳过验证步骤、找回方式、直接到设置新密码页面」的形态在逻辑漏洞里非常常见。
- **用户名从客户端来**：`USERNAME_COOKIE`（或 `user`、`account`、`reset_user` 之类的 Cookie/隐藏字段）被服务端当作「本次要重置谁」的依据时，攻击者改成受害者用户名即可。若该值经过 base64 或简单编码，先解码看清结构再改回编码，避免直接改坏格式导致请求被拒。
- **两者叠加才构成接管**：只跳过步骤通常仍需要「重置的是自己的账号」才算无害；只有「跳过校验 + 目标用户可控」同时成立，才能重置他人密码。所以测试时要分别验证：`step` 是否可跳、身份标识是否可改，再看组合效果。

## 触发条件

- 找回密码为多步流程，请求中出现 `step`/`stage`/`phase` 之类步骤参数。
- 服务端不校验步骤顺序（无服务端会话状态、无一次性步骤 token），或可重复提交已完成的步骤。
- 「设置新密码」的提交里带用户名/用户标识（Cookie、隐藏字段、JSON 字段），且服务端用它定位用户而不与会话绑定。
- 攻击者能触发给目标的找回流程（知道目标用户名/手机号/邮箱），且重置接口无短信/邮箱二次校验、无验证码限制。

## 利用步骤

1. 用自己的账号完整走一遍找回流程，逐步抓包，记录每一步的 URL、请求参数（尤其 `step` 的取值序列）以及 Cookie 变化。
2. 定位「设置新密码」这一步：记录其 URL 与提交参数；观察参数里是否带用户名/用户 ID，Cookie 里是否有 `USERNAME_COOKIE`、`user`、`account` 等字段。
3. 换一个自己的其他账号，在未完成前序校验的情况下，直接把请求里的 `step` 改成最后一步（示例为 `4`）提交，看是否直接进入改密成功分支（对照正常流程的响应差异）。
4. 若第 3 步只对自己生效，再篡改身份标识：把 `USERNAME_COOKIE` 的值换成受害者用户名（若 Cookie 值看起来是 base64，先解码确认是明文用户名，改后重新编码）。
5. 组合提交：`step` 设为最终步骤 + 身份标识指向受害者 + 新密码，观察是否返回成功；随后用新密码登录受害者账号验证接管。
6. 若 `step` 不可改，尝试第 2 步记录的「设置新密码」URL 直接访问（保持受害者流程的会话参数），验证页面是否可直达并提交成功。
7. 成功后立即停止并记录证据；评估是否影响管理员账号（可把身份标识改为 `admin` 再做一次受控验证）。

## PoC

原始报文无公开引用，篡改形态如下（字段名按实际接口替换）：

```http
POST /user/resetPassword HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: USERNAME_COOKIE=<base64(受害者用户名)>; SESSION=<自己的会话>

step=4&username=<受害者>&newPassword=Evil%40123&confirmPassword=Evil%40123
```

对照基线（正常流程的最后一步，身份为自己）：

```http
step=4&username=<自己>&newPassword=MyNewPwd&confirmPassword=MyNewPwd
```

判据：不携带任何短信/邮箱校验结果，仅凭 `step=4` 即返回「密码修改成功」，且用新密码能登录目标账号。

## 变体与关联

- 参数变体：`step` 可换成 `stage`、`phase`、`action=reset_finish`、`next=finish`；也有实现用 `success=true`、`verified=1` 之类布尔字段表示「已通过校验」，同样可篡改。
- 身份标识变体：Cookie（`USERNAME_COOKIE`/`user`/`uid`）、隐藏字段（`<input type="hidden" name="username">`）、JSON body 字段；编码可能是 base64、URL 编码、或「用户名 + 分隔符 + 时间戳」。
- 直达页面变体：记住「设置新密码」页面 URL 后回访，或在未完成前序步骤时直接请求最终提交接口（与 `step` 篡改等价）。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（身份标识可改但步骤正常）、[[web-generic-auth-digital-lock-client-validate-step-skip]]（前端暴露校验函数导致的步骤跳过）、[[web-generic-auth-password-reset-response-tampering-sms-bypass]]（改响应体 `success` 跳过短信校验）。

## 检测与防御

- **服务端状态机**：重置进度必须存在服务端（会话或带 TTL 的记录），每步成功后推进；最终改密只读服务端状态，忽略请求里的 `step`/`success`/`verified`。
- **一次性步骤凭证**：短信/邮箱校验成功后下发一次性 token，最终提交必须携带且只能用一次，token 与用户绑定。
- **身份绑定**：待重置用户由服务端会话决定，禁止从 Cookie/隐藏字段读取用户名；若必须传递，做签名（HMAC）而非裸 base64。
- **直达防护**：设置新密码页面要求有效的一次性 token，缺失即跳回第一步；对最终提交接口做「前序步骤已完成」校验。
- **检测信号**：同一会话在极短时间内从 `step=1` 跳到最终步骤；`step` 值非法或超出流程范围；`USERNAME_COOKIE` 与会话用户不一致；重置成功但全程没有短信/邮箱校验请求。
