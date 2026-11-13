---
id: web-generic-auth-login-resultcode-response-tamper-bypass
title: 前后端分离登录只信 resultCode：把失败响应改成 resultCode=0 直接进入后台
type: scenario
domain: web
path: web/generic/auth
technique: login-resultcode-response-tamper
tags:
- web
- auth-bypass
- client-side-trust
- response-tampering
- login
- spa
- src
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-11'
verification:
  verified_by: verifier-V505
  verified_at: '2026-11-11T04:09:45+08:00'
  notes: 已对照原文（content.md 全文+26/26 图）核对：img/18 登录请求、img/19 响应 data.resultCode 改 0（data.success 仍 false）、img/20 进入 890 用户后台与正文一致；已按截图修正 PoC 的 JSON 结构（原 PoC 误写为顶层 success 并把 resultMsg 改成登录成功，实际截图仅修改 data.resultCode，success 保持 false）。与 password-reset 响应篡改、module-permission-code-response-tamper 属不同阶段（登录/忘记密码/模块授权），非重复，保留。未验证点：PoC 未在目标执行，原始（篡改前）resultCode 值截图未展示。
  unverified:
  - PoC 未复现；原始响应业务码未展示；后台接口是否另有服务端鉴权未独立验证（原文 890 用户页已渲染）
url: /docs/web/generic/auth/web-generic-auth-login-resultcode-response-tamper-bypass/
draft: false
kb_aliases:
- 改返回包绕过登录
- resultCode 改 0
- 登录响应篡改
- 前端逻辑缺陷登录
- 客户端信任绕过登录
---

## 一句话结论

前后端分离系统登录时，后端返回 JSON 里的 `success:false`（位于 `data` 内）与业务码 `resultCode` 表示失败，但前端只根据 `resultCode`（或 HTTP 状态码）决定是否跳转后台；攻击者用 Burp 把响应中的 `resultCode` 改为 `0` 再放行，前端就认为登录成功并进入管理后台，绕过账号口令校验。

## 原理

- **前端承担了登录判定**：SPA 登录页拿到响应后，通常判断 `res.data.resultCode === 0`（或 `success`/`statusCode`/`code`）来决定是否保存登录态、跳转路由；真正的“是否通过认证”本应由服务端会话/Token 决定，但该实现把业务码当成了认证结果。
- **响应可被客户端修改**：HTTP 响应在到达浏览器前经过 Burp/代理，攻击者把 `resultCode` 从非 0（如 `1`/`1001`）改为 `0` 再放行，前端逻辑即走成功分支。原文截图（img/19.png）里 `data.success` 仍是 `false`、只有 `data.resultCode` 被改为 `"0"` 即放行，说明该前端只认 `resultCode`；其它系统也可能只看 `success`/`statusCode`，按实际判定字段修改即可。
- **为什么能进入后台**：原文改包后成功打开后台用户管理页（可见 890 个用户），说明后台页面/接口要么只依赖前端路由守卫，要么服务端接口未对会话做严格校验；若后续接口有独立鉴权，则只能看到页面壳，危害降级。
- **根因**：客户端信任 + 服务端未把认证状态作为唯一事实来源；登录接口返回的业务码不是服务端签发的凭证，前端也不应仅凭它授权。
- **与“忘记密码响应篡改”的区别**：本卡针对**登录**响应（进入后台），不是短信验证码/重置密码流程；但同属“客户端信任响应字段”的逻辑缺陷。

## 触发条件

- 目标为前后端分离/SPA 应用，登录接口返回 JSON，包含 `resultCode`/`code`/`success`/`statusCode` 等业务字段。
- 前端仅依据该字段决定是否登录成功/跳转后台，未校验服务端签发的会话/Token。
- 攻击者能拦截并修改登录响应（Burp/浏览器插件/中间代理）。
- 后台页面或接口没有独立、严格的服务端鉴权（否则只能绕过页面路由，无法获取数据/操作）。

## 利用步骤

1. 在登录页输入任意用户名/口令，抓取登录请求与响应。
2. 观察响应结构：原文为 `{"costs":70,"code":"0","data":{"resultCode":"<非0>","resultMsg":"<错误信息>","resultData":null,"success":false}}` 一类（success 在 data 内），记录业务码/成功标志字段。
3. 在 Burp 中拦截响应，把 `resultCode` 改为 `0`（或 `success:true`、`statusCode:200`），Forward 放行。
4. 观察前端是否跳转后台/保存登录态；若进入后台，浏览用户管理、配置等功能，确认页面与接口是否可用。
5. 若接口仍返回 401/403，说明仅绕过了前端路由，需继续寻找未授权接口或其它认证缺陷；若接口正常返回数据，则危害成立。
6. 记录请求/响应、修改前后字段与后台访问证据；仅在授权范围内测试。

## PoC

```http
POST /api/login HTTP/1.1
Host: target
Content-Type: application/json

{"username":"test","password":"wrong"}
```

```json
// 原始响应（示意；原文未展示篡改前的业务码）
{"costs":70,"code":"0","data":{"resultCode":"1","resultMsg":"<错误信息>","resultData":null,"success":false}}
```

```json
// Burp 修改后（按原文截图：仅 resultCode 改为 "0"，success 仍为 false，resultMsg 仍为乱码错误文案）
{"costs":70,"code":"0","data":{"resultCode":"0","resultMsg":"<错误信息>","resultData":null,"success":false}}
```

```text
# 放行后前端跳转后台，原文可见用户管理页（890 个用户）等后台功能。
```

原文目标与接口路径多处打码；原始响应业务码未展示，修改后响应按截图（img/19.png）还原；未在目标执行。

## 变体与关联

- 变体：改 `success`/`statusCode`/`code` 字段；改 HTTP 状态码 401→200；改 `role`/`isAdmin` 字段；改 `Set-Cookie`/token 响应。
- 变体：前端路由守卫只检查本地存储的 `isLogin` 标记时，直接写入 localStorage 也可绕过页面级守卫（服务端接口仍需鉴权）。
- 关联：[[web-generic-auth-password-reset-response-tampering-sms-bypass]]——同为客户端信任响应字段，但该卡是忘记密码短信验证流程；本卡是登录响应。
- 关联：[[web-generic-auth-cookie-login-response-splice-username-cookie]]（登录响应拼接身份 Cookie）、[[web-generic-auth-vue-router-frontend-guard-bypass]]（前端路由守卫绕过）。
- 边界：服务端接口独立鉴权、登录成功需服务端签发不可伪造 Token、前端不依据响应业务码授权时失效；仅绕过页面壳不构成实质危害。

## 检测与防御

- 检测：登录响应中出现 `resultCode`/`success` 等字段被客户端篡改的迹象（前端日志/网关响应与后端不一致）；同一账号短时间多次登录失败后突然进入后台。
- 检测：后台接口调用缺少有效会话/Token 但返回数据；前端路由跳转与后端会话状态不一致。
- 防御：认证结果由服务端会话/签名 Token 决定，前端不得仅凭响应业务码授权；所有后台接口做服务端鉴权与对象级授权。
- 防御：登录响应使用服务端签发的短期 token，前端只做展示层路由；对敏感接口校验 token 签名/有效期/会话绑定。
- 加固：前端路由守卫只作为用户体验，不作为安全边界；安全测试覆盖“改响应包/改本地存储/直接访问后台路由”三类绕过。
