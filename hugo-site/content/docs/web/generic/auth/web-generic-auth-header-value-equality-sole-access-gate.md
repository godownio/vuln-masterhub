---
id: web-generic-auth-header-value-equality-sole-access-gate
title: 隐藏接口只比对某个请求头的字面值：把 UA 或 X-Requested-With 改成目标期望的字符串即可越过 403
type: scenario
domain: web
path: web/generic/auth
technique: header-value-equality-sole-access-gate
tags:
- header
- auth-bypass
- user-agent
- x-requested-with
- 403
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:37:20+08:00'
  notes: '已对照原文核对；本次核对未读取图片；/agent-access 的提示语「Not FBI-SiteAccess-Authorized-Agent. Unauthorized access detected.」、改为 User-Agent: FBI-SiteAccess-Authorized-Agent、以及 /flag 需 X-Requested-With: XMLHttpRequest（源码 request.headers.get(X-Requested-With) == XMLHttpRequest）、XSS 中需显式 setRequestHeader 均与原文一致。原理段「该头只由浏览器在 XHR/fetch 自动添加」表述不准（原生 XHR/fetch 默认不加，jQuery 才加），原文自己的 403 实验也印证了这一点，无碍利用写法，建议改写。未验证点：靶机已下线，PoC 未复跑'
url: /docs/web/generic/auth/web-generic-auth-header-value-equality-sole-access-gate/
draft: false
kb_aliases:
- User-Agent 相等校验
- FBI-SiteAccess-Authorized-Agent
- X-Requested-With XMLHttpRequest 门槛
- 仅允许 AJAX 访问
- 请求头当访问票据
---

## 一句话结论

有些“隐藏接口”根本不校验身份，只校验一个请求头的值是否等于某个固定字符串：把 `User-Agent` 改成页面提示的 `FBI-SiteAccess-Authorized-Agent`，或给请求补上 `X-Requested-With: XMLHttpRequest`，403 立刻变成 200。请求头是客户端完全可控的输入，凡是拿它当唯一门槛（而不是配合会话/签名）的鉴权都等价于没有鉴权；发现它的方式通常是读前端源码、看 403 提示文案，或用 XHR 与普通请求的差异做对比。

## 原理

- **门槛落在客户端可控值上**：服务端判断 `request.headers.get("X-Requested-With") == "XMLHttpRequest"`，或 `User-Agent` 必须等于某个魔法字符串时，判定依据完全由攻击者书写，构造同值请求头即可通过。
- **XHR 门槛的常见意图**：开发者想“只让页面内 JS 调用、不让用户直接打开”，于是检查 `X-Requested-With`。这个头只由浏览器在 XHR/fetch（部分库）中自动添加，curl/浏览器地址栏不会带，因此可以挡住“直接访问 URL”，但挡不住任何人手工补上——它是一致性检查，不是认证。
- **UA 门槛的常见意图**：想让“只有合作方/内部代理/特定客户端”能访问（如只允许某个采集器、内部网关），把预期 UA 硬编码进判断。UA 可任意伪造，等于把口令写在了公开的前端代码或 403 文案里。
- **为什么容易发现**：门槛值往往就写在提示语或前端 JS 里（`Not FBI-SiteAccess-Authorized-Agent. Unauthorized access detected.` 直接把期望值念出来），或者从前端 `XMLHttpRequest` 调用能正常工作、而等价 curl 请求 403 的差异反推。
- **与真正认证的差别**：正常做法是服务端会话/签名票据 + 角色校验；请求头只应作为“附加信号”（如 CSRF 防护的 `X-Requested-With` 配合 SameSite Cookie、或配合服务端签发的 CSRF token），单独作为门槛时不具备任何安全性。

## 触发条件

- 目标存在一个未在导航中暴露的接口，直接访问返回 403 或 “Access Denied”。
- 服务端的判定是“某个请求头的值等于固定字符串”（可从提示文案、前端源码或响应差异推断）。
- 攻击者能自行构造请求（burp/curl/浏览器插件），无 WAF 针对该头的额外校验。

## 利用步骤

1. 从前端 JS、页面注释、403 响应体或目录扫描结果里找出隐藏路径（如 `/agent-access`、`/flag`）。
2. 直接请求，记录 403 文案；文案里若出现形如 “Not <某个字符串>” 的描述，该字符串很可能就是期望的头值。
3. 用 burp 拦截该请求，把 `User-Agent` 整体替换为期望值（注意不能是追加，必须是完全相等），放行；或在请求里新增 `X-Requested-With: XMLHttpRequest`。
4. 观察状态码与响应体变化；若仍 403，换大小写/去空格/试 `X-Requested-With: XMLHttpRequest` 与其他常见值（`XMLHttpRequest`、`fetch`、`1`）。
5. 拿到数据后继续用同一头访问相邻的隐藏接口（同一套门槛常被复制到多个路由），把单点绕过扩展成整片接口暴露。
6. 若目标是 XSS 场景：普通 `<script>` 内的 XHR 默认不带该头，需在 `xhr.open()` 之后显式 `xhr.setRequestHeader('X-Requested-With','XMLHttpRequest')` 才能读到受保护资源。

## PoC

```http
GET /agent-access HTTP/1.1
Host: target
User-Agent: FBI-SiteAccess-Authorized-Agent
```

```http
GET /flag HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
```

```javascript
// 若从页面内 XSS 上下文取受保护资源，必须显式补头
var xhr = new XMLHttpRequest();
xhr.open('GET', '/flag', true);
xhr.withCredentials = true;
xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
xhr.onload = function () { console.log(xhr.status, xhr.responseText); };
xhr.send();
```

## 变体与关联

- **头的种类变体**：`Referer` 必须来自站内、`Origin` 必须匹配、`X-Forwarded-For` 必须是内网段、自定义头 `X-Internal: 1`、`X-Original-URL` 覆盖路径（见 [[web-generic-auth-xforwarded-for-ip-whitelist-bypass]]）。
- **值来源变体**：期望值可能不在提示文案里，而写在前端打包产物、`robots.txt`、注释、错误页堆栈中；也可用“同一接口的正常前端调用”抓包直接照抄。
- **组合绕过**：头校验 + 路径匹配粗糙时，可用改写方法/加尾斜杠进一步绕（见 [[web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass]]）。
- **关联**：[[web-generic-auth-unsigned-cookie-admin-keys]]（另一种“把判定依据放到客户端”的形态）、[[web-generic-auth-cookie-plaintext-role-flip]]（Cookie 明文改角色）。
- **边界**：门槛值同时绑定会话票据、HMAC 签名或服务端不可预测的 nonce 时，本手法失效；反向代理若强制剥离/覆写该头（如统一重写 UA），伪造也无效。

## 检测与防御

- **代码审计**：全局搜索 `headers.get("User-Agent")`、`X-Requested-With`、`Referer`、`Origin`、`X-Forwarded-For` 与常量字符串的相等比较，凡是“比较通过即放行敏感逻辑”的分支都要标记；重点看是否有 `==`/`equals` 后再无其他鉴权。
- **修复**：敏感接口一律走会话/签名票据 + 角色校验；`X-Requested-With` 只能作为 CSRF 的辅助信号，且必须与 SameSite Cookie、CSRF token 组合使用。
- **加固**：反向代理层统一覆写 `User-Agent`/`X-Forwarded-For`，禁止客户端自带值直传后端；把“隐藏路由”改为真实鉴权，不依赖隐蔽性。
- **检测（流量）**：`User-Agent` 出现与业务客户端完全一致的罕见长串、`X-Requested-With` 出现在浏览器不会发送的请求（如 curl/扫描器指纹）中、同一 IP 对多个隐藏路径短时间连续 403→200，都是探测特征。
