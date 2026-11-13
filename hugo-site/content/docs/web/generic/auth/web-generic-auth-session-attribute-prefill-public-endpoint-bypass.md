---
id: web-generic-auth-session-attribute-prefill-public-endpoint-bypass
title: 未授权业务接口预置 session 鉴权属性：先访问 /index2 写入 user，再访问只判属性非空的 /index1 即放行
type: scenario
domain: web
path: web/generic/auth
technique: session-attribute-prefill-public-endpoint-auth-bypass
tags:
- web
- java
- servlet
- session
- auth-bypass
- attribute
- logic-flaw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V696
  verified_at: '2026-11-13T18:22:46+08:00'
  notes: '已对照原文与全部37图核对：图11 /index1 仅判 session.getAttribute("user")!=null 并重定向 /index1/yes|no，图12 /index2 无需认证直接 req.getSession().setAttribute("user", user.getUsername())，图13 响应 Set-Cookie: JSESSIONID，图14 带 Cookie 请求 /Test18/index1 返回 302 Location: /Test18/index1/yes，与卡内结论/PoC 一致（截图中两次 JSESSIONID 值不同，属作者两次会话截图，不影响原理）。与 servlet-null-role-fail-open 的 dedup 复核：候选为 null 属性导致布尔表达式 fail-open、无需写入点；本卡为公开接口主动写入属性使非空判断成立，根因与利用顺序均不同，不合并成立。其余 skipped 场景（token base64 伪造、AES 硬编码、catch 默认 true、前端 login 响应、yml 后缀/..、@PassTokenAnno、endsWith/contains/antMatch、正则 \r\n）抽查对应已验证卡均存在且同场景，merge/不新增合理。未验证点：未复跑请求，原文未给组件版本，未设 affected_versions 正确。'
url: /docs/web/generic/auth/web-generic-auth-session-attribute-prefill-public-endpoint-bypass/
draft: false
kb_aliases:
- session 属性预置
- setAttribute("user") 绕过
- getAttribute 非空即放行
- 会话状态注入
- 先访问 index2 再访问 index1
---

## 一句话结论

当受保护页面只判断 `session.getAttribute("user") != null` 作为登录态，而另一个无需认证的业务接口会主动 `session.setAttribute("user", ...)` 时，攻击者先访问该公开接口让服务端在会话里写入 `user`，再带着同一个 `JSESSIONID` 访问受保护页面，属性非空即通过鉴权（本例访问 `/index2` 后再访问 `/index1`，服务端返回 302 到 `/index1/yes`）。

## 原理

- **登录态表示错误**：把“session 中存在某个业务属性”等同于“用户已认证”。属性本身没有签名、没有与登录事件绑定，任何能拿到 `HttpSession` 的代码路径都可以写入它。
- **存在未授权的写入点**：`/index2` 是一个无需登录即可访问的业务接口（示例中是展示页），其控制器执行 `req.getSession().setAttribute("user", user.getUsername())`，把用户名写进当前会话；这一步不需要任何凭据。
- **会话在同一浏览器/同一 JSESSIONID 下延续**：服务端为 `/index2` 的请求创建会话并返回 `Set-Cookie: JSESSIONID=...`；攻击者把该 Cookie 带到 `/index1`，服务端读取到同一个 session，`getAttribute("user")` 非空 → 判定已登录 → 放行并重定向 `/index1/yes`。
- **与 Cookie 伪造的区别**：不需要知道密钥或签名算法，也不需要构造身份数据；攻击者只是按正常业务顺序访问两个接口，利用服务端自己写入的会话状态。
- **为什么常见**：开发常把“游客信息、临时用户对象、主题偏好”等写进 session，却用同一个属性名或同一个“非空判断”作为认证标记；只要属性名碰撞或鉴权逻辑粗糙，就能升级为认证绕过。

## 触发条件

- 受保护接口的鉴权逻辑仅检查某 session 属性是否存在/非空（不校验角色、来源、登录时间或服务端认证标记）。
- 存在无需认证、可被外部访问且会向 session 写入同名属性的接口（如 `setAttribute("user", ...)`）。
- 两个接口属于同一 Web 应用/同一会话域，攻击者能保存并重放 `JSESSIONID`。
- 写入的属性值无需真实（即使是用户名、游客标识或任意字符串）也能通过非空判断。

## 利用步骤

1. 审计/黑盒定位受保护接口：观察其鉴权代码是否为 `if (req.getSession().getAttribute("user") != null)` 一类判断（本例 `/index1`）。
2. 全局搜索 `setAttribute("user"` / `getSession()` 写入点，找出无需登录即可访问的接口（本例 `/index2`）。
3. 用干净会话请求该公开接口，记录响应中的 `Set-Cookie: JSESSIONID=...`。
4. 携带该 `JSESSIONID` 请求受保护接口，观察是否返回放行（本例 302 `Location: /index1/yes`）。
5. 以该会话继续访问后续受保护功能；若属性名不同，可按同一思路寻找其它可写属性或键名碰撞。

## PoC

```http
# 1) 未登录访问公开接口，服务端把 user 写入 session
GET /Test18/index2 HTTP/1.1
Host: target
# 响应：302/200 + Set-Cookie: JSESSIONID=<sid>

# 2) 带同一会话访问受保护接口
GET /Test18/index1 HTTP/1.1
Host: target
Cookie: JSESSIONID=<sid>
# 响应：302 Location: /Test18/index1/yes（判定 user 非空，未登录也放行）
```

```java
// /index2：无需认证的业务接口，写入 session 属性
@RequestMapping("/index2")
public void hello(HttpServletRequest req, HttpServletResponse resp) {
    User user = new User();
    user.setUsername("novy");
    req.getSession().setAttribute("user", user.getUsername());
}

// /index1：只判断属性是否存在/非空
if (req.getSession().getAttribute("user") != null) {
    resp.sendRedirect(req.getContextPath() + "/index1/yes");
} else {
    resp.sendRedirect(req.getContextPath() + "/index1/no");
}
```

## 变体与关联

- 变体：其它“错误处理/拒绝逻辑顺带写 session”的路径——如禅道 `deny()` 先把 `$app->user` 写入 session，随后被 API 入口信任（[[web-generic-auth-zentao-qvd-2024-15263-testcase-deny-session-user-bypass]]）。
- 变体：session 角色属性为 null 时布尔表达式 fail-open（[[web-generic-auth-servlet-null-role-fail-open]]）。
- 变体：会话固定——攻击者先取得/固定一个 `JSESSIONID`，再诱导受害者登录使其具备认证属性；本卡是服务端可直接写入、无需受害者。
- 关联：[[web-generic-auth-cookie-base64-identity-forgery]]（客户端侧身份伪造）、[[web-generic-auth-sessionfilter-username-cache-key-session-hijack]]（会话键取值不当）。
- 边界：受保护接口同时校验角色/签名/服务端登录标记、公开接口写入的属性名与鉴权属性不同、或写入接口本身需要认证时，本场景不成立。

## 检测与防御

- 检测：同一 `JSESSIONID` 在未登录状态下先访问公开的 `setAttribute` 接口、随后访问受保护接口；日志中出现“无登录事件但 session 属性被写入后访问管理页”的序列；公开接口对 session 的写操作。
- 防御：登录态必须由认证流程设置专门标记（如 `LOGIN_SUBJECT`）并与用户主体绑定，不能以任意业务属性存在性判断；业务临时数据与认证数据分命名空间存放。
- 加固：对写 session 的公开接口做最小化与审计；拦截器校验角色/权限而不只是非空；对同一 session 的认证状态变化做服务端记录。
