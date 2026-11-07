---
id: ctf-web-bot-xss-role-gated-debug-sqli-escalation
title: CTF Bot 链：superbot 页面 XSS 打角色受限 debug SQL 注入点，堆叠 UPDATE 提权读 Flag
type: scenario
domain: ctf
path: ctf/web
technique: bot-xss-role-gated-debug-sqli-privilege-escalation
aliases:
- ScrapScrap I Revenge
- ASIS CTF 2025 ScrapScrap
- XSS to SQLi 提权
- debug/create_log SQL 注入
- superbot XSS 改 role
- bot 会话打 debug 接口
tags:
- ctf
- web
- xss
- sqli
- bot
- privilege-escalation
- sqlite
- exploit-chain
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:38+08:00'
  notes: 已对照原文与 img/01-07 核对 ScrapScrap 的角色 demo/user、/debug/create_log 的 INSERT 拼接与 SQLite exec 多语句、XSS 用 bot 会话发同源 POST 堆叠 UPDATE id=2、以及 8 秒定时器/挂起 URL 条件；原稿“每次请求重新读取”已修正为“重新登录/会话刷新生效”。未验证点：未复跑；依赖目标 session/bot 实现。
---

## 一句话结论

在 bot 以较高角色访问页面的场景中，攻击者先用页面 XSS 在 bot 会话里发起同源请求，打到一个只有 `role=user` 才能访问、且把输入拼接进多语句 SQL `exec` 的 debug 接口，用堆叠 `UPDATE` 把自己的 `demo` 账号改成 `user`，随后访问角色受限页面读取 Flag。

## 原理

- 应用用 `req.session.user.role` 做角色判断：普通注册用户默认 `demo`，bot（如 `superbot`）初始化为 `user`；`/scrap` 由中间件要求 `role=user` 才能渲染 Flag。
- `/debug/create_log` 同样先检查 session 的 `role === "user"`，然后把 `req.body.log` 直接拼进 `INSERT INTO logs VALUES('${log}')`，使用 SQLite 的 `database.exec` 执行；`exec` 支持多条以分号分隔的语句，且黑名单只拒绝 `/`、`-` 和长度超过 50 的输入。
- 攻击者自己的 `demo` 会话不能直接调用该接口（会被重定向），但 XSS 在 bot 的浏览器会话中执行；同源 `fetch('/debug/create_log')` 会自动携带 bot 的 session cookie，于是通过角色检查。
- 注入 payload `');UPDATE users SET role="user" WHERE id=2;SELECT` 先闭合原来的字符串和 `VALUES(...)`，追加一条 `UPDATE` 把 id=2（攻击者注册的账号）的 `role` 改成 `user`，末尾的 `SELECT` 用来消化模板后面追加的 `')` 片段。
- 角色存储在服务端（数据库/会话），UPDATE 后重新登录（或会话刷新）即可生效；攻击者再以自己的会话访问 `/scrap`，即满足 `role=user` 并拿到 Flag。
- 该链的关键是“特权 bot 的浏览器上下文 + 只有特权角色可达的注入接口”：SQL 注入本身对 demo 用户不可达，必须借 bot 的会话才能触达。

## 触发条件

- bot 以 `role=user`（或更高）登录并访问攻击者可控的 URL；
- 目标 origin 上存在 XSS（本例为 DOMPurify `textContent`→`innerHTML` 二次解析链）；
- XSS 能向同源 debug/管理接口发起请求，且接口没有额外 CSRF token 或 XSS 可读取 token；
- SQL 接口使用支持多语句的数据库/驱动（SQLite `exec`、MSSQL、MySQL multi-statement 等），且只做弱黑名单；
- 角色来自服务端会话/数据库，提权后重新登录（或会话刷新）即可生效；
- 若 XSS 在延迟回调中执行而页面会因表单提交导航，需要让被提交的抓取 URL 保持挂起（慢响应/连接池耗尽）到定时器触发。

## 利用步骤

1. 注册普通账号，确认其用户 id（本例为 2）和默认 `role=demo`。
2. 找到 bot 的访问入口（本例 `/checker` 的 visit 逻辑：bot 登录后访问用户提交的 URL）。
3. 让 bot 访问带 XSS 的页面，在 bot 会话中执行同源请求：
   ```javascript
   fetch('/debug/create_log', {
     method: 'POST',
     body: new URLSearchParams({log: `');UPDATE users SET role="user" WHERE id=2;SELECT`})
   });
   ```
4. 确认 `UPDATE` 成功（可重新登录查看 `/scrap` 是否返回 Flag）。
5. 延迟触发场景：把 bot 要抓取的 URL 指向自己服务器上一个 sleep 8 秒以上的接口，或建立大量挂起连接占满浏览器连接池，使 `form.submit()` 的导航保持 pending，旧文档里的 `setTimeout` 才能执行 XSS。

## PoC

```html
<!-- 放在 url 参数中的 XSS；HTML 属性内的双引号需写成 &quot; -->
<img src=x onerror="fetch('/debug/create_log',{method:'POST',body:new URLSearchParams({log:'\');UPDATE users SET role=&quot;user&quot; WHERE id=2;SELECT'})})">
```

```javascript
// 等价的 JS 核心；log 长度 49，且不含 / 和 -
const log = `');UPDATE users SET role="user" WHERE id=2;SELECT`;
fetch('/debug/create_log', {method: 'POST', body: new URLSearchParams({log})});
```

## 变体与关联

- 若 id 不确定，可把 `WHERE id=2` 换成 `WHERE username='attacker'`（注意长度与禁用字符限制）；若不能堆叠，可尝试 `INSERT OR REPLACE`、子查询或先做布尔/时间盲注确认。
- 角色若保存在 JWT/签名 cookie 中，需要改打签名或密钥问题，本卡只适用于服务端会话/数据库角色。
- 连接池挂起技巧也适用于其它“定时器在导航后触发”的 XSS：用不返回的响应或大量挂起请求拖住导航。
- 关联：[[web-generic-xss-dompurify-textcontent-innerhtml-reparse]]（本例使用的 XSS 原语）、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（另一类角色参数篡改）、[[ctf-web-bot-jku-csp-crlf-cookie-hijack-chain]]（同为 bot 链，但目标是窃取 Cookie 而非改数据库角色）。
- 边界：bot 使用独立 origin、debug 接口有不可绕过的 CSRF token、数据库驱动不允许堆叠语句、或角色从不可写的外部身份源读取时，链断裂。

## 检测与防御

- 删除或锁定 debug/管理接口，至少不要在生产开放；SQL 全部参数化，禁用多语句执行。
- 授权检查放在服务端统一授权层，不依赖 session 中可被数据库写入的普通字段；对角色变更做审计与二次确认。
- bot 不要用高权限会话访问不可信页面；敏感页面加 CSP、CSRF token，Cookie 设 HttpOnly/SameSite。
- 检测：普通用户请求中出现 `;UPDATE`、`role=`、`debug/create_log` 等特征；demo 账号角色突然变化；bot 访问后紧接对 debug 接口的 POST；页面出现 `textContent` 后接 `innerHTML` 的可疑渲染代码。
