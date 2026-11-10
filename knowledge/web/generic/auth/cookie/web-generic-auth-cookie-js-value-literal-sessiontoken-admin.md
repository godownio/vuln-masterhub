---
id: web-generic-auth-cookie-js-value-literal-sessiontoken-admin
title: 前端 login.js 里把 SessionToken 与固定字面值比较：直接设置 Cookie 为 statusOrCookie 进入 /admin 并读取 SSH 私钥
type: scenario
domain: web
path: web/generic/auth/cookie
technique: client-side-js-cookie-literal-auth-gate
aliases:
- SessionToken=statusOrCookie
- login.js 判断 Cookie 值
- 前端 JS 鉴权字面值
- 后台 JS 鉴权绕过
tags:
- web
- auth-bypass
- cookie
- client-side-auth
- information-disclosure
- ssh-key
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:28+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文：目录爆破得 /admin，查看源码发现 login.js 里的判断，设置 Cookie SessionToken=statusOrCookie 刷新即进入后台，响应含 SSH 私钥，并给出 curl --cookie 加 perl 抽 pre 标签的命令；卡片 PoC 与该命令一致。需注意：判定值 statusOrCookie 与 login.js 的具体比较逻辑原文只以截图呈现，正文仅一句「存在可利用信息」，卡片对「前端 JS 比较固定字面量、后端不校验」的定性属依据该句的推断，故 confidence medium 恰当。未执行任何请求。
---

## 一句话结论

后台 `/admin` 的访问判定完全写在前端 `login.js` 里：只要 `SessionToken` 这个 Cookie 的值等于某个字面量（本例为 `statusOrCookie`），JS 就认为已登录并把页面内容渲染出来；后端对 `/admin/` 本身不做服务端会话校验，因此攻击者手工给 Cookie 赋值即可直接拿到含 SSH 私钥的后台页面。

## 原理

- **鉴权逻辑放在客户端等于没有鉴权**：前端 JS 读 `document.cookie` 取 `SessionToken`，与硬编码字符串比较后决定是否跳转或被拒；浏览器端的一切判断都能被用户完全控制（改 Cookie、改返回的 JS、直接请求接口）。
- **服务端未复核**：`/admin/` 响应本身由服务端直接输出（含员工 SSH 私钥），后端只信任「前端跳走过」这一事实，没有在服务端检查会话 Cookie 是否由登录流程签发，也没有签名/过期/绑定。
- **为什么能读到私钥**：私钥被当作静态页面内容嵌在 `/admin/` 的 `<pre>` 里；绕过展示层判断后，服务端就把这些内容原样吐出，等于一个未授权文件读取点。
- **与弱口令的关系**：本例 admin 登录表单曾试过 SQL 注入未成功，真正入口是源码里的这段判断——信息收集重点应放到 `login.js`、`*.js.map` 等前端资源，而不是反复打登录框。

## 触发条件

- 目标后台的访问控制在前端 JS 中实现，且判断依据是可被客户端任意设置的值（Cookie、LocalStorage、URL 参数）。
- 服务端对受保护路径不做二次鉴权，或仅校验「有没有这个 Cookie」而不校验其来源。
- 后台页面内包含敏感内容（凭据、私钥、配置），使绕过具备实际危害。

## 利用步骤

1. 目录爆破发现 `/admin`，访问后是登录表单；先看页面引用的脚本（`login.js` 等），搜索 `cookie`、`token`、`indexOf`、`==` 等关键字。
2. 在脚本中找到比较分支，确认期望的字面值（本例 `SessionToken` 需等于 `statusOrCookie`）。
3. 在浏览器 DevTools 或请求工具中给目标域设置该 Cookie，再请求 `/admin/`（或直接带 Cookie 发 curl）。
4. 确认返回页包含后台内容；提取页面中的私钥/凭据块。

## PoC

```bash
# 直接带字面值 Cookie 请求后台，并抽出 <pre> 中的内容（私钥）
curl http://<target>/admin/ --cookie "SessionToken=statusOrCookie" \
  | perl -0777 -ne 'while (/\<pre\>(.*?)\<\/pre\>/sg) {print "$1\n"}'
```

拿到 PEM 私钥后，若其口令保护，用 `ssh2john` 转格式再交给 `john` 字典破解，即可用对应用户登录 SSH。

## 变体与关联

- **同族客户端鉴权绕过**：响应包里的 JS 客户端校验可篡改（[[web-generic-auth-response-js-client-check-tamper]]）、隐藏接口只比对某个请求头字面值（[[web-generic-auth-header-value-equality-sole-access-gate]]）、仅凭明文 Cookie 用户名拼接他站成功响应（[[web-generic-auth-cookie-login-response-splice-username-cookie]]）。共同点是「判断依据由客户端提供且服务端不复核」。
- **私钥/凭据到手后的落点**：口令保护的私钥先离线破解再登录；后台里的 SSH key 属于典型的「后台敏感文件 → 边界登录」链路。

## 检测与防御

- **检测**：审计前端资源中是否出现 Cookie/Storage 与字面量的比较分支；对 `/admin` 这类路径做无 Cookie、伪造 Cookie 的对照请求，观察服务端是否返回相同内容；访问日志中同一 IP 在无登录请求的情况下直接命中后台路径。
- **防御**：所有受保护资源在服务端做会话校验，Cookie 必须是服务端签发、带签名/过期/绑定属性的会话标识；前端判断只能用于体验优化；后台页面禁止内嵌私钥/凭据，SSH 私钥改为按需签发并加口令保护。
