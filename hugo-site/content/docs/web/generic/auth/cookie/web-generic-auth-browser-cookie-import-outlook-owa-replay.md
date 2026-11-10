---
id: web-generic-auth-browser-cookie-import-outlook-owa-replay
title: 浏览器 Cookie 导出/导入重放：Cookie-Editor 导入 OWA 会话绕过登录，Chromium Cookie 库完整性校验 vs Firefox 明文注入
type: scenario
domain: web
path: web/generic/auth/cookie
technique: browser-cookie-export-import-session-replay
tags:
- web
- cookie
- session-hijack
- mfa-bypass
- browser
- outlook
- chromium
- firefox
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:47:20+08:00'
  notes: 已对照原文13682及16张图核对：OWA startupdata.ashx 440/200判定、单包替换不足需整套Cookie、Cookie-Editor JSON导出导入、Burp拦截/FORWARD后导入流程、Chromium cookie库注入不识别vs Firefox明文注入均与原文一致；force理由成立（既有Entra ID卡针对ESTSAUTH企业身份令牌，本卡为消费级OWA+Cookie-Editor导入及浏览器侧注入差异，步骤与触发条件不同）；未本机复现
url: /docs/web/generic/auth/cookie/web-generic-auth-browser-cookie-import-outlook-owa-replay/
draft: false
kb_aliases:
- Cookie-Editor 导出导入
- Outlook Cookie 重放
- OWA 会话劫持
- 浏览器 Cookie 注入
- Chromium Cookie 完整性校验
- Firefox cookies 明文注入
---

## 一句话结论

已登录浏览器中的会话 Cookie 是可直接复用的 bearer 凭据：用 Cookie-Editor 把已登录主机的 Outlook OWA Cookie 导出为 JSON，在未登录主机上通过 Burp 拦截 `/mail/0` 的初始请求，在页面请求静态/SVG 资源时导入 Cookie 并放行，即可无账号密码、无 MFA 直接进入对方邮箱；但只替换 `startupdata.ashx` 单个请求不够，后续请求也必须携带同一套 Cookie，且部分站点会下发动态 Cookie，磁盘存储型 Cookie 重放可能失败，需要从内存转储完整 Cookie。此外 Chromium 对 Cookie 数据库有完整性校验，手工注入 Cookie 文件不生效；Firefox 的 Cookie 明文存储、无完整性校验，可把窃取的 Cookie 注入其 `cookies.sqlite`。

## 原理

- **会话 Cookie 即凭据**：服务端把会话状态绑定在 Cookie 上，只要 Cookie 集合完整且未过期，服务器无法区分持有者是否为本人；MFA 只在登录时校验，已建立的会话不再要求二次验证，因此重放 Cookie 可绕过密码与 MFA。
- **OWA 的行为验证**：无 Cookie 访问 `outlook.live.com/mail/0` 后，POST `/owa/0/startupdata.ashx?app=Mail&n=0` 返回 440 Login Timeout 并跳登录页；带有效 Cookie 时同一请求返回 200 并加载邮箱页面，说明会话有效性完全由 Cookie 决定。
- **为什么要成套导入**：只在 Burp 中替换 `startupdata.ashx` 一个请求的 Cookie，虽然该请求返回 200，但后续资源/接口请求若不带登录用户 Cookie 仍会跳登录页；必须在浏览器层面导入整套 Cookie（Cookie-Editor JSON），或确保所有后续请求都携带。
- **动态 Cookie 的坑**：部分站点在交互过程中由服务端再下发 session/动态 Cookie，磁盘里的存储型 Cookie 不含这些值；只导入存储型 Cookie 会登录失败。从运行中浏览器内存转储 Cookie（CookieMonster）可拿到动态 Cookie，直接导入即可成功。
- **Chromium 与 Firefox 的注入差异**：Chromium 对 `Cookies` 数据库有类似完整性校验，复制后注入/直接改原生文件均不被识别（原文实测）；Firefox 的 `cookies.sqlite` 明文存储且不做完整性检测，可把窃取的 Cookie 写入 Firefox 配置文件实现注入。
- **Cookie-Editor 的工作方式**：浏览器插件以 JSON/Netscape/Header String 格式导出当前站点全部 Cookie（name/value/domain/path/expires/httpOnly/secure/sameSite），导入时按 domain/path 写回浏览器 Cookie 存储；这使"复制会话"只需两步 UI 操作，降低了攻击门槛。

## 触发条件

- 攻击者已获得受害者浏览器中目标站点的有效 Cookie 集合（本机导出、恶意扩展、窃密木马、内存/文件转储等）。
- 目标站点仅以 Cookie 维持会话，未绑定客户端证书/设备指纹/IP 等强约束；会话未过期、未被服务端吊销。
- 攻击者能在自己的浏览器安装 Cookie-Editor 或可写 Firefox profile；若用 Burp 方式，需要在初始请求阶段拦截并导入。
- 对 Chromium 注入路线需注意完整性校验，Firefox 路线要求目标站点接受同一 Cookie 集合。

## 利用步骤

1. 在已登录主机打开目标站点（如 Outlook），用 Cookie-Editor 导出当前域全部 Cookie 为 JSON。
2. 在未登录主机打开同一站点；若直接导入后仍跳登录，改用 Burp 拦截：先让浏览器发起 `/mail/0`，Forward 后在页面请求 SVG/静态资源时用 Cookie-Editor 导入 JSON，再停止拦截并放行。
3. 观察 `startupdata.ashx` 从 440 变为 200，页面加载出邮箱内容，确认会话复用成功；检查浏览器开发者工具确认后续请求均带 Cookie。
4. 若只拿到磁盘存储型 Cookie（如从 Chrome `Network/Cookies` 解密），先尝试导入；失败说明站点依赖动态 Cookie，改用内存转储（见关联卡）获取完整集合。
5. 文件注入路线：Chromium 因完整性校验通常失败；可把窃取的 Cookie 写入 Firefox `cookies.sqlite`（明文、无完整性校验），启动 Firefox 访问目标站点验证。
6. 记录 Cookie 来源、导入方式与站点响应，评估会话有效期与可访问范围（邮箱、云盘、管理后台等）。

## PoC

原文为浏览器 UI + Burp 的手工流程，无脚本；最小复现步骤：

```text
主机A（已登录 Outlook）:
  Cookie-Editor → Export As JSON → 保存 outlook_cookies.json

主机B（未登录）:
  打开 outlook.live.com/mail/0，Burp Intercept 开启
  Forward 初始请求 → 页面请求 svg 静态资源时
  Cookie-Editor → Import → 粘贴 outlook_cookies.json → Import
  关闭 Intercept → 页面加载邮箱
```

文件注入示意（Firefox）：

```text
将 Cookie 记录写入 <profile>/cookies.sqlite 的 moz_cookies 表
（host/name/value/path/expiry/isSecure/isHttpOnly 等字段），
启动 Firefox 访问目标站点验证会话。
```

## 变体与关联

- 变体：用 Cookie-Editor 的 Header String 格式直接拼 `Cookie:` 头，通过 HTTP 客户端访问 API；对 OWA 这类依赖 JS 动态加载的页面不如浏览器整包导入稳定。
- 变体：从 Chromium 内存 CookieMonster 转储动态 Cookie 后再导入（见 [[pentest-privilege-escalation-chromium-memory-cookiemonster-dump]]）；磁盘侧解密见 [[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]。
- 关联：[[cloud-cloud-iam-entra-id-session-cookie-replay]]（Entra ID 的 ESTSAUTH 会话 Cookie 注入，云身份场景）、[[web-generic-auth-cookie-tenant-unit-idor-password-change]]（Cookie 中租户/单元字段导致越权）。
- 边界：会话过期/服务端吊销、Cookie 绑定设备指纹或客户端证书、SameSite/分区 Cookie、Chromium 完整性校验、MFA 策略要求重新认证时，重放失败或受限。

## 检测与防御

- 检测：同一账号在短时间内从不同设备/IP/UA 复用同一会话 Cookie；登录日志中出现"无登录事件的会话访问"；异常地理位置访问邮箱；Cookie 导入插件在非受管浏览器中的使用。
- 防御：会话 Cookie 绑定设备指纹/客户端证书、短有效期与滚动续期、敏感操作强制重新认证；服务端支持会话吊销与异常会话检测；Chromium 的 Cookie 完整性/App-Bound 机制；终端侧监控浏览器 Cookie 数据库与 profile 目录的异常读取。
- 边界：Cookie 重放属会话劫持，单凭"多设备访问"不能定性，需要结合设备指纹与行为基线。
