---
id: web-generic-xss-influxdb-flux-error-die-html
title: InfluxDB Flux 注入错误回显 XSS：die(msg) 把 HTML 塞进 text/html 错误响应
type: scenario
domain: web
path: web/generic/xss
technique: influxdb-flux-die-error-html-xss
aliases:
- Flux 注入 XSS
- InfluxDB 错误回显 XSS
- die msg HTML 注入
- HttpError 反射 XSS
- Express res.send text/html XSS
tags:
- influxdb
- flux
- xss
- nosql-injection
- error-reflection
- express
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:36:40+08:00'
  notes: 已对照原文与截图07核对：Express catch(res.send(err.toString())) 返回 Content-Type text/html，die(msg:<img src=x onerror=alert(document.domain)>) 在错误消息中原样渲染并触发 alert(127.0.0.1)，payload 与截图 URL 一致；图01/03/04/05 错误响应头确为 text/html，原理成立。与本篇数据外带卡共用 Flux 注入原语但影响面不同（信息外带 vs 浏览器端执行），两卡互相引用、保留双卡不重复。原文无版本声明，affected_versions 保持 null。未在真实浏览器复现。
---

## 一句话结论

Flux 注入点除了 `die()` 外带数据，还能把 HTML 放进去：Express 的 `catch { res.send(err.toString()) }` 默认以 `text/html` 返回错误，`die(msg:"<img src=x onerror=alert(document.domain)>")` 的 payload 被原样拼进 HTML 错误消息，浏览器解析后执行 JS，形成反射 XSS。

## 原理

- **错误通道**：应用在 InfluxDB 查询抛错时执行 `res.send(err.toString())`。Express 的 `res.send(string)` 会根据内容设置 `Content-Type: text/html; charset=utf-8`，浏览器按 HTML 渲染。
- **可控错误消息**：Flux 的 `die(msg: <string>)` 抛出的错误文本包含 `msg` 参数；注入 `") die(msg:"<img src=x onerror=...>")//` 后，错误消息里出现完整 HTML 标签。
- **为什么成立**：错误消息被当成纯文本处理（只做了字符串拼接，没有 HTML 转义），而响应头又声明为 HTML，两个环节叠加使任意标签/脚本可执行。`text/html` 是 Express `res.send` 对字符串的默认行为，很多自建查询接口都有同样的错误回显。
- 与数据外带共用同一注入原语：闭合字符串与括号后用 `die` 抛错，末尾 `//` 注释残余 Flux。

## 触发条件

- Web 应用把用户输入拼接进 Flux 查询，且异常信息回传客户端；
- 响应 `Content-Type` 为 `text/html`（如 Express `res.send(err.toString())`），且错误文本未做 HTML 转义；
- 受害者访问含 payload 的链接（反射型），或该错误内容被持久化/共享（存储型）。

## 利用步骤

1. 确认注入导致的错误会以 HTML 返回：传 `"` 看响应头是否为 `text/html`。
2. 构造 payload：`") die(msg:"<img src=x onerror=alert(document.domain)>")//`，URL 编码后作为 data 参数发送。
3. 浏览器打开该 URL，页面显示 `HttpError: error calling function "die" ...` 的同时执行 `alert(document.domain)`。
4. 进一步可把 JS 换成窃取 Cookie/token、发起 CSRF 请求等（结合目标环境）。

## PoC

```text
/query?data=")%20die(msg:%3a"<img%20src%3dx%20onerror%3dalert(document.domain)>")%2f%2f
```

页面同时渲染 `HttpError: error calling function "die" @1:117-1:170:` 与 `<img>`，触发 `alert(127.0.0.1)`。

## 变体与关联

- 变体：`<script>`、`<svg onload>`、`<iframe srcdoc>` 等标签视过滤情况替换；若存在 CSP，可尝试同源脚本注入或信息泄露型 XSS。
- 关联：Flux 注入数据外带主卡 [[web-generic-sqli-influxdb-flux-die-error-exfil]]（同一注入原语）；错误消息反射 XSS 的通用模式（`res.send(err)` 未转义）见 web/generic/xss 其它卡。
- 变体：存储型场景——错误日志被后台页面读取并以 HTML 渲染时升级为存储型 XSS。

## 检测与防御

- 检测：请求参数中出现 `die(msg:`、`<img`、`onerror`、`%3c` 等与 Flux 注入特征组合；响应错误页面包含未转义的 HTML 标签；`Content-Type: text/html` 的 HTTP 错误响应。
- 防御：错误消息统一 HTML 转义或改为 `text/plain`/JSON 返回；查询参数化，杜绝 Flux 拼接；对 InfluxDB 错误只返回通用错误码，详细异常只记服务端日志；部署 CSP 作为纵深防御。
