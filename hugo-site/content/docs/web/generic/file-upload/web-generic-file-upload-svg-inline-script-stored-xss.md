---
id: web-generic-file-upload-svg-inline-script-stored-xss
title: 上传 SVG 图片触发同源存储型 XSS：<svg><script>alert()</script></svg> 被当作图片放行
type: scenario
domain: web
path: web/generic/file-upload
technique: svg-upload-inline-script-stored-xss
tags:
- web
- xss
- file-upload
- svg
- stored-xss
- active-content
- ssrf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:08:44+08:00'
  notes: 已对照原文与18张图核对：图02 /WWW 目录下 svg.svg、图03 访问 127.0.0.1/WWW/svg.svg 弹出 XSS Attack!，与卡片 PoC 完全一致；PDF JS（图04/09-13 app.alert）、Flash 钓鱼（图05-08）、HTML 上传 XSS（图14-16）、JSP 上传与蚁剑连接（图17-18）均如实对应 cards.json 的 skipped/另一卡。SVG 卡原理（image/svg+xml 活动内容、图片白名单放行、同源直接访问执行）与原文一致；SSRF/file:// 仅作为低置信度线索标注，符合原文未打通的事实。原子性：单一「SVG 图片白名单上传→同源脚本执行」场景，未过粗。dedup 除自索引外 top 为 XXE/SVG、HTML 静态 XSS、MIME 嗅探等 related（机制不同），dup-scan 无本卡 pair。原文未标版本，未设置 versions；未执行上传/PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-svg-inline-script-stored-xss/
draft: false
kb_aliases:
- SVG XSS
- SVG 上传 XSS
- svg script 上传
- image/svg+xml XSS
- 图片上传 XSS
- SVG 存储型 XSS
- SVG 转 PDF SSRF
---

## 一句话结论

上传接口如果把 SVG 当作“图片”放行（仅校验 `image/*` 或扩展名 `.svg`），而文件落在 Web 同源可访问目录并被浏览器直接打开/内联展示，SVG 内的 `<script>` 会在站点同源下执行，形成存储型 XSS；同一 SVG 若被服务端用于缩略图/转 PDF，还可能借 `file://` 等协议读取本地文件（原文只提出该线索，未给出成功验证，置信度低）。

## 原理

- **SVG 是可执行活动内容**：SVG 基于 XML，支持 `<script>`、事件属性（`onload`/`onclick`）、`<foreignObject>` 等；浏览器把 `image/svg+xml` 当作文档渲染时，其中的脚本会在文档所属源执行，而不是像普通位图那样只解码像素。
- **上传校验的盲区**：很多上传点只判断“是不是图片”，白名单写成 `image/*` 或允许 `.jpg/.png/.gif/.svg`；`Content-Type: image/svg+xml` 与 `.svg` 扩展名都能通过“图片”校验，但内容实际是脚本容器。
- **同源与响应头**：文件若保存在 Web 根/静态资源映射内，浏览器访问 `https://site/uploads/x.svg` 时按 `image/svg+xml` 渲染；若服务端未强制 `Content-Disposition: attachment`、未加 `X-Content-Type-Options: nosniff`、也未把用户内容放到独立沙箱域，脚本就在主站同源执行，可读取非 HttpOnly Cookie、调用同源接口、发起 CSRF 或跳转钓鱼。
- **为什么危害是 XSS 而不是“图片解析”**：浏览器对顶层导航的 SVG 会执行脚本；即使用 `<img>` 嵌入通常不执行脚本，攻击者只需诱导受害者直接打开上传后的 URL（或站点以 iframe/内联方式预览 SVG）即可触发。
- **SSRF/文件读取线索**：如果服务端把上传的 SVG 交给 ImageMagick/wkhtmltopdf 等组件转 PDF/缩略图，SVG 可引用外部 URL 或 `file://` 本地文件；这类组件历史上多次出现 SSRF/任意文件读取。原文只给出“可能存在 SSRF、可尝试 file://”的方向，没有给出成功利用，属于待验证线索。
- **与 HTML 上传 XSS 的区别**：HTML 上传通常靠“后缀黑名单漏项”绕过；SVG 上传的入口往往是“图片类型白名单”，攻击者不需要绕过脚本后缀黑名单，而是利用“SVG 也是图片”这一认知盲区。

## 触发条件

- 上传接口允许 SVG（扩展名 `.svg` 或 `Content-Type: image/svg+xml`），且没有对 SVG 内容做脚本/外部引用清洗。
- 文件保存目录位于 Web 可访问路径，且访问时按 `image/svg+xml` 返回或浏览器按扩展名渲染。
- 响应未强制 `Content-Disposition: attachment`，未设置 `X-Content-Type-Options: nosniff`，也未使用独立沙箱域。
- 受害者直接访问上传后的 SVG URL，或站点以 iframe/内联预览方式展示该文件。

## 利用步骤

1. 构造最小 SVG：
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="100" height="100">
     <script type="application/javascript">
       alert('XSS Attack!');
     </script>
     <polygon points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   </svg>
   ```
2. 通过上传点上传该 `.svg`，记录返回的文件 URL。
3. 在浏览器直接访问该 URL；若弹出 `XSS Attack!`，说明 SVG 脚本在同源执行。
4. 替换 payload 为读取同源 Cookie/Token、调用同源接口或跳转钓鱼页；若站点把 SVG 内联嵌入页面，也可在页面加载时自动触发。
5. （待验证）若目标存在“SVG 转 PDF/缩略图”功能，测试 SVG 引用 `file:///etc/passwd`、`http://169.254.169.254/...` 等，观察是否由服务端发起请求或把本地文件内容渲染进 PDF；该方向原文仅提出线索、未给出成功验证，需按具体组件版本验证。

## PoC

最小 SVG XSS（原文验证：上传后访问 `/WWW/svg.svg` 弹窗成功）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script type="application/javascript">
    alert('XSS Attack!');
  </script>
  <polygon points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
</svg>
```

上传请求（multipart 关键字段）：

```text
Content-Disposition: form-data; name="file"; filename="svg.svg"
Content-Type: image/svg+xml

<svg ...><script>alert(document.domain)</script></svg>
```

## 变体与关联

- **脚本位置变体**：`<script>`、`onload=`、`<a xlink:href="javascript:...">`、`<foreignObject>` 内嵌 XHTML、`<use href="data:...">` 等。
- **校验绕过变体**：`.svg` 改成 `.svgz`、大小写、双扩展名、`Content-Type: image/svg+xml` 配 `.jpg`；只校验魔数的上传点可用 polyglot。
- **渲染方式变体**：直接访问、`<img>`（多数浏览器不执行）、`<iframe>`/`<object>`/`<embed>`、站点内联预览；不同方式执行条件不同。
- **SSRF/文件读取线索**：SVG→PDF/缩略图组件（ImageMagick、wkhtmltopdf 等）的 `file://`/外部 URL 引用；参见 [[web-generic-file-upload-svg-imagemagick-text-protocol-file-read]]、[[web-generic-xss-wkhtmltopdf-local-file-read-shadow-login]]。
- **同类活动内容上传**：[[web-generic-file-upload-html-static-stored-xss]]（HTML 静态目录 XSS）、[[web-generic-file-upload-upload-blacklist-miss-html-family-stored-xss]]（后缀黑名单漏项）、[[web-generic-file-upload-xml-xhtml-namespace-script-xss]]（XML/XHTML 命名空间脚本）。
- **边界**：若服务端对 SVG 做 XML 清洗/白名单标签、强制下载、使用 `Content-Security-Policy` 或独立域托管，XSS 不成立；若上传点只允许位图且校验真实文件头，SVG 无法上传。

## 检测与防御

- **上传校验**：优先禁止 SVG；确需支持时用 XML 解析器白名单标签/属性，移除 `<script>`、事件属性、`javascript:`/`data:` 外部引用，并做真实类型/魔数校验。
- **响应头**：对用户上传文件强制 `Content-Disposition: attachment`、`X-Content-Type-Options: nosniff`，使用独立域名/沙箱域托管用户内容。
- **渲染隔离**：预览 SVG 时用 `<img>` 或沙箱 iframe（`sandbox` 不带 `allow-scripts`），不要在同源顶层直接打开。
- **服务端转换**：SVG 转 PDF/缩略图使用最小权限、禁用外部实体与 `file://`、限制网络访问，及时更新 ImageMagick/wkhtmltopdf 等组件。
- **检测**：上传目录出现 `.svg` 且内容含 `<script>`/`onload`/`javascript:`；访问日志中对用户上传 SVG 的直接 GET；WAF 对 SVG 上传内容做脚本特征检测。
- **响应**：删除恶意 SVG、排查同上传目录其他文件；若已被同源 XSS 利用，重置相关会话并检查 CSRF/接口调用日志。
