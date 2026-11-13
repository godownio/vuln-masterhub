---
id: web-generic-ssrf-curl-pathinfo-extension-windows-fragment-query-bypass
title: 'Windows libcurl 下 pathinfo 后缀白名单绕过：file:///c:/windows/win.ini 追加 ?.jpg 或 #.jpg 读取本地任意文件'
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-pathinfo-extension-windows-fragment-query-bypass
tags:
- web
- ssrf
- php
- curl
- windows
- file-read
- pathinfo
- whitelist-bypass
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V639
  verified_at: '2026-11-13T02:16:16+08:00'
  notes: 已对照原文与截图核对：file.php pathinfo(PATHINFO_EXTENSION)白名单jpg/gif/png/ico、CURLPROTO_ALL、落盘files/download回显(图06-10)；Windows libcurl 7.64.0 Burp fuzz中0x3f/0x23生效(图35/36)，macOS 7.52.1双字节fuzz无命中(正文)。发现并修正两处：原文实际payload为win.ini%3f.jpg(解码后?.jpg)，原稿写?jpg/%23jpg会使pathinfo得到ini?jpg无法过白名单(PHP 7.3.4实测)，已改为?.jpg/#.jpg与%3f.jpg/%23.jpg；标题因YAML中#被当注释而截断(追加?/)，已改为带引号完整标题。dedup与既有file://读取卡非同链，保留。未验证点：仅Windows 7.64.0截图证据，其他Windows/libcurl版本未逐一实测
url: /docs/web/generic/ssrf/web-generic-ssrf-curl-pathinfo-extension-windows-fragment-query-bypass/
draft: false
kb_aliases:
- pathinfo 后缀校验绕过
- file:/// win.ini
- 图片后缀白名单本地文件读取
- Windows curl file 协议
- SSRF 后缀白名单 file 读取
---

## 一句话结论

当 PHP SSRF 用 `pathinfo($url, PATHINFO_EXTENSION)` 校验 URL 必须以 `jpg/gif/png/ico` 结尾、又允许 `file://` 时，在 Windows 版 libcurl（原文 7.64.0）里把本地文件路径追加 `?.jpg` 或 `#.jpg`（分隔符后必须紧跟 `.jpg`）即可：`pathinfo` 看到的后缀是 `jpg` 通过白名单，而 curl 对 `file://` 忽略 query/fragment，实际读取 `file:///c:/windows/win.ini`，配合“抓取结果落盘并回显 URL”的 SSRF 就能任意读本地文件；同环境实测 macOS libcurl 7.52.1 用 0-255 双字节 fuzz 未找到绕过。

## 原理

- **两次解析分歧**：`pathinfo('file:///c:/windows/win.ini?.jpg', PATHINFO_EXTENSION)` 取最后一个点之后的内容得到 `jpg`（若写成 `...win.ini?jpg`，最后一个点落在 `.ini` 上，得到 `ini?jpg` 会被白名单拒绝，PHP 7 实测如此）；而 libcurl 解析 `file://` URL 时把 `?` 后的 query、`#` 后的 fragment 视为非路径部分，读取的仍是 `c:\windows\win.ini`。
- **Windows 路径形态**：Windows 下 `file:///c:/windows/win.ini` 是合法本地文件 URL；把 `?.jpg`/`#.jpg` 拼在路径后既满足白名单又不改变实际读取目标（原文 Burp 实际发出的即 `win.ini%3f.jpg`，服务端解码为 `win.ini?.jpg`）。
- **回显方式**：该 SSRF 把 `curl_exec` 的响应写入 `files/download/<随机名>.jpg` 并返回可访问 URL，因此本地文件内容可被打包成“图片”下载回读（不是盲 SSRF）。
- **平台差异**：文章在 Windows libcurl 7.64.0 的 Burp Intruder 里遍历 0x00-0xff 双字节，`0x3f`（`?`）与 `0x23`（`#`）两组返回了 win.ini 内容；macOS 7.52.1 用同样 2 字节 fuzz 没有任何命中，说明该 trick 依赖 Windows 的 URL 解析与 curl 版本行为。
- **为什么白名单挡不住**：白名单校验的是“字符串后缀”，不是“实际读取的路径”；两个组件对同一 URL 的语义理解不一致（TOCTOU 式的解析差异）。

## 触发条件

- PHP SSRF 通过 curl 抓取用户 URL，允许 `file://`（`CURLPROTO_ALL`、未收窄 `CURLPROTO_*`，或默认编译支持）。
- 存在基于 `pathinfo`/字符串的扩展名白名单（如 jpg/gif/png/ico）。
- 目标为 Windows 主机，libcurl 版本存在该解析行为（原文 7.64.0）。
- 应用有回显或落盘回读能力（否则只能盲读，需要其它外带）。

## 利用步骤

1. 确认后缀白名单：提交 `file:///c:/windows/win.ini` 应被拒（后缀 ini）。
2. 提交 `file:///c:/windows/win.ini?.jpg` 或 `file:///c:/windows/win.ini#.jpg`（注意 `.` 不能省，否则 pathinfo 取到的是 `ini?jpg` 会被拒）。
3. 若响应报“抓取成功”并给出落盘 URL，访问该 URL 读取 win.ini 内容；换成 `c:/windows/win.ini`、`c:/boot.ini`、站点配置等目标。
4. 遇到注入字节被过滤时可换 URL 编码 `%3f.jpg`/`%23.jpg`（服务端解码后仍是 `?.jpg`/`#.jpg`）或其它非 ASCII 字节组合。

## PoC

```http
POST /include/file.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

url=file:///c:/windows/win.ini%3f.jpg
```

或：

```http
url=file:///c:/windows/win.ini%23.jpg
```

响应（原文回显格式）：

```json
{"code":"200","msg":"抓取图片成功","url":"/files/download/202311261610xxxx.jpg","size":"1KB"}
```

访问该 URL 即得到 `[fonts]`、`[extensions]`、`[mci extensions]` 等 win.ini 内容。

## 变体与关联

- 与 `web-generic-ssrf-curl-redirect-protocol-surface-suffix-whitelist-bypass` 同属“后缀白名单旁路”，那张用 302 换协议（gopher/dict），本卡用 `?`/`#` 换读取目标（file）。
- 与 `web-generic-ssrf-image-proxy-url-param-file-scheme-arbitrary-read` 等 file:// 读取卡区别：本卡的核心不是“允许 file”，而是“后缀白名单 + Windows 解析差异”绕过。
- `pathinfo` 与 curl 的分歧也可用于其它 scheme/参数的校验绕过，思路可迁移。

## 检测与防御

- 不要用 `pathinfo` 对完整 URL 取扩展名做白名单；应先 `parse_url` 拆出 scheme/host/path/query/fragment，仅对 path 取扩展名并规范化。
- 禁止 file/scp 等本地协议（`CURLOPT_PROTOCOLS` 只留 HTTP/HTTPS），或在 curl 前解析并拒绝私网/本地目标。
- 抓取结果按内容类型与真实文件头校验，不以 URL 后缀决定落盘类型；落盘目录禁止脚本执行。
- 监控 `file://`、`%3f.jpg`、`%23.jpg`（解码后 `?.jpg`/`#.jpg`）等异常组合的请求参数。
