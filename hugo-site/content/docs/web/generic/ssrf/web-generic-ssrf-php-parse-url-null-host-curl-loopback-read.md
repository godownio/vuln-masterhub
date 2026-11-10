---
id: web-generic-ssrf-php-parse-url-null-host-curl-loopback-read
title: PHP parse_url 单斜杠 URL 使 host=null 绕过校验，curl_exec 按原始串回环请求读本地文件
type: scenario
domain: web
path: web/generic/ssrf
technique: php-parse-url-null-host-curl-loopback-read
tags:
- web
- ssrf
- php
- parse-url
- parser-differential
- loopback
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-25
  verified_at: '2026-11-08T14:28:20+08:00'
  notes: 已对照原文与图11-13核对：源码确为 host===null&&scheme==='http' 放行分支+curl_init原始串；http:/127.00.1/flag 回显提示文件名、再请求 FFFFF11111AAAAAggggg.php 回显flag，PoC实证成立；CTF题目无组件版本标记，不设versions
url: /docs/web/generic/ssrf/web-generic-ssrf-php-parse-url-null-host-curl-loopback-read/
draft: false
kb_aliases:
- parse_url host null
- 单斜杠 SSRF
- curl 单斜杠回环
- 127.00.1 变体 IP
---

## 一句话结论

PHP 中 `parse_url("http:/127.00.1/flag")` 因 URL 只有单斜杠而返回 `host=null`，使 `host` 相关黑/白名单校验失效（或恰好落入 `host===null && scheme==='http'` 的放行分支），而 `curl_init` 拿到原始 URL 串仍会连接 `127.00.1`（等价 127.0.0.1），形成打向本机的 SSRF 任意读取内网/本地资源。

## 原理

RFC 3986 允许 `scheme:` 后跟未以 `//` 开头的路径（same-document 引用），此时 URL 没有 authority 部分：`parse_url` 解析出 `scheme=http`、`host=null`、`path=/127.00.1/flag`。校验代码若以 `parse_url` 的 `host` 字段做黑名单（内网 IP/域名检查）或以 `host===null` 为放行条件，就会被这种"无 authority"的畸形 URL 骗过。但 `curl_init($url)` 收到的是未经归一化的原始字符串，libcurl 对 `http:/host/path` 做兼容性修复按 `http://host/path` 处理，且 `127.00.1` 这类带前导零的 IP 段被按十进制解析仍指向 127.0.0.1——"解析器看到的 URL"与"请求库执行的 URL"不一致，构成 parser differential SSRF。

## 触发条件

- 服务端用 `parse_url` 提取 host/scheme 做校验（黑名单内网 IP 或 host 非空断言，或存在 `host===null && scheme==='http'` 即执行的分支）。
- 校验后把**原始 URL 字符串**交给 curl/file_get_contents 等请求库执行。
- 目标可访问本机 HTTP 服务（含 flag 文件、内网接口）。

## 利用步骤

1. 审计/探测：请求 `?url=http://127.0.0.1/` 被拦截，确认存在 host 校验。
2. 改用单斜杠去掉 authority：`?url=http:/127.00.1/flag`，parse_url 的 host 变 null，校验通过。
3. 服务端 `curl_exec` 按原始串回环请求，响应回显 `/flag` 内容及提示文件名。
4. 继续请求 `http:/127.00.1/FFFFF11111AAAAAggggg.php` 等回显出的内部路径，逐跳拿到最终 flag。

## PoC

```text
GET /?url=http:/127.00.1/flag
→ 响应回显: Well, Going to http:/127.00.1/flag  (本地 flag 内容/提示)
GET /?url=http:/127.00.1/FFFFF11111AAAAAggggg.php
→ 回显 flag
```

## 变体与关联

- 变体：`http:/`、`https:/` 单斜杠；前导零/八进制/十六进制 IP 变体（127.00.1、0x7f000001、2130706433）；`url=http:@127.0.0.1/` 等 userinfo 形式。
- 关联：parser differential 家族（Python urlparse 反斜杠绕过、URL userinfo 前缀白名单绕过、IP 记法黑名单绕过）；本卡特征是"host 字段为 null"这一 PHP parse_url 特有行为。

## 检测与防御

- 校验必须基于归一化后的最终 URL：先修复 scheme://authority 再 parse，或直接拒绝 host 为空/非空的畸形 URL（`scheme:` 后必须 `//`）。
- 对请求库实际解析的目标（curl 的 `CURLINFO_PRIMARY_IP`）做出口校验，禁止回环/内网段。
- 不要把"校验用的解析结果"与"执行的原始串"分离。
