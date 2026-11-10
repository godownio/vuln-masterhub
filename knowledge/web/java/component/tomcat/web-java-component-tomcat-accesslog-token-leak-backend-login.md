---
id: web-java-component-tomcat-accesslog-token-leak-backend-login
title: Tomcat 访问日志泄露 GET 请求中的 token 并重放登录后台
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-accesslog-querystring-token-replay
aliases:
- localhost_access_log token 泄露
- 访问日志 GET 参数
- AccessLogValve %r
- 日志重放登录
tags:
- tomcat
- 访问日志
- localhost_access_log
- token
- 认证绕过
- 信息泄露
- 重放
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:40:18+08:00'
  notes: 已对照原文核对；日志中GET /share 携带token并重放登录后台与图19及正文一致；原文对后台上传jsp是否解析成功措辞为「看一下解不解析」，卡片原理段「改jsp后缀解析getshell」略有外推，但核心结论即日志token重放登录后台已由原文「利用该请求直接登录到后台中」证实；原文无受影响版本区间，已clear
---

## 一句话结论

Tomcat 的 AccessLogValve 用 `%r` 把完整请求行（含 query string）写进 `localhost_access_log.YYYY-MM-DD.txt`；若应用把登录 token/会话凭证放在 GET 参数里，任何能读到 logs 目录的攻击者都可从历史访问日志提取仍有效的 token，直接重放该 URL 登录后台，绕过口令爆破，进而借后台功能（如任意文件上传）拿 webshell。

## 原理

- 常见 AccessLogValve 配置 `pattern="%h %l %u %t &quot;%r&quot; %s %b"` 中 `%r` 是请求首行，包含 method、完整 URI（含 `?` 后的 query string）与协议版本。
- 开发图方便把认证 token、临时票据、分享链接凭证放在 URL 查询参数中传递，于是登录态凭据被原样落盘到访问日志，并按天归档保留数月。
- 日志位于 `$CATALINA_HOME/logs/`，在"Web 根目录映射错误"或"任意文件读取"下可被 HTTP 读取；访问日志是纯文本，无需解密。
- 危害成立的关键：token 有效期长 / 未绑定客户端 IP-UA / 非一次性失效，且后台会话校验只认 token，重放历史 URL 即被当成合法登录。
- 原文完整打通：读访问日志 → 发现 `GET /share?token=...` → 用该请求直接登录后台 → 后台任意文件上传改 jsp 后缀解析 → getshell。

## 触发条件

- AccessLogValve 记录 `%r`（或任何含 URI 的 pattern）。
- 应用把 token/会话/票据放在 GET query string 或 URL 路径参数中传递。
- 攻击者可读取 Tomcat logs 目录（appBase 配置错误、任意文件读取、备份/目录列表泄露等）。
- token 在日志生成时仍有效（长时效、无 IP/UA 绑定、非一次性）。

## 利用步骤

1. 通过目录扫描或配置读取确认 logs 目录可访问，枚举 `localhost_access_log.*.txt`（按日期）。
2. 在日志中搜索 `token=`、`ticket=`、`session`、`auth`、`key=`、`/share?` 等含凭据的请求行。
3. 提取完整 URL（含全部 query 参数），原样在浏览器或脚本中重放。
4. 若返回登录态页面/后台，即认证绕过成功；随后利用后台能力（上传点改后缀解析 jsp 等）扩大战果。
5. 也可从日志中发现未知接口、内部路径、管理员操作记录，辅助进一步探测。

## PoC

```text
# logs/localhost_access_log.2024-03-22.txt 中的一行（%r 含完整 query）
[21/Mar/2025:15:29:37 +0800] "GET /share?token=<有效token>&mobile=1 HTTP/1.1" 302 -

# 直接重放该 URL 即进入后台
GET /share?token=<有效token>&mobile=1 HTTP/1.1
```

（token 为占位示意，未执行文中任何请求。）

## 变体与关联

- 变体：Shiro/Spring 的 `;jsessionid=` 路径参数、密码重置链接、一次性下载链接、API key 出现在 URL 时同样被 `%r` 记录。
- 变体：应用自身 logback/log4j 日志（DEBUG 级）记录请求参数、调用栈、类名，也可泄露凭据与内部结构。
- 关联：与"appBase 为空导致 Web 根回退""分号路径参数绕过 .log 拦截"组合——前者让日志目录可达，后者突破对 .log 的读取限制。
- 关联：从日志中拿到类名后可进一步读 WEB-INF/classes 下 class 还原源码。

## 检测与防御

- 检测：日志中出现含 `token=`/`password=`/`key=` 的 GET 请求行；logs 目录被 Web 访问；异常来源大量读取历史日志文件。
- 防御：认证 token 绝不放 URL，改用 POST body 或 HttpOnly+Secure Cookie；对敏感字段在日志中脱敏，或让 AccessLogValve 只记录路径不记录 query（自定义 pattern / 过滤）。
- 防御：token 短时效、绑定 IP/UA、一次性使用并支持吊销；后台关键操作二次校验。
- 防御：禁止 logs 目录经 Web 访问，前置代理拒绝 /logs/ 且规范化 URI 后再匹配；日志归档加密、定期清理与访问审计。
