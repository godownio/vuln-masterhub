---
id: web-generic-sqli-content-type-dual-header-waf-bypass
title: Content-Type 双头混淆：WAF 判为文件上传、Tomcat 按表单解析的 SQLi 绕过
type: scenario
domain: web
path: web/generic/sqli
technique: content-type-dual-header-waf-bypass
tags:
- sqli
- waf-bypass
- content-type
- multipart
- tomcat
- parser-differential
- http-smuggling
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:08:33+08:00'
  notes: '已对照原文与截图核对：WAF 需 multipart/form-data 头 + body 中不同行的 ------ 与 Content-Disposition: 才判文件上传；前置 application/x-www-form-urlencoded 后 Tomcat 按表单收参；无效参数 w 承载特征串；先前被拦的 1''/if(length(database())=1,1,1)# 加双头后放行，均与图 09-12 一致。''Tomcat 取第一个 Content-Type'' 属由实验行为反推，未单独做头序对比，使用时需现场验证。原文未声明受影响版本，未设置 affected_versions。未验证点：未复现。'
url: /docs/web/generic/sqli/web-generic-sqli-content-type-dual-header-waf-bypass/
draft: false
kb_aliases:
- Content-Type 双头绕过
- 重复 Content-Type
- WAF 文件上传分类绕过
- multipart 与 urlencoded 解析差异
- 某池 WAF Content-Type 混淆
- Content-Disposition 注入体
---

## 一句话结论

WAF 依据 `Content-Type: multipart/form-data` 和请求体中的 `------`/`Content-Disposition:` 把请求归类为文件上传，而 Tomcat 依据**第一个** `Content-Type: application/x-www-form-urlencoded` 把同一请求体解析为普通表单；利用这种双头/双解析差异，把 SQL 注入 payload 放进表单参数，就能绕过 WAF 的 SQL 注入检测。

## 原理

- WAF 需要先判断“这份请求是什么”，再选择对应的攻击检测引擎（SQLi、文件上传、XSS 等）。它通常依赖 `Content-Type` 与 `Content-Disposition` 等特征做分类。
- 实测某池 9.3.5 的文件上传识别边界很宽松：`Content-Type` 头包含 `multipart/form-data`，且请求体中出现 `------` 与 `Content-Disposition:`（两者不在同一行），即归类为文件上传，不再走 SQLi 检测。
- 后端 Tomcat 解析表单时使用请求中的 `Content-Type`；当出现多个 `Content-Type` 头时，Tomcat 取第一个 `application/x-www-form-urlencoded`，按普通表单解析请求体。
- 因此可以构造同时满足两边的请求：WAF 看到第二个 `multipart/form-data` 头与 `Content-Disposition:` 特征 → 判为文件上传放行；Tomcat 看到第一个 `application/x-www-form-urlencoded` → 按表单解析，`username`/`password` 正常传参。
- 请求体中的 `------\nContent-Disposition:` 会被 Tomcat 当作表单值的一部分，可能污染参数导致 SQL 错误；把它赋值给一个无效参数（如 `&w=...`）即可，既保留 WAF 特征，又不影响业务参数。

## 触发条件

- 目标前置 WAF 依据 `Content-Type`/`Content-Disposition` 做请求分类，且对 multipart 请求不执行 SQLi 检测。
- 后端（如 Tomcat）在重复 `Content-Type` 头时取第一个头解析请求体，且与 WAF 取的头不一致。
- 请求体可同时包含 `application/x-www-form-urlencoded` 表单数据与 `------`/`Content-Disposition:` 特征。
- 存在 SQL 注入点，且 WAF 对普通表单请求会拦截注入 payload。

## 利用步骤

1. 确认 WAF 与后端对 Content-Type 的处理差异：发送带两个 `Content-Type` 头的请求，观察 WAF 是否放行、后端是否按表单解析。
2. 构造最小文件上传特征：第二个 `Content-Type: multipart/form-data; boundary=...`，请求体含 `------` 与 `Content-Disposition:`（不同行）。
3. 在请求体前置正常表单参数，把注入 payload 放到 `Content-Disposition:` 后面的值里，并赋给无效参数：
   ```http
   POST /login HTTP/1.1
   Host: target
   Content-Type: application/x-www-form-urlencoded
   Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXXXX
   Content-Length: ...

   username=1&password=1&w=------
   Content-Disposition:1'/if(length(user())=1,exp(1),1)#
   ```
4. 观察响应：WAF 不拦截，后端正常接收 `username`/`password`，且注入语句被执行（布尔/报错/时间差异）。
5. 用之前被拦截的 payload（如 `1'/if(length(database())=1,1,1)#`）替换 `w` 的值，确认绕过效果。

## PoC

```http
POST /sqli-range/login HTTP/1.1
Host: 192.168.3.33:81
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNzUHhOeme2xTQrf8
Content-Length: 236

username=1&password=1&w=------
Content-Disposition:1'/if(length(user())=1,exp(1),1)#
```

```text
# WAF 视角：multipart/form-data + ------ + Content-Disposition: → 文件上传，放行
# Tomcat 视角：第一个 Content-Type 是 x-www-form-urlencoded → 解析 username/password/w
# w 参数承载注入 payload，不影响 username/password 的正常业务逻辑
```

## 变体与关联

- 变体：调换两个 `Content-Type` 的顺序，测试 WAF/后端各自取第一个还是最后一个；不同中间件（Tomcat、Spring、Nginx）行为可能不同。
- 变体：把 `Content-Disposition:` 放在 body 的不同位置、用不同大小写/空白，满足 WAF 特征但保持后端表单可解析。
- 变体：同类“解析器差异”还可用于绕过文件上传检测（WAF 判为表单、后端判为 multipart）或 XSS 检测。
- 关联：[[web-generic-sqli-semantic-waf-layerwise-bypass]]（同一 WAF 的语义绕过）、[[web-generic-http-smuggling-host-connection-state-bypass]]（HTTP 解析差异类问题）。
- 边界：WAF 与后端取同一个 `Content-Type`、拒绝重复头、或对 multipart 也执行 SQLi 检测时，绕过失效。

## 检测与防御

- 检测：请求中出现重复 `Content-Type` 头；`multipart/form-data` 与 `application/x-www-form-urlencoded` 混用；请求体同时含表单参数与 `------`/`Content-Disposition:`；同一来源的请求在 WAF 放行但后端出现 SQL 错误。
- 修复：WAF 与后端必须使用同一套 HTTP 解析规则（同一 `Content-Type` 头、同一优先级）；拒绝重复/冲突的 `Content-Type`；对 multipart 请求也执行参数级 SQLi 检测。
- 加固：根本防御是参数化查询；对请求头做规范化与一致性校验；限制异常 Content-Type 组合；监控 WAF 放行但后端报 SQL 错误的差异。
