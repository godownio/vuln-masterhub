---
id: web-generic-file-upload-wisdom-education-upload-whitelist-jsp
title: 智慧云教育平台 /api/upload 拦截器白名单未授权上传：随机名仍保留原始 .jsp 后缀
type: scenario
domain: web
path: web/generic/file-upload
technique: interceptor-whitelist-upload-preserve-client-extension
aliases:
- 智慧云智能教育平台上传
- wisdom-education 任意文件上传
- /api/upload/2 上传 JSP
- AdminAuthInterceptor 白名单上传
- FileTypeEnum 上传
- 时间戳 UUID 保留后缀
tags:
- web
- file-upload
- java
- spring-boot
- spring-mvc
- auth-bypass
- whitelist
- extension-bypass
- webshell
- arbitrary-write
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V226
  verified_at: '2026-11-07T06:56:34+08:00'
  notes: 已对照原文与38张图核对：AdminAuthInterceptor 的 startsWith(/api/dict|/api/upload|/uploads) 白名单、UploadController 第62/63/69行取原始后缀并拼接随机名、FileTypeEnum 1-4 前缀、FileUpload.putObject 直接写盘、响应 url 字段，均与图15/27/28/30一致；已修正 /excel/→/excels/ 及行号；原文未展示 JSP 访问/解析成功，confidence medium；未复跑。
---

## 一句话结论

智慧云智能教育平台的 `UploadController` 把上传接口暴露为 `/api/upload/{uploadFileType}`，而管理员拦截器 `AdminAuthInterceptor` 用 `targetUrl.startsWith("/api/upload")` 把它放进免登录白名单；接口只取客户端文件名的扩展名拼到“时间戳-UUID”新文件名上，没有后缀白名单、MIME 或内容校验，未登录即可把 `.jsp` 写入上传根目录下由 `FileTypeEnum` 决定的子目录，并可从响应拿到相对路径。

## 原理

- 鉴权侧：`AdminAuthInterceptor.preHandle` 在取会话前先判断 `targetUrl.startsWith("/api/dict")`、`startsWith("/api/upload")`、`startsWith("/uploads")`，命中直接 `return true`。`/api/upload/{1-4}` 因此对未登录请求完全放行；`StudentAuthInterceptor` 只拦截 `/student/**`，不会覆盖该路径。
- 上传侧：`UploadController.uploadFile`（`@RequestMapping(value="{uploadFileType}", method={GET,POST})`）第 62 行 `file.getOriginalFilename()`，第 63 行 `FilenameUtils.getExtension(fileName)` 并拼成 `suffix = StrUtil.DOT + extension`，第 69 行 `newFileName = ObjectUtils.generateFileBySecond() + "-" + ObjectUtils.generateUUId() + suffix`。
- 路径侧：第 65 行 `FileTypeEnum.getFileTypeEnumByCode(uploadFileType)` 决定前缀（1=`/videos/`、2=`/images/`、3=`/excels/`、4=`/words/`），第 68 行 `filePath = prefix + ObjectUtils.generateFileByTime()`，随后 `fileUpload.putObject(filePath, newFileName, inputStream)`。
- 落盘侧：`FileUpload.putObject` 直接 `FileUtil.writeFromStream(inputStream, new File(uploadPath + filePath + fileName))`，没有对后缀、大小、类型做任何判断；第 77 行把 `filePath + newFileName` 放进响应 `url`，攻击者无需猜路径。
- 为什么成立：随机化文件名只改变名字，不改变类型。`generateUUId()` 让文件名不可预测，但扩展名完全来自 multipart 的 `filename`，`shell.jsp` 得到 `.jsp`；只要 `uploadPath` 所在目录被静态映射（`/uploads` 亦在白名单中，说明该目录可被直接访问）且容器解析 JSP，上传即等于 WebShell 落盘。即使不解析 JSP，任意类型文件写入本身也可用于覆盖/投放 HTML/JS。

## 触发条件

- 目标为使用该代码的智慧云智能教育平台（`UploadController`、`FileTypeEnum`、`AdminAuthInterceptor` 白名单结构一致）。
- `/api/upload/{uploadFileType}` 可从外网直达；未登录即可访问。
- 服务进程对 `uploadPath` 指向的上传目录有写权限。
- 上传目录被 Web 容器/Nginx 静态映射，且 `.jsp` 被当作 JSP 解析（原文未展示访问/解析成功的截图，故置信度定为 medium；仅任意文件写入已由代码与请求确认）。

## 利用步骤

1. 确认目标指纹（教育平台登录页/管理端/FOFA 特征），直接请求 `/api/upload/2` 探测是否免登录返回 JSON。
2. 构造 `multipart/form-data`，`filename` 使用 `随机串.jsp`，`Content-Type` 可设为 `image/jpeg` 伪装；`uploadFileType=2` 对应 `/images/` 前缀。
3. 发送 `POST /api/upload/2`，从响应 JSON 的 `url` 字段读取 `filePath + newFileName`（形如 `/images/2025/09/18/<时间戳>-<UUID>.jsp`）。
4. 按部署方式拼接访问路径：若上传根映射为 `/uploads`，访问 `/uploads` + `url`；若返回的是域名前缀则直接访问。文件存在且可下载即证明任意文件写。
5. 若 JSP 被解析，替换为功能完整的 WebShell；若静态目录禁止脚本解析，则改用 HTML/JS 投放同源 XSS 或覆盖已有资源。
6. 探测其它 `uploadFileType`（1/3/4）确认前缀差异与可写性；GET 方法同样映射，可用于无 body 的边界测试。

## PoC

```http
POST /api/upload/2 HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKfAHSQTSwCjo25Kz
Content-Length: 2890

------WebKitFormBoundaryKfAHSQTSwCjo25Kz
Content-Disposition: form-data; name="file"; filename="16a985dfee9b093d76a0ffc4cf4c77ba20c2eb0d.jsp"
Content-Type: image/jpeg

123123
------WebKitFormBoundaryKfAHSQTSwCjo25Kz--
```

响应 `url` 字段即为落盘的相对路径；原文只证明上传成功与代码路径，未给出访问该 JSP 的截图，故不将“已 getshell”写成既成事实。

## 变体与关联

- 路径变体：`uploadFileType` 1/2/3/4 分别落 `/videos/`、`/images/`、`/excels/`、`/words/`；可挑一个静态映射可访问且允许脚本的目录。
- 命名变体：`generateFileBySecond()` 为秒级时间戳，`generateUUId()` 为 UUID，二者都只影响文件名；任何保留客户端后缀的随机命名实现同理。
- 鉴权变体：白名单使用前缀 `startsWith`，若存在 `/api/uploadXxx` 这类其它路由，也可能被误放行；本例中已确认 `/api/upload` 本身即可直达。
- 关联：[[web-generic-file-upload-spring-uuid-preserve-original-extension]]（同属 Spring MVC 随机名保留原后缀，但本卡强调拦截器白名单导致未授权）、[[web-generic-file-upload-xiaozhi-upload-any-extension-webroot]]（同模式，前端平台）、[[web-generic-file-upload-extension-zero-check]]（后缀零校验基线）。
- 边界：上传目录不在 Web 根、容器对上传目录关闭脚本解析、或 `uploadPath` 只写对象存储且不公开回源时，危害降为任意文件写/存储型内容投放。

## 检测与防御

- 检测：未登录请求 `/api/upload/*` 出现 multipart；`filename` 含 `.jsp`/`.jspx`/`.php` 等脚本后缀而 `Content-Type` 为图片；上传目录出现“时间戳-UUID.jsp”命名的新文件；访问该路径返回 200 且内容为脚本输出。
- 检测：拦截器白名单中出现 `startsWith("/api/upload")` 这类宽前缀，审计所有匹配路由是否都做了独立鉴权。
- 防御：上传接口单独做认证/授权，不要只靠拦截器白名单；扩展名使用服务端白名单并丢弃客户端后缀，校验 MIME 与魔数，图片做二次渲染；上传目录移出 Web 根，必须公开时禁止脚本解析（Tomcat 映射、Nginx `location`、Apache `php_flag engine off`）。
- 加固：`FileTypeEnum` 只作为目录分类，不承担类型校验；对返回的 `url` 做下载/访问代理而不是直接暴露物理目录；限制文件大小与请求频率。
