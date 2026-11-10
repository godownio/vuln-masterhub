---
id: web-java-component-mcms-checkuploadpath-absolute-path-upload
title: MCMS 上传路径校验只拦 ../：uploadPath 传绝对路径/根路径绕过 checkUploadPath，模板、Logo 与 file/upload 三处任意目录写文件
type: scenario
domain: web
path: web/java/component
technique: mcms-checkuploadpath-absolute-path-upload
aliases:
- checkUploadPath 绕过
- uploadPath 绝对路径
- BaseFileAction uploadTemplate
- ManageFileAction upload
- MCMS 站点 logo 任意文件上传
- 上传目录穿越
tags:
- file-upload
- path-traversal
- arbitrary-file-write
- java
- springboot
- cms
- mcms
cve: []
severity: high
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.8（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:08:46+08:00'
  notes: 已通读原文并逐张核对本地图：图20/21/51/52 checkUploadPath 只查 ../ 与 ..\ ；图14-19 模板上传、图23-28 Logo 上传、图53-55 /ms/file/upload.do 均回显落盘路径；图22 BaseFileAction 对绝对路径直接采用。注意：Logo 截图实际 uploadPath=C:/Program Files/Git/appLogo、appId=30，响应为 /upload/1/appLogo，卡内 uploadPath=/ 为概括，完整绝对路径写入为原文文字声称与同函数推断，原文未演示。未验证点：PoC 未复跑；无 sources/source_url。
---

## 一句话结论

MCMS 的 `checkUploadPath(Bean)` 只判断 `uploadPath` 是否包含 `../` 或 `..\`，传 `/`、`C:/...` 等不含 `..` 的绝对路径即可通过；`BaseFileAction.uploadTemplate()`/`upload()` 直接用该路径构造 `File` 写入，因此后台的模板上传 `/ms/file/uploadTemplate.do`、站点 Logo 上传 `/ms/app/-1/edit.do` 以及 `/ms/file/upload.do` 都能把任意内容写到任意可写目录，返回的 `data` 还会给出落盘路径。

## 原理

- **校验函数只覆盖相对穿越**：`protected boolean checkUploadPath(Bean bean) { return bean.getUploadPath() != null && (bean.getUploadPath().contains("../") || bean.getUploadPath().contains("..\\")); }`——只拦截“两点+斜杠”的相对路径穿越。绝对路径 `/`、`/upload`、`C:\inetpub\wwwroot` 不含 `..`，直接放行。
- **写入端信任 uploadPath**：`ManageFileAction#uploadTemplate` 在 `checkUploadPath` 通过后，把 `uploadPath` 放进 `Config` 交给 `BaseFileAction#uploadTemplate`；后者判断 `new File(uploadTemplatePath).isAbsolute()`，绝对路径时直接作为真实路径使用，`FileWriter`/上传流按该路径落盘。路径没有做规范化（canonicalize）和“必须位于上传根目录内”的二次校验。
- **三处入口共用同一缺陷**：
  - 模板上传：`ManageFileAction#uploadTemplate` → `/ms/file/uploadTemplate.do`，`uploadPath` 可传 `/`，文件落到 webapp 根或模板目录。
  - 站点 Logo：`/ms/app/-1/edit.do` 的 multipart 上传，`uploadPath=/`，`appId=30` 时实际路径为 `/upload/1/appLogo/<时间戳>.<ext>`。
  - 通用上传：`ManageFileAction#upload` → `/ms/file/upload.do`，同样只过 `checkUploadPath`。
- **为什么能拿到路径**：上传响应 `{"result":true,"code":200,"data":"/upload/1/appLogo/1709726541909.txt"}` 直接告诉攻击者文件 URL；文章/模板目录又位于 `webapp` 下，随后可访问验证。
- **危害**：任意文件写入本身可覆盖配置/模板/静态资源；若目标容器会把写入目录中的 `.jsp/.jspx` 当 JSP 解析，则可进一步 getshell（本卡只证明任意文件写；JSP 落地链见同层 MCMS 上传/解压卡）。

## 触发条件

- 攻击者能访问后台上传接口（本案例需登录后台；若存在未授权路由/弱口令则门槛更低）。
- `uploadPath` 参数可控且服务端只做 `../` 黑名单；目标目录对应用进程可写。
- 上传接口未额外做扩展名白名单（或白名单可绕过），且落盘目录在 Web 可访问路径下（便于验证/利用）。
- 文件重命名（`isRename=true`）只会改文件名，不影响目录选择。

## 利用步骤

1. 登录后台，进入模板管理/站点设置/文件上传功能，抓取 multipart 请求。
2. 把 `uploadPath` 改为 `/`（或目标绝对路径），`uploadFloderPath=true`、`isRename` 按需设置，附带任意内容文件（如 `1.txt`，`Content-Type: text/html`）。
3. 发送 `/ms/file/uploadTemplate.do`（模板）、`/ms/app/-1/edit.do`（Logo）或 `/ms/file/upload.do`（通用上传）。
4. 从响应 `data` 取落盘路径，访问确认内容写入。
5. 若写入目录可解析 JSP，将内容换成 JSP webshell 并访问；否则可覆盖模板/静态文件或写入计划任务可读路径（取决于权限）。

## PoC

```http
POST /ms/file/uploadTemplate.do HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="uploadPath"

/
------WebKitFormBoundaryX
Content-Disposition: form-data; name="uploadFloderPath"

true
------WebKitFormBoundaryX
Content-Disposition: form-data; name="rename"

false
------WebKitFormBoundaryX
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/html

test
------WebKitFormBoundaryX--
```

响应示例：`{"result":true,"code":200,"data":"/template/1/1709723660886.txt"}`；Logo 接口响应 `data` 形如 `/upload/1/appLogo/<时间戳>.txt`。

## 变体与关联

- 同项目其它上传绕过：`web-java-component-mcms-fileaction-upload-blacklist-jspx-ads`（`/file/upload.do` 未授权 + 后缀黑名单仅 `.exe/.jsp`，用 `.jspx`/NTFS ADS 绕过）、`web-generic-file-upload-mcms-uploadtemplate-zip-magic-header-jsp`（zip 魔数伪装绕过 Tika 检查）。
- 本卡的独特点是“路径校验只查 `../`、绝对路径放行”，与后缀黑名单绕过是两条独立绕过线，可组合使用。
- 通用防御见 `web/generic/file-upload` 同层卡；上传目录穿越的其它案例可参考 `web-generic-file-upload-ueditor-filepathformat-traversal`。

## 检测与防御

- 修复：上传路径不接受客户端绝对路径；用 `Path.normalize()`/`getCanonicalPath()` 后校验必须位于配置的上传根目录内；`checkUploadPath` 同时拒绝绝对路径、盘符、UNC、URL 编码变体。
- 扩展名：使用白名单而非黑名单；重命名时保留安全扩展名；上传目录禁止脚本解析（Nginx/Apache 配置 `Location` 禁止执行）。
- 检测：上传请求中 `uploadPath` 以 `/`、盘符、`\\` 开头；响应 `data` 指向非预期目录；Web 目录出现非图片/非文档扩展名文件。
- 加固：上传目录与 Web 根分离、对象存储直传；对上传接口做鉴权与 CSRF 防护；定期扫描 webapp 下新增可执行文件。
