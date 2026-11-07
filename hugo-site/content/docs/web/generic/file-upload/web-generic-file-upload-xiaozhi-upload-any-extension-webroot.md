---
id: web-generic-file-upload-xiaozhi-upload-any-extension-webroot
title: 小智 ESP32 管理平台：/api/file/upload 仅取原始后缀且无类型校验，任意文件落 Web 可访问 uploads 目录
type: scenario
domain: web
path: web/generic/file-upload
technique: spring-upload-original-extension-no-validation
tags:
- file-upload
- java
- spring
- unrestricted-upload
- webroot
- uuid-rename
- xiaozhi
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:10:34+08:00'
  notes: '已对照原文与图28-31核对：FileUploadController @PostMapping(/upload)，UUID+extension 命名，FileUploadUtils.smartUpload 按配置走 COS 或本地 uploadFile，uploadFile 仅 assertAllowed 大小校验后 IOUtils.copy，无后缀/内容校验；实测 POST /api/file/upload 携带 Cookie: username=admin 上传 test.jsp 返回 200 与 /uploads/common/2025/11/28/uuid.jsp URL。未验证点：文章未访问 JSP 验证执行，卡已标 medium；type 参数路径穿越未测试；frontmatter 无 sources/source_url。'
url: /docs/web/generic/file-upload/web-generic-file-upload-xiaozhi-upload-any-extension-webroot/
draft: false
kb_aliases:
- 小智 ESP32 任意文件上传
- /api/file/upload
- UUID+extension 上传
- uploads 目录任意文件
- 无后缀校验上传
- 存储型 XSS 上传
---

## 一句话结论

小智 ESP32 管理平台的 `POST /api/file/upload` 直接取原始文件名的最后一个后缀，用 `UUID + extension` 命名并保存到 Web 根下的 `uploads/<type>/<yyyy/MM/dd>/`；`FileUploadUtils.uploadFile` 只校验文件大小，不做扩展名白名单、Content-Type 或内容校验，攻击者可上传任意类型文件（如 `.jsp`、`.html`、`.svg`），并通过 `/uploads/**` 公开路径访问。文章只验证了上传成功与 URL 返回，未验证 JSP 执行。

## 原理

- 入口：`FileUploadController#uploadFile`，`@PostMapping("/upload")`，参数 `MultipartFile file` 与 `type`（默认 `common`）。
- 路径：`datePath = LocalDate.now().format("yyyy/MM/dd")`，`relativePath = type + "/" + datePath`。
- 文件名：`originalFilename = file.getOriginalFilename()`，`extension = originalFilename.substring(originalFilename.lastIndexOf("."))`，`fileName = UUID.randomUUID().toString().replaceAll("-", "") + extension`。
- 上传：`FileUploadUtils.smartUpload(uploadPath, relativePath, fileName, file)`；若配置了腾讯云 COS 则上传到 COS，否则本地 `uploadFile`。
- 本地写入：`uploadFile` 仅 `assertAllowed(file)` 检查大小（文章代码 53 行），创建 `baseDir + File.separator + relativePath` 目录，`File destFile = new File(directory, fileName)`，`IOUtils.copy(file.getInputStream(), fos)`；没有后缀白名单、没有图片头/MIME 校验、没有内容扫描。
- 可访问性：`/uploads/**` 在拦截器排除列表中，上传后的文件可通过 `http://host/uploads/common/2025/11/28/<uuid>.jsp` 直接访问（文章响应返回 `url`、`relativePath`、`newFileName`、`hash`）。
- 危害：任意文件写入 Web 可访问目录。若目标能解析上传的脚本后缀（如传统 Tomcat + JSP），可 getshell；在 Spring Boot 默认静态资源模式下 JSP 通常不执行，但仍可托管 HTML/SVG 造成同源存储型 XSS、钓鱼页或恶意文件分发。文章只上传 `test.jsp` 内容为 `test`，未验证执行。

## 触发条件

- 目标为小智 ESP32 Server Java 管理平台，`/api/file/upload` 可达。
- 该接口不在白名单中，需要有效会话；文章请求携带 `Cookie: username=admin`（可由 Cookie 冒充或密码重置获得）。
- 本地存储模式（未配置腾讯云 COS）或 COS 允许任意后缀上传。
- 目标对上传目录的静态访问开放（`/uploads/**` 已放行）。

## 利用步骤

1. 获取有效会话（Cookie 冒充、JWT 伪造或密码重置）。
2. 构造 multipart POST 到 `/api/file/upload`，`file` 字段文件名设为 `test.jsp`（或 `x.html`/`x.svg`），内容为脚本或 HTML；`type` 设为 `common`/`image` 等。
3. 响应返回 `fileName`、`relativePath`、`newFileName`、`url`，确认文件已写入。
4. 访问返回的 `url`（如 `/uploads/common/2025/11/28/<uuid>.jsp`）验证文件可公开访问。
5. 若目标为可解析 JSP 的传统容器，将内容替换为 webshell；否则用 HTML/SVG 做同源存储型 XSS/钓鱼，或托管恶意文件。

## PoC

```http
POST /api/file/upload HTTP/1.1
Host: target.example:10808
Cookie: username=admin
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuxLzULmmlfW0hCjK
Content-Length: 141

------WebKitFormBoundaryuxLzULmmlfW0hCjK
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: image/png

test
------WebKitFormBoundaryuxLzULmmlfW0hCjK
Content-Disposition: form-data; name="type"

image
------WebKitFormBoundaryuxLzULmmlfW0hCjK--
```

```text
# 预期：HTTP/1.1 200
# {"fileName":"test.jsp","code":200,"relativePath":"uploads/common/2025/11/28/",
#  "newFileName":"9676703ad0914c3ebbacc148a01708fc.jsp","message":"上传成功",
#  "hash":"...","url":"http://target/uploads/common/2025/11/28/9676703ad0914c3ebbacc148a01708fc.jsp"}
# 访问 url 可下载/打开该文件；文章未验证 JSP 被执行。
```

## 变体与关联

- 变体：上传 `.html`/`.svg` 可在同源下执行脚本（存储型 XSS），`.jsp`/`.jspx` 在支持 JSP 的容器可能 getshell，`.war`/`.xml` 等按目标解析规则评估。
- 变体：`type` 参数可控，可改变相对目录（如 `type=../../`），但文章未测试路径穿越；文件名本身由 UUID 生成，不含原始路径。
- 关联：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]（仅校验大小/无后缀校验的上传 getshell）；[[web-generic-file-upload-roothub-custompath-traversal-no-extension]]（不限制后缀的上传）；[[web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx]]（Web 根可访问上传）。
- 边界：文章只证明上传成功与返回公开 URL，未证明脚本执行；Spring Boot 默认静态资源不编译 JSP，故 RCE 不成立时仍可作为存储型 XSS/文件托管。confidence 定为 medium。

## 检测与防御

- 检测：审计上传接口的后缀/内容校验；监控 `/api/file/upload` 上传 `.jsp`、`.html`、`.svg`、`.war` 等非预期类型；监控 `/uploads/` 下新增的可执行/脚本文件与被访问情况。
- 修复：扩展名白名单 + 内容/魔数校验 + 重命名为无意义的固定安全后缀；上传目录禁止脚本执行（IIS/Tomcat/Spring 静态资源均配置为不可执行）；不要将上传目录放在 Web 根下。
- 加固：上传接口要求认证与权限校验；限制文件大小与类型；对上传内容做病毒/HTML 扫描；`/uploads/**` 响应加 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`。
