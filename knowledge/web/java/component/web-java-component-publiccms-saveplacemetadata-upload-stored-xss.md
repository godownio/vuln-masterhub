---
id: web-java-component-publiccms-saveplacemetadata-upload-stored-xss
title: PublicCMS savePlaceMetaData 任意文件上传（CVE-2024-40550）：path 仅删除 ".."，可向 include 目录写入任意 HTML 造成同源存储型 XSS
type: scenario
domain: web
path: web/java/component
technique: publiccms-saveplacemetadata-arbitrary-file-upload-xss
affected_versions: PublicCMS V4.0.202302.e
cve:
- CVE-2024-40550
aliases:
- PublicCMS 任意文件上传
- CVE-2024-40550
- savePlaceMetaData
- cmsTemplate/savePlaceMetaData
- getSafeFileName
- include 目录上传
- PublicCMS 存储型 XSS
tags:
- java
- publiccms
- cve-2024-40550
- file-upload
- arbitrary-file-write
- stored-xss
- cms
- path-filter
- csrf
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:12:04+08:00'
  notes: 已对照原文与23张图核对：图01 savePlaceMetaData @Csrf 入口；图06-10 getTemplateFilePath/getFullTemplatePath/getSafeFileName 仅 replace("..") 后得到 include 目录；图11-14 createFile 写入 123；图15-17 updatePlaceMetadata/savePlaceMetadata 写 metadata.data；图20-21 include 目录与前台访问；图22 拼接 include 访问；图23 14.html 的 <img onerror> 弹窗。修正：原文图23 弹窗实际为 PHPSESSID/XDEBUG_SESSION/PUBLICCMS_ANALYTICS_ID，未出现 JSESSIONID/PUBLICCMS_ADMIN，卡内 Cookie 表述已按实际截图改正（关键 Cookie 可能为 HttpOnly）。原文实测 .jsp 不被解析、RCE 未达成，卡内如实标注。原文明确影响 PublicCMS V4.0.202302.e，已 set-versions。dup-scan pair#172 与 filemanager 任意读写卡为 related（不同产品/端点/危害），保留；dedup 最高分为卡自身，related 为通用 HTML 上传 XSS 与 PublicCMS replace 接口，非同一链。未复跑。
---

## 一句话结论

PublicCMS V4.0.202302.e 的后台接口 `/admin/cmsTemplate/savePlaceMetaData`（需要管理员会话与 CSRF token）把用户传入的 `path` 拼到模板 `include` 目录后直接 `CmsFileUtils.createFile(filepath, content)`；防穿越逻辑 `getSafeFileName` 只是把 `..` 字符串删掉，既不限制扩展名也不限制内容，因此可把任意 HTML/JS 写入 Web 可访问的 `template/site_1/include/` 目录，访问 `/publiccms/include/<文件名>` 即触发同源存储型 XSS，可读取 `document.cookie` 中可见的（非 HttpOnly）Cookie（原文弹窗为 `PHPSESSID`/`XDEBUG_SESSION`/`PUBLICCMS_ANALYTICS_ID`）。原文测试上传 `.jsp` 未被解析，未达成 RCE；CVE 描述的“任意代码执行”是否成立取决于部署对 include 目录的脚本解析配置。

## 原理

- **入口与参数**：`CmsTemplateAdminController.savePlaceMetaData(@RequestAttribute SysSite site, @SessionAttribute SysUser admin, String path, @ModelAttribute CmsPlaceMetadata metadata, String content, ...)`，使用 `@Csrf` 校验，因此需要有效的管理员会话与 CSRF token。
- **路径拼接**：`String filepath = siteComponent.getTemplateFilePath(site.getId(), TemplateComponent.INCLUDE_DIRECTORY + path);`；`getTemplateFilePath` = 模板根目录 + `getFullTemplatePath`。`getFullTemplatePath` 在 path 不以 `/` 或 `\` 开头时返回 `SITE_PATH_PREFIX + siteId + SEPARATOR + CmsFileUtils.getSafeFileName(path)`。
- **过滤缺陷**：`getSafeFileName` 只做 `path.replace("..", "")`（把 `..` 子串删掉），没有规范化、没有 `startsWith` 校验、没有扩展名/内容白名单。删除 `..` 后仍然可以控制 include 目录内的相对文件名（如 `14.html`、`.jsp`），并且可以把内容原样写入。
- **文件创建**：`CmsFileUtils.createFile(filepath, content)` 在文件不存在时调用 `FileUtils.writeStringToFile(file, content, DEFAULT_CHARSET_NAME)`，内容完全由请求的 `content` 字段决定。
- **元数据与可访问性**：写完文件后调用 `metadataComponent.updatePlaceMetadata(filepath, metadata)`，把文件信息写入同目录 `metadata.data`；include 目录属于站点模板目录，PublicCMS 前台会以静态模板资源形式对外提供，因此上传的 `.html` 可直接通过 `/publiccms/include/14.html` 访问并执行其中的脚本。
- **影响边界**：`.html`/`.svg` 等按静态资源返回 → 同源存储型 XSS（可读取非 HttpOnly Cookie、借管理员会话发起后台操作；原文弹窗未出现 `PUBLICCMS_ADMIN`/`JSESSIONID`，关键 Cookie 可能已设 HttpOnly）；`.jsp` 在原文环境中不被解析（作者实测失败），因此该文只证明了任意文件上传 + XSS，未证明 RCE。若目标把 include 目录映射到 JSP/Servlet 解析器，或上传到可执行目录，则可能升级为 RCE。
- **与同类漏洞的区别**：另有 `/admin/cmsTemplate/replace` 的路径穿越任意文件内容替换 + `execScript` RCE（见关联卡）；本漏洞是 `savePlaceMetaData` 的任意文件创建/上传，入口、参数与利用结果不同。

## 触发条件

- 目标为 PublicCMS V4.0.202302.e（或受 CVE-2024-40550 影响的版本）。
- 攻击者拥有管理员账号/会话，并能从后台页面拿到 CSRF token（接口带 `@Csrf`）。
- 模板 include 目录存在且 Web 进程有写权限；该目录可通过 Web 访问。
- 受害者会访问上传后的同源 HTML（管理员/普通用户均可）；若要升级 RCE，需要目标对上传目录的脚本解析配置满足条件。
- 上传文件名可通过 `path` 控制（`..` 会被删除，但不会删除普通文件名/扩展名）。

## 利用步骤

1. 登录 PublicCMS 后台，进入模板管理页面，获取当前 `PUBLICCMS_ADMIN` 会话与页面中的 `_csrf` token。
2. 构造 multipart POST 到 `/publiccms/admin/cmsTemplate/savePlaceMetaData?callbackType=closeCurrent&navTabId=cmsTemplate/list`，字段包括 `_csrf`、`path`、`content`、`encoding=utf-8`、`ajax=1`。
3. 上传验证文件：`path=1.txt`、`content=123`，确认返回 JSON `"message":"操作成功"`，并在 `data/publiccms/template/site_1/include/` 下生成文件。
4. 上传 XSS 页面：`path=14.html`、`content=<img src=1 onerror=alert(document.cookie)>`，访问 `/publiccms/include/14.html` 触发脚本，读取同源 Cookie。
5. 尝试 RCE（可选）：`path=.jsp` 或带 `.jsp` 后缀的文件；原文环境中未被解析。若目标环境不同，需结合目录解析配置评估。
6. 清理：删除上传文件与 `metadata.data` 中对应记录（或调用后台删除接口）。

## PoC

```http
POST /publiccms/admin/cmsTemplate/savePlaceMetaData?callbackType=closeCurrent&navTabId=cmsTemplate/list HTTP/1.1
Host: localhost:8088
Cookie: PUBLICCMS_ADMIN=1_<uuid>; JSESSIONID=<sid>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="_csrf"

<csrf-token>
------boundary
Content-Disposition: form-data; name="path"

14.html
------boundary
Content-Disposition: form-data; name="content"

<img src=1 onerror=alert(document.cookie)>
------boundary
Content-Disposition: form-data; name="encoding"

utf-8
------boundary
Content-Disposition: form-data; name="ajax"

1
------boundary--
```

上传成功后访问 `http://target/publiccms/include/14.html`，脚本在 PublicCMS 源下执行；原文图 23 弹窗显示的是 `PHPSESSID`、`XDEBUG_SESSION`、`PUBLICCMS_ANALYTICS_ID`，未出现 `JSESSIONID`/`PUBLICCMS_ADMIN`（二者可能为 HttpOnly）。

## 变体与关联

- 关联（同类 PublicCMS 后台任意文件能力）：[[web-java-component-publiccms-template-replace-traversal-execscript-rce]]（`/admin/cmsTemplate/replace` 路径穿越替换脚本内容 + `execScript` 执行，可 RCE）。
- 关联：[[web-generic-ssrf-publiccms-method-gethtml-apptoken]]（另一处 PublicCMS 接口的 SSRF）。
- 变体：若 include 目录被 Web 容器按 JSP/Servlet 解析，任意文件上传可升级为 webshell RCE；若只能静态访问，则按存储型 XSS 处理（可读取非 HttpOnly Cookie、在管理员会话下发起同源操作）。
- 检测：`savePlaceMetaData` 请求中 `path` 含脚本/HTML 扩展名、`content` 含 `<script>`/事件处理器、include 目录出现陌生文件。

## 检测与防御

- **修复根因**：对 `path` 做规范化并校验 `startsWith(includeDir)`，同时使用扩展名白名单（只允许模板允许的文本/图片类型）；不要把 `..` 删除当作安全过滤。
- **权限与隔离**：上传目录与 Web 可执行目录分离，禁止 include 目录解析脚本；对模板目录设置只读或独立存储。
- **会话与 CSRF**：`PUBLICCMS_ADMIN` 等敏感 Cookie 设置 HttpOnly/Secure/SameSite，降低 XSS 窃取效果；接口保持 CSRF 校验。
- **检测**：监控后台模板上传接口的异常扩展名/内容、include 目录新增 HTML/JS/JSP 文件、前台对可疑上传文件的访问；CSP 限制内联脚本。
- **响应**：删除恶意文件、轮换管理员会话与 Cookie、审计是否已有管理员操作或进一步 RCE 痕迹，升级到修复版本。
