---
id: web-generic-file-upload-weaver-ebridge-multipart-name-overwrite-jsp
title: 泛微云桥 e-Bridge 任意文件上传：同名 multipart 字段覆盖 O'Reilly MultipartRequest files 哈希表绕过 isSafeFile
type: scenario
domain: web
path: web/generic/file-upload
technique: weaver-ebridge-multipart-name-overwrite-jsp-upload
aliases:
- 泛微云桥 e-Bridge 文件上传
- ResumeController addResume
- 同名 file 字段覆盖
- MultipartRequest files Hashtable
- isSafeFile 绕过
- JFinal 多部件同名上传
- 云桥 JSP 上传
tags:
- web
- java
- file-upload
- jfinal
- oreilly
- multipart
- hash-overwrite
- jsp
- weaver
- ebridge
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:17:26+08:00'
  notes: 已对照原文与11张图核对：图01/05/08 显示 oreilly MultipartRequest 先 writeTo 再 files.put(name, UploadedFile)，图04 为两个同名 name=file 部件（harder.jsp 与 harder.png），图03 显示两文件均已落盘，图07 getFilesystemName 从 files.get(name) 取到 harder.png，图09 isSafeFile 断点对象 fileName=harder.png（originalFileName=harder.png），图11 /upload/202407/CY/1.txt 返回 1 证明目录 Web 可访问。卡内链路与原文一致；JSP 执行绕过（URL 编码后缀/jsp;）已标注来自引用他文、未验证，置信度 medium 合理；原文未给版本，未设 affected_versions。未执行 PoC。
---

## 一句话结论

泛微云桥 e-Bridge 的 `/wxclient/app/recruit/resume/addResume` 使用 JFinal 封装的上传链（`ResumeController#addResume` → `BaseController#getWxBaseFile` → `Controller.getFiles` → `com.jfinal.upload.MultipartRequest` → `com.oreilly.servlet.MultipartRequest`）。O'Reilly `MultipartRequest` 把每个文件部件按**表单字段名**存入 `Hashtable files`，同名 `file` 的第二个部件（`harder.png`）会覆盖第一个部件（`harder.jsp`）的映射；两个部件都已先写入上传目录，但随后 `isSafeFile(UploadFile)` 检查到的是哈希表里留下的 PNG 对象，`.jsp` 因此绕过后缀拦截落盘。文章验证了上传成功并可通过 `/upload/202407/CY/1.txt` 访问落盘文件；要拿到 JSP 执行还需利用 JFinal 与 Tomcat 的路径解析差异（后缀 URL 编码或 `jsp;`），该绕过是文章引用他文所述，未在本篇给出执行验证。

## 原理

- **上传入口**：`ResumeController#addResume` 由 `@ActionKey("/wxclient/app/recruit/resume/addResume")` 暴露，检测 `multipart/form-data` 后调用 `getWxBaseFile(service, getPara("fileElementId"), null, 2097152, null)`。该调用最终进入 JFinal 的 `Controller#getFiles` 与 JFinal 自己的 `com.jfinal.upload.MultipartRequest`，后者在 `wrapMultipartRequest` 中实例化 `com.oreilly.servlet.MultipartRequest`。
- **O'Reilly 的 files 哈希表**：`com.oreilly.servlet.MultipartRequest` 内部有 `protected Hashtable files`。构造时遍历每个文件部件：先 `filePart.writeTo(dir)` 把文件写到保存目录，再执行 `files.put(name, new UploadedFile(dir.toString(), filePart.getFileName(), fileName, filePart.getContentType()))`，其中 `name` 是表单字段名。两个部件都使用 `name="file"` 时，后一个 `harder.png` 覆盖前一个 `harder.jsp` 的键值，但两个文件都已经落盘。
- **JFinal 侧读取错位**：JFinal 的 `getFiles` 遍历 `multipartRequest.getFileNames()`/`nameElements()`，对每个名字调用 `multipartRequest.getFilesystemName(name)`；该方法实现为 `UploadedFile file = (UploadedFile) this.files.get(name); return file.getFilesystemName();`。由于键 `file` 已被 PNG 覆盖，返回的是 `harder.png`；`getOriginalFileName(name)`、`getContentType(name)` 同样取到 PNG 的值，最终构造出的 `UploadFile` 的 `fileName/originalFileName` 都是 `harder.png`。
- **isSafeFile 看错对象**：JFinal 随后执行 `if (!isSafeFile(uploadFile))`；`isSafeFile` 只检查 `uploadFile.getFileName().toLowerCase().endsWith(".jsp")`，命中才 `uploadFile.getFile().delete()` 并返回 false。此时 `uploadFile` 指向 PNG，检查通过，`.jsp` 文件未被删除，留在上传目录。
- **为什么可行**：文件落盘是“按部件逐个执行”，而安全检查与后续对象构造是“按字段名从哈希表取最后一条”，两套记录不一致；同名部件让安全函数检查的对象与实际落盘的恶意文件不是同一个。这是上传组件用非唯一字段名做 key 导致的典型 hash/状态覆盖问题。
- **路径与解析**：文章示例落盘 URL 形如 `/upload/202407/CY/1.txt`，目录中含有 1~2 位随机大写字母（示例 `CY`）；文章称可利用条件竞争进一步绕过，但随机目录增大了竞争难度。JSP 能否执行取决于 JFinal/Tomcat 对路径的解析差异：文章引用他文总结的绕过方式是（1）对 `.jsp` 后缀做 URL 编码；（2）在 `jsp` 后加分号，如 `harder.jsp;`。

## 触发条件

- 目标为泛微云桥 e-Bridge，`/wxclient/app/recruit/resume/addResume` 可访问（未授权或低权限即可，示例直接 POST）。
- 上传逻辑使用 O'Reilly `MultipartRequest`（或被 JFinal 包装的同类实现），且按表单字段名存储文件、同名 key 会被后者覆盖。
- 上传目录位于 Web 可访问路径下，且允许写入 `.jsp` 等脚本后缀（或存在 JFinal/Tomcat 解析绕过）。
- 同一 multipart 请求中可发送两个同名文件部件；服务端未拒绝重复字段名。

## 利用步骤

1. 确认目标存在 e-Bridge 与上传入口，抓取正常简历上传请求，记录 multipart 字段名（示例为 `file`）。
2. 构造一个 multipart 请求，包含两个同名 `file` 部件：
   - 第一个部件：`filename="harder.jsp"`，`Content-Type: image/png`，内容为 JSP 代码（如 `<% out.println("Hello World-2023"); %>`）；
   - 第二个部件：`filename="harder.png"`，`Content-Type: image/png`，内容随意（如 `1`）。
3. 发送请求；O'Reilly 构造阶段会把两个文件都写入上传目录，哈希表 `file` 键记录的是后一个 PNG。
4. JFinal `getFiles` 取到 PNG 的 `filesystemName/originalFileName/contentType` 构造 `UploadFile`，`isSafeFile` 检查 PNG 后缀通过，返回“提交成功”；`.jsp` 留在磁盘。
5. 从响应/已知上传路径规则推导落盘 URL（示例 `/upload/YYYYMM/<1-2 位大写字母>/<文件名>`），访问 `.txt` 等非脚本文件验证目录可访问。
6. 对 `.jsp` 访问按 JFinal/Tomcat 解析差异尝试绕过：后缀 URL 编码（如 `harder%2Ejsp`）或在文件名后加 `;`（如 `harder.jsp;`）；文章仅引用他文给出这两种方式，未在本篇演示 JSP 执行。
7. 若目标存在定期清理/条件竞争窗口，按文章提示可在文件落盘到被处理前竞争访问，但随机 1~2 位大写目录会显著增加难度。

## PoC

请求示例（与文章截图一致，字段名与路径按目标调整）：

```http
POST /wxclient/app/recruit/resume/addResume?fileElementId=aaa HTTP/1.1
Host: 192.168.52.134:8088
User-Agent: Mozilla/5.0
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary72teVnxhbdTTaUf
Content-Length: 323

------WebKitFormBoundary72teVnxhbdTTaUf
Content-Disposition: form-data; name="file"; filename="harder.jsp"
Content-Type: image/png

<% out.println("Hello World-2023"); %>
------WebKitFormBoundary72teVnxhbdTTaUf
Content-Disposition: form-data; name="file"; filename="harder.png"
Content-Type: image/png

1
------WebKitFormBoundary72teVnxhbdTTaUf--
```

落盘验证：上传成功后目录中同时存在 `harder.jsp` 与 `harder`（PNG）；示例通过 `/upload/202407/CY/1.txt` 返回 `1`，证明上传目录可通过 Web 访问。JSP 执行绕过（URL 编码后缀 / `harder.jsp;`）来自文章引用的另一篇分析，本文未给出实际访问截图。

## 变体与关联

- [[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]：同为 JFinal 上传/文件管理问题，但那张卡是 `path/currentpath` 未过滤导致任意读/写/下载，JSP 直连被 JFinalFilter 404 后改写模板拿 RCE；本卡是 multipart 同名 key 覆盖导致安全检查对象错位。
- [[web-java-component-tomcat-semicolon-path-param-access-bypass]]：Tomcat 分号路径参数解析差异，可与本卡最后一步的 `jsp;` 绕过相互参照。
- [[web-generic-file-upload-upload1-filename-traversal-jsp-webroot]]：另一类“原始文件名 + Web 目录写 JSP”的上传；本卡的差异点是不依赖路径穿越，而依赖同名字段覆盖安全检查对象。
- [[web-generic-file-upload-whir-ezoffice-fileupload-action-extension]]、[[web-generic-file-upload-hanvon-eface-original-suffix-resource-jsp]]：其他 OA 产品保留原始后缀落 JSP 的案例，可对照检测规则。
- 变体：若上传字段名不固定，可枚举控制器使用的字段名/`fileElementId`；不同 JFinal/oreilly 版本对同名部件的处理可能不同（有的取第一个、有的报错）。
- 边界：文章只验证了任意文件上传与目录可访问，未验证 JSP 执行；实际 RCE 取决于 JFinal/Tomcat 版本、上传目录是否禁止脚本解析、是否启用 JFinalFilter 全路径过滤等，利用前需自行确认。

## 检测与防御

- **检测**：multipart 请求中出现重复 `name`、同一字段名混合 `.jsp`/图片后缀；`Content-Disposition` 的 filename 为脚本后缀但 `Content-Type` 为 `image/*`；上传目录出现 `.jsp`/`.jspx`/`.war` 等脚本文件；访问 `/upload/.../*.jsp`、URL 编码后缀或 `;` 变体；同一请求中文件数量与业务预期不符。
- **防御**：升级 e-Bridge/JFinal/oreilly MultipartRequest 到修复版本；上传组件按“每个部件独立对象”校验，禁止用非唯一表单字段名作为文件 map 的 key，拒绝重复字段名；对每个部件同时校验原始文件名、存储名、Content-Type 与文件内容（magic/脚本特征）；上传目录移出 Web 根目录并通过下载接口输出；上传目录禁用脚本解析（Tomcat 侧移除 JSP Servlet 映射/关闭脚本执行）；JFinalFilter/网关统一规范化路径并拦截编码后缀、分号与脚本扩展名。
- **响应**：检查上传目录与访问日志，删除恶意 `.jsp` 及同名图片；回溯请求中重复 `file` 字段的来源 IP；确认是否已有 JSP 被执行。
