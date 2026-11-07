---
id: web-generic-file-upload-roothub-custompath-traversal-no-extension
title: RootHub CommonController 上传：customPath 未校验导致任意目录写入且不限制文件后缀
type: scenario
domain: web
path: web/generic/file-upload
technique: roothub-upload-custompath-traversal-no-extension
tags:
- java
- spring
- file-upload
- path-traversal
- arbitrary-write
- roothub
- web
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:27:07+08:00'
  notes: 已对照原文与图01/02/03核对：CommonController @RequestMapping("/common") 的 /upload 接收 @RequestParam("file") MultipartFile 与 @RequestParam(value="customPath", defaultValue="top...") String，调用 storageService.store(file, Paths.get(customPath))，与图01一致；store() 仅对 getOriginalFilename 做 cleanPath + contains("..") 检查，customPath 直接 Paths.get 后拼 getUploadFiledir()，FileNameUtil.getFileName 保留后缀、Files.copy(..., REPLACE_EXISTING)，与图02/03一致；未见后缀白名单。原文为纯代码审计，未给上传请求/回显，任意目录写与 RCE 为按代码推断，卡内 confidence=medium 及“需目标目录可解析”边界正确；PoC 未本机执行。原文未给版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-roothub-custompath-traversal-no-extension/
draft: false
kb_aliases:
- RootHub 任意文件上传
- customPath 路径穿越上传
- 物料资产平台文件上传
- /common/upload
---

## 一句话结论

RootHub 物料资产平台的 `/common/upload` 接口把 `customPath` 参数直接 `Paths.get()` 后拼到上传根目录，未做 `../` 校验；同时 `store()` 只检查原始文件名、不校验扩展名，攻击者可上传任意后缀文件并借助 `customPath=../..` 写入任意目录，若目标目录可被 Web 解析则升级为 RCE。

## 原理

- **入口**：`CommonController.upload(@RequestParam("file") MultipartFile file, @RequestParam(value="customPath", defaultValue="top...") String customPath)`，调用 `storageService.store(file, Paths.get(customPath))`。
- **只防了一半**：`StorageService.store()` 对 `file.getOriginalFilename()` 做 `StringUtils.cleanPath()` 并检查 `filename.contains("..")`，即阻止通过“文件名”目录穿越；但 `customPath` 是独立参数，直接 `Paths.get(customPath)` 传入，没有 `..`/绝对路径校验。
- **路径拼接**：本地存储分支 `path = Paths.get(storageProperties.getUploadFiledir() + path.toString())`，随后 `Files.copy(inputStream, path.resolve(newFilename), REPLACE_EXISTING)`。`customPath` 中的 `../` 在 `Paths.get`/`resolve` 时被规范化，最终可跳出上传根目录。
- **后缀未校验**：`newFilename = FileNameUtil.getFileName(filename)` 只取文件名（保留原始后缀），代码没有扩展名白名单/魔数校验；因此 `.jsp`、`.jspx`、`.html` 等任意类型都能落盘。
- **为什么能升级**：任意目录写 + 任意后缀 + `REPLACE_EXISTING` 允许覆盖；若能写入 Tomcat `webapps/ROOT`、应用静态目录或其他可解析路径，即可部署 JSP WebShell/覆盖配置实现 RCE；至少可覆盖业务文件、写入计划任务/脚本（取决于运行权限）。
- **原文验证边界**：文章为代码审计，展示了 controller/store 代码并断言“可上传任意文件到任意目录”，未给出实际上传请求与回显；本卡按代码判定，confidence 定为 medium。

## 触发条件

- 目标部署 RootHub（backup 分支）或包含相同 `CommonController`/`StorageService` 代码的物料平台。
- `/common/upload` 可达（是否需登录原文未说明，按实际鉴权判断）。
- 存储类型为本地存储（非 OSS）；`storageProperties.getUploadFiledir()` 为可写目录，Seata 进程有权限创建目录/文件。
- `customPath` 未被上游网关/WAF 拦截 `../`；目标目录存在可被 Web 访问/解析的路径。
- 若仅能写入非 Web 目录，则危害为任意文件写/覆盖，RCE 需结合其他条件。

## 利用步骤

1. 确认 `/common/upload` 接口与参数名 `file`、`customPath`。
2. 构造 multipart 请求，`file` 为恶意文件（如 `shell.jsp`），`customPath` 用 `../../webapps/ROOT/` 或相对上传根目录的穿越路径，具体层数按部署目录调整。
3. 观察响应中的 `data`（文件访问 URL）或错误信息，确认落盘路径。
4. 访问写入后的文件；若为 JSP 且目录可解析，即获得 WebShell；若为 HTML，可形成同源 XSS/钓鱼页。
5. 可配合 `REPLACE_EXISTING` 覆盖已有 JSP/配置文件，或写入启动脚本实现持久化。

## PoC

```http
POST /common/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="customPath"

../../webapps/ROOT/
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<% out.println("upload-ok"); %>
------WebKitFormBoundary--
```

（`customPath` 的具体穿越层数与目标目录以实际部署为准；原文未给出可直接复用的完整请求。）

## 变体与关联

- **仅文件名过滤的绕过**：本卡是“文件名过滤了、另一个路径参数没过滤”的典型；类似模式还有上传目录参数、`fileAddr`、`patch`、`metadata.name` 等独立路径参数。
- **后缀变体**：`.jsp/.jspx/.html/.svg`；若目标容器不解析 JSP，可写 `.html` 做存储型 XSS、写 `.properties`/`.xml` 覆盖配置。
- **覆盖利用**：`REPLACE_EXISTING` 可覆盖业务 JSP、模板、jar 配置；结合备份/重启触发。
- **关联**：Spring 上传接口 UUID 重命名保留后缀、上传目录路径穿越、任意文件写转 RCE 等卡片；根因都是“路径/后缀未同时校验”。

## 检测与防御

- **修复**：`customPath` 只允许白名单目录（枚举映射），拒绝绝对路径与 `..`；`Path base = Paths.get(uploadDir).toAbsolutePath().normalize()`，最终路径 `normalize()` 后必须以 `base` 开头；文件后缀白名单 + 魔数校验；上传文件重命名为无后缀/固定后缀，禁止 `REPLACE_EXISTING` 覆盖。
- **存储**：上传目录移出 Web 根，或禁止脚本解析；使用对象存储并设置 `Content-Disposition: attachment`。
- **检测**：`customPath` 含 `../`、`..\\`、绝对路径；上传请求文件名为 `.jsp/.jspx/.html` 等；上传目录出现非预期类型/覆盖已有文件；上传后短时间内访问新文件。
- **排查**：检查上传根目录之外的 Web 目录、临时目录是否出现业务无关文件；对比 JSP/配置文件哈希；审计所有接收路径参数的控制器。
