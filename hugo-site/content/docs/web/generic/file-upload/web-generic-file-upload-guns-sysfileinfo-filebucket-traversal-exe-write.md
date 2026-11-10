---
id: web-generic-file-upload-guns-sysfileinfo-filebucket-traversal-exe-write
title: Guns 后台 sysFileInfo/upload：fileBucket 目录穿越 + 原文件名后缀，把 .exe 写到任意目录（启动项持久化/钓鱼）
type: scenario
domain: web
path: web/generic/file-upload
technique: guns-sysfileinfo-filebucket-traversal-extension
tags:
- java
- spring
- guns
- file-upload
- path-traversal
- arbitrary-write
- persistence
- phishing
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:31:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文（原文 12 张含拦截器代码与落盘路径的截图未读）。请求包字段（file/filename=.exe/secretFlag/fileBucket）、fileBucket 决定目录+fieldId 决定主名+filename 只定后缀、落点与钓鱼/启动项用途均与原文一致；两处需注意：(1) 原文穿越段实际为 18 层 ../（正文写作约 19 层，属近似表述）；(2) 原文只贴出带管理员 JWT 的请求，未做未授权验证，卡内“该接口要求登录、需后台 JWT”属推断，已写入触发条件。原文未标注 Guns 版本，affected_versions 保持 null；未访问文中地址。
url: /docs/web/generic/file-upload/web-generic-file-upload-guns-sysfileinfo-filebucket-traversal-exe-write/
draft: false
kb_aliases:
- Guns 任意文件上传
- sysFileInfo/upload 上传
- fileBucket 路径穿越
- 文件夹就是 fieldid
- 上传到启动项
---

## 一句话结论

Guns 后台的 `POST /api/sysFileInfo/upload` 虽然改 `filename` 不能决定最终落盘名（服务端固定用记录主键 `fieldId` 拼名），但 `fileBucket` 参数被直接当作目录拼入路径且未过滤 `../`，而扩展名又取自客户端原始文件名，于是「目录由 `fileBucket` 完全控制、名字是 `<fieldId>`、后缀由上传文件名控制」，可以把任意内容的 `.exe` 写进目标机任意可写目录——写进当前用户启动目录即开机自启，写进用户目录配合社工即钓鱼执行。

## 原理

- **入口与鉴权**：`/api/sysFileInfo/upload` 走 Guns 的 `HandlerInterceptor`（`TokenAndPermissionInterceptor`）鉴权：先按 `getRequestURI()` 匹配白名单，若请求带 `Authorization` 头则校验 JWT，无 token 时再查 `resourceServiceApi` 中该路由是否 `@GetResource(requiredLogin = false)`。实测环境中请求带的是管理员账号的 JWT，因此这条链的前提是**已拿到后台权限**（或后台存在弱口令/其它入口），不是未授权漏洞。
- **落盘路径的拼法**：`SysFileInfo` 的实体里有 `fileBucket`（业务桶/目录）、`fileOriginName`、`fileSuffix`、`fileObjectName` 等字段；上传时服务端把 `fileBucket` 当目录、把「记录 id」当文件名、把原始文件名的后缀当扩展名，拼成 `fileBucket/<fieldId>.<suffix>` 后写入磁盘。因此：
  - 改 `filename` 只影响后缀，改不了文件主名；
  - 改 `fileBucket` 就改了整个目录前缀。
- **为什么穿越成立**：`fileBucket` 只是被字符串拼接/`Paths.get` 后 `resolve`，没有做 `normalize()` 后的根目录前缀校验，`../../..` 会在拼接时被文件系统吃掉，最终落到上传根目录之外；实际测试的请求里塞了约 19 层 `../` 并跟一段中文目录名，落点即「盘符根目录下的那个中文目录」。
- **为什么能当可执行文件用**：后缀取自 `filename=".exe"`（原始文件名只有一个点加后缀时，取后缀逻辑得到 `exe`），内容由 multipart 的 `file` 部分完全控制，于是得到 `<fieldId>.exe`。主名不可控并不影响利用：`.exe` 的内容和目录都可控，只需要事后知道文件名（响应里会回显，或按 id 推断）。
- **危害升级路径**：写进 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 即当前用户登录自启；写进 `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` 即所有用户登录自启；写进用户下载/桌面目录再配合文件名社工即钓鱼；若服务以高权限运行且目录可写，还可覆盖其它可执行文件或脚本。

## 触发条件

- 已获得 Guns 后台有效 JWT（管理员或任意可访问 `/api/sysFileInfo/upload` 的账号）；该接口本身要求登录。
- 上传根目录与目标目录在同一分区，且穿越后的目标目录对运行 Guns 的账户可写（Windows 上用 Tomcat/内嵌容器以服务账户或当前用户运行）。
- `fileBucket` 未被上游 WAF/网关拦截 `../`（实测环境直连 `9000` 端口，未见拦截）。
- 目标机存在启动目录等可被利用的落点；若只写到普通目录，则降级为任意文件写。

## 利用步骤

1. 登录后台拿到 `Authorization` JWT。
2. 构造 multipart 请求：`file` 部分 `filename=".exe"`、内容为载荷；额外带 `secretFlag`（原样保留，值随意）与 `fileBucket`，`fileBucket` 用足量 `../` 跳到目标目录。
3. 发送到 `/api/sysFileInfo/upload`，从响应中取回 `fileId`/`fileObjectName`，得到实际文件名 `<fieldId>.exe`。
4. 若落点是启动目录，注销/重启后自动执行；若是普通目录，配合社工或二次下载执行。
5. 清理：调用业务删除接口或直接删除文件，并检查 `sys_file_info` 表中新增记录（会留下 `fileBucket` 含 `../` 的异常行）。

## PoC

实测请求（Host、JWT、目录名按原样；此处不改写为可执行载荷）：

```http
POST /api/sysFileInfo/upload HTTP/1.1
Host: 192.168.91.130:9000
Authorization: <后台管理员 JWT>
Content-Type: multipart/form-data; boundary=---------------------------4047569836919132683218702

-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="file"; filename=".exe"
Content-Type: image/png

1111
-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="secretFlag"

N
-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="fileBucket"

../../../../../../../../../../../../../../../../../../看到请点击exe备份
-----------------------------4047569836919132683218702--
```

要点复述：`filename` 只提供后缀（`.exe`），`fileBucket` 提供目录（用 `../` 跳出上传根），最终文件名为 `<fieldId>.exe`。

## 变体与关联

- **变体：`fileBucket` 直接写绝对路径**（如 `C:\Users\Public\`），若拼接实现是字符串相加而非 `resolve`，可绕过相对层级计算。
- **变体：后缀换成 `.bat`/`.lnk` 生成器输入/`.ps1`**，落进启动目录同样自启；换成 `.jsp`/`.jspx` 则取决于上传根是否在 Web 根内（Guns 默认上传目录通常在 webapp 之外，本场景未验证能否被解析）。
- **变体：只改 `filename`**（不改 `fileBucket`）→ 后缀可控但目录被限制在上传根内，可用于上传 `.html`/`.svg` 做存储型 XSS 或覆盖同名 `fieldId` 文件。
- **关联**：[[web-generic-file-upload-upload1-filename-traversal-jsp-webroot]]（文件名穿越落 Web 根）、[[web-generic-file-upload-roothub-custompath-traversal-no-extension]]（另一个「目录参数没校验、后缀不校验」的同型缺陷）、[[pentest-initial-access-lnk-ftp-fsharp-signed-interpreter]]（落地物如何被诱导执行）。
- 边界：需要后台 JWT；文件名主名不可控，需要能从响应或 `fieldId` 推出；启动目录落点要求 Guns 进程账户与目标用户一致或具备写权限。

## 检测与防御

- **修复**：`fileBucket` 只允许枚举值/白名单目录映射，拒绝 `..`、绝对路径与盘符；拼路径后用 `Path.toAbsolutePath().normalize()` 并校验 `startsWith(uploadRoot)`；扩展名改服务端白名单（图片/文档）并做魔数校验；落盘名统一 UUID + 固定后缀，禁止使用原始文件名的后缀。
- **加固**：上传目录移出 Web 根并禁止脚本解析；运行 Guns 的账户降权（不对启动目录、用户目录可写）；上传接口加 CSRF/签名与频率限制。
- **检测**：`fileBucket` 含 `../`、`..\`、绝对路径；原始文件名为 `.exe`/`.bat`/`.lnk` 等可执行后缀；上传根之外（尤其启动目录、用户目录、`System32`）出现 `<数字>.exe`；`sys_file_info` 表中 `file_bucket` 字段出现穿越串；上传后短时间内出现该文件的执行（4688/Sysmon 1 的 Image 路径与父进程为 explorer）。
- **排查**：审计 `/api/sysFileInfo/*` 的调用记录与 JWT 来源，确认后台账号是否被弱口令/钓鱼获取；对上传根做全量哈希比对，找出非业务文件。
