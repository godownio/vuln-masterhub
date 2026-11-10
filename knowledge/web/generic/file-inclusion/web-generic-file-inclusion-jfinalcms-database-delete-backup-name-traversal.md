---
id: web-generic-file-inclusion-jfinalcms-database-delete-backup-name-traversal
title: JFinalCMS 后台 /admin/database/delete 备份名直接拼路径：../../ 穿越删除 Web 根目录外任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: jfinalcms-database-delete-backup-name-path-traversal
aliases:
- JFinalCMS 任意文件删除
- DatabaseController delete
- BackupUtils.delete
- backupName 路径穿越
- 删除接口任意文件
- name=../../../../flag.txt
tags:
- web
- java
- jfinalcms
- cms
- file-delete
- arbitrary-file-deletion
- path-traversal
- admin
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:59:41+08:00'
  notes: 已对照原文与图01-04核对：DatabaseController /delete → BackupUtils.delete(name)、webRoot+BACK_PATH+backupName、仅 exists 后 deleteQuietly、name=../../../../../../../../flag.txt 删除 flag.txt、响应 {type:success} 均一致；需后台 JSESSIONID；原文未给版本/CVE 编号。未复现
---

## 一句话结论

JFinalCMS 后台 `DatabaseController` 的 `/admin/database/delete` 把请求参数 `name` 原样传给 `BackupUtils.delete`，后者拼成 `PathUtils.getWebRootPath() + "/" + BACK_PATH + "/" + backupName` 后只调用 `File.exists()` 判断存在性，就直接 `FileUtils.deleteQuietly` 删除，完全没有规范化路径或过滤 `..`；登录后台后提交 `name=../../../../../../flag.txt` 即可删除 Web 根目录外的任意文件，接口仍返回 JSON `success`。

## 原理

- **拼接式路径**：`BackupUtils.delete(String backupName)` 内 `new File(PathUtils.getWebRootPath() + "/" + CommonConstant.BACK_PATH + "/" + backupName)`。`backupName` 来自 HTTP 参数，未做 `..`、绝对路径或分隔符过滤。
- **只校验存在性**：代码只有 `if (!backupFile.exists()) return;`，没有 `getCanonicalPath()` 后判断是否仍在备份目录内。`File.exists()` 对 `../` 解析后的真实路径同样返回 true，因此穿越路径不会被拦。
- **删除动作**：`FileUtils.deleteQuietly(backupFile)` 直接删除文件（文件不存在或删除失败也不抛异常），所以只要进程有权限，目标文件就会被删；返回 `Feedback.success(...)`，攻击者得到成功回执。
- **危害**：可删除应用配置、数据库备份、安装锁文件、日志、其它站点文件等；删除安装锁可能导致重新安装/覆盖配置，删除关键文件可造成拒绝服务或为后续利用铺路。接口在后台，需要有效管理员会话（PoC 中带 `JSESSIONID`）。
- **黑盒可达**：参数直接出现在表单体里，黑盒抓包改 `name` 即可验证，不必先读源码。

## 触发条件

- 攻击者拥有 JFinalCMS 后台管理员会话（或后台鉴权可绕过）。
- `/admin/database/delete` 路由可达，`name` 参数被接收。
- 目标文件对应用进程用户可删除；路径从 Web 根目录出发用 `../` 能到达（Linux/Windows 均可）。
- 原文未给出具体受影响版本号，仅在测试环境复现；CVE 编号原文只称“提了 cve”，未写出编号，故本卡不写 CVE。

## 利用步骤

1. 登录后台，获取有效 `JSESSIONID`。
2. 确认删除接口：抓取数据库备份管理页的删除请求，或用 `POST /admin/database/delete` 直接构造。
3. 用 `../` 从备份目录逐级上跳，构造目标文件相对 Web 根目录的路径；先用已知存在的文件（如 `flag.txt`、`config.properties`）验证。
4. 发送请求，观察响应是否为 `{"type":"success",...}`；到文件系统/目录列表确认文件已消失。
5. 若目标文件不存在或路径不对，接口静默返回成功但不会删除；需结合目录遍历/其它读接口确认路径。

## PoC

```http
POST /admin/database/delete HTTP/1.1
Host: 127.0.0.1:8888
Cookie: JSESSIONID=6DD997E088E0DCBF8F72AF2897F1B845
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

name=../../../../../../../../flag.txt
```

响应：

```json
{"type":"success","data":{},"msg":null}
```

原文截图中删除后目录里的 `flag.txt` 消失；`name` 的 `../` 数量按 Web 根目录与目标文件的相对深度调整。

## 变体与关联

- **编码/双写绕过**：若后续版本加了简单 `../` 黑名单，可尝试 `%2e%2e%2f`、`..%5c`（Windows）、`....//`、双写等；本卡版本没有过滤，直接原始 `../` 即可。
- **Windows 路径**：用 `..\\..\\` 或正反斜杠混用；`File` 在 Windows 上同时接受 `/` 和 `\`。
- **删除目标选择**：安装锁、`config.properties`、数据库备份、日志、模板文件；删除模板可造成页面不可用，删除锁文件可尝试触发重装。
- **同产品其它文件操作**：[[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]] 是 JFinalCMS FileManager 的任意读/写/下载；本卡是后台备份删除接口，端点与参数不同。
- **同类删除卡**：[[web-generic-file-inclusion-goldlib-file-controller-delete-traversal]]、[[web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete]]，均为“参数拼根路径后直接 delete”的模式。
- **边界**：需要后台权限；删除是不可逆操作，测试时用可恢复的测试文件；原文环境为 Spring Boot/JFinalCMS 测试实例，版本与部署方式未给出。

## 检测与防御

- **路径规范化 + 根目录约束**：删除前 `getCanonicalFile()`，并校验 `canonicalPath.startsWith(backupDir.getCanonicalPath() + File.separator)`；拒绝包含 `..`、绝对路径、分隔符的 `name`。
- **白名单**：只允许删除备份目录下符合命名规则（如 UUID/时间戳 + 固定后缀）的文件；用文件 ID 映射到服务端路径，不把路径交给客户端。
- **权限与审计**：删除接口要求管理员二次确认；记录操作者、目标路径、时间；备份文件放在 Web 根目录之外，且应用进程只对备份目录有写/删权限。
- **检测**：监控 `/admin/database/delete` 中出现 `../`、`%2e`、绝对路径的请求；对后台删除操作做告警与审计。
- **合规**：仅在授权环境测试；不要删除生产文件。
