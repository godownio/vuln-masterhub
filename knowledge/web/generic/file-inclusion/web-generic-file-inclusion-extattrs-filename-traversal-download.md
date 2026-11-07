---
id: web-generic-file-inclusion-extattrs-filename-traversal-download
title: 可写 extAttrs.fileName 目录穿越：下载接口按资源记录路径读取任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: extattrs-filename-traversal-download
aliases:
- extAttrs fileName 穿越
- resourceUuid 任意文件下载
- ResourceOperation 下载
- 资源记录 fileName 注入
- Hibernate 资源表路径穿越
- 下载接口任意文件读取
tags:
- java
- hibernate
- file-download
- path-traversal
- arbitrary-file-read
- json
- extattrs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:25:14+08:00'
  notes: 已对照原文25张图核对：downloadAttachment(GET /download, resourceUuid) 调 downloadResourceOperation（图15）；后者按 resourceUuid 查 Hibernate 取首条、解析 extAttrs.fileName、destFile=tempFilePath+separator+fileName 并 copyFile 后返回（图16）；HBM 映射 aaa_resource_operation（图18）；addResourceOperation 原样写 extAttrs（图20）；AlarmPlanStep set 链路（图19/22/23）；POST /set 成功（图24）；GET /download 返回 server.xml 内容（图25）。未验证点：copyFile 是否覆盖/异常处理原文未展示，卡片已列为代码层风险；PoC 未本机复跑；原文未标注产品与版本，已清除 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

某管理系统下载接口只按 `resourceUuid` 查 `aaa_resource_operation` 记录，取 `extAttrs` JSON 中的 `fileName` 拼成临时目录下的文件路径并返回；而 `extAttrs` 可由同一系统的 `setAlarmPlanStep` 接口写入，攻击者把 `fileName` 设为 `../../../../Tomcat/conf/server.xml`，再调用下载接口即可读取任意文件。

## 原理

- **下载入口**：`GET /aaa/bbb/download?resourceUuid=...` 调 `ResourceOperationService.downloadResourceOperation(resourceUuid)`；后者用 Hibernate 按 `resourceUuid` 查 `aaa_resource_operation`，取第一条记录。
- **路径构造**：从 `op.getExtAttrs()` 取 JSON，反序列化后读取 `fileName`；`fileSuffix` 取 `fileName` 最后一个 `.` 之后的部分；`srcFile` 为 `uploadFilePath/resourceUuid.<suffix>`，`destFile` 为 `tempFilePath + File.separator + fileName`；随后 `FileUtils.copyFile(srcFile, destFile)` 并 `return destFile`。
- **穿越点**：`fileName` 由客户端写入，未做 `..`、绝对路径或规范化校验，直接拼到 `tempFilePath` 后。把 `fileName` 设为 `../../../../Tomcat/conf/server.xml`，`destFile` 就指到 Tomcat 配置目录；下载控制器随后读取并返回该文件。原文实测响应体为 `server.xml` 内容。
- **写入点**：`POST /aaa/bbb/set` 的 `AlarmPlanStepSetDto` 包含 `addList: List<ResourceOperation>`；`AlarmPlanStepService.addOrUpdateAlarmPlanStepForSet` 遍历 `addList` 调用 `addResourceOperation`，后者把客户端传入的 `resourceUuid`、`extAttrs`、`resourceType` 等原样保存。`extAttrs` 是字符串，内部 JSON 的 `fileName` 完全可控。
- **为什么能串起来**：下载接口信任数据库里的 `fileName` 作为路径，而写入该字段的接口没有做业务归属/路径校验；两个功能单独看都“正常”，组合后形成“先写路径、再按路径读文件”的任意文件读取链。
- **代码还显示 `copyFile(srcFile, destFile)`**：若实现会覆盖已存在文件，同一 sink 还可能把 `uploadFilePath/resourceUuid.suffix` 的内容写到穿越后的目标，构成任意文件写；原文只演示了读取，未验证写入影响。
- 该链需要有效会话（原文 PoC 带 `JSESSIONID`），属于认证后/低权限用户可利用的路径穿越，而非完全未授权。

## 触发条件

- 目标存在 `/aaa/bbb/download` 与 `/aaa/bbb/set` 一类资源操作接口，资源记录表含 `resourceUuid` 与 `extAttrs` 字段。
- `set` 接口允许当前用户写入 `extAttrs`（JSON 字符串），且未校验 `fileName` 路径。
- `download` 接口按 `resourceUuid` 取 `extAttrs.fileName` 并拼路径，未做规范化/白名单。
- 攻击者持有有效会话；进程对目标文件有读权限（读取）/写权限（写入变体）。

## 利用步骤

1. 登录系统，取得 `JSESSIONID`。
2. 向 `POST /aaa/bbb/set` 提交 `AlarmPlanStepSetDto`，在 `addList` 中放入一条 `ResourceOperation`，`resourceUuid` 设为任意值（如 `123456789`），`extAttrs` 设为包含 `fileName` 的 JSON 字符串。
3. `fileName` 填目标文件的相对穿越路径，如 `../../../../Tomcat/conf/server.xml`；`fileSize` 等字段可随意。
4. 记录响应成功后，调用 `GET /aaa/bbb/download?resourceUuid=123456789`。
5. 响应体返回目标文件内容；根据部署路径调整 `../` 层数与文件名（Linux 用 `/`，Windows 可用 `..\\..\\`）。
6. 若要读取其他文件，重复创建记录或更新 `extAttrs` 后再次下载。

## PoC

写入资源记录：

```http
POST /aaa/bbb/set HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid>
Content-Type: application/json

{"alarmPlanStep":{"name":"123","planUuid":"123"},"addList":[{"resourceUuid":"123456789","resourceType":123456789,"operationType":12,"extAttrs":"{\"fileName\":\"../../../../Tomcat/conf/server.xml\",\"fileSize\":\"1.50KB\"}","pUuid":"123","isOn":true}],"deleteList":[],"updateList":[]}
```

触发下载：

```http
GET /aaa/bbb/download?resourceUuid=123456789 HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid>
```

响应体为 `Tomcat/conf/server.xml` 内容（原文截图为 Apache License 与 `<Server port=... shutdown=...>`）。

## 变体与关联

- 变体：`fileName` 指向 `/etc/passwd`、应用配置文件、数据库凭据文件等；Windows 下用 `..\\..\\` 或绝对路径（取决于 `File` 对绝对路径的处理）。
- 变体：其他调用 `addResourceOperation`/`setExtAttrs` 的业务接口也可写入 `extAttrs`，不限于 `setAlarmPlanStep`。
- 变体：若 `copyFile` 覆盖目标文件，可进一步造成任意文件写（如覆盖 JSP、配置文件）；原文未验证，属代码层风险。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（同为 Java `new File` 拼接路径导致的任意文件读取）。
- 关联：[[web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read]]（同为接口参数直接控制文件路径）。
- 边界：若下载前对 `fileName` 做规范化并校验必须位于 `tempFilePath` 下，或 `extAttrs` 由服务端生成不可写，则该链不成立。

## 检测与防御

- **检测**：`extAttrs.fileName` 含 `../`、`..\\`、绝对路径、`/etc/`、`Tomcat/conf` 等；同一 `resourceUuid` 先调用 set/add 再调用 download；下载响应为配置文件/系统文件而非业务附件。
- **检测**：审计所有写入 `extAttrs` 的接口，检查 `fileName` 是否可由客户端控制；对比数据库中 `fileName` 与实际上传文件。
- **修复**：下载时不要用客户端可控的 `fileName` 拼路径；只允许按 `resourceUuid` 在服务端映射到固定的上传目录，使用 `Path.normalize()` 后校验 `startsWith(uploadRoot)`；`extAttrs` 中的 `fileName` 仅作展示，不参与路径计算。
- **加固**：`set` 接口校验资源归属与字段白名单；文件服务使用随机 ID 而非原始文件名；限制进程对配置目录的读权限；记录并告警路径穿越特征。
