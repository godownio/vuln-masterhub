---
id: web-java-deser-fastjson-c3p0-hex-useroverrides
title: Fastjson 触发 C3P0 userOverridesAsString 十六进制原生反序列化
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-c3p0-hex-useroverrides-deserialization
aliases:
- C3P0 HexAsciiSerializedMap
- userOverridesAsString 反序列化
- C3P0 不出网反序列化
- WrapperConnectionPoolDataSource 利用
- 十六进制序列化 payload
tags:
- java
- fastjson
- c3p0
- deserialization
- commons-collections
- hex
- no-egress
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: c3p0 0.9.5.2；fastjson 1.2.24；commons-collections 3.2.1
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:32:05+08:00'
  notes: 已对照原文核对 setUserOverridesAsString→parseUserOverridesAsString→ByteUtils.fromHexAscii→SerializableUtils.fromByteArray→readObject 链；已修正关联卡 wikilink id；未验证点：原文超长 CC5 十六进制 payload 未复制，仅结构化占位
---

## 一句话结论

Fastjson 将 `@type` 设为 `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` 并给 `userOverridesAsString` 传入 `HexAsciiSerializedMap:<hex>` 时，C3P0 会把十六进制还原成字节并直接交给 `ObjectInputStream.readObject()`，从而在目标侧触发原生反序列化；配合 CommonsCollections 等 gadget 可在不出网条件下 RCE。

## 原理

- `WrapperConnectionPoolDataSource` 的 `setUserOverridesAsString(String)` 会调用 `C3P0ImplUtils.parseUserOverridesAsString()`。
- 该方法检查字符串非空后，用 `substring(HASM_HEADER.length() + 1)` 去掉前缀 `HexAsciiSerializedMap` 和冒号，得到十六进制串；`ByteUtils.fromHexAscii()` 转成字节数组。
- 随后 `SerializableUtils.fromByteArray(bytes)` 调用 `deserializeFromByteArray()`，内部执行 `new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject()`，即完整的原生 Java 反序列化。
- 因此 `userOverridesAsString` 等价于一个“可控字节数组 → 原生反序列化”的入口。攻击者把任意原生序列化 gadget（如 CommonsCollections5）编码成十六进制放入即可。
- 该路径不需要目标出网加载远程类，适合内网/无外联环境；但要求目标 classpath 上存在可用的反序列化 gadget 库（原文为 commons-collections 3.2.1），或至少存在可被 `readObject` 触发的危险类。
- Fastjson 只是触发器：`@type` 实例化 `WrapperConnectionPoolDataSource` 并调用 setter。SnakeYAML 等能设置该属性的组件同样可触发。

## 触发条件

- 目标使用 Fastjson（原文 1.2.24，AutoType 可用）或 SnakeYAML 等可设置任意属性的反序列化组件。
- classpath 含 c3p0（原文 0.9.5.2）。
- classpath 含可用的原生反序列化 gadget（如 commons-collections 3.2.1），或存在其他可被 `readObject` 利用的类。
- 目标未启用严格的 `ObjectInputFilter`/序列化白名单阻断 gadget 类。

## 利用步骤

1. 确认 Fastjson 版本/AutoType 状态、c3p0 与 gadget 库依赖。
2. 用 ysoserial 或手写代码生成目标 gadget 的原生序列化字节（如 CommonsCollections5 执行命令）。
3. 将字节数组转为十六进制，拼接前缀：`HexAsciiSerializedMap:<hex>`。
4. 构造 Fastjson JSON，`@type` 为 `WrapperConnectionPoolDataSource`，`userOverridesAsString` 填入上述字符串。
5. 发送到解析入口；目标在 `parseUserOverridesAsString` 中还原并 `readObject`，触发 gadget。
6. 观察命令执行结果；不出网环境也可用写文件/反弹到内网等方式验证。

## PoC

```json
{
  "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
  "userOverridesAsString": "HexAsciiSerializedMap:ACED0005...<原生序列化 gadget 的十六进制>..."
}
```

```java
// 生成 payload 的结构示意
byte[] ser = /* ysoserial CommonsCollections5 等 gadget 的序列化字节 */;
StringBuilder hex = new StringBuilder("HexAsciiSerializedMap:");
for (byte b : ser) hex.append(String.format("%02X", b));

String json = "{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\","
            + "\"userOverridesAsString\":\"" + hex + "\"}";
// 交给 Fastjson 解析即可触发
```

```text
# 解析链路：
# WrapperConnectionPoolDataSource.setUserOverridesAsString
# -> C3P0ImplUtils.parseUserOverridesAsString
# -> ByteUtils.fromHexAscii
# -> SerializableUtils.fromByteArray
# -> deserializeFromByteArray
# -> ObjectInputStream.readObject
```

## 变体与关联

- 变体：使用 CommonsBeanutils、CommonsCollections、JDK 原生等不同 gadget；只要目标 classpath 可达即可。
- 变体：SnakeYAML 等组件设置 `userOverridesAsString` 同样可触发；原文指出与 SnakeYAML 反序列化章节是同一机制。
- 变体：十六进制字符串很长时注意请求体大小/WAF 限制，可分段/压缩或换用其他触发方式。
- 关联：[[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]（C3P0 的 URLClassLoader 链）；[[web-java-deser-fastjson-c3p0-jndiref-jndi]]（C3P0 的 JNDI 链）；[[web-java-deser-c3p0-beanfactory-el-no-egress]]（另一条不出网链）。
- 边界：目标无可用 gadget、启用了严格序列化过滤、或 Fastjson 关闭 AutoType 且无绕过时，链不成立。Hex 本身只是编码，不构成利用；必须有可执行的 `readObject` gadget。

## 检测与防御

- 检测：监控请求/日志中出现 `HexAsciiSerializedMap`、`WrapperConnectionPoolDataSource`、`userOverridesAsString`；对包含超长十六进制字符串的 JSON 告警；监控 `ObjectInputStream.readObject` 加载异常 gadget 类。
- 修复：升级 Fastjson 并开启 safeMode/关闭 AutoType；移除或升级 c3p0；对反序列化入口设置 `ObjectInputFilter` 白名单。
- 加固：移除不必要的 commons-collections 等 gadget 库；使用 JDK 序列化过滤（`jdk.serialFilter`）；RASP 监控危险 `readObject` 调用链。
