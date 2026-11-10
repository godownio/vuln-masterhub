---
id: web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell
title: Fastjson 1.2.47 缓存绕过 + C3P0 HexAsciiSerializedMap 投递 TemplatesImpl 字节码内存马
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1247-c3p0-hex-templatesimpl-memshell
tags:
- java
- fastjson
- c3p0
- templatesimpl
- memshell
- deserialization
- unicode
- waf-bypass
- class-cache
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: fastjson 1.2.47
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:07:22+08:00'
  notes: 已对照原文核对；原文 payload 的 Unicode 转义 @type/userOverridesAsString、C3P0 HexAsciiSerializedMap 内含 TemplatesImpl 与 IceShell 类均一致；密码 goautomne 与原文一致；affected_versions fastjson 1.2.47 原文明确
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell/
draft: false
kb_aliases:
- fastjson 1.2.47 内存马
- C3P0 HexAsciiSerializedMap 内存马
- TemplatesImpl 字节码投递
- IceShell 内存马
- '@type 绕过'
---

## 一句话结论

在 fastjson 1.2.47 的解析入口，先把 `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` 通过 `{"@type":"java.lang.Class","val":...}` 写入类缓存，再用第二个对象设置其 `userOverridesAsString` 为 `HexAsciiSerializedMap:<hex>`；C3P0 会把十六进制还原成原生序列化流并 `readObject`，其中 `TemplatesImpl` 的 `_bytecodes` 携带继承 `AbstractTranslet` 的 IceShell 类，从而在目标 JVM 定义并注册内存马（随后可用哥斯拉连接执行命令）。属性名写成 `\u0075\u0073\u0065\u0072...` 形式的 Unicode 转义可让按字面匹配 `@type`/`userOverridesAsString` 的 WAF 失效。

## 原理

- **1.2.47 类缓存绕过**：`java.lang.Class` 的 `val` 经 `MiscCodec` 调 `TypeUtils.loadClass`，默认 `cache=true` 把类写进全局 `mappings`；`checkAutoType` 先查缓存再走黑白名单，所以同一 JSON 内第二次引用该危险类时 AutoType 关闭也能实例化。
- **C3P0 的 setter 反序列化**：`WrapperConnectionPoolDataSource#setUserOverridesAsString` → `C3P0ImplUtils.parseUserOverridesAsString` 去掉 `HexAsciiSerializedMap:` 前缀后 `ByteUtils.fromHexAscii` 转字节 → `SerializableUtils.fromByteArray` → `ObjectInputStream.readObject`。因此该属性等价于一个可控字节数组的原生反序列化入口。
- **TemplatesImpl 为什么能执行字节码**：原生 gadget 里把恶意类字节放进 `TemplatesImpl._bytecodes`，通过 `BadAttributeValueExpException`/`HashMap` 等触发 `TemplatesImpl.toString()` → `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()`，最终 `ClassLoader.defineClass` 加载恶意 translet；translet 类实现 `AbstractTranslet`，其静态块/构造器里完成内存马注册。
- **内存马形态**：示例 hex 流内含名为 `IceShell` 的 translet 类（哥斯拉系 Filter 内存马），加载后注册自身；随后用内置密码 goautomne 通过哥斯拉连接执行命令。整个过程没有 JSP/class 文件落地，传统文件查杀失效，但随 JVM 重启消失。
- **Unicode 转义绕过**：JSON 解析器会把 `\u0040\u0074\u0079\u0070\u0065` 还原为 `@type`，把 `\u0075\u0073\u0065\u0072\u004f\u0076\u0065\u0072\u0072\u0069\u0064\u0065\u0073\u0041\u0073\u0053\u0074\u0072\u0069\u006e\u0067` 还原为 `userOverridesAsString`；WAF 若只按字面匹配关键字就会漏检。该转义是 JSON 规范行为，不是解析器差异漏洞，但足以绕过多数字符串规则。

## 触发条件

- 目标使用 fastjson 1.2.47，且存在解析不可信 JSON 的入口；AutoType 是否开启不影响该缓存绕过。
- classpath 含 c3p0（`WrapperConnectionPoolDataSource` 可用）。
- 目标 JDK 允许 `TemplatesImpl` 定义 translet（JDK 8 常见；高版本受模块封装/`_bytecodes` 访问限制影响）。
- 攻击者能生成原生序列化 gadget（TemplatesImpl + 触发 toString 的包装类）并转为十六进制。
- WAF/网关未对 Unicode 转义做与 JSON 解析器等价的还原，或未按行为检测。

## 利用步骤

1. 生成恶意 translet 类（实现 `AbstractTranslet`，在静态块/构造器里注册内存马或执行命令），编译并取字节。
2. 用序列化构造器生成 `TemplatesImpl`（设置 `_bytecodes`、`_name`、`_tfactory` 等）并套上触发 `toString()` 的 gadget，序列化成字节数组。
3. 转十六进制并加前缀：`HexAsciiSerializedMap:<hex>`。
4. 构造两个对象的 fastjson JSON：`a` 用 `java.lang.Class` 缓存 c3p0 类，`b` 引用 c3p0 并设置 `userOverridesAsString`；关键字可用 `\uXXXX` 转义。
5. 发送到 JSON 解析入口；c3p0 setter 触发 `readObject`，TemplatesImpl 定义并执行 translet，内存马注册。
6. 用哥斯拉按注册路径与密码连接验证命令执行。

## PoC

```json
{
  "a": {
    "@type": "java.lang.Class",
    "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"
  },
  "b": {
    "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "userOverridesAsString": "HexAsciiSerializedMap:<TemplatesImpl gadget 序列化字节的十六进制>"
  }
}
```

## 变体与关联

- 变体：c3p0 hex 内换成 CommonsCollections gadget 直接命令执行（不落地内存马）。
- 变体：`userOverridesAsString` 改用其他能触发 `readObject` 的 setter；或利用 `JdbcRowSetImpl`/BCEL/H2 等其他二次入口。
- 关联：[[web-java-deser-fastjson-1247-class-cache-bypass]]（1.2.47 缓存绕过原理与 JdbcRowSetImpl/BCEL/C3P0 变体）。
- 关联：[[web-java-deser-fastjson-c3p0-hex-useroverrides]]（C3P0 HexAsciiSerializedMap 基础反序列化入口）。
- 关联：[[web-java-deser-fastjson-templatesimpl-batchupdate-rce]]（AutoType 开启时直接以 `@type` 使用 TemplatesImpl 的版本）。
- 关联：[[web-java-deser-fastjson-waf-ghostbits-escape]]（`\u`/`\x` 转义与关键字拆分的 WAF 绕过家族）。

## 检测与防御

- 检测：请求体含 `HexAsciiSerializedMap`、`WrapperConnectionPoolDataSource`、`TemplatesImpl`、超长十六进制串；含 `\u0040`/`\u0074` 等 Unicode 转义；JSON 中同时出现 `java.lang.Class` 与危险类名。
- 检测：JVM 内出现运行期 defineClass 的匿名 translet、非预期 ClassLoader；内存马注册后的新路由/Filter。
- 防御：升级 fastjson 至 1.2.48+ 或开启 SafeMode；移除/升级 c3p0；WAF 先做 Unicode 还原再匹配并按行为检测；JVM 配置 `ObjectInputFilter` 限制反序列化类；应用重启后复查内存马是否复活。
