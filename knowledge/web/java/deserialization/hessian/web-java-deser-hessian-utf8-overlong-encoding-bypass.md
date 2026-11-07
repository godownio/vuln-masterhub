---
id: web-java-deser-hessian-utf8-overlong-encoding-bypass
title: Hessian 反序列化黑名单绕过：UTF-8 Overlong Encoding 隐藏类名
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-utf8-overlong-bypass
aliases:
- Hessian UTF8 Overlong 绕过
- UTF-8 超长编码绕过
- Overlong Encoding 反序列化
- Hessian 黑名单绕过
- 类名字符串匹配绕过
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- deserialization
- bypass
- utf8
- overlong-encoding
- blacklist
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:55+08:00'
  notes: 已对照原文与图（类名消失对比、java-chains Utf8OverlongEncoding 选项）核对 2/3 字节超长编码原理与适用边界：仅绕过解码前字节匹配，不能绕过解码后 getDeserializer(type) 黑名单；PoC 未在本机执行。
---

## 一句话结论

把 Hessian 序列化流中类名的 ASCII 字节用 UTF-8 超长编码（overlong，如 2 字节补零形式）重新编码，Java 的 UTF-8 解码器会把它还原成原类名，但基于原始字节做字符串匹配的黑名单/流量检测看不到 `TemplatesImpl`、`JdbcRowSetImpl` 等明文，从而放行恶意 gadget。

## 原理

- UTF-8 允许用 1–4 字节表示 Unicode 字符；标准要求最短编码，但很多解码器（包括 Java 的 `DataInputStream.readUTF`/`String` 构造）接受“超长编码”——把本可用 1 字节表示的 ASCII 字符用 2 或 3 字节编码，高位补零。
- 例如字符 `a`（0x61）的标准编码是 `0x61`；2 字节超长编码为 `0xC0 | (0x61 >> 6) = 0xC1`、`0x80 | (0x61 & 0x3F) = 0xA1`，即 `C1 A1`；3 字节形式为 `E0 81 A1`。Java 解码后仍得到 `a`。
- Hessian 的类名以长度前缀 + UTF-8 字符串写入流。把类名的每个 ASCII 字节替换为超长编码后：
  - 解码后的 `type` 字符串仍是原类名，`SerializerFactory`/`Class.forName` 正常加载；
  - 原始字节中不再出现连续可读的类名，绕过对序列化字节做子串匹配的 WAF、IDS、黑名单过滤器。
- **适用边界**：该绕过针对“在解码前检查原始字节/字符串”的过滤。若服务端在 `SerializerFactory.getDeserializer(String type)` 中对**已解码**的 `type` 做黑名单/允许列表，超长编码不会改变 `type` 的值，因此不能绕过——这是最常见的误判点。
- 3 字节超长形式与 2 字节混用可进一步规避只识别某一种编码模式的特征规则。

## 触发条件

1. Hessian 反序列化入口可控。
2. 防护/黑名单基于原始序列化字节或传输层字符串匹配，而不是在类解码后做允许列表。
3. 恶意 gadget 类在目标 classpath 上（与普通 Hessian 链相同）。
4. 用于编码类名的自定义输出流/生成器可用（如重写 `writeUTF`/字符串写入逻辑）。

## 利用步骤

1. 先用普通 Hessian payload 确认目标的反序列化行为与黑名单命中情况。
2. 实现自定义 `OutputStream`（或修改 payload 生成器），对所有写入的类名/字符串做 UTF-8 超长编码。
3. 选择 2 字节、3 字节或混合模式，重新生成 payload。
4. 发送 payload；Java 解码后得到原类名并正常实例化 gadget。
5. 结合 JDK-only/Spring/Rome/Groovy 等链完成 RCE。

## PoC

2 字节超长编码函数：

```java
static byte[] overlong2(String s) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    for (char c : s.toCharArray()) {
        out.write(0xC0 | (c >> 6));
        out.write(0x80 | (c & 0x3F));
    }
    return out.toByteArray();
}
```

3 字节形式：

```java
out.write(0xE0 | (c >> 12));
out.write(0x80 | ((c >> 6) & 0x3F));
out.write(0x80 | (c & 0x3F));
```

在 Hessian 输出流中替换类名写入逻辑（或使用现成的 `CustomObjectOutputStream` 实现），把 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 等类名逐字节超长编码后再写入；Java 侧解码结果不变，原始字节中不再出现明文类名。

原文通过对比图展示：编码后可读类名从字节流中消失；java-chains 也提供 `Utf8OverlongEncoding` 选项（0 关闭、1 随机混合 2/3 字节、2 纯 2 字节、3 纯 3 字节）。

## 变体与关联

- 2 字节与 3 字节混用、随机化每个字符的编码长度，规避基于固定模式的特征。
- 同类思路可用于其他基于字符串匹配的反序列化过滤器（Java 原生序列化、JSON 类名过滤等），本质是“检查的表示”与“实际解析的表示”不一致。
- 与 Hessian 黑名单临时修复卡互补：黑名单越依赖字节匹配，越容易被该手法绕过；允许列表在解码后校验才可靠。
- 若目标在网关/WAF 层做字节匹配，该手法有效；若在应用内 `getDeserializer` 做解码后校验，则无效。

## 检测与防御

- 在**解码后**做允许列表校验（`getDeserializer(String type)` 中对 `type` 精确匹配业务类），不要依赖原始字节匹配。
- 检测序列化流中的非法/超长 UTF-8 序列（2 字节 `C0/C1` 开头、3 字节 `E0 80/81` 开头表示超长编码），对 Hessian 入口做协议规范化校验。
- WAF/IDS 增加 UTF-8 超长编码规则，或在解码后检查类名，而不是只匹配明文。
- 升级 Hessian、限制 gadget 类加载，配合 JVM 层反序列化过滤器（JEP 290）作为纵深防御。
- 监控异常类加载与反序列化异常；对 Hessian 入口做来源限制与鉴权。
