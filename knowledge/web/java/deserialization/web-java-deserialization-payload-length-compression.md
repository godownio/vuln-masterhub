---
id: web-java-deserialization-payload-length-compression
title: Java 反序列化 payload 长度压缩：Unsafe 空字段、去调试信息与 Deflate 短链
type: scenario
domain: web
path: web/java/deserialization
technique: java-deser-payload-size-reduction
aliases:
- 反序列化 payload 缩短
- payload 长度限制绕过
- Deflate 压缩 payload
- Unsafe.allocateInstance 缩减
- 删除调试信息缩小字节码
- InflaterInputStream 反序列化
tags:
- java
- deserialization
- payload
- compression
- deflate
- unsafe
- javassist
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:41:26+08:00'
  notes: 已对照原文与图06-14核对：入口限制 Base64 长度1282并用 InflaterInputStream；Unsafe.allocateInstance 置空字段（_transletIndex 由 -1 变 0）、删除 SourceFile/LineNumberTable/LocalVariableTable+compact、三种 Deflate strategy 取最短 Base64、短链 SignedObject 直接返回 TemplatesImpl，最终1272并通过/flag取flag。原文未给受影响版本，未设置 affected_versions。未复现PoC。
---

## 一句话结论

当反序列化入口限制 Base64 长度并在 `readObject` 前套 `InflaterInputStream` 时，可通过“更短的 gadget 链 + `Unsafe.allocateInstance` 置空无用字段 + 删除类调试信息 + Deflate 压缩”把 Java 原生反序列化 payload 压到限制以内（文章从超限压到 1272，限制 1282）。

## 原理

- 长度检查通常针对 Base64 字符串（`payload.length() > 1282`），而 Base64 会把原始字节放大约 4/3，因此要同时优化序列化字节与编码后的长度。
- `Unsafe.allocateInstance(clazz)` 不调用构造器，对象字段保持 null/0：未使用字段以 `TC_NULL` 编码，比携带完整对象图短得多；同时避免构造器写入默认值（如 `TemplatesImpl._transletIndex` 默认 -1，Unsafe 下为 0），有时反而更利于利用。
- Javassist 生成的类默认带 `SourceFile`、`LineNumberTable`、`LocalVariableTable` 等调试属性；删除后 `ClassFile.compact()` 可进一步减少 `_bytecodes` 字节数。
- 选择最短的 gadget 链：例如让 `SignedObject.getObject` 直接返回 `TemplatesImpl`，由 Jackson 调 `getOutputProperties`，而不是在 `SignedObject` 内再套一层 `EventListenerList → POJONode`。
- 入口若用 `new InflaterInputStream(bytes)` 包住输入，则应对序列化字节做 raw Deflate 压缩；`Deflater.BEST_COMPRESSION` 下依次尝试 `DEFAULT_STRATEGY`、`FILTERED`、`HUFFMAN_ONLY`，取 Base64 最短者。
- 若入口不解压，压缩只会让 payload 无法反序列化；需先确认入口的流包装方式。

## 触发条件

- 反序列化入口有明确长度上限（常针对 Base64 字符串）。
- 入口在 `ObjectInputStream` 前使用 `InflaterInputStream`/`GZIPInputStream` 等解压流，或允许其他压缩封装。
- 攻击者可自定义 payload 生成器（Javassist/Unsafe/序列化代码）。
- 目标 JDK 允许使用 `Unsafe` 与动态类定义。

## 利用步骤

1. 先构造可用但较长的 gadget，确认能在目标上触发（如命令执行/文件删除）。
2. 按影响面选择最短链：优先让 getter 直接返回危险对象，减少一层嵌套。
3. 用 `Unsafe.allocateInstance` 创建字段多、构造器会填充大量默认值的对象；只反射设置链必需的字段。
4. 对 Javassist 生成类删除 `SourceFile`、`LineNumberTable`、`LocalVariableTable`，调用 `ClassFile.compact()`。
5. 若入口解压：序列化后做 Deflate，遍历三种 strategy，选 Base64 最短结果；再检查长度是否低于限制。
6. 发送并验证利用结果；若仍超限，继续削减对象图或换更短的 sink。

## PoC

删除调试信息并压缩类字节码：

```java
ClassFile cf = clazz.getClassFile();
cf.removeAttribute("SourceFile");
cf.removeAttribute("LineNumberTable");
cf.removeAttribute("LocalVariableTable");
cf.compact();
byte[] minimized = clazz.toBytecode();
```

无构造器实例化，减少序列化字段：

```java
Field f = Unsafe.class.getDeclaredField("theUnsafe");
f.setAccessible(true);
Unsafe unsafe = (Unsafe) f.get(null);
TemplatesImpl templates = (TemplatesImpl) unsafe.allocateInstance(TemplatesImpl.class);
setValue(templates, "_bytecodes", new byte[][]{minimized});
setValue(templates, "_name", "a");
```

针对 Deflate 入口选择最短 Base64：

```java
int[] strategies = {
    Deflater.DEFAULT_STRATEGY, Deflater.FILTERED, Deflater.HUFFMAN_ONLY
};
String best = null;
for (int s : strategies) {
    Deflater def = new Deflater(Deflater.BEST_COMPRESSION);
    def.setStrategy(s);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, def)) {
        dos.write(serializedBytes);
    }
    String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
    if (best == null || b64.length() < best.length()) best = b64;
}
```

文章最终 payload 的 Base64 长度为 1272，低于入口的 1282 限制；入口代码为 `new MyObjectInputStream(new InflaterInputStream(new ByteArrayInputStream(Base64.decode(payload))))`。

## 变体与关联

- 变体：入口用 gzip/zlib 时改用对应压缩流；Base64 URL-safe 编码；把序列化字节先压缩再编码，避免对 Base64 文本压缩。
- 变体：用更短的 sink（如 `TemplatesImpl` 短链）替代完整 CC 链；用 `SignedObject` 内层直接返回危险对象。
- 变体：通过反射/Unsafe 移除不参与链的集合、日志、缓存字段；用 `writeReplace`/`readResolve` 控制序列化形态。
- 关联：[[web-java-deserialization-jackson-signedobject-getobject-short-chain]]（文章使用的短链）、[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]。
- 边界：若入口不提供解压流，Deflate 步骤不适用；若目标禁用 `Unsafe` 或模块封装阻止动态类定义，需换构造方式。

## 检测与防御

- 长度上限不是安全边界：攻击者可用压缩与短链绕过；应使用类允许列表与 JEP 290/415 过滤器，而不是只限长度。
- 若必须接受压缩输入，应在解压后、反序列化前执行过滤；限制解压后大小以防 zip bomb。
- 检测 Deflate/gzip 魔数包裹的序列化流、短小的 `AC ED 00 05` 流、`SignedObject` 嵌套流与动态类定义。
- 记录并告警异常短的 gadget 组合（如 `POJONode` + `SignedObject` + `TemplatesImpl`）。
- 根本措施：避免对不可信数据使用 Java 原生反序列化，改用 JSON/Protobuf 等数据格式。
