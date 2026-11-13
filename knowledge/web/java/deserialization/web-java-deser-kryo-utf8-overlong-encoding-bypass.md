---
id: web-java-deser-kryo-utf8-overlong-encoding-bypass
title: Kryo 反序列化 UTF-8 Overlong Encoding 混淆：类名/字段/数组/Map 超长编码绕过字节黑名单与 WAF
type: scenario
domain: web
path: web/java/deserialization
technique: kryo-utf8-overlong-encoding-obfuscation
aliases:
- Kryo UTF-8 Overlong Encoding
- Kryo 反序列化混淆
- Kryo 黑名单绕过
- Kryo WAF 绕过
- readClassAndObject 类名混淆
- Kryo Input.readString Overlong
- Kryo writeString_slow 超长编码
- Kryo 数据流 ASCII 转 UTF-8
tags:
- java
- kryo
- deserialization
- overlong-encoding
- utf8
- waf-bypass
- blacklist-bypass
- obfuscation
- serialization
- traffic-evasion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:33:48+08:00'
  notes: 已对照原文全文与18/18图核对：writeString ASCII/UTF-8双模式、writeUtf8Length(charCount+1)、writeString_slow 1/2/3字节分支、readString首字节(0x80)判定、readUtf8_slow按b>>4分派不校验最短编码、C1 AF overlong实例、StringSerializer/ClassSerializer/String[]/Map混淆面、ASCII<->UTF-8流转换(buffer[end-1]&=0x7F)均与图一致；与Hessian/JDK ObjectInputStream/javaagent三张overlong卡为不同协议不同流结构，非重复；卡内无sources/文章ID/URL/长段摘录，路径web/java/deserialization合法；原文无Kryo版本标注，versions保持为空；PoC为示意代码未执行
---

## 一句话结论

Kryo 的 `readClassAndObject` 从输入流读取类名时会走 `Input.readString`，其 UTF-8 解码函数 `readUtf8_slow` 只按首字节高位分支做 2/3 字节组合、**不校验最短编码**，因此接受 `C1 AF` 这类 2 字节超长形式（overlong）并还原成 `o`。把序列化端 `Output.writeString` 改成强制 UTF-8 模式、只输出 2 字节超长序列（或对已有 ASCII 流做流转换），就能让类名、String/Class 字段、数组元素和 Map 键值在原始字节中不再出现明文，而 Kryo 仍能正常反序列化，从而绕过按原始字节匹配类名/关键字的 WAF 与黑名单。

## 原理

- **Kryo 字符串有两种写入模式**：纯 ASCII 且长度在 1–63 之间的字符串走 ASCII 模式——不写长度前缀，直接把字符写入缓冲区，然后把**最后一个字节**置高位（`buffer[position - 1] |= 0x80`）作为结束标记。非 ASCII（或超长）字符串则走 UTF-8 模式——先 `writeUtf8Length(charCount + 1)` 写一个带高位标记的长度（例如 16 个字符写 `0x91`，低 7 位为 17），再逐字符写入：`c <= 0x7F` 写 1 字节、`c > 0x7FF` 写 3 字节（`0xE0 | c>>12`、`0x80 | c>>6 & 0x3F`、`0x80 | c & 0x3F`）、其余写 2 字节（`0xC0 | c>>6 & 0x1F`、`0x80 | c & 0x3F`）。
- **读取端如何判定模式**：`Input.readString` 先读一字节 `b`；`(b & 0x80) == 0` 时走 `readAscii`（没有长度前缀，读到高位字节为止），否则把低 7 位当作“字符数+1”的长度，调用 `readUtf8`。`readUtf8` 先快速读 7bit 字符，一旦遇到高位为 1 的字节就回退指针并转入 `readUtf8_slow`；`readUtf8_slow` 按 `b >> 4` 分派：0–7 单字节、12/13 两字节（`(b & 0x1F) << 6 | next & 0x3F`）、14 三字节（`(b & 0x0F) << 12 | …`），**没有验证编码是否为最短形式**。
- **为什么 overlong 能生效**：Unicode 只要求字符与码点对应，不要求编码器使用最短字节序列；`o`（0x6F）的标准 UTF-8 是 `6F`，但 2 字节超长形式 `C1 AF` 在 `readUtf8_slow` 的 case 12/13 分支中同样被组合回 0x6F，3 字节形式 `E0 81 A1` 也同理。于是原始字节里不再有 `org.example.Test` 这样的明文类名，但反序列化后 `DefaultClassResolver.readName` 拿到的仍是原类名，`Class.forName` 正常加载。
- **为什么不能直接改字节**：ASCII 模式与 UTF-8 模式的流结构不同——ASCII 模式没有长度前缀、用末字节高位做结束标记；UTF-8 模式有长度前缀、字符按 1/2/3 字节编码。把一段 ASCII 流直接替换成超长序列会被 `readString` 当成 ASCII 模式解析而错位。正确做法是重写 `Output`：让 `writeString` 强制走 UTF-8 分支，并把 `writeString_slow` 的 1 字节与 3 字节分支注释掉、只保留 2 字节超长编码；或者写一个流转换器，把已有 ASCII 流改成 UTF-8 形式。
- **可混淆的不止类名**：Kryo 的类名、字段名与对象属性中的字符串共用 `Output.writeString`/`Input.readString`。`DefaultSerializers$StringSerializer`（String 字段）、`DefaultSerializers$ClassSerializer`（Class 字段）、`StringBuffer`/`StringBuilder`/`Charset`/`URL` 等默认序列化器，以及 `DefaultArraySerializer`（如 `String[]`）和 `MapSerializer` 的 key/value，只要类型允许被该方式编码，都能做同样的混淆。对 `Kryo` 内嵌的 Java 原生序列化（`JavaSerializer` 包装 `ObjectOutputStream`），也可以在序列化端替换 `ObjectOutputStream` 的写入实现来达到同样效果，与 JDK 原生 overlong 卡同源。

## 触发条件

- 目标使用 Kryo 从不可信输入反序列化：典型如 `kryo.readClassAndObject(input)`，或 `readObject(input, clazz)` 中存在 String/Class/数组/Map 等可写字符串的属性。常见于 RPC、缓存、会话、消息队列等传输层。
- 目标 Kryo 未开启或可绕过 class registration/白名单（`setRegistrationRequired(true)` 时未注册类会被拒绝），或者白名单内已有可利用的类。
- 前置 WAF/黑名单/流量检测按**原始字节**做子串匹配（例如匹配 `TemplatesImpl`、`JdbcRowSetImpl`、`commons-collections` 等类名/关键字），且不在匹配前先做 UTF-8 解码与规范化。
- 攻击者需要能控制序列化端（修改 `Output` 源码、使用 agent 或后处理工具），且目标端 Kryo 版本的 `readUtf8_slow` 同样不校验最短编码。

## 利用步骤

1. 确认入口使用 Kryo 的 `readClassAndObject`/`readObject` 接收字节流，且能从流中解析出类名或可控字符串属性。
2. 在序列化端重写 `Output.writeString`，使类名与字符串强制走 UTF-8 模式；把 `writeString_slow` 的 1 字节和 3 字节分支注释掉，只保留 2 字节分支（全部字符变成 `C0/C1` 开头的超长序列），或只对敏感关键字做替换以缩小体积。
3. 生成混淆流：确认原始字节中不再出现明文类名/关键字；例如 `org.example.Test` 的首字符 `o` 变为 `C1 AF`，UTF-8 长度前缀为 `91`（`0x11 | 0x80`）。
4. 若手上已有普通 ASCII 模式流：对每个字符串清除末字节的 `0x80` 位，并在字符串前插入 UTF-8 长度前缀（字符数+1 且首字节带 `0x80` 标记）；逆向转换则去掉长度前缀并把末字符重新置高位。
5. 将混淆后的流发送到目标入口；Kryo 的 `readUtf8_slow` 会把超长序列还原为原字符，`readClassAndObject` 正常加载类并还原对象，WAF 因原始字节不含明文而放行。
6. 本地用相同 Kryo 版本对混淆流做反序列化对照，确认类名与字段值与原始流一致后再投放。

## PoC

无完整 PoC（文章以调试方式验证编码可被 `readUtf8_slow` 正确还原）。最小验证代码（示意，需与目标 Kryo 版本一致）：

```java
// 序列化端：强制 UTF-8 模式，并把每个字符写成 2 字节超长序列
int charCount = value.length();
output.writeUtf8Length(charCount + 1);       // 长度前缀：charCount+1，首字节带 0x80 标记
for (int i = 0; i < charCount; i++) {
    int c = value.charAt(i);
    output.writeByte(0xC0 | ((c >> 6) & 0x1F)); // 2 字节形式，如 'o'(0x6F) -> C1 AF
    output.writeByte(0x80 | (c & 0x3F));
}
```

字节对照（同一个字符串的两种模式）：

```text
ASCII 模式:  6F 72 67 2E 65 78 61 6D 70 6C 65 2E 54 65 73 F4   # 末字节高位为结束标记
UTF-8 模式:  91 6F 72 67 2E 65 78 61 6D 70 6C 65 2E 54 65 73 74  # 91 = 0x11|0x80 长度标记
超长混淆:    91 C1 AF 72 67 2E 65 78 61 6D 70 6C 65 2E 54 65 73 74  # 'o' -> C1 AF
```

## 变体与关联

- 同族绕过：[[web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass]]（JDK 原生 `ObjectInputStream` 字节黑名单）、[[web-java-deser-hessian-utf8-overlong-encoding-bypass]]（Hessian 类名）、[[web-java-deser-overlong-utf8-javaagent-writeutf]]（agent 在生成端改 `writeUTF`）。
- 变体：2 字节（`C0/C1` 开头）或 3 字节（`E0` 开头）超长形式可混用；既可全量混淆，也可只混淆类名/关键字以缩小流体积；混淆面可扩展到 Class 字段、String[]、Map key/value、`StringBuilder`/`Charset`/`URL`；也可通过流转换工具对已有 payload 做离线改写。
- 变体：Kryo 内嵌 Java 原生序列化时，可替换 `JavaSerializer` 中的 `ObjectOutputStream` 实现，把 JDK 原生 payload 同样做 overlong 处理。
- 边界：只绕过“解码前按原始字节匹配”的过滤；如果 WAF/黑名单先做 UTF-8 解码/规范化再匹配类名（如 `resolveClass` 拿到 `getName()` 后比对），或目标开启了严格的 Kryo 类注册/白名单，该混淆无效。Kryo 版本不同 `readString` 的分支细节可能变化，需以目标依赖版本为准。流若被压缩/加密/签名，需先同步对应处理。

## 检测与防御

- **检测**：在反序列化入口对字节流做 UTF-8 解码与规范化后再匹配类名/关键字；静态匹配 `C0/C1/E0` 开头的超长编码模式与不合理的 UTF-8 长度前缀；对 Kryo 流量做结构解析并记录 `readString` 解码后的类名；在 `Input.readString`/`readUtf8_slow` 处加 agent 埋点，比较“原始字节匹配结果”与“解码后类名”的差异。
- **防御**：Kryo 一律开启 `setRegistrationRequired(true)` 并只注册必需类；不要把 `readClassAndObject` 暴露给不可信输入，优先使用固定类型的 `readObject(input, clazz)`；对序列化流做签名/认证与长度限制；WAF 采用解码后匹配并拒绝无法规范化的超长编码；升级依赖并关注 Kryo 对 overlong 编码的处理变化。
