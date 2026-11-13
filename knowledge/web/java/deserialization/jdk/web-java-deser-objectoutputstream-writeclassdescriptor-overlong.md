---
id: web-java-deser-objectoutputstream-writeclassdescriptor-overlong
title: 原生 Java 反序列化 Overlong Encoding 生成：自定义 ObjectOutputStream 重写 writeClassDescriptor，用 2/3 字节编码类名绕过 WAF
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: objectoutputstream-writeclassdescriptor-overlong-encoding
aliases:
- Overlong Encoding 生成
- writeClassDescriptor 重写
- ObjectStreamClass.writeNonProxy
- 2字节类名编码
- 3字节类名编码
- Java 序列化流类名超长编码
tags:
- java
- deserialization
- objectoutputstream
- overlong-encoding
- utf8
- waf-bypass
- blacklist-bypass
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:47:15+08:00'
  notes: 已对照原文全文与12张图核对：readNonProxy→readUTF(图01)、readUTFBody/readUTFSpan(图02)、switch(b1>>4)分支0-7字节/12-13两字节/14三字节/其余抛异常(图03/08)、b2&0xC0==0x80校验(图04)、2字节解码公式(图05)、int不截断(图06)、writeClassDescriptor→writeNonProxy(图09)、writeNonProxy内out.writeUTF(name)(图10)、三种写入方式switch(图11)、3字节E0 8x类名成功弹计算器(图12)均一致。2/3字节公式复算正确：a(0x61)→C1 A1、o(0x6F)→C1 AF、.(0x2E)→C0 AE、j(0x6A)→E0 81 AA；enc2=0xC0|(c>>6)、enc3=(0xE0,0x80|((c&0xC0)>>6),0x80|(c&0x3F))与原文表一致。修正三处精确性问题并同步staging：①readUTFSpan分支原文为0-7走1字节、12/13走2字节、14走3字节、8-11/15抛UTFDataFormatException（原写'其余走1字节'）；②2字节类名前缀应为C0/C1（点、分号、$等为C0），原写C1 xx；③检测特征同步改为C0/C1 8x-Bx。原文未给JDK受影响区间（截图仅显示测试环境jdk1.8.0_102），不设affected_versions正确。dedup：与web-java-deser-overlong-utf8-javaagent-writeutf(likely_duplicate,trigram0.27/simhash5)对比，该卡用-javaagent+Javassist改BlockDataOutputStream.writeUTF/writeUTFBody、类名/字段名/String全三字节编码；本卡纯Java子类化ObjectOutputStream重写writeClassDescriptor、仅改类名、含2字节变体，代码路径、依赖与产物不同，非同链，dedup_review理由成立；与objectinputstream-overlong-utf8-blacklist-bypass为检测/后处理侧卡，本卡为生成侧，互补；dup-scan未涉及本篇。
---

## 一句话结论

不必等序列化完成后再改字节，也不必挂 Java Agent：继承 `ObjectOutputStream` 并重写 `protected void writeClassDescriptor(ObjectStreamClass desc)`，照抄 `ObjectStreamClass.writeNonProxy` 的写流逻辑，只把类名改成 modified UTF-8 的 overlong 形式（每个 ASCII 字符写 2 或 3 字节）并同步长度前缀，`writeObject` 产出的原生序列化流中类名全部变成 `C0/C1 xx` 或 `E0 8x xx` 字节；目标端 `ObjectInputStream.readUTF/readUTFSpan` 不校验最短编码，解码后仍是原类名可正常反序列化，而按原始字节匹配类名的 WAF/黑名单全部失配。

## 原理

- **序列化端**：`ObjectOutputStream.writeClassDescriptor` 调用 `ObjectStreamClass.writeNonProxy(this)`，后者用 `writeUTF(name)` 写类名。`writeUTF` 先写 2 字节长度前缀，再按 modified UTF-8 每字符写 1/2/3 字节。重写 `writeClassDescriptor` 后，自己用 `writeShort(字节数)` + 自定义编码字节替代 `writeUTF(name)`，其余 `serialVersionUID`、flags、字段描述逻辑照抄原实现（私有字段/方法通过反射读取）。
- **反序列化端**：`ObjectInputStream.readNonProxy` 调 `readUTF`；`readUTFSpan` 取 `(buf[pos] & 0xFF) >> 4`：`0`–`7` 走 1 字节、`12`/`13` 走 2 字节、`14` 走 3 字节，其余（`8`–`11`、`15`）抛 `UTFDataFormatException`。2 字节解码 `(char)(((b1 & 0x1F) << 6) | ((b2 & 0x3F) << 0))`，3 字节解码 `(char)(((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | ((b3 & 0x3F) << 0))`；代码只校验后续字节前缀，不检查该码点是否本应使用更短编码，因此 overlong 形式被接受并还原成同一字符。
- **2 字节编码推导**（ASCII < 0x80）：b1 前缀 `110`、b2 前缀 `10`。由于 `b1 & 0x1F` 左移 6 位在 int 中不截断，要让 OR 结果最高位为 0（ASCII 范围），b1 参与运算的 5 位里只能低 2 位承载字符高位，中间 3 位必须为 0，所以 `b1 = 0xC0 | (c >> 6)`（ASCII 只可能是 0xC0 或 0xC1），`b2 = 0x80 | (c & 0x3F)`。例：`a`(0x61)→`C1 A1`，`o`(0x6F)→`C1 AF`，`.`(0x2E)→`C0 AE`。
- **3 字节编码推导**：b1 前缀 `1110`；同理为保证结果最高位为 0，b1 只能是 `0xE0`，字符高 2 位放进 b2、低 6 位放进 b3：`b2 = 0x80 | ((c & 0xC0) >> 6)`，`b3 = 0x80 | (c & 0x3F)`。例：`j`(0x6A)→`E0 81 AA`。
- **因此每个字符的编码是固定的**（不是随便填）：b1、b2（2 字节形式）或 b1、b2、b3（3 字节形式）只由字符值决定，可直接打表或按公式生成。
- **实现要点**：`writeClassDescriptor` 内需按原逻辑写 `desc.getSerialVersionUID()`、flags（externalizable/serializable/hasWriteObjectData/isEnum，含 protocol 判断）、字段数，以及每个字段的 typeCode、`writeUTF(f.getName())`、非基本类型的 `writeTypeString`。本方法只改了类名字符串；字段名与 String 值仍按普通 `writeUTF` 写出，WAF 仍可能匹配这些明文（若需整体隐藏，可叠加 agent 方案）。
- **边界**：文章给出的映射表只覆盖字母、`.`、`$`、`;`、`[`、`]` 等符号，数字等字符需按同一公式补充；要求类名全为 ASCII；`writeShort` 长度前缀必须等于实际写出的字节数（2 字节形式 `name.length()*2`，3 字节形式 `name.length()*3`），否则 `readUTF` 错位。

## 触发条件

- 目标存在 Java 原生反序列化入口，防护是按原始字节/明文字符串匹配类名的 WAF 或自定义黑名单（如 `checkData(byte[])`）。
- 目标 JDK 的 `readUTF` 接受 overlong 形式（OpenJDK 常见实现如此，不做最短编码校验）；若防护在 `resolveClass` 按解码后的 `desc.getName()` 判断或使用 JEP 290 `ObjectInputFilter`，本方法无效。
- 攻击者控制 payload 生成端，能用自定义 `ObjectOutputStream` 序列化 gadget 对象图。
- 目标 classpath 存在可用 gadget 链。

## 利用步骤

1. 先构造会触发原始字节黑名单的 gadget 对象图（如 CC、TemplatesImpl 等），确认目标拒绝原始 payload。
2. 编写 `CustomObjectOutputStream extends ObjectOutputStream`，重写 `writeClassDescriptor`：类名用 2 或 3 字节编码写出，其余逻辑复制 `ObjectStreamClass.writeNonProxy`。
3. 用该流 `writeObject(gadget)` 生成字节流；十六进制检查类名位置已无 ASCII 明文、长度前缀与字节数一致。
4. base64 后发送到目标反序列化入口，观察命令执行/回显；必要时切换 2/3 字节形式或仅编码部分字符。
5. 若被解码后类名黑名单或 JEP 290 拦截，说明防护位置不同，换其它绕过或 gadget。

## PoC

编码公式（Java）：

```java
static int[] enc2(char c) { return new int[]{0xC0 | (c >> 6), 0x80 | (c & 0x3F)}; }
static int[] enc3(char c) { return new int[]{0xE0, 0x80 | ((c & 0xC0) >> 6), 0x80 | (c & 0x3F)}; }
```

自定义流骨架：

```java
class CustomOOS extends ObjectOutputStream {
    CustomOOS(OutputStream out) throws IOException { super(out); }
    void writeName(String name, boolean three) throws IOException {
        int n = three ? 3 : 2;
        byte[] bytes = new byte[name.length() * n];
        int k = 0;
        for (char c : name.toCharArray()) {
            int[] b = three ? enc3(c) : enc2(c);
            for (int v : b) bytes[k++] = (byte) v;
        }
        writeShort(name.length() * n);
        write(bytes);
    }
    @Override protected void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
        writeName(desc.getName(), true);          // 关键改动：类名 3 字节 overlong
        writeLong(desc.getSerialVersionUID());
        byte flags = 0;
        // 按 ObjectStreamClass.writeNonProxy 原逻辑用反射读取
        // externalizable/serializable/hasWriteObjectData/isEnum，写 flags、字段数、字段描述
        // ...（其余照抄原实现）
    }
}
```

示例编码：

```text
'a' 0x61 -> C1 A1        'o' 0x6F -> C1 AF        '.' 0x2E -> C0 AE
'j' 0x6A -> E0 81 AA     'a'(3B) -> E0 81 A1
```

## 变体与关联

- 变体：2 字节与 3 字节混用、只编码类名中部分字符、按需扩展数字/其它 ASCII 字符映射；3 字节形式字节数膨胀 3 倍，注意长度前缀。
- 关联：[[web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass]]——同一绕过目标（原生反序列化字节黑名单），该卡侧重攻击判定与后处理改写工具；本卡给出自定义序列化流生成方式。
- 关联：[[web-java-deser-overlong-utf8-javaagent-writeutf]]——用 Java Agent+Javassist 重写 `writeUTF`，类名/字段名/String 全部三字节编码；本卡只编码类名、无需 agent。
- 关联：[[web-java-deser-hessian-utf8-overlong-encoding-bypass]]、[[web-java-deser-kryo-utf8-overlong-encoding-bypass]]——Hessian/Kryo 协议的同类 overlong 类名隐藏。
- 关联：[[web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi]]——用 Overlong UTF-8 绕过 `com.sun` 字符串黑名单的实战链。

## 检测与防御

- 防御：使用 JEP 290 `ObjectInputFilter` 在类解析阶段按解码后的类名/包名白名单拒绝；或在 `resolveClass` 对 `desc.getName()` 做白名单，不要只匹配原始字节。
- 防御：WAF/网关先做严格 UTF-8 规范化并拒绝 overlong 形式（`C0/C1` 开头、`E0 80/81` 开头的三字节序列），再匹配类名特征。
- 检测：反序列化流中字符串长度前缀约为字符数的 2/3 倍；类名区域出现大量 `C0/C1 8x–Bx` 或 `E0 8x xx` 字节而 ASCII 明文消失；代码审计关注自定义 `ObjectOutputStream`/`writeClassDescriptor`/`checkData` 实现。
- 检测：类加载日志中出现 `TemplatesImpl`、`InvokerTransformer` 等敏感类，但请求体按字节匹配不到对应明文时告警。
