---
id: web-java-deser-overlong-utf8-javaagent-writeutf
title: 序列化端生成 UTF-8 Overlong Encoding：Java Agent + Javassist 重写 ObjectOutputStream$BlockDataOutputStream#writeUTF/writeUTFBody，让类名自动三字节编码绕过字节黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: objectoutputstream-writeutf-agent-overlong-encoding
aliases:
- Java Agent 实现 UTF-8 Overlong Encoding
- writeUTF 打补丁 overlong
- BlockDataOutputStream writeUTFBody 重写
- 序列化时超长编码
- ObjectOutputStream 三字节编码
- Overlong 编码 payload 生成
tags:
- web
- java
- deserialization
- overlong-encoding
- utf8
- java-agent
- javassist
- instrumentation
- waf-bypass
- blacklist-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:35:06+08:00'
  notes: 已对照原文全文与9张图核实：writeUTF 快速路径/utflen 处理、writeUTFBody 分支、readUTFChar 三字节不校验最短编码、agent+javassist 补丁及 MANIFEST 均一致；原文 premain retransform AccessibleObject 的目标错位卡内已标注。与既有 overlong 后处理卡、Hessian overlong 卡、certpath agent 卡为不同生成手段/协议/目的，非同链。小提示（不影响成立）：utflen 来自 getUTFLength（modified UTF-8 字节长），仅纯 ASCII 时 equals 字符数，故 utflen*3 前缀只在纯 ASCII（全走三字节分支）时自洽，非 ASCII 字符会前缀超出；卡内边界说明可再精确。原文未给受影响 JDK 版本区间，仅演示环境 JDK8+CC3.2.1，不设 affected_versions 正确。dup-scan(11-08)早于建卡，不涉及本卡。
---

## 一句话结论

不必在序列化完成后手工改写字节：在 payload 生成端用 `java.lang.instrument` agent + Javassist 在类加载时替换 `java.io.ObjectOutputStream$BlockDataOutputStream` 的 `writeUTF(String,long)` 与 `writeUTFBody(String)`，把长度前缀同步为 `utflen*3` 并让每个字符都走三字节分支，`writeObject` 产出的序列化流中类名/字段名/字符串会整体变成 UTF-8 overlong 编码；Java 的 `readUTF` 不校验最短编码，目标端仍能解出原字符正常反序列化，而依赖 ASCII 明文类名的 WAF/字节黑名单全部失配。

## 原理

- **序列化方如何写字符串**：Java 原生序列化用 modified UTF-8 写类名、字段名与 String 值。`BlockDataOutputStream#writeUTF(String s)` 先调 `writeUTF(s, getUTFLength(s))`；`writeUTF(String s, long utflen)` 先 `writeShort((int) utflen)`，若 `utflen == s.length()`（纯 ASCII 且无 NUL）走 `writeBytes(s)` 快速路径，否则才走 `writeUTFBody(s)`。`writeUTFBody` 对 `c <= 0x7F` 写 1 字节、`0x80–0x7FF` 写 2 字节、`> 0x7FF` 写 3 字节。
- **打补丁思路**：把 `writeUTF(String,long)` 改为 `writeShort((int) utflen * 3); writeUTFBody(s);`，再把 `writeUTFBody` 中 1 字节和 2 字节分支注释/删除，只保留三字节分支 `0xE0|((c>>12)&0x0F)`、`0x80|((c>>6)&0x3F)`、`0x80|(c&0x3F)`。这样 ASCII 的 `R`（0x52）也会写成 `E0 81 92`，长度前缀按每字符 3 字节计算，二者一致。
- **为什么目标端还能解开**：`ObjectInputStream#readUTFChar` 按首字节前缀分派：`0xxxxxxx` 1 字节、`110xxxxx` 2 字节、`1110xxxx` 3 字节；三字节分支只校验后两字节为 `10xxxxxx`，然后按位组合出 char，并不检查该码点是否本应使用更短编码。因此 `E0 81 92` 被还原成 0x52，反序列化行为与原始流完全一致。
- **效果**：流中不再出现 `java.lang.Runtime`、`org.apache.commons.collections.functors.InvokerTransformer`、`TemplatesImpl` 等 ASCII 明文。按原始字节 `contains`/正则匹配类名的 WAF 与自定义字节黑名单失效；文章用 CC 链验证，overlong 流仍正常反序列化并弹出计算器。
- **agent 实现路径**：`premain` 中 `Instrumentation.addTransformer(transformer, true)` 注册可重转换的 `ClassFileTransformer`；`transform` 收到 `java/io/ObjectOutputStream$BlockDataOutputStream` 时用 Javassist `ClassPool.get(...)` 取类，`removeMethod` 删旧方法后 `CtNewMethod.make` 添加补丁方法，返回 `toBytecode()`；其他类原样返回 `classfileBuffer`。清单需 `Premain-Class`、`Can-Redefine-Classes`、`Can-Retransform-Classes`，生成端 JVM 加 `-javaagent:<jar>`。
- **实现注意**：文章 `premain` 里调用 `retransformClasses(AccessibleObject.class)` 与目标类不符，疑似笔误/占位；实际生效要么依赖 transformer 在该类首次加载时被调用（即在 `ObjectOutputStream` 使用前注册），要么应重转换 `ObjectOutputStream$BlockDataOutputStream` 本身。
- **边界**：长度前缀固定写 `utflen*3`，只有所有字符都走三字节分支时长度才匹配；文章实现保留了 `writeUTFBody` 中缓冲将满（`pos > MAX_BLOCK_SIZE - 3`）时的原逐字节写出分支，长字符串/跨块会把字节数写少导致 `readUTF` 错位。本卡 PoC 改为写每个字符前先判断并 `drain()`，使长串也保持每字符 3 字节。

## 触发条件

- 攻击者控制 payload 生成端 JVM：能使用 `-javaagent` 挂载 premain agent（或有 retransform 能力），并具备 Javassist/ASM。
- 目标存在 Java 原生反序列化入口，防护为匹配原始字节/明文字符串的 WAF 或自定义黑名单（不校验解码后类名，也未使用 JEP 290 白名单）。
- 目标 JVM 的 `readUTF` 接受 overlong 形式（OpenJDK 常见实现如此，`readUTFChar` 三字节分支不做最短编码校验）。

## 利用步骤

1. 编写 `ClassFileTransformer`，仅当类名为 `java/io/ObjectOutputStream$BlockDataOutputStream` 时用 Javassist 重写两个方法；其他类原样返回。
2. 替换 `writeUTF(String s, long utflen)`：改为 `writeShort((int) utflen * 3)` 后直接 `writeUTFBody(s)`。
3. 替换 `writeUTFBody(String s)`：删除 1 字节/2 字节分支，所有字符都按三字节写出（长串需处理块边界）。
4. 打包 agent jar，MANIFEST 设置 `Premain-Class` 与 `Can-Retransform-Classes`；生成端 JVM 加 `-javaagent`。
5. 正常构造 gadget 链（如 CC + LazyMap/ChainedTransformer，或 TemplatesImpl 链）并 `writeObject` 落盘；用十六进制/编辑器确认类名区域的字节呈现 `E0 8x xx` 三字节序列、原 ASCII 明文消失。
6. 将 overlong 流发送到目标反序列化入口，验证命令执行；若目标在 `resolveClass` 用解码后类名或 JEP 290 白名单拦截，需要改用其他绕过。

## PoC

最小 agent 骨架（生成端离线使用，未在目标执行）：

```java
public static void premain(String args, Instrumentation inst) {
    inst.addTransformer((loader, className, redefined, pd, buf) -> {
        if (!"java/io/ObjectOutputStream$BlockDataOutputStream".equals(className)) return buf;
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass cc = pool.get("java.io.ObjectOutputStream$BlockDataOutputStream");
            cc.removeMethod(cc.getMethod("writeUTF", "(Ljava/lang/String;J)V"));
            cc.addMethod(CtNewMethod.make(
                "public void writeUTF(String s, long utflen) throws IOException {" +
                "  writeShort((int) utflen * 3); writeUTFBody(s); }", cc));
            cc.removeMethod(cc.getDeclaredMethod("writeUTFBody"));
            cc.addMethod(CtNewMethod.make(
                "private void writeUTFBody(String s) throws IOException {" +
                "  for (int i = 0; i < s.length(); i++) {" +
                "    char c = s.charAt(i);" +
                "    if (pos > MAX_BLOCK_SIZE - 3) drain();" +
                "    buf[pos + 2] = (byte)(0x80 | ((c >> 0) & 0x3F));" +
                "    buf[pos + 1] = (byte)(0x80 | ((c >> 6) & 0x3F));" +
                "    buf[pos + 0] = (byte)(0xE0 | ((c >> 12) & 0x0F));" +
                "    pos += 3;" +
                "  } }", cc));
            byte[] bytes = cc.toBytecode();
            cc.detach();
            return bytes;
        } catch (Exception e) { throw new RuntimeException(e); }
    }, true);
}
```

生成：`new ObjectOutputStream(new FileOutputStream("ser.bin")).writeObject(<gadget 对象图>)`（例如 LazyMap/ChainedTransformer 的 CC 链），在 `-javaagent` 生效的 JVM 中运行即可得到 overlong 流。

## 变体与关联

- **与后处理改写的关系**：同一目标（隐藏类名绕过字节黑名单）也可在 `writeObject` 之后用工具/脚本逐字节把类名重编码并修正 UTF 长度前缀（如 java-chains 的 Utf8OverlongEncoding）。本卡是"序列化时直接产出"，无需后处理；参见既有卡 [[web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass]]，两者绕过目标相同、生成手段不同。
- **同类 agent 构造技巧**：payload 构造端用 agent+Javassist 改 JDK 类，还可删除 `CertPath.writeReplace` 防止对象被替换，见 [[web-java-deser-certpath-writereplace-agent-strip]]。
- **适用面**：所有经 `writeUTF` 写出的字符串都会受影响（类名、字段名、String 字段值），因此流中 ASCII 特征整体消失；但对 `resolveClass` 的解码后类名判定、JEP 290 `ObjectInputFilter`、包名白名单无效。
- **其他协议**：Hessian 等同样基于 modified UTF-8/字符串类名的协议有类似 overlong 绕过，但编码位置与长度字段不同，不能直接套用本 agent。

## 检测与防御

- **防御**：用 JEP 290 `ObjectInputFilter` 在类解析阶段按解码后的类名/包名做白名单；不要用原始字节或明文字符串匹配类名；能不用原生序列化就不用。
- **检测**：反序列化流量中出现非最短 UTF-8 编码——ASCII/两字节范围字符被写成 `E0 8x xx` 三字节形式；字符串长度前缀约等于字符数的 3 倍；大量 `E0 80`/`E0 81` 前缀的三字节序列。
- **WAF 侧**：匹配前先做严格 UTF-8 规范化/解码（拒绝 overlong 形式），或直接按解码后的类名做检测，而不是匹配原始字节。
- 生成端 agent 只影响攻击者本地 JVM，不能替代目标侧防护。
