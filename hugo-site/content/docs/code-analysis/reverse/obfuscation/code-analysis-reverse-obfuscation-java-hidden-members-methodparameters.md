---
id: code-analysis-reverse-obfuscation-java-hidden-members-methodparameters
title: Java 字节码反反编译隐藏术：ACC_SYNTHETIC/ACC_BRIDGE 与 FernFlower hiddenMembers 隐藏方法与字段，MethodParameters 属性伪造参数名
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: java-bytecode-hidden-members-methodparameters
tags:
- java
- bytecode
- asm
- obfuscation
- anti-decompilation
- fernflower
- idea
- synthetic
- bridge
- method-parameters
- supply-chain
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V616
  verified_at: '2026-11-12T20:49:20+08:00'
  notes: 已通读原文 content.md 并逐张核对 61 张图片：hide 判据（isSynthetic&&REMOVE_SYNTHETIC || ACC_BRIDGE&&REMOVE_BRIDGE || hiddenMembers.contains）与图 10 一致；ACC_SYNTHETIC/ACC_BRIDGE/自定义 Synthetic 属性实现与图 11/13/15 一致；EnumProcessor values/valueOf 规则（图 18/19）、AssertProcessor static+final+synthetic 断言字段规则（图 22/23）、字段 hide 判据（图 21）均一致；MethodParameters 解析格式 长度字节+N×(name_index_ushort,access_flags_ushort) 与图 30/31 一致，USE_METHOD_PARAMETERS 无 isValidIdentifier 校验（图 27/29）成立，中文/多行参数名效果图 32/33 吻合。DoS 类条目（参数数量越界致反编译退出、描述符缺分号死循环）按 brief 未单独成卡，处理正确；dedup 报告 recommendation=new，top 候选（ClassFinal javaagent dump 等）非同链；dup-scan 无涉及 pair。未验证点：未在本机复现隐藏效果；原文未给出精确 IDEA 版本（仅称演讲时最新版），卡片写 2023 前后版本属合理推断。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-java-hidden-members-methodparameters/
draft: false
kb_aliases:
- FernFlower 隐藏方法
- IDEA 反编译隐藏成员
- ACC_SYNTHETIC 隐藏
- ACC_BRIDGE 隐藏
- hiddenMembers
- MethodParameters 属性伪造
- 反反编译混淆
---

## 一句话结论

IDEA/FernFlower 在输出类源码时按 `hide = (isSynthetic && REMOVE_SYNTHETIC) || (ACC_BRIDGE && REMOVE_BRIDGE) || hiddenMembers.contains(key)` 跳过成员；攻击者用 ASM 给方法/字段加 `ACC_SYNTHETIC`/`ACC_BRIDGE` 标志或 `Synthetic` 属性，或刻意构造与 `EnumProcessor`/`AssertProcessor` 等处理器隐藏规则匹配的签名，就能让真实存在且会执行的方法、字段在反编译结果里"消失"；再用自定义 `MethodParameters` 属性给参数写入任意名字（反编译器不做标识符校验），可把代码伪装成无害或难以阅读的形态。

## 原理

- **元数据驱动隐藏**：FernFlower 的 `ClassWriter#classToJava` 遍历类的方法/字段时，只要 `hide` 为 true 就 `continue` 跳过输出。判据来自字节码元数据：`isSynthetic()`（`ACC_SYNTHETIC` 修饰符或 `Synthetic` 属性）、`ACC_BRIDGE` 修饰符、以及 `hiddenMembers` 集合。这些元数据完全由 class 文件提供，攻击者可任意构造；JVM 执行代码并不依赖这些标志，所以被隐藏的成员照常运行。
- **标志位可手写**：ASM 中 `visitMethod(ACC_PUBLIC | ACC_SYNTHETIC, ...)`、`visitMethod(ACC_PUBLIC | ACC_BRIDGE, ...)` 直接生效；`ACC_BRIDGE`/`ACC_VOLATILE`/`ACC_STATIC_PHASE` 共用 `0x0040`。也可 `methodVisitor.visitAttribute(new SyntheticAttribute())` 添加自定义 `Synthetic` 属性（属性名为 "Synthetic"、内容为空）。
- **hiddenMembers 由处理器自动填充**：反编译器的语义处理器会把"编译器生成、不应展示"的成员加入集合，例如 `EnumProcessor` 把枚举类中方法名 `values`、描述符 `()[L<全类名>;`（以及 `valueOf` 等）的方法加入；`AssertProcessor` 把用于断言的 `static final`（且 `isSynthetic` 或 `noSynthFlag`）辅助字段加入；`ClassReference14Processor`、`NestedClassProcessor` 等也有类似规则。攻击者只需让自造成员命中这些签名规则，即被当作"编译器生成物"隐藏；还可以利用重载再造一个同名方法迷惑读者。
- **MethodParameters 伪造参数名**：默认开启 `USE_METHOD_PARAMETERS`，`ClassWrapper#applyParameterNames` 读取 `StructMethodParametersAttribute` 的条目并按 `VarProcessor` 的槽位设置变量名，IDEA 的这条路径没有 `TextUtil.isValidIdentifier` 校验（`USE_DEBUG_VAR_NAMES` 则有），因此可以写入同名、超长、中文甚至带特殊字符的参数名；`StructMethodParametersAttribute.initContent` 逐条读取 `name_index` 与 `access_flags`，自定义 `Attribute#write` 按同样格式写回即可。
- **为什么能欺骗**：反编译器的可读性优化（隐藏编译器生成物、采用调试元数据命名）建立在"class 文件由 javac 生成"的假设上；手写字节码打破该假设后，同一份元数据在"展示层"与"执行层"产生分歧。

## 触发条件

- 攻击者可分发/篡改 Java class 或 jar（插件、依赖包、补丁包、靶场投放物）；
- 受害者用 IDEA/FernFlower 做人工代码审计或反编译查看；
- 目标版本对相应隐藏规则未做元数据一致性校验（原文测试 IDEA 2023 前后版本、JDK8/JDK11）。

## 利用步骤

1. 用 ASM 生成或改写类：`ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);`，`cw.visit(V1_8, ACC_PUBLIC|ACC_SUPER, "HelloWorld", null, "java/lang/Object", null);`。
2. 隐藏方法：`cw.visitMethod(ACC_PUBLIC|ACC_STATIC|ACC_SYNTHETIC, "abc", "()V", null, null)`，方法体照常写恶意逻辑；或加 `ACC_BRIDGE`、或 `visitAttribute(new SyntheticAttribute())`。
3. 隐藏字段：`cw.visitField(ACC_PUBLIC|ACC_STATIC|ACC_FINAL|ACC_SYNTHETIC, "abc", "Ljava/lang/String;", null, null)`。
4. 命中处理器规则：枚举类中构造 `values()`（描述符 `()[L<class>;`）等被 `EnumProcessor` 加入 hiddenMembers 的方法；或构造 `static final` 断言辅助字段命中 `AssertProcessor`。
5. 伪造参数名：继承 `Attribute` 实现 `MethodParameters` 属性的 `write`，按"长度字节 + N×(name_index_ushort, access_flags_ushort)"写入与真实参数数量一致的条目，参数名统一写成相同字符串或误导性文本；`mv.visitAttribute(...)` 添加。
6. 用 `ClassWriter.COMPUTE_FRAMES` 重新计算栈帧，保存 class 分发；受害者反编译时看到的是被裁剪、改名后的"无害"代码，而 JVM 执行的是完整逻辑。

## PoC

```java
// 隐藏方法：ACC_SYNTHETIC 标志
MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC, "abc", "()V", null, null);
mv.visitCode();
mv.visitFieldInsn(GETSTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;");
// ... 真实逻辑（例如 exec）
mv.visitInsn(RETURN);
mv.visitMaxs(2, 0);
mv.visitEnd();

// 隐藏字段：static final synthetic
cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL | ACC_SYNTHETIC, "abc", "Ljava/lang/String;", null, null);

// 自定义 Synthetic 属性
class SyntheticAttribute extends Attribute {
    public SyntheticAttribute() { super("Synthetic"); }
    protected ByteVector write(ClassWriter cw, byte[] code, int len, int maxStack, int maxLocals) {
        return new ByteVector(); // 无内容
    }
}
mv.visitAttribute(new SyntheticAttribute());

// MethodParameters 属性：长度 + N×(name_index, access_flags)
class MethodParameterAttribute extends Attribute {
    int length;
    public MethodParameterAttribute(int length) { super("MethodParameters"); this.length = length; }
    protected ByteVector write(ClassWriter cw, byte[] code, int len, int maxStack, int maxLocals) {
        ByteVector v = new ByteVector();
        v.putByte(length);
        for (int i = 0; i < length; i++) {
            v.putByte(0); v.putByte(5); // name_index 高位/低位（指向常量池同一字符串）
            v.putByte(0); v.putByte(8); // access_flags
        }
        return v;
    }
}
mv.visitAttribute(new MethodParameterAttribute(3));
```

效果：反编译结果中 `abc` 方法/字段不再出现或参数名被统一重命名（原文演示多参数全部显示为同一误导性中文名），但 `java HelloWorld` 仍正常执行。

## 变体与关联

- 变体：用 `ClassReader` + `ClassVisitor` 改写现有 class（`cr.accept(cv, SKIP_DEBUG|SKIP_FRAMES)`，`ClassWriter.COMPUTE_FRAMES`），对第三方 jar 批量注入隐藏标志与伪造参数名。
- 变体：利用 `ACC_STATIC_PHASE`/`ACC_VOLATILE` 与 `ACC_BRIDGE` 共用 0x0040，在字段/方法场景互换使用。
- 变体：给隐藏方法里放计算器等"惊喜"逻辑，反编译者看不到但运行会触发。
- 关联：[[code-analysis-reverse-obfuscation-jsr-ret-pop-swap-decompiler-deception]]（运行时真码/反编译假码的互补手法）、[[code-analysis-reverse-obfuscation-garble-go-binary-symbol-static-evasion]]（另一语言的符号消除思路）。

## 检测与防御

- 分析方：不要只信 IDEA 反编译视图；用 `javap -p -v` 对比 class 的完整方法/字段列表，检查 `ACC_SYNTHETIC`/`ACC_BRIDGE`/`Synthetic` 标记与 `MethodParameters` 异常命名；用多个反编译器（CFR、Procyon、JD-GUI）交叉比对；对可疑类跑动态验证。
- 开发/运维：依赖包校验签名与哈希、固定版本源；对插件/补丁做字节码元数据扫描（合成标志滥用、参数名重复/非标识符）。
- 检测：构建期扫描 `Synthetic`/`Bridge` 标志与源码可见性不一致的类；监控分发包中 class 元数据异常。
