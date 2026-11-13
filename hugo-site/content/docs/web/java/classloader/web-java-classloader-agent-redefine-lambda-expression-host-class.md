---
id: web-java-classloader-agent-redefine-lambda-expression-host-class
title: Java Agent redefineClasses 的 lambda 限制：新字节码含 lambda 即 ClassFormatError 或增删方法报错，宿主类选择与 ASM 清空方法体绕过
type: scenario
domain: web
path: web/java/classloader
technique: agent-redefineclasses-lambda-host-class-selection-asm-clear
tags:
- java
- jvm
- instrumentation
- agent
- redefineclasses
- lambda
- javassist
- asm
- memshell
- debugging
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V629
  verified_at: '2026-11-12T23:26:55+08:00'
  notes: 已对照 content.md 与全部 8 张截图核对：图04 ClassFormatError、图05 attempted to delete a method、图06 attempted to add a method 与原文叙述顺序一致；宿主类清单（WsFilter/StandardContextValve 推荐）、Javassist 无法彻底删除 lambda、源码改匿名内部类仍报 attempted to add a method、ASM visitMethod 返回 null 清空方法体且保留 lambda 合成方法、JRebel/spring-loaded 代理为最后手段、Tomcat10 javax→jakarta 提示，均与原文一致；ASM PoC 与原文代码一致。未验证点：未实际运行 javassist/ASM 复现报错。dedup top 候选均为 Attach/ASM Agent 注入链，非同链，保留。
url: /docs/web/java/classloader/web-java-classloader-agent-redefine-lambda-expression-host-class/
draft: false
kb_aliases:
- redefineClasses lambda 报错
- ClassFormatError redefineClasses
- attempted to add a method
- attempted to delete a method
- Agent 内存马宿主类选择
- WsFilter 宿主类
- StandardContextValve 宿主类
- ASM 清空方法体
---

## 一句话结论

用 Java Agent/Instrumentation 的 `redefineClasses` 做内存替换时，若新字节码所在方法含有 lambda 表达式，会直接失败：轻则 `java.lang.ClassFormatError`，重则 `UnsupportedOperationException: class redefinition failed: attempted to add/delete a method`；Javassist 无法彻底删除 lambda，源码改成匿名内部类也会因“新增方法”被拒绝。可行路径是选无 lambda 且类体小的宿主类（`WsFilter`、`StandardContextValve` 等），或用 ASM 清空/重写方法体（保留 lambda 生成的合成方法不动），必要时用热部署式代理替换调用点。

## 原理

- **Instrument API 的硬约束**：`redefineClasses`/`retransformClasses` 只允许修改方法体、常量池等，不允许增加或删除方法、字段、接口；JVM 会比对新旧类结构，结构不一致就抛 `UnsupportedOperationException: attempted to add/delete a method`。
- **lambda 为什么会踩线**：Java 8 的 lambda 在编译后是 `invokedynamic` + 编译器生成的 synthetic 方法（如 `lambda$doFilter$0`）。用 Javassist 加载含 lambda 的类再输出时，字节码里这些合成方法/引导方法结构会变化，导致重定义时 JVM 看到“新增/删除方法”而拒绝；直接用 Javassist 改含 lambda 的方法体（insertBefore/setBody）也无法干净移除 lambda，原文在 `org.apache.catalina.core.ApplicationFilterChain.doFilter` 上反复失败并出现 `ClassFormatError`。
- **为什么换宿主类有效**：`ApplicationFilterChain.doFilter` 内部用了 `AccessController.doPrivileged(... () -> {...})` lambda；而 `org.apache.tomcat.websocket.server.WsFilter`、`org.apache.catalina.core.StandardContextValve`（改 `invoke()`）等请求必经类没有 lambda 且体积短小，改方法体不会触碰方法/字段结构，因此能被 `redefineClasses` 接受。
- **源码级等效替换的陷阱**：把 lambda 改成匿名内部类 `new PrivilegedExceptionAction<Void>() { ... }` 后重新编译，虽然语义等价，但匿名类会生成新的方法/内部类，仍然触发“attempted to add a method”类错误——Instrument API 不认这种替代。
- **ASM 方案为什么可行**：原文用 ASM 的 `ClassVisitor.visitMethod` 对目标方法 `visitCode` 后写入全新方法体并 `return null`（不调用 `super.visitMethod` 转发原方法内容），等于把方法体清空/替换；注意这并没有删除字节码中的 lambda 生成方法，只是去掉了会引发结构比对的残余数据，因此不违反“不增删方法”约束。之后再可用 Javassist 读取 ASM 产物做二次编辑，兼顾精确与便捷。
- **最后手段**：参考 JRebel/spring-loaded/hotcode2 等热部署工具，在每个调用点做代理并加载全新类，绕过 redefineClasses 的结构限制，但需要替换多个类，成本高。

## 触发条件

- 使用 Java Agent（agentmain/premain 或生成式无文件注入）对已加载类做 `redefineClasses`/`retransformClasses`。
- 新字节码涉及的方法含 lambda 表达式，或修改方式导致方法/字段增删。
- 目标 JDK 为 8 等对 lambda 用 invokedynamic + synthetic 方法实现的环境（高版本行为类似，限制更严）。

## 利用/排错步骤

1. 复现报错：替换含 lambda 的宿主类（如 `ApplicationFilterChain.doFilter`）时观察控制台：`ClassFormatError` 或 `UnsupportedOperationException: attempted to add/delete a method`。
2. 控制变量：换成不含 lambda 的类（`WsFilter`）验证注入逻辑本身没问题。
3. 选宿主类：优先请求处理必经、无 lambda、类体小的方法——`org.apache.tomcat.websocket.server.WsFilter.doFilter`、`org.apache.catalina.core.StandardContextValve.invoke`；备选 `DispatcherServlet`、`HttpServlet.service`（Tomcat 10 的 javax→jakarta 变化需注意）。
4. 若必须用含 lambda 的类：用 ASM 清空/重写目标方法体（`visitMethod` 返回 null 表示不复制原内容），确认 lambda 生成的方法保留在字节码中不被删除，再重新生成类。
5. 仍失败时：检查是否因源码改匿名内部类引入新方法（回退该做法），最后才考虑热部署式代理替换调用点。

## PoC

javassist 选择无 lambda 宿主类并插入逻辑（宿主类样例）：

```java
ClassPool pool = ClassPool.getDefault();
CtClass ctClass = pool.getCtClass("org.apache.tomcat.websocket.server.WsFilter");
CtMethod m = ctClass.getDeclaredMethod("doFilter");
m.insertBefore("Runtime.getRuntime().exec(\"calc\");");
ctClass.writeFile();
ctClass.detach();
```

ASM 清空目标方法体（原文 ChatGPT 生成的写法，核心是 `visitMethod` 不转发原方法）：

```java
ClassReader cr = new ClassReader("org.apache.catalina.core.ApplicationFilterChain");
ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
ClassVisitor cv = new ClassVisitor(Opcodes.ASM7, cw) {
    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
        if (name.equals("doFilter")) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, ex);
            mv.visitCode();
            mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
            mv.visitLdcInsn("Hello, World!");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(2, 1);
            mv.visitEnd();
            return null; // 不复制原方法体，避免 lambda 残余触发 redefine 失败
        }
        return super.visitMethod(access, name, desc, sig, ex);
    }
};
cr.accept(cv, 0);
byte[] out = cw.toByteArray();
```

## 变体与关联

- 关联应用：[[web-java-classloader-fileless-agent-memshell-jvmti-can-redefine-patch]]（无文件 Agent 内存马注入，宿主类选择同样适用本卡结论）。
- 对照：落地 agent jar 的 Attach 注入 [[web-java-classloader-deser-attach-agent-filterchain-memshell]]、ASM 工程化改写 [[web-java-classloader-agent-asm-framework-filter-memshell]]。
- 变体：换用 ASM 完全重写方法体后可再交给 Javassist 二次编辑复杂逻辑；不同中间件（Tomcat/WebLogic/Jetty）的请求必经类不同，按“无 lambda + 短小 + 必经”筛选。

## 检测与防御

- 检测：JVM 日志中 `redefineClasses` 的 `ClassFormatError`/`attempted to add/delete a method` 报错，可能是攻击者试注入失败的痕迹；监控 `InstrumentationImpl.redefineClasses0` 调用与宿主类（WsFilter/StandardContextValve/HttpServlet）被重定义的记录。
- 防御：RASP 拦截对请求链关键类的重定义；升级 JDK 并开启强封装；对 Agent 注入工具与内存马做常规排查。
