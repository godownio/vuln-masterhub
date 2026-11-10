---
id: defense-hardening-rasp-asm-visitcode-hook-localvar-index
title: 用 ASM 在 ClassFileTransformer 里插入 hook 调用：visitCode + 局部变量表下标规则定位表达式/命令参数
type: scenario
domain: defense
path: defense/hardening
technique: rasp-asm-visitcode-hook-localvar-index
aliases:
- ASM 实现 RASP hook
- visitCode 插入静态回调
- 局部变量表下标规则
- AdviceAdapter 插桩
- ProcessBuilder.command GETFIELD
- ClassReader accept 遍历所有方法
tags:
- java
- rasp
- asm
- instrumentation
- bytecode
- hook
- jvm
- hardening
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:37:45+08:00'
  notes: 已对照原文核对；原文 case2/case3 的 TestClassVisitor 按 name+desc 匹配后 visitCode 内插 ALOAD/GETFIELD/INVOKESTATIC、表达式注入 demo 用 MethodHookDesc 三元组列表驱动且 OGNL/MVEL 取 ALOAD 0、SpEL <init> 取 ALOAD 1、阻断用 throw SecurityException、agentmain 重复 attach 与无法新增 public 方法（class redefinition failed）等要点均与原文一致；已修正原文两处下标写法表述（原文 MVEL.eval 与 Ognl.parseExpression 同为静态方法走 ALOAD 0，卡内原先误写为实例方法 ALOAD 1）。未验证点：原文以 Spring Boot 2.1.3/ASM 5.1 环境演示，未做版本适用范围声明，故未设 versions
---

## 一句话结论

要自己写一个能检测表达式注入/命令执行的最小 RASP，核心只有三步：`ClassFileTransformer` 里按「类名 `equals` + 方法名 `equals` + 方法描述符 `equals`」精确匹配目标方法，用 `ClassReader → ClassVisitor → MethodVisitor(AdviceAdapter)` 在 `visitCode()` 里插入一条 `INVOKESTATIC` 回调把参数传出去，再用 `ClassWriter(COMPUTE_MAXS).toByteArray()` 回写字节码；能否正确取到「要检查的那个参数」取决于**局部变量表下标规则**（静态方法 `0` 是首个参数，实例方法 `0` 是 `this`、`1` 才是首个参数），取字段则用 `GETFIELD`/`GETSTATIC` 而不是查局部变量表。

## 原理

- **匹配必须精确到描述符**：同一个类里可能有多个同名重载方法（如 `eval(String)` 与 `eval(char[])`），只比方法名会把 hook 插错位置。ASM 的 `visitMethod(access, name, desc, signature, exceptions)` 同时给出 `name` 与 `desc`，`desc` 就是 JVM 方法描述符（`(Ljava/lang/String;)Ljava/lang/Object;` 表示「接收一个 String、返回 Object」），因此三个条件都 `equals` 才返回自定义 `MethodVisitor`。
- **插入点在 `visitCode()`**：`ClassVisitor.visitMethod` 返回的 `MethodVisitor` 在被 `ClassReader.accept()` 驱动时，按顺序收到 `visitAnnotation`/`visitCode`/指令事件/`visitMaxs`/`visitEnd`。在 `visitCode()`（即原方法体第一条指令之前）插入回调，等于在方法入口执行检查；`AdviceAdapter` 在此基础上封装了 `onMethodEnter()`，并负责维护 `COMPUTE_MAXS` 下的栈帧正确性。
- **为什么要在意局部变量表**：JVM 方法调用时，参数与 `this` 都占用局部变量表的前几个槽位。**实例方法**槽 0 是 `this`，第一个参数在槽 1；**静态方法**没有 `this`，第一个参数就在槽 0。原文里 `ognl.Ognl.parseExpression` 与 `org.mvel2.MVEL.eval` 都是静态方法所以 `ALOAD 0`，而 `SpelExpression.<init>` 是实例方法所以 `ALOAD 1`；取错槽位会拿到 `this` 或下一个参数，回调里打印出来的"表达式"就不是攻击者真正传的那串。这解释了为什么同一套代码对不同 hook 点要按方法类型选下标。
- **取字段不是取局部变量**：检查 `ProcessBuilder.start()` 时，要看的命令列表不在参数里，而是对象的 `command` 字段。`ProcessBuilder` 的 `start()` 描述符是 `()Ljava/lang/Process;`（无参实例方法），`this` 在槽 0，于是指令序列是 `ALOAD 0` → `GETFIELD java/lang/ProcessBuilder.command:Ljava/util/List;` → `INVOKESTATIC Hook.start(Ljava/util/List;)V`。局部变量表里只有 `this`，字段值必须通过对象引用读取。
- **`ClassReader.accept()` 会遍历整个类**：只要 transformer 判定该类需要处理，`accept` 就会对类中**每一个**方法回调 `visitMethod`（这也是为什么原文 case2 只匹配到 `ProcessBuilder` 一次，却在控制台看到该类所有方法的名字与描述符被打印）。反过来说，想只处理一个方法，必须在 `visitMethod` 内部再判一次名与描述符，否则等于给整个类都插了桩。
- **阻断就是一个 `throw`**：RASP 的回调里判定命中后抛 `SecurityException`，异常会沿被 hook 方法的调用栈向上抛，直接中断当前业务调用，无需修改返回类型或跳过原方法体。
- **打包与加载**：`MANIFEST.MF` 要声明 `Premain-Class`、`Can-Retransform-Classes: true`、`Can-Redefine-Classes: true`；hook 用的依赖（ASM、javassist）必须 shade 进同一个 agent jar，否则 agent 自己加载不到；`-javaagent` 只是让 `premain` 在 `main` 之前跑，`addTransformer` 之后新加载的类才会被回调。

## 触发条件

- 要在不改业务源码的前提下对 JVM 内的方法调用做实时检查（自建 RASP、AWD 通防、诊断 agent）。
- 目标 JVM 允许 `-javaagent`（或可 attach），且待 hook 的类尚未被更强的 ClassLoader/字节码保护阻断 transform。
- 知道目标方法所在类名、方法名与精确描述符（可从 jar 反编译、`javap -s` 或文档获得）。

## 利用步骤

1. 用 `javap -s`/反编译确认目标方法的三元组：类名（内部名 `a/b/C`）、方法名、描述符（含参数与返回值）。
2. 写 `ClassFileTransformer.transform`：把 `className.replace('/','.')` 后与目标类名比对；命中才进入 ASM 改写。
3. 构造 `ClassReader(classfileBuffer)`、`ClassWriter(cr, COMPUTE_MAXS)`、自定义 `ClassVisitor`，并 `cr.accept(cv, ClassReader.EXPAND_FRAMES)`。
4. 在 `ClassVisitor.visitMethod` 里按名 + 描述符精确匹配，命中则返回一个在 `visitCode()` 里插入 `ALOAD`（按上表选槽位）+ 可选 `GETFIELD`/`GETSTATIC` + `INVOKESTATIC` 回调的 `MethodVisitor`。
5. 回调方法签名与压栈类型严格对应（例如 `(Ljava/lang/String;)V` 就只能压一个 String），并在回调里打印参数、调用栈（`Thread.currentThread().getStackTrace()`）以及上下文信息。
6. 打包成 agent jar（shade 依赖 + 写 `MANIFEST.MF`），用 `-javaagent:agent.jar` 启动被测应用；访问触发点验证回调确实打印出攻击者传入的表达式。
7. 判定命中后抛 `SecurityException` 即可阻断；先用宽松日志模式验证不误报，再切到拦截模式。

## PoC

```java
// 类 + 方法 + 描述符三元组匹配，visitCode 插入静态回调
public byte[] transform(ClassLoader loader, String className, Class<?> redefined,
                        ProtectionDomain pd, byte[] buf) {
    final String cn = className.replace('/', '.');
    if (!"ognl.Ognl".equals(cn)) return buf;                 // 只处理目标类
    ClassReader cr = new ClassReader(buf);
    ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
    ClassVisitor cv = new ClassVisitor(Opcodes.ASM5, cw) {
        @Override public MethodVisitor visitMethod(int acc, String name, String desc,
                                                   String sig, String[] ex) {
            MethodVisitor mv = super.visitMethod(acc, name, desc, sig, ex);
            if (!"parseExpression".equals(name)
                    || !"(Ljava/lang/String;)Ljava/lang/Object;".equals(desc)) return mv;
            return new MethodVisitor(Opcodes.ASM5, mv) {
                @Override public void visitCode() {
                    mv.visitVarInsn(Opcodes.ALOAD, 0);           // 静态方法：槽 0 = 首个参数
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        "cn/org/javaweb/agent/Agent", "expression",
                        "(Ljava/lang/String;)V", false);
                }
            };
        }
    };
    cr.accept(cv, ClassReader.EXPAND_FRAMES);
    return cw.toByteArray();
}

public static void expression(String exp) {
    System.err.println("EXP: " + exp);
    for (StackTraceElement e : Thread.currentThread().getStackTrace()) System.err.println(e);
}
```

```java
// 读实例字段：ProcessBuilder.start() 无参，this 在槽 0，命令在 command 字段
mv.visitVarInsn(Opcodes.ALOAD, 0);
mv.visitFieldInsn(Opcodes.GETFIELD, "java/lang/ProcessBuilder", "command", "Ljava/util/List;");
mv.visitMethodInsn(Opcodes.INVOKESTATIC, "cn/org/javaweb/agent/ProcessBuilderHook",
                   "start", "(Ljava/util/List;)V", false);
```

```text
MANIFEST.MF
Manifest-Version: 1.0
Premain-Class: cn.org.javaweb.agent.Agent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
```

```java
// 命中即阻断：抛异常沿调用栈向上传播，中断当前业务调用
throw new SecurityException("Detected malicious expression: " + exp);
```

## 变体与关联

- **实例方法 vs 静态方法**：`SpelExpression` 的 `<init>` 是实例方法，首个 String 参数在槽 1；`MVEL.eval` 与 `Ognl.parseExpression` 是静态方法，首个参数在槽 0，压栈下标必须按方法类型区分，写错会取到 `this`。
- **类变量 vs 局部变量**：`AbstractParser.parse()` 里 `stk`/`dStack` 属于对象实例，只能通过 `this` 读（`ALOAD 0` + `GETFIELD`）；静态字段用 `GETSTATIC`/`PUTSTATIC`，与局部变量表无关。
- **多 hook 点合并**：用 `MethodHookDesc(className, methodName, argDesc)` 列表驱动同一个 transformer，可一次覆盖 MVEL/OGNL/SpEL 等多个表达式引擎入口。
- **换插桩库**：Javassist 的 `insertBefore` 写法更短但在复杂方法上更易踩栈帧/局部变量冲突；见 [[defense-hardening-java-rasp-sink-hookpoints-limits]]（同为 RASP hook 布局，但用 Javassist 代理与 JSON 配置驱动、六类 sink 名单）。
- **攻击侧对照**：同样的 ASM + `transform` 能力可用于改写业务逻辑/认证判断，见 [[web-java-classloader-asm-retransform-auth-bypass]]。
- **边界**：hook 点必须是可被 retransform 的非 native 方法；`forkAndExec` 这类 native 方法改不了字节码；`COMPUTE_MAXS` 下改动过大时需改用 `COMPUTE_FRAMES`。

## 检测与防御

- 检测（防守侧自检）：确认 `visitMethod` 的匹配同时包含方法名与描述符，否则重载方法会误插；确认压栈下标与目标方法是静态还是实例一致；用 `VERIFY` 关闭时插入非法字节码会静默失败，务必先在测试环境验证。
- 检测（作为被防护方视角）：JVM 启动参数出现 `-javaagent`/`-Xbootclasspath`；类加载期出现大量 `ClassReader`/`ClassWriter` 活动；应用日志出现 `SecurityException` 且无业务代码抛出点。
- 防御设计：hook 点选在「参数已确定、尚未产生副作用」的位置（如 `parseExpression` 入口、`ProcessBuilder.start` 入口），避免在已经执行完的动作上判定；规则用精确白名单而非子串黑名单。
- 稳定性：回调内部必须自己吞掉异常（抛出代理类 `NotClassFound` 之类错误会直接打断业务），并把检查逻辑与业务线程隔离（例如异步聚合后再决策）。
