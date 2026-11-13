---
id: web-java-classloader-agent-asm-framework-filter-memshell
title: Java Agent + ASM 改写 Spring/Shiro 框架 Filter 的工程化内存马
type: scenario
domain: web
path: web/java/classloader
technique: agent-asm-framework-filter-memshell
aliases:
- Agent-filter 内存马
- agentmain 改写 DelegatingFilterProxy
- ASM 篡改 doFilter
- Shiro AbstractShiroFilter 内存马
- 工程化 Agent 内存马
- 冰蝎 reGeorg filter 内存马
tags:
- java
- agent
- instrumentation
- asm
- memshell
- filter
- spring
- shiro
- attach
- tomcat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V605
  verified_at: '2026-11-12T18:36:35+08:00'
  notes: 已对照原文与图01-09核对：Filter 链示意图（图01）、Shiro 调试调用栈 doFilterInternal:362→OncePerRequestFilter→DelegatingFilterProxy（图02）；Shiro AbstractShiroFilter.doFilterInternal 篡改前/后，后版本以 getHeader("Signature").equals("bl4ckH0le") 命中后 new File(jar绝对路径).toURI().toURL() + URLClassLoader 反射 loadClass("com.jk.HookFun").newInstance() 并反射调用 beforeMethod（图03-04）；Spring DelegatingFilterProxy.doFilter 篡改前/后，后版本插入 if (HookFun.beforeMethod(var1,var2)==0) 才执行原逻辑（图05-06）；HookFun 路由（/user/apiproxy、/user/apiproxy2、口令 osskey、exec/upload/rebyed/download，图07）与自定义 MyRequest/MyResponse/MySession 等 redef 类（图08）、memAgent 多容器 plugins 工程与 Agent.java attach 实现/MANIFEST 用法（图09）均一致。修正一处技术笔误：原理中 HookFun.beforeMethod 描述符 (Object,Object)Z 改为原文 paramstype 的 (Object,Object)I（HookFun 实际返回 int，0 继续原逻辑、非 0 提前 RETURN），库内卡片与 staging 草稿同步修正并记录。原文只给代码与工程结构、未给命令回显/冰蝎连接运行截图，confidence=medium 合理；原文未声明具体受影响版本（仅称版本跨度大），affected_versions 保持 null；未在本机执行任何代码。
---

## 一句话结论

在已取得目标 JVM 同用户权限的前提下，可用 Attach API 把自写 Agent 注入 Tomcat/Spring Boot/JBoss/WebLogic/Jetty 进程，`agentmain` 里注册 ASM `ClassFileTransformer` 并对已加载的框架 Filter 类（Spring `DelegatingFilterProxy`、Shiro `AbstractShiroFilter`）`retransformClasses`，在 `doFilter`/`doFilterInternal` 入口插入静态 `HookFun` 调用，命中特征头时在 Filter 层直接执行命令、读文件、接入冰蝎或 reGeorg 代理并提前返回，形成不落地、重启即消失的 Filter 型内存马。

## 原理

- **Filter 链是递归调用**：容器 Filter 的 `doFilter(request,response,chain)` 内部调用 `chain.doFilter`，所有请求都会经过；在链条入口任一 Filter 的方法体开头插桩，就能在业务逻辑前处理任意请求并决定是否放行。
- **Attach + agentmain 重定义已加载类**：`VirtualMachine.list()` 枚举 JVM（按 `weblogic.server`、`jetty.runner`、`jboss.as.standalone`、`catalina`、springboot 特征筛选），`attach()` 后 `loadAgent(agentJar)`；Agent 的 `agentmain` 调 `inst.addTransformer(new TransformerAsm(), true)`，再对已加载的目标类 `inst.retransformClasses(c)`，JVM 用 Transformer 返回的字节码替换类定义，无需重启或新建 ClassLoader。
- **ASM 注入入口逻辑**：Transformer 用 `ClassReader`/`ClassWriter` 与自定义 `MethodVisitor`，在目标方法 `visitCode()` 时插入：加载 `request`/`response`（或 Filter 的 `ServletRequest`/`ServletResponse` 参数），`INVOKESTATIC HookFun.beforeMethod(Object,Object)I`；返回非 0 则 `RETURN` 结束原 Filter（请求已被 HookFun 处理），返回 0 则继续原逻辑（用 Label 与 `F_SAME` frame 保证栈帧合法）。
- **为什么选 ASM 而不是 javassist**：ASM 生成的 agent jar 更小（原文约 10KB），适合投递；代价是字节码编写复杂。
- **类加载器差异**：Jetty/Spring/Tomcat/WebLogic 的 Filter 类加载器能加载 agent 包内依赖，可直接 `INVOKESTATIC`；JBoss/Shiro 的上下文不加载本地依赖，需要在注入的字节码里用反射/`URLClassLoader` 从 agent jar 重新加载 `HookFun` 再反射调用，否则 `NoClassDefFoundError`。
- **HookFun 的后门能力**：所有功能通过反射实现，避免直接引用容器类；按请求头 `Signature: bl4ckH0le` 识别控制流量，支持命令执行、文件读取/下载、冰蝎协议、reGeorg/reGeorg2 正向代理。自定义 Request/Response 包装用于适配不同容器的 API 差异。
- **工程化**：`MANIFEST.MF` 设置 `Agent-Class`/`Premain-Class`/`Main-Class` 为对应容器的 Agent 类，`Can-Redefine-Classes`/`Can-Retransform-Classes: true`；每个容器一个 plugin，按运行环境选择，减小 jar 体积。
- **证据边界**：原文给出完整工程代码、ASM 前后对比与目录结构，但未给出实际命令回显/冰蝎连接的运行截图，故本卡 confidence 记 medium；技术链本身与既有 Attach Agent 内存马一致。

## 触发条件

- 攻击者已能在目标主机以与 JVM 相同用户执行代码（后渗透/命令执行），可访问 `tools.jar`（JDK 8）或 `jdk.attach` 模块。
- 目标 JVM 未禁用 Attach（`-XX:+DisableAttachMechanism` 未开启），且目标类已加载。
- Agent jar 可被目标进程读取；目标 Filter 类未被禁止 retransform。
- 需要知道容器类型以选择 attach 特征与 Agent 入口。

## 利用步骤

1. 枚举进程与 JVM：`jps -l`/`VirtualMachine.list()`，按容器特征（catalina、springboot、jboss、weblogic、jetty）选择目标。
2. 将 memAgent.jar 上传到目标可读路径，`java -cp tools.jar:memAgent.jar plugins.<container>.<X>Agent` 或由已控代码调用 `VirtualMachine.attach(vmd).loadAgent(path)`。
3. `agentmain` 注册 ASM Transformer 并 `retransformClasses` 目标 Filter 类（Spring `DelegatingFilterProxy.doFilter` 或 Shiro `AbstractShiroFilter.doFilterInternal`）。
4. 发送带 `Signature: bl4ckH0le` 的请求验证：命令执行、文件读取、冰蝎或 reGeorg 代理。
5. 清理：detach、删除 agent jar；内存马随重启消失，需重新注入。

## PoC

MANIFEST 关键项：

```text
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Agent-Class: plugins.tomcat.TomcatAgent
Premain-Class: plugins.tomcat.TomcatAgent
Main-Class: plugins.tomcat.TomcatAgent
```

ASM 注入骨架（在目标方法 `visitCode` 插入静态调用，true 则提前返回）：

```java
mv.visitVarInsn(ALOAD, 1);
mv.visitVarInsn(ALOAD, 2);
mv.visitMethodInsn(INVOKESTATIC, "com/jk/HookFun", "beforeMethod",
        "(Ljava/lang/Object;Ljava/lang/Object;)I");
Label l0 = new Label();
mv.visitJumpInsn(IFEQ, l0);
mv.visitInsn(RETURN);
mv.visitLabel(l0);
mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
super.visitCode();
```

Attach：

```bash
"%JAVA_HOME%/bin/java" -cp "%JAVA_HOME%/lib/tools.jar";memAgent.jar plugins.tomcat.TomcatAgent
# 或代码：VirtualMachine.attach(vmd).loadAgent(agentFile, agentArgs); vm.detach();
```

## 变体与关联

- **变体（目标方法）**：Tomcat `ApplicationFilterChain.doFilter`、Spring `DelegatingFilterProxy.doFilter`、Shiro `AbstractShiroFilter.doFilterInternal`、Servlet `service`、Valve/Listener 等。
- **变体（注入方式）**：反序列化链触发 Attach、命令执行后 attach、JVMTI agent、memfd 无文件加载。
- **变体（后门能力）**：命令执行、文件管理、冰蝎/哥斯拉协议、reGeorg 代理、DNS/HTTP 隧道。
- **关联**：[[web-java-classloader-deser-attach-agent-filterchain-memshell]]（Attach Agent 改写 ApplicationFilterChain.doFilter）、[[web-java-classloader-agentmain-filterchain-dynamic-servletregistration]]（agentmain + 动态 Servlet 注册）、[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]（JVMTI Agent 改写 HttpServlet.service）、[[web-java-classloader-asm-retransform-auth-bypass]]（ASM retransform 热替换方法体）。
- **边界**：JVM 禁用 Attach、目标类不可 retransform、无 tools.jar、不同容器类加载器无法加载 HookFun、或 Filter 类未加载时，需换目标方法/注入方式；字节码 frame 处理错误会导致 `VerifyError`。

## 检测与防御

- **检测**：监控 `VirtualMachine.attach`/`loadAgent`/`retransformClasses` 行为；`jcmd VM.class_hierarchy`、Arthas `jad`/`retransform` 检查 Filter 类是否被改；对比 Filter 类字节码与磁盘基线；发现异常 `Signature` 请求头与 Filter 层命令执行。
- **防御**：`-XX:+DisableAttachMechanism`；限制同用户 shell 与 tools.jar；启用 RASP 对 Instrumentation/ASM 类加载监控；容器与业务最小权限；定期重启与镜像校验。
- **加固**：Filter 类关键方法做完整性校验；禁止运行期 retransform 敏感类；限制出站与代理端口。
