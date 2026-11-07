---
id: defense-detection-tomcat-upgrade-executor-memshell-arthas-vmtool-remove
title: Arthas vmtool 查杀 Tomcat Upgrade/Executor 内存马：httpUpgradeProtocols 移除与恶意线程池安全替换
type: scenario
domain: defense
path: defense/detection
technique: arthas-vmtool-tomcat-upgrade-executor-memshell-remove
tags:
- java
- tomcat
- memshell
- arthas
- vmtool
- upgrade
- executor
- threadpool
- incident-response
- detection
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/defense/detection/defense-detection-tomcat-upgrade-executor-memshell-arthas-vmtool-remove/
draft: false
kb_aliases:
- Arthas 杀 Upgrade 内存马
- Arthas 杀 Executor 内存马
- httpUpgradeProtocols remove
- NioEndpoint setExecutor
- ThreadPoolExecutor 替换
- vmtool 内存马查杀
---

## 一句话结论

对 Tomcat 的 Upgrade 内存马，可用 `vmtool` 读取 `AbstractHttp11Protocol.httpUpgradeProtocols` 并 `remove` 恶意协议键，但必须同时找到并删除负责触发升级的 Servlet/JSP/Filter，否则治标不治本；对 Executor 内存马，不能直接删除恶意线程池（会导致服务不可用），需用同参数新建一个 `ThreadPoolExecutor` 并通过 `NioEndpoint.setExecutor` 替换。

## 原理

- **Upgrade 内存马**：注入侧通过反射取 `AbstractHttp11Protocol.httpUpgradeProtocols`（`HashMap<String, UpgradeProtocol>`），`put("hello", EvilUpgrade)` 注册自定义协议；请求带 `Connection: Upgrade` + `Upgrade: hello` + 自定义命令头时，Tomcat 在 Connector 层调用 `UpgradeProtocol.accept` 执行命令。用 `vmtool` 读该 map 可看到 `hello -> MyUpgrade`，`remove("hello")` 即可让后续升级请求不再命中；但恶意 `accept` 需要一个触发点（恶意 Servlet、JSP 或 Filter）把请求引导到升级流程/重新注册协议，只删 map 不删触发点会被再次注入。
- **Executor 内存马**：注入侧用恶意 `ThreadPoolExecutor` 子类替换 `NioEndpoint.executor`；该线程池在 `SocketProcessor` 执行前读取原始请求字节并执行命令，因此对所有 Context/路径生效。`vmtool` 读 `instances[i].executor` 会显示恶意的 `EvilExecutor`。直接删除/关闭该 executor 会中断 Tomcat 的请求处理线程池，导致服务不可用或崩溃，所以必须“替换”而不是“删除”。
- **替换方法**：用 `ThreadPoolExecutor` 的 7 参数构造函数，按恶意 executor 当前的 `corePoolSize`、`maximumPoolSize`、`keepAliveTime`、`TimeUnit`、`workQueue`、`threadFactory`、`rejectedExecutionHandler` 新建一个正常的 `ThreadPoolExecutor`，再调用 `NioEndpoint.setExecutor(newExecutor)`。Arthas 的 OGNL 没有 `new` 关键字，需要用 `@java.util.concurrent.ThreadPoolExecutor@class.getConstructor(...)` 拿构造函数再 `newInstance(...)`。
- **为什么可行**：内存马的本质是运行时对象引用；把连接器的 `executor` 指回一个正常线程池，恶意 `execute` 逻辑就不再被调用，而线程池参数与原配置一致，业务请求继续正常处理。
- **失败尝试**：文章尝试直接删除/重编译恶意类并 `retransform`，因类结构变化报 `UnsupportedOperationException: class redefinition failed: attempted to change the schema (add/remove fields)`；说明这类处置应改对象引用，而不是改类字节。

## 触发条件

- 已获得目标 JVM 的 attach 权限，可启动 Arthas 并 attach 到 Tomcat 进程。
- 目标为 Tomcat NIO（`NioEndpoint`）环境；NIO2/APR 的 endpoint 类名与字段不同，需相应调整。
- Upgrade 内存马已在 `httpUpgradeProtocols` 中注册；Executor 内存马已替换 `NioEndpoint.executor`。
- 处置前确认恶意协议名/恶意 executor 实例，避免误删业务 Upgrade 协议或破坏正常线程池。

## 利用步骤

1. attach Arthas，选择目标 Tomcat PID。
2. **Upgrade 查**：确认 `AbstractHttp11Protocol` 实例与 `httpUpgradeProtocols`：
   ```bash
   sc org.apache.coyote.http11.AbstractHttp11Protocol
   vmtool --action getInstances --className org.apache.coyote.http11.AbstractHttp11Protocol --express 'instances[0].httpUpgradeProtocols'
   ```
   看到 `hello -> MyUpgrade` 一类恶意键值；执行移除：
   ```bash
   vmtool --action getInstances --className org.apache.coyote.http11.AbstractHttp11Protocol --express 'instances[0].httpUpgradeProtocols.remove("hello")'
   ```
   再查一次 map 确认已空；同时定位并删除触发升级的恶意 Servlet/JSP/Filter（例如注册 `injectUpgrade` 的组件），否则攻击者可重新注册。
3. **Executor 查**：确认 `NioEndpoint` 实例与 executor：
   ```bash
   vmtool --action getInstances --className org.apache.tomcat.util.net.NioEndpoint --express 'instances[i].executor'
   ```
   返回 `EvilExecutor` 即中招；用同参数构造新线程池并替换（需删除换行后执行）：
   ```bash
   vmtool --action getInstances --className org.apache.tomcat.util.net.NioEndpoint --express '
   #nio=instances[i],
   #exe=instances[i].executor,
   #constructor=@java.util.concurrent.ThreadPoolExecutor@class.getConstructor(@int@class,@int@class,@long@class,@java.util.concurrent.TimeUnit@class,@java.util.concurrent.BlockingQueue@class,@java.util.concurrent.ThreadFactory@class,@java.util.concurrent.RejectedExecutionHandler@class),
   #newexe=#constructor.newInstance(#exe.getCorePoolSize(),#exe.getMaximumPoolSize(),#exe.getKeepAliveTime(@java.util.concurrent.TimeUnit@MILLISECONDS),@java.util.concurrent.TimeUnit@MILLISECONDS,#exe.getQueue(),#exe.getThreadFactory(),#exe.getRejectedExecutionHandler()),
   #nio.setExecutor(#newexe)
   '
   ```
4. 验证：再查 `instances[i].executor` 应为普通 `ThreadPoolExecutor`；访问任意路径/恶意触发头不再执行命令（案例返回 404），业务请求仍正常。
5. 清理攻击入口并复查，防止重新注入。

## PoC

```bash
# Upgrade：查与删
vmtool --action getInstances --className org.apache.coyote.http11.AbstractHttp11Protocol --express 'instances[0].httpUpgradeProtocols'
vmtool --action getInstances --className org.apache.coyote.http11.AbstractHttp11Protocol --express 'instances[0].httpUpgradeProtocols.remove("hello")'

# Executor：查
vmtool --action getInstances --className org.apache.tomcat.util.net.NioEndpoint --express 'instances[1].executor'

# Executor：同参数新建并替换（实际执行时删掉换行）
vmtool --action getInstances --className org.apache.tomcat.util.net.NioEndpoint --express '#nio=instances[1],#exe=instances[1].executor,#constructor=@java.util.concurrent.ThreadPoolExecutor@class.getConstructor(@int@class,@int@class,@long@class,@java.util.concurrent.TimeUnit@class,@java.util.concurrent.BlockingQueue@class,@java.util.concurrent.ThreadFactory@class,@java.util.concurrent.RejectedExecutionHandler@class),#newexe=#constructor.newInstance(#exe.getCorePoolSize(),#exe.getMaximumPoolSize(),#exe.getKeepAliveTime(@java.util.concurrent.TimeUnit@MILLISECONDS),@java.util.concurrent.TimeUnit@MILLISECONDS,#exe.getQueue(),#exe.getThreadFactory(),#exe.getRejectedExecutionHandler()),#nio.setExecutor(#newexe)'
```

验证：`httpUpgradeProtocols` 中恶意键消失；`executor` 不再为 `EvilExecutor`；原恶意触发请求不再执行命令，业务仍可用。

## 变体与关联

- Upgrade 触发点可能是 Servlet、JSP、Filter 或反序列化入口；只删 `httpUpgradeProtocols` 不删触发点，攻击者可再次注册。
- Executor 类型随 Connector 不同：NIO 用 `NioEndpoint`，NIO2 用 `Nio2Endpoint`，APR 用 `AprEndpoint`；字段名也可能是 `executor`，替换前先用 `sc -d`/`vmtool` 确认。
- 其他基础组件移除：Servlet/Listener/Valve 见 `defense-detection-tomcat-servlet-listener-valve-memshell-arthas-vmtool-remove`；Filter 见 `defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove`。
- 检测与枚举：`sc`/`jad`/`sc -d` 与 java-memshell-scanner 见 `defense-detection-tomcat-memshell-scanner-arthas`。
- 类删除/重编译不可行（schema 变化导致 retransform 失败），应优先对象替换。

## 检测与防御

- 监控 `AbstractHttp11Protocol.httpUpgradeProtocols.put` 与 `AbstractEndpoint.setExecutor` 的异常调用（RASP/Java Agent 记录调用栈）。
- 排查 `httpUpgradeProtocols` 中陌生协议名、`NioEndpoint.executor` 非标准 `ThreadPoolExecutor` 类型；结合 `sc -d` 查看类来源与 `code-source`。
- Web 侧最小化 JSP/动态注册能力，修复上传/反序列化/表达式注入入口；处置后删除触发点，防止重新注入。
- 保留 Arthas 等应急工具的受控访问权限；对生产线程池替换先在测试环境验证参数与业务影响。
