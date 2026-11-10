---
id: defense-detection-shell-analyzer-agent-attach-java-memshell-locate-remove
title: Shell-Analyzer（Agent attach + GUI）定位并删除冰蝎 Servlet 内存马：特征排查 + 反编译 + 一键移除
type: scenario
domain: defense
path: defense/detection
technique: shell-analyzer-agent-attach-gui-memshell-locate-remove-icu
tags:
- java
- tomcat
- memshell
- incident-response
- java-agent
- attach-api
- shell-analyzer
- behinder
- detection
- forensics
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:48:42+08:00'
  notes: 已对照原文核对：Shell-Analyzer 走 Java Agent attach（remote-0.1.jar 的 com.n1ar4.RemoteLoader <PID> <密钥>）+ gui-0.1.jar 客户端、10032 端口、同用户同 JDK 版本要求（sudo -u www /usr/bin/jdk1.8.0_101）、冰蝎改写 HttpServlet#service 的 /memshell 路由 + base64 内嵌 class + defineClass + Decrypt 密钥 e45e329feb5d925b 均与正文一致；原文只提实验环境 JDK1.8、无受影响版本区间，故未设 affected_versions；本次核对未读取图片，仅依据正文。未验证点：工具链未在本机执行
url: /docs/defense/detection/defense-detection-shell-analyzer-agent-attach-java-memshell-locate-remove/
draft: false
kb_aliases:
- Shell-Analyzer 查杀内存马
- shell-analyzer remote-0.1.jar
- gui-0.1.jar 内存马
- Java Agent 查杀内存马
- 冰蝎 Servlet 内存马定位
- /memshell 路由内存马
- 内存马流量特征
---

## 一句话结论

Java 内存马不落盘、重启才消失，静态扫目录扫不到；用 Shell-Analyzer 这套 Java Agent 工具（服务端 `remote-0.1.jar` 通过 Attach API 挂到目标 JVM，客户端 `gui-0.1.jar` 连过去）遍历 JVM 已加载的全部 Class、按预置规则匹配可疑类，可一键反编译看清 `service`/`doFilter` 里的 `defineClass`+`Decrypt` 链并直接删除该类，从而在不重启业务的情况下摘掉内存马；配套的流量特征（不存在的路由却能执行）与代码特征（硬编码 AES 密钥、自定义 ClassLoader、`Runtime.exec`）是定位入口。

## 原理

- **为什么必须看运行时**：Filter/Servlet/Listener/Valve 型内存马都是运行期通过反射把组件注册进 `StandardContext`，或者用 `Instrumentation` 改写已加载类的字节码；磁盘上没有任何对应文件，类加载器也常常是临时 `defineClass` 出来的，所以「扫 Web 目录/比对 JAR」天然失效。
- **Shell-Analyzer 的工作方式**：服务端 jar 以 Java Agent 方式 attach 到目标 JVM（内嵌 attach 逻辑 + 远程加载器 `com.n1ar4.RemoteLoader`），获得 `Instrumentation` 后可枚举 `getAllLoadedClasses()`；客户端通过 TCP（默认 10032 端口）拉取类列表与字节码，在本地按规则匹配、反编译、展示，并下发删除指令。
- **规则匹配而非人工翻**：规则通常覆盖「类名含 shell/cmd/hack、实现 `javax.servlet.Filter`/`Servlet`/`ServletRequestListener`、继承 `HttpServlet` 但无对应 code source、调用 `Runtime.exec`/`ProcessBuilder`、`ClassLoader.defineClass`、`javax.crypto`」等组合，先缩小到个位数候选，再由人确认。
- **典型冰蝎 Servlet 马的形态**：改写（或新增）一个 `HttpServlet` 子类，`service` 里判断 `requestURI.matches("/memshell")`，命中后把请求体读出，先用硬编码 AES 密钥 `e45e329feb5d925b`（AES/ECB/PKCS5Padding）解密，再 `defineClass` 加载解密出的字节码并 `newInstance().equals(hashMap)` 执行——因此反编译时会看到一个超长的 base64 常量（内嵌的 class 字节码），这正是冰蝎「二次加载」的特征。
- **删除的内存语义**：Agent 侧删除的本质是把该组件从容器结构中摘除（或还原被改写的类字节码），使后续请求不再命中；进程不重启则其它无关类不受影响。因为内存马可能同时存在多个（Filter + Valve + Agent transformer），删除后必须复测原连接是否失败、并检查是否还有其它入口。
- **前提条件**：能与目标 JVM 同用户（或 root）执行 java 命令以 attach；目标 JDK 有 `tools.jar`（JDK 8）或开启 attach 机制（`-XX:+DisableAttachMechanism` 未启用）；服务端与客户端版本、Java 版本匹配，防火墙放行客户端连接端口。

## 触发条件

- 疑似 Java 内存马：出现「请求一个不存在的路径却返回执行结果」、正常路径的 POST 携带命令且被成功执行、响应体大小随命令输出动态变化、固定异常 UA/Referer、响应时间抖动等流量特征。
- 能在目标主机上以与 Tomcat 相同用户执行命令（`sudo -u www ...`），并可读取 JDK 目录（`tools.jar`）。
- 目标 JVM 未禁用 attach；或虽禁用但可用 heap dump / sa-jdi 等替代路线。
- 需要保留业务不重启（生产环境），否则直接重启也能临时清除。

## 利用步骤

1. 先按流量特征圈定范围：抓包里 `GET /memshell?cmd=...` 这类路径不存在却返回 200/执行结果的请求、POST 正常路径但响应长度随命令变化的请求；结合 Tomcat 访问日志确认时间线。
2. 代码特征初筛（有源码/备份时）：搜 `password`/`key`/`token` 常量、`@WebServlet`/`@RequestMapping` 等自定义路由、`javax.crypto`+`Base64`、`Runtime.getRuntime().exec`/`ProcessBuilder`、`ClassLoader.defineClass`/`Class.forName`、以及伪装成 `util`/`shell` 的类名。
3. 取进程 PID：`ps -aux | grep java`（或 `jps -l`），记下 Tomcat 的 Java 进程。
4. 启动远程服务端（版本与权限必须与 Tomcat 一致）：`sudo -u www <jdk>/bin/java -cp <jdk>/lib/tools.jar:./remote-0.1.jar com.n1ar4.RemoteLoader <PID> <密钥>`。
5. 本地启动客户端 `java -jar gui-0.1.jar`，填入服务器 IP 与同一密钥（放行 10032 端口），刷新类列表。
6. 在 GUI 中按规则筛出的可疑类里定位：本例命中被改写的 `javax/servlet/http/HttpServlet` 的 `service` 方法，反编译可见 `"/memshell"` 路由判断、`ClassLoader.defineClass(ByteBuffer)` 与 `Decrypt` 调用、硬编码 AES 密钥。
7. 确认后执行删除（工具内一键移除），再刷新列表确认该类/组件消失。
8. 复测：用原 webshell 客户端重连应失败；同时检查是否还有 Valve/Listener/Agent transformer 等其它类型残留，最后修复入口（上传点/反序列化/弱口令）并重启一次做彻底清理。

## PoC

```bash
# 1) 定位 Tomcat Java 进程
ps -aux | grep java

# 2) 服务端：以与 Tomcat 相同用户、相同 JDK 版本 attach
sudo -u www /usr/bin/jdk1.8.0_101/bin/java \
  -cp /usr/bin/jdk1.8.0_101/lib/tools.jar:./remote-0.1.jar \
  com.n1ar4.RemoteLoader <PID> <密钥>

# 3) 客户端
java -jar gui-0.1.jar
# 填入服务器 IP + 密钥，放行 10032 端口，刷新后查看可疑类
```

```text
反编译典型特征（冰蝎 Servlet 马，改写 HttpServlet#service）：
  String var6 = "/memshell";
  if (request.getRequestURI().matches(var6)) { ... }
  ClassLoader var8 = this.getClass().getClassLoader();
  String var9 = "yv66vgAAADIAXAoACwAp..."   // 内嵌 class 的 base64
  ... ClassLoader.defineClass(...) ... Decrypt(...) ... newInstance().equals(var7)

Decrypt 中的密钥：e45e329feb5d925b（AES/ECB/PKCS5Padding，Base64 解码后 doFinal）
```

## 变体与关联

- 变体（工具）：`java-memshell-scanner.jsp` 只能枚举 Tomcat 的 Filter/Servlet/Listener（看不到 Agent 改写型），轻量但覆盖窄；Arthas 的 `sc`/`jad` 可人工排查；sa-jdi `ClassDump` 从 JVM 元数据 dump 真实字节码，不受 transformer 缓存影响。三者与 Shell-Analyzer 互补。
- 变体（attach 不可用）：目标禁用 attach 或权限不足时，改走 heap dump 离线分析、sa-jdi、或直接重启+根因修复。
- 变体（其它类型）：Valve 型不在 Filter/Servlet 表里，需要看 `StandardContext` 的 Pipeline；Agent transformer 型要查 `sun.instrument.InstrumentationImpl` 的 transformer 列表；Executor/Upgrade/WebSocket 型各有自己的容器结构。
- 关联：[[defense-detection-tomcat-memshell-scanner-arthas]]（JSP 枚举 + Arthas + Copagent 的静态/attach 组合，本卡补充 Agent attach + GUI 的 Shell-Analyzer 路线上线操作与冰蝎 Servlet 马的反编译特征）、[[defense-detection-arthas-agent-memshell-detect-remove]]（Agent transformer 型内存马的 transformer 列表定位与 `retransform` 还原）、[[defense-detection-sajdi-classdump-memshell-bytecode]]（sa-jdi 直接 dump 真实字节码）、[[defense-forensics-behinder-jsp-static-key-password-extraction]]（冰蝎密钥与流量的取证侧）。
- 边界：Attach 需要同用户/同权限，`sudo -u www` 用错用户会 attach 失败；JDK 版本不一致（如用 JDK 11 的 java 去 attach JDK 8 进程）常导致失败；工具本身会在目标机留下 jar 与 attach 痕迹（`.attach_pid`/`.java_pid`），排查结束需清理。

## 检测与防御

- 检测（流量）：不存在的路径被访问却返回执行结果、POST 正常路径但响应长度随命令变化、固定 UA/Referer、响应时间抖动；同一来源在极短时间内探测 `/shell`、`/cmd`、`/memshell`、`/test` 等路径。
- 检测（代码/运行时）：无磁盘 class 文件的 Servlet/Filter/Listener；`JasperLoader` 加载的 `*$1` 匿名类；`defineClass` 后立即 `newInstance`；硬编码 16 位 AES 密钥 + Base64 常量；`Runtime.exec`/`ProcessBuilder` 出现在组件类中。
- 防御：最小化 JSP 与动态注册能力、Web 目录只读；用 RASP/Java Agent 监控 `StandardContext.addChild`/`addFilterDef`/`addApplicationEventListener` 与 `Instrumentation.retransformClasses` 调用；限制 attach 能力（`-XX:+DisableAttachMechanism`、隔离 JVM 用户与文件权限）；修复上传/反序列化/弱口令等入口，内存马只是结果不是根因。
- 处置纪律：删除内存马后必须复测原连接、排查其它类型残留、清理排查工具痕迹，并安排一次重启；只删不修根因会被重新植入。
