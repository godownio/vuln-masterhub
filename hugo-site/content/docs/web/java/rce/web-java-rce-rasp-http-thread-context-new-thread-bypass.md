---
id: web-java-rce-rasp-http-thread-context-new-thread-bypass
title: RASP 命令执行拦截的线程上下文绕过：从 HTTP 线程 fork 新线程执行命令
type: scenario
domain: web
path: web/java/rce
technique: rasp-http-thread-context-new-thread-bypass
tags:
- java
- rasp
- bypass
- thread
- command-execution
- defense-evasion
- memshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:46:51+08:00'
  notes: '已对照原文与 19-22、15 图核对：HTTP_THREAD_PATTERNS/WEB_CONTEXT_FRAMES、shouldBlock 仅按线程名与栈帧判定、NativeMethodPrefix 包装 forkAndExec、CmdRunner extends Thread 在内存马中 start 后执行 /getflag、直接 ping 注入返回 X-Protected-By: OpenRASP 均与原文一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。'
url: /docs/web/java/rce/web-java-rce-rasp-http-thread-context-new-thread-bypass/
draft: false
kb_aliases:
- RASP 新线程绕过
- 请求线程绕过
- 线程上下文绕过
- CmdRunner extends Thread
- shouldBlock 线程名检测
- RASP thread bypass
---

## 一句话结论

RASP 只在“当前线程是 HTTP 请求线程或调用栈含 Web 框架帧”时拦截 `Runtime.exec`/`ProcessBuilder.start`；攻击者在内存马或反序列化链里 `new Thread(...).start()`，让命令在普通工作线程执行，线程名与调用栈都不含 HTTP 标识，`shouldBlock()` 返回 false，命令执行即被放行。

## 原理

- **RASP 依赖上下文判断**：示例 `RaspChecker.shouldBlock()` 先看 `Thread.currentThread().getName()` 是否匹配 `http-nio-`、`catalina-exec-`、`qtp`、`XNIO-` 等 HTTP 线程模式；不匹配再看调用栈是否含 `javax.servlet.`、`org.apache.catalina.`、`org.springframework.web.` 等 Web 框架帧。只有命中 HTTP 上下文才拦截。
- **新线程丢失上下文**：`Thread.start()` 创建的新线程默认继承线程组但不继承调用栈；线程名是 `Thread-N`，栈顶是 `Thread.run` 和目标 `run()`，不含 Servlet/Spring 帧，因此不被判定为 HTTP 请求。
- **RASP hook 点仍在**：`Runtime.exec`、`ProcessBuilder.start`、`ProcessImpl` 等仍被 hook，但 `shouldBlock()` 因上下文不匹配而放行；拦截逻辑本身没有失效，失效的是“请求来源判定”。
- **为什么最终危害成立**：命令执行发生在 JVM 进程内、由同一用户权限运行，可读写文件、外联、读取 flag；RASP 只记录/拦截 HTTP 上下文中的执行，非 HTTP 线程被视为内部调用。
- **常见触发载体**：反序列化注入的内存马（Interceptor/Filter/Listener）、WebShell、表达式注入；只要能在请求处理链中启动一个新线程并调用命令执行即可。

## 触发条件

- 目标部署了基于线程名/调用栈判断请求上下文的 RASP（示例 OpenRASP 风格 `shouldBlock`）。
- 攻击者已获得 Java 代码执行/反序列化/内存马注入能力。
- RASP 未对 `Thread.start`/`Executor` 做上下文传播，也未 hook `ProcessImpl.forkAndExec` 的 native wrapper 并强制检查。
- 命令在新线程中执行，且该线程不被 RASP 标记为请求线程。

## 利用步骤

1. 确认 RASP 拦截行为：在 HTTP 请求中直接执行命令，观察是否返回 RASP 拦截页（示例 `X-Protected-By: OpenRASP`）。
2. 注入一个能启动新线程的内存马/反序列化链；线程类在 `run()` 中调用 `Runtime.getRuntime().exec(cmd)` 并读取输出。
3. 在 HTTP 请求处理链中调用 `runner.start()`，让命令在 `Thread-N` 中执行。
4. 通过内存马把输出写回响应/文件，或写临时文件后读取；示例用 download 模式取回结果。
5. 若 RASP 还检查文件操作，改用文件写入/下载等未被拦截的 sink；示例 RASP 只拦命令执行，文件读写可用。
6. 若新线程仍被拦，尝试线程池、定时任务、`ForkJoinPool`、`CompletableFuture` 等不同线程来源，确认上下文判定边界。

## PoC

```java
public class CmdRunner extends Thread {
    private final String[] cmd;
    private String output = "";
    public CmdRunner(String[] cmd) { this.cmd = cmd; }

    @Override
    public void run() {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            // 读取 stdout/stderr，waitFor 后写入 output
        } catch (Exception e) {
            output = "ERROR: " + e.getMessage();
        }
    }
    public String getOutput() { return output; }
}

// 在 HTTP 处理链（内存马 preHandle / 反序列化回调）中：
CmdRunner runner = new CmdRunner(new String[]{"/bin/bash", "-c", "id"});
runner.start();
runner.join(10000);
response.getWriter().write(runner.getOutput());
```

原文实测：直接 `ping` 注入命令返回 `X-Protected-By: OpenRASP` 拦截页；通过反序列化加载 `CmdRunner` 并在内存马中 `start()` 后，`/getflag` 在新线程执行成功。

## 变体与关联

- **线程来源变体**：`new Thread`、`Executors.newSingleThreadExecutor().submit`、`ScheduledMethodRunnable`、`CompletableFuture`、`ForkJoinPool`、定时任务。
- **RASP 判定变体**：只查线程名、只查栈帧、查线程组、查 `ThreadLocal` 请求上下文；对应可用线程名伪造、栈帧裁剪、线程组隔离等绕过。
- **拦截点变体**：只 hook `Runtime.exec` 未 hook `ProcessBuilder`/`ProcessImpl`；或只拦命令执行、不拦文件操作/网络。
- **关联卡片**：[[web-java-rce-ffm-native-system-rasp-bypass]]（FFM 绕过命令执行 hook）、[[web-java-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（PHP RASP 绕过）、[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]（内存马注入）。
- **边界**：若 RASP 使用 `InheritableThreadLocal` 传播请求上下文，或 hook `Thread.start` 并继承标记，新线程会被识别；若同时 hook native `forkAndExec` 并在 wrapper 中强制检查，绕过失效。

## 检测与防御

- **RASP 设计**：不要只用线程名/栈帧判断请求来源；用 `ThreadLocal`/`InheritableThreadLocal` 在请求入口打标并随线程创建传播；hook `Thread.start`/`Executor` 继承标记；对命令执行 sink 做“调用链 + 线程创建链”双重检查。
- **兜底**：同时 hook `ProcessImpl`/`UNIXProcess` 的 native wrapper，避免只拦 Java 层 API；对 `forkAndExec` 的调用者做白名单。
- **检测信号**：HTTP 请求处理期间出现 `Thread-N` 新线程并调用 `Runtime.exec`；内存马注册的 Interceptor/Filter 中启动线程；`/tmp` 下出现命令输出文件；RASP 日志只有 HTTP 线程拦截记录。
- **响应**：发现新线程命令执行后，排查内存马注册点（`adaptedInterceptors`、FilterChain、Listener）、反序列化入口与 RASP 版本，升级 RASP 规则并重启 JVM。
