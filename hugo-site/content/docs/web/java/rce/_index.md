---
title: Java 命令执行与反弹 Shell
weight: 1
---

# Java 命令执行与反弹 Shell

## 这层是什么

Java 拿到 RCE 后的命令执行与交互式通道：`Runtime.exec`/`ProcessBuilder`、反射进程创建、Windows/Linux 反弹 Shell 与载荷构造。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Java FFM API mmap RWX 内存加载 Shellcode：JVM 进程内无子进程执行机器码](web-java-rce-ffm-mmap-shellcode-inprocess/) | verified | high | 2026-11-05 |
| [Java FFM API 直调 libc system/fork+execve：绕过 Runtime/ProcessBuilder 的 RASP 命令执行拦截](web-java-rce-ffm-native-system-rasp-bypass/) | verified | high | 2026-11-05 |
| [Java Socket 双向流泵反弹 Shell（Windows/Linux 通用）](web-java-rce-socket-revshell-stream-pump/) | verified | high | 2026-11-05 |
| [Java 命令队列满触发异常兜底：ArrayBlockingQueue.add 抛错进入无校验 handleError，绕过命令白名单 RCE](web-java-rce-command-queue-full-exception-allowlist-bypass/) | verified | high | 2026-11-07 |
| [JSP pageEncoding/contentType 指定非 UTF-8 编码绕过静态 webshell 检测](web-java-rce-jsp-pageencoding-static-detection-bypass/) | verified | medium | 2026-11-05 |
| [JSP scriptlet 特殊闭合逃逸生成 Java 的 try/catch 结构绕过检测](web-java-rce-jsp-scriptlet-special-closure-bypass/) | verified | high | 2026-11-05 |
| [JSP trimDirectiveWhitespaces 拼接 scriptlet 片段绕过 webshell 检测](web-java-rce-jsp-trim-whitespace-fragment-bypass/) | verified | high | 2026-11-05 |
| [Nashorn ScriptEngine 黑名单绕过：Java.type 直接引用 java.nio.file.Files 读文件](web-java-rce-nashorn-java-type-blacklist-file-read/) | verified | high | 2026-11-06 |
| [Nashorn 引擎 + Base64 JS + BCEL ClassLoader 的 JSP Webshell 静态免杀](web-java-rce-nashorn-bcel-jsp-webshell-av-bypass/) | verified | medium | 2026-11-05 |
| [OA BeanShell Interpreter.eval 代码执行（script_run.jsp / 调度任务 JobDataMap）](web-java-rce-oa-beanshell-interpreter-eval/) | verified | medium | 2026-11-05 |
| [OpenSSL s_client + FIFO 加密反弹 Shell：-keylogfile 留痕可还原 TLS 命令](web-java-rce-openssl-s-client-keylogfile-encrypted-revshell/) | verified | high | 2026-11-07 |
| [RASP 命令执行拦截的线程上下文绕过：从 HTTP 线程 fork 新线程执行命令](web-java-rce-rasp-http-thread-context-new-thread-bypass/) | verified | high | 2026-11-06 |
| [Runtime.exec(String) 分词限制与 bash $@|bash 单字符串反弹 Shell](web-java-rce-runtime-exec-string-tokenizer-bash-revshell/) | verified | high | 2026-11-05 |
| [RuoYi 定时任务调用目标字符串反射 RCE：JobInvokeUtil 任意类方法调用 + SnakeYAML 链与协议黑名单单引号绕过](web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml/) | verified | high | 2026-11-07 |
| [Spring MVC actionNetworkCmd 将 ip/time 拼入 sh -c：分号截断的 ping/iperf 命令注入](web-java-rce-spring-actionnetworkcmd-ip-time-sh-c/) | verified | high | 2026-11-05 |
| [反射调用 ProcessImpl 构造器直接创建进程执行命令](web-java-rce-processimpl-constructor-reflect-exec/) | verified | medium | 2026-11-05 |
| [定时任务 invokeTarget 反射调用 + 白名单尾部截断绕过：上传 .so 后 System.load 加载执行](web-java-rce-job-invoketarget-whitelist-suffix-system-load-so/) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
