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
| [ELF __attribute__((constructor))：Linux .so 被 dlopen 时经 .init_array 自动执行](web-java-rce-elf-constructor-load-time-exec/) | verified | high | 2026-11-08 |
| [Flowable ScriptExecutionListener：class 监听器填 script + language=js，流程启动时交给 JSR-223 脚本引擎执行命令](web-java-rce-flowable-script-execution-listener/) | verified | high | 2026-11-09 |
| [Java FFM API mmap RWX 内存加载 Shellcode：JVM 进程内无子进程执行机器码](web-java-rce-ffm-mmap-shellcode-inprocess/) | verified | high | 2026-11-05 |
| [Java FFM API 直调 libc system/fork+execve：绕过 Runtime/ProcessBuilder 的 RASP 命令执行拦截](web-java-rce-ffm-native-system-rasp-bypass/) | verified | high | 2026-11-05 |
| [Java Socket 双向流泵反弹 Shell（Windows/Linux 通用）](web-java-rce-socket-revshell-stream-pump/) | verified | high | 2026-11-05 |
| [Java 命令队列满触发异常兜底：ArrayBlockingQueue.add 抛错进入无校验 handleError，绕过命令白名单 RCE](web-java-rce-command-queue-full-exception-allowlist-bypass/) | verified | high | 2026-11-07 |
| [JNI_OnLoad 导出符号：JVM 加载原生库时主动调用，无需任何 Java_ 方法即执行](web-java-rce-jni-onload-export-load-time-exec/) | verified | high | 2026-11-08 |
| [JSP pageEncoding/contentType 指定非 UTF-8 编码绕过静态 webshell 检测](web-java-rce-jsp-pageencoding-static-detection-bypass/) | verified | medium | 2026-11-05 |
| [JSP scriptlet 特殊闭合逃逸生成 Java 的 try/catch 结构绕过检测](web-java-rce-jsp-scriptlet-special-closure-bypass/) | verified | high | 2026-11-05 |
| [JSP trimDirectiveWhitespaces 拼接 scriptlet 片段绕过 webshell 检测](web-java-rce-jsp-trim-whitespace-fragment-bypass/) | verified | high | 2026-11-05 |
| [Mirth Connect 后台通道脚本 JavaScript 命令执行（Postprocessor 回显 + parameters cmd 马）](mirth-connect-channel-script-rce/) | verified | high | 2026-11-08 |
| [Nashorn JEP202 ClassFilter 绕过：受过滤脚本内新建 ScriptEngineManager 再 eval](web-java-rce-nashorn-jep202-classfilter-nested-engine-bypass/) | verified | high | 2026-11-09 |
| [Nashorn ScriptEngine 黑名单绕过：Java.type 直接引用 java.nio.file.Files 读文件](web-java-rce-nashorn-java-type-blacklist-file-read/) | verified | high | 2026-11-06 |
| [Nashorn 引擎 + Base64 JS + BCEL ClassLoader 的 JSP Webshell 静态免杀](web-java-rce-nashorn-bcel-jsp-webshell-av-bypass/) | verified | medium | 2026-11-05 |
| [NginxWebUI reload/check 直接拼接 nginxExe 执行：非 null 请求参数绕过 handlePath 实现 bash -c 反弹](web-java-rce-nginxwebui-reload-check-nginxexe-rce/) | verified | high | 2026-11-10 |
| [NginxWebUI runCmd 白名单自校验绕过：可控 nginxExe/nginxPath + handlePath 漏删 $、()、{} 导致命令执行](web-java-rce-nginxwebui-runcmd-allowlist-selfcheck-bypass/) | verified | high | 2026-11-10 |
| [OA BeanShell Interpreter.eval 代码执行（script_run.jsp / 调度任务 JobDataMap）](web-java-rce-oa-beanshell-interpreter-eval/) | verified | medium | 2026-11-05 |
| [OpenSSL s_client + FIFO 加密反弹 Shell：-keylogfile 留痕可还原 TLS 命令](web-java-rce-openssl-s-client-keylogfile-encrypted-revshell/) | verified | high | 2026-11-07 |
| [RASP 命令执行拦截的线程上下文绕过：从 HTTP 线程 fork 新线程执行命令](web-java-rce-rasp-http-thread-context-new-thread-bypass/) | verified | high | 2026-11-06 |
| [Runtime.exec(String) 分词限制与 bash $@|bash 单字符串反弹 Shell](web-java-rce-runtime-exec-string-tokenizer-bash-revshell/) | verified | high | 2026-11-05 |
| [RuoYi 4.7.8 计划任务白名单绕过：GenTableServiceImpl.createTable 的 MyBatis ${} SQL 注入改写 sys_job.invoke_target 后触发 RCE](web-java-rce-ruoyi-478-createtable-sqli-job-invoketarget-bypass/) | verified | medium | 2026-11-09 |
| [RuoYi 定时任务调用目标字符串反射 RCE：JobInvokeUtil 任意类方法调用 + SnakeYAML 链与协议黑名单单引号绕过](web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml/) | verified | high | 2026-11-07 |
| [Spring MVC actionNetworkCmd 将 ip/time 拼入 sh -c：分号截断的 ping/iperf 命令注入](web-java-rce-spring-actionnetworkcmd-ip-time-sh-c/) | verified | high | 2026-11-05 |
| [Spring 控制器把请求里的 ScriptContent 拼进 agscript 参数并交给 python 转发：Aggressor 脚本注入 → 任意文件写入（openf/writeb 覆盖配置 → 二次 JDBC 反序列化）](web-java-rce-connect-controller-agscript-script-content-injection-file-write/) | verified | medium | 2026-11-09 |
| [Windows DllMain 的 DLL_PROCESS_ATTACH：LoadLibrary 加载 dll 时即执行载荷](web-java-rce-windows-dllmain-load-time-exec/) | verified | high | 2026-11-08 |
| [反射调用 ClassLoader#loadLibrary / ClassLoader$NativeLibrary#load 加载本地 DLL/SO：绕开 Runtime/System 的 RASP、EDR 与查杀 hook，配合写文件能力完成落地执行](web-java-rce-reflect-classloader-nativelibrary-load-dll-bypass-hooks/) | verified | medium | 2026-11-09 |
| [反射调用 ProcessImpl 构造器直接创建进程执行命令](web-java-rce-processimpl-constructor-reflect-exec/) | verified | medium | 2026-11-05 |
| [命令执行被 RASP/杀软拦截时改调 BeanShell Interpreter.eval：以 String[] 预热 method_map 消除 String/Reader 重载歧义](web-java-rce-beanshell-eval-method-map-preheat/) | verified | medium | 2026-11-09 |
| [哥斯拉 JSP 马改模板返回伪 404 页 + 客户端 findStr 换自定义前后缀，抹掉 md5(pass+key) 前后 16 位的标准流量指纹](web-java-rce-godzilla-jsp-404-fake-response-findstr-custom-marker/) | verified | high | 2026-11-09 |
| [哥斯拉上帝模式生成 JSP 马：globalCode/code 全部 stringToUnicode 转义后再嵌入模板，静态关键字扫描难匹配](web-java-rce-jsp-godzilla-godmode-unicode-escape-static-bypass/) | verified | medium | 2026-11-09 |
| [定时任务 invokeTarget 反射调用 + 白名单尾部截断绕过：上传 .so 后 System.load 加载执行](web-java-rce-job-invoketarget-whitelist-suffix-system-load-so/) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
