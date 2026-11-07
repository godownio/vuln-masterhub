---
id: defense-forensics-java-memshell-heapdump-bytecode
title: Java 内存马 heap dump 取证：cafebabe/yv66 字节码特征与 strings 请求记录
type: scenario
domain: defense
path: defense/forensics
technique: java-memshell-heapdump-forensics
aliases:
- 内存马 dump 分析
- jmap heap dump 内存马
- cafebabe 搜索内存马
- yv66 Base64 字节码
- heap dump strings 请求记录
tags:
- java
- memshell
- forensics
- heapdump
- jmap
- cafebabe
- yv66
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:50:31+08:00'
  notes: 已对照原文与 img/45-58 核对：img/45/51 Arthas heapdump，img/46 cafebabe 共 17 处，img/47/48 5f6a73702431，img/52-55 yv66→CyberChef Base64→JADX 还原 Decrypt 类与 AES 密钥，img/57/58 strings 提取 POST /memshell 与 /webapps/ 路径。PoC 未在本机执行；无版本区间。
---

## 一句话结论

当 Arthas/Copagent 因攻击者防检测无法 attach 时，可用 `jmap -dump` 或 Arthas `heapdump` 导出堆，按 class 文件魔数 `cafebabe`、其 Base64 头 `yv66vg`、JSP 匿名类名 `_jsp$1` 的十六进制 `5f6a73702431` 搜索字节码，再用 CyberChef 还原 class、JADX 反编译，并用 `strings` 提取堆中的 HTTP 请求记录定位访问入口。

## 原理

- JVM 堆中保存已加载类的 Class 对象、类名字符串、字节码数组、请求/响应对象以及日志字符串。内存马无论由 `defineClass`、JSP 匿名类还是 Agent 字节码改写产生，其字节码、类名或 URL 映射都会在堆中以某种形式残留。
- class 文件魔数为 `CA FE BA BE`；Base64 编码后的常见开头是 `yv66vg`（`CAFEBABE` 的 Base64 形式）。攻击者用 Base64 传输/存储字节码时，堆中会留下可搜索的串。
- JSP 编译出的类名包含 `_jsp$1`，对应 ASCII 十六进制 `5f 6a 73 70 24 31`，可在十六进制视图中直接定位匿名内部类。
- Web 容器会把访问日志、请求行、URI、响应状态等字符串留在堆中；`strings` 提取可读字符串后，用 `POST /`、`/webapps/` 等模式可找到内存马连接路径与注入入口。
- 找到的 class 可能是加载器/解密器而非最终载荷：其字节码中会引用 AES 密钥、`Base64`/`Decrypt` 等方法，需要继续跟进字符串与密钥还原下一层载荷。

## 触发条件

- 能获取目标 JVM 的 heap dump：同用户/root 执行 `jmap`、已 attach Arthas 执行 `heapdump`，或通过暴露的 Actuator heapdump 下载；
- dump 包含类元数据/字节码数组（多数 HotSpot dump 满足）；
- 有足够磁盘空间与十六进制/字符串分析工具（WinHex、010 Editor、CyberChef、JADX、strings）。

## 利用步骤

1. `jps` 找到目标 Java 进程 PID；`jmap -dump:format=b,file=heap.hprof <pid>` 导出，或 attach Arthas 后执行 `heapdump`。
2. 用十六进制编辑器搜索 `cafebabe`，记录偏移并提取完整 class 字节；也可搜索明文敏感词 `shell`、`memshell`、`eval`、`inject`、`horse`、`_jsp$1`。
3. 搜索 `yv66` 定位 Base64 编码的 class；复制完整 Base64 串到 CyberChef 执行 “From Base64”，保存为 `.class`。
4. 搜索 `_jsp$1` 的十六进制 `5f6a73702431` 定位 JSP 匿名类；结合类名与 classloader 判断是否为内存马。
5. 用 JADX 反编译还原出的 class，检查 `service`/`doFilter`/`requestInitialized`/`transform` 等入口；若发现 AES 密钥或 `Decrypt` 方法，继续还原下一层载荷。
6. 用 `strings heap.hprof | grep "POST /"` 查看连接记录，用 `strings heap.hprof | grep -E "/webapps/.*!" | sort -u` 列出 Web 目录路径，定位被访问的 shell 与上传的 JSP。
7. 结论落地：确认内存马类型与入口后，删除入口文件、移除内存组件或重启，并修复根因；dump 文件按敏感数据保管。

## PoC

```bash
jps
jmap -dump:format=b,file=heapdump1 <pid>

# Arthas 内
heapdump

# 十六进制搜索
cafebabe
5f6a73702431        # _jsp$1

# Base64 class 头
yv66vg

# 堆内请求记录
strings heapdump1 | grep "POST /"
strings heapdump1 | grep -E "/webapps/.*!" | sort -u
```

## 变体与关联

- 变体：通过 Spring Boot Actuator 暴露的 heapdump 直接下载，见 [[web-java-framework-spring-actuator-heapdump-credential-leak]]；该路径既可用于攻击者取凭据，也可用于应急取证。
- 关联排查：[[defense-detection-tomcat-memshell-scanner-arthas]]（在线枚举组件）、[[defense-detection-arthas-agent-memshell-detect-remove]]（Agent transformer 定位与还原）。
- 关联攻击卡：[[web-java-component-tomcat-standardcontext-servlet-memshell]]、[[web-java-component-tomcat-dynamic-filter-memshell]]、[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-godzilla-filtershell-memshell]]。

## 检测与防御

- 检测特征：堆中出现多个 `cafebabe`/`yv66` 字节码块；存在无磁盘 code-source 的类；`org.apache.jsp.*$1` 匿名类；`/memshell`、`/shell` 等异常访问记录；JSP 访问后紧跟大量同一 URI 的 POST。
- 防御：限制 `jmap`/Attach 权限，禁用或鉴权 Actuator heapdump；监控大体积 dump 的产生；对 Web 目录与 JSP 做完整性监控；内存马清除后必须修复入口并重启，单纯删除文件无效。
- 注意：heap dump 可能包含密码、密钥、会话等敏感数据，导出、传输、留存均应加密并限制访问；Base64 串可能跨堆块截断，需要按上下文补全后再解码。
