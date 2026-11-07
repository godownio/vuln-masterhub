# 类加载

## 这层是什么

ClassLoader、字节码、内存马与加载机制。

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
| [ASM + Instrumentation 热替换：Attach Agent 篡改认证与业务逻辑](web-java-classloader-asm-retransform-auth-bypass.md) | verified | high | 2026-11-05 |
| [Java Attach API 加载 JVMTI Agent 改写 HttpServlet.service 实现内存马](web-java-classloader-attach-api-jvmti-agent-memory-shell.md) | verified | high | 2026-11-05 |
| [JDBC Driver SPI 劫持：投放恶意 JAR 透明截获数据库凭证](web-java-classloader-jdbc-driver-spi-credential-theft.md) | verified | high | 2026-11-05 |
| [JDK 17+ 强封装绕过：Unsafe 篡改调用者 Class.module 伪装为 java.base](web-java-classloader-jdk17-class-module-field-spoof.md) | verified | high | 2026-11-05 |
| [JDK 17+ 模块强封装绕过：Unsafe 内存直读 IMPL_LOOKUP](web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup.md) | verified | high | 2026-11-05 |
| [JRE CharsetProvider SPI 注入：任意文件写入 jre/classes 后由 Accept charset 触发命令执行](web-java-classloader-charsetprovider-spi-accept-rce.md) | verified | medium | 2026-11-05 |
| [JSP 内置 GZIP+Base64 类 blob：反射 defineClass 内存马 + DNSlog 回显](web-java-classloader-gzip-base64-dnslog-jsp-webshell.md) | draft | high | 2026-11-07 |
| [JSP 经 Unsafe.defineAnonymousClass 执行请求参数中的匿名类字节码](web-java-classloader-unsafe-anonymous-class-jsp-shell.md) | verified | medium | 2026-11-04 |
| [JSP 自定义 ClassLoader 注册内存 Servlet WebShell](web-java-classloader-jsp-memory-servlet-webshell.md) | verified | medium | 2026-11-04 |
| [memfd_create 配合 Attach 协议实现无文件 Java Agent 注入](web-java-classloader-memfd-fileless-agent-injection.md) | verified | high | 2026-11-05 |
| [ServletContainerInitializer SPI 注入：WEB-INF/lib 放置 JAR 自动注册后门 Servlet](web-java-classloader-servletcontainerinitializer-spi-backdoor.md) | verified | high | 2026-11-05 |
| [Tomcat JSR-356 WebSocket Endpoint 内存马：反射注册 WsServerContainer 端点实现持久命令通道](web-java-classloader-websocket-endpoint-memshell.md) | verified | high | 2026-11-05 |
| [反序列化打内存马的类加载原语选型：TemplatesImpl/Groovy 走构造器、BCEL 只走静态块](web-java-classloader-deserialization-memshell-loader-selection.md) | verified | medium | 2026-11-07 |
| [线程上下文类加载器决定嵌套 jar URL 类型名能否被加载](web-java-classloader-tccl-nested-jar-type-loading.md) | verified | high | 2026-11-04 |
| [自定义 ClassLoader 缺失 Sealed Package 校验导致包内类型注入](web-java-classloader-sealed-package-type-injection.md) | verified | high | 2026-11-04 |
| [覆盖 jre/lib/charsets.jar + Accept charset=GBK：JDK 8 字符集类加载触发命令执行](web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
