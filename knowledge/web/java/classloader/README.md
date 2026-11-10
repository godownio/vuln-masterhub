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
| [agentmain 改写 ApplicationFilterChain.doFilter：借 ServletContext 动态注册 API 装入 EvilServlet](web-java-classloader-agentmain-filterchain-dynamic-servletregistration.md) | verified | medium | 2026-11-08 |
| [ASM + Instrumentation 热替换：Attach Agent 篡改认证与业务逻辑](web-java-classloader-asm-retransform-auth-bypass.md) | verified | high | 2026-11-05 |
| [JAR 上传 + 可控 getter 反射 URLClassLoader.addURL 动态加 classpath：jar:file 绕过协议黑名单，反序列化加载类触发 static 块 RCE](web-java-classloader-urlclassloader-addurl-uploaded-jar-deser-rce.md) | verified | high | 2026-11-08 |
| [Java Attach Agent 改写 HttpServlet.service 为通用 Jar Loader：lUrl/lName 从远程加载并实例化任意类](web-java-classloader-agent-httpservlet-jar-loader.md) | verified | high | 2026-11-07 |
| [Java Attach API 加载 JVMTI Agent 改写 HttpServlet.service 实现内存马](web-java-classloader-attach-api-jvmti-agent-memory-shell.md) | verified | high | 2026-11-05 |
| [JDBC Driver SPI 劫持：投放恶意 JAR 透明截获数据库凭证](web-java-classloader-jdbc-driver-spi-credential-theft.md) | verified | high | 2026-11-05 |
| [JDK 17+ 强封装绕过：Unsafe 篡改调用者 Class.module 伪装为 java.base](web-java-classloader-jdk17-class-module-field-spoof.md) | verified | high | 2026-11-05 |
| [JDK 17+ 模块强封装绕过：Unsafe 内存直读 IMPL_LOOKUP](web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup.md) | verified | high | 2026-11-05 |
| [JetLinks 协议包加载 RCE：`/api/protocol/convert` 让 `fileId`/`location` 进入 JarProtocolSupportLoader，实例化攻击者 jar 里的 Provider](web-java-classloader-jetlinks-protocol-jar-upload-remote-load-rce.md) | verified | medium | 2026-11-08 |
| [JRE CharsetProvider SPI 注入：任意文件写入 jre/classes 后由 Accept charset 触发命令执行](web-java-classloader-charsetprovider-spi-accept-rce.md) | verified | medium | 2026-11-05 |
| [JSP 内置 GZIP+Base64 类 blob：反射 defineClass 内存马 + DNSlog 回显](web-java-classloader-gzip-base64-dnslog-jsp-webshell.md) | verified | high | 2026-11-07 |
| [JSP 经 Unsafe.defineAnonymousClass 执行请求参数中的匿名类字节码](web-java-classloader-unsafe-anonymous-class-jsp-shell.md) | verified | medium | 2026-11-04 |
| [JSP 自定义 ClassLoader 注册内存 Servlet WebShell](web-java-classloader-jsp-memory-servlet-webshell.md) | verified | medium | 2026-11-04 |
| [memfd_create 配合 Attach 协议实现无文件 Java Agent 注入](web-java-classloader-memfd-fileless-agent-injection.md) | verified | high | 2026-11-05 |
| [MethodHandles.Lookup.defineClass 同包加载字节码：lookup 调用者决定恶意类包名](web-java-classloader-methodhandles-lookup-defineclass-same-package.md) | verified | medium | 2026-11-08 |
| [ServletContainerInitializer SPI 注入：WEB-INF/lib 放置 JAR 自动注册后门 Servlet](web-java-classloader-servletcontainerinitializer-spi-backdoor.md) | verified | high | 2026-11-05 |
| [Tomcat JSR-356 WebSocket Endpoint 内存马：反射注册 WsServerContainer 端点实现持久命令通道](web-java-classloader-websocket-endpoint-memshell.md) | verified | high | 2026-11-05 |
| [内存马 defineClass 的落点选择：从 ServletContext 取 WebApp 类加载器，避免容器实例化 Filter 时 ClassNotFoundException](web-java-classloader-memshell-webapp-loader-selection.md) | verified | medium | 2026-11-08 |
| [冰蝎式 JSP 字节码 Webshell 的载荷组装：javassist 替换 Encrypt、ASM 向构造器注入参数、随机类名与版本降级](web-java-classloader-behinder-bytecode-payload-assembly.md) | verified | medium | 2026-11-08 |
| [反序列化打内存马的类加载原语选型：TemplatesImpl/Groovy 走构造器、BCEL 只走静态块](web-java-classloader-deserialization-memshell-loader-selection.md) | verified | medium | 2026-11-07 |
| [反序列化链驱动 Attach API 装载 Agent：改写 ApplicationFilterChain.doFilter 植入 cmd Filter 内存马](web-java-classloader-deser-attach-agent-filterchain-memshell.md) | verified | medium | 2026-11-08 |
| [线程上下文类加载器决定嵌套 jar URL 类型名能否被加载](web-java-classloader-tccl-nested-jar-type-loading.md) | verified | high | 2026-11-04 |
| [自定义 ClassLoader 缺失 Sealed Package 校验导致包内类型注入](web-java-classloader-sealed-package-type-injection.md) | verified | high | 2026-11-04 |
| [覆盖 charsets.jar 之后怎么让它真正被加载：Accept 头里 multipart 前缀 / LRU 缓存两条 Charset.forName 触发链，以及非 Spring 场景的 fastjson Charset setter 触发](web-java-classloader-charsets-jar-load-trigger-accept-multipart-cache-fastjson.md) | verified | high | 2026-11-08 |
| [覆盖 jre/lib/charsets.jar + Accept charset=GBK：JDK 8 字符集类加载触发命令执行](web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce.md) | verified | high | 2026-11-06 |
| [跨类加载器注入容器对象：同名 FilterMapping 的 ClassCastException 与容器 ClassLoader 反射实例化](web-java-classloader-container-type-identity-memshell.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
