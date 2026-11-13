# Shiro

## 这层是什么

Shiro 反序列化、RememberMe 与密钥问题。

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
| [Actuator heapdump 泄露 Shiro rememberMe 密钥与内置账号，伪造 admin 身份](web-java-framework-shiro-actuator-heapdump-key-account-forgery.md) | verified | high | 2026-11-06 |
| [Shiro /**/*.js 匿名规则与 Spring @PathVariable 语义差异：伪造静态后缀绕过 JWT](web-java-framework-shiro-static-suffix-anon-pathvariable-bypass.md) | verified | high | 2026-11-05 |
| [Shiro 1.4.0 版本号"已验证安全"仍中招：配置文件里自设 cipherKey（短字符串 copyOf 补齐 16 字节）让 rememberMe 依旧可伪造，审计必须查密钥来源而非只看版本](web-java-framework-shiro-configured-weak-cipherkey-rememberme-rce.md) | verified | high | 2026-11-13 |
| [Shiro 1.7.1 默认密钥 + AES-GCM rememberMe：跨 JDK 构造 commons-collections4 CC2 链写文件回显](web-java-framework-shiro-rememberme-aes-gcm-cc2-cross-jdk.md) | verified | high | 2026-11-06 |
| [Shiro rememberMe 8KB 头限制绕过：两段式 ShellLoader 从 POST 加载内存马类](web-java-framework-shiro-rememberme-two-stage-memshell-loader.md) | verified | high | 2026-11-05 |
| [Shiro rememberMe 单请求注入 Filter 内存马：TemplatesImpl 静态块自注册 ApplicationFilterConfig（Tomcat 8.5 < 8.5.78）](web-java-framework-shiro-rememberme-filter-memshell-static-block.md) | verified | high | 2026-11-12 |
| [Shiro rememberMe 反序列化 + Spring RequestContextHolder 两段式投递 Interceptor 内存马](web-java-framework-shiro-rememberme-spring-interceptor-memshell-classdata.md) | verified | medium | 2026-11-13 |
| [Shiro rememberMe 反序列化被拦截：改用非标准 HTTP 方法绕过安全产品，405 由 MVC 返回但 Shiro 过滤器已反序列化](web-java-framework-shiro-http-method-waf-bypass.md) | verified | medium | 2026-11-09 |
| [Shiro rememberMe 流量复盘：默认密钥解密、AbstractTranslet 内存马与 DNS 外带](web-java-framework-shiro-rememberme-pcap-memshell-dns-exfil.md) | verified | high | 2026-11-07 |
| [Shiro 与 Spring 路径解析差异导致鉴权绕过（分号、编码与 trim）](web-java-framework-shiro-spring-path-auth-bypass.md) | verified | medium | 2026-11-05 |
| [Shiro-550 硬编码 AES 密钥导致 rememberMe 反序列化 RCE](web-java-framework-shiro-550-hardcoded-key-deserialization.md) | verified | high | 2026-11-05 |
| [Shiro-721 对 rememberMe AES-CBC 做 Padding Oracle 伪造恶意 Cookie](web-java-framework-shiro-721-padding-oracle.md) | verified | high | 2026-11-05 |
| [手工构造 Shiro-550 rememberMe 载荷：AES-CBC 加密与密钥判定](web-java-framework-shiro-550-manual-rememberme-payload.md) | verified | high | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
