# Spring

## 这层是什么

Spring Framework/Spring Boot 漏洞与利用。

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
| [Actuator env 未授权：从 propertySources 里捞 AK/SK 与数据源口令，一路接管 OSS 与 MySQL](web-java-framework-spring-actuator-env-ak-sk-oss-db-takeover.md) | verified | low | 2026-11-09 |
| [CVE-2026-22733 Spring Boot CloudFoundry Actuator：web.ignoring 整段路径 + HandlerMapping 无 catch-all 导致认证绕过](web-java-framework-spring-cloudfoundry-actuator-ignoring-bypass.md) | verified | high | 2026-11-05 |
| [Enjoy 模板引擎 SSTI：springMacroRequestContext 取 Spring Bean/ClassLoader，经 Jackson+SpEL 加载内存马](web-java-framework-spring-enjoy-template-springmacrocontext-spel-memshell.md) | verified | high | 2026-11-06 |
| [Litemall 评论接口大量赋值：普通用户伪造管理员回复内容（CVE-2025-6702）](web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery.md) | verified | medium | 2026-11-05 |
| [Spring @RequestBody 大量赋值：普通用户注入 role 字段注册为管理员](web-java-framework-spring-requestbody-mass-assignment-privilege-escalation.md) | verified | high | 2026-11-05 |
| [Spring AntPathMatcher 大小写不敏感 + Unicode ſ：路由命中 suctf、拦截器却漏判](web-java-framework-spring-antpathmatcher-unicode-long-s-case-bypass.md) | verified | high | 2026-11-06 |
| [Spring Boot Actuator env + refresh 注入 bootstrap.location：远程 YAML 触发 SnakeYAML ScriptEngineManager RCE](web-java-framework-spring-actuator-bootstrap-location-yaml-rce.md) | verified | high | 2026-11-07 |
| [Spring Boot Actuator env 改写 spring.datasource.url：refresh 后触发 MySQL JDBC autoDeserialize 反序列化 RCE](web-java-framework-spring-actuator-env-datasource-url-mysql-jdbc-deserialization.md) | verified | medium | 2026-11-08 |
| [Spring Boot Actuator env 未授权泄露环境变量与配置源，定位内部备份文件下载路径](web-java-framework-spring-actuator-env-config-backup-path.md) | verified | high | 2026-11-06 |
| [Spring Boot Actuator heapdump 暴露导致数据库与系统凭据泄露](web-java-framework-spring-actuator-heapdump-credential-leak.md) | verified | high | 2026-11-05 |
| [Spring Boot Actuator Jolokia 未授权调用 SpringApplicationAdminMXBean#getProperty 读取配置明文（如 security.user.password）](web-java-framework-spring-actuator-jolokia-getproperty-config-disclosure.md) | verified | high | 2026-11-08 |
| [Spring Boot Actuator Jolokia 调 logback JMXConfigurator#reloadByURL：远程 XML 外部实体 XXE 任意文件读取](web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-xxe-file-read.md) | verified | high | 2026-11-08 |
| [Spring Boot Actuator Jolokia 调用 logback JMXConfigurator#reloadByURL：远程 XML 的 insertFromJNDI 触发 JNDI RCE](web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce.md) | verified | high | 2026-11-08 |
| [Spring Boot Actuator Jolokia 调用 Tomcat MBeanFactory#createJNDIRealm + Realm 属性写：rmi lookup 触发 JNDI RCE](web-java-framework-spring-actuator-jolokia-tomcat-createjndirealm-rce.md) | verified | high | 2026-11-08 |
| [Spring Boot Actuator restart + logging.config 指向恶意 logback XML：insertFromJNDI 触发 JNDI 命令执行](web-java-framework-spring-actuator-restart-logging-config-logback-jndi-rce.md) | verified | high | 2026-11-08 |
| [Spring Boot Actuator restart + logging.config 指向远程 .groovy：logback ContextInitializer 加载 Groovy 配置执行命令](web-java-framework-spring-actuator-restart-logging-config-groovy-rce.md) | verified | medium | 2026-11-08 |
| [Spring Boot Actuator restart + spring.datasource.data 加载远程 SQL：H2 CREATE ALIAS 编译 Java 执行命令](web-java-framework-spring-actuator-restart-spring-datasource-data-h2-sql-rce.md) | verified | medium | 2026-11-08 |
| [Spring Boot Actuator 未授权 mappings + env 作攻击面侦察：从隐藏路由拿到 sink，从 jar 清单选型本地 JNDI 工厂 gadget](web-java-framework-spring-actuator-mappings-env-classpath-gadget-recon.md) | verified | high | 2026-11-07 |
| [Spring MVC + FreeMarker 沙箱逃逸：springMacroRequestContext 重置 TemplateClassResolver](web-java-framework-spring-freemarker-macro-context-resolver-reset.md) | verified | high | 2026-11-05 |
| [Spring MVC Interceptor 内存马：反射注入 adaptedInterceptors](web-java-framework-spring-mvc-interceptor-memshell.md) | verified | high | 2026-11-05 |
| [Spring MVC 运行时注册 Controller 内存马（SpEL defineClass 投递）](web-java-framework-spring-mvc-dynamic-controller-memshell.md) | verified | medium | 2026-11-05 |
| [Spring remember-me 无签名 AES-CBC Cookie 伪造 + welcome 接口 SpEL 求值读文件](web-java-framework-spring-rememberme-aes-cookie-spel-injection.md) | verified | high | 2026-11-05 |
| [Spring RequestContextHolder 命令载荷：取当前 request/response，读 cmd 头 Runtime.exec 回显](web-java-framework-spring-requestcontextholder-cmd-header-echo.md) | verified | medium | 2026-11-08 |
| [Spring uriDecode 高位截断“幽灵比特”路径穿越](web-java-framework-spring-ghost-bits-path-traversal.md) | verified | high | 2026-11-04 |
| [Spring WebFlux 内存马：替换 FilteringWebHandler.chain 注入恶意 WebFilter](web-java-framework-spring-webflux-filteringwebhandler-memshell.md) | verified | high | 2026-11-05 |
| [Spring WebFlux/Netty 无 Servlet 回显：NettyWebServer→HttpServerConfig.channelGroup→channel.attributes→HttpServerOperations 取 request/response，命令输出写 result 响应头](web-java-framework-spring-webflux-netty-httpserveroperations-header-echo.md) | verified | high | 2026-11-09 |
| [Spring 自定义鉴权按原始 URI 判断导致路径解析差异绕过](web-java-framework-spring-custom-auth-path-parsing-bypass.md) | verified | high | 2026-11-05 |
| [spring-boot-actuator-logview CVE-2021-21234：/manage/log/view 的 base/filename 路径穿越任意文件读取](web-java-framework-spring-actuator-logview-cve-2021-21234-file-read.md) | verified | high | 2026-11-08 |
| [Spring4Shell（CVE-2022-22965）：Spring MVC 数据绑定 class.module.classLoader 链改写 Tomcat AccessLogValve 写 JSP](web-java-framework-spring-cve-2022-22965-accesslogvalve-webshell.md) | verified | high | 2026-11-07 |
| [反序列化 TemplatesImpl 落 Spring Controller 内存马：translet 构造器内用 getMappingForMethod 生成 RequestMappingInfo 再 registerMapping](web-java-framework-spring-mvc-memshell-translet-ctor-getmappingformethod.md) | verified | medium | 2026-11-09 |
| [容器化 Spring Boot 默认 native 转发头策略使 X-Forwarded-Proto 成为未校验的 URI scheme，污染 baseUrl 构造](web-java-framework-spring-native-forwarded-header-proto-scheme-injection.md) | verified | medium | 2026-11-08 |
| [文都 OA 匿名白名单 `/info/**` 通配放行：未授权读取 288 条员工 PII 并任意增删改](web-java-framework-spring-oa-anon-urls-info-wildcard-unauth-crud.md) | verified | high | 2026-11-07 |
| [新版 Spring MVC PathPatternsRequestCondition 动态路由内存马](web-java-framework-spring-mvc-pathpattern-memshell.md) | verified | high | 2026-11-05 |
| [暴露的 Eureka 注册中心被恶意实例注册劫持网关流量并捕获登录凭据](web-java-framework-spring-eureka-instance-hijack-credential-capture.md) | verified | high | 2026-11-05 |
| [泛微 E10 运维平台 /sapi/bs/** 通配白名单全局鉴权绕过：未授权 addUser + saveUserRole 添加管理员](web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin.md) | verified | high | 2026-11-07 |
| [配置接口双重 URL 解码 + 反斜杠归一化路径穿越：读 application.yml 经 actuator env 下载 heapdump](web-java-framework-spring-config-double-decode-backslash-traversal-heapdump.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
