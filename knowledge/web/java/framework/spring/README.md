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
| [CVE-2026-22733 Spring Boot CloudFoundry Actuator：web.ignoring 整段路径 + HandlerMapping 无 catch-all 导致认证绕过](web-java-framework-spring-cloudfoundry-actuator-ignoring-bypass.md) | verified | high | 2026-11-05 |
| [Enjoy 模板引擎 SSTI：springMacroRequestContext 取 Spring Bean/ClassLoader，经 Jackson+SpEL 加载内存马](web-java-framework-spring-enjoy-template-springmacrocontext-spel-memshell.md) | verified | high | 2026-11-06 |
| [Litemall 评论接口大量赋值：普通用户伪造管理员回复内容（CVE-2025-6702）](web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery.md) | verified | medium | 2026-11-05 |
| [Spring @RequestBody 大量赋值：普通用户注入 role 字段注册为管理员](web-java-framework-spring-requestbody-mass-assignment-privilege-escalation.md) | verified | high | 2026-11-05 |
| [Spring AntPathMatcher 大小写不敏感 + Unicode ſ：路由命中 suctf、拦截器却漏判](web-java-framework-spring-antpathmatcher-unicode-long-s-case-bypass.md) | verified | high | 2026-11-06 |
| [Spring Boot Actuator env + refresh 注入 bootstrap.location：远程 YAML 触发 SnakeYAML ScriptEngineManager RCE](web-java-framework-spring-actuator-bootstrap-location-yaml-rce.md) | verified | high | 2026-11-07 |
| [Spring Boot Actuator env 未授权泄露环境变量与配置源，定位内部备份文件下载路径](web-java-framework-spring-actuator-env-config-backup-path.md) | verified | high | 2026-11-06 |
| [Spring Boot Actuator heapdump 暴露导致数据库与系统凭据泄露](web-java-framework-spring-actuator-heapdump-credential-leak.md) | verified | high | 2026-11-05 |
| [Spring MVC + FreeMarker 沙箱逃逸：springMacroRequestContext 重置 TemplateClassResolver](web-java-framework-spring-freemarker-macro-context-resolver-reset.md) | verified | high | 2026-11-05 |
| [Spring MVC Interceptor 内存马：反射注入 adaptedInterceptors](web-java-framework-spring-mvc-interceptor-memshell.md) | verified | high | 2026-11-05 |
| [Spring MVC 运行时注册 Controller 内存马（SpEL defineClass 投递）](web-java-framework-spring-mvc-dynamic-controller-memshell.md) | verified | medium | 2026-11-05 |
| [Spring remember-me 无签名 AES-CBC Cookie 伪造 + welcome 接口 SpEL 求值读文件](web-java-framework-spring-rememberme-aes-cookie-spel-injection.md) | verified | high | 2026-11-05 |
| [Spring uriDecode 高位截断“幽灵比特”路径穿越](web-java-framework-spring-ghost-bits-path-traversal.md) | verified | high | 2026-11-04 |
| [Spring WebFlux 内存马：替换 FilteringWebHandler.chain 注入恶意 WebFilter](web-java-framework-spring-webflux-filteringwebhandler-memshell.md) | verified | high | 2026-11-05 |
| [Spring 自定义鉴权按原始 URI 判断导致路径解析差异绕过](web-java-framework-spring-custom-auth-path-parsing-bypass.md) | verified | high | 2026-11-05 |
| [Spring4Shell（CVE-2022-22965）：Spring MVC 数据绑定 class.module.classLoader 链改写 Tomcat AccessLogValve 写 JSP](web-java-framework-spring-cve-2022-22965-accesslogvalve-webshell.md) | verified | high | 2026-11-07 |
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
