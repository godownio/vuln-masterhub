---
title: SpEL
weight: 1
---

# SpEL

## 这层是什么

Spring Expression Language 注入与利用。

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
| [CVE-2022-22963 Spring Cloud Function routing-expression 头 SpEL 注入：/functionRouter 未授权命令执行](web-java-expression-spel-spring-cloud-function-cve-2022-22963-routing-expression-rce/) | verified | high | 2026-11-13 |
| [DataGear 数据行值 #{...} 被 SpEL 求值：SQL 插入触发命令执行与列长限制绕过](web-java-expression-spel-datagear-row-expression-rce/) | verified | high | 2026-11-05 |
| [JWT 密钥泄露伪造身份 + 路径穿越上传 Thymeleaf 模板：dynamic-template 渲染读取环境变量](web-java-expression-spel-jwt-leak-upload-thymeleaf-template-rce/) | verified | high | 2026-11-07 |
| [RuoYi Thymeleaf 片段注入的四个入口与逐字符 %hex 编码投递：用 header() 包裹 SpEL、以响应含端点名作为黑盒命中 oracle](web-java-expression-spel-ruoyi-thymeleaf-fragment-four-endpoint-hex-probe/) | verified | medium | 2026-11-09 |
| [RuoYi Thymeleaf 片段表达式 SSTI 与双美元绕过](web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti/) | verified | high | 2026-11-04 |
| [SimpleEvaluationContext 只读绑定仍调用 getter：SpEL 属性 outputProperties 触发 TemplatesImpl 字节码加载 RCE](web-java-expression-spel-simplecontext-property-getter-templatesimpl-rce/) | verified | high | 2026-11-07 |
| [SimpleEvaluationContext 数组赋值经 ObjectToObjectConverter 调用构造器：ClassPathXmlApplicationContext 加载远程 XML RCE](web-java-expression-spel-simplecontext-array-assignment-objectconverter-constructor-rce/) | verified | high | 2026-11-07 |
| [SpEL 关键字与字符过滤绕过：ScriptEngine 内联、字符数组、Base64 与反射](web-java-expression-spel-waf-bypass-scriptengine-reflection/) | verified | medium | 2026-11-05 |
| [SpEL 无回显注入：Scanner 读进程输出、StreamUtils 写响应与 DNS/HTTP 外带](web-java-expression-spel-no-echo-exfil-streamutils/) | verified | high | 2026-11-05 |
| [SpEL 注入改写 systemProperties['user.home']：重定向应用读取路径实现任意文件读取](web-java-expression-spel-systemproperties-user-home-file-read/) | verified | high | 2026-11-07 |
| [SpEL 禁用 T()/new 时用反射链构造对象并注入内存马](web-java-expression-spel-restricted-reflection-memshell/) | verified | high | 2026-11-04 |
| [Spring AI SimpleVectorStore 过滤键未转义 SpEL 注入：闭合 #metadata 字符串实现无认证 RCE（CVE-2026-22738）](web-java-expression-spel-spring-ai-simplevectorstore-filter-key-rce/) | verified | high | 2026-11-06 |
| [Spring Boot Whitelabel Error Page 递归解析 ${} 并交给 SpEL：参数值进入默认错误页导致命令执行](web-java-framework-spring-whitelabel-error-page-spel-injection/) | verified | medium | 2026-11-08 |
| [Spring Cloud Gateway actuator 路由创建 SpEL 注入命令执行（CVE-2022-22947）](web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce/) | verified | high | 2026-11-05 |
| [Spring Cloud Gateway CVE-2022-22947 SpEL 投递内存马：ReflectUtils.defineClass + MLet 类加载器 + doInject 注册路由](web-java-expression-spel-spring-cloud-gateway-22947-defineclass-mlet-memshell/) | verified | high | 2026-11-10 |
| [Spring Cloud Gateway CVE-2025-41243 属性写读取 Environment 配置并置 H2 Console 打 JNDI](web-java-expression-spel-spring-cloud-gateway-property-write-env-h2-rce/) | verified | high | 2026-11-05 |
| [Spring Cloud Gateway SpEL 属性写 + 方法名兜底调用链实现任意文件读取](web-java-expression-spel-spring-cloud-gateway-property-method-chain/) | verified | high | 2026-11-05 |
| [Spring Messaging STOMP selector SpEL 注入 RCE（CVE-2018-1270）](web-java-expression-spel-spring-messaging-stomp-selector-rce/) | verified | medium | 2026-11-05 |
| [Thymeleaf 3.0.12 受限 SpEL 的 T( 静态访问检测绕过：T 与 ( 之间插入空格/换行/制表符](web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass/) | verified | high | 2026-11-08 |
| [Thymeleaf 3.0.12 视图名预处理 SSTI 绕过：URI 分号与 Spring cached path 归一化差异骗过 checkViewNameNotInRequest](web-java-expression-spel-thymeleaf-312-viewname-check-semicolon-bypass/) | verified | high | 2026-11-08 |
| [Thymeleaf 3.1.2 类型黑名单绕过：非 c/j/o/s 包直接放行 + 借第三方反射实例化 API 套娃执行 SpEL/EL](web-java-expression-spel-thymeleaf-312-istypeallowed-prefix-blacklist-bypass/) | verified | medium | 2026-11-08 |
| [Thymeleaf SSTI 禁用 T() 时用](web-java-expression-spel-thymeleaf-strings-reflection-file-read/) | verified | high | 2026-11-06 |
| [Thymeleaf 主题名存储型 SSTI：后台写入 __${...}__ 主题，首页拼接模板路径触发命令执行](web-java-expression-spel-thymeleaf-theme-name-stored-ssti/) | verified | high | 2026-11-05 |
| [Thymeleaf 视图名预处理 SSTI：__${...}__::x 读取文件与 Runtime.exec](web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti/) | verified | high | 2026-11-04 |
| [用户输入进入 SpelExpressionParser 导致 SpEL 注入命令执行](web-java-expression-spel-injection-to-rce/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
