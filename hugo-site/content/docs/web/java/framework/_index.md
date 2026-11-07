---
title: Java 框架
weight: 1
---

# Java 框架

## 这层是什么

Spring、Struts2、Shiro、Spring Boot 等框架漏洞。

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

- [Spring](spring/) —— Spring Framework/Spring Boot 漏洞与利用。
- [Struts2](struts2/) —— Struts2 OGNL 与历史漏洞。
- [Shiro](shiro/) —— Shiro 反序列化、RememberMe 与密钥问题。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Blade 框架动态注册 Route 内存马：反射 RouteMatcher.addRoute + register](web-java-framework-blade-route-memshell/) | verified | high | 2026-11-05 |
| [CVE-2026-3672 JeecgBoot /sys/api/getDictItems：字典 WAF 正则与黑名单不对称导致布尔盲注](web-java-framework-jeecgboot-api-dict-waf-regex-sqli/) | verified | high | 2026-11-05 |
| [GWT-RPC 隐藏服务方法可达导致未授权命令执行](web-java-framework-gwt-rpc-hidden-method-authz-rce/) | verified | high | 2026-11-04 |
| [Java *.do 过滤器按 URL 反射调用任意 Action 方法导致未授权 SQL 注入](web-java-framework-do-filter-reflection-dispatch/) | verified | high | 2026-11-04 |
| [JDK 21 虚拟线程默认空名导致以线程名为键的上下文串扰与跨租户越权](web-java-framework-virtual-thread-empty-name-context-crosstalk/) | verified | medium | 2026-11-04 |
| [JeecgBoot 3.8.3 /airag/flow/debug：任意用户提交 Groovy 脚本节点导致命令执行](web-java-framework-jeecgboot-airag-flow-debug-groovy-rce/) | verified | high | 2026-11-05 |
| [JeecgBoot getDictItems filterSql ${} 拼接：黑名单漏 #/or，布尔盲注窃取用户与口令哈希](web-java-framework-jeecgboot-dict-filter-sql-injection/) | verified | high | 2026-11-05 |
| [JeecgBoot ≤3.4.0 验证码 Redis Key 复用导致任意用户注册](web-java-framework-jeecgboot-captcha-redis-key-reuse-register/) | verified | high | 2026-11-05 |
| [JeecgBoot 字典接口 SQL 注入：黑名单 select%0a/current_user/innodb_table_stats 绕过与未过滤透传](web-java-framework-jeecgboot-dict-blacklist-bypass-sqli/) | verified | high | 2026-11-05 |
| [RuoYi 4.5.0 /common/download/resource 路径穿越任意文件读取](web-java-framework-ruoyi-download-resource-path-traversal/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
