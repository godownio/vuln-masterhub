---
title: JNDI 注入
weight: 1
---

# JNDI 注入

## 这层是什么

JNDI/LDAP/RMI 注入与高版本绕过。

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
| [Apache CXF JMS JndiHelper 未校验 java.naming.provider.url：可控 JNDI 环境经 LDAP 反序列化 RCE（CVE-2025-48913）](web-java-jndi-cxf-jms-jndihelper-provider-url-rce/) | verified | medium | 2026-11-05 |
| [Databricks JDBC 驱动 krbJAASFile 远程 JAAS 配置注入：JndiLoginModule 触发二次 JNDI lookup（CVE-2024-49194）](web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi/) | verified | high | 2026-11-06 |
| [Java 17 Oracle JDBC RowSet 反序列化触发 RMI JNDI：POJONode+EventListenerList+动态代理包装 OracleCachedRowSet](web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi/) | verified | high | 2026-11-07 |
| [JDK 高版本 JNDI 绕过：Tomcat ResourceFactory 本地工厂链到 BasicDataSourceFactory JDBC 反序列化](web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass/) | verified | high | 2026-11-05 |
| [JNDI 远程类加载注入 Tomcat Filter 内存马（单类 defineClass + StandardContext 注册）](web-java-deserialization-jndi-tomcat-filter-memshell/) | verified | high | 2026-11-05 |
| [LDAP JNDI 高版本绕过：javaNamingReference 本地工厂 + Tomcat DataSourceFactory 触发 H2 INIT RCE](web-java-deserialization-jndi-ldap-local-factory-h2-init-rce/) | verified | high | 2026-11-05 |
| [Log4j2 登录参数触发 JNDI 注入并反弹 Shell](web-java-deserialization-jndi-log4j2-login-rce/) | verified | high | 2026-11-04 |
| [SolarWinds Web Help Desk AjaxProxy JSON-RPC 未授权调用导致 JNDI 注入 RCE（CVE-2025-40551 链）](web-java-deserialization-jndi-solarwinds-whd-ajaxproxy-rpc-rce/) | verified | high | 2026-11-05 |
| [低版本 JNDI RMI/LDAP 远程 codebase 类加载 RCE（Reference + 静态初始化块）](web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase/) | verified | high | 2026-11-06 |
| [用友 BIP SprMonitorServlet 原生反序列化触发 JNDI](web-java-deserialization-jndi-ufida-sprmonitorservlet/) | verified | medium | 2026-11-04 |
| [高版本 JDK JNDI 绕过：本地 BeanFactory + ELProcessor 执行命令](web-java-deserialization-jndi-high-version-beanfactory-el/) | verified | high | 2026-11-05 |
| [高版本 JNDI 绕过：c3p0 JavaBeanObjectFactory 的 REF_PROPS_KEY 与 userOverridesAsString 反序列化](web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory/) | verified | high | 2026-11-05 |
| [高版本 JNDI 绕过：DruidDataSourceFactory 本地工厂解析 Reference 属性触发 H2 INIT RCE](web-java-deserialization-jndi-druid-datasource-factory-h2-init/) | verified | high | 2026-11-07 |
| [高版本 JNDI 绕过：Tomcat BeanFactory + Batik JSVGCanvas 解析 SVG 脚本加载远程 Jar（SVG-Handler-Class）](web-java-deserialization-jndi-batik-jsvgcanvas-beanfactory-svg-jar/) | verified | high | 2026-11-07 |
| [高版本 JNDI 绕过：ViburDBCPObjectFactory 本地工厂把 Reference 属性转成 JDBC 连接](web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
