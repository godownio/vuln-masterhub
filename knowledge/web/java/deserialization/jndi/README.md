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
| [Apache CXF JMS JndiHelper 未校验 java.naming.provider.url：可控 JNDI 环境经 LDAP 反序列化 RCE（CVE-2025-48913）](web-java-jndi-cxf-jms-jndihelper-provider-url-rce.md) | verified | medium | 2026-11-05 |
| [BAVE 被禁时的 Jackson 触发链：Hashtable 哈希碰撞 + XString.equals→POJONode.toString→LdapAttribute→LDAP javaSerializedData 二次反序列化](web-java-deser-xstring-pojonode-ldapattribute-javaserializeddata.md) | verified | high | 2026-11-10 |
| [Databricks JDBC 驱动 krbJAASFile 远程 JAAS 配置注入：JndiLoginModule 触发二次 JNDI lookup（CVE-2024-49194）](web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi.md) | verified | high | 2026-11-06 |
| [Java 17 Oracle JDBC RowSet 反序列化触发 RMI JNDI：POJONode+EventListenerList+动态代理包装 OracleCachedRowSet](web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi.md) | verified | high | 2026-11-07 |
| [JDK 8u191 LDAP JNDI javaSerializedData 反序列化通道：Obj.decodeObject 直接 readObject，配合本地 gadget 链 RCE](web-java-deserialization-jndi-ldap-javaserializeddata-deser.md) | verified | high | 2026-11-09 |
| [JDK 高版本 JNDI 绕过：Tomcat ResourceFactory 本地工厂链到 BasicDataSourceFactory JDBC 反序列化](web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass.md) | verified | high | 2026-11-05 |
| [JNDI 远程类加载注入 Tomcat Filter 内存马（单类 defineClass + StandardContext 注册）](web-java-deserialization-jndi-tomcat-filter-memshell.md) | verified | high | 2026-11-05 |
| [JNDI 高版本本地工厂 MemoryUserDatabaseFactory：pathname 读远端 XML 解析（XXE）并回写为 jsp，配合 EL 表达式绕过 Tomcat 的实体编码](web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write.md) | verified | medium | 2026-11-09 |
| [LDAP JNDI 高版本绕过：javaNamingReference 本地工厂 + Tomcat DataSourceFactory 触发 H2 INIT RCE](web-java-deserialization-jndi-ldap-local-factory-h2-init-rce.md) | verified | high | 2026-11-05 |
| [LdapAttribute.getAttributeDefinition 作反序列化 JNDI sink：TemplatesImpl 被禁时经 ReflectionFactory 免构造器实例化触发远程类加载](web-java-deser-jndi-ldapattribute-getattributedefinition-sink.md) | verified | high | 2026-11-08 |
| [Log4j2 登录参数触发 JNDI 注入并反弹 Shell](web-java-deserialization-jndi-log4j2-login-rce.md) | verified | high | 2026-11-04 |
| [RMIConnector.connect 的 JNDI 分支：JMXServiceURL urlPath 以 /jndi/ 开头触发 findRMIServerJNDI → InitialContext.lookup](web-java-deser-rmiconnector-jndi-findrmiserverjndi.md) | verified | medium | 2026-11-10 |
| [SolarWinds Web Help Desk AjaxProxy JSON-RPC 未授权调用导致 JNDI 注入 RCE（CVE-2025-40551 链）](web-java-deserialization-jndi-solarwinds-whd-ajaxproxy-rpc-rce.md) | verified | high | 2026-11-05 |
| [Tomcat 8.5.79+ 删掉 forceString 不等于安全：BeanFactory 仍按 RefAddr 名反射调用 setter，用 c3p0 setUserOverridesAsString 再接 readObject](web-java-deserialization-jndi-tomcat-beanfactory-setter-forcestring-removed.md) | verified | medium | 2026-11-08 |
| [WebLogic MessageDestinationObjectFactory 本地工厂：Reference 的 jndiName 被 lookupMessageDestination 直接 InitialContext.lookup（JNDI 二次注入 gadget）](web-java-deserialization-jndi-weblogic-messagedestinationobjectfactory-local-lookup.md) | verified | high | 2026-11-10 |
| [低版本 JNDI RMI/LDAP 远程 codebase 类加载 RCE（Reference + 静态初始化块）](web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase.md) | verified | high | 2026-11-06 |
| [只过滤 Reference 的 factory 白名单没用：Tomcat ResourceFactory/LookupFactory 会按 factory 属性再加载任意本地工厂（含 GenericNamingResourcesFactory 覆盖系统属性）](web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection.md) | verified | medium | 2026-11-08 |
| [用友 BIP SprMonitorServlet 原生反序列化触发 JNDI](web-java-deserialization-jndi-ufida-sprmonitorservlet.md) | verified | medium | 2026-11-04 |
| [高版本 JDK JNDI 绕过：本地 BeanFactory + ELProcessor 执行命令](web-java-deserialization-jndi-high-version-beanfactory-el.md) | verified | high | 2026-11-05 |
| [高版本 JNDI 绕过：c3p0 JavaBeanObjectFactory 的 REF_PROPS_KEY 与 userOverridesAsString 反序列化](web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory.md) | verified | high | 2026-11-05 |
| [高版本 JNDI 绕过：DruidDataSourceFactory 本地工厂解析 Reference 属性触发 H2 INIT RCE](web-java-deserialization-jndi-druid-datasource-factory-h2-init.md) | verified | high | 2026-11-07 |
| [高版本 JNDI 绕过：Tomcat BeanFactory + Batik JSVGCanvas 解析 SVG 脚本加载远程 Jar（SVG-Handler-Class）](web-java-deserialization-jndi-batik-jsvgcanvas-beanfactory-svg-jar.md) | verified | high | 2026-11-07 |
| [高版本 JNDI 绕过：ViburDBCPObjectFactory 本地工厂把 Reference 属性转成 JDBC 连接](web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
