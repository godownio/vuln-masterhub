---
title: Java 反序列化
weight: 1
---

# Java 反序列化

## 这层是什么

原生反序列化、gadget 链、触发点、绕过与利用。

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

- [Comparator 链](comparator/) —— 通过 Comparator/compare 触发 toString、hashCode 等方法的 gadget 组合。
- [JDK 原生链](jdk/) —— JDK 内置类形成的反序列化链与触发点。
- [Fastjson](fastjson/) —— Fastjson AutoType、缓存与绕过。
- [Jackson](jackson/) —— Jackson 多态反序列化与 gadget。
- [XStream](xstream/) —— XStream 反序列化与 CVE 利用。
- [Hessian](hessian/) —— Hessian 反序列化与利用链。
- [JNDI 注入](jndi/) —— JNDI/LDAP/RMI 注入与高版本绕过。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ActiveMQ CVE-2023-46604 不出网利用：IniEnvironment 加载 Shiro INI 触发 getter/setter 链](web-java-deserialization-activemq-46604-intranet-ini-environment-getter-setter/) | verified | high | 2026-11-05 |
| [ActiveMQ OpenWire 反序列化任意 String 构造方法致 RCE（CVE-2023-46604）](web-java-deserialization-activemq-openwire-throwable-constructor-rce/) | verified | high | 2026-11-05 |
| [Apache Camel JMS ObjectMessage 自动反序列化导致 RCE（CVE-2026-40860）](web-java-deserialization-camel-jms-objectmessage-rce/) | verified | high | 2026-11-05 |
| [Apache Causeway ViewModel Bookmark memento 反序列化 RCE：URL 片段经 GZip+Base64 还原对象（CVE-2025-64408）](web-java-deserialization-causeway-viewmodel-bookmark-memento-rce/) | verified | high | 2026-11-05 |
| [Apache NiFi GetAsanaObject 缓存状态反序列化（CVE-2025-66524）：可写 MapCache 即触发 ObjectInputStream.readObject](web-java-deserialization-nifi-getasanaobject-cache-state-deser/) | verified | medium | 2026-11-05 |
| [Axis server-config.wsdd 隐藏服务反序列化：allowedMethods=* 的 receiveData 直通 readObject](web-java-deserialization-axis-wsdd-hidden-service-readobject/) | verified | low | 2026-11-06 |
| [C3P0 PoolBackedDataSourceBase 反序列化经 ReferenceableUtils 远程加载类](web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader/) | verified | high | 2026-11-05 |
| [C3P0 反序列化不出网利用：Tomcat BeanFactory 结合 ELProcessor 执行命令](web-java-deser-c3p0-beanfactory-el-no-egress/) | verified | high | 2026-11-05 |
| [CC 3.2.2 禁用 Transformer 后借 Hutool JSONObject 自动调用 getter 绕过](web-java-deser-commonscollections-322-jsonobject-getter-bypass/) | verified | medium | 2026-11-05 |
| [CC1 LazyMap + AnnotationInvocationHandler 动态代理触发链](web-java-deser-commonscollections-cc1-lazymap-proxy/) | verified | high | 2026-11-05 |
| [CC1 TransformedMap + AnnotationInvocationHandler 反射链执行命令](web-java-deser-commonscollections-cc1-transformedmap/) | verified | high | 2026-11-05 |
| [CC5 BadAttributeValueExpException + TiedMapEntry.toString 触发 LazyMap](web-java-deser-commonscollections-cc5-badattribute-tostring/) | verified | high | 2026-11-05 |
| [CC6 触发 + CC3 TemplatesImpl 攻击的 Commons Collections 组合链](web-java-deser-commonscollections-cc6-cc3-templatesimpl/) | verified | high | 2026-11-05 |
| [CC7 Hashtable reconstitutionPut + AbstractMap.equals 触发 LazyMap](web-java-deser-commonscollections-cc7-hashtable-equals-lazymap/) | verified | high | 2026-11-05 |
| [Commons Collections4 Transformer 链内复用同一对象完成两段式反射调用](web-java-deser-cc4-transformer-reuse-object-multicall/) | verified | high | 2026-11-05 |
| [CSS 反序列化 + StringValueTransformer + JSONArray：把 transform 桥接成 toString 触发 TemplatesImpl](web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl/) | verified | high | 2026-11-05 |
| [FineReport channel 反序列化实战：FrChannel 注入内存马与 suo5 内网隧道](web-java-deserialization-finereport-channel-frchannel-memshell-suo5/) | verified | medium | 2026-11-05 |
| [Hibernate getter + ActivatableRef.getRef 触发 JRMP 二次反序列化绕过类名黑名单](web-java-deser-hibernate-activatableref-jrmp-secondary-bypass/) | verified | medium | 2026-11-06 |
| [IBM Db2 JCC createLicenseCache 触发本地 jccServerListCache.bin 反序列化](web-java-deserialization-ibm-jcc-serverlistcache-getconnection/) | verified | high | 2026-11-05 |
| [ImmutableSetMultimap 空 key 检查触发 JSONArray toString：checkEntryNotNull 桥接 DruidXADataSource + HSQL 二次反序列化](web-java-deserialization-immutablesetmultimap-nullkey-checkentrynotnull-tostring/) | verified | high | 2026-11-05 |
| [ImmutableSetMultimap 经 UsingToStringOrdering 触发 JSONArray getter，再走 DruidXADataSource + HSQL 二次反序列化](web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql/) | verified | medium | 2026-11-05 |
| [Jackson POJONode.toString 经 Spring AOP 代理在 JDK17 触发 TemplatesImpl](web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17/) | verified | high | 2026-11-05 |
| [Java 反序列化 payload 长度压缩：Unsafe 空字段、去调试信息与 Deflate 短链](web-java-deserialization-payload-length-compression/) | verified | high | 2026-11-05 |
| [Java 反序列化过滤器 rootChecked 短路：只校验首个白名单类导致 gadget 绕过](web-java-deserialization-filter-rootchecked-first-class-bypass/) | verified | high | 2026-11-05 |
| [JDBC URL WAF 绕过：利用驱动解码与参数解析差异绕过 autoDeserialize 过滤](web-java-deserialization-jdbc-url-waf-parser-bypass/) | verified | medium | 2026-11-05 |
| [JDK 21 下用外部 Xalan-J TemplatesImpl 替代被封装的 Sink](web-java-deserialization-external-xalan-templatesimpl-sink/) | verified | medium | 2026-11-05 |
| [JDK17 原生反序列化：EventListenerList 触发 Spring AOP 链反射调用 TemplatesImpl](web-java-deser-spring-aop-jdk17-templatesimpl-chain/) | verified | high | 2026-11-05 |
| [mapdb linked record 指针改写：8 字节目录穿越写把反序列化重定向到分段 Payload](web-java-deserialization-mapdb-linked-record-pointer-rewrite-deser-rce/) | verified | medium | 2026-11-06 |
| [MyFaces client viewState 反序列化：密钥已知时用 EL gadget 链 RCE](web-java-deserialization-myfaces-client-viewstate-el/) | verified | medium | 2026-11-05 |
| [MySQL JDBC 不出网利用：NamedPipeSocketFactory 读 /proc/self/fd 上传的临时文件触发反序列化](web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress/) | verified | high | 2026-11-05 |
| [ObjectInputStream 漏拦 resolveProxyClass：动态代理 + Hutool MapProxy 二次反序列化绕过黑名单](web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy/) | verified | high | 2026-11-06 |
| [OpenAM jato.clientSession 认证前反序列化：绕过 jato.pageSession 白名单的替代入口（CVE-2026-33439）](web-java-deserialization-openam-jato-clientsession-preauth-rce/) | verified | medium | 2026-11-05 |
| [Parquet Avro schema 指定 record 类经 SpecificData.newInstance 触发构造器 RCE（1.15.2 仍可绕过）](web-java-deserialization-parquet-avro-record-class-constructor-rce/) | verified | high | 2026-11-05 |
| [SerializedLambda 构造可序列化匿名类 + 多接口代理方法优先级：Hutool Singleton 到 Spring XML 加载](web-java-deser-serializedlambda-multiinterface-proxy-gadget/) | verified | high | 2026-11-06 |
| [Spring AOP MethodBeforeAdvice + PriorityQueue 比较器链：绕过危险类黑名单调用任意静态方法写 .so 并 System.load](web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method/) | verified | high | 2026-11-06 |
| [Spring AOP 有参调用 gadget：AspectJAdvice + JdkDynamicAopProxy 经 Hashtable.equals 触发 Map.get](web-java-deserialization-spring-aop-parameterized-advice-gadget/) | verified | high | 2026-11-05 |
| [TarzanCMS 主题包 theme.yaml 触发 SnakeYAML 1.27 反序列化：ScriptEngineManager→URLClassLoader 远程加载 SPI 执行命令](web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce/) | verified | high | 2026-11-05 |
| [TemplatesImpl 非 AbstractTranslet 载荷：构造/静态初始化在 ClassCastException 前执行](web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect/) | verified | high | 2026-11-06 |
| [仅允许 HashMap 的反序列化接口被业务字段滥用：path 直达 FileInputStream 任意文件读取](web-java-deserialization-hashmap-business-field-local-file-read/) | verified | high | 2026-11-05 |
| [反序列化 Getter 链触发 H2 JDBC URL INIT 参数命令执行](web-java-deserialization-h2-jdbc-init-create-alias-rce/) | verified | medium | 2026-11-05 |
| [帆软 /remote/design/channel Gzip+SafeInvocationSerializer 反序列化：V10 前台、V11 后台触发](web-java-deserialization-finereport-channel-gzip-safeinvocation/) | verified | medium | 2026-11-05 |
| [接口动态代理包装 TemplatesImpl 绕过 Jackson/Fastjson 黑名单与 JDK17 模块封装](web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass/) | verified | high | 2026-11-05 |
| [接收任意 Serializable 对象且业务类 readObject 直接 Runtime.exec 导致反序列化 RCE](web-java-deserialization-custom-readobject-runtime-exec/) | verified | high | 2026-11-05 |
| [用友 NC UserSynchronizationServlet 未认证 readObject 入口：/servlet/~uapim 路由叠加 CC6 链 RCE](web-java-deser-yonyou-nc-usersynchronizationservlet/) | verified | high | 2026-11-05 |
| [直接可控 JDBC URL 加 autoDeserialize：恶意 MySQL 服务端返回序列化对象 RCE](web-java-deserialization-mysql-jdbc-url-autodeserialize-rce/) | verified | high | 2026-11-05 |
| [自定义 readObject 反射调用 + RMIConnector 二次反序列化绕过黑名单](web-java-deser-readobject-reflection-rmiconnector-secondary/) | verified | medium | 2026-11-05 |
| [黑名单封禁 javax.swing/java.security 后的 JDK17 Spring 链：HotSwappableTargetSource+XString 接 POJONode/TemplatesImpl](web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
