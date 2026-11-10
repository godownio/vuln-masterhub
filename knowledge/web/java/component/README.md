# Java 组件

## 这层是什么

WebLogic、Tomcat、Confluence、Jenkins 等组件漏洞。

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

- [WebLogic](weblogic/README.md) —— WebLogic 反序列化、T3/IIOP 与历史漏洞。
- [Tomcat](tomcat/README.md) —— Tomcat 漏洞、Session 与文件处理。
- [Confluence](confluence/README.md) —— Confluence OGNL/模板注入与历史漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ActiveMQ Fileserver PUT/MOVE 任意文件写入：search 提取 activemq.home 后将 JSP 移入 webapps 致 RCE（CVE-2016-3088）](web-java-component-activemq-fileserver-put-move-webshell.md) | verified | high | 2026-11-08 |
| [ActiveMQ Jolokia HTTP Discovery 二级 URI 绕过 vm 黑名单致 RCE（CVE-2026-40466）](web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass.md) | verified | high | 2026-11-05 |
| [ActiveMQ Jolokia 默认放行 Broker exec：addNetworkConnector 的 vm brokerConfig 加载远程 Spring XML RCE（CVE-2026-34197）](web-java-component-activemq-jolokia-networkconnector-xbean-rce.md) | verified | high | 2026-11-05 |
| [AJ-Report 分号路径参数绕过 TokenFilter：;swagger-ui 混入 getRequestURI 白名单后仍路由到受保护接口](web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass.md) | verified | high | 2026-11-09 |
| [AJ-Report 前台 ScriptEngine.eval RCE：/dataSetParam/verification 的 validationRules 与 /dataSet/testTransform 的 transformScript 直接执行 JS（1.4.0/1.4.1）](web-java-component-aj-report-scriptengine-eval-rce.md) | verified | high | 2026-11-08 |
| [AJ-Report 数据源测试连接任意 jdbcUrl：恶意 MySQL 服务端 LOAD DATA LOCAL INFILE 读取服务端文件](web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read.md) | verified | high | 2026-11-05 |
| [AJ-Report 默认 JWT 密钥与固定 Share-Token 密钥伪造：自签 admin 令牌 + reportCode=/ 绕过登录缓存](web-java-component-aj-report-default-jwt-sharetoken-forgery.md) | verified | high | 2026-11-09 |
| [Apache Hertzbeat <=1.7.1 后台自定义监控模板 H2 JDBC URL 注入 RCE](web-java-component-hertzbeat-h2-jdbc-url-bypass-rce.md) | verified | high | 2026-11-05 |
| [Apache InLong < 1.12.0 JDBC 反序列化：括号式 host-info URL 绕过 MySQLSensitiveUrlUtils 的 ? 参数黑名单](web-java-component-inlong-cve-2024-26579-jdbc-parenthesis-url-bypass.md) | verified | high | 2026-11-09 |
| [Apache Kafka Client SASL/OAUTHBEARER 可控 token.endpoint.url=file:// 任意文件读取（JWT 校验报错回显）与 SSRF（CVE-2025-27817）](web-java-component-kafka-client-oauthbearer-token-endpoint-url-file-read.md) | verified | high | 2026-11-08 |
| [Apache Karaf Web Console 默认口令 + OSGi Bundle 上传：BundleActivator.start() 直接命令执行](web-java-component-karaf-webconsole-default-login-bundle-upload-rce.md) | verified | high | 2026-11-07 |
| [Apache NiFi 未启用认证 + ExecuteProcess 处理器：在 UI/API 建流执行系统命令，再用 LogMessage+listQueue 取回回显](web-java-component-nifi-unauth-executeprocess-rce.md) | verified | medium | 2026-11-09 |
| [Apache OFBiz CVE-2023-49070：/webtools/control/xmlrpc 预认证 XML-RPC 反序列化 RCE（ysoserial 需 JDK11 生成 payload）](web-java-component-ofbiz-cve-2023-49070-xmlrpc-deserialization-preauth-rce.md) | verified | high | 2026-11-08 |
| [Apache OFBiz CVE-2023-51467：ProgramExport 鉴权绕过（requirePasswordChange=Y）+ groovyProgram Groovy 表达式 RCE](web-java-component-ofbiz-cve-2023-51467-programexport-auth-bypass-groovy-rce.md) | verified | high | 2026-11-08 |
| [Apache OFBiz CVE-2024-32113：ControlFilter 路径遍历/分号参数绕过，未授权访问 ProgramExport 触发 Groovy RCE](web-java-component-ofbiz-cve-2024-32113-controlfilter-traversal-programexport-rce.md) | verified | high | 2026-11-09 |
| [Apache POI xlsx 自定义 XML 映射触发外部 schema 加载（CVE-2019-12415）：xsd:redefine 指向任意地址](web-java-component-poi-xlsx-cve-2019-12415-schema-redirect.md) | verified | medium | 2026-11-08 |
| [Apache Solr Config API 启用 VelocityResponseWriter：wt=velocity 模板注入执行命令](web-java-component-solr-velocityresponsewriter-config-rce.md) | verified | high | 2026-11-07 |
| [Apache Solr CVE-2017-12629：xmlparser XXE 调内部 Config API 添加 RunExecutableListener 实现 RCE](web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce.md) | verified | high | 2026-11-05 |
| [Apache Solr DumpRequestHandler stream.url=file:// 任意文件读取（CVE-2024-45216 认证绕过路径）](web-java-component-solr-dumprequesthandler-file-read.md) | verified | medium | 2026-11-07 |
| [Apache Spark CVE-2023-32007：ACL 开启时 doAs 参数进入 getUnixGroups 的 bash -c 拼接命令注入](web-java-component-spark-cve-2023-32007-doas-acl-bash-c-injection.md) | verified | high | 2026-11-09 |
| [Apache Syncope REST 连接器 testScript 认证后 RCE](web-java-component-syncope-connector-script-rce.md) | verified | high | 2026-11-04 |
| [clickhouse-jdbc localFile + 堆叠 INSERT FROM INFILE：恶意 ClickHouse 服务端读取应用服务器任意文件](web-java-component-clickhouse-jdbc-localfile-stacked-infile-read.md) | verified | high | 2026-11-09 |
| [CVE-2023-52251 Kafka UI GROOVY_SCRIPT 消息过滤未沙箱执行 Groovy：q 参数直接 ProcessBuilder 执行命令（v0.7.1，修复 0.7.2）](web-java-component-kafka-ui-groovy-script-filter-rce.md) | verified | high | 2026-11-08 |
| [CVE-2024-37704 MySQL Connector/J 8.0.x：setBlob/setBinaryStream 文本编码双重转义 5C/27，GBK 宽字节下前导字节吃掉 5C 导致引号逃逸 SQL 注入](web-java-component-mysql-connector-j-cve-2024-37704-setblob-gbk-wide-byte-sqli.md) | verified | high | 2026-11-08 |
| [CVE-2025-48734 Commons BeanUtils 枚举 declaringClass 属性遍历：经 ClassLoader 改写 Tomcat AccessLogValve 写 JSP](web-java-component-commons-beanutils-cve-2025-48734-declaringclass-webshell.md) | verified | high | 2026-11-07 |
| [DataEase /api/plugin/update 插件包更新：zip 内 plugin.json 可控 dsType + 覆盖已安装插件 jar，插件类静态初始化块直接执行任意代码](web-java-component-dataease-plugin-update-zip-malicious-plugin-rce.md) | verified | medium | 2026-11-09 |
| [DataEase CommunityTokenFilter 校验失败后未在 catch 中断（fail-open）+ 伪造 uid=1 JWT 的鉴权绕过](web-java-component-dataease-communitytokenfilter-catch-no-return-auth-bypass.md) | verified | high | 2026-11-08 |
| [DataEase CVE-2024-31441：ClickHouse 数据源额外参数 localFile=true，SQL 数据集堆叠 INFILE 读取服务器文件](web-java-component-dataease-cve-2024-31441-clickhouse-localfile-file-read.md) | verified | high | 2026-11-09 |
| [DataEase 数据源 extraParams 校验：黑名单随请求下发（illegalParameters）导致校验可被清空，配合 autoDeserialize 打通 JDBC 反序列化](web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize.md) | verified | medium | 2026-11-09 |
| [DataEase 数据源 JDBC RCE：type 选 Oracle 绕过 H2 黑名单，JSON 覆盖 driver/jdbcUrl](web-java-component-dataease-json-driver-override-jdbc-rce.md) | verified | high | 2026-11-05 |
| [DataGear 后台 JDBC 驱动上传替换：篡改 Driver.connect 执行命令，覆盖 error.ftl 回显](web-java-component-datagear-jdbc-driver-upload-connect-rce.md) | verified | high | 2026-11-07 |
| [Druid StatViewServlet 监控台整体未鉴权：直接访问 /druid/websession.html 与 websession.json 读取全站会话 ID](web-java-component-druid-statview-unauth-websession-json.md) | verified | high | 2026-11-08 |
| [Druid StatViewServlet 监控台默认口令登录：数据源、SQL、Session 与 classpath 信息泄露](web-java-component-druid-monitor-default-credentials.md) | verified | medium | 2026-11-05 |
| [Druid 监控台弱口令 → URI 监控导出业务路由 → 自增 ID 接口未授权遍历批量拉取 PII](web-java-component-druid-uri-monitor-route-discovery-sequential-id-pii-dump.md) | verified | medium | 2026-11-08 |
| [FastCMS 0.1.6 后台插件上传 RCE：PF4J 加载插件并调用 start() 执行任意 Java 代码](web-java-component-fastcms-plugin-upload-pf4j-start-rce.md) | verified | high | 2026-11-05 |
| [FineReport /view/ReportServer 把 query string 当模板渲染，${sql()} 注入 SQLite 写 JSP](web-java-component-finereport-view-reportserver-template-sqli-webshell.md) | verified | high | 2026-11-05 |
| [FineReport DecisionInterceptor 鉴权绕过：reportlets=/ 使模板鉴权返回 null，配合 op=getSessionID 未认证获取合法 sessionID](web-java-component-finereport-getsessionid-auth-bypass.md) | verified | high | 2026-11-05 |
| [FineReport export/excel 的 params XML Formula 注入：Calculator.evalValue 执行 sql()，借 SQLite VACUUM INTO 写 JSP WebShell](web-java-component-finereport-export-excel-formula-sqli-vacuum-webshell.md) | verified | high | 2026-11-05 |
| [FineReport ReportServer 无会话参数注入 HSQL 堆叠语句，page_content 渲染时二次触发 RCE](web-java-component-finereport-reportserver-hsql-param-rce.md) | verified | high | 2026-11-05 |
| [FineReport v9 print/ie/pdf 的 sessionID 头进入模板渲染，${sql()} 注入 SQLite 写 JSP WebShell](web-java-component-finereport-print-ie-pdf-sqli-webshell.md) | verified | high | 2026-11-05 |
| [flink-streaming-platform-web JAR 任务提交 RCE：任意 jar 上传/服务端下载 + 主类名，经 flink run 在服务器执行](web-java-component-flink-streaming-platform-web-job-jar-rce.md) | verified | high | 2026-11-10 |
| [GeoServer 2.24.2 WFS GetPropertyValue 表达式注入 RCE：exec() 执行命令与 defineAnonymousClass 内存马](web-java-component-geoserver-wfs-getpropertyvalue-exec-rce.md) | verified | high | 2026-11-07 |
| [GeoServer CVE-2021-40822 TestWfsPost SSRF：url+Host 双参数让服务端请求 AWS IMDS 窃取临时凭证](web-java-component-geoserver-cve-2021-40822-testwfspost-ssrf-imds.md) | verified | high | 2026-11-08 |
| [GeoServer CVE-2023-51444 REST CoverageStore 任意文件写入：file 绝对路径 URL 绕过 Paths 校验 + filename ../../ 穿越](web-java-component-geoserver-cve-2023-51444-coveragestore-absolute-url-traversal.md) | verified | high | 2026-11-08 |
| [GeoServer CVE-2024-36401 OGC Filter PropertyName 表达式注入：WFS GetFeature 的 BBOX/Intersects/Between/NotDisjoint/Math 与 WMS GetMap SLD_BODY 经 GeoTools JXPath 执行任意 Java 方法](web-java-component-geoserver-cve-2024-36401-ogc-filter-propertyname-jxpath-rce.md) | verified | high | 2026-11-08 |
| [H2 Console 未授权 JDBC 注入：PostgreSQL loggerFile 写 ASCII JAR + socketFactory 加载 Spring XML RCE](web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce.md) | verified | medium | 2026-11-06 |
| [H2 Console 未授权登录表单：Driver Class 填 javax.naming.InitialContext + rmi/ldap URL 触发 JNDI 注入 RCE](web-java-component-h2-console-unauth-jndi-initialcontext-driver.md) | verified | high | 2026-11-08 |
| [H2 CVE-2022-23221：FORBID_CREATION=TRUE 补丁绕过 + INIT CREATE TRIGGER JavaScript RCE](web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce.md) | verified | high | 2026-11-07 |
| [H2 JDBC URL 过滤绕过：RUN\SCRIPT 转义、双斜杠文件模式与不可见空格](web-java-component-h2-jdbc-url-filter-bypass-runscript.md) | verified | high | 2026-11-05 |
| [H2 JRE-only RCE：无 javac 时用 CREATE ALIAS FOR 静态方法 + Spring ReflectUtils 加载 XML 执行命令](web-java-component-h2-jre-only-create-alias-static-method-rce.md) | verified | medium | 2026-11-07 |
| [H2 的 INIT 只能执行一条语句：出网用 RUNSCRIPT 拉远程 SQL，不出网用 CREATE ALIAS/JS 触发器，INIT 被过滤时改打 TRACE_LEVEL_* 的堆叠执行](web-java-component-h2-init-single-statement-trace-stacked-alias-groovy.md) | verified | medium | 2026-11-09 |
| [h2o-3 <= V3.46.0.8 ImportSQLTable JDBC URL 校验绕过：参数空格/二次 URL 编码 + 恶意 MySQL 服务端 autoDeserialize RCE（CVE-2025-6507/5662/6544）](web-java-component-h2o3-importsqltable-jdbc-url-validation-bypass-rce.md) | verified | high | 2026-11-07 |
| [H3C iMC XVE-2024-4567：Via 请求头命令注入 RCE 与 certutil 分段投递 JSP](web-java-component-h3c-imc-via-header-command-execution.md) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台 delBackup 备份删除：type/fileName 直接拼接导致 ../ 路径穿越任意文件删除](web-java-component-halo-delbackup-path-traversal-file-delete.md) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 getTpl：tplName 未过滤 ../ 路径穿越任意文件读取](web-java-component-halo-theme-gettpl-path-traversal-read.md) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 saveTpl：tplName 无过滤导致 ../ 路径穿越任意文件写入](web-java-component-halo-theme-savetpl-path-traversal-write.md) | verified | medium | 2026-11-05 |
| [HSQLDB 1.8 JavaObject/OBJECT 列反序列化：INSERT…SELECT 类型转换触发 Column.convertObject 与 InOutUtil.deserialize](web-java-component-hsqldb-javaobject-object-column-deserialization.md) | verified | medium | 2026-11-09 |
| [HSQLDB CALL 任意静态方法：JDBC 连接内串联 JNDI、c3p0/Spring 二次反序列化与 defineClass RCE](web-java-component-hsqldb-call-static-method-rce.md) | verified | medium | 2026-11-07 |
| [HSQLDB file 模式：JDBC URL 指定路径落盘与 .script 无盐 MD5 口令摘要泄露](web-java-component-hsqldb-file-mode-script-hash-leak.md) | verified | high | 2026-11-07 |
| [HSQLDB JDBC URL 的 ${} 展开：读取 JVM 系统属性并随连接请求外带（SSRF）](web-java-component-hsqldb-jdbc-url-property-expansion-exfil.md) | verified | high | 2026-11-07 |
| [HugeGraph AuthenticationFilter 鉴权绕过：getUriInfo().getPath() 未归一化 + endsWith 白名单，任意路径追加 ;versions 即跳过认证（CVE-2024-27349）](web-java-component-hugegraph-authenticationfilter-getpath-semicolon-whitelist-bypass.md) | verified | high | 2026-11-09 |
| [HugeGraph-Hubble 图连接 SSRF 链：/versions 跟随 30x 重定向到 HugeGraph GET /gremlin，无图信息也能执行 Gremlin（CVE-2024-27347）](web-java-component-hugegraph-hubble-graph-connections-redirect-ssrf-gremlin.md) | verified | high | 2026-11-09 |
| [JavaMelody /monitoring 未授权：会话列表泄露 JSESSIONID 可劫持在线用户，JNDI/MBeans 泄露密钥文件名与数据库配置](web-java-component-javamelody-monitoring-unauth-session-hijack.md) | verified | medium | 2026-11-07 |
| [JBoss 4.2.3 端口 4446 反序列化：内置 CommonsCollections 3.1 链写文件读 flag](web-java-component-jboss-4-2-3-4446-deserialization.md) | verified | medium | 2026-11-07 |
| [JBoss AS /invoker/readonly CVE-2017-12149：HttpInvoker 反序列化 RCE](web-java-component-jboss-cve-2017-12149-invoker-readonly-deserialization.md) | verified | medium | 2026-11-07 |
| [JDBC 数据源测试重复 url 参数属性走私：& 开头的第二值拼成 socketFactory，绕过字面量过滤加载 Spring XML RCE](web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling.md) | verified | high | 2026-11-05 |
| [Jenkins CLI @ 参数任意文件读取（CVE-2024-23897）：args4j 展开文件内容并回显](web-java-component-jenkins-cli-at-file-arbitrary-read-cve-2024-23897.md) | verified | high | 2026-11-06 |
| [Jenkins 管理员 Script Console 读取 master.key/hudson.util.Secret 解密 credentials.xml 取凭据横向](web-java-component-jenkins-script-console-master-key-credential-decrypt.md) | verified | high | 2026-11-07 |
| [Jetty 11 内存马：遍历 ThreadLocal 取 HttpConnection，请求头执行命令并由响应头回显](web-java-component-jetty11-threadlocal-header-memshell.md) | verified | high | 2026-11-05 |
| [Jetty 9 Filter 内存马：反射取 ServletHandler._filterPathMappings 注入 FilterMapping](web-java-component-jetty9-servlethandler-filter-memshell.md) | verified | high | 2026-11-08 |
| [Jetty 9 Servlet 内存马：反射调用 ServletHandler.addServlet/addServletMapping 注册 ServletHolder](web-java-component-jetty9-servlethandler-servlet-memshell.md) | verified | high | 2026-11-08 |
| [Jetty 9.4.44+ FilterHolder 内存马初始化绕过：setStarted + setServletHandler + initialize](web-java-component-jetty9-filterholder-initialize-bypass.md) | verified | high | 2026-11-08 |
| [Jetty URIUtil.canonicalPath 双斜杠绕过：//..//..// 让 canonical 长度≥2 绕过 doDotsSlash 拒绝，canonicalPath 返回非 null 而调用方仍用原始 subPath 穿越](web-java-component-jetty-uriutil-canonicalpath-double-slash-bypass.md) | verified | high | 2026-11-09 |
| [Jetty XML 配置 + BCEL ClassLoader 内存马：向 webapps 上传 XML 触发静态块，反射注册 Filter 到 ServletHandler](web-java-component-jetty-xml-bcel-filter-memshell.md) | verified | medium | 2026-11-08 |
| [jfinal cms FileManager：path/currentpath 未过滤导致任意文件读/写/下载，jsp 直连被 JFinalFilter 404 后靠改写模板拿 RCE](web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter.md) | verified | high | 2026-11-08 |
| [JimuReport /jmreport/queryFieldBySql 时间盲注：FreeMarker ${} 拼接绕过 sleep 关键词过滤](web-java-component-jimureport-queryfieldbysql-time-blind-sqli.md) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/queryFieldBySql 的 FreeMarker <#include> 任意文件读取](web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read.md) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/save 报表单元格表达式注入：AviatorScript use 或 FreeMarker ?new Execute 执行任意代码](web-java-component-jimureport-save-cell-expression-injection-rce.md) | verified | medium | 2026-11-07 |
| [JimuReport /jmreport/testConnection JDBC URL 注入：H2 init 创建 JavaScript 触发器加载字节码不出网 RCE](web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce.md) | verified | medium | 2026-11-07 |
| [JimuReport 1.5.6 /jmreport/queryFieldBySql 未授权 FreeMarker ?new Execute RCE：SQL 关键字 WAF 只在渲染后检查](web-java-component-jimureport-queryfieldbysql-execute-ssti-rce.md) | verified | high | 2026-11-08 |
| [JimuReport 1.5.6 /jmreport/qurestSql 未授权注入：apiSelectId 取出 jimu_report_db.db_dyn_sql 模板后 id 参数直拼执行](web-java-component-jimureport-qurestsql-dyndb-sql-injection.md) | verified | high | 2026-11-08 |
| [JimuReport FreeMarker SSTI：jeecg.compute 暴露 Aviator 实现沙箱外 RCE（CVE-2026-51086/51087）](web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce.md) | verified | high | 2026-11-05 |
| [JimuReport queryFieldBySql 的 FreeMarker ObjectConstructor 链：经 ScriptEngineManager 取 Nashorn 执行 JS，再用 defineClass 注入内存马；渲染阶段即执行、SQL 报错不代表失败](web-java-component-jimureport-queryfieldbysql-objectconstructor-nashorn-memshell.md) | verified | high | 2026-11-08 |
| [JimuReport TokenInterceptor 鉴权绕过：previousPage + 数据库中不存在的 jmLink/shareToken/JmReport-Share-Token 即放行](web-java-component-jimureport-token-interceptor-jmlink-auth-bypass.md) | verified | high | 2026-11-08 |
| [JimuReport v2.5.1 硬编码打印插件签名 + Aviator 表达式注入未授权 RCE](web-java-component-jimureport-unauth-aviator-rce.md) | verified | high | 2026-11-05 |
| [Karaf/OSGi HttpService 注册内存 Servlet WebShell：BundleActivator 跟踪 HttpService 后 registerServlet](web-java-component-karaf-osgi-httpservice-servlet-memshell.md) | verified | high | 2026-11-07 |
| [Kingbase8 JDBC ConfigurePath 本地属性文件注入：socketFactory 通配符加载临时文件 Spring XML RCE](web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce.md) | verified | high | 2026-11-06 |
| [kkFileView 4.2.0–4.4.0-beta 压缩包预览 Zip Slip：zip 条目 ../ 拼接到 hack.zip_ 缓存目录后未校验，任意文件写入](web-java-component-kkfileview-compress-zipslip-arbitrary-write.md) | verified | high | 2026-11-10 |
| [kkFileView getCorsFile 任意文件读取：读 .bash_history 定位解析缓存目录并下载归档](web-java-component-kkfileview-getcorsfile-bashhistory-cache-artifact.md) | verified | high | 2026-11-06 |
| [kkFileView v4.0.0 getCorsFile 的 urlPath 未限制协议与目标：file:// 任意文件读取与云元数据 SSRF](web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read.md) | verified | high | 2026-11-05 |
| [Litemall 对象存储删除接口 key 未规范化导致任意文件删除](web-java-component-litemall-storage-delete-arbitrary-file.md) | verified | high | 2026-11-05 |
| [MCMS 5.2.4 FileAction 未授权上传：黑名单仅 .exe/.jsp，jspx 与 Windows NTFS ADS ::$DATA 绕过写 WebShell](web-java-component-mcms-fileaction-upload-blacklist-jspx-ads.md) | verified | high | 2026-11-07 |
| [MCMS 5.2.4 双路由前缀鉴权绕过：/ms/** 需登录、无前缀 /cms/** 直接未授权访问](web-java-component-mcms-dual-route-prefix-auth-bypass.md) | verified | high | 2026-11-07 |
| [MCMS 5.2.4 模板 ZIP 解压 Zip Slip：entry 名 ../../test.html 绕过 tempDir 过滤写入 webapp 根目录](web-java-component-mcms-template-unzip-zipslip.md) | verified | high | 2026-11-07 |
| [MCMS 上传路径校验只拦 ../：uploadPath 传绝对路径/根路径绕过 checkUploadPath，模板、Logo 与 file/upload 三处任意目录写文件](web-java-component-mcms-checkuploadpath-absolute-path-upload.md) | verified | high | 2026-11-10 |
| [Metabase CVE-2021-41277：GeoJSON url 参数任意文件读取](web-java-component-metabase-cve-2021-41277-geojson-file-read.md) | verified | high | 2026-11-05 |
| [Nacos /v1/cs/ops/derby 未授权 SQL 查询（CVE-2021-29442）：select 开头即执行，导出用户表与 BCrypt 口令](web-java-component-nacos-derby-ops-unauth-sqli-user-dump.md) | verified | high | 2026-11-08 |
| [Nacos AuthFilter 末尾斜杠绕过：ControllerMethodsCache 取不到 method 时直接放行请求](web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass.md) | verified | high | 2026-11-08 |
| [Nacos Derby 未授权到 RCE：/v1/cs/ops/data/removal 导入 SQL，sqlj.install_jar / EXPORT_QUERY_LOBS_TO_EXTFILE / create type external 加载恶意类](web-java-component-nacos-derby-removal-sqlj-install-jar-rce.md) | verified | high | 2026-11-08 |
| [Nacos serverIdentity 请求头鉴权绕过：配置 server.identity.key/value 后带对应头即跳过 JWT 校验](web-java-component-nacos-server-identity-header-auth-bypass.md) | verified | high | 2026-11-08 |
| [Nacos 默认 token.secret.key：用公开默认密钥 HS256 伪造 accessToken 绕过鉴权](web-java-component-nacos-default-token-secret-key-jwt-forge.md) | verified | high | 2026-11-08 |
| [Nacos 默认配置 nacos.core.auth.enabled=false：未授权访问 v1/auth/users 枚举/新建用户并登录控制台](web-java-component-nacos-default-auth-disabled-user-admin.md) | verified | high | 2026-11-08 |
| [Netty ChannelPipeline 内存马：替换 doOnChannelInit 注入恶意 Handler](web-java-component-netty-pipeline-memshell.md) | verified | high | 2026-11-05 |
| [O2OA 默认口令登录后「添加接口」驻入 Java.type 代码，通过 JNDI 外带实现 RCE](web-java-component-o2oa-default-credential-invoke-jndi-rce.md) | verified | high | 2026-11-08 |
| [ONLYOFFICE Document Server 存储 key 路径穿越导致任意文件写](web-java-component-onlyoffice-storage-key-path-traversal-file-write.md) | verified | medium | 2026-11-05 |
| [ONLYOFFICE runtime.json 热加载与配置合并导致安全开关静默降级](web-java-component-onlyoffice-runtime-config-hot-reload-downgrade.md) | verified | medium | 2026-11-05 |
| [PgJDBC CVE-2022-21724：可控 JDBC URL 的 socketFactory/socketFactoryArg 实例化 ClassPathXmlApplicationContext 加载 Spring XML RCE](web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce.md) | verified | high | 2026-11-07 |
| [PostgreSQL JDBC 的 loggerLevel/loggerFile 当任意文件写用：把 JSP 代码塞进 URL，靠 = 截断让驱动把 shell 写进 Web 目录](web-java-component-pgjdbc-loggerfile-jsp-webshell-file-write.md) | verified | medium | 2026-11-09 |
| [PublicCMS savePlaceMetaData 任意文件上传（CVE-2024-40550）：path 仅删除 ".."，可向 include 目录写入任意 HTML 造成同源存储型 XSS](web-java-component-publiccms-saveplacemetadata-upload-stored-xss.md) | verified | high | 2026-11-08 |
| [PublicCMS 模板替换路径穿越改写预置脚本，配合 execScript 执行导致 RCE](web-java-component-publiccms-template-replace-traversal-execscript-rce.md) | verified | medium | 2026-11-07 |
| [Smartbi RMIServlet 反射调用 DataSourceService：DB2 JDBC clientRerouteServerListJNDIName 触发 JNDI RCE](web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce.md) | verified | medium | 2026-11-05 |
| [Smartbi RMIServlet 服务端 JS/Rhino 表达式执行：checkExpression 与 checkJavaScript 命令执行](web-java-component-smartbi-rmiservlet-js-rhino-expression-rce.md) | verified | medium | 2026-11-05 |
| [Smartbi V10 *.stub + jsonpCallback：GET 转 POST 绕过仅拦 POST 的 DB2 RCE 补丁](web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass.md) | verified | medium | 2026-11-05 |
| [Smartbi V10 windowUnloading 参数分裂：鉴权检查与 RMIServlet 实际调用方法不一致的绕过](web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass.md) | verified | medium | 2026-11-05 |
| [UEditor Java 上传文件名 JSON 注入：BaseState 字符串拼接污染下游 JSON 解析与 fastjson](web-java-component-ueditor-filename-json-injection-parse-sink.md) | verified | high | 2026-11-09 |
| [VMware vCenter CVE-2021-22005：CEIP analytics 代理路径穿越 + Velocity 写 JSP 到 vSphere ROOT，/idm/..;/ 访问 root Webshell](web-java-component-vcenter-cve-2021-22005-ceip-analytics-agent-jsp-file-write.md) | verified | high | 2026-11-08 |
| [WSO2 API Manager 数据源测试 SOAP 接口：H2 validationQuery 用 CSVWRITE+FILE_READ 写 webapp 读 flag](web-java-component-wso2-ndatasourceadmin-h2-validationquery-file-read.md) | verified | high | 2026-11-06 |
| [XXL-Job Executor 1.9.2 瘦身版 Jetty 内存马：从线程栈反射取 JettyServer 的 HandlerCollection，向 _handlers 前置恶意 Handler](web-java-component-xxl-job-executor-jetty-handler-collection-memshell.md) | verified | high | 2026-11-09 |
| [XXL-JOB executor 9999 未授权命令执行：直接 POST /run 覆盖 GLUE 脚本，gluesource 落盘成为取证点](web-java-component-xxl-job-executor-unauth-run-glue-rce.md) | verified | high | 2026-11-09 |
| [YAMCS 算法脚本 java-expression 注入：Runtime.exec 执行并用输出参数回显](web-java-component-yamcs-algorithm-java-expression-rce.md) | verified | medium | 2026-11-07 |
| [Zimbra RestFilter 参数名直转 request 属性：注入 javax.servlet.include.servlet_path 触发 /h/rest 本地文件包含（CVE-2025-68645）](web-java-component-zimbra-restfilter-param-attribute-lfi.md) | verified | high | 2026-11-05 |
| [ZooKeeper AdminServer IP 认证绕过：伪造 X-Forwarded-For 冒充 127.0.0.1](web-java-component-zookeeper-admin-ip-auth-bypass.md) | verified | high | 2026-11-05 |
| [东方通 TongWeb 控制台 twusers.properties 初始口令未改导致后台登录](web-java-component-tongweb-default-console-credentials.md) | verified | medium | 2026-11-05 |
| [低代码平台数据源配置校验接口 JDBC URL 注入：H2 init CREATE TRIGGER JavaScript 不出网 RCE](web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce.md) | verified | medium | 2026-11-06 |
| [原始 Netty ServerBootstrapAcceptor.childHandler 替换：全局 Handler 内存马与 cmd 头回显](web-java-component-netty-serverbootstrapacceptor-childhandler-memshell.md) | verified | high | 2026-11-07 |
| [大华智慧园区 attachment_clearTempFile.action：bean.recId 字符串拼接 SQL 注入](web-java-component-dahua-attachment-cleartempfile-recid-sqli.md) | verified | medium | 2026-11-07 |
| [大华智慧园区 AttachmentAction downloadByUrlAtt：filePath 直入 URL.openStream 任意文件读取](web-java-component-dahua-attachment-downloadbyurlatt-fileread.md) | verified | high | 2026-11-07 |
| [大华智慧园区 deleteFtp 接口 Fastjson 1.2.44 反序列化 RCE（JdbcRowSetImpl JNDI）](web-java-component-dahua-swingcardrecord-deleteftp-fastjson.md) | verified | medium | 2026-11-07 |
| [大华智慧园区 emap devicePoint_addImgIco 任意文件上传：后缀取自上传文件名并写入 webapps/upload/emap/society_new](web-java-component-dahua-emap-devicepoint-addingico-upload.md) | verified | high | 2026-11-09 |
| [大华智慧园区 emap MyInterceptor 鉴权绕过：permission 默认 true 且 catch 吞异常，hasSubsystem=true 触发 NPE 即放行](web-java-component-dahua-emap-myinterceptor-catch-auth-bypass.md) | verified | high | 2026-11-09 |
| [大华智慧园区 getFaceCapture 分页 orderBy 报错注入：CXF WebService 将排序字段直接拼入 order by](web-java-component-dahua-getfacecapture-orderby-sqli.md) | verified | high | 2026-11-09 |
| [大华智慧园区 MaterialController 任意文件上传：原始文件名与内容直写 Web 目录](web-java-component-dahua-material-file-upload-webshell.md) | verified | medium | 2026-11-07 |
| [大华智慧园区 MyBatis ORDER BY 排序参数 SQL 注入（Material/Player bycondition 接口）](web-java-component-dahua-wpms-mybatis-orderby-sqli.md) | verified | medium | 2026-11-07 |
| [大华智慧园区 publishing UserAuthenticationFilter 路径包含即放行：/publishing/publishing/* 与 css/js/png/gif 后缀全模块未授权](web-java-component-dahua-publishing-userauthenticationfilter-path-whitelist-bypass.md) | verified | high | 2026-11-09 |
| [大华智慧园区 user_getUserInfoByUserName 未授权泄露 loginPass：按 md5(loginName:dss:password) 规则爆破管理员口令](web-java-component-dahua-usergetuserinfobyusername-unauth-hash-leak.md) | verified | high | 2026-11-09 |
| [契约锁 OFD 上传 Zip Slip 覆盖热补丁 JAR：热加载 static 块执行 RCE](web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce.md) | verified | medium | 2026-11-07 |
| [契约锁安全补丁 security.rsc 硬编码 RSA 私钥：离线解密还原 PdfverifierPreventWrapper 过滤配置](web-java-component-qiyuesuo-security-rsc-hardcoded-rsa-key-decrypt.md) | verified | medium | 2026-11-07 |
| [帆软 FineReport largedataset/export/excel 的 functionParams 注入 Formula：evalValue 执行 SQL() 函数](web-java-component-finereport-largedataset-export-excel-formula-sqli.md) | verified | medium | 2026-11-05 |
| [帆软 FineReport 内置测试用户统一默认口令 123456 登录管理后台（CNVD-2024-37222）](web-java-component-finereport-builtin-user-default-password.md) | verified | high | 2026-11-05 |
| [泛微 e-cology 10 DataConnController JDBC URL 注入：任意驱动加载 + H2 init JavaScript 触发器 RCE（含 MySQL 文件读取/DB2 JNDI）](web-java-component-weaver-ecology10-dataconn-jdbc-h2-init-rce.md) | verified | medium | 2026-11-07 |
| [泛微 e-cology 后台 JDBC socketFactory 加载上传 XML 注入内存马：materialLib 上传 + datasource 测试链](web-java-component-weaver-ecology-jdbc-socketfactory-memshell.md) | draft | high | 2026-11-05 |
| [泛微 E10 addMysqlMonitor 未授权 JDBC URL：allowLoadLocalInfile=true + 恶意 MySQL 服务端读取服务器文件](web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read.md) | verified | high | 2026-11-07 |
| [海康威视综合安防 /center/api/installation/detection 未授权命令注入：machines.id 经 assembleCheckInstallEnvs/convertExecuteCommand 进入 analysisCmdexeExecuteResult](web-java-component-hikvision-isecure-installation-detection-rce.md) | verified | medium | 2026-11-08 |
| [海康威视综合安防 iSecure Center 任意文件上传：文件名路径穿越写 JSP GetShell](web-java-component-hikvision-isecure-file-upload-path-traversal-rce.md) | verified | high | 2026-11-05 |
| [用友 NC 6.5 CourseWareAction.download fileName 路径穿越任意文件读取（web.xml 回显）](web-java-component-yonyou-nc65-courseware-download-fileread.md) | verified | high | 2026-11-06 |
| [用友 NC ComboOperTools importCombo JAXB XXE：setExpandEntityReferences(false) 仍解析外部实体并 OOB 读文件](web-java-component-yonyou-nc-comboopertools-importcombo-jaxb-xxe.md) | verified | high | 2026-11-07 |
| [用友 NC6.5 MtAppTimeLineAction doApply SQL 注入：meapk 拼接绕过 sqlEncode 的 chrw 包装](web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli.md) | verified | high | 2026-11-06 |
| [用友 NCCloud GatewayServlet 反射调用 ProcessFileUtils 命令拼接 RCE](web-java-component-yonyou-nccloud-gateway-reflection-command-injection.md) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud NCCloudGatewayServlet 反射调用 IFileTrans 任意文件上传写 WebShell](web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload.md) | verified | high | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet InvocationInfo.readExternal 嵌套反序列化：白名单外壳内嵌 CC6/TemplatesImpl 绕过 token 直接 RCE](web-java-component-yonyou-u8-servicedispatcher-invocationinfo-readexternal-cc6.md) | verified | medium | 2026-11-07 |
| [用友 U8 Cloud ServiceDispatcherServlet 补丁绕过：硬编码 tenantId 伪造 token + 长度前缀 InvocationInfo 反序列化写 WebShell](web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload.md) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet：InvocationInfo 反序列化 + 硬编码 tokenSeed 伪造 token 反射调用文件写入方法 getshell](web-java-component-yonyou-u8-servicedispatcher-invocationinfo-token-file-write.md) | verified | high | 2026-11-05 |
| [用友 U8-OA 基础版 operaFileActionController.jsp：path/context 任意文件覆盖写 JSP getshell](web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite.md) | verified | high | 2026-11-08 |
| [用友 U8C 暴露 BeanShell Servlet：/servlet/~ic/bsh.servlet.BshServlet 未鉴权执行脚本，certutil 拉取 JSP WebShell](web-java-component-yonyou-u8c-bsh-servlet-beanshell-exec.md) | verified | medium | 2026-11-08 |
| [用友 U8Cloud NCCloudGatewayServlet 20250924 补丁分析：ts+HMAC 校验仍以硬编码 nctoken 为密钥，旧 RCE 链被黑名单封堵](web-java-component-yonyou-u8cloud-nccloudgateway-20250924-patch-hmac-auth-bypass.md) | verified | medium | 2026-11-07 |
| [用友时空 KSOA ImageUpload servlet 任意文件上传：filepath/filename 参数把 JSP 写进 Web 根](web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload.md) | verified | medium | 2026-11-08 |
| [用友时空 KSOA 未授权 JSP SQL 注入：PreviewKPQT/PrintZP*/PrintZPYG/fillKP 等十余处参数直接拼接（MSSQL）](web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint.md) | verified | high | 2026-11-08 |
| [网动 ActiveUC gsCheckUser 未鉴权 XXE：AuthorizedInfo 直入 dom4j DocumentHelper.parseText](web-java-component-activeuc-gscheckuser-dom4j-xxe.md) | verified | medium | 2026-11-06 |
| [网动 ActiveUC meetingShow!downloadDocument 未鉴权 filePath 路径穿越任意文件读取](web-java-component-activeuc-meetingshow-downloaddocument-arbitrary-file-read.md) | verified | high | 2026-11-06 |
| [网动 ActiveUC user!exportUsers 登录后 iBATIS $ 拼接 SQL 注入（temps → PK_TEMP IN）](web-java-component-activeuc-exportusers-ibatis-dollar-sqli.md) | verified | medium | 2026-11-06 |
| [网动 ActiveUC versionCtr!editVersion 未鉴权 ZIP 上传：解压目录穿越 + jsp/jspx 后缀过滤与 ::$DATA 绕过](web-java-component-activeuc-versionctr-upload-unzip-zipslip.md) | verified | medium | 2026-11-06 |
| [致远 OA autoinstall.do 前台未授权，login_locale Cookie 目录穿越下载任意 ZIP](web-java-component-seeyon-autoinstall-login-locale-zip-traversal.md) | verified | high | 2026-11-05 |
| [致远 OA xrdController.do checkIsSign 文件名目录穿越：覆盖已有 JSP 致 RCE](web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal.md) | verified | medium | 2026-11-05 |
| [蓝凌 EKP dataxml.jsp 的 s_bean=sysFormulaSimulateByJS：script 参数经 BeanShell 解释器执行命令](web-java-component-landray-ekp-dataxml-sbean-beanshell-rce.md) | verified | high | 2026-11-08 |
| [蓝凌 EKP V16 SysUiComponent#replaceExtend 未鉴权目录复制：把受保护 JSP 目录搬到匿名路径实现前台 RCE](web-java-component-landray-ekp-sysuicomponent-replaceextend-directory-copy.md) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
