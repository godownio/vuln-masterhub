---
title: Java 组件
weight: 1
---

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

- [WebLogic](weblogic/) —— WebLogic 反序列化、T3/IIOP 与历史漏洞。
- [Tomcat](tomcat/) —— Tomcat 漏洞、Session 与文件处理。
- [Confluence](confluence/) —— Confluence OGNL/模板注入与历史漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ActiveMQ Fileserver PUT/MOVE 任意文件写入：search 提取 activemq.home 后将 JSP 移入 webapps 致 RCE（CVE-2016-3088）](web-java-component-activemq-fileserver-put-move-webshell/) | verified | high | 2026-11-08 |
| [ActiveMQ Jolokia HTTP Discovery 二级 URI 绕过 vm 黑名单致 RCE（CVE-2026-40466）](web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass/) | verified | high | 2026-11-05 |
| [ActiveMQ Jolokia 认证后任意文件写入：LoggerContextAdminMBean / FlightRecorderMXBean 写 JSP Webshell（CVE-2022-41678）](web-java-component-activemq-jolokia-arbitrary-file-write-cve-2022-41678/) | verified | high | 2026-11-11 |
| [ActiveMQ Jolokia 默认放行 Broker exec：addNetworkConnector 的 vm brokerConfig 加载远程 Spring XML RCE（CVE-2026-34197）](web-java-component-activemq-jolokia-networkconnector-xbean-rce/) | verified | high | 2026-11-05 |
| [Adobe ColdFusion CVE-2023-26360：cfclient 请求的 _metadata.classname 模板编译未授权任意文件读取与 RCE](web-java-component-coldfusion-cve-2023-26360-cfclient-template-rce/) | verified | high | 2026-11-12 |
| [AJ-Report 分号路径参数绕过 TokenFilter：;swagger-ui 混入 getRequestURI 白名单后仍路由到受保护接口](web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass/) | verified | high | 2026-11-09 |
| [AJ-Report 前台 ScriptEngine.eval RCE：/dataSetParam/verification 的 validationRules 与 /dataSet/testTransform 的 transformScript 直接执行 JS（1.4.0/1.4.1）](web-java-component-aj-report-scriptengine-eval-rce/) | verified | high | 2026-11-08 |
| [AJ-Report 数据源测试连接任意 jdbcUrl：恶意 MySQL 服务端 LOAD DATA LOCAL INFILE 读取服务端文件](web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read/) | verified | high | 2026-11-05 |
| [AJ-Report 默认 JWT 密钥与固定 Share-Token 密钥伪造：自签 admin 令牌 + reportCode=/ 绕过登录缓存](web-java-component-aj-report-default-jwt-sharetoken-forgery/) | verified | high | 2026-11-09 |
| [Allegra AttachmentGlobalAction#download 任意文件读取：fileName 未过滤读 GeneralSettings.properties 取 JWT 签名密钥（CVE-2024-22507）](web-java-component-allegra-download-attachment-filename-traversal-jwt-key/) | verified | high | 2026-11-11 |
| [Allegra branding!uploadFile 任意文件上传：uploadedFileName 与 fileToReplace 可控，路径/后缀不限（CVE-2024-22510）](web-java-component-allegra-branding-uploadfile-path-traversal/) | verified | high | 2026-11-11 |
| [Allegra importFromAllegraFormat zipslip：ZipEntry.getName 未校验，解压穿越任意写文件（CVE-2024-22504）](web-java-component-allegra-import-allegra-format-zipslip/) | verified | medium | 2026-11-11 |
| [Apache DolphinScheduler Switch 任务条件 ScriptEngine.eval RCE：CVE-2023-49299 与 CVE-2024-23320 变量替换引号闭合绕过](web-java-component-dolphinscheduler-switch-scriptengine-eval-rce/) | verified | high | 2026-11-11 |
| [Apache Hertzbeat <=1.7.1 后台自定义监控模板 H2 JDBC URL 注入 RCE](web-java-component-hertzbeat-h2-jdbc-url-bypass-rce/) | verified | high | 2026-11-05 |
| [Apache InLong < 1.12.0 JDBC 反序列化：括号式 host-info URL 绕过 MySQLSensitiveUrlUtils 的 ? 参数黑名单](web-java-component-inlong-cve-2024-26579-jdbc-parenthesis-url-bypass/) | verified | high | 2026-11-09 |
| [Apache Jackrabbit RMI /rmi 端点反序列化 SimpleCredentials.attributes：CB1 链无认证 RCE（CVE-2023-37895）](web-java-component-jackrabbit-rmi-simplecredentials-cb1-rce/) | verified | high | 2026-11-13 |
| [Apache Kafka Client SASL/OAUTHBEARER 可控 token.endpoint.url=file:// 任意文件读取（JWT 校验报错回显）与 SSRF（CVE-2025-27817）](web-java-component-kafka-client-oauthbearer-token-endpoint-url-file-read/) | verified | high | 2026-11-08 |
| [Apache Karaf Web Console 默认口令 + OSGi Bundle 上传：BundleActivator.start() 直接命令执行](web-java-component-karaf-webconsole-default-login-bundle-upload-rce/) | verified | high | 2026-11-07 |
| [Apache NiFi 未启用认证 + ExecuteProcess 处理器：在 UI/API 建流执行系统命令，再用 LogMessage+listQueue 取回回显](web-java-component-nifi-unauth-executeprocess-rce/) | verified | medium | 2026-11-09 |
| [Apache OFBiz CacheFilter 精确 URI 检查绕过：路径矩阵参数 /control/xmlrpc/;/ 躲开 </serializable 安检，叠加 requirePasswordChange=Y 预认证复活 XML-RPC 反序列化](web-java-component-ofbiz-cachefilter-matrix-uri-xmlrpc-bypass/) | verified | high | 2026-11-12 |
| [Apache OFBiz CVE-2023-49070：/webtools/control/xmlrpc 预认证 XML-RPC 反序列化 RCE（ysoserial 需 JDK11 生成 payload）](web-java-component-ofbiz-cve-2023-49070-xmlrpc-deserialization-preauth-rce/) | verified | high | 2026-11-08 |
| [Apache OFBiz CVE-2023-51467 getJSONuiLabelArray 未授权 SSRF 与任意配置文件读取：requiredLabels 键名直达 UtilProperties URL 解析](web-java-component-ofbiz-cve-2023-51467-getjsonuilabelarray-ssrf-lfr/) | verified | high | 2026-11-12 |
| [Apache OFBiz CVE-2023-51467：ProgramExport 鉴权绕过（requirePasswordChange=Y）+ groovyProgram Groovy 表达式 RCE](web-java-component-ofbiz-cve-2023-51467-programexport-auth-bypass-groovy-rce/) | verified | high | 2026-11-08 |
| [Apache OFBiz CVE-2024-25065：LoginWorker.hasBasePermission 用未规范化的 contextPath 查 Webapp 失败后默认放行，低权限账号可登录并越权访问 webtools](web-java-component-ofbiz-cve-2024-25065-loginworker-contextpath-auth-bypass/) | verified | high | 2026-11-11 |
| [Apache OFBiz CVE-2024-32113：ControlFilter 路径遍历/分号参数绕过，未授权访问 ProgramExport 触发 Groovy RCE](web-java-component-ofbiz-cve-2024-32113-controlfilter-traversal-programexport-rce/) | verified | high | 2026-11-09 |
| [Apache POI xlsx 自定义 XML 映射触发外部 schema 加载（CVE-2019-12415）：xsd:redefine 指向任意地址](web-java-component-poi-xlsx-cve-2019-12415-schema-redirect/) | verified | medium | 2026-11-08 |
| [Apache Solr Config API 启用 VelocityResponseWriter：wt=velocity 模板注入执行命令](web-java-component-solr-velocityresponsewriter-config-rce/) | verified | high | 2026-11-07 |
| [Apache Solr CVE-2017-12629：xmlparser XXE 调内部 Config API 添加 RunExecutableListener 实现 RCE](web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce/) | verified | high | 2026-11-05 |
| [Apache Solr DataImportHandler dataConfig XXE：FTP OOB 外带读取文件与目录](web-java-component-solr-dataimport-dataconfig-xxe-ftp-oob/) | verified | high | 2026-11-12 |
| [Apache Solr DumpRequestHandler stream.url=file:// 任意文件读取（CVE-2024-45216 认证绕过路径）](web-java-component-solr-dumprequesthandler-file-read/) | verified | medium | 2026-11-07 |
| [Apache Spark CVE-2023-32007：ACL 开启时 doAs 参数进入 getUnixGroups 的 bash -c 拼接命令注入](web-java-component-spark-cve-2023-32007-doas-acl-bash-c-injection/) | verified | high | 2026-11-09 |
| [Apache Syncope REST 连接器 testScript 认证后 RCE](web-java-component-syncope-connector-script-rce/) | verified | high | 2026-11-04 |
| [Apereo CAS 5.3.16 默认口令 + /status/heapdump 泄露 flow execution 加密/签名密钥 → 伪造 execution 参数执行命令](web-java-component-apereo-cas-heapdump-flow-execution-key-forgery/) | verified | medium | 2026-11-10 |
| [clickhouse-jdbc localFile + 堆叠 INSERT FROM INFILE：恶意 ClickHouse 服务端读取应用服务器任意文件](web-java-component-clickhouse-jdbc-localfile-stacked-infile-read/) | verified | high | 2026-11-09 |
| [CVE-2023-52251 Kafka UI GROOVY_SCRIPT 消息过滤未沙箱执行 Groovy：q 参数直接 ProcessBuilder 执行命令（v0.7.1，修复 0.7.2）](web-java-component-kafka-ui-groovy-script-filter-rce/) | verified | high | 2026-11-08 |
| [CVE-2024-23897 读取行数差异：未授权 who-am-i/help 仅回显 1-2 行，Overall/Read + multiValued 命令（connect-node）可全量读取](web-java-component-jenkins-cve-2024-23897-args4j-line-limit-multivalued/) | verified | high | 2026-11-12 |
| [CVE-2024-37704 MySQL Connector/J 8.0.x：setBlob/setBinaryStream 文本编码双重转义 5C/27，GBK 宽字节下前导字节吃掉 5C 导致引号逃逸 SQL 注入](web-java-component-mysql-connector-j-cve-2024-37704-setblob-gbk-wide-byte-sqli/) | verified | high | 2026-11-08 |
| [CVE-2025-48734 Commons BeanUtils 枚举 declaringClass 属性遍历：经 ClassLoader 改写 Tomcat AccessLogValve 写 JSP](web-java-component-commons-beanutils-cve-2025-48734-declaringclass-webshell/) | verified | high | 2026-11-07 |
| [DataEase /api/plugin/update 插件包更新：zip 内 plugin.json 可控 dsType + 覆盖已安装插件 jar，插件类静态初始化块直接执行任意代码](web-java-component-dataease-plugin-update-zip-malicious-plugin-rce/) | verified | medium | 2026-11-09 |
| [DataEase <1.18.15 / <2.3.0 MySQL 数据源 JDBC 黑名单 URL 编码绕过（CVE-2024-23328）：allowLoadLocalInfile 编码键名后经恶意 MySQL 服务端读服务器文件](web-java-component-dataease-cve-2024-23328-jdbc-url-encoded-blacklist-bypass-local-infile-read/) | verified | high | 2026-11-12 |
| [DataEase CommunityTokenFilter 校验失败后未在 catch 中断（fail-open）+ 伪造 uid=1 JWT 的鉴权绕过](web-java-component-dataease-communitytokenfilter-catch-no-return-auth-bypass/) | verified | high | 2026-11-08 |
| [DataEase CVE-2024-31441：ClickHouse 数据源额外参数 localFile=true，SQL 数据集堆叠 INFILE 读取服务器文件](web-java-component-dataease-cve-2024-31441-clickhouse-localfile-file-read/) | verified | high | 2026-11-09 |
| [DataEase 数据源 extraParams 校验：黑名单随请求下发（illegalParameters）导致校验可被清空，配合 autoDeserialize 打通 JDBC 反序列化](web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize/) | verified | medium | 2026-11-09 |
| [DataEase 数据源 JDBC RCE：type 选 Oracle 绕过 H2 黑名单，JSON 覆盖 driver/jdbcUrl](web-java-component-dataease-json-driver-override-jdbc-rce/) | verified | high | 2026-11-05 |
| [DataGear 后台 JDBC 驱动上传替换：篡改 Driver.connect 执行命令，覆盖 error.ftl 回显](web-java-component-datagear-jdbc-driver-upload-connect-rce/) | verified | high | 2026-11-07 |
| [DolphinScheduler 数据源连接 JDBC URL 双层过滤绕过：URL 编码键名绕过 contains 黑名单 +](web-java-component-dolphinscheduler-datasource-connect-jdbc-url-filter-bypass-file-read/) | verified | high | 2026-11-11 |
| [Druid StatViewServlet 监控台整体未鉴权：直接访问 /druid/websession.html 与 websession.json 读取全站会话 ID](web-java-component-druid-statview-unauth-websession-json/) | verified | high | 2026-11-08 |
| [Druid StatViewServlet 监控台默认口令登录：数据源、SQL、Session 与 classpath 信息泄露](web-java-component-druid-monitor-default-credentials/) | verified | medium | 2026-11-05 |
| [Druid 监控台弱口令 → URI 监控导出业务路由 → 自增 ID 接口未授权遍历批量拉取 PII](web-java-component-druid-uri-monitor-route-discovery-sequential-id-pii-dump/) | verified | medium | 2026-11-08 |
| [FastCMS 0.1.6 后台插件上传 RCE：PF4J 加载插件并调用 start() 执行任意 Java 代码](web-java-component-fastcms-plugin-upload-pf4j-start-rce/) | verified | high | 2026-11-05 |
| [FineReport /view/ReportServer 把 query string 当模板渲染，${sql()} 注入 SQLite 写 JSP](web-java-component-finereport-view-reportserver-template-sqli-webshell/) | verified | high | 2026-11-05 |
| [FineReport DecisionInterceptor 鉴权绕过：reportlets=/ 使模板鉴权返回 null，配合 op=getSessionID 未认证获取合法 sessionID](web-java-component-finereport-getsessionid-auth-bypass/) | verified | high | 2026-11-05 |
| [FineReport export/excel 的 params XML Formula 注入：Calculator.evalValue 执行 sql()，借 SQLite VACUUM INTO 写 JSP WebShell](web-java-component-finereport-export-excel-formula-sqli-vacuum-webshell/) | verified | high | 2026-11-05 |
| [FineReport ReportServer 无会话参数注入 HSQL 堆叠语句，page_content 渲染时二次触发 RCE](web-java-component-finereport-reportserver-hsql-param-rce/) | verified | high | 2026-11-05 |
| [FineReport v9 print/ie/pdf 的 sessionID 头进入模板渲染，${sql()} 注入 SQLite 写 JSP WebShell](web-java-component-finereport-print-ie-pdf-sqli-webshell/) | verified | high | 2026-11-05 |
| [flink-streaming-platform-web JAR 任务提交 RCE：任意 jar 上传/服务端下载 + 主类名，经 flink run 在服务器执行](web-java-component-flink-streaming-platform-web-job-jar-rce/) | verified | high | 2026-11-10 |
| [GeoServer 2.24.2 WFS GetPropertyValue 表达式注入 RCE：exec() 执行命令与 defineAnonymousClass 内存马](web-java-component-geoserver-wfs-getpropertyvalue-exec-rce/) | verified | high | 2026-11-07 |
| [GeoServer CVE-2021-40822 TestWfsPost SSRF：url+Host 双参数让服务端请求 AWS IMDS 窃取临时凭证](web-java-component-geoserver-cve-2021-40822-testwfspost-ssrf-imds/) | verified | high | 2026-11-08 |
| [GeoServer CVE-2023-43795 WPS Reference SSRF：Execute 请求 xlink:href 由服务端 RemoteRequestInputProvider 取回并支持自定义 Header](web-java-component-geoserver-cve-2023-43795-wps-reference-ssrf/) | verified | high | 2026-11-13 |
| [GeoServer CVE-2023-51444 REST CoverageStore 任意文件写入：file 绝对路径 URL 绕过 Paths 校验 + filename ../../ 穿越](web-java-component-geoserver-cve-2023-51444-coveragestore-absolute-url-traversal/) | verified | high | 2026-11-08 |
| [GeoServer CVE-2024-36401 OGC Filter PropertyName 表达式注入：WFS GetFeature 的 BBOX/Intersects/Between/NotDisjoint/Math 与 WMS GetMap SLD_BODY 经 GeoTools JXPath 执行任意 Java 方法](web-java-component-geoserver-cve-2024-36401-ogc-filter-propertyname-jxpath-rce/) | verified | high | 2026-11-08 |
| [H2 Console 未授权 JDBC 注入：PostgreSQL loggerFile 写 ASCII JAR + socketFactory 加载 Spring XML RCE](web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce/) | verified | medium | 2026-11-06 |
| [H2 Console 未授权登录表单：Driver Class 填 javax.naming.InitialContext + rmi/ldap URL 触发 JNDI 注入 RCE](web-java-component-h2-console-unauth-jndi-initialcontext-driver/) | verified | high | 2026-11-08 |
| [H2 CREATE ALIAS 受限环境 RCE：File.createTempFile + FileUtils 分块写 .so，MethodUtils 反射 System.load](web-java-component-h2-create-alias-file-write-system-load/) | verified | high | 2026-11-11 |
| [H2 CVE-2022-23221：FORBID_CREATION=TRUE 补丁绕过 + INIT CREATE TRIGGER JavaScript RCE](web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce/) | verified | high | 2026-11-07 |
| [H2 JDBC URL 过滤绕过：RUN\SCRIPT 转义、双斜杠文件模式与不可见空格](web-java-component-h2-jdbc-url-filter-bypass-runscript/) | verified | high | 2026-11-05 |
| [H2 JRE-only RCE：无 javac 时用 CREATE ALIAS FOR 静态方法 + Spring ReflectUtils 加载 XML 执行命令](web-java-component-h2-jre-only-create-alias-static-method-rce/) | verified | medium | 2026-11-07 |
| [H2 的 INIT 只能执行一条语句：出网用 RUNSCRIPT 拉远程 SQL，不出网用 CREATE ALIAS/JS 触发器，INIT 被过滤时改打 TRACE_LEVEL_* 的堆叠执行](web-java-component-h2-init-single-statement-trace-stacked-alias-groovy/) | verified | medium | 2026-11-09 |
| [h2o-3 <= V3.46.0.8 ImportSQLTable JDBC URL 校验绕过：参数空格/二次 URL 编码 + 恶意 MySQL 服务端 autoDeserialize RCE（CVE-2025-6507/5662/6544）](web-java-component-h2o3-importsqltable-jdbc-url-validation-bypass-rce/) | verified | high | 2026-11-07 |
| [H3C iMC XVE-2024-4567：Via 请求头命令注入 RCE 与 certutil 分段投递 JSP](web-java-component-h3c-imc-via-header-command-execution/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台 delBackup 备份删除：type/fileName 直接拼接导致 ../ 路径穿越任意文件删除](web-java-component-halo-delbackup-path-traversal-file-delete/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 getTpl：tplName 未过滤 ../ 路径穿越任意文件读取](web-java-component-halo-theme-gettpl-path-traversal-read/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 saveTpl：tplName 无过滤导致 ../ 路径穿越任意文件写入](web-java-component-halo-theme-savetpl-path-traversal-write/) | verified | medium | 2026-11-05 |
| [HSQLDB 1.8 JavaObject/OBJECT 列反序列化：INSERT…SELECT 类型转换触发 Column.convertObject 与 InOutUtil.deserialize](web-java-component-hsqldb-javaobject-object-column-deserialization/) | verified | medium | 2026-11-09 |
| [HSQLDB CALL 任意静态方法：JDBC 连接内串联 JNDI、c3p0/Spring 二次反序列化与 defineClass RCE](web-java-component-hsqldb-call-static-method-rce/) | verified | medium | 2026-11-07 |
| [HSQLDB file 模式：JDBC URL 指定路径落盘与 .script 无盐 MD5 口令摘要泄露](web-java-component-hsqldb-file-mode-script-hash-leak/) | verified | high | 2026-11-07 |
| [HSQLDB JDBC URL 的 ${} 展开：读取 JVM 系统属性并随连接请求外带（SSRF）](web-java-component-hsqldb-jdbc-url-property-expansion-exfil/) | verified | high | 2026-11-07 |
| [HtmlUnit CVE-2023-26119：XSLTProcessor 未启用 FEATURE_SECURE_PROCESSING，恶意页面经 Xalan Java 扩展函数在服务端执行命令](web-java-component-htmlunit-cve-2023-26119-xsltprocessor-extension-rce/) | verified | high | 2026-11-12 |
| [HtmlUnit CVE-2023-49093：CVE-2023-26119 修复不完整，IE 模式 msxml XSLProcessor 仍可用 XSLT 扩展函数在服务端执行命令（<3.8.0）](web-java-component-htmlunit-cve-2023-49093-msxml-xslprocessor-extension-rce/) | verified | high | 2026-11-12 |
| [HugeGraph AuthenticationFilter 鉴权绕过：getUriInfo().getPath() 未归一化 + endsWith 白名单，任意路径追加 ;versions 即跳过认证（CVE-2024-27349）](web-java-component-hugegraph-authenticationfilter-getpath-semicolon-whitelist-bypass/) | verified | high | 2026-11-09 |
| [HugeGraph-Hubble 图连接 SSRF 链：/versions 跟随 30x 重定向到 HugeGraph GET /gremlin，无图信息也能执行 Gremlin（CVE-2024-27347）](web-java-component-hugegraph-hubble-graph-connections-redirect-ssrf-gremlin/) | verified | high | 2026-11-09 |
| [I Doc View /doc/upload 默认 token=testtoken 鉴权绕过 + url 参数任意文件读取：file/UNC/FTP/HTTP(S) 内容落地后回读](web-java-component-idocv-doc-upload-url-arbitrary-file-read/) | verified | high | 2026-11-12 |
| [I Doc View /html/2word 抓取外部 HTML 链接下载，Windows 反斜杠文件名穿越写入 JSP 前台 RCE](web-java-component-idocv-html-2word-link-download-backslash-path-traversal-jsp-rce/) | verified | high | 2026-11-13 |
| [JavaMelody /monitoring 未授权：会话列表泄露 JSESSIONID 可劫持在线用户，JNDI/MBeans 泄露密钥文件名与数据库配置](web-java-component-javamelody-monitoring-unauth-session-hijack/) | verified | medium | 2026-11-07 |
| [JBoss 4.2.3 端口 4446 反序列化：内置 CommonsCollections 3.1 链写文件读 flag](web-java-component-jboss-4-2-3-4446-deserialization/) | verified | medium | 2026-11-07 |
| [JBoss AS /invoker/readonly CVE-2017-12149：HttpInvoker 反序列化 RCE](web-java-component-jboss-cve-2017-12149-invoker-readonly-deserialization/) | verified | medium | 2026-11-07 |
| [JDBC 数据源测试重复 url 参数属性走私：& 开头的第二值拼成 socketFactory，绕过字面量过滤加载 Spring XML RCE](web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling/) | verified | high | 2026-11-05 |
| [JEECG <=4.0 interfaceTest SSRF 回显 fastjson 1.2.31 反序列化 RCE（/api/../ 绕过鉴权）](web-java-component-jeecg-cve-2023-49442-interface-test-fastjson-rce/) | verified | high | 2026-11-12 |
| [Jenkins CLI @ 参数任意文件读取（CVE-2024-23897）：args4j 展开文件内容并回显](web-java-component-jenkins-cli-at-file-arbitrary-read-cve-2024-23897/) | verified | high | 2026-11-06 |
| [Jenkins 加密凭据值取明文：Script Console 里 hudson.util.Secret.fromString().getPlainText()，或把 GitLab 连接 URL 指向监听端用 Test Connection 钓出 PRIVATE-TOKEN](web-java-component-jenkins-hudson-secret-plaintext-test-connection-token-leak/) | verified | high | 2026-11-12 |
| [Jenkins 管理员 Script Console 读取 master.key/hudson.util.Secret 解密 credentials.xml 取凭据横向](web-java-component-jenkins-script-console-master-key-credential-decrypt/) | verified | high | 2026-11-07 |
| [Jetty 11 内存马：反射注册 HttpConfiguration.Customizer，逐请求执行命令并兼容哥斯拉协议](web-java-component-jetty11-customizer-memshell-godzilla/) | verified | high | 2026-11-13 |
| [Jetty 11 内存马：遍历 ThreadLocal 取 HttpConnection，请求头执行命令并由响应头回显](web-java-component-jetty11-threadlocal-header-memshell/) | verified | high | 2026-11-05 |
| [Jetty 11 脚本级内存马：Nashorn Java.extend 实现 HttpConfiguration.Customizer，Unsafe 线程对象图自定位注册](web-java-component-jetty11-nashorn-javaextend-customizer-memshell/) | verified | high | 2026-11-13 |
| [Jetty 9 Filter 内存马：反射取 ServletHandler._filterPathMappings 注入 FilterMapping](web-java-component-jetty9-servlethandler-filter-memshell/) | verified | high | 2026-11-08 |
| [Jetty 9 Servlet 内存马：反射调用 ServletHandler.addServlet/addServletMapping 注册 ServletHolder](web-java-component-jetty9-servlethandler-servlet-memshell/) | verified | high | 2026-11-08 |
| [Jetty 9.4.44+ FilterHolder 内存马初始化绕过：setStarted + setServletHandler + initialize](web-java-component-jetty9-filterholder-initialize-bypass/) | verified | high | 2026-11-08 |
| [Jetty URIUtil.canonicalPath 双斜杠绕过：//..//..// 让 canonical 长度≥2 绕过 doDotsSlash 拒绝，canonicalPath 返回非 null 而调用方仍用原始 subPath 穿越](web-java-component-jetty-uriutil-canonicalpath-double-slash-bypass/) | verified | high | 2026-11-09 |
| [Jetty XML 配置 + BCEL ClassLoader 内存马：向 webapps 上传 XML 触发静态块，反射注册 Filter 到 ServletHandler](web-java-component-jetty-xml-bcel-filter-memshell/) | verified | medium | 2026-11-08 |
| [jfinal cms FileManager：path/currentpath 未过滤导致任意文件读/写/下载，jsp 直连被 JFinalFilter 404 后靠改写模板拿 RCE](web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter/) | verified | high | 2026-11-08 |
| [JimuReport /jmreport/queryFieldBySql 时间盲注：FreeMarker ${} 拼接绕过 sleep 关键词过滤](web-java-component-jimureport-queryfieldbysql-time-blind-sqli/) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/queryFieldBySql 的 FreeMarker <#include> 任意文件读取](web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read/) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/save 报表单元格表达式注入：AviatorScript use 或 FreeMarker ?new Execute 执行任意代码](web-java-component-jimureport-save-cell-expression-injection-rce/) | verified | medium | 2026-11-07 |
| [JimuReport /jmreport/testConnection JDBC URL 注入：H2 init 创建 JavaScript 触发器加载字节码不出网 RCE](web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce/) | verified | medium | 2026-11-07 |
| [JimuReport 1.5.6 /jmreport/queryFieldBySql 未授权 FreeMarker ?new Execute RCE：SQL 关键字 WAF 只在渲染后检查](web-java-component-jimureport-queryfieldbysql-execute-ssti-rce/) | verified | high | 2026-11-08 |
| [JimuReport 1.5.6 /jmreport/qurestSql 未授权注入：apiSelectId 取出 jimu_report_db.db_dyn_sql 模板后 id 参数直拼执行](web-java-component-jimureport-qurestsql-dyndb-sql-injection/) | verified | high | 2026-11-08 |
| [JimuReport <=1.6.0 queryFieldBySql 的 ObjectConstructor→SpEL 变体：SpelExpressionParser 执行 T(cglib ReflectUtils).defineClass 装载回显内存马，1.6.1 用 SAFER_RESOLVER 修复](web-java-component-jimureport-queryfieldbysql-objectconstructor-spel-defineclass/) | verified | medium | 2026-11-12 |
| [JimuReport FreeMarker SSTI：jeecg.compute 暴露 Aviator 实现沙箱外 RCE（CVE-2026-51086/51087）](web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce/) | verified | high | 2026-11-05 |
| [JimuReport queryFieldBySql 的 FreeMarker ObjectConstructor 链：经 ScriptEngineManager 取 Nashorn 执行 JS，再用 defineClass 注入内存马；渲染阶段即执行、SQL 报错不代表失败](web-java-component-jimureport-queryfieldbysql-objectconstructor-nashorn-memshell/) | verified | high | 2026-11-08 |
| [JimuReport TokenInterceptor 鉴权绕过：previousPage + 数据库中不存在的 jmLink/shareToken/JmReport-Share-Token 即放行](web-java-component-jimureport-token-interceptor-jmlink-auth-bypass/) | verified | high | 2026-11-08 |
| [JimuReport v2.5.1 硬编码打印插件签名 + Aviator 表达式注入未授权 RCE](web-java-component-jimureport-unauth-aviator-rce/) | verified | high | 2026-11-05 |
| [jshERP 3.3 前台 RCE：getUserAllList 未授权泄露 admin 哈希，password 替换登录后上传恶意插件 jar 并 installByPath 安装](web-java-component-jsherp3-getuseralllist-plugin-upload-rce/) | verified | high | 2026-11-12 |
| [Kafka Connect /connectors 未授权创建 Debezium 连接器：database.history.producer.sasl.jaas.config 的 JndiLoginModule JNDI 注入（CVE-2023-25194）](web-java-component-kafka-connect-debezium-sasl-jaas-jndi/) | verified | high | 2026-11-13 |
| [Karaf/OSGi HttpService 注册内存 Servlet WebShell：BundleActivator 跟踪 HttpService 后 registerServlet](web-java-component-karaf-osgi-httpservice-servlet-memshell/) | verified | high | 2026-11-07 |
| [Kingbase8 JDBC ConfigurePath 本地属性文件注入：socketFactory 通配符加载临时文件 Spring XML RCE](web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce/) | verified | high | 2026-11-06 |
| [kkFileView 4.2.0–4.4.0-beta 压缩包预览 Zip Slip：zip 条目 ../ 拼接到 hack.zip_ 缓存目录后未校验，任意文件写入](web-java-component-kkfileview-compress-zipslip-arbitrary-write/) | verified | high | 2026-11-10 |
| [kkFileView getCorsFile 任意文件读取：读 .bash_history 定位解析缓存目录并下载归档](web-java-component-kkfileview-getcorsfile-bashhistory-cache-artifact/) | verified | high | 2026-11-06 |
| [kkFileView v4.0.0 getCorsFile 的 urlPath 未限制协议与目标：file:// 任意文件读取与云元数据 SSRF](web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read/) | verified | high | 2026-11-05 |
| [Litemall 对象存储删除接口 key 未规范化导致任意文件删除](web-java-component-litemall-storage-delete-arbitrary-file/) | verified | high | 2026-11-05 |
| [MCMS 5.2.4 FileAction 未授权上传：黑名单仅 .exe/.jsp，jspx 与 Windows NTFS ADS ::$DATA 绕过写 WebShell](web-java-component-mcms-fileaction-upload-blacklist-jspx-ads/) | verified | high | 2026-11-07 |
| [MCMS 5.2.4 双路由前缀鉴权绕过：/ms/** 需登录、无前缀 /cms/** 直接未授权访问](web-java-component-mcms-dual-route-prefix-auth-bypass/) | verified | high | 2026-11-07 |
| [MCMS 5.2.4 模板 ZIP 解压 Zip Slip：entry 名 ../../test.html 绕过 tempDir 过滤写入 webapp 根目录](web-java-component-mcms-template-unzip-zipslip/) | verified | high | 2026-11-07 |
| [MCMS 上传路径校验只拦 ../：uploadPath 传绝对路径/根路径绕过 checkUploadPath，模板、Logo 与 file/upload 三处任意目录写文件](web-java-component-mcms-checkuploadpath-absolute-path-upload/) | verified | high | 2026-11-10 |
| [Metabase CVE-2021-41277：GeoJSON url 参数任意文件读取](web-java-component-metabase-cve-2021-41277-geojson-file-read/) | verified | high | 2026-11-05 |
| [Metabase CVE-2023-38646：未授权 setup-token 泄露 + /api/setup/validate JDBC 校验注入 H2 init JavaScript 触发器 RCE](web-java-component-metabase-cve-2023-38646-setup-token-h2-init-javascript-rce/) | verified | high | 2026-11-13 |
| [Nacos /v1/cs/ops/derby 未授权 SQL 查询（CVE-2021-29442）：select 开头即执行，导出用户表与 BCrypt 口令](web-java-component-nacos-derby-ops-unauth-sqli-user-dump/) | verified | high | 2026-11-08 |
| [Nacos AuthFilter 末尾斜杠绕过：ControllerMethodsCache 取不到 method 时直接放行请求](web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass/) | verified | high | 2026-11-08 |
| [Nacos Derby 未授权到 RCE：/v1/cs/ops/data/removal 导入 SQL，sqlj.install_jar / EXPORT_QUERY_LOBS_TO_EXTFILE / create type external 加载恶意类](web-java-component-nacos-derby-removal-sqlj-install-jar-rce/) | verified | high | 2026-11-08 |
| [Nacos serverIdentity 请求头鉴权绕过：配置 server.identity.key/value 后带对应头即跳过 JWT 校验](web-java-component-nacos-server-identity-header-auth-bypass/) | verified | high | 2026-11-08 |
| [Nacos 默认 token.secret.key：用公开默认密钥 HS256 伪造 accessToken 绕过鉴权](web-java-component-nacos-default-token-secret-key-jwt-forge/) | verified | high | 2026-11-08 |
| [Nacos 默认配置 nacos.core.auth.enabled=false：未授权访问 v1/auth/users 枚举/新建用户并登录控制台](web-java-component-nacos-default-auth-disabled-user-admin/) | verified | high | 2026-11-08 |
| [Netty ChannelPipeline 内存马：替换 doOnChannelInit 注入恶意 Handler](web-java-component-netty-pipeline-memshell/) | verified | high | 2026-11-05 |
| [O2OA 默认口令登录后「添加接口」驻入 Java.type 代码，通过 JNDI 外带实现 RCE](web-java-component-o2oa-default-credential-invoke-jndi-rce/) | verified | high | 2026-11-08 |
| [ONLYOFFICE Document Server 存储 key 路径穿越导致任意文件写](web-java-component-onlyoffice-storage-key-path-traversal-file-write/) | verified | medium | 2026-11-05 |
| [ONLYOFFICE runtime.json 热加载与配置合并导致安全开关静默降级](web-java-component-onlyoffice-runtime-config-hot-reload-downgrade/) | verified | medium | 2026-11-05 |
| [Openfire CVE-2023-32315：AuthCheckFilter 只查 `..`/`%2e`，用 Jetty `%u002e` 非标准 Unicode 解码穿越绕过管理控制台鉴权](web-java-component-openfire-cve-2023-32315-authcheckfilter-u002e-traversal/) | verified | high | 2026-11-13 |
| [PgJDBC CVE-2022-21724：可控 JDBC URL 的 socketFactory/socketFactoryArg 实例化 ClassPathXmlApplicationContext 加载 Spring XML RCE](web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce/) | verified | high | 2026-11-07 |
| [PostgreSQL JDBC 的 loggerLevel/loggerFile 当任意文件写用：把 JSP 代码塞进 URL，靠 = 截断让驱动把 shell 写进 Web 目录](web-java-component-pgjdbc-loggerfile-jsp-webshell-file-write/) | verified | medium | 2026-11-09 |
| [PublicCMS savePlaceMetaData 任意文件上传（CVE-2024-40550）：path 仅删除 ".."，可向 include 目录写入任意 HTML 造成同源存储型 XSS](web-java-component-publiccms-saveplacemetadata-upload-stored-xss/) | verified | high | 2026-11-08 |
| [PublicCMS 模板替换路径穿越改写预置脚本，配合 execScript 执行导致 RCE](web-java-component-publiccms-template-replace-traversal-execscript-rce/) | verified | medium | 2026-11-07 |
| [PublicCMS 站点模板上传 originalFilename 目录穿越：-site.zip 后缀约束下的任意路径文件写入](web-java-component-publiccms-sitefile-upload-traversal-write/) | verified | medium | 2026-11-12 |
| [Rebuild /filex/del-make-share 未授权 SQL 注入：20 位 ID 参数拼接 DELETE 语句删除全表数据](web-java-component-rebuild-unauth-sqli-del-share-id-delete/) | verified | medium | 2026-11-12 |
| [Rebuild 内置默认账号 admin/admin 与 rebuild/rebuild 可直接登录管理后台](web-java-component-rebuild-default-user-login/) | verified | high | 2026-11-12 |
| [Rebuild 未授权受限文件读取 ~/.rebuild/.rebuild 安装配置：默认 AES 密钥 REBUILD2018 解密数据库口令](web-java-component-rebuild-unauth-file-read-install-config-aes-default-key/) | verified | high | 2026-11-12 |
| [Resin 3.x/4.x 无回显利用的三种取 request/response 路径：ThreadLocals 扫描、ServletInvocation.getContextRequest 与 TcpSocketLink.getCurrentRequest](web-java-component-resin-request-response-echo-threadlocals-servletinvocation-tcpsocketlink/) | verified | high | 2026-11-12 |
| [Resin 4.x Filter 内存马：反射 WebApp.addFilterMapping 动态注册恶意 Filter，配合 ClassLoader.defineClass 注入冰蝎 Filter](web-java-component-resin-filter-memshell-webapp-addfiltermapping/) | verified | high | 2026-11-12 |
| [RocketMQ updateBrokerConfig 的 rocketmqHome 命令注入 RCE（CVE-2023-33246）](web-java-component-rocketmq-updatebrokerconfig-command-injection-cve-2023-33246/) | verified | high | 2026-11-11 |
| [Smartbi RMIServlet 反射调用 DataSourceService：DB2 JDBC clientRerouteServerListJNDIName 触发 JNDI RCE](web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce/) | verified | medium | 2026-11-05 |
| [Smartbi RMIServlet 服务端 JS/Rhino 表达式执行：checkExpression 与 checkJavaScript 命令执行](web-java-component-smartbi-rmiservlet-js-rhino-expression-rce/) | verified | medium | 2026-11-05 |
| [Smartbi V10 *.stub + jsonpCallback：GET 转 POST 绕过仅拦 POST 的 DB2 RCE 补丁](web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass/) | verified | medium | 2026-11-05 |
| [Smartbi V10 windowUnloading 参数分裂：鉴权检查与 RMIServlet 实际调用方法不一致的绕过](web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass/) | verified | medium | 2026-11-05 |
| [Solr CVE-2023-50386：BACKUP/RESTORE 导出恶意配置集 class 到 collection 的 lib 目录，创建 Collection 时经 URLClassLoader 加载执行](web-java-component-solr-cve-2023-50386-backup-restore-configset-class-deploy-rce/) | verified | high | 2026-11-11 |
| [spider-flow CVE-2024-0195：/function/save 的 name/parameter/script 拼接后 Nashorn eval，注入 }Java.type(...) 执行命令，存量函数重启再执行](web-java-component-spider-flow-cve-2024-0195-function-nashorn/) | verified | high | 2026-11-12 |
| [SysAid On-Premise CVE-2023-47246 /userentry 任意文件上传：accountId 路径穿越 + zlib(zip) 落盘后解压写 JSP](web-java-component-sysaid-cve-2023-47246-userentry-zip-slip-upload/) | verified | high | 2026-11-13 |
| [TeamCity CVE-2023-42793：/**/RPC2 路径免鉴权，createToken 命名 RPC2 窃取管理员 token 并 RCE](web-java-component-teamcity-cve-2023-42793-rpc2-pathset-bypass-token-rce/) | verified | high | 2026-11-11 |
| [TeamCity CVE-2024-27198：jsp 参数改写视图名 + 分号路径参数剥离，二次 dispatch 绕过鉴权创建 token](web-java-component-teamcity-cve-2024-27198-jsp-view-dispatch-semicolon-auth-bypass/) | verified | high | 2026-11-11 |
| [UEditor Java 上传文件名 JSON 注入：BaseState 字符串拼接污染下游 JSON 解析与 fastjson](web-java-component-ueditor-filename-json-injection-parse-sink/) | verified | high | 2026-11-09 |
| [VMware vCenter CVE-2021-22005：CEIP analytics 代理路径穿越 + Velocity 写 JSP 到 vSphere ROOT，/idm/..;/ 访问 root Webshell](web-java-component-vcenter-cve-2021-22005-ceip-analytics-agent-jsp-file-write/) | verified | high | 2026-11-08 |
| [VMware vRealize Network Insight CVE-2023-20887 预认证 RCE：/saas. 绕过 nginx 本机 ACL，Thrift createSupportBundle 的 nodeId 命令注入](web-java-component-vrni-cve-2023-20887-thrift-nodeid-rce/) | verified | high | 2026-11-13 |
| [WSO2 API Manager 数据源测试 SOAP 接口：H2 validationQuery 用 CSVWRITE+FILE_READ 写 webapp 读 flag](web-java-component-wso2-ndatasourceadmin-h2-validationquery-file-read/) | verified | high | 2026-11-06 |
| [XXL-JOB admin 默认口令 admin/123456 登录：GLUE 计划任务跨平台命令执行与 executor 出网排查](web-java-component-xxl-job-admin-default-password-glue-task-rce/) | verified | high | 2026-11-11 |
| [XXL-JOB executor /run 2.2.0+ 伪造：REST JSON 与默认 accessToken default_token 利用，兼 <2.1.2 Hessian 协议](web-java-component-xxl-job-executor-run-default-token-rce/) | verified | high | 2026-11-11 |
| [XXL-Job Executor 1.9.2 瘦身版 Jetty 内存马：从线程栈反射取 JettyServer 的 HandlerCollection，向 _handlers 前置恶意 Handler](web-java-component-xxl-job-executor-jetty-handler-collection-memshell/) | verified | high | 2026-11-09 |
| [XXL-Job Executor 2.3.0（Tomcat 9）GLUE 任务注入 Filter 内存马：遍历线程组取 TomcatEmbeddedContext 后动态注册 filter](web-java-component-xxl-job-executor-tomcat-filter-memshell-threadgroup/) | verified | high | 2026-11-12 |
| [XXL-JOB executor 9999 未授权命令执行：直接 POST /run 覆盖 GLUE 脚本，gluesource 落盘成为取证点](web-java-component-xxl-job-executor-unauth-run-glue-rce/) | verified | high | 2026-11-09 |
| [XXL-JOB 数据库写入 xxl_job_info 恶意 CRON 任务：trigger_status 置 1 触发 executor 执行 GLUE 命令](web-java-component-xxl-job-db-insert-cron-job-rce/) | verified | high | 2026-11-11 |
| [YAMCS 算法脚本 java-expression 注入：Runtime.exec 执行并用输出参数回显](web-java-component-yamcs-algorithm-java-expression-rce/) | verified | medium | 2026-11-07 |
| [Zimbra RestFilter 参数名直转 request 属性：注入 javax.servlet.include.servlet_path 触发 /h/rest 本地文件包含（CVE-2025-68645）](web-java-component-zimbra-restfilter-param-attribute-lfi/) | verified | high | 2026-11-05 |
| [ZooKeeper AdminServer IP 认证绕过：伪造 X-Forwarded-For 冒充 127.0.0.1](web-java-component-zookeeper-admin-ip-auth-bypass/) | verified | high | 2026-11-05 |
| [东方通 TongWeb 控制台 twusers.properties 初始口令未改导致后台登录](web-java-component-tongweb-default-console-credentials/) | verified | medium | 2026-11-05 |
| [云安宝-云匣子 /3.0/authService/config 登录前拦截器 fastjson 1.2.38 AutoType → C3P0 userOverridesAsString Hex 反序列化（CC6+ScriptEngineManager 回显）RCE](web-java-component-yunxiabox-authservice-config-fastjson-c3p0-hex-rce/) | verified | high | 2026-11-11 |
| [亿赛通 CDG dlpPolicy/importPolicy.do 反序列化 RCE：上传文件经 DES(esafenet) 解密后 byteToObject，CC1 链执行命令](web-java-component-esafenet-cdg-importpolicy-deserialization-rce/) | verified | high | 2026-11-11 |
| [亿赛通 CDG LinkFilterService 权限绕过：path/userId/cur 经 CDGUtil 加密直传，构造 systemadmin 会话进入后台](web-java-component-esafenet-cdg-linkfilterservice-auth-bypass/) | verified | high | 2026-11-11 |
| [低代码平台数据源配置校验接口 JDBC URL 注入：H2 init CREATE TRIGGER JavaScript 不出网 RCE](web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce/) | verified | medium | 2026-11-06 |
| [原始 Netty ServerBootstrapAcceptor.childHandler 替换：全局 Handler 内存马与 cmd 头回显](web-java-component-netty-serverbootstrapacceptor-childhandler-memshell/) | verified | high | 2026-11-07 |
| [大华智慧园区 attachment_clearTempFile.action：bean.recId 字符串拼接 SQL 注入](web-java-component-dahua-attachment-cleartempfile-recid-sqli/) | verified | medium | 2026-11-07 |
| [大华智慧园区 AttachmentAction downloadByUrlAtt：filePath 直入 URL.openStream 任意文件读取](web-java-component-dahua-attachment-downloadbyurlatt-fileread/) | verified | high | 2026-11-07 |
| [大华智慧园区 deleteFtp 接口 Fastjson 1.2.44 反序列化 RCE（JdbcRowSetImpl JNDI）](web-java-component-dahua-swingcardrecord-deleteftp-fastjson/) | verified | medium | 2026-11-07 |
| [大华智慧园区 emap devicePoint_addImgIco 任意文件上传：后缀取自上传文件名并写入 webapps/upload/emap/society_new](web-java-component-dahua-emap-devicepoint-addingico-upload/) | verified | high | 2026-11-09 |
| [大华智慧园区 emap MyInterceptor 鉴权绕过：permission 默认 true 且 catch 吞异常，hasSubsystem=true 触发 NPE 即放行](web-java-component-dahua-emap-myinterceptor-catch-auth-bypass/) | verified | high | 2026-11-09 |
| [大华智慧园区 getFaceCapture 分页 orderBy 报错注入：CXF WebService 将排序字段直接拼入 order by](web-java-component-dahua-getfacecapture-orderby-sqli/) | verified | high | 2026-11-09 |
| [大华智慧园区 MaterialController 任意文件上传：原始文件名与内容直写 Web 目录](web-java-component-dahua-material-file-upload-webshell/) | verified | medium | 2026-11-07 |
| [大华智慧园区 MyBatis ORDER BY 排序参数 SQL 注入（Material/Player bycondition 接口）](web-java-component-dahua-wpms-mybatis-orderby-sqli/) | verified | medium | 2026-11-07 |
| [大华智慧园区 publishing UserAuthenticationFilter 路径包含即放行：/publishing/publishing/* 与 css/js/png/gif 后缀全模块未授权](web-java-component-dahua-publishing-userauthenticationfilter-path-whitelist-bypass/) | verified | high | 2026-11-09 |
| [大华智慧园区 user_getUserInfoByUserName 未授权泄露 loginPass：按 md5(loginName:dss:password) 规则爆破管理员口令](web-java-component-dahua-usergetuserinfobyusername-unauth-hash-leak/) | verified | high | 2026-11-09 |
| [契约锁 OFD 上传 Zip Slip 覆盖热补丁 JAR：热加载 static 块执行 RCE](web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce/) | verified | medium | 2026-11-07 |
| [契约锁安全补丁 security.rsc 硬编码 RSA 私钥：离线解密还原 PdfverifierPreventWrapper 过滤配置](web-java-component-qiyuesuo-security-rsc-hardcoded-rsa-key-decrypt/) | verified | medium | 2026-11-07 |
| [帆软 FineReport largedataset/export/excel 的 functionParams 注入 Formula：evalValue 执行 SQL() 函数](web-java-component-finereport-largedataset-export-excel-formula-sqli/) | verified | medium | 2026-11-05 |
| [帆软 FineReport 内置测试用户统一默认口令 123456 登录管理后台（CNVD-2024-37222）](web-java-component-finereport-builtin-user-default-password/) | verified | high | 2026-11-05 |
| [泛微 e-cology 10 DataConnController JDBC URL 注入：任意驱动加载 + H2 init JavaScript 触发器 RCE（含 MySQL 文件读取/DB2 JNDI）](web-java-component-weaver-ecology10-dataconn-jdbc-h2-init-rce/) | verified | medium | 2026-11-07 |
| [泛微 e-cology 9.0 Resin InvokerServlet 暴露 BshServlet：/weaver/bsh.servlet.BshServlet 未授权 BeanShell 命令执行（CNVD-2019-32204）](web-java-component-weaver-ecology-bshservlet-invoker-rce/) | verified | high | 2026-11-12 |
| [泛微 e-cology 后台 JDBC socketFactory 加载上传 XML 注入内存马：materialLib 上传 + datasource 测试链](web-java-component-weaver-ecology-jdbc-socketfactory-memshell/) | draft | high | 2026-11-05 |
| [泛微 e-cology 集群模式前台任意文件上传：X-Forwarded-For 绕过 IP 校验 + tokenCheck.jsp 泄漏 license 伪造 token + 补丁包 ZIP 解压 JSP 落盘](web-java-component-weaver-ecology-clusterupgrade-upload-jsp-webshell/) | verified | high | 2026-11-13 |
| [泛微 E10 addMysqlMonitor 未授权 JDBC URL：allowLoadLocalInfile=true + 恶意 MySQL 服务端读取服务器文件](web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read/) | verified | high | 2026-11-07 |
| [海康威视综合安防 /center/api/installation/detection 未授权命令注入：machines.id 经 assembleCheckInstallEnvs/convertExecuteCommand 进入 analysisCmdexeExecuteResult](web-java-component-hikvision-isecure-installation-detection-rce/) | verified | medium | 2026-11-08 |
| [海康威视综合安防 iSecure Center 任意文件上传：文件名路径穿越写 JSP GetShell](web-java-component-hikvision-isecure-file-upload-path-traversal-rce/) | verified | high | 2026-11-05 |
| [用友 NC /lfw/core/rpc 未授权 JSON-RPC 反射调用：ServiceLocator 服务定位把 rpcname 带入 JNDI（ldap://）注入](web-java-component-yonyou-nc-lfw-rpc-reflection-service-locator-jndi/) | verified | high | 2026-11-11 |
| [用友 NC 6.5 CourseWareAction.download fileName 路径穿越任意文件读取（web.xml 回显）](web-java-component-yonyou-nc65-courseware-download-fileread/) | verified | high | 2026-11-06 |
| [用友 NC Cloud /ncchr/pm/fb/attachment/uploadChunk 任意文件上传：fileGuid 与原始文件名未过滤，路径穿越写 JSP](web-java-component-yonyou-nccloud-attachment-uploadchunk-fileguid-traversal/) | verified | medium | 2026-11-12 |
| [用友 NC Cloud /ncchr/pm/staff/queryStaffByName SQL 注入：name 拼接 like 查询，Oracle 时间盲注实测打通](web-java-component-yonyou-nccloud-staff-querystaffbyname-sqli/) | verified | high | 2026-11-12 |
| [用友 NC Cloud ncchr LoginFilter 鉴权绕过：JWT 密钥硬编码 defaultSecret，自签 accessTokenNcc 头即放行](web-java-component-yonyou-nccloud-ncchr-loginfilter-jwt-defaultsecret-bypass/) | verified | high | 2026-11-12 |
| [用友 NC ComboOperTools importCombo JAXB XXE：setExpandEntityReferences(false) 仍解析外部实体并 OOB 读文件](web-java-component-yonyou-nc-comboopertools-importcombo-jaxb-xxe/) | verified | high | 2026-11-07 |
| [用友 NC PortalSpecServiceImpl.createSkinFile 任意文件上传：接口名作 rpcname 反射调用 + 双 URL 编码绕过 '/' 截断写 webroot](web-java-component-yonyou-nc-portalspec-createskinfile-upload/) | verified | high | 2026-11-11 |
| [用友 NC6.5 MtAppTimeLineAction doApply SQL 注入：meapk 拼接绕过 sqlEncode 的 chrw 包装](web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli/) | verified | high | 2026-11-06 |
| [用友 NC65 mp 模块 UploadFileServlet 任意文件上传：LoginInterceptor 用 getRequestURL 对 IGNORE_URI 做子串匹配，/mp/login/../ 绕过鉴权 getshell](web-java-component-yonyou-nc65-mp-uploadfileservlet-logininterceptor-url-bypass/) | verified | high | 2026-11-12 |
| [用友 NCCloud GatewayServlet 反射调用 ProcessFileUtils 命令拼接 RCE](web-java-component-yonyou-nccloud-gateway-reflection-command-injection/) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud NCCloudGatewayServlet 反射调用 IFileTrans 任意文件上传写 WebShell](web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload/) | verified | high | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet InvocationInfo.readExternal 嵌套反序列化：白名单外壳内嵌 CC6/TemplatesImpl 绕过 token 直接 RCE](web-java-component-yonyou-u8-servicedispatcher-invocationinfo-readexternal-cc6/) | verified | medium | 2026-11-07 |
| [用友 U8 Cloud ServiceDispatcherServlet 补丁绕过：硬编码 tenantId 伪造 token + 长度前缀 InvocationInfo 反序列化写 WebShell](web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload/) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet：InvocationInfo 反序列化 + 硬编码 tokenSeed 伪造 token 反射调用文件写入方法 getshell](web-java-component-yonyou-u8-servicedispatcher-invocationinfo-token-file-write/) | verified | high | 2026-11-05 |
| [用友 U8-OA 基础版 operaFileActionController.jsp：path/context 任意文件覆盖写 JSP getshell](web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite/) | verified | high | 2026-11-08 |
| [用友 U8C 暴露 BeanShell Servlet：/servlet/~ic/bsh.servlet.BshServlet 未鉴权执行脚本，certutil 拉取 JSP WebShell](web-java-component-yonyou-u8c-bsh-servlet-beanshell-exec/) | verified | medium | 2026-11-08 |
| [用友 U8Cloud NCCloudGatewayServlet 20250924 补丁分析：ts+HMAC 校验仍以硬编码 nctoken 为密钥，旧 RCE 链被黑名单封堵](web-java-component-yonyou-u8cloud-nccloudgateway-20250924-patch-hmac-auth-bypass/) | verified | medium | 2026-11-07 |
| [用友 U8Cloud 多接口 SQL 注入：KeyWord*ReportQuery、AppPhoneServletService、ReportDetailDataQuery、ArchiveVerify 参数拼接（MSSQL 时间盲注验证）](web-java-component-yonyou-u8cloud-multi-service-sqli/) | verified | high | 2026-11-12 |
| [用友时空 KSOA ImageUpload servlet 任意文件上传：filepath/filename 参数把 JSP 写进 Web 根](web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload/) | verified | medium | 2026-11-08 |
| [用友时空 KSOA 未授权 JSP SQL 注入：PreviewKPQT/PrintZP*/PrintZPYG/fillKP 等十余处参数直接拼接（MSSQL）](web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint/) | verified | high | 2026-11-08 |
| [网动 ActiveUC gsCheckUser 未鉴权 XXE：AuthorizedInfo 直入 dom4j DocumentHelper.parseText](web-java-component-activeuc-gscheckuser-dom4j-xxe/) | verified | medium | 2026-11-06 |
| [网动 ActiveUC meetingShow!downloadDocument 未鉴权 filePath 路径穿越任意文件读取](web-java-component-activeuc-meetingshow-downloaddocument-arbitrary-file-read/) | verified | high | 2026-11-06 |
| [网动 ActiveUC user!exportUsers 登录后 iBATIS $ 拼接 SQL 注入（temps → PK_TEMP IN）](web-java-component-activeuc-exportusers-ibatis-dollar-sqli/) | verified | medium | 2026-11-06 |
| [网动 ActiveUC versionCtr!editVersion 未鉴权 ZIP 上传：解压目录穿越 + jsp/jspx 后缀过滤与 ::$DATA 绕过](web-java-component-activeuc-versionctr-upload-unzip-zipslip/) | verified | medium | 2026-11-06 |
| [致远 M3 前台日志注入二阶 Fastjson RCE：推送接口把 userMessageId 写进 app.log，日志读取接口反序列化触发 C3P0/TemplatesImpl](web-java-component-seeyon-m3-pns-log-injection-fastjson-rce/) | verified | high | 2026-11-13 |
| [致远 OA A8 thirdpartyController.do 任意用户登录：enc 为 Base64+字符偏移，伪造 L/M/T 参数指定默认管理员 memberId](web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login/) | verified | high | 2026-11-11 |
| [致远 OA ajax.do 反射调用 formulaManager：formulaExpression 拼进 Groovy 脚本执行，黑名单可绕过写 JSP WebShell](web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp/) | verified | high | 2026-11-11 |
| [致远 OA ajax.do 未授权访问：needlessUrlMap 子串匹配叠加 Spring UrlPathHelper 路径规范化，借 /main.do/../ajax.do 或 /autoinstall.do/../ajax.do 绕过 CTPSecurityFilter](web-java-component-seeyon-ajaxdo-needless-urlmap-path-normalization-auth-bypass/) | verified | high | 2026-11-13 |
| [致远 OA autoinstall.do 前台未授权，login_locale Cookie 目录穿越下载任意 ZIP](web-java-component-seeyon-autoinstall-login-locale-zip-traversal/) | verified | high | 2026-11-05 |
| [致远 OA CTPSecurityFilter 鉴权链：ServletAuthenticator 白名单只覆盖部分 servlet，其余落入无校验 defaultAuthenticator](web-java-component-seeyon-ctpsecurityfilter-servlet-auth-gap/) | verified | medium | 2026-11-12 |
| [致远 OA fileToExcelManager.saveExcelInBase 任意文件写入：filePath 不校验，CSV 双引号包裹用换行闭合写 JSP WebShell](web-java-component-seeyon-filetoexcelmanager-saveexcelinbase-arbitrary-file-write-jsp/) | verified | high | 2026-11-13 |
| [致远 OA REST 重置密码权限绕过：密码段追加 .do 让 /seeyon/rest/... 走 SpringController 会话校验，普通用户重置管理员密码](web-java-component-seeyon-rest-changepassword-dotdo-auth-bypass/) | verified | high | 2026-11-11 |
| [致远 OA wpsAssistServlet 未授权任意文件上传：flag=save 进入 oaSaveFile，realFileType 拼接路径穿越落 jsp](web-java-component-seeyon-wpsassistservlet-realfiletype-upload-traversal/) | verified | medium | 2026-11-12 |
| [致远 OA xrdController.do checkIsSign 文件名目录穿越：覆盖已有 JSP 致 RCE](web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal/) | verified | medium | 2026-11-05 |
| [致远OA A8 officeservlet 任意文件读取：iMsgServer2000 64 字节包头 + 变种 Base64，LOADTEMPLATE 触发 MsgFileLoad](web-java-component-seeyon-officeservlet-imsgserver2000-file-read/) | verified | high | 2026-11-11 |
| [致远OA OFD 解压 Zip Slip：saveFile 控制 fileId 上传恶意包、content.do invokingForm 触发解压写 Web 根 JSPX 致 RCE](web-java-component-seeyon-ofd-unzip-zipslip-webshell-write/) | verified | high | 2026-11-11 |
| [蓝凌 EKP dataxml.jsp 的 s_bean=sysFormulaSimulateByJS：script 参数经 BeanShell 解释器执行命令](web-java-component-landray-ekp-dataxml-sbean-beanshell-rce/) | verified | high | 2026-11-08 |
| [蓝凌 EKP RedirectServlet `/ui-ext/**` 匿名路径未授权文件读取：`/./ui-ext/./` 绕过前缀判断，拼接 file: URL 读 resource 目录与请求日志](web-java-component-landray-ekp-redirectservlet-uiext-unauth-file-read/) | verified | high | 2026-11-13 |
| [蓝凌 EKP V16 SysUiComponent#replaceExtend 未鉴权目录复制：把受保护 JSP 目录搬到匿名路径实现前台 RCE](web-java-component-landray-ekp-sysuicomponent-replaceextend-directory-copy/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
