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
| [ActiveMQ Jolokia HTTP Discovery 二级 URI 绕过 vm 黑名单致 RCE（CVE-2026-40466）](web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass/) | verified | high | 2026-11-05 |
| [ActiveMQ Jolokia 默认放行 Broker exec：addNetworkConnector 的 vm brokerConfig 加载远程 Spring XML RCE（CVE-2026-34197）](web-java-component-activemq-jolokia-networkconnector-xbean-rce/) | verified | high | 2026-11-05 |
| [AJ-Report 数据源测试连接任意 jdbcUrl：恶意 MySQL 服务端 LOAD DATA LOCAL INFILE 读取服务端文件](web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read/) | verified | high | 2026-11-05 |
| [Apache Hertzbeat <=1.7.1 后台自定义监控模板 H2 JDBC URL 注入 RCE](web-java-component-hertzbeat-h2-jdbc-url-bypass-rce/) | verified | high | 2026-11-05 |
| [Apache Solr CVE-2017-12629：xmlparser XXE 调内部 Config API 添加 RunExecutableListener 实现 RCE](web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce/) | verified | high | 2026-11-05 |
| [Apache Syncope REST 连接器 testScript 认证后 RCE](web-java-component-syncope-connector-script-rce/) | verified | high | 2026-11-04 |
| [DataEase 数据源 JDBC RCE：type 选 Oracle 绕过 H2 黑名单，JSON 覆盖 driver/jdbcUrl](web-java-component-dataease-json-driver-override-jdbc-rce/) | verified | high | 2026-11-05 |
| [Druid StatViewServlet 监控台默认口令登录：数据源、SQL、Session 与 classpath 信息泄露](web-java-component-druid-monitor-default-credentials/) | verified | medium | 2026-11-05 |
| [FastCMS 0.1.6 后台插件上传 RCE：PF4J 加载插件并调用 start() 执行任意 Java 代码](web-java-component-fastcms-plugin-upload-pf4j-start-rce/) | verified | high | 2026-11-05 |
| [FineReport /view/ReportServer 把 query string 当模板渲染，${sql()} 注入 SQLite 写 JSP](web-java-component-finereport-view-reportserver-template-sqli-webshell/) | verified | high | 2026-11-05 |
| [FineReport DecisionInterceptor 鉴权绕过：reportlets=/ 使模板鉴权返回 null，配合 op=getSessionID 未认证获取合法 sessionID](web-java-component-finereport-getsessionid-auth-bypass/) | verified | high | 2026-11-05 |
| [FineReport export/excel 的 params XML Formula 注入：Calculator.evalValue 执行 sql()，借 SQLite VACUUM INTO 写 JSP WebShell](web-java-component-finereport-export-excel-formula-sqli-vacuum-webshell/) | verified | high | 2026-11-05 |
| [FineReport ReportServer 无会话参数注入 HSQL 堆叠语句，page_content 渲染时二次触发 RCE](web-java-component-finereport-reportserver-hsql-param-rce/) | verified | high | 2026-11-05 |
| [FineReport v9 print/ie/pdf 的 sessionID 头进入模板渲染，${sql()} 注入 SQLite 写 JSP WebShell](web-java-component-finereport-print-ie-pdf-sqli-webshell/) | verified | high | 2026-11-05 |
| [H2 Console 未授权 JDBC 注入：PostgreSQL loggerFile 写 ASCII JAR + socketFactory 加载 Spring XML RCE](web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce/) | verified | medium | 2026-11-06 |
| [H2 JDBC URL 过滤绕过：RUN\SCRIPT 转义、双斜杠文件模式与不可见空格](web-java-component-h2-jdbc-url-filter-bypass-runscript/) | verified | high | 2026-11-05 |
| [H3C iMC XVE-2024-4567：Via 请求头命令注入 RCE 与 certutil 分段投递 JSP](web-java-component-h3c-imc-via-header-command-execution/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台 delBackup 备份删除：type/fileName 直接拼接导致 ../ 路径穿越任意文件删除](web-java-component-halo-delbackup-path-traversal-file-delete/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 getTpl：tplName 未过滤 ../ 路径穿越任意文件读取](web-java-component-halo-theme-gettpl-path-traversal-read/) | verified | high | 2026-11-05 |
| [Halo 0.4.3 后台主题编辑 saveTpl：tplName 无过滤导致 ../ 路径穿越任意文件写入](web-java-component-halo-theme-savetpl-path-traversal-write/) | verified | medium | 2026-11-05 |
| [JDBC 数据源测试重复 url 参数属性走私：& 开头的第二值拼成 socketFactory，绕过字面量过滤加载 Spring XML RCE](web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling/) | verified | high | 2026-11-05 |
| [Jenkins CLI @ 参数任意文件读取（CVE-2024-23897）：args4j 展开文件内容并回显](web-java-component-jenkins-cli-at-file-arbitrary-read-cve-2024-23897/) | verified | high | 2026-11-06 |
| [Jetty 11 内存马：遍历 ThreadLocal 取 HttpConnection，请求头执行命令并由响应头回显](web-java-component-jetty11-threadlocal-header-memshell/) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/queryFieldBySql 时间盲注：FreeMarker ${} 拼接绕过 sleep 关键词过滤](web-java-component-jimureport-queryfieldbysql-time-blind-sqli/) | verified | high | 2026-11-05 |
| [JimuReport /jmreport/queryFieldBySql 的 FreeMarker <#include> 任意文件读取](web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read/) | verified | high | 2026-11-05 |
| [JimuReport FreeMarker SSTI：jeecg.compute 暴露 Aviator 实现沙箱外 RCE（CVE-2026-51086/51087）](web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce/) | verified | high | 2026-11-05 |
| [JimuReport v2.5.1 硬编码打印插件签名 + Aviator 表达式注入未授权 RCE](web-java-component-jimureport-unauth-aviator-rce/) | verified | high | 2026-11-05 |
| [Kingbase8 JDBC ConfigurePath 本地属性文件注入：socketFactory 通配符加载临时文件 Spring XML RCE](web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce/) | verified | high | 2026-11-06 |
| [kkFileView getCorsFile 任意文件读取：读 .bash_history 定位解析缓存目录并下载归档](web-java-component-kkfileview-getcorsfile-bashhistory-cache-artifact/) | verified | high | 2026-11-06 |
| [kkFileView v4.0.0 getCorsFile 的 urlPath 未限制协议与目标：file:// 任意文件读取与云元数据 SSRF](web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read/) | verified | high | 2026-11-05 |
| [Litemall 对象存储删除接口 key 未规范化导致任意文件删除](web-java-component-litemall-storage-delete-arbitrary-file/) | verified | high | 2026-11-05 |
| [Metabase CVE-2021-41277：GeoJSON url 参数任意文件读取](web-java-component-metabase-cve-2021-41277-geojson-file-read/) | verified | high | 2026-11-05 |
| [Netty ChannelPipeline 内存马：替换 doOnChannelInit 注入恶意 Handler](web-java-component-netty-pipeline-memshell/) | verified | high | 2026-11-05 |
| [ONLYOFFICE Document Server 存储 key 路径穿越导致任意文件写](web-java-component-onlyoffice-storage-key-path-traversal-file-write/) | verified | medium | 2026-11-05 |
| [ONLYOFFICE runtime.json 热加载与配置合并导致安全开关静默降级](web-java-component-onlyoffice-runtime-config-hot-reload-downgrade/) | verified | medium | 2026-11-05 |
| [Smartbi RMIServlet 反射调用 DataSourceService：DB2 JDBC clientRerouteServerListJNDIName 触发 JNDI RCE](web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce/) | verified | medium | 2026-11-05 |
| [Smartbi RMIServlet 服务端 JS/Rhino 表达式执行：checkExpression 与 checkJavaScript 命令执行](web-java-component-smartbi-rmiservlet-js-rhino-expression-rce/) | verified | medium | 2026-11-05 |
| [Smartbi V10 *.stub + jsonpCallback：GET 转 POST 绕过仅拦 POST 的 DB2 RCE 补丁](web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass/) | verified | medium | 2026-11-05 |
| [Smartbi V10 windowUnloading 参数分裂：鉴权检查与 RMIServlet 实际调用方法不一致的绕过](web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass/) | verified | medium | 2026-11-05 |
| [WSO2 API Manager 数据源测试 SOAP 接口：H2 validationQuery 用 CSVWRITE+FILE_READ 写 webapp 读 flag](web-java-component-wso2-ndatasourceadmin-h2-validationquery-file-read/) | verified | high | 2026-11-06 |
| [Zimbra RestFilter 参数名直转 request 属性：注入 javax.servlet.include.servlet_path 触发 /h/rest 本地文件包含（CVE-2025-68645）](web-java-component-zimbra-restfilter-param-attribute-lfi/) | verified | high | 2026-11-05 |
| [ZooKeeper AdminServer IP 认证绕过：伪造 X-Forwarded-For 冒充 127.0.0.1](web-java-component-zookeeper-admin-ip-auth-bypass/) | verified | high | 2026-11-05 |
| [东方通 TongWeb 控制台 twusers.properties 初始口令未改导致后台登录](web-java-component-tongweb-default-console-credentials/) | verified | medium | 2026-11-05 |
| [低代码平台数据源配置校验接口 JDBC URL 注入：H2 init CREATE TRIGGER JavaScript 不出网 RCE](web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce/) | verified | medium | 2026-11-06 |
| [帆软 FineReport largedataset/export/excel 的 functionParams 注入 Formula：evalValue 执行 SQL() 函数](web-java-component-finereport-largedataset-export-excel-formula-sqli/) | verified | medium | 2026-11-05 |
| [帆软 FineReport 内置测试用户统一默认口令 123456 登录管理后台（CNVD-2024-37222）](web-java-component-finereport-builtin-user-default-password/) | verified | high | 2026-11-05 |
| [泛微 e-cology 后台 JDBC socketFactory 加载上传 XML 注入内存马：materialLib 上传 + datasource 测试链](web-java-component-weaver-ecology-jdbc-socketfactory-memshell/) | draft | high | 2026-11-05 |
| [海康威视综合安防 iSecure Center 任意文件上传：文件名路径穿越写 JSP GetShell](web-java-component-hikvision-isecure-file-upload-path-traversal-rce/) | verified | high | 2026-11-05 |
| [用友 NC 6.5 CourseWareAction.download fileName 路径穿越任意文件读取（web.xml 回显）](web-java-component-yonyou-nc65-courseware-download-fileread/) | verified | high | 2026-11-06 |
| [用友 NC6.5 MtAppTimeLineAction doApply SQL 注入：meapk 拼接绕过 sqlEncode 的 chrw 包装](web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli/) | verified | high | 2026-11-06 |
| [用友 NCCloud GatewayServlet 反射调用 ProcessFileUtils 命令拼接 RCE](web-java-component-yonyou-nccloud-gateway-reflection-command-injection/) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud NCCloudGatewayServlet 反射调用 IFileTrans 任意文件上传写 WebShell](web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload/) | verified | high | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet 补丁绕过：硬编码 tenantId 伪造 token + 长度前缀 InvocationInfo 反序列化写 WebShell](web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload/) | verified | medium | 2026-11-05 |
| [用友 U8 Cloud ServiceDispatcherServlet：InvocationInfo 反序列化 + 硬编码 tokenSeed 伪造 token 反射调用文件写入方法 getshell](web-java-component-yonyou-u8-servicedispatcher-invocationinfo-token-file-write/) | verified | high | 2026-11-05 |
| [网动 ActiveUC gsCheckUser 未鉴权 XXE：AuthorizedInfo 直入 dom4j DocumentHelper.parseText](web-java-component-activeuc-gscheckuser-dom4j-xxe/) | verified | medium | 2026-11-06 |
| [网动 ActiveUC meetingShow!downloadDocument 未鉴权 filePath 路径穿越任意文件读取](web-java-component-activeuc-meetingshow-downloaddocument-arbitrary-file-read/) | verified | high | 2026-11-06 |
| [网动 ActiveUC user!exportUsers 登录后 iBATIS $ 拼接 SQL 注入（temps → PK_TEMP IN）](web-java-component-activeuc-exportusers-ibatis-dollar-sqli/) | verified | medium | 2026-11-06 |
| [网动 ActiveUC versionCtr!editVersion 未鉴权 ZIP 上传：解压目录穿越 + jsp/jspx 后缀过滤与 ::$DATA 绕过](web-java-component-activeuc-versionctr-upload-unzip-zipslip/) | verified | medium | 2026-11-06 |
| [致远 OA autoinstall.do 前台未授权，login_locale Cookie 目录穿越下载任意 ZIP](web-java-component-seeyon-autoinstall-login-locale-zip-traversal/) | verified | high | 2026-11-05 |
| [致远 OA xrdController.do checkIsSign 文件名目录穿越：覆盖已有 JSP 致 RCE](web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
