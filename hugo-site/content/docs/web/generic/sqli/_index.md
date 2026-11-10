---
title: SQL 注入
weight: 1
---

# SQL 注入

## 这层是什么

注入类型、绕过、堆叠与二次注入。

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
| [.NET Entity.FindAll/Meta.DBO.Select 字符串拼接 SQL：登录 GetByName 时间盲注、编辑用户 ConfirmName、列表 GetPager 的 strWhere 注入](web-dotnet-entity-findall-concat-sqli-login-confirmname-getpager/) | verified | high | 2026-11-08 |
| [.NET Handler 参数直拼 MSSQL：getCities/getPersonInfo 用 @@VERSION 报错回显注入](web-generic-sqli-dotnet-handler-mssql-param-concat-version/) | verified | high | 2026-11-05 |
| [.NET 参数直拼 Oracle 查询：itemid/key 用 dbms_xdb_version.checkin(user) 报错注入](web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin/) | verified | high | 2026-11-05 |
| [360webscan 白名单 URL 绕过：命中 webscan_white_url 的后台接口整体跳过过滤，POST 参数直拼 UPDATE 注入](web-generic-sqli-360webscan-whitelist-url-bypass/) | verified | medium | 2026-11-08 |
| [360webscan 黑名单下的堆叠注入写 WebShell：PDO query 直执行 `;SELECT ... INTO OUTFILE`，绕开 union/and 与函数过滤](web-generic-sqli-360webscan-stacked-outfile-webshell/) | verified | high | 2026-11-08 |
| [AI WAF 语义拦截下的 MySQL 版本注释绕过：/*!50000union*/ 被当成注释、MySQL 仍执行](web-generic-sqli-ai-waf-mysql-versioned-comment-bypass/) | verified | high | 2026-11-06 |
| [Artery ERP workflow.sqlResult 未授权 SQL 注入：params/sql 直接交给 executeQuery](web-generic-sqli-artery-erp-workflow-sqlresult-unauth/) | verified | high | 2026-11-07 |
| [ASP.NET WebForms 报表 txtWhere 拼接 WHERE：') 闭合与 1/DB_NAME() 报错注入](web-generic-sqli-aspnet-webforms-report-txtwhere-mssql/) | verified | high | 2026-11-05 |
| [ASP.NET 成绩查询 sortname 排序参数 ORDER BY 报错注入：updatexml 经 XML 响应带出库名](web-generic-sqli-aspnet-sortname-orderby-updatexml/) | verified | high | 2026-11-08 |
| [BootDo 列表接口 `${sort} ${order}` 文本拼接：Map 隐藏参数 sort/order 的 ORDER BY SQL 注入](web-generic-sqli-bootdo-sort-order-token/) | verified | high | 2026-11-05 |
| [CCFlow/CCBPM Demo Port_Emp 未授权 SQL 注入：报错/UNION 取管理员口令并伪造 privateKey 令牌](web-generic-sqli-ccflow-demo-port-emp-unauth/) | verified | high | 2026-11-05 |
| [ClickHouse 盲注：FROM 前置 + INTERSECT/JOIN ON LIKE 绕过 select.*from 黑名单](web-generic-sqli-clickhouse-from-first-intersect-join-blind/) | verified | high | 2026-11-07 |
| [CMSEasy crossall execsql 加密参数 SQL 注入泄露管理员凭证](cmseasy-crossall-execsql-encrypted-sqli-admin-credential/) | verified | high | 2026-11-08 |
| [College Management System 图书搜索 book_name/book_author 直拼 SELECT：POST 表单 UNION 回显库名版本（faculty.php 与 university.php 同源两处）](web-generic-sqli-college-mgmt-book-search-post-union/) | verified | high | 2026-11-08 |
| [Content-Type 双头混淆：WAF 判为文件上传、Tomcat 按表单解析的 SQLi 绕过](web-generic-sqli-content-type-dual-header-waf-bypass/) | verified | high | 2026-11-05 |
| [CookieShop 订单多条件查询 JPQL 字符串拼接注入（name/phone/address 可控）](cookieshop-custorder-search-jpql-concat-injection/) | verified | high | 2026-11-08 |
| [CordysCRM departmentIds 经 StringJoiner 拼入 FIELD() 再进 MyBatis ${orderByClause}：列表接口 SQL 注入](web-generic-sqli-cordyscrm-departmentids-field-orderby/) | verified | medium | 2026-11-05 |
| [Craft Commerce sort 参数 ORDER BY 时间盲注（CVE-2026-29172）](web-generic-sqli-craft-commerce-sort-orderby-time-blind/) | verified | high | 2026-11-05 |
| [CVE-2026-1207 Django PostGIS raster band index 未校验导致堆叠 SQL 注入](web-generic-sqli-django-postgis-raster-band-index/) | verified | high | 2026-11-05 |
| [Cynthia 项目管理系统用户列表 LIKE 拼接时间盲注：initUser=true 的 userName 直入 JDBC Statement](web-generic-sqli-cynthia-user-list-like-time-blind/) | verified | high | 2026-11-07 |
| [Django CVE-2026-1312：order_by + FilteredRelation 带点别名走 RawSQL 导致 SQL 注入](web-generic-sqli-django-orderby-filteredrelation-period-alias/) | verified | high | 2026-11-05 |
| [Django FilteredRelation 列别名未校验：annotate/alias 的 **kwargs 键注入 SQL](web-generic-sqli-django-filteredrelation-alias/) | verified | high | 2026-11-05 |
| [DocSys/MxsDoc /getUserList.do 的 userName 经 MyBatis ${} 拼进 LIKE：sqlmap 时间盲注拖库](web-generic-sqli-docsys-getuserlist-mybatis-like/) | verified | medium | 2026-11-08 |
| [DTStack Taier ConsoleController.listNames 的 jobName 参数经 MyBatis ${} 拼接导致 SQL 注入（CVE-2024-41579）](web-generic-sqli-taier-console-listnames-jobname/) | verified | medium | 2026-11-09 |
| [DWR 报文体里的注入点：payload 放在 c0-param0 的类型前缀之后，其余字段保持合法](web-generic-sqli-dwr-typed-param-injection-point/) | verified | high | 2026-11-08 |
| [eDoc Easy Tables table-id 直接拼进表名：同参数两处拼接、SLEEP 被执行两次的时间盲注（CVE-2025-22519）](web-generic-sqli-wordpress-edoc-easy-tables-table-id-double-splice/) | verified | high | 2026-11-08 |
| [edu 就业系统统计查询 otherQuery 参数 SQL 注入：Oracle 后端 sqlmap 获取交互式 SQL shell](web-generic-sqli-edu-employment-otherquery-oracle-sql-shell/) | verified | medium | 2026-11-07 |
| [EIS 办公平台 Down.aspx i 参数直拼 main_id：前台 MSSQL 延时注入](web-generic-sqli-eis-down-aspx-i-param-mssql/) | verified | high | 2026-11-05 |
| [EIS 办公平台 Notify.asmx getTodo：targets.LoginName 直拼 SQL 并打通 xp_cmdshell](web-generic-sqli-eis-notify-asmx-loginname-xp-cmdshell/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 文章列表 orderBy 参数注入：MyBatis-Plus orderByDesc 拼入 ${ew.customSqlSegment}](web-generic-sqli-fastcms-article-list-orderby-injection/) | verified | high | 2026-11-05 |
| [FE 系统 JDBC 拼接 SQL 注入：treeXml.jsp menuName 与 editflow_manager.jsp GUID 直入 WHERE](web-generic-sqli-fe-system-jdbc-concat-treexml-editflow/) | verified | high | 2026-11-05 |
| [FilePress 分享列表 order 参数 ORDER BY 时间盲注：邻近参数漏加白名单（CVE-2026-8133）](web-generic-sqli-filepress-order-orderby-time-blind/) | verified | high | 2026-11-05 |
| [FortiWeb Fabric Connector 预认证 SQL 注入：Bearer token 注入 MySQL INTO OUTFILE 写 .pth 触发 root RCE（CVE-2025-25257）](web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce/) | verified | medium | 2026-11-06 |
| [GBK 宽字节注入：%df 与转义反斜杠合成汉字，让单引号重新逃逸](web-generic-sqli-gbk-wide-byte-escape-bypass/) | verified | high | 2026-11-05 |
| [GEO my WordPress 4.5.4 未授权 SQL 注入：经纬度参数直接拼进 BETWEEN 的时间盲注](web-generic-sqli-geo-my-wordpress-boundary-time-blind/) | verified | high | 2026-11-05 |
| [Hibernate 6.x HQL `sql()` 函数逃逸：把原生 SQL 片段无引号嵌入生成语句，闭合后 UNION 读任意表](web-generic-sqli-hibernate-hql-sql-function-escape/) | verified | high | 2026-11-07 |
| [Hibernate HQL `function()` 关键字逃逸：第一参数被当函数名拼接，5.x/6.x 通用地注入原生 SQL](web-generic-sqli-hibernate-hql-function-keyword-escape/) | verified | high | 2026-11-07 |
| [Hibernate HQL 与原生 SQL 拼接注入：createQuery/createNativeQuery 及命名查询 replace 陷阱](web-generic-sqli-hibernate-hql-native-query-injection/) | verified | medium | 2026-11-04 |
| [Hibernate HQL 反斜杠转义差异逃逸：用 `\'` 让 HQL 当普通字符、MySQL 当转义符，闭合字符串并 UNION 注入](web-generic-sqli-hibernate-hql-backslash-escape-union/) | verified | high | 2026-11-07 |
| [HTTP 请求头作为 SQL 注入点：GET/POST 被过滤后的 User-Agent、X-Forwarded-For、Cookie、Referer 注入](web-generic-sqli-http-header-injection/) | verified | medium | 2026-11-05 |
| [IF、SLEEP、AND、OR 被过滤时的 SQL 盲注替代原语](web-generic-sqli-blind-filter-bypass-functions/) | verified | high | 2026-11-05 |
| [information_schema 被 WAF 过滤时的布尔盲注替代：用 schema_auto_increment_columns.tables 取表名，配合 /**/ 代空格与 like 代等号](web-generic-sqli-schema-auto-increment-columns-information-bypass/) | verified | medium | 2026-11-08 |
| [INSERT 注入无结果集时把函数结果写进可见字段再回读：新增分类处 database() 落库后列表显示库名](web-generic-sqli-insert-visible-field-function-readback/) | verified | high | 2026-11-09 |
| [J2eeFAST /bpm/procdef/list 的 sql_filter 未经过 DataFilter 切面：${sql_filter} 直接拼接导致 ORDER BY/WHERE 注入](web-generic-sqli-j2eefast-sql-filter-procdef/) | verified | medium | 2026-11-05 |
| [Java MongoDB 查询字符串拼接注入：username/password 直拼 JSON 后 JSON.parse 进 find，$regex 前缀盲注爆 32 位随机密码](web-generic-sqli-mongodb-java-json-concat-regex-blind/) | verified | high | 2026-11-08 |
| [Java Servlet accountid 参数直拼 SQL 导致布尔盲注（CRM 头像保存接口）](web-generic-sqli-java-servlet-accountid-concat-boolean/) | verified | medium | 2026-11-05 |
| [Java Servlet 教务系统 JDBC Statement 拼接：check_login 用 admin'or 1=1# 登录绕过，同类 DAO 里 checkAccount/findWithId/findWithName/deleteStudent 六处共用一套未过滤拼接](web-generic-sqli-java-jdbc-statement-login-concat-multi-dao/) | draft | high | 2026-11-08 |
| [JDBC/MyBatis 标识符位置注入：表名与 ORDER BY 列名无法预编译时的拼接注入](web-generic-sqli-java-identifier-table-order-by-injection/) | verified | high | 2026-11-04 |
| [jfinal cms 列表接口 form.orderColumn 拼进 order by：报错注入 extractvalue 回显数据库口令](web-generic-sqli-jfinalcms-baseform-orderby-extractvalue/) | verified | high | 2026-11-08 |
| [JHSoft OA AddressImportPub.aspx 把 XML 节点值拼进 INSERT：通讯录导入 SQL 注入](web-generic-sqli-jhsoft-addressimportpub-xml-node-concat/) | verified | medium | 2026-11-07 |
| [JHSoft OA HomeService.asmx GetHomeInfo 的 userID 经 GetUserSex 直拼 SQL：时间盲注](web-generic-sqli-jhsoft-homeservice-getuserinfo-getusersex/) | verified | medium | 2026-11-07 |
| [JHSoft OA IncentivePlanFulfill.aspx 的 IncentiveID/TVersion 直拼 MSSQL：延时注入](web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version/) | verified | high | 2026-11-07 |
| [JHSoft OA TaskTreeJSON.aspx 的 id 参数经 InitTaskTree 拼进任务树查询：SQL 注入审计线索](web-generic-sqli-jhsoft-tasktreejson-id-concat/) | verified | low | 2026-11-07 |
| [jshERP 未授权注册 + ORDER BY 注入：safeSqlParse 删除关键字后用 extractvalue 盲注 load_file 读文件](web-generic-sqli-jsherp-orderby-extractvalue-loadfile/) | verified | high | 2026-11-05 |
| [JSON 条件构造器直接拼接 colName/colValue：ThemeUtil.whereSql 生成 MyBatis ${} 注入片段](web-generic-sqli-json-where-builder-colname-colvalue/) | verified | medium | 2026-11-05 |
| [LIKE 通配符未转义：real_escape_string 后搜索条件被 _%_ 扩大导致全表泄露](web-generic-sqli-like-wildcard-metacharacter-data-exposure/) | verified | high | 2026-11-05 |
| [LlamaIndex DuckDBRetriever match_bm25 SQL 注入 + shellfs 管道执行命令（CVE-2024-11958）](web-generic-sqli-llamaindex-duckdb-shellfs-rce/) | verified | high | 2026-11-06 |
| [LlamaIndex DuckDBVectorStore ref_doc_id SQL 注入：堆叠 COPY 任意文件读写与潜在 RCE（CVE-2025-1750）](web-generic-sqli-llamaindex-duckdb-refdocid-copy-file-rce/) | verified | medium | 2026-11-06 |
| [LuckyFrameWeb 部门编辑把 ancestors 写入后再拼进 IN (${ancestors})：条件可达的二级 SQL 注入](web-generic-sqli-luckyframeweb-ancestors-in-clause/) | verified | medium | 2026-11-05 |
| [MCMS /ms/mdiy/formData/queryData.do orderBy 参数 Mybatis ${} 注入（空格过滤可绕过）](web-generic-sqli-mcms-formdata-querydata-orderby/) | verified | high | 2026-11-08 |
| [MCMS 5.2.4 /mdiy/dict/listExcludeApp orderBy 参数直拼 ${}：未授权 ORDER BY 注入 updatexml 报错注入](web-generic-sqli-mcms-mdiy-dict-orderby-injection/) | verified | medium | 2026-11-07 |
| [MCMS BaseEntity.sqlWhere 解析成 sqlWhereList 后，IBaseDao.sqlWhere 片段把 ${item.field} 拼进 SQL 造成注入](web-generic-sqli-mcms-sqlwherelist-field-include/) | verified | medium | 2026-11-10 |
| [MCMS 内容列表 categoryId 直接拼进 IContentDao.xml query 的 ${categoryId}，POST 参数可报错注入](web-generic-sqli-mcms-content-categoryid-query/) | verified | high | 2026-11-10 |
| [MCMS 校验接口 fieldName 作为 MyBatis ${key} 拼进 SQL：/ms/mdiy/page/verify.do → validated → queryBySQL 注入](web-generic-sqli-mcms-querybysql-wheres-key-fieldname/) | verified | high | 2026-11-10 |
| [MES getHqlAppend 拼接 siteName/userName/menuName 导致 HQL 注入（findMessages/findImages/menuManager）](web-generic-sqli-mes-hql-append-find-actions/) | verified | high | 2026-11-05 |
| [MetaCRM mcc_login.jsp workerid 参数拼接 SQL 注入（MSSQL WAITFOR DELAY 时间盲注）](web-generic-sqli-crm-mcc-login-workerid-time-blind/) | verified | high | 2026-11-07 |
| [MetInfo 7.6 前台 search/para Base64 JSON 未授权 SQL 注入](web-generic-sqli-metinfo-search-para-base64-blind/) | verified | high | 2026-11-04 |
| [MSSQL 非 xp_cmdshell 写 Webshell：sp_makewebtask 与日志/差异备份](web-generic-sqli-mssql-backup-sp-makewebtask-webshell/) | verified | medium | 2026-11-05 |
| [MyBatis Mapper 中 ${} 文本替换导致 SQL 注入：值、表名、ORDER BY、IN、LIKE 五类拼接点](web-generic-sqli-mybatis-dollar-brace-injection/) | verified | high | 2026-11-04 |
| [MySQL 8 TABLE 语句 + 元组字典序比较的二分布尔盲注：不依赖 select/列名/报错，按 information_schema 实际列数补齐常量逐字符还原库表字段](web-generic-sqli-mysql8-table-row-constructor-lexicographic-blind/) | verified | medium | 2026-11-08 |
| [MySQL 8 VALUES ROW(...) 充当表值构造器：用 union values row(1,2,…) 试列数并直接占回显位，替代被过滤的 order by 与 select](web-generic-sqli-mysql8-values-row-column-count-union-probe/) | verified | medium | 2026-11-08 |
| [MySQL 8.0 TABLE 语句替代 SELECT + exp(710) 溢出报错：绕过 select 关键字过滤的无列名注入](web-generic-sqli-mysql8-table-keyword-exp-error-bypass/) | verified | medium | 2026-11-06 |
| [MySQL GET_LOCK 跨会话锁等待延时注入：按 Web 连接布局（短/长会话、连接池、多Web共用库）构造锁竞争并绕过 sleep/BENCHMARK 拦截](web-generic-sqli-getlock-web-session-layout-waf-bypass/) | verified | high | 2026-11-07 |
| [MySQL INTO OUTFILE 文件名可控：LINES/FIELDS TERMINATED BY 注入写 Webshell](web-generic-sqli-mysql-outfile-filename-clause-injection/) | verified | medium | 2026-11-05 |
| [MySQL LIMIT 位置注入：PROCEDURE ANALYSE 触发报错/延时](web-generic-sqli-mysql-limit-procedure-analyse/) | verified | medium | 2026-11-05 |
| [MySQL Quine 在 REPLACE/@/CONCAT 被过滤时的构造：MAKE_SET(bits,...) + QUOTE(s) + 派生表列别名让查询结果等于输入](web-generic-sqli-make-set-quote-derived-table-quine/) | verified | high | 2026-11-06 |
| [MySQL SQL 注入写 WebShell：INTO OUTFILE、DUMPFILE 与 general_log 落盘](web-generic-sqli-mysql-outfile-general-log-webshell/) | verified | high | 2026-11-05 |
| [MySQL 注入分块拼接任意文件：CONCAT 在表内累积 hex 片段后 INTO OUTFILE 精确导出](web-generic-sqli-mysql-chunked-concat-table-into-outfile/) | verified | high | 2026-11-07 |
| [MySQL 约束攻击：超长用户名截断插入覆盖 admin 账户](web-generic-sqli-mysql-constraint-truncation-admin-overwrite/) | verified | medium | 2026-11-05 |
| [MySQL/MariaDB UNION 注入 + load_file 任意文件读取：列数探测后把文件内容回显到联合查询列](web-generic-sqli-mysql-union-load-file-read/) | verified | high | 2026-11-06 |
| [NewBeeMall MyBatis ${} 两处注入：后台 goodsName 与前台 keyword 直拼 LIKE](web-generic-sqli-newbeemall-mybatis-dollar-goodsname-keyword/) | verified | medium | 2026-11-05 |
| [NocoBase myInAppChannels 的 filter.$lt 拼接进 Sequelize.literal 导致认证后 SQL 注入](web-generic-sqli-nocobase-myinappchannels-sequelize-literal/) | verified | medium | 2026-11-05 |
| [OA JSP orderBy/sort 未走 sqlstr 导致 MySQL 报错注入（linkman_list_sel / listmember）](web-generic-sqli-oa-jsp-orderby-sort-updatexml/) | verified | high | 2026-11-05 |
| [OA TranformdomoaServlet 按 #**# 拆分 multipart 字段名拼接 INSERT，时间盲注](web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli/) | draft | high | 2026-11-05 |
| [OPENROWSET(BULK ... SINGLE_CLOB) + Ad Hoc Distributed Queries：用 T-SQL 读取服务器任意文本文件确认站点路径与配置](web-generic-sqli-mssql-openrowset-bulk-arbitrary-file-read/) | verified | high | 2026-11-08 |
| [Oracle 注入借 dbms_xmlquery.newcontext 编译 Java Source：创建 LINXRUNCMD 函数后以数据库权限执行系统命令](web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec/) | verified | medium | 2026-11-08 |
| [ORDER BY 大小比较盲注：UNION 注入候选串作排序键，按首行回显逐字符还原密码](web-generic-sqli-order-by-union-lexicographic-blind/) | verified | high | 2026-11-07 |
| [ORDER BY 注入 INTO OUTFILE 写 webshell：上传文件名承载 PHP 代码 + 正则未锚点绕过](web-generic-sqli-order-by-into-outfile-filename-webshell/) | verified | high | 2026-11-06 |
| [orderType 排序注入：逗号 + if(sleep) 被 WAF 403，重复参数 HPP 绕过做时间盲注](web-generic-sqli-orderby-ordertype-hpp-parameter-pollution-blind/) | verified | high | 2026-11-07 |
| [PageVo.sort 拼接 order by 进入 MyBatis ${pageSql}：分页实体污染多个列表接口的 ORDER BY 注入](web-generic-sqli-pagevo-sort-orderby-pagesql-injection/) | verified | high | 2026-11-07 |
| [PDO 模拟预编译占位符错位注入：反引号列名拼接配合反斜杠逃逸](web-generic-sqli-pdo-emulated-prepare-identifier/) | verified | medium | 2026-11-06 |
| [PHP 多参数拼接 SQL 注入：逐参数正则过滤被跨参数拆分绕过 + 反斜杠逃逸单引号，时间盲注读 flag（CISCN 2024 php2）](web-generic-sqli-php-multi-param-concat-backslash-cross-boundary/) | verified | high | 2026-11-08 |
| [PHP 搜索接口 LIKE "%$word%" 双引号拼接注入：UNION 拖库、INTO OUTFILE 写 Webshell/反弹 Shell](web-generic-sqli-php-like-double-quote-union-outfile/) | verified | high | 2026-11-05 |
| [PHP 数组参数过滤器回调写错导致 addslashes 失效：serialize 后拼接 SQL 注入](web-generic-sqli-php-array-filter-walk-recursive-unfiltered/) | verified | high | 2026-11-05 |
| [PHPGurukul Small CRM 1.0 后台 edit-user.php 的 id 单引号字符串注入：POST 分支拼接 SQL，UNION 十列取 database()](web-generic-sqli-phpgurukul-crm-edit-user-get-post-id-union/) | verified | high | 2026-11-08 |
| [PHPGurukul Student Record Management System 3.2 login.php 登录处 UNION 注入（CVE-2025-5216）](web-generic-sqli-phpgurukul-student-record-login-union/) | verified | high | 2026-11-05 |
| [PHPGurukul 在线课程注册系统 my-profile.php cgpa 参数时间盲注（CVE-2025-10663）](web-generic-sqli-phpgurukul-myprofile-cgpa-time-blind/) | verified | high | 2026-11-05 |
| [phpStudy Linux 面板 8090 本地服务登录 SQL 注入：username 堆叠 INSERT INTO TASKMNG 建计划任务写 PHP Webshell](web-generic-sqli-phpstudy-linux-panel-socket-login-taskmng-webshell/) | verified | medium | 2026-11-08 |
| [PostgreSQL SQL 注入：pg_read_file/pg_ls_dir 读文件与 COPY TO PROGRAM 命令执行](web-generic-sqli-postgres-copy-to-program-rce/) | verified | high | 2026-11-05 |
| [PostgreSQL 注入仅允许 SELECT：用 lo_import/lo_get/lo_export 读写数据库服务器文件](web-generic-sqli-postgresql-lo-import-file-read-write/) | verified | high | 2026-11-05 |
| [PostgreSQL 注入无 information_schema 取列名：json_object_keys + json_populate_record](web-generic-sqli-postgres-json-column-enum/) | verified | high | 2026-11-07 |
| [PostgreSQL 注入绕 WAF：关键字间插入 /*"*/ 注释与 JSON Unicode 转义](web-generic-sqli-postgres-waf-comment-quote-bypass/) | verified | high | 2026-11-07 |
| [RootHub MyBatis LIKE 拼接注入：搜索 s 与后台 nodeTitle 两处 ${}](web-generic-sqli-roothub-mybatis-like-dollar-brace/) | verified | medium | 2026-11-05 |
| [RuoYi 数据权限 ${params.dataScope} SQL 注入：admin 跳过切面覆盖后直入 Mapper](web-generic-sqli-ruoyi-datascope-params-admin-bypass/) | verified | high | 2026-11-07 |
| [RuoYi 部门编辑 ancestors 写入后拼进 IN (${ancestors})：同请求内二阶 SQL 注入](web-generic-sqli-ruoyi-dept-ancestors-second-order-in/) | verified | high | 2026-11-07 |
| [SeaCMS 12.9 后台 admin_datarelate.php 任意 SQL 执行：ExecuteNoneQuery2 缺 CheckSql 绕过 SQL 安全检查](web-generic-sqli-seacms-admin-datarelate-execute-none-query/) | verified | high | 2026-11-08 |
| [SeaCMS 12.9 未授权 SQL 注入：dmku/index.php ac=edit 弹幕编辑直接拼接 cid/text/color](web-generic-sqli-seacms-dmku-unauth-danmaku-edit/) | verified | high | 2026-11-08 |
| [SeaCMS ≤13.3 admin_members.php 后台多处 SQL 注入：uid/uname/id 直接拼接（CVE-2025-10662）](web-generic-sqli-seacms-admin-members-multi-param/) | verified | high | 2026-11-05 |
| [search POST 参数 SQL 注入（UNION + 时间盲注）拖库获取明文口令并破解 MD5 admin 口令](web-generic-sqli-search-union-time-blind-credential-dump/) | verified | high | 2026-11-08 |
| [Showdoc < 3.2.6 item/pwd 的 item_id 拼接注入：接口自取验证码 + OCR 识别，UNION 布尔盲注外带 user_token](web-generic-sqli-showdoc-item-pwd-item-id-union-captcha-ocr-user-token/) | verified | high | 2026-11-08 |
| [SiteServer CMS V6.15.51 libraryText/list keyword SQL 注入：API Key 访问 + 堆叠查询写 UDF](web-generic-sqli-siteserver-cve-2021-42655-librarytext-udf/) | verified | high | 2026-11-05 |
| [sobey-mchEditor wxarticleList 未授权 SQL 注入：String.format 拼接叠加 getRequestURI 白名单路径穿越绕过](web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass/) | verified | medium | 2026-11-07 |
| [SourceCodester Stock Management System 1.0 后台三处 view 页面 id 参数 UNION 注入（CVE-2025-4786/4787/4267）](web-generic-sqli-sourcecodester-stock-view-id-union/) | verified | high | 2026-11-05 |
| [SourceCodester Stock Management System 1.0 登录 username 参数时间盲注（CVE-2025-4283）](web-generic-sqli-sourcecodester-stock-login-time-blind/) | verified | high | 2026-11-05 |
| [sp_oacreate Scripting.FileSystemObject 以数据库服务账户落盘 ASP 木马：不走 HTTP 上传、文件属主为高权限进程，360 等杀软不查杀且低权木马会话改不动该文件](web-generic-sqli-mssql-ole-fso-write-webshell-av-survive/) | verified | high | 2026-11-08 |
| [Spring Boot RBAC 系统 MyBatis ${} 两处注入：字典 dictName LIKE 与部门 params.dataScope 数据范围](web-generic-sqli-spring-rbac-mybatis-dollar-dictname-datascope/) | verified | high | 2026-11-07 |
| [SQL Quine 绕过 UNION 结果自校验：REPLACE(@a:=模板, 占位符, HEX(@a)) 让返回行等于注入 payload 自身（含 SHA2 变体）](web-generic-sqli-replace-hex-self-referential-quine/) | verified | high | 2026-11-06 |
| [SQL Server 堆叠注入开启 xp_cmdshell 与 OLE 自动化实现命令执行](web-generic-sqli-mssql-stacked-xp-cmdshell/) | verified | high | 2026-11-04 |
| [SQL 报错注入：用 updatexml、extractvalue 与类型转换错误回显数据](web-generic-sqli-error-based-extraction/) | verified | high | 2026-11-05 |
| [SQL 注入 WAF 绕过：关键字中插 %0a 拆分正则 + 十六进制字面量替代单引号](web-generic-sqli-waf-newline-keyword-split-hex/) | verified | high | 2026-11-05 |
| [SQL 注入启发式探测：随机引号串报错/类型转换报错/算术求值差异一次请求初筛可注入参数（sqlmap heuristic check）](web-generic-sqli-sqlmap-heuristic-probe/) | verified | medium | 2026-11-10 |
| [SQL 注入数据库指纹：PostgreSQL/达梦/GaussDB 的版本函数与系统视图差异](web-generic-sqli-db-fingerprint-postgres-dameng-gaussdb/) | verified | high | 2026-11-07 |
| [SQL 注入无回显的 DNS 带外取数：LOAD_FILE UNC 与 xp_cmdshell ping](web-generic-sqli-dnslog-oob-exfiltration/) | verified | medium | 2026-11-05 |
| [SQL 注入：关键字被单次替换为空时用双写还原 select/or/and](web-generic-sqli-keyword-double-write-bypass/) | verified | high | 2026-11-05 |
| [SQLite ATTACH DATABASE 写 PHP WebShell：代理 curl 拉取攻击者 SQL payload，堆叠注入落盘 dt.php 直接解析](web-generic-sqli-sqlite-attach-database-php-webshell-proxy-ssrf/) | verified | medium | 2026-11-09 |
| [SQLite UNION VALUES 绕过 SELECT 关键字过滤：无需 SELECT 生成 admin 行](web-generic-sqli-sqlite-union-values-select-filter-bypass/) | verified | high | 2026-11-06 |
| [SQLite 堆叠注入 ATTACH DATABASE 写 EJS 模板：借模板 include 读取服务器文件](web-generic-sqli-sqlite-attach-database-write-template-include/) | verified | high | 2026-11-07 |
| [SQLite 布尔盲注：%09 代替空格 + substr 二分提取 secret](web-generic-sqli-sqlite-boolean-blind-tab-bypass/) | verified | high | 2026-11-06 |
| [SQLite 搜索接口 tags 参数时间盲注：sqlmap 全自动拖库 dump 出未哈希的明文密码](web-generic-sqli-sqlite-tags-timeblind-sqlmap-plaintext-password/) | verified | high | 2026-11-08 |
| [SQLite 注入：%0a 绕过空格过滤、JOIN 子查询绕过逗号过滤，查 sqlite_master 取 flag](web-generic-sqli-sqlite-newline-join-comma-bypass/) | verified | high | 2026-11-06 |
| [Struts2 自研 Tray 封装 repHashMap 不过滤：searchCode 直接拼接 LIKE 造成 SQL 注入](web-generic-sqli-struts2-tray-searchcode-concat/) | verified | medium | 2026-11-07 |
| [ThinkPHP 3 数组参数 exp 逃逸 where 条件：union select 绕过关键字黑名单读表](web-generic-sqli-thinkphp3-array-exp-union-blacklist-bypass/) | verified | medium | 2026-11-08 |
| [ThinkPHP 3.2.3 order() 数组 key/value 注入：parseOrder 原样拼接 ORDER BY](web-generic-sqli-thinkphp3-order-array-key-value-injection/) | verified | medium | 2026-11-09 |
| [ThinkPHP 3.2.3 update bind 注入：id[]=bind 借 execute() 的 strtr 占位符替换把 SQL 片段带进 WHERE](web-generic-sqli-thinkphp32-update-bind-placeholder-strtr-injection/) | verified | medium | 2026-11-09 |
| [ThinkPHP 3.2.x find($options) 数组参数污染：cid[where] 字符串被 parseWhere 原样拼接形成 SQL 注入](web-generic-sqli-thinkphp32-find-options-where-string-injection/) | verified | high | 2026-11-09 |
| [ThinkPHP 3.x where() 数组特殊键注入：_string/_complex 经 parseThinkWhere 原样拼入 WHERE](web-generic-sqli-thinkphp3-parsewhere-special-key-injection/) | verified | high | 2026-11-09 |
| [ThinkPHP 5.1.23 之前 order() 接受数组时 key 进 field() 拼接：parseDataBind 铸入 :data__ 前缀后用反引号逃逸报错注入（CVE-2018-16385）](web-generic-sqli-thinkphp5-order-array-key-field-injection/) | verified | high | 2026-11-08 |
| [ThinkPHP 查询数组 raw 键原样拼接：前台订单/客服/查单接口 where['raw'] 用户输入报错 SQL 注入](web-generic-sqli-thinkphp-where-raw-array-fragment-injection/) | verified | high | 2026-11-09 |
| [Tmall_demo 五处 MyBatis ORDER BY ${orderUtil.orderBy} 排序注入：OrderUtil 透传 orderBy，sqlmap 时间盲注打通](web-generic-sqli-tmall-orderutil-orderby-mybatis/) | verified | high | 2026-11-07 |
| [UPDATE 的 SET 子句直接把表单字段拼进语句：在某个赋值项里用单引号闭合后追加 ,列=值 WHERE 条件-- ，一次请求批量改写全表签约状态](web-generic-sqli-update-set-clause-extra-assignment/) | verified | medium | 2026-11-08 |
| [WeGIA 3.6.1 Atendido_ocorrenciaControle id_memorando 认证后 SQL 注入（CVE-2026-23723）](web-generic-sqli-wegia-atendido-ocorrencia-id-memorando/) | verified | high | 2026-11-05 |
| [WeiPHP wp_where() 信任用户可控 exp 数组：bind_follow 未授权报错 SQL 注入](web-generic-sqli-thinkphp-where-exp-array-injection/) | verified | high | 2026-11-05 |
| [WeKnora Agent database_query 工具 SQL 注入：注释替代空白绕过表名正则，pg_read_file 读取数据库服务器文件（CVE-2026-22687）](web-generic-sqli-weknora-database-query-comment-bypass-file-read/) | verified | medium | 2026-11-06 |
| [WeKnora SQL 校验器未递归 ArrayExpr/RowExpr：PostgreSQL 函数黑名单绕过经大对象写 .so 实现 RCE（CVE-2026-30860）](web-generic-sqli-weknora-arrayexpr-validator-bypass-lo-rce/) | verified | high | 2026-11-06 |
| [WordPress 1.5.1.1 的 /?cat= 未过滤拼接：order by 探列 → UNION 回显 database() → group_concat 用 0x2d 分隔拖 wp_users（含 user_level）](web-generic-sqli-wordpress-151-cat-union-dump-wp-users/) | verified | high | 2026-11-08 |
| [WordPress Automatic <3.92.1 csv.php 未授权 SQL 注入（CVE-2024-27956）：auth=%00 + integ=md5(q) 绕过并 INSERT 管理员](web-generic-sqli-wordpress-automatic-csv-unauth-cve-2024-27956/) | verified | high | 2026-11-09 |
| [WordPress LayerSlider ls_get_popup_markup 的 id[where] 数组参数未授权 SQL 注入（CVE-2024-2879）：esc_sql 转义循环显式跳过 where 键](web-generic-sqli-wordpress-layerslider-popup-markup-where-array/) | verified | high | 2026-11-09 |
| [WordPress Ultimate Member 2.8.2 um_get_members sorting 参数时间盲注（CVE-2024-1071）：exploit 取 nonce/directory_id + sqlmap dump wp_users](web-generic-sqli-wordpress-ultimate-member-sorting-cve-2024-1071/) | verified | high | 2026-11-08 |
| [WordPress 插件 ORDER BY 裸拼时间盲注：ORDER BY 子查询 SLEEP 逐字符提取管理员哈希（CVE-2026-9179）](web-generic-sqli-wordpress-plugin-order-by-time-blind/) | verified | high | 2026-11-05 |
| [XFire SOAP 参数直落 SQL 文本：预编译执行拼接语句导致未授权 SQL 注入（MSSQL 延时验证）](web-java-framework-xfire-soap-parameter-sql-injection/) | verified | high | 2026-11-08 |
| [xp_cmdshell 被拦时用 xp_dirtree 递归列目录定位 Web 站点绝对路径](web-generic-sqli-mssql-xp-dirtree-webroot-enumeration/) | verified | high | 2026-11-08 |
| [万户 ezOFFICE receivefile_gd.jsp recordId 未授权 SQL 注入：HashMap→EJB→wf_onlineuser 删除语句拼接](web-generic-sqli-whir-ezoffice-receivefile-gd-recordid/) | verified | high | 2026-11-07 |
| [万户OA 三处 JSP 拼接 SQL 注入：statDate/numId/RecordID 直入查询](web-generic-sqli-whir-ezoffice-jsp-concat-three/) | verified | high | 2026-11-07 |
| [业务豁免参数 operType=132 使 SQL 注入过滤器整体放行](web-generic-sqli-business-exemption-param-filter-bypass/) | verified | high | 2026-11-04 |
| [东胜物流系统三处 SQL 注入：modulename/optype/attrid 参数直拼 MSSQL](web-generic-sqli-dongsheng-logistics-multi-entry-concat/) | verified | medium | 2026-11-06 |
| [九垠赢系统 QueryConfig/DeleteIn 参数拼接导致 Oracle 删除型 SQL 注入](web-generic-sqli-jiuyin-queryconfig-deletein-oracle/) | verified | high | 2026-11-05 |
| [二次注入：恶意数据先安全入库，后续读取拼接时触发 SQL 注入](web-generic-sqli-second-order-injection/) | verified | medium | 2026-11-05 |
| [从访问日志/pcap 按响应差异还原布尔盲注：ord/substr ASCII 逐字符提取](web-generic-sqli-blind-log-pcap-response-length-recovery/) | verified | high | 2026-11-07 |
| [以“正常/异常回显”为布尔 oracle 的 EXISTS+left() 盲注提取密码](web-generic-sqli-exists-left-boolean-oracle/) | verified | high | 2026-11-04 |
| [信呼OA 2.6.5 前台 SQL 注入：openkqjAction 重写 initAction 绕过 openkey，ccid 直拼 kqjcmdModel::savefingerprint](web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth/) | verified | high | 2026-11-07 |
| [信呼OA getmfilvAction：fname 先 base64decode 后被 insert 拼进 filename，绕过全局黑名单做时间盲注](web-generic-sqli-xinhu-getmfilv-fname-base64-insert/) | verified | medium | 2026-11-08 |
| [信呼OA openapi opendkq zktime：Host 头伪造绕过 openkey 校验，JSON 的 sn 直拼 insert 形成前台 SQL 注入](web-generic-sqli-xinhu-opendkq-zktime-sn-insert/) | verified | high | 2026-11-08 |
| [信呼OA openbase querydata：basemodenum 经 flowModel→initbase 拼进 `num` 条件，Host 头绕过校验的前台 SQL 注入](web-generic-sqli-xinhu-openbase-querydata-basemodenum-initbase/) | verified | medium | 2026-11-08 |
| [信呼OA v2.6.3 备份恢复 huifdatanewAjax：JSON 里的 createsql 被 db->query 直接执行，adminid=1 可任意 SQL](web-generic-sqli-xinhu-beifen-huifdatanew-createsql-arbitrary-sql/) | verified | high | 2026-11-08 |
| [信呼OA v2.7.0 前台 SQL 注入：setwxqyAction 对 base64decode(shouji/userid) 直接拼入 getone](web-generic-sqli-xinhu-setwxqy-base64-mobile-getone/) | verified | high | 2026-11-07 |
| [信呼OA 后台 base64 参数绕过全局过滤：inputAction actstr 与 tableAction dz 两处 SQL 注入](web-generic-sqli-xinhu-base64-filter-bypass-admin-actions/) | verified | high | 2026-11-07 |
| [前端 JS 暴露的 Identity_Get 未授权接口：单引号报错确认 Oracle 字符串型注入并 UNION 取数](web-generic-sqli-frontend-js-hidden-identity-get-oracle-union/) | verified | medium | 2026-11-08 |
| [华夏ERP /account/list 的 search JSON 进入 MyBatis LIKE '%${name}%' 时间盲注](web-generic-sqli-xiahuia-erp-account-search-json-like-injection/) | verified | high | 2026-11-05 |
| [单引号被转义的 GBK 注入点用 %bf%27 宽字节逃逸并 UNION 取数](web-generic-sqli-gbk-wide-byte-ctf-ezsql/) | verified | high | 2026-11-06 |
| [后台报表/菜单 SQL 编辑器可执行任意 SQL：SQL Server xp_cmdshell 命令执行](web-generic-sqli-admin-report-sql-editor-xp-cmdshell/) | verified | high | 2026-11-05 |
| [堆叠注入改 s_filedata 文件路径：借 FileGUID 下载接口任意文件读取（FileDir 长度溢出到 FilePath）](web-generic-sqli-stacked-file-table-arbitrary-file-read/) | verified | high | 2026-11-08 |
| [大小写敏感关键字检测 + 反斜杠吞引号：大写绕过 strpos/str_ireplace 组合后用 ASCII()>c 盲注读密码](web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii/) | verified | medium | 2026-11-08 |
| [布尔盲注先定闭合：单引号版 payload 无差异不是「没有注入」，而是闭合符实为 ')——用 1'||'1'='1 与 1')||(1='1 对比差分定出真闭合](web-generic-sqli-boolean-blind-parenthesis-closure-discovery/) | verified | medium | 2026-11-08 |
| [布尔盲注的大小写陷阱：字符比较大小写不敏感，登录校验区分大小写时用 ORD/ASCII 还原](web-generic-sqli-blind-ascii-case-restore-login/) | verified | high | 2026-11-06 |
| [引号黑名单 MySQL 注入：反斜杠转义闭合引号 + 十六进制字面量 UNION 写入会话用户名触发 Jinja2 SSTI](web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti/) | verified | high | 2026-11-06 |
| [报表 fieldConditions.value 拼接 SQL：updatexml 报错 + union 四列注出 user()/version()](web-generic-sqli-json-fieldconditions-value-updatexml-union/) | verified | high | 2026-11-07 |
| [搜索接口 LIKE '%value%' 字符串拼接导致 SQL 注入](web-generic-sqli-like-clause-append-search/) | verified | high | 2026-11-05 |
| [搜索框 LIKE '%输入%' 的注入要“闭合再补回”：payload 末尾必须自己补上 %' 把模式串接回去，否则语法错、sqlmap 也跑不出来](web-generic-sqli-like-pattern-closed-then-reopened-quote-payload/) | verified | high | 2026-11-08 |
| [数据源配置查询注入：SourceCode 直拼 selectOne 由 ROOT 数据源执行，绕过前台普通用户权限读取后台密码](web-generic-sqli-datasource-sourcecode-root-privilege/) | verified | high | 2026-11-08 |
| [某和OA RssModulesHttp.aspx interfaceID 未授权 SQL 注入：GetRssInfo 直接把参数拼进 MSSQL 查询](web-generic-sqli-jhsoft-rssmoduleshttp-interfaceid-unauth/) | verified | high | 2026-11-09 |
| [汉王e脸通 MyBatis `${columnKey} ${order}` 排序注入：queryManyPeopleGroupList 与 queryAntiStealthyList 两个后台接口](web-generic-sqli-hanvon-eface-order-columnkey-mybatis/) | verified | high | 2026-11-07 |
| [泛微 e-cology mobilemode runSQL 后台 SQL 注入：datasource 非本地池绕过 isSafeSql 执行 insert/update/delete](web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass/) | verified | high | 2026-11-05 |
| [泛微 e-cology9 WorkPlanService 前台 SQL 注入：deleteWorkPlan 的 workid 直拼 WorkPlan 查询](web-generic-sqli-weaver-ecology-workplanservice-deleteworkplan/) | verified | high | 2026-11-07 |
| [泛微 E10 getLogManagerByCon/getAllArthasPort 拼接 searchInput SQL 注入：sleep 时间盲注](web-generic-sqli-weaver-e10-logmanager-arthasport-searchinput/) | verified | medium | 2026-11-07 |
| [泛微 e9 /api/doc/out/more/list 未授权布尔盲注：两段式 sessionKey 与 counts 判真](web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind/) | verified | high | 2026-11-05 |
| [泛微 e9 browser.jsp 未授权 union 注入：%20 制造双斜杠绕过移动端安全规则](web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli/) | verified | high | 2026-11-05 |
| [泛微 e9 FileDownloadLocation 未授权 SQL 注入：union 控制 emlpath/subject 实现任意文件读取与密码回显](web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read/) | verified | high | 2026-11-05 |
| [瑞友天翼 7.0.5.1 PHP 升级致 magic_quotes 失效：appsave/appdel GET 注入与 INTO OUTFILE 写 WebShell](web-generic-sqli-ruiyou-tianyi-php54-appsave-appdel-outfile-webshell/) | verified | high | 2026-11-09 |
| [瑞友天翼应用虚拟化 AgentBoard.XGI SQL 注入 INTO OUTFILE：Windows WebRoot 写 PHP webshell RCE](web-generic-sqli-ruiyou-tianyi-agentboard-xgi-union-outfile-webshell/) | draft | medium | 2026-11-08 |
| [登录处 UNION 注入伪造管理员行：密码列填已知明文 MD5 使哈希比对通过](web-generic-sqli-login-union-forge-admin-known-md5/) | verified | high | 2026-11-08 |
| [登录密码字段未加引号：利用 or 优先级构造恒真条件绕过登录](web-generic-sqli-login-password-unquoted-or-bypass/) | verified | high | 2026-11-05 |
| [登录框注入点只过滤单引号/select/union/空格/逗号：用反斜杠吞掉闭合引号 + %09 替代空格 + substr(...from N for M) 绕过逗号过滤，ASCII 盲注出同表 code 字段登录](web-generic-sqli-login-quote-escape-tab-substr-from-for-ascii-blind/) | verified | high | 2026-11-09 |
| [登录用户名注入 + 注释符万能密码：枚举管理员用户名接管后台](web-generic-sqli-login-username-comment-universal-password/) | verified | high | 2026-11-05 |
| [禁数字与截取函数的布尔盲注：true and (子查询) like 'prefix%' 逐字符提取](web-generic-sqli-true-and-like-prefix-blind-no-digits/) | verified | high | 2026-11-06 |
| [禅道 baseRouter::setVersion 未过滤 account 直接拼 SQL：index.php 初始化阶段即可未授权注入](web-generic-sqli-zentao-router-setversion-account-preath/) | verified | high | 2026-11-09 |
| [禅道开源版搜索 words 参数：getSqlParams 直接拼进 AGAINST() 与 LIKE 双条件导致前台 SQL 注入](web-generic-sqli-zentao-search-words-against-like/) | verified | high | 2026-11-08 |
| [笛卡尔积时间盲注：SLEEP、空格与等号被过滤时逐字符提取](web-generic-sqli-cartesian-product-time-blind/) | verified | high | 2026-11-05 |
| [等号被过滤时用 XOR（^）当比较运算符：if(... ^ ... , BENCHMARK) 造时间盲注 oracle](web-generic-sqli-xor-boolean-oracle-no-equal-sign/) | verified | medium | 2026-11-09 |
| [语义型 WAF 的 SQLi 绕过：OR/|| 解析差异与闭合-运算符-函数逐层 fuzz](web-generic-sqli-semantic-waf-layerwise-bypass/) | verified | high | 2026-11-05 |
| [达梦 DMSQL 注入实战：无 updatexml 时用除零/exp 溢出报错与布尔盲注，靠 SYS 系统表与 UTL_* 带外取数](web-generic-sqli-dameng-dmsql-error-boolean-oob-systables/) | verified | medium | 2026-11-08 |
| [通天星 CMSV6 edu_security_officer/disable 的 ids 直拼 UPDATE ... IN：大写 SLEEP 与 %28 编码绕过 SQL 过滤器的时间盲注](web-generic-sqli-cmsv6-edu-security-officer-disable-ids/) | verified | high | 2026-11-08 |
| [通天星 CMSV6 point_manage/merge 的 name 直拼 WHERE：大写/换行绕过 XssSqlFilter 后 UNION INTO DUMPFILE 写 JSP WebShell](web-generic-sqli-cmsv6-point-manage-merge-name-dumpfile/) | verified | medium | 2026-11-08 |
| [金和 OA C6 GeneralXmlhttpPage.aspx CheckAppraiseState 的 id 直拼 SQL：MSSQL WAITFOR 时间盲注](web-generic-sqli-jhsoft-generalxmlhttppage-appraiseid-time-sqli/) | verified | high | 2026-11-07 |
| [隐藏参数发现到 SQL 注入：Arjun 扫出 PHP 端点 ?id + Burp Intruder 枚举报错差分 + if(sleep) 时间盲注](web-generic-sqli-arjun-hidden-param-intruder-diff-time-blind/) | verified | high | 2026-11-08 |
| [非 HTTP 原始 TCP 登录服务的 SQL 时间盲注：TCP→HTTP 中转代理让 sqlmap 可用](web-generic-sqli-raw-tcp-login-relay-proxy/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
