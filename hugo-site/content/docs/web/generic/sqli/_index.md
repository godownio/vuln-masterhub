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
| [.NET Handler 参数直拼 MSSQL：getCities/getPersonInfo 用 @@VERSION 报错回显注入](web-generic-sqli-dotnet-handler-mssql-param-concat-version/) | verified | high | 2026-11-05 |
| [.NET 参数直拼 Oracle 查询：itemid/key 用 dbms_xdb_version.checkin(user) 报错注入](web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin/) | verified | high | 2026-11-05 |
| [AI WAF 语义拦截下的 MySQL 版本注释绕过：/*!50000union*/ 被当成注释、MySQL 仍执行](web-generic-sqli-ai-waf-mysql-versioned-comment-bypass/) | verified | high | 2026-11-06 |
| [Artery ERP workflow.sqlResult 未授权 SQL 注入：params/sql 直接交给 executeQuery](web-generic-sqli-artery-erp-workflow-sqlresult-unauth/) | verified | high | 2026-11-07 |
| [ASP.NET WebForms 报表 txtWhere 拼接 WHERE：') 闭合与 1/DB_NAME() 报错注入](web-generic-sqli-aspnet-webforms-report-txtwhere-mssql/) | verified | high | 2026-11-05 |
| [BootDo 列表接口 `${sort} ${order}` 文本拼接：Map 隐藏参数 sort/order 的 ORDER BY SQL 注入](web-generic-sqli-bootdo-sort-order-token/) | verified | high | 2026-11-05 |
| [CCFlow/CCBPM Demo Port_Emp 未授权 SQL 注入：报错/UNION 取管理员口令并伪造 privateKey 令牌](web-generic-sqli-ccflow-demo-port-emp-unauth/) | verified | high | 2026-11-05 |
| [ClickHouse 盲注：FROM 前置 + INTERSECT/JOIN ON LIKE 绕过 select.*from 黑名单](web-generic-sqli-clickhouse-from-first-intersect-join-blind/) | verified | high | 2026-11-07 |
| [Content-Type 双头混淆：WAF 判为文件上传、Tomcat 按表单解析的 SQLi 绕过](web-generic-sqli-content-type-dual-header-waf-bypass/) | verified | high | 2026-11-05 |
| [CordysCRM departmentIds 经 StringJoiner 拼入 FIELD() 再进 MyBatis ${orderByClause}：列表接口 SQL 注入](web-generic-sqli-cordyscrm-departmentids-field-orderby/) | verified | medium | 2026-11-05 |
| [Craft Commerce sort 参数 ORDER BY 时间盲注（CVE-2026-29172）](web-generic-sqli-craft-commerce-sort-orderby-time-blind/) | verified | high | 2026-11-05 |
| [CVE-2026-1207 Django PostGIS raster band index 未校验导致堆叠 SQL 注入](web-generic-sqli-django-postgis-raster-band-index/) | verified | high | 2026-11-05 |
| [Cynthia 项目管理系统用户列表 LIKE 拼接时间盲注：initUser=true 的 userName 直入 JDBC Statement](web-generic-sqli-cynthia-user-list-like-time-blind/) | verified | high | 2026-11-07 |
| [Django CVE-2026-1312：order_by + FilteredRelation 带点别名走 RawSQL 导致 SQL 注入](web-generic-sqli-django-orderby-filteredrelation-period-alias/) | verified | high | 2026-11-05 |
| [Django FilteredRelation 列别名未校验：annotate/alias 的 **kwargs 键注入 SQL](web-generic-sqli-django-filteredrelation-alias/) | verified | high | 2026-11-05 |
| [edu 就业系统统计查询 otherQuery 参数 SQL 注入：Oracle 后端 sqlmap 获取交互式 SQL shell](web-generic-sqli-edu-employment-otherquery-oracle-sql-shell/) | verified | medium | 2026-11-07 |
| [EIS 办公平台 Down.aspx i 参数直拼 main_id：前台 MSSQL 延时注入](web-generic-sqli-eis-down-aspx-i-param-mssql/) | verified | high | 2026-11-05 |
| [EIS 办公平台 Notify.asmx getTodo：targets.LoginName 直拼 SQL 并打通 xp_cmdshell](web-generic-sqli-eis-notify-asmx-loginname-xp-cmdshell/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 文章列表 orderBy 参数注入：MyBatis-Plus orderByDesc 拼入 ${ew.customSqlSegment}](web-generic-sqli-fastcms-article-list-orderby-injection/) | verified | high | 2026-11-05 |
| [FE 系统 JDBC 拼接 SQL 注入：treeXml.jsp menuName 与 editflow_manager.jsp GUID 直入 WHERE](web-generic-sqli-fe-system-jdbc-concat-treexml-editflow/) | verified | high | 2026-11-05 |
| [FilePress 分享列表 order 参数 ORDER BY 时间盲注：邻近参数漏加白名单（CVE-2026-8133）](web-generic-sqli-filepress-order-orderby-time-blind/) | verified | high | 2026-11-05 |
| [FortiWeb Fabric Connector 预认证 SQL 注入：Bearer token 注入 MySQL INTO OUTFILE 写 .pth 触发 root RCE（CVE-2025-25257）](web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce/) | verified | medium | 2026-11-06 |
| [GBK 宽字节注入：%df 与转义反斜杠合成汉字，让单引号重新逃逸](web-generic-sqli-gbk-wide-byte-escape-bypass/) | verified | high | 2026-11-05 |
| [GEO my WordPress 4.5.4 未授权 SQL 注入：经纬度参数直接拼进 BETWEEN 的时间盲注](web-generic-sqli-geo-my-wordpress-boundary-time-blind/) | verified | high | 2026-11-05 |
| [Hibernate HQL 与原生 SQL 拼接注入：createQuery/createNativeQuery 及命名查询 replace 陷阱](web-generic-sqli-hibernate-hql-native-query-injection/) | verified | medium | 2026-11-04 |
| [HTTP 请求头作为 SQL 注入点：GET/POST 被过滤后的 User-Agent、X-Forwarded-For、Cookie、Referer 注入](web-generic-sqli-http-header-injection/) | verified | medium | 2026-11-05 |
| [IF、SLEEP、AND、OR 被过滤时的 SQL 盲注替代原语](web-generic-sqli-blind-filter-bypass-functions/) | verified | high | 2026-11-05 |
| [J2eeFAST /bpm/procdef/list 的 sql_filter 未经过 DataFilter 切面：${sql_filter} 直接拼接导致 ORDER BY/WHERE 注入](web-generic-sqli-j2eefast-sql-filter-procdef/) | verified | medium | 2026-11-05 |
| [Java Servlet accountid 参数直拼 SQL 导致布尔盲注（CRM 头像保存接口）](web-generic-sqli-java-servlet-accountid-concat-boolean/) | verified | medium | 2026-11-05 |
| [JDBC/MyBatis 标识符位置注入：表名与 ORDER BY 列名无法预编译时的拼接注入](web-generic-sqli-java-identifier-table-order-by-injection/) | verified | high | 2026-11-04 |
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
| [MCMS 5.2.4 /mdiy/dict/listExcludeApp orderBy 参数直拼 ${}：未授权 ORDER BY 注入 updatexml 报错注入](web-generic-sqli-mcms-mdiy-dict-orderby-injection/) | verified | medium | 2026-11-07 |
| [MES getHqlAppend 拼接 siteName/userName/menuName 导致 HQL 注入（findMessages/findImages/menuManager）](web-generic-sqli-mes-hql-append-find-actions/) | verified | high | 2026-11-05 |
| [MetaCRM mcc_login.jsp workerid 参数拼接 SQL 注入（MSSQL WAITFOR DELAY 时间盲注）](web-generic-sqli-crm-mcc-login-workerid-time-blind/) | verified | high | 2026-11-07 |
| [MetInfo 7.6 前台 search/para Base64 JSON 未授权 SQL 注入](web-generic-sqli-metinfo-search-para-base64-blind/) | verified | high | 2026-11-04 |
| [MSSQL 非 xp_cmdshell 写 Webshell：sp_makewebtask 与日志/差异备份](web-generic-sqli-mssql-backup-sp-makewebtask-webshell/) | verified | medium | 2026-11-05 |
| [MyBatis Mapper 中 ${} 文本替换导致 SQL 注入：值、表名、ORDER BY、IN、LIKE 五类拼接点](web-generic-sqli-mybatis-dollar-brace-injection/) | verified | high | 2026-11-04 |
| [MySQL 8.0 TABLE 语句替代 SELECT + exp(710) 溢出报错：绕过 select 关键字过滤的无列名注入](web-generic-sqli-mysql8-table-keyword-exp-error-bypass/) | verified | medium | 2026-11-06 |
| [MySQL INTO OUTFILE 文件名可控：LINES/FIELDS TERMINATED BY 注入写 Webshell](web-generic-sqli-mysql-outfile-filename-clause-injection/) | verified | medium | 2026-11-05 |
| [MySQL LIMIT 位置注入：PROCEDURE ANALYSE 触发报错/延时](web-generic-sqli-mysql-limit-procedure-analyse/) | verified | medium | 2026-11-05 |
| [MySQL Quine 在 REPLACE/@/CONCAT 被过滤时的构造：MAKE_SET(bits,...) + QUOTE(s) + 派生表列别名让查询结果等于输入](web-generic-sqli-make-set-quote-derived-table-quine/) | verified | high | 2026-11-06 |
| [MySQL SQL 注入写 WebShell：INTO OUTFILE、DUMPFILE 与 general_log 落盘](web-generic-sqli-mysql-outfile-general-log-webshell/) | verified | high | 2026-11-05 |
| [MySQL 注入分块拼接任意文件：CONCAT 在表内累积 hex 片段后 INTO OUTFILE 精确导出](web-generic-sqli-mysql-chunked-concat-table-into-outfile/) | draft | high | 2026-11-07 |
| [MySQL 约束攻击：超长用户名截断插入覆盖 admin 账户](web-generic-sqli-mysql-constraint-truncation-admin-overwrite/) | verified | medium | 2026-11-05 |
| [MySQL/MariaDB UNION 注入 + load_file 任意文件读取：列数探测后把文件内容回显到联合查询列](web-generic-sqli-mysql-union-load-file-read/) | verified | high | 2026-11-06 |
| [NewBeeMall MyBatis ${} 两处注入：后台 goodsName 与前台 keyword 直拼 LIKE](web-generic-sqli-newbeemall-mybatis-dollar-goodsname-keyword/) | verified | medium | 2026-11-05 |
| [NocoBase myInAppChannels 的 filter.$lt 拼接进 Sequelize.literal 导致认证后 SQL 注入](web-generic-sqli-nocobase-myinappchannels-sequelize-literal/) | verified | medium | 2026-11-05 |
| [OA JSP orderBy/sort 未走 sqlstr 导致 MySQL 报错注入（linkman_list_sel / listmember）](web-generic-sqli-oa-jsp-orderby-sort-updatexml/) | verified | high | 2026-11-05 |
| [OA TranformdomoaServlet 按 #**# 拆分 multipart 字段名拼接 INSERT，时间盲注](web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli/) | draft | high | 2026-11-05 |
| [ORDER BY 大小比较盲注：UNION 注入候选串作排序键，按首行回显逐字符还原密码](web-generic-sqli-order-by-union-lexicographic-blind/) | verified | high | 2026-11-07 |
| [ORDER BY 注入 INTO OUTFILE 写 webshell：上传文件名承载 PHP 代码 + 正则未锚点绕过](web-generic-sqli-order-by-into-outfile-filename-webshell/) | verified | high | 2026-11-06 |
| [orderType 排序注入：逗号 + if(sleep) 被 WAF 403，重复参数 HPP 绕过做时间盲注](web-generic-sqli-orderby-ordertype-hpp-parameter-pollution-blind/) | verified | high | 2026-11-07 |
| [PageVo.sort 拼接 order by 进入 MyBatis ${pageSql}：分页实体污染多个列表接口的 ORDER BY 注入](web-generic-sqli-pagevo-sort-orderby-pagesql-injection/) | verified | high | 2026-11-07 |
| [PDO 模拟预编译占位符错位注入：反引号列名拼接配合反斜杠逃逸](web-generic-sqli-pdo-emulated-prepare-identifier/) | verified | medium | 2026-11-06 |
| [PHP 搜索接口 LIKE "%$word%" 双引号拼接注入：UNION 拖库、INTO OUTFILE 写 Webshell/反弹 Shell](web-generic-sqli-php-like-double-quote-union-outfile/) | verified | high | 2026-11-05 |
| [PHP 数组参数过滤器回调写错导致 addslashes 失效：serialize 后拼接 SQL 注入](web-generic-sqli-php-array-filter-walk-recursive-unfiltered/) | verified | high | 2026-11-05 |
| [PHPGurukul Student Record Management System 3.2 login.php 登录处 UNION 注入（CVE-2025-5216）](web-generic-sqli-phpgurukul-student-record-login-union/) | verified | high | 2026-11-05 |
| [PHPGurukul 在线课程注册系统 my-profile.php cgpa 参数时间盲注（CVE-2025-10663）](web-generic-sqli-phpgurukul-myprofile-cgpa-time-blind/) | verified | high | 2026-11-05 |
| [PostgreSQL SQL 注入：pg_read_file/pg_ls_dir 读文件与 COPY TO PROGRAM 命令执行](web-generic-sqli-postgres-copy-to-program-rce/) | verified | high | 2026-11-05 |
| [PostgreSQL 注入仅允许 SELECT：用 lo_import/lo_get/lo_export 读写数据库服务器文件](web-generic-sqli-postgresql-lo-import-file-read-write/) | verified | high | 2026-11-05 |
| [PostgreSQL 注入无 information_schema 取列名：json_object_keys + json_populate_record](web-generic-sqli-postgres-json-column-enum/) | verified | high | 2026-11-07 |
| [PostgreSQL 注入绕 WAF：关键字间插入 /*"*/ 注释与 JSON Unicode 转义](web-generic-sqli-postgres-waf-comment-quote-bypass/) | verified | high | 2026-11-07 |
| [RootHub MyBatis LIKE 拼接注入：搜索 s 与后台 nodeTitle 两处 ${}](web-generic-sqli-roothub-mybatis-like-dollar-brace/) | verified | medium | 2026-11-05 |
| [RuoYi 数据权限 ${params.dataScope} SQL 注入：admin 跳过切面覆盖后直入 Mapper](web-generic-sqli-ruoyi-datascope-params-admin-bypass/) | verified | high | 2026-11-07 |
| [RuoYi 部门编辑 ancestors 写入后拼进 IN (${ancestors})：同请求内二阶 SQL 注入](web-generic-sqli-ruoyi-dept-ancestors-second-order-in/) | verified | high | 2026-11-07 |
| [SeaCMS ≤13.3 admin_members.php 后台多处 SQL 注入：uid/uname/id 直接拼接（CVE-2025-10662）](web-generic-sqli-seacms-admin-members-multi-param/) | verified | high | 2026-11-05 |
| [SiteServer CMS V6.15.51 libraryText/list keyword SQL 注入：API Key 访问 + 堆叠查询写 UDF](web-generic-sqli-siteserver-cve-2021-42655-librarytext-udf/) | verified | high | 2026-11-05 |
| [sobey-mchEditor wxarticleList 未授权 SQL 注入：String.format 拼接叠加 getRequestURI 白名单路径穿越绕过](web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass/) | verified | medium | 2026-11-07 |
| [SourceCodester Stock Management System 1.0 后台三处 view 页面 id 参数 UNION 注入（CVE-2025-4786/4787/4267）](web-generic-sqli-sourcecodester-stock-view-id-union/) | verified | high | 2026-11-05 |
| [SourceCodester Stock Management System 1.0 登录 username 参数时间盲注（CVE-2025-4283）](web-generic-sqli-sourcecodester-stock-login-time-blind/) | verified | high | 2026-11-05 |
| [SQL Quine 绕过 UNION 结果自校验：REPLACE(@a:=模板, 占位符, HEX(@a)) 让返回行等于注入 payload 自身（含 SHA2 变体）](web-generic-sqli-replace-hex-self-referential-quine/) | verified | high | 2026-11-06 |
| [SQL Server 堆叠注入开启 xp_cmdshell 与 OLE 自动化实现命令执行](web-generic-sqli-mssql-stacked-xp-cmdshell/) | verified | high | 2026-11-04 |
| [SQL 报错注入：用 updatexml、extractvalue 与类型转换错误回显数据](web-generic-sqli-error-based-extraction/) | verified | high | 2026-11-05 |
| [SQL 注入 WAF 绕过：关键字中插 %0a 拆分正则 + 十六进制字面量替代单引号](web-generic-sqli-waf-newline-keyword-split-hex/) | verified | high | 2026-11-05 |
| [SQL 注入数据库指纹：PostgreSQL/达梦/GaussDB 的版本函数与系统视图差异](web-generic-sqli-db-fingerprint-postgres-dameng-gaussdb/) | verified | high | 2026-11-07 |
| [SQL 注入无回显的 DNS 带外取数：LOAD_FILE UNC 与 xp_cmdshell ping](web-generic-sqli-dnslog-oob-exfiltration/) | verified | medium | 2026-11-05 |
| [SQL 注入：关键字被单次替换为空时用双写还原 select/or/and](web-generic-sqli-keyword-double-write-bypass/) | verified | high | 2026-11-05 |
| [SQLite UNION VALUES 绕过 SELECT 关键字过滤：无需 SELECT 生成 admin 行](web-generic-sqli-sqlite-union-values-select-filter-bypass/) | verified | high | 2026-11-06 |
| [SQLite 堆叠注入 ATTACH DATABASE 写 EJS 模板：借模板 include 读取服务器文件](web-generic-sqli-sqlite-attach-database-write-template-include/) | verified | high | 2026-11-07 |
| [SQLite 布尔盲注：%09 代替空格 + substr 二分提取 secret](web-generic-sqli-sqlite-boolean-blind-tab-bypass/) | verified | high | 2026-11-06 |
| [SQLite 注入：%0a 绕过空格过滤、JOIN 子查询绕过逗号过滤，查 sqlite_master 取 flag](web-generic-sqli-sqlite-newline-join-comma-bypass/) | verified | high | 2026-11-06 |
| [Struts2 自研 Tray 封装 repHashMap 不过滤：searchCode 直接拼接 LIKE 造成 SQL 注入](web-generic-sqli-struts2-tray-searchcode-concat/) | verified | medium | 2026-11-07 |
| [Tmall_demo 五处 MyBatis ORDER BY ${orderUtil.orderBy} 排序注入：OrderUtil 透传 orderBy，sqlmap 时间盲注打通](web-generic-sqli-tmall-orderutil-orderby-mybatis/) | verified | high | 2026-11-07 |
| [WeGIA 3.6.1 Atendido_ocorrenciaControle id_memorando 认证后 SQL 注入（CVE-2026-23723）](web-generic-sqli-wegia-atendido-ocorrencia-id-memorando/) | verified | high | 2026-11-05 |
| [WeiPHP wp_where() 信任用户可控 exp 数组：bind_follow 未授权报错 SQL 注入](web-generic-sqli-thinkphp-where-exp-array-injection/) | verified | high | 2026-11-05 |
| [WeKnora Agent database_query 工具 SQL 注入：注释替代空白绕过表名正则，pg_read_file 读取数据库服务器文件（CVE-2026-22687）](web-generic-sqli-weknora-database-query-comment-bypass-file-read/) | verified | medium | 2026-11-06 |
| [WeKnora SQL 校验器未递归 ArrayExpr/RowExpr：PostgreSQL 函数黑名单绕过经大对象写 .so 实现 RCE（CVE-2026-30860）](web-generic-sqli-weknora-arrayexpr-validator-bypass-lo-rce/) | verified | high | 2026-11-06 |
| [WordPress 插件 ORDER BY 裸拼时间盲注：ORDER BY 子查询 SLEEP 逐字符提取管理员哈希（CVE-2026-9179）](web-generic-sqli-wordpress-plugin-order-by-time-blind/) | verified | high | 2026-11-05 |
| [万户OA 三处 JSP 拼接 SQL 注入：statDate/numId/RecordID 直入查询](web-generic-sqli-whir-ezoffice-jsp-concat-three/) | verified | high | 2026-11-07 |
| [业务豁免参数 operType=132 使 SQL 注入过滤器整体放行](web-generic-sqli-business-exemption-param-filter-bypass/) | verified | high | 2026-11-04 |
| [东胜物流系统三处 SQL 注入：modulename/optype/attrid 参数直拼 MSSQL](web-generic-sqli-dongsheng-logistics-multi-entry-concat/) | verified | medium | 2026-11-06 |
| [九垠赢系统 QueryConfig/DeleteIn 参数拼接导致 Oracle 删除型 SQL 注入](web-generic-sqli-jiuyin-queryconfig-deletein-oracle/) | verified | high | 2026-11-05 |
| [二次注入：恶意数据先安全入库，后续读取拼接时触发 SQL 注入](web-generic-sqli-second-order-injection/) | verified | medium | 2026-11-05 |
| [从访问日志/pcap 按响应差异还原布尔盲注：ord/substr ASCII 逐字符提取](web-generic-sqli-blind-log-pcap-response-length-recovery/) | verified | high | 2026-11-07 |
| [以“正常/异常回显”为布尔 oracle 的 EXISTS+left() 盲注提取密码](web-generic-sqli-exists-left-boolean-oracle/) | verified | high | 2026-11-04 |
| [信呼OA 2.6.5 前台 SQL 注入：openkqjAction 重写 initAction 绕过 openkey，ccid 直拼 kqjcmdModel::savefingerprint](web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth/) | draft | high | 2026-11-07 |
| [信呼OA v2.7.0 前台 SQL 注入：setwxqyAction 对 base64decode(shouji/userid) 直接拼入 getone](web-generic-sqli-xinhu-setwxqy-base64-mobile-getone/) | verified | high | 2026-11-07 |
| [信呼OA 后台 base64 参数绕过全局过滤：inputAction actstr 与 tableAction dz 两处 SQL 注入](web-generic-sqli-xinhu-base64-filter-bypass-admin-actions/) | verified | high | 2026-11-07 |
| [华夏ERP /account/list 的 search JSON 进入 MyBatis LIKE '%${name}%' 时间盲注](web-generic-sqli-xiahuia-erp-account-search-json-like-injection/) | verified | high | 2026-11-05 |
| [单引号被转义的 GBK 注入点用 %bf%27 宽字节逃逸并 UNION 取数](web-generic-sqli-gbk-wide-byte-ctf-ezsql/) | verified | high | 2026-11-06 |
| [后台报表/菜单 SQL 编辑器可执行任意 SQL：SQL Server xp_cmdshell 命令执行](web-generic-sqli-admin-report-sql-editor-xp-cmdshell/) | verified | high | 2026-11-05 |
| [布尔盲注的大小写陷阱：字符比较大小写不敏感，登录校验区分大小写时用 ORD/ASCII 还原](web-generic-sqli-blind-ascii-case-restore-login/) | verified | high | 2026-11-06 |
| [引号黑名单 MySQL 注入：反斜杠转义闭合引号 + 十六进制字面量 UNION 写入会话用户名触发 Jinja2 SSTI](web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti/) | verified | high | 2026-11-06 |
| [报表 fieldConditions.value 拼接 SQL：updatexml 报错 + union 四列注出 user()/version()](web-generic-sqli-json-fieldconditions-value-updatexml-union/) | verified | high | 2026-11-07 |
| [搜索接口 LIKE '%value%' 字符串拼接导致 SQL 注入](web-generic-sqli-like-clause-append-search/) | verified | high | 2026-11-05 |
| [汉王e脸通 MyBatis `${columnKey} ${order}` 排序注入：queryManyPeopleGroupList 与 queryAntiStealthyList 两个后台接口](web-generic-sqli-hanvon-eface-order-columnkey-mybatis/) | verified | high | 2026-11-07 |
| [泛微 e-cology mobilemode runSQL 后台 SQL 注入：datasource 非本地池绕过 isSafeSql 执行 insert/update/delete](web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass/) | verified | high | 2026-11-05 |
| [泛微 E10 getLogManagerByCon/getAllArthasPort 拼接 searchInput SQL 注入：sleep 时间盲注](web-generic-sqli-weaver-e10-logmanager-arthasport-searchinput/) | verified | medium | 2026-11-07 |
| [泛微 e9 /api/doc/out/more/list 未授权布尔盲注：两段式 sessionKey 与 counts 判真](web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind/) | verified | high | 2026-11-05 |
| [泛微 e9 browser.jsp 未授权 union 注入：%20 制造双斜杠绕过移动端安全规则](web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli/) | verified | high | 2026-11-05 |
| [泛微 e9 FileDownloadLocation 未授权 SQL 注入：union 控制 emlpath/subject 实现任意文件读取与密码回显](web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read/) | verified | high | 2026-11-05 |
| [登录密码字段未加引号：利用 or 优先级构造恒真条件绕过登录](web-generic-sqli-login-password-unquoted-or-bypass/) | verified | high | 2026-11-05 |
| [登录用户名注入 + 注释符万能密码：枚举管理员用户名接管后台](web-generic-sqli-login-username-comment-universal-password/) | verified | high | 2026-11-05 |
| [禁数字与截取函数的布尔盲注：true and (子查询) like 'prefix%' 逐字符提取](web-generic-sqli-true-and-like-prefix-blind-no-digits/) | verified | high | 2026-11-06 |
| [笛卡尔积时间盲注：SLEEP、空格与等号被过滤时逐字符提取](web-generic-sqli-cartesian-product-time-blind/) | verified | high | 2026-11-05 |
| [语义型 WAF 的 SQLi 绕过：OR/|| 解析差异与闭合-运算符-函数逐层 fuzz](web-generic-sqli-semantic-waf-layerwise-bypass/) | verified | high | 2026-11-05 |
| [非 HTTP 原始 TCP 登录服务的 SQL 时间盲注：TCP→HTTP 中转代理让 sqlmap 可用](web-generic-sqli-raw-tcp-login-relay-proxy/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
