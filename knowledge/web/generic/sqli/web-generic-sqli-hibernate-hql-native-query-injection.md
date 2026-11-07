---
id: web-generic-sqli-hibernate-hql-native-query-injection
title: Hibernate HQL 与原生 SQL 拼接注入：createQuery/createNativeQuery 及命名查询 replace 陷阱
type: scenario
domain: web
path: web/generic/sqli
technique: hibernate-hql-injection
aliases:
- HQL 注入
- Hibernate HQL 注入
- Hibernate 原生 SQL 注入
- createNativeQuery 注入
- createNamedQuery replace 注入
- HQLmap
tags:
- sqli
- java
- hibernate
- hql
- jpa
- named-query
- orm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:45:10+08:00'
  notes: 已对照原文核对：createQuery HQL拼接、createSQLQuery/createNativeQuery原生SQL拼接、@NamedNativeQuery占位符被replace绕过，及HQL的union/注释符版本限制均与原文一致；原文仅为语法示例无目标实测，卡片confidence=medium、未声称已打通。无组件版本，未设versions；未执行PoC
---

## 一句话结论

Hibernate/JPA 中把用户输入拼进 `createQuery()` 的 HQL 或 `createSQLQuery()`/`createNativeQuery()` 的 SQL，都会在查询解析前改变语句结构；即使是 `@NamedNativeQuery` 里写死的占位符，只要业务代码用 `replace()` 替换用户输入，也会重新引入注入。

## 原理

Hibernate 提供两套查询：

- HQL：面向实体类的查询语言，Hibernate 先把 HQL 翻译成 SQL 再执行；
- 原生 SQL：`createSQLQuery`（Hibernate 5 起废弃）、`createNativeQuery` 直接执行 SQL。

两者的安全边界相同：`setParameter()`/`setProperties()` 对应预编译参数绑定；字符串拼接则让输入进入语法层。HQL 多一层翻译，带来一些限制，但不等于安全：

- 查询对象是实体类与已映射字段，不是任意表；
- `UNION` 在 5.x 不支持，6.x 起在映射关系满足时可使用；
- 注释符 `/**/` 仅 6.x 支持，`--` 与 `#` 各版本均不支持；
- 子查询可用但限于已映射表/字段；延时函数不支持。

这些限制缩小了可利用空间，却仍可通过布尔逻辑、子查询、报错或已映射字段做数据提取；原生 SQL 则没有这些限制。

另一类常见陷阱是命名查询：注解里写死 `'%PLACEHOLDER%'`，业务代码用 `getQueryString().replace("PLACEHOLDER", book)` 拼入用户输入。`replace()` 发生在 HQL/SQL 字符串上，等价于拼接，命名查询的参数绑定优势被完全绕过。

## 触发条件

- `createQuery(hql)`、`createSQLQuery(sql)`、`createNativeQuery(sql)` 的参数字符串由用户输入拼接；
- 或 `@NamedQuery`/`@NamedNativeQuery` 的查询串被取出后 `replace()` 用户输入，而不是 `setParameter()`；
- 用户可控值进入 HQL/SQL 的值位置、标识符位置或 `ORDER BY` 等动态片段；
- 项目使用 Hibernate/JPA，且未对拼接点做白名单/参数化改造。

## 利用步骤

1. 审计搜索 `createQuery(`、`createSQLQuery(`、`createNativeQuery(`、`createNamedQuery(`，检查参数是否由字符串拼接或 `replace()` 生成。
2. 判断查询类型：HQL 先确认实体名与映射字段（从实体类、`@Entity`、`@Table`、`@Column` 获取）；原生 SQL 按普通 SQL 注入处理。
3. HQL 值位置尝试单引号闭合与布尔对比（`' AND '1'='1` / `' AND '1'='2`）；受限时改用子查询/已映射字段做布尔或报错推断。
4. 原生 SQL 可用 union、报错、时间盲注等常规手法；HQL 不支持 `--`/`#` 注释，payload 需按实际语法闭合剩余部分。
5. HQL 注入 sqlmap 支持有限，可使用 HQLmap；原生 SQL 可直接用 sqlmap。
6. 命名查询场景确认 `replace()` 后的最终查询串，再按对应语法构造 payload。

## PoC

```java
// 不安全：HQL 拼接
String hql = "SELECT s FROM Student s WHERE s.name = '" + name + "'";
Query q = entityManager.createQuery(hql, Student.class);
// name = ' OR '1'='1  ->  WHERE s.name = '' OR '1'='1'

// 安全：命名参数
String hql = "SELECT s FROM Student s WHERE s.name = :name";
Query q = entityManager.createQuery(hql, Student.class);
q.setParameter("name", name);
```

```java
// 不安全：命名查询 + replace
@NamedNativeQuery(
    name = "Student.findByBook",
    query = "SELECT * FROM student WHERE book LIKE '%PLACEHOLDER%'"
)
String qs = em.createNamedQuery("Student.findByBook")
    .unwrap(Query.class).getQueryString()
    .replace("PLACEHOLDER", book);   // 用户输入直接进入 SQL

// 安全：注解用 :book，代码 setParameter
@NamedNativeQuery(
    name = "Student.findByBook",
    query = "SELECT * FROM student WHERE book LIKE :book"
)
TypedQuery<Student> q = em.createNamedQuery("Student.findByBook", Student.class);
q.setParameter("book", "%" + book + "%");
```

```bash
# HQL 专用工具
python HQLmap.py --url="http://target/search?q=alice" --param=q --check
python HQLmap.py --url="http://target/search?q=alice" --param=q -T Student --columns --dump
```

## 变体与关联

- 原生 SQL 变体：`createSQLQuery`（H5 废弃）与 `createNativeQuery` 行为一致，拼接即注入。
- 命名查询变体：`@NamedQuery`（HQL）同样可能被 `replace()` 绕过，改为 `:param` + `setParameter`。
- HQL 6.x 变体：支持 `UNION` 与 `/**/` 后，可利用面比 5.x 更大；仍需已映射实体/字段。
- 关联：JDBC 拼接注入、MyBatis `${}` 注入；三者共同根因是“用户输入进入查询文本而非参数绑定”。

## 检测与防御

- 防御：所有入参位置使用 `:param` 命名占位 + `setParameter()`/`setProperties()`；禁止对查询串做 `replace()`/`format()`/字符串拼接。
- 标识符与动态片段（表名、排序字段）不能参数化时使用固定枚举/白名单映射。
- 审计：搜索 `createQuery`、`createSQLQuery`、`createNativeQuery`、`createNamedQuery`，追踪参数是否来自请求；搜索 `.replace(` 与查询串的组合。
- 检测：Hibernate SQL 日志中出现用户输入引号/布尔表达式；HQL 报错暴露实体/字段名；对非常规查询结构告警。
- 测试：HQL 用布尔对比与子查询验证，注意注释符限制；原生 SQL 用常规注入手法；命名查询重点验证 `replace()` 后的最终语句。
