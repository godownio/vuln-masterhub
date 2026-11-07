---
id: web-generic-sqli-mybatis-dollar-brace-injection
title: MyBatis Mapper 中 ${} 文本替换导致 SQL 注入：值、表名、ORDER BY、IN、LIKE 五类拼接点
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-dollar-brace-injection
aliases:
- MyBatis ${} 注入
- MyBatis 美元符注入
- MyBatis Mapper SQL 注入
- MyBatis 动态 SQL 注入
- foreach 注入
tags:
- sqli
- java
- mybatis
- mapper
- dollar-brace
- prepared-statement
- xml
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:45:30+08:00'
  notes: 已对照原文核对：MyBatis 井号占位符预编译 vs 美元符文本替换，值/表名/ORDER BY/IN/LIKE五类落点及foreach+concat安全写法均与原文一致。已修正frontmatter中多余的null别名。原文无组件版本，未设versions；未执行PoC
---

## 一句话结论

MyBatis 的 `#{}` 会编译成 JDBC `?` 占位符，参数按数据处理；`${}` 是在 SQL 解析前做纯文本替换，任何用户可控的 `${}` 都等价于字符串拼接，用户输入直接进入 SQL 语法层。

## 原理

MyBatis 对原生 JDBC 做封装，两种占位符的语义完全不同：

- `#{}`：生成 `PreparedStatement` 的 `?`，由数据库预编译，参数只作为值绑定，无法改变 SQL 结构；
- `${}`：在生成 SQL 文本时直接替换成输入字符串，替换发生在 SQL 解析之前，输入中的引号、空格、注释符、`UNION` 等都会成为 SQL 语法的一部分。

因此 `${}` 的注入面与原生 JDBC 拼接一致，区别只在写法。常见五类落点：

| 位置 | 不安全写法 | 结果 |
| --- | --- | --- |
| 普通条件值 | `name = '${username}'` | 引号可逃逸，布尔/联合注入 |
| 表名 | `FROM ${tableName}` | 标识符注入，可接子查询/UNION |
| 排序列 | `ORDER BY ${sortColumn}` | 表达式、`IF()`、时间盲注 |
| IN 多值 | `IN (${ids})` | 直接拼集合，可注入 |
| LIKE 模糊 | `LIKE '%${username}%'` | 字符串上下文注入 |

`#{}` 唯一不能覆盖的是表名/列名这类标识符位置，对这些位置应使用白名单，而不是退回 `${}` 后不做校验。

## 触发条件

- Mapper XML 或注解 SQL 中出现 `${}`，且其值来自请求参数、Header、配置或数据库内容；
- 污点未在 Controller/Service 层被白名单或枚举映射截断；
- 该 `${}` 位于值、表名、排序列、IN 集合或 LIKE 模式中；
- 对标识符位置使用 `${}` 且只做了“非空/长度”校验，没有固定集合比对。

## 利用步骤

1. 在 Mapper XML/注解中搜索 `${`，记录每个替换点及其参数名；沿 Controller→Service→Mapper 追踪参数来源。
2. 区分上下文：值位置尝试单引号闭合与 `' AND '1'='1`；`ORDER BY` 位置尝试 `IF(1=1,SLEEP(2),0)`；表名位置尝试括号子查询/`UNION`。
3. 用布尔差异、响应时间或报错确认可执行；MyBatis 的 SQL 日志（`logImpl`/`StdOutImpl`）可直接看到替换后的最终 SQL。
4. 无回显时用时间盲注或报错函数（`extractvalue`/`updatexml`）；确认后交给 sqlmap 等工具扩大利用。
5. 审计修复时，对每个 `${}` 判断能否改成 `#{}`；不能改的标识符位置改为白名单映射。

## PoC

```xml
<!-- 不安全：值位置 -->
<select id="findUser" resultType="User">
  select * from users where name = '${username}'
</select>
<!-- username = ' OR '1'='1  ->  select * from users where name = '' OR '1'='1' -->

<!-- 不安全：排序位置 -->
<select id="listUser" resultType="User">
  select * from users order by ${sortColumn}
</select>
<!-- sortColumn = IF(SUBSTR(database(),1,1)='a',SLEEP(2),0) -->

<!-- 不安全：IN 集合 -->
<select id="getByIds" resultType="User">
  select * from users where id in (${ids})
</select>

<!-- 不安全：LIKE -->
<select id="search" resultType="User">
  select * from users where name like '%${keyword}%'
</select>
```

```xml
<!-- 安全：值/IN/LIKE 全部走 #{} -->
<select id="getUserFromList" resultType="User">
  select * from users where username in
  <foreach collection="list" item="u" open="(" separator="," close=")">
    #{u}
  </foreach>
</select>

<select id="search" resultType="User">
  select * from users where name like concat('%', #{keyword}, '%')
</select>

<!-- 安全：标识符走白名单映射（Java 层校验后只传固定列名） -->
<select id="listUser" resultType="User">
  select * from users order by ${sortColumn}
</select>
<!-- sortColumn 必须是 Map 映射后的固定值，如 name/created_at/id，不能透传原始输入 -->
```

## 变体与关联

- `<foreach>` 中误用 `${item}`：集合元素仍会被文本替换，应使用 `#{item}`。
- 表名/列名/排序字段用 `${}` 时，即使加了引号也无法修复，必须白名单。
- 注解方式 `@Select("... ${x}")` 与 XML 等价。
- 关联：JDBC 标识符位置注入；Hibernate HQL/原生 SQL 拼接注入；两者根因都是“文本替换先于 SQL 解析”。

## 检测与防御

- 防御：值位置一律 `#{}`；IN 用 `<foreach>` + `#{}`；LIKE 用 `concat('%', #{x}, '%')` 或数据库等价函数；表名/排序列用固定枚举映射或白名单。
- 代码审计：搜索 `${`；对每个结果确认参数是否用户可控、是否处于标识符位置、是否有白名单。
- 运行检测：开启 MyBatis SQL 日志，观察 `${}` 替换后的 SQL 是否出现用户输入中的引号、空格、注释符、函数名；对排序/表名参数出现非枚举值告警。
- 测试：对每个疑似参数做单引号闭合、布尔对比、时间盲注；排序参数尝试 `IF()`/`SLEEP()`，表名参数尝试括号子查询。
