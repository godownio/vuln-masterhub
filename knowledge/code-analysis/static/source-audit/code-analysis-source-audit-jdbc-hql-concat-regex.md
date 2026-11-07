---
id: code-analysis-source-audit-jdbc-hql-concat-regex
title: 大型 JDBC/HQL 项目的拼接注入审计：预编译基线与 .append(... + ...) 正则筛选
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: jdbc-hql-concat-regex-audit
aliases:
- JDBC 注入审计
- append 拼接 SQL 审计
- 正则筛注入
- 预编译基线审计
- HQL 拼接审计
- 大型项目 SQL 注入审计
- SQL 拼接 grep
tags:
- code-audit
- java
- jdbc
- hql
- sqli
- regex
- source-audit
- static-analysis
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:19:24+08:00'
  notes: 已对照原文与18张截图核对预编译基线/.append(...+...)正则/HQL LIKE拼接点/controller参数溯源；原文未给出实际注入回显或数据提取，仅代码审计结论，PoC未在本会话执行
---

## 一句话结论

在没有 MyBatis、以 JDBC/HQL 为主的大型 Java 项目里，先用“正常查询是否使用 `?` 占位 + 参数数组/setParameter”建立预编译基线，再用正则批量筛出 `.append(... + ...)`、`LIKE '%...+...%'` 等非参数化写法，最后沿 controller 的 `@RequestParam` 回溯到 DAO/QT 方法，可以把几千处 SQL 操作快速收敛到少量可注入点。

## 原理

- **预编译与拼接的代码形态不同**：安全写法通常出现 `?` 占位符、`Object[] params`、`setParameter`/`setString`；拼接写法则是 `StringBuilder.append("... " + value)`、`String.format`、`"where x = '" + value + "'"`。形态差异让正则筛选成为可能。
- **正则不证明注入，只负责降噪**：命中 `.append(... + ...)` 不一定可控，可能拼的是常量或服务端计算值；但把几千处 SQL 操作压缩到几十处“含变量拼接”的候选，再由人工回溯参数来源，效率远高于逐条阅读。
- **重点不在值位置，而在“无法参数化的位置”**：`ORDER BY` 列名、表名、`IN` 列表、`LIKE` 模式串等地方开发者常以“不能预编译”为由拼接；这些位置需要白名单映射，不能直接拼用户输入。
- **HQL 与 JDBC 共用同一套审计思路**：HQL 的 `hql.append("and (bm like '%" + keyWorld + "%' ...)")` 与 JDBC 的 `where name = '" + name + "'"` 本质相同——用户输入进入查询文本，而不是作为绑定参数。
- **误报与漏报**：正则可能命中日志拼接、常量拼接；也可能漏掉跨行拼接、变量间接赋值、`StringBuilder` 分段 append。应配合数据流追踪/SAST 与手工确认。

## 触发条件

- 能拿到项目源码或反编译产物，且项目规模较大（数百至数千处 SQL 操作）。
- 项目以 JDBC、Hibernate HQL/原生 SQL 或自研 JDBC 工具类为主，未全面使用 MyBatis 的 `#{}` 参数绑定。
- 代码中存在少量非预编译写法，且部分参数来自 `@RequestParam`/`getParameter`。
- 审计者需要快速定位候选点，而不是对每个 SQL 调用逐一阅读。

## 利用步骤

1. 判断查询技术栈：搜索 `mybatis` 依赖、`#{}`/`${}`、`createQuery`、`createNativeQuery`、`JdbcTemplate`、`queryForList`、`prepareStatement` 等特征。没有 MyBatis 时按 JDBC/HQL 处理。
2. 建立预编译基线：搜索 `where`、`append`、`?`、`setParameter`、`Object[] params`，观察多数查询是否使用占位符与参数数组。
3. 用正则筛非预编译写法（按项目实际风格调整）：
   - `.append(` 参数中含 `+` 的拼接；
   - `LIKE '%` 后直接跟 `+` 变量；
   - `String.format` 生成 where/order by；
   - `createQuery(`/`createNativeQuery(` 的参数字符串含 `+`。
4. 对每个命中点回溯：方法参数是否来自 controller 的 `@RequestParam`/`request.getParameter`，中间是否有白名单、类型转换、转义。
5. 单独审查无法参数化的位置：`ORDER BY`、表名、`IN` 列表、`LIKE` 模式串，确认是否用固定枚举/白名单。
6. 对确认可控的点，用布尔/时间/报错 payload 或 sqlmap/HQLmap 验证；记录注入类型与数据库权限。

## PoC

审计命令示例（ripgrep，按项目风格调整）：

```bash
# 1. 找 StringBuilder/StringBuffer 中带变量拼接的 append
rg -n '\.append\([^)]*\+[^)]*\)' --glob '*.java'

# 2. 找 LIKE '%...' 直接拼变量
rg -n "LIKE\s*'%?\s*\"?\s*\+" --glob '*.java'

# 3. 找 createQuery/createNativeQuery 的字符串拼接
rg -n 'create(Query|NativeQuery|SQLQuery)\s*\([^)]*\+' --glob '*.java'
```

命中的典型危险代码：

```java
// HQL：搜索关键字直接进入 LIKE 模式串
if (!keyWorld.isEmpty()) {
    hql.append("and (bm like '%" + keyWorld + "%' or mc like '%" + keyWorld + "%')");
}
```

```java
// JDBC：where 条件直接拼接
sb.append(" where id = " + id);
sb.append(" order by " + sortField);
```

对应的 controller 溯源示例：

```java
@GetMapping("/find")
public List<Report> find(@RequestParam(value = "keyWorld", required = false) String keyWorld) {
    return service.find(flag, start, end, shzt, keyWorld);  // 一路传到 hql.append
}
```

说明：以上为审计方法与结构化示例；正则只用于候选筛选，是否可注入需结合参数来源与运行验证。

## 变体与关联

- 变体（拼接 API）：`String.format("... %s", value)`、`MessageFormat`、`+` 直接拼在 `createQuery` 参数里、`StringBuilder.append` 分段拼接；正则需按实际代码风格扩展。
- 变体（无法参数化）：`ORDER BY` 列名、表名、`IN (…)`、`LIKE` 模式串；应改为枚举/白名单映射，而不是拼接。
- 变体（ORM 差异）：MyBatis 用 `${}`、JPA/Hibernate 用 `createQuery` 拼接、JFinal 用 `whereLike`，代码形态不同但根因一致。
- 关联：[[web-generic-sqli-hibernate-hql-native-query-injection]]（HQL/原生 SQL 拼接注入的利用与限制）；[[web-generic-sqli-like-clause-append-search]]（LIKE '%value%' append 注入）；[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置无法预编译时的注入）。
- 边界：全量使用参数绑定、拼接值均为服务端常量/白名单、或正则覆盖不到跨行/间接赋值时，需改用 SAST/数据流追踪，不能只依赖 grep。

## 检测与防御

- 检测（审计侧）：把上述正则加入代码审计清单；对每个 `append(... + ...)` 命中点检查参数来源；重点看 controller → service → DAO 的调用链。
- 检测（运行时）：SQL 日志中出现用户输入的单引号、布尔表达式、`--`/`#` 注释；同一接口在关键字变化时返回结构异常；数据库报错暴露 SQL 片段。
- 防御：所有值位置使用 `?`/`:param` 绑定；`ORDER BY`、表名、`IN` 列表用固定枚举/白名单映射；禁止 `String.format`/`+`/`append` 拼接用户输入。
- 防御（工程）：在 CI 中加入针对拼接 SQL 的 SAST 规则与 grep 门禁；对自研 JDBC 工具类封装参数化查询，减少开发者手写拼接的机会。
- 防御（验证）：修复后用原 payload 回归，确认输入被当作值而非语法；对动态标识符位置单独做白名单测试。
