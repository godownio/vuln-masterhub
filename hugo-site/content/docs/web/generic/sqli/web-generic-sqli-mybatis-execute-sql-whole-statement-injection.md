---
id: web-generic-sqli-mybatis-execute-sql-whole-statement-injection
title: MyBatis 全语句 ${sql} 拼接：审计搜索 ${ 定位 execute(@Param("sql")) 并从 Controller 透传到任意 SQL 查询
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-whole-statement-dollar-execute-injection
tags:
- mybatis
- sqli
- java
- code-audit
- dollar-substitution
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V548
  verified_at: '2026-11-11T21:51:06+08:00'
  notes: 已对照原文（xz.aliyun.com/news/13068）与全部16张图核对：图01 Mapper select 语句体为单个 ${sql}，图02 DAO List<Map<String,Object>> execute(@Param("sql") String sql)，图03 Controller 调用 execute(sql)，图04 debug 执行 SELECT SCHEMA_NAME AS NAME FROM information_schema.SCHEMATA 返回 information_schema/dreamer-cms/jsh_erp/mysql/performance_schema/sys 六个库，与卡片原理、审计路径、PoC 一致；原文未展示完整 HTTP 参数名，卡片已按通用形式给出示例并注明需按实际参数名调整。通用场景卡，无组件版本，未设置 affected_versions 合理。dedup 与 web-generic-sqli-mybatis-dollar-brace-injection（五类落点）为相关但不同形态（整语句任意 SQL），非同一利用链；dup-scan 无涉及本卡的 pair。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/sqli/web-generic-sqli-mybatis-execute-sql-whole-statement-injection/
draft: false
kb_aliases:
- MyBatis ${sql} 注入
- execute(@Param("sql")) 任意 SQL
- Mapper 全语句拼接
- 代码审计搜索 ${
- information_schema 读取验证
---

## 一句话结论

Java 管理系统里存在一种最彻底的 MyBatis 注入形态：Mapper 的 `<select>` 语句体直接写成 `${sql}`，DAO 层提供 `execute(@Param("sql") String sql)` 这样"执行任意语句"的方法，Controller 又把前端参数原样传进去——`${}` 是文本替换而非预编译占位符，攻击者因此可把任意 SQL 语句拼进查询，审计时全局搜索 `${` 并沿 Mapper→DAO→Controller 追踪即可定位，验证时用 `information_schema.SCHEMATA` 读出全部库名。

## 原理

- **`#{}` 与 `${}` 的本质差异**：`#{}` 会生成 JDBC `?` 占位符并通过 `PreparedStatement` 绑定参数，值只作为数据；`${}` 是 MyBatis 在构建 SQL 前的**字符串文本替换**，参数内容直接进入 SQL 语法树。当整个语句体都是 `${sql}` 时，攻击者控制的不只是某个值，而是完整的 SQL 语句结构。
- **为什么会写成全语句拼接**：这类系统常有一个"通用查询/报表/列表"组件，为兼容不同表、不同字段、动态排序与分页，开发者把 SQL 片段或整条语句交给前端/上层拼好后传入 Mapper；`execute(@Param("sql") String sql)` 这种 DAO 方法就是为了"什么语句都能执行"而设计，天然是任意 SQL sink。
- **审计路径为什么有效**：`${}` 在 Mapper XML 中是显眼的文本特征，全局搜索即可定位所有拼接点；再沿 Java 侧调用链（Mapper 接口方法名 → Service → Controller）确认参数是否来自请求（`@RequestParam`/`@RequestBody`/`HttpServletRequest`），最后在可控参数处插入验证语句并用调试器观察实际执行的 SQL，即可从"可疑"变成"已证实"。
- **能读到什么**：只要数据库账号有权限，攻击者可以查询 `information_schema`（MySQL）等元数据视图枚举库/表/列，进而读取业务数据、管理员口令哈希等；能否堆叠 `UPDATE/DELETE` 或 `INTO OUTFILE` 取决于 JDBC 驱动是否开启多语句（如 MySQL `allowMultiQueries=true`）与数据库权限，不能仅凭注入点直接断言 RCE。
- **为什么容易漏审**：这类通用 DAO 往往被多个 Controller 复用，审计时只看到一个入口就以为影响有限；实际应统计所有调用该 `execute`/`selectBySql` 方法的 Controller，逐个确认参数来源与鉴权，往往会放大影响面。

## 触发条件

- 应用使用 MyBatis，Mapper XML 中存在 `${}` 且其位置是语句结构（整条语句、`ORDER BY`、`LIKE`、`IN` 等）而非普通值。
- 存在把用户输入（请求参数/JSON 字段/Header）传入 `${}` 所在方法的调用链，且中间没有白名单、类型限制或转义。
- 接口可访问（未授权或任意登录用户），数据库账号具备查询 `information_schema`/业务表的权限。
- 若是整语句 `${sql}`，通常需要 DAO 方法签名允许任意字符串（如 `execute(@Param("sql") String sql)`），且没有 SQL 语法校验。

## 利用步骤

1. 全局搜索 Mapper XML 与注解中的 `${`，标记所有拼接点；优先关注语句体只有一个 `${...}` 的"通用查询"。
2. 从 Mapper 接口方法名（如 `execute`/`queryBySql`）反查调用：`grep`/IDE 查 Service 与 Controller，确认参数是否来自 `@RequestParam`/`@RequestBody`/`request.getParameter`。
3. 对可疑接口发送正常请求确认可达与回显格式（列表/JSON/报错）。
4. 在可控参数处插入最小验证语句，例如 `SELECT SCHEMA_NAME AS NAME FROM information_schema.SCHEMATA LIMIT 0;`，用调试器或响应确认语句被执行、库名列表被返回。
5. 进一步按需枚举表/列（`information_schema.TABLES/COLUMNS`）、读取目标业务表；如需写入/多语句，先确认驱动多语句配置与账号权限，再评估影响。
6. 记录完整调用链（Mapper 文件与行号、DAO 方法、Controller 路由、参数名），作为修复依据。

## PoC

```text
# 审计侧最小验证（不执行写操作）
1) 搜索: grep -rn '\${' src/main/resources/**/mapper/*.xml
   命中示例: <select id="execute" resultType="java.util.Map"> ${sql} </select>
2) 调用链:
   List<Map<String,Object>> execute(@Param("sql") String sql);
   -> Service 调用 execute(userParam)
   -> Controller @RequestMapping(...) 接收参数
3) 请求参数（示例，需按实际参数名调整）:
   sql = SELECT SCHEMA_NAME AS NAME FROM information_schema.SCHEMATA LIMIT 0;
4) 观察: 响应/调试器中出现 information_schema、业务库名等结果，证明任意 SQL 被执行
```

```text
判据：Mapper XML 的语句体为单个 ${sql}，DAO 方法以 String 直接接收整条语句，
Controller 未做 SQL 白名单/类型校验；正常请求返回列表数据，注入元数据查询后返回库名。
```

## 变体与关联

- 关联：[[web-generic-sqli-artery-erp-workflow-sqlresult-unauth]]（同为"上层直接传整条 SQL 给执行层"的任意 SQL 注入，本卡 sink 在 MyBatis `${sql}` 而非 JDBC `executeQuery`）、[[web-generic-sqli-docsys-getuserlist-mybatis-like]]（MyBatis `${}` 在 LIKE 值位的常见形态）、[[web-generic-sqli-hanvon-eface-order-columnkey-mybatis]]（`${}` 在 ORDER BY 结构位的形态）、[[code-analysis-sast-mybatis-mapper-sql-concat-sink-extraction]]（SAST 视角批量提取 Mapper 拼接 sink）。
- 变体：`${}` 可出现在 `ORDER BY`/`LIKE`/`IN`/表名/列名等位置；DAO 可命名为 `execute`/`queryBySql`/`selectBySql`/`getList`；参数可来自 JSON 字段、Header 或 Cookie；多语句是否可用取决于 JDBC URL（如 `allowMultiQueries`）与数据库权限。
- 边界：若 `${}` 参数被服务端白名单（表名/列名枚举）或正则严格限制，注入不成立；若数据库账号只读且无元数据权限，危害限于可读范围内；`#{}` 改写后注入即消失。

## 检测与防御

- 检测：代码审计阶段统计所有 `${}` 拼接点及其调用链；运行时监控返回大量 `information_schema`/`UNION`/`SLEEP` 等特征的请求与 SQL 日志；IDS/WAF 对 SQL 关键字与异常长参数告警。
- 防御：禁止在 Mapper 中使用 `${}` 拼接用户输入，统一改 `#{}`；动态表名/列名/排序字段用服务端枚举白名单映射；不要提供 `execute(@Param("sql"))` 这类任意语句执行 DAO；数据库账号最小权限（禁用 FILE、限制 `information_schema` 之外权限）；对通用查询接口加鉴权与参数校验。
