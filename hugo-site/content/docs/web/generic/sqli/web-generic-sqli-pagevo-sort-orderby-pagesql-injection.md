---
id: web-generic-sqli-pagevo-sort-orderby-pagesql-injection
title: PageVo.sort 拼接 order by 进入 MyBatis ${pageSql}：分页实体污染多个列表接口的 ORDER BY 注入
type: scenario
domain: web
path: web/generic/sqli
technique: pagevo-sort-orderby-pagesql-injection
tags:
- sqli
- java
- spring
- mybatis
- orderby
- sort
- pagevo
- time-blind
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:23+08:00'
  notes: 已对照原文与图10-14核对：PageVo.getPageSql拼接sort/order到${pageSql}、9个分页接口（原文列表findSingConfigPage重复一次，按原文计9处）、POST /login.jsp/..;/dept/findDeptPage.do的sort=1 AND (SELECT 8234 FROM (SELECT SLEEP(4))test)实测约4096ms均一致；未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-pagevo-sort-orderby-pagesql-injection/
draft: false
kb_aliases:
- PageVo SQL 注入
- sort 参数 ORDER BY 注入
- getPageSql 注入
- ${pageSql} 注入
- 分页实体排序注入
---

## 一句话结论

分页实体 `PageVo` 的 `getPageSql()` 把请求绑定来的 `sort`/`order` 直接拼成 `order by <sort> <order> limit ...`，Mapper 再用 `${pageSql}` 做文本替换；由于同一实体被多个列表 Controller 复用，`findDeptPage.do` 等 9 个接口全部继承该注入点，`sort=1 AND (SELECT 8234 FROM (SELECT SLEEP(4))test)` 实测响应延迟约 4 秒。

## 原理

- **MyBatis `${}` 是文本替换**：`#{}` 会生成预编译占位符 `?`，而 `${}` 把参数原样拼进 SQL。ORDER BY 的列名/方向属于标识符，无法用 `?` 绑定，开发者为支持动态排序常写成 `${sort}`、`${order}` 或 `${pageSql}`，一旦值来自请求就形成注入。
- **分页实体的拼接链**：`PageVo` 是接收前后端分页参数的实体，字段包括 `page`、`rows`、`sort`、`order`、`pageSql`，并实现 `getPageSql()`：
  - `sort != null` 时：`pageSql = " order by " + sort`；
  - `order != null` 时：继续追加 `" " + order`；
  - 最后拼 `" limit " + (page-1)*rows + "," + rows`。
  Spring MVC 会把请求中的 `sort`、`order`、`page`、`rows` 绑定到该实体，`sort` 完全可控。
- **多接口共用同一实体**：Mapper 方法以 `@Param("pageVo") PageVo` 接收对象，XML 中写 `select ... ${pageSql}`。原文在部门、文件服务器、租户、模块、角色、单点配置、用户、分类等 9 个分页接口中发现同一模式；只要 Controller 接受 `PageVo`，注入就随之复制。
- **为什么能绕过“只查一个接口”的审计**：漏洞不在单个 Mapper 的 SQL 字面量，而在共享实体的 getter；全局搜索 `${` 找到 Mapper 后，还要反查哪些 Controller 绑定了该实体，才能得到完整攻击面。
- **本例的可达性**：原文通过 `/login.jsp/..;/<模块>/<接口>.do` 的路径解析绕过鉴权，使这些接口在未登录状态可达；即使没有绕过，任何低权限账号也可利用（取决于接口权限）。

## 触发条件

- Java/Spring + MyBatis 项目，存在接收分页实体（`PageVo` 或类似基类）的 Controller 方法。
- 分页实体对 `sort`/`order` 等排序字段无白名单校验，并参与拼接 `order by`。
- Mapper XML 使用 `${pageSql}`、`${sort}`、`${orderBy}` 等文本替换。
- 接口可达（外网暴露、低权限账号或配合鉴权绕过）。

## 利用步骤

1. 源码审计：全局搜索 `${` 找出 Mapper 中的文本替换点，重点看 `order by`、`pageSql`、`orderByClause`、表名/列名位置。
2. 搜索分页实体（`PageVo`、`PageRequest`、`BasePage`）及其 `getPageSql`/`getOrderBy` 实现，确认 `sort`/`order` 是否直接拼接。
3. 反查 Controller：搜索 `import`/参数类型使用该实体的接口，得到所有受影响路由（本例 9 个）。
4. 构造时间盲注：`sort=1 AND (SELECT 8234 FROM (SELECT SLEEP(4))test)`，观察响应时间；也可用报错/布尔/联合注入。
5. 对每个路由重复验证；若鉴权拦截，配合路径解析绕过或其他低权限会话。
6. 用 sqlmap 等工具进一步枚举库表（注意请求体为表单编码，参数名 `sort`）。

## PoC

```http
POST /login.jsp/..;/dept/findDeptPage.do HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Connection: keep-alive

sort=1+AND+(SELECT+8234+FROM+(SELECT+SLEEP(4))test)
```

```text
# 原文实测响应（节选）：HTTP/1.1 200，响应时间约 4096 ms
{"total":0,"rows":[]}
```

说明：PoC 为原文请求的结构化复现，未在本机执行；原文截图显示 `findDeptPage.do` 在注入 SLEEP(4) 后响应延迟约 4 秒，并列出 9 个同类分页接口。URL 中 `/login.jsp/..;/` 是原文用于绕过鉴权的路径解析技巧，单独看 SQLi 不依赖该绕过。

## 变体与关联

- 变体（字段）：`order` 方向字段同样可控；`page`/`rows` 若参与字符串拼接也可注入；`pageSql` 还可能被用于其他 SQL 片段。
- 变体（注入类型）：报错注入（`extractvalue`/`updatexml`）、布尔盲注、时间盲注、堆叠查询（取决于驱动）。
- 变体（同类排序注入）：[[web-generic-sqli-bootdo-sort-order-token]]（Map 参数 `${sort} ${order}`）、[[web-generic-sqli-fastcms-article-list-orderby-injection]]（MyBatis-Plus `orderByDesc` 进 `${ew.customSqlSegment}`）、[[web-generic-sqli-cordyscrm-departmentids-field-orderby]]（列表拼 `FIELD()` 进 `${orderByClause}`）、[[web-generic-sqli-mybatis-dollar-brace-injection]]（`${}` 通用拼接面）。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（`startsWith` 白名单 + `/..;/` 路径解析绕过，本篇用其把 SQLi 变为未授权可达）。
- 边界：`sort`/`order` 使用枚举白名单、`${pageSql}` 改为固定子句、或接口不可达时失效；不同数据库的报错/时间函数不同。

## 检测与防御

- 检测（代码/SAST）：搜索 Mapper XML 中的 `${`；追踪分页实体 getter 的字符串拼接；对 `order by` 位置做污点分析；CodeQL/Checkmarx 规则可匹配“请求绑定对象 → 字符串拼接 → `${}`”。
- 检测（运行时）：请求参数 `sort`/`order` 中出现 SQL 关键字、函数、注释、括号；数据库慢查询日志中出现 `SLEEP`、`BENCHMARK`、`extractvalue`；同一接口异常延迟。
- 防御：对 `sort`/`order` 使用枚举/列名白名单映射，绝不直接拼接；分页 SQL 用固定模板 + 预编译参数；MyBatis 中禁用不必要的 `${}`，必须使用时在 DAO 层二次校验；最小权限数据库账号、关闭堆叠查询；WAF 作为兜底而非唯一防线。
