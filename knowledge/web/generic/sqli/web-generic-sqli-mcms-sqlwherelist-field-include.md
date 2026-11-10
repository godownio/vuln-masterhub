---
id: web-generic-sqli-mcms-sqlwherelist-field-include
title: MCMS BaseEntity.sqlWhere 解析成 sqlWhereList 后，IBaseDao.sqlWhere 片段把 ${item.field} 拼进 SQL 造成注入
type: scenario
domain: web
path: web/generic/sqli
technique: mcms-sqlwherelist-item-field-sqli
aliases:
- MCMS sqlWhere 注入
- sqlWhereList 注入
- IBaseDao.sqlWhere ${item.field}
- CategoryDao include 注入
- BaseEntity 自定义 where
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
confidence: medium
affected_versions: MCMS（MingSoft CMS）5.2.8（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:08:50+08:00'
  notes: 已通读原文；第11节 SQLi 复现截图指向 xzfile.aliyuncs.com 远程图，未包含在本地 img，只能依正文核对：BaseEntity.sqlWhere/getSqlWhereList(JSONObject.parseArray)、CategoryDao.xml include IBaseDao.sqlWhere、${item.field} 与 CategoryAction#query 链路与卡一致；卡内 /ms/cms/category/query.do 路由与 POST 方式为推断，卡已标注需按目标调整。未验证点：实际请求截图缺失；PoC 未复跑；无 sources/source_url。
---

## 一句话结论

MCMS 的 `BaseEntity.sqlWhere` 是一个可被请求参数绑定的字符串字段，`getSqlWhereList()` 用 `JSONObject.parseArray(sqlWhere, Map.class)` 把它解析成 `List<Map>`；业务 Mapper（如 `CategoryDao.xml`）通过 `<include refid="net.mingsoft.base.dao.IBaseDao.sqlWhere"/>` 复用公共片段，而该片段把 `${item.field}` 直接拼进 SQL 的列名位置——攻击者在 `sqlWhere` JSON 的 `field` 里放报错/布尔表达式即可注入。

## 原理

- **`sqlWhere` 是设计给“自定义查询条件”的入口**：`BaseEntity` 中定义 `protected String sqlWhere` 及 getter/setter，注释写明“自定义 SQL where 条件，需要配合对应 dao.xml 使用”；`getSqlWhereList()` 在 `sqlWhere` 非空时调用 `JSONObject.parseArray(sqlWhere, Map.class)`，返回 `[{"field":..., ...}]` 形式的 List。
- **公共片段使用 `${item.field}`**：`IBaseDao.xml` 的 `sqlWhere` 片段遍历 `sqlWhereList`，用 `${item.field}` 拼列名、可能还有操作符/值拼接。`${}` 是文本替换，JSON 里的 `field` 值不会被预编译。
- **业务层原样透传**：`CategoryAction` 的 `query` 接收 `CategoryEntity`（继承 `BaseEntity`），调用 `categoryBiz.query(entity)`；`BaseBizImpl.query(entity)` 再调 `getDao().query(entity)`，MyBatis 把实体的 `sqlWhereList` 作为集合参数传入片段。整个过程没有对 `field` 做白名单。
- **为什么 `field` 可注入**：`field` 处于 SQL 标识符/表达式位置，`#{}` 无法用于列名；即使值部分用了 `#{}`，`${item.field}` 仍可被替换为 `1 and updatexml(...)` 之类的表达式，闭合后续 SQL。
- **与同类 MCMS SQLi 的区别**：本卡不是 `orderBy`，也不是 `queryBySQL` 的 `wheres` key，而是 `sqlWhereList` 的 `field` 属性；三者都在 `ms-base` 的公共 XML 里，但参数入口不同。

## 触发条件

- MCMS 5.2.8，目标业务实体的查询接口接收 `sqlWhere` 参数（如栏目查询 `CategoryAction` 的 query）。
- 目标 Mapper XML include 了 `IBaseDao.sqlWhere` 片段，且该片段使用 `${item.field}`。
- 请求能绑定到继承 `BaseEntity` 的实体（Spring MVC 自动绑定 `sqlWhere` 字符串）。
- 数据库为 MySQL（报错注入 `updatexml` 或时间盲注可用）；接口可访问（后台或未授权路由）。

## 利用步骤

1. 找到使用 `CategoryEntity`/`BaseEntity` 的查询接口（本案例 `CategoryAction` 映射在 `/ms/cms/category`，query 方法）。
2. 构造 `sqlWhere` JSON 数组，键名 `field` 放注入表达式，例如：
   `sqlWhere=[{"field":"1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)"}]`
3. 把 `sqlWhere` 作为查询参数/表单字段随请求发送；`field` 被 `${item.field}` 拼进 WHERE 后触发 SQL 错误，错误信息回显数据库名。
4. 若报错被吞，改用布尔/时间盲注（`and if(...,sleep(5),1)`）。
5. 按需调整 JSON 中其它键（如操作符/值）以保持 SQL 语法闭合；不同 Mapper 的片段写法可能略有差异，需按目标 XML 调整。

## PoC

```http
POST /ms/cms/category/query.do HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

sqlWhere=[{"field":"1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)"}]
```

具体路由/方法名以目标版本 `CategoryAction` 的 `@RequestMapping` 为准；`field` 的表达式需按 `IBaseDao.sqlWhere` 片段实际拼接方式微调。原文通过报错注入回显验证。

## 变体与关联

- 同项目的另外两处 SQLi：`web-generic-sqli-mcms-querybysql-wheres-key-fieldname`（`queryBySQL` 的 Map key）、`web-generic-sqli-mcms-content-categoryid-query`（`IContentDao.xml` 的 `${categoryId}`）。
- 同项目 `orderBy` 注入：`web-generic-sqli-mcms-formdata-querydata-orderby`、`web-generic-sqli-mcms-mdiy-dict-orderby-injection`。
- 通用模式：MyBatis 的 `sqlWhere`/动态条件构造器如果允许前端传字段名，等于把 SQL 标识符交给用户；应使用字段白名单或 QueryWrapper 的列名映射。
- `getSqlWhereList` 使用 fastjson `JSONObject.parseArray` 解析，若版本存在 AutoType 风险也可能叠加反序列化问题（本卡不展开）。

## 检测与防御

- 修复：不要接受前端传入的 `field`；用字段白名单映射到真实列名；`IBaseDao.sqlWhere` 片段改为只允许白名单列 + `#{}` 值。
- 代码审计：搜索 `sqlWhereList`、`${item.field}`、`include refid="...IBaseDao.sqlWhere"`，逐项确认字段是否用户可控。
- 检测：请求体出现 `sqlWhere=` + JSON 数组、`updatexml`/`sleep`/`extractvalue` 等关键字；SQL 错误回显。
- 加固：关闭详细 SQL 错误、数据库最小权限、WAF 覆盖 JSON 参数中的 SQL 表达式。
