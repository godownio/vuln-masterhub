---
id: web-generic-sqli-mes-hql-append-find-actions
title: MES getHqlAppend 拼接 siteName/userName/menuName 导致 HQL 注入（findMessages/findImages/menuManager）
type: scenario
domain: web
path: web/generic/sqli
technique: mes-struts2-hql-append-injection
aliases:
- MES HQL 注入
- getHqlAppend 注入
- findMessages.action 注入
- findImages.action 注入
- menuManager.action 注入
- TbSysAdviseMessage HQL
tags:
- java
- struts2
- hql
- sql-injection
- mes
- hibernate
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:02:19+08:00'
  notes: 已对照原文核对：三处 getHqlAppend 分别拼接 siteName、userName/imageName/fileCategory、menuName/parentName，Service 拼 from ... + hqlStr 执行，路由 findMessages/findImages/menuManager；原文仅给出 PoC 未执行。
---

## 一句话结论

某企业 MES 的多个 Struts2 Action 把请求参数原样交给 `getHqlAppend()` 拼进 HQL 的 `where` 片段，再由 Service 拼成 `from <实体> <hqlStr> ORDER BY ...` 交给 Hibernate 执行；`siteName`、`userName`/`imageName`/`fileCategory`、`menuName`/`parentName` 等参数均无过滤或参数绑定，形成 HQL 注入。

## 原理

- **统一模式**：`TbSysAdviseMessageAction.find()`、`TbSysImagesAction.find()`、`SysMenuManagerAction.findPage()` 都先 `request.getParameterMap()` 把全部参数复制到 `HashMap param`，再调用各自的 `getHqlAppend(param)`（菜单 Action 是两个字符串参数）。
- **拼接**：`getHqlAppend` 以 `new StringBuffer(" where 1=1 ")` 或 `" where m.status = '1' "` 开头，对非空参数直接 `append(" and mes.siteName like '%").append(siteName).append("%'")`、`append(" and mi.createUser = '").append(userName).append("'")`、`append(" and m.menuName like '%").append(menuName).append("%'")` 等。没有预编译占位符、没有转义、没有白名单。
- **进入执行**：Service 的 `queryForPage(int pageSize, int page, String hqlStr)` 执行 `String hql = "from TbSysAdviseMessage mes " + hqlStr + " ORDER BY ..."`，再 `helperDao.queryForPage(hql, offset, length)`；Hibernate 把拼接后的 HQL 当查询语言解析，字符串中的引号/布尔表达式会改变语义。
- **三个入口**（原文路由）：
  1. `*Messages` → `TbSysAdviseMessageAction.find`，参数 `siteName`、`CREATE_DATE_START`、`CREATE_DATE_END`；路由 `/cmt/findMessages.action`。
  2. `*Images` → `TbSysImagesAction.find`，参数 `userName`、`imageName`、`fileCategory`、`CREATE_DATE_START/END`；路由 `/cmt/findImages.action`。
  3. `menuManager` → `SysMenuManagerAction.findPage`，参数 `menuName`、`parentName`；路由 `/cmt/menuManager.action`。
- **鉴权**：项目用自定义 `AuthorityInterceptor` 检查 session 中的 `user`，未登录返回 `login`；但 `struts.xml` 中哪些 action 套用了含该拦截器的 `mydefault` 栈需要逐个核对，白名单 action 不经过鉴权。原文 PoC 未带有效会话，实际利用前需确认目标路由的拦截器配置。
- **HQL 注入能力**：可闭合原有字符串改变 `where` 条件、用 `or` 恒真、调用 HQL 函数/子查询；Hibernate 对 `like`/`=` 的字符串拼接不会自动参数化，因此与原生 SQL 注入类似。

## 触发条件

- 目标为使用该 MES 代码库的 Java/Struts2/Hibernate 应用，存在上述 Action 与 `getHqlAppend` 写法。
- 对应 action 路由可访问；若被 `AuthorityInterceptor` 保护，需要有效低权限会话或找到白名单 action。
- 参数通过 GET/POST 传入（`request.getParameterMap()` 同时覆盖两者）。
- 目标未部署 HQL 注入 WAF/RASP。

## 利用步骤

1. 枚举路由：`/cmt/findMessages.action`、`/cmt/findImages.action`、`/cmt/menuManager.action`，确认返回列表页。
2. 选择一个参数（如 `siteName`），先注入 `' OR '1'='1` 观察返回行数变化。
3. 用布尔/时间/报错技巧逐步确认注入；HQL 支持 `and`/`or`、子查询、字符串函数，可按 Hibernate 版本构造。
4. 提取数据：可读当前库中的用户、角色、业务数据；若权限足够，可进一步读写文件/执行（取决于数据库与 Hibernate 配置）。
5. 保留请求与响应作为证据，避免破坏业务数据。

## PoC

原文 PoC（未在本机执行）：

```http
GET /cmt/findMessages.action?siteName=1%' OR '1'='1&CREATE_DATE_START=2026-01-01 00:00:00&CREATE_DATE_END=2026-12-31 23:59:59 HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

```http
POST /cmt/findImages.action HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 120

userName=admin' AND 1=1--&page=1
```

```http
GET /cmt/menuManager.action?menuName=1%' OR '1'='1 HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Cookie: JSESSIONID=
Connection: close
```

## 变体与关联

- **同一模式的其他 getHqlAppend**：代码库中其他 Action 若同样把请求参数 append 到 HQL，也可按本卡方法测试；原文还提到 `SysDictMacroDao` 存在 `"from SysDictMacro where code = '" + code + "'"` 的拼接，可作为额外审计点。
- **日期参数**：`CREATE_DATE_START/END` 被放入 `to_date('...','yyyy-mm-dd hh24:mi:ss')`，同样可闭合引号注入。
- **鉴权差异**：三个入口的拦截器配置可能不同；`menuManager` 在原文 PoC 中带空 `JSESSIONID`，不代表一定未授权，需按目标配置判断。
- 关联卡片：[[web-java-framework-hibernate-hql-native-sql-injection]]（如已存在）、[[web-generic-sqli-nocobase-myinappchannels-sequelize-literal]]（ORM literal 注入的另一种形态）。

## 检测与防御

- **代码**：HQL 必须使用参数绑定（`query.setParameter` 或 `?`/`:name`），不要拼接字符串；对 `like` 使用参数并转义 `%`/`_`；对排序/表名等标识符使用白名单。
- **鉴权**：确认 `AuthorityInterceptor` 覆盖所有业务 Action，白名单最小化；对列表查询做行级权限过滤。
- **检测**：`siteName`/`userName`/`imageName`/`fileCategory`/`menuName`/`parentName` 中出现单引号、`or`、`and`、`--`、注释、子查询；返回行数异常、HQL 语法错误堆栈、数据库慢查询。
- **应急**：修复拼接点并回归测试；审计相关接口访问日志与数据库查询日志；评估数据是否被批量读取。
