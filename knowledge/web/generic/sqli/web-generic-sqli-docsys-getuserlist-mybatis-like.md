---
id: web-generic-sqli-docsys-getuserlist-mybatis-like
title: DocSys/MxsDoc /getUserList.do 的 userName 经 MyBatis ${} 拼进 LIKE：sqlmap 时间盲注拖库
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-dollar-like-userlist-time-blind
aliases:
- DocSys SQL 注入
- MxsDoc getUserList.do 注入
- UserMapper.xml queryUserWithParamLike 注入
- MyBatis ${name} LIKE 注入
- 文件管理系统用户列表注入
tags:
- java
- mybatis
- sqli
- like-injection
- time-blind
- sqlmap
- docs-management
cve: []
severity: high
confidence: medium
status: verified
affected_versions: DocSys V2.02.36（原文使用该 war 包复现，未给修复版本）
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:48+08:00'
  notes: 已对照原文核对；本次核对未读取图片；注入点与 userMapper queryUserWithParamLike/userName 参数、sqlmap 时间盲注流程与正文一致，仅复现截图未读，页面回显形态与库表内容未验证
---

## 一句话结论

DocSys（MxsDoc）的用户列表接口 `/getUserList.do` 把 `userName` 透传到 `UserMapper.xml` 里写成 `LIKE '%${name}%'` 的语句，`${}` 是文本替换而非预编译占位符，所以 `userName` 里带的 SQL 片段会直接进入语句结构；即使页面不回显数据，也能用时间盲注把库名、表名与管理员口令一位一位读出来。

## 原理

- MyBatis 的 `#{}` 走 `PreparedStatement` 参数绑定，值只当数据；`${}` 是在 SQL 文本层面做字符串替换，值里的引号、括号、`AND`、`SLEEP()` 都会成为语法的一部分。所以一旦 `${}` 落在值位置，预编译带来的防注入能力完全失效。
- 本例的 Mapper 语句形如 `... where name like '%${name}%'`，参数由 Controller 以 `HashMap`（`queryUserWithParamLike`）传入 DAO，链路上没有任何转义或白名单；`userName` 完全可控。
- `LIKE '%payload%'` 这种模式串对注入有个额外门槛：payload 必须自己把首尾的 `%'` 补回去，否则语句在 `%` 处语法错，工具也跑不出结果；因此常用的做法是先用 `*` 标记注入点（`userName=*`）交给 sqlmap，由它按位置替换并自动补全 `%'`。
- 因为列表页通常只返回"查到/没查到"，盲注（时间或布尔）是更现实的取数方式：用 `AND SLEEP(5)` 之类条件延时判断真假，再逐字符比较。

## 触发条件

- 应用使用 MyBatis，Mapper XML（或注解 SQL）中存在 `${}` 形式的文本替换，且位置在 WHERE 的值/LIKE/ORDER BY 等可控处。
- 该语句对应的 HTTP 接口可达；原文场景需要能访问后台用户列表，实际鉴权状态随部署而异，不能默认未授权。
- 数据库账号有权限读目标库（常见为业务库全权限）。
- 能观测到响应时间差（时间盲注）或页面差异（布尔盲注）。

## 利用步骤

1. 全局搜索 Mapper XML 里的 `${`，从 SQL 语句找到对应 Mapper 方法名，再沿 DAO → Service → Controller 反查暴露的 HTTP 路由与参数名。
2. 定位到 `/getUserList.do`，确认参数为 `userName`、`pageIndex`、`pageSize`。
3. 传 `userName=*`（或用 `%'` 手工补全）交给 sqlmap，先用 `--technique=T` 时间盲注确认注入点。
4. 依次 `--dbs`、`--tables`、`--columns`、`--dump` 取管理员表与口令哈希；口令若为可逆或弱哈希再离线破解。
5. 用拿到的管理员凭据登录后台，衔接文件管理类接口做进一步操作。

## PoC

```http
GET /DocSystem/getUserList.do?userName=*&pageIndex=1&pageSize=20 HTTP/1.1
Host: target
Cookie: <会话>
```

```bash
# 时间盲注确认（--technique=T 只走时间盲注，避免 union 报错干扰）
sqlmap -r req.txt --batch --technique=T --dbs
```

```text
# 等价脆弱语句（Mapper XML 中的文本替换，而非 #{} 绑定）
... WHERE name LIKE '%${name}%'
```

## 变体与关联

- 变体（注入点位置）：同一套 `${}` 写法还会出现在 ORDER BY 排序字段、`IN (...)` 列表、表名拼接处，这些位置无法用 `#{}` 替代，是 MyBatis 项目最集中的注入面。
- 变体（探测手法）：无回显时用时间盲注；有报错回显时可直接 `updatexml`/`extractvalue` 报错注入；页面有差异时用布尔盲注。
- 关联：[[web-generic-sqli-mysql-mybatis-dollar-five-sink]] 类卡片（MyBatis `${}` 五类拼接点）、订单/搜索类 LIKE 注入卡；本条的价值在于给出"文件管理系统用户列表接口"这一具体落点与 `*` 标记注入点的实操细节。
- 边界：若 Mapper 改用 `#{}`、或在 Service 层对 `%`、`_`、引号做白名单转义，则本条失效；`ORDER BY` 位置即使换 `#{}` 也会变成常量字符串，必须靠字段白名单。

## 检测与防御

- 修复：值位置一律用 `#{}`；LIKE 场景写成 `LIKE CONCAT('%', #{name}, '%')`；排序列、表名用服务端枚举白名单映射，不要拼接用户输入。
- 加固：对 `userName` 做长度与字符白名单（如仅字母数字下划线）；数据库账号最小权限，业务账号不给 `FILE`、`PROCESS` 等权限。
- 检测：请求参数出现 `%'`、`AND SLEEP`、`OR 1=1`、`*` 占位符；同一接口响应时间出现规律性 5 秒级差异；WAF 侧对 `LIKE` 接口的异常引号与注释符告警。
- 审计：搜索 Mapper XML 与 `@Select` 注解中的 `${`，逐条回溯参数来源是否为外部输入。
