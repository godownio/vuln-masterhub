---
id: web-java-component-jimureport-qurestsql-dyndb-sql-injection
title: JimuReport 1.5.6 /jmreport/qurestSql 未授权注入：apiSelectId 取出 jimu_report_db.db_dyn_sql 模板后 id 参数直拼执行
type: scenario
domain: web
path: web/java/component
technique: jmreport-dynamic-sql-template-injection
aliases:
- 积木报表 qurestSql SQL 注入
- JimuReport qurestSql 注入
- jimu_report_db db_dyn_sql 注入
- JeecgBoot 3.50 前台 SQL 注入
- CMS 积木报表 updatexml
tags:
- jimureport
- jeecgboot
- java
- spring-boot
- sqli
- error-based
- unauth
- updatexml
cve: []
severity: high
confidence: high
affected_versions: JimuReport 1.5.6（JeecgBoot 3.50 内置；原文测试版本）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T08:34:47+08:00'
  notes: 已完整读 content.md 与全部19张图核对：图01源码搜索无结果→图02/03 jar内a.a#b @PostMapping(/qurestSql)；图04-06 getById→JmReportDbDao.get(@Select SELECT * FROM jimu_report_db WHERE ID=:id，参数化非注入点)；图07 jimu_report_db记录含db_dyn_sql；图08 qurestchSql取dbDynSql+参数→getDbSql→dynamicDbUtil执行；图09 debug确认dbDynSql=select * from rep_demo_employee where id=''；图13 jmFilter仅注册/jmreport/queryFieldBySql与/jmreport/loadTableData；图16 updatexml报错栈(select * from rep_demo_employee where id='1' or '%1%' like (updatexml...)，佐证id闭合注入。PoC与原文完全一致。单卡原子(db字段存SQL模板+参数直拼注入)，粒度合适。affected_versions原文明确JimuReport 1.5.6(JeecgBoot3.50内置)，卡内已填且正确。dedup最高分为卡自身exact自匹配；dup-scan中与同文queryFieldBySql卡及既有objectconstructor等pair均verdict=related(不同端点/机制)，保留。未验证点：未复现目标环境；39tzamcto0d字段用途原文未说明。
---

## 一句话结论

`POST /jeecg-boot/jmreport/qurestSql` 无需登录：它用请求里的 `apiSelectId` 从 `jimu_report_db` 取出 `db_dyn_sql` 字段中存好的 SQL 模板（如 `select * from rep_demo_employee where id='${id}'`），把剩余 JSON 参数渲染进模板后直接交给数据库执行，`id` 可闭合引号造成 SQL 注入；`jmFilter` 只注册在 `queryFieldBySql`/`loadTableData`，本接口不受其关键字过滤，可用 `updatexml` 报错回显 `current_user`。

## 原理

- 路由在 `jimureport-spring-boot-starter-1.5.6.jar` 的 `org.jeecg.modules.jmreport.desreport.a.a#b`（反编译名）。方法签名与流程：

  ```java
  @PostMapping("/qurestSql")
  public Result<?> b(@RequestBody JSONObject var1, HttpServletRequest var2) {
      String var3 = var1.getString("apiSelectId");
      var1.remove("apiSelectId");
      JmReportDb var4 = this.reportDbService.getById(var3);
      List var5 = this.reportDbService.qurestchSql(var4, var1);
      this.jmReportDesignService.replaceDbCode(var4, var5);
      return Result.OK(e.b(var5));
  }
  ```

  `getById` 走 `JmReportDbDao#get`，SQL 为 `SELECT * FROM jimu_report_db WHERE ID = :id`，这里是参数化的，不是注入点；`apiSelectId` 实际是「选哪一条报表数据源记录」的索引。
- `qurestchSql(JmReportDb, JSONObject)` 中取出 `jmReportDb.getDbDynSql()`（动态 SQL 模板），再取出该报表的参数定义，最后 `jimuReportService.getDbSql(jmReportDb, params, ...)` 把参数渲染进模板，得到最终 SQL 并执行。`jimu_report_db.db_dyn_sql` 的真实值就是这种模板，例如：

  ```sql
  select * from rep_demo_employee where id='${id}'
  ```

  这里的 `${id}` 是 FreeMarker/字符串模板占位，不是预编译参数；请求 JSON 里的 `id` 直接替换进去，闭合单引号即可改变 SQL 结构。
- 为什么过滤器没拦住：JimuReport 的 `jmFilterRegistration` 只把 `jmFilter` 注册到 `["/jmreport/queryFieldBySql", "/jmreport/loadTableData"]` 两个 URL；`/jmreport/qurestSql` 不在其中，因此没有任何 SQL 关键字黑名单。即使在其他接口，黑名单也只匹配请求原文，模板渲染后的内容不在检查范围。
- 报错注入 payload 的构造：`id=1' or '%1%' like (updatexml(0x3a,concat(1,(select current_user)),1)) or '%%' like '`。上下文 `where id='${id}'` 先被闭合为 `where id='1' or '%1%' like (updatexml(...)) or '%%' like ''`，`updatexml` 的第二个参数不是合法 XPath，MySQL 抛出 `XPATH syntax error`，错误信息中带出 `current_user`；响应中的数据库异常信息把错误回显给攻击者。
- 影响：可读取当前库数据（用户、口令哈希、业务数据），并在数据库权限/驱动允许时进一步写文件或堆叠执行；文章将其归为前台 SQL 注入。

## 触发条件

- 目标为 JimuReport 1.5.6（JeecgBoot 3.50 内置）或同源代码版本，暴露 `/jeecg-boot/jmreport/qurestSql`（上下文路径随部署变化，可能是 `/jmreport/qurestSql`）。
- `jimu_report_db` 中存在 `db_dyn_sql` 非空的记录（演示/业务报表默认有，例如 `rep_demo_employee`），且该记录的 `apiSelectId` 可直接用作索引；文章用的是 `1316997232402231298`。
- 数据库为 MySQL/MariaDB 且支持 `updatexml`（或改用 `extractvalue`、布尔/时间盲注）。
- 接口未被额外鉴权/网关拦截；文章 PoC 无 Cookie。

## 利用步骤

1. 枚举/猜测 `apiSelectId`：先从返回错误的提示、报表列表接口或默认演示数据中获取存在的 ID；文章使用的 ID 对应 `rep_demo_employee` 报表。
2. 发送 `POST /jeecg-boot/jmreport/qurestSql`，`Content-Type: application/json`，body 含 `apiSelectId` 与要注入的参数名（如 `id`）；参数名必须与 `db_dyn_sql` 模板里的 `${...}` 占位一致，否则不会被替换。
3. 先用 `id=1` 观察正常返回，再用 `id=1' or '1'='1` 验证布尔差异，最后用 `updatexml` 报错取 `current_user`、`database()`、表名等。
4. 用 `information_schema` 逐表逐列拖库；若报错被吞，改用时间盲注（`sleep`）或布尔盲注。
5. 若返回被包装为统一异常，检查响应中的 SQL 错误详情是否带出 XPath 错误；必要时换 `extractvalue(1,concat(0x7e,(select ...)))`。

## PoC

```http
POST /jeecg-boot/jmreport/qurestSql HTTP/1.1
Host: 192.168.200.1:3100
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Type: application/json
Content-Length: 148
Connection: close

{"apiSelectId":"1316997232402231298","id":"1' or '%1%' like (updatexml(0x3a,concat(1,(select current_user)),1)) or '%%' like '","39tzamcto0d":"="}
```

`apiSelectId` 指向的 `db_dyn_sql` 模板为 `select * from rep_demo_employee where id='${id}'`；响应中的 `XPATH syntax error` 会包含 `current_user` 的值。`39tzamcto0d` 是原请求携带的额外 JSON 字段，保留即可，具体用途以目标为准。

## 变体与关联

- 同一 JimuReport 的 `/jmreport/queryFieldBySql` 是另一种注入面：那里 `sql` 本身是模板，可直接 FreeMarker SSTI（见 JimuReport queryFieldBySql 卡）；本卡的注入点在数据库里存的 `db_dyn_sql` 模板，攻击者只能控制模板参数，不能改模板本身。
- `loadTableData`/其他使用 `getDbSql` 的报表接口若同样把参数渲染进 `db_dyn_sql`，可复用本卡思路；`jmFilter` 的 URL 白名单是判断有没有 WAF 的关键。
- 若目标版本把 `db_dyn_sql` 改成预编译/参数绑定，则本注入不成立；审计时重点看 `getDbSql` 的实现是字符串替换还是 `PreparedStatement`。
- 通用手法：`web/generic/sqli` 下 `updatexml` 报错注入卡可作为语法参考；本卡差异是「SQL 存在数据库字段里 + 参数渲染」的二次注入形态。

## 检测与防御

- 修复：`db_dyn_sql` 模板中的参数改为预编译绑定，禁止把请求参数渲染进 SQL 文本；对 `apiSelectId` 做归属校验，禁止未授权访问报表接口。
- 模板：FreeMarker 渲染 SQL 时只允许白名单参数、禁止表达式求值；渲染后的 SQL 再做一次参数化/语法校验。
- 过滤：不要把 `jmFilter` 的 URL 白名单当作安全边界；`qurestSql` 等接口应同样接入参数校验与 WAF，并覆盖模板渲染后的最终 SQL。
- 检测：监控 `/jmreport/qurestSql` 的 `apiSelectId` 遍历与参数中的 `updatexml`/`extractvalue`/`or`/`like`/`sleep`；对包含 `XPATH syntax error` 的响应、异常 SQL 日志告警。
- 排查：审计 `jimu_report_db.db_dyn_sql` 是否存在 `${}` 拼接模板，核对最近被访问的 `apiSelectId` 与数据库错误日志。
