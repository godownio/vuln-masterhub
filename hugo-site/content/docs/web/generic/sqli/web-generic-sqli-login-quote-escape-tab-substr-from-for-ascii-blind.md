---
id: web-generic-sqli-login-quote-escape-tab-substr-from-for-ascii-blind
title: 登录框注入点只过滤单引号/select/union/空格/逗号：用反斜杠吞掉闭合引号 + %09 替代空格 + substr(...from N for M) 绕过逗号过滤，ASCII 盲注出同表 code 字段登录
type: scenario
domain: web
path: web/generic/sqli
technique: login-sqli-backslash-quote-escape-tab-whitespace-substr-from-for-comma-bypass
tags:
- sqli
- mysql
- php
- blind-injection
- ascii
- waf-bypass
- whitespace-filter
- login
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:53:34+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。登录点黑名单挡掉单引号/select/union/空格/逗号（正文黑名单字典实跑得出）、用户名传单个反斜杠让 "'\'" 吞掉闭合引号并把 and password = 拉进字符串、空格用 %09、取值改用 ascii(substr(CODE from N for 1)) like <值> 免逗号、最终跑出 87 122 114 74 76 104 48 51 86 89 82 52 70 即 WzrJLh03VYR4F 并与建表 INSERT 的 code 一致，全部与正文符；num_rows==1 后比对 $user['code']==$code 的同表二次校验判断正确。已修正两处：(1) 利用步骤里 'or%09 1=1#' 的空格被 %09 替代后不应再有空格，改为 'or%091=1#'；(2) PoC 原写作 username = \' and password = 一长串，易被照抄成整段提交，改为「用户名只填单反斜杠」并加说明；并补充注记：示例载荷尾部 like%0932 是原文字面上的演示值，与随后第一位 ASCII 87 不对应，逐位爆破需替换当前猜测值。dedup 首候选为自身 trigram=1.000，外部最高为关键字大小写错配卡(0.118)、反斜杠+UNION 十六进制卡(0.104)，绕过点与后续链不同，非同一条链，保留合理；引用四张关联卡均存在。未验证点：后端语句形状为原文猜测；PoC 未执行；原文无组件受影响版本，未 set-versions。
url: /docs/web/generic/sqli/web-generic-sqli-login-quote-escape-tab-substr-from-for-ascii-blind/
draft: false
kb_aliases:
- 空格被 ban 用 %09 代替
- substr from for 绕过逗号过滤
- 单引号被过滤用反斜杠闭合
- 登录框 ASCII 盲注 code 字段
- 逗号过滤 SQL 注入
---

## 一句话结论

当登录接口把用户名/密码直接拼进 `WHERE username='$u' AND password='$p'`，而黑名单只挡了单引号 `'`、`select`、`union`、空格与逗号时，可以完全绕开：用户名填一个反斜杠 `\` 让 SQL 里的 `'\'` 吞掉闭合引号（使 password 段变成可控表达式），空格用 `%09`（Tab）替代，取值函数改用 `substr(CODE from N for M)` 这种"位置式"写法免掉逗号，最后用 `ascii(...) like <数字>` 做逐位盲注，把同一张表里的 `code` 字段跑出来即可通过校验登录。

## 原理

- **反斜杠闭合逃逸**：PHP 侧只把 `'` 列入黑名单（并且没有用 `addslashes`/`mysql_real_escape_string` 处理反斜杠），但 MySQL 的字符串字面量同样把 `\` 当作转义符。用户名字段传入单个 `\` 后，语句里的 `username = '\'` 中的反斜杠把紧随的闭合引号转义掉，字符串继续吞掉 ` AND password = '`，于是 password 段的内容落在 SQL 表达式位置——即"不能输入单引号也能注入"。
- **空白被黑名单挡掉时换 Tab**：多数只做字面黑名单的实现只过滤 ASCII 空格 `0x20`，`%09`（Tab）、`%0a`、`%0b`、`%0c`、`%0d`、`/**/` 在 SQL 中同样是合法分隔符，MySQL 解析器一视同仁，因此 `or%09ascii(...)` 完全等价于带空格的写法。
- **逗号过滤用位置式函数绕开**：`substr(str, pos, len)` 需要逗号，但 MySQL 同时支持 SQL 标准写法 `SUBSTR(str FROM pos FOR len)` 以及 `MID`/`LEFT`/`RIGHT`；把取值表达式改成 `substr(CODE from N for 1)` 就不需要任何逗号，`LIMIT` 也可以用 `LIMIT n OFFSET m` 避开。
- **同表字段直接读**：代码在 `num_rows == 1` 后比对 `$user['code'] == $code`，说明 `username/password/code` 在同一张表同一行；只要把该行的 `code` 逐位读出，就能提交正确的 `code` 通过二次校验（否则密码对了也会失败）。
- **为什么可行**：过滤是"逐关键字/逐字符黑名单"而没有参数化查询，攻击者只需要为每个被过滤的字符找一个语义等价替代（反斜杠→闭合、Tab→空白、FROM/FOR→逗号、ASCII 数值→字符比较），过滤集合再密也补不全 SQL 的等价语法。

## 触发条件

- PHP + MySQL（mysqli/PDO 直接拼接）的登录接口，SQL 用单引号字符串拼接，字符串里含用户名与密码两个可控位。
- 过滤为字面黑名单：单引号、`select`、`union`、空格、逗号（大小写与关键字替换策略不限，只要能判断出实际生效的集合）。
- 后端没有把 `\` 一并转义（未用预处理语句，或转义函数遗漏反斜杠）。
- 页面存在布尔 oracle（登录成功/失败、或回显不同），可从外部区分条件真假。
- 目标表里存在与登录校验关联的第三字段（本例 `code`），且其值可被逐位猜解。

## 利用步骤

1. 先猜语句形状：登录失败且对 `'` 报错/被拦，说明是单引号拼接；用 `1\'` 之类判断闭合方式，确认 `\` 未被转义。
2. 用 `%09` 替换所有空格构造最小布尔条件，例如 password 传 `or%091=1#`，观察是否恒定成功/失败，确认注入生效。
3. 判断被过滤字符的实际集合：分别提交含 `'`、`select`、`union`、空格、逗号、`#`、`--` 的载荷，看哪一类被拦（本例四类被 ban、`#` 与 `--` 可用）。
4. 用 `ascii(substr(CODE from N for 1)) like <值>` 逐位盲注：先对第 1 位做 0–127 二分或线性尝试判定 ASCII 值，再递增 N，直到某一位取不到新值（回显与上一位相同）为止。
5. 把 ASCII 序列转回字符串；原文跑出 `87 122 114 74 76 104 48 51 86 89 82 52 70`，即 `WzrJLh03VYR4F`。
6. 用合法用户名/密码配合该 `code` 提交，通过 `$user['code'] == $code` 校验，完成登录（原文最后一步即拿到 flag）。

## PoC

（原文用户名处写成「传参位1」加反斜杠再加上 and password = 这样一长串，那只是描述拼接后 SQL 片段的样子；真正要提交的用户名值只有单个反斜杠，否则不会把后续的 and password = 吞进字符串。）

被判定的后端语句形状：

```sql
select a from bbb where username = '$u' and password = '$p';
```

传递 payload（`%09` 为 Tab，`#` 注释掉残余引号）：

```text
# 实际提交：用户名只填一个反斜杠；密码填 or ...#
username = \
password = or%09ascii(substr(CODE%09from%091%09for%091))%09like%0932#
```

拼接后实际执行：

```sql
select a from bbb where username = '\' and password = 'or ascii(substr(CODE from 1 for 1)) like 32#'
```

逐位取值（把 `from 1 for 1` 的位置依次改成 2、3、…）：

```text
or%09ascii(substr(CODE%09from%09N%09for%091))%09like%09<ascii>
```

跑出的 ASCII 序列 `87 122 114 74 76 104 48 51 86 89 82 52 70` → `WzrJLh03VYR4F`。

（注意：上文示例载荷里的 `32` 是原文截图中的演示值（ASCII 空格），与随后跑出的第一位 ASCII `87`（`W`）并不对应；逐位爆破时此处应替换为当前猜测值，第一位取 `87`。）

## 变体与关联

- **空白替代的其它写法**：`%0a`/`%0b`/`%0c`/`%0d`、`/**/`、括号 `()`、`or(1)=(1)`；Tab 多数 WAF 与手写黑名单都漏。
- **逗号替代的其它写法**：`substr(x from n for m)`、`mid(x from n for m)`、`left`/`right` 组合、`limit n offset m`、`substring_index`；`union select` 被 ban 时也可用 `insert`/`update` 子查询或报错注入替代。
- **闭合方式变体**：单引号被过滤不只有反斜杠一条路——`\`、双写引号（若 `magic_quotes` 类实现）、注释截断、宽字节 `%bf%27`（GBK 连接）、数组参数（PHP 把 `[]` 传成数组导致拼接失效）。
- **盲注提速变体**：把 `ascii(...) like n` 换成 `ascii(...) > n` 做二分，或 `ord(mid(...))`；有回显时改用 `UNION`/报错注入直接取。
- **关联**：`web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii`（同样是反斜杠吞引号，但绕过点在关键字大小写错配）、`web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti`（反斜杠吞引号后走 UNION + 十六进制）、`web-generic-sqli-blind-filter-bypass-functions`（函数级黑名单绕过的通用族）、`web-generic-sqli-sqlite-boolean-blind-tab-bypass`（Tab 替代空格的同族手法）。
- **边界**：后端改用预处理语句、把 `\` 与引号一并转义、对参数做类型强转（`intval`）、或对 `%09`/关键字/函数名做统一归一化（先 `preg_replace` 去掉所有空白再匹配）时，该链不成立。

## 检测与防御

- **检测**：请求体中出现 `%09`/`%0a`/`%0b` 替代空格的 SQL 片段、`substr(...from...for...)`、`ascii(`/`ord(`/`mid(` 与 `like <数字>` 的组合、用户名恰好为单个 `\`、以及"每请求只泄露 1 位"的高频同 IP 请求；WAF 日志里被拦载荷与被放行载荷仅差空白字符，是典型绕过信号。
- **防御**：登录查询一律用参数化查询/预处理语句（`prepare` + `bind_param`），彻底消除拼接；字段做类型与长度白名单校验（用户名只允许 `[A-Za-z0-9_.-]`），出现 `\`、`'`、控制字符直接拒绝而不是"替换后继续拼"；不要以"过滤了哪些字符"作为安全边界，改为在执行层限制（最小权限数据库账号、关闭 `FILE`/`information_schema` 不必要权限）。
- **加固**：开启数据库审计与慢查询/错误日志关联分析，对同一 IP 的短时间大量登录失败做限速与告警；`code` 一类二次校验字段应独立校验（如 HMAC/服务端 session），不要与用户输入一起查表。
