---
id: web-generic-sqli-waf-newline-keyword-split-hex
title: SQL 注入 WAF 绕过：关键字中插 %0a 拆分正则 + 十六进制字面量替代单引号
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-waf-newline-keyword-split
tags:
- sqli
- waf-bypass
- keyword-filter
- hex-literal
- mysql
- error-based
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:27:55+08:00'
  notes: 已对照原文与图 4-7 核对：update%0axml、dat%0aabase、informat%0aion_schema、sele%0act 的换行拆分，单引号被过滤后用 0x2561646d696e25 代替 '%admin%'，以及错误信息中还原出的完整 updatexml 语句均一致；时间盲注 IF(1=1,sleep(3),0) 与图 37 一致。该绕过依赖宝塔免费版 WAF 的实现，原文未给版本区间，未设置 affected_versions。未验证点：未本机复现。
url: /docs/web/generic/sqli/web-generic-sqli-waf-newline-keyword-split-hex/
draft: false
kb_aliases:
- '%0a 绕过 WAF'
- 关键字换行拆分
- update%0axml
- dat%0aabase
- 十六进制代替引号
- 宝塔 WAF 绕过 SQL 注入
---

## 一句话结论

当 WAF 用连续字符串正则匹配 `updatexml`、`database`、`information_schema` 等 SQL 关键字，且后端把参数 URL 解码后交给 MySQL 时，在关键字中间插入 `%0a`（换行）可拆断 WAF 匹配；若单引号也被过滤，再用 `0x...` 十六进制字面量代替字符串，即可继续完成报错/盲注并取数。

## 原理

- WAF 的关键字黑名单通常对解码后的参数做正则匹配（如 `/updatexml/i`、`/information_schema/i`）。在关键字内部插入换行字节后，字符串不再连续，正则不命中；而 SQL 解析器把换行视为空白/可忽略字符，或在 WAF 规范化阶段被去除，最终仍按原关键字执行。
- 该手法是否成立取决于 WAF 的“解码/规范化 → 匹配 → 转发”顺序：若 WAF 先去空白再匹配则无效；若先匹配原始（或仅 URL 解码）字符串、后转发，则有效。原文在宝塔免费版 WAF 上实测有效，并可从报错信息看到还原后的 `updatexml(...)` 语句。
- 单引号被过滤时，MySQL 的十六进制字面量 `0x...` 可表示二进制字符串，等价于 `'...'`；例如 `'%admin%'` 写作 `0x2561646d696e25`，`table_name = 'x'` 写作 `table_name = 0x78`。十六进制不包含引号，可绕过基于引号的黑名单。
- 报错注入本身依赖 `updatexml`/`extractvalue` 的非法 XPath 错误回显；WAF 绕过只是让这些函数到达数据库。盲注场景则把 `IF(...,SLEEP(...),0)` 与十六进制比较结合，逐字符判断。
- 之所以可复用：过滤器与 SQL 解析器对“同一字节序列”的语义不同（换行是分隔符还是关键字一部分、十六进制是数字还是字符串），这类解析差异普遍存在于 WAF 与数据库之间。

## 触发条件

- 存在 SQL 注入点，数据库为 MySQL（`updatexml`/`extractvalue` 可用）或支持十六进制字面量。
- WAF 以关键字/函数名黑名单为主，且未在匹配前做完整的去空白/语义归一化。
- 参数经过 URL 解码后进入 SQL；能发送 `%0a`、`%0d`、`%09` 等编码字符。
- 应用会回显数据库错误（报错注入）或响应时间/内容可观察（盲注）。
- 单引号被过滤，但十六进制字面量未被拦截。

## 利用步骤

1. 用普通 `'`/`and 1=1` 探测注入点与 WAF 行为，确认是关键字拦截还是引号拦截。
2. 在函数名/关键字中插入 `%0a`：`updatexml` → `update%0axml`，`database()` → `dat%0aabase()`，`information_schema` → `informat%0aion_schema`，`select` → `sele%0act`。
3. 若单引号被过滤，把字符串改为十六进制：`'%admin%'` → `0x2561646d696e25`。
4. 用报错注入爆库名/表名/字段名/数据；长数据用 `limit`/`substr` 分段。
5. 报错不回显时改用时间盲注：`id=9 and IF(条件, sleep(3), 0)`，逐字符比较十六进制值。
6. 拿到管理员 MD5 后离线破解，登录后台继续利用。

## PoC

```text
# 基础报错注入（被 WAF 拦截）
id=0 and updatexml(1, concat(0x7e, database(), 0x7e), 1);

# 关键字内插 %0a 绕过
id=0 and update%0axml(1, concat(0x7e, dat%0aabase(), 0x7e), 1);

# 单引号被过滤：十六进制代替 '%admin%'
id=0 and update%0axml(1, concat(0x7e, (sele%0act table_name from informat%0aion_schema.tables where table_name like 0x2561646d696e25 limit 0,1), 0x7e), 1);

# 时间盲注
id=9 and IF(1 = 1, sleep(3), 0);
```

说明：原文在宝塔免费版 WAF 上按上述方式完成报错注入、表名/字段名/数据提取并破解管理员 MD5；PoC 未在本会话执行。`%0a` 绕过依赖 WAF 实现，换目标需重新测试。

## 变体与关联

- **其他空白/注释**：`/**/`、`/*!50000updatexml*/`、`%09`/`%0d`、大小写混写、双写（`updupdatexmlatexml`）；不同 WAF 的规范化顺序不同。
- **无引号字符串**：十六进制 `0x...`、`char()`、`unhex()`、`concat(0x..)`；十六进制也可用于表名/列名比较。
- **盲注替代原语**：`IF`/`SLEEP` 被过滤时用 `CASE WHEN`、`BENCHMARK`、`GET_LOCK`（见关联卡）。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入原理）、[[web-generic-sqli-keyword-double-write-bypass]]（另一种关键字过滤绕过）、[[web-generic-sqli-blind-filter-bypass-functions]]（盲注原语替代）。

## 检测与防御

- **检测**：SQL 参数中出现 `%0a`、`%0d`、`%09`、`/**/` 等关键字拆分特征；同一参数在短时间内出现大量报错/延时请求；WAF 日志中“关键字变形”告警；数据库错误信息回显。
- **防御**：使用参数化查询/预编译，根除拼接注入；WAF 在解码、去空白、大小写归一化后再做语义检测，不能只匹配原始字符串；关闭详细数据库错误回显；限制 `updatexml`/`extractvalue` 等函数与 `information_schema` 的访问权限；对注入尝试做速率限制与告警。
