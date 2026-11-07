---
id: defense-forensics-mysql-binlog-delete-row-recovery
title: MySQL binlog 行镜像恢复被删除订单：定位 Delete_rows 事件并解码 before-image
type: scenario
domain: defense
path: defense/forensics
technique: mysql-binlog-delete-row-recovery
aliases:
- MySQL binlog 取证
- 删除订单恢复
- row-based binlog
- Delete_rows 事件
- before-image
- binlog 行镜像
tags:
- defense
- forensics
- mysql
- binlog
- database
- delete-recovery
- row-image
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:31:21+08:00'
  notes: 已对照原文与图24/25核对：binlog.000002、DELETE事件2025-09-18 20:58:54、偏移0x00000000000671A1A、操作内容hex中可解出4V8XNK8Q02MD5D2R均一致；ROW/FULL与mysqlbinlog流程为通用知识；无CVE、无sources/source_url；未在MySQL实跑mysqlbinlog。
---

## 一句话结论

MySQL 的 ROW 格式 binlog 为每条 DELETE 保存删除前的行镜像（before-image）；在服务器磁盘检材中找到 `binlog.000002` 一类的文件，按时间/表名定位 `Delete_rows` 事件，解出 `### WHERE`/行数据中的列值（或对取证工具展示的十六进制行内容做解码），即可恢复被删除的订单号等业务字段。

## 原理

- MySQL binlog 有三种格式：STATEMENT、ROW、MIXED。ROW 格式记录 `Table_map` 事件与 `Write_rows/Update_rows/Delete_rows` 事件；DELETE 的 before-image 包含被删行的各列值（取决于 `binlog_row_image`，默认 `FULL` 时包含全部列）。
- binlog 文件中的行事件以二进制存储，`mysqlbinlog` 会按 `--base64-output=DECODE-ROWS -vv` 把行数据解码成可读的 `###` 注释（列名/列值），并给出 `### DELETE FROM db.tbl` 与 `### WHERE`。
- 若使用图形化取证工具，行内容可能以十六进制展示；ASCII 字段（订单号、邮箱、用户名）会以 `34 56 38 58 ...` 形式出现，按十六进制转 ASCII 即可读出。案例中删除事件的 `操作内容` 里可见 `...0010003456385854...`，对应 `4V8XNK8Q02MD5D2R`。
- 为什么能恢复：binlog 是追加写的日志，DELETE 不会抹掉历史事件；只要事件未被 purge、未被加密且磁盘镜像完整，就能从事件的时间戳、表 ID 和行镜像还原删除内容。
- 案例还显示：`binlog.000002` 中有大量同一秒的 INSERT 事件与一条 2025-09-18 20:58:54 的 DELETE 事件，偏移位置 `0x00000000000671A1A`；删除事件的行数据就是取证重点。

## 触发条件

- 拿到 MySQL 数据目录或 binlog 文件（`binlog.000001`、`binlog.000002` 等），且 `log_bin` 已开启。
- binlog 为 ROW 格式，`binlog_row_image=FULL`（或至少包含待恢复列）。
- binlog 未被 purge、未被加密（或已获得解密密钥）、未被压缩（或工具支持解压）。
- 已知目标表、时间范围或字段特征（例如订单号格式）。

## 利用步骤

1. **定位 binlog**：在数据目录查找 `binlog.index`、`binlog.00000*`；若数据库可启动，执行 `SHOW BINARY LOGS;` 与 `SHOW VARIABLES LIKE 'binlog%';`。
2. **确认格式与行镜像**：`SHOW VARIABLES LIKE 'binlog_format';`、`binlog_row_image`；ROW + FULL 最利于恢复。
3. **解码**：`mysqlbinlog --base64-output=DECODE-ROWS -vv --start-datetime='...' binlog.000002 > decoded.sql`；若文件加密/压缩，先按对应选项处理。
4. **定位删除事件**：在解码结果中搜索 `DELETE FROM`、`Delete_rows`、目标表名、时间戳；读取 `### WHERE` 与 `###   @N=...` 列值。
5. **十六进制兜底**：若只有原始 hex（图形工具/自定义解析），提取行 payload，按列类型解码；字符串列直接 hex→ASCII，整数列注意大小端与有符号。
6. **交叉验证**：用订单表、备份、应用日志、支付记录核对订单号、时间、金额；恢复后不要直接写回生产库，先导出为证据文件。

## PoC

```bash
# 1. 解码 row 事件为可读伪 SQL
mysqlbinlog --base64-output=DECODE-ROWS -vv \
  --start-datetime='2025-09-18 20:50:00' \
  --stop-datetime='2025-09-18 21:10:00' \
  binlog.000002 > decoded.sql

# 2. 找删除事件
grep -n -A 20 -B 5 'DELETE FROM' decoded.sql | head -100

# 3. 若工具只给十六进制行内容，转 ASCII
python - <<'PY'
h = "0000400c1b000000000010003456385854..."
b = bytes.fromhex(h)
print("".join(chr(c) if 32 <= c < 127 else "." for c in b))
# 可读出 4V8XNK8Q02MD5D2R
PY
```

本卡不连接生产数据库；案例使用图形化取证工具查看 binlog，上述 `mysqlbinlog` 为等价通用流程。

## 变体与关联

- `binlog_row_image=MINIMAL` 时 DELETE 只记录主键，需回到业务表/备份补全其它列。
- `binlog_encryption=ON` 需要密钥/密钥文件；`binlog_transaction_compression=ON` 需要支持解压的版本或工具。
- 事件可能分布在多个 binlog 文件/relay log；按 `binlog.index` 顺序与时间范围拼接。
- 关联：[[defense-forensics-c2-server-sqlite-conf-artifacts]]（服务端数据库取证）、[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（加密数据库恢复）、[[ctf-forensics-sqlite-freeblock-linked-list-page-xor]]（SQLite 删除记录恢复）。
- 边界：若 binlog 已 purge、未开启 ROW、或磁盘镜像缺少 binlog 文件，无法从 binlog 恢复；只能依赖备份/应用日志/磁盘残留。

## 检测与防御

- 运维侧：开启 ROW binlog 与足够保留期；定期备份并验证可恢复；把 binlog 放在受保护、可审计的存储。
- 安全侧：限制数据库账号的 DELETE 权限；对批量删除、异常时间窗口的 DELETE 做审计告警；启用 binlog 加密与访问控制。
- 取证侧：先做磁盘只读镜像，保留原始 binlog 哈希；恢复结果与业务备份交叉验证，避免把解析错误当成事实。
- 加固：对订单等关键表使用软删除/审计表；开启 general_log/audit plugin 作为补充证据。
