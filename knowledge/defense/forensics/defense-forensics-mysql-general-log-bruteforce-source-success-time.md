---
id: defense-forensics-mysql-general-log-bruteforce-source-success-time
title: MySQL 通用查询日志溯源：按 Access denied 聚合爆破源 IP 并定位首次成功登录时间
type: scenario
domain: defense
path: defense/forensics
technique: mysql-general-log-bruteforce-forensics
aliases:
- MySQL 日志分析
- general log 爆破溯源
- MySQL 登录失败 IP 统计
- 数据库爆破成功时间
- err 错误日志定位
tags:
- forensics
- log-analysis
- mysql
- bruteforce
- incident-response
- timezone
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:24+08:00'
  notes: 已对照原文 MISC2 与图02-05核对：Windows 数据目录下 err/general、general 日志中 webuser@10.10.88.101 的 Access denied 与 08:13:51.607446Z 的 SHOW VARIABLES、时区+8 换算均与原文一致；未验证点：未在原始 general 日志上复跑。
---

## 一句话结论

在 MySQL 的通用查询日志（`general`）中按 IP 聚合 `Access denied for user ... (using password: YES)` 可以定位爆破源，再以该 IP 第一条不带 `Access denied` 的成功 `Connect` 之后的首个 `Query`（如 `SHOW VARIABLES`）作为首次登录成功时间；日志时间若为 UTC，需按本地时区换算（北京时间 +8）。

## 原理

- MySQL 8.0 在 Windows 上默认数据目录为 `C:\ProgramData\MySQL\MySQL Server 8.0\Data`，错误日志默认文件名为 `err`；Linux 常见 `hostname.err`、`mysqld.log`，数据目录 `/var/lib/mysql` 或 `/var/log/mysql`。通用查询日志的文件名由 `general_log_file` 决定，常见为 `hostname.log`，本题为 `general`。
- `general_log=ON` 时，日志按连接记录 `Connect`、`Query`、`Quit` 等事件；认证失败会写成 `Access denied for user 'webuser'@'10.10.88.101' (using password: YES)`。爆破的典型形态是同一 IP/用户短时间大量 `Connect` 且全部 `Access denied`，随后突然出现一条成功连接和正常查询。
- 判定“成功”不能只看 `Connect` 行是否出现用户名：失败连接同样会打印 `Connect`；关键是该行没有 `Access denied`，且后续紧跟 `Query`（客户端连上后通常会先执行 `SHOW VARIABLES`、`SET NAMES` 等初始化语句）。首个业务/初始化 `Query` 的时间就是首次成功登录时间。
- 时区：MySQL 8.0 的 `general_log` 时间戳常带 `Z`（UTC），例如 `2023-10-26T08:13:51.565062Z`；转北京时间要 +8 小时。若日志用本地时间则不能重复加。先确认 `log_timestamps` 系统变量（UTC 或 SYSTEM）。
- 错误日志 `err` 主要记录启动/关闭/连接层错误与崩溃，不一定包含成功查询；通用日志更适合还原“爆破 → 成功 → 操作”的完整时间线。

## 触发条件

- 拿到 MySQL 数据目录或其日志（`err`、`general`、`slow` 等），且日志未被清空/截断。
- `general_log` 记录了连接与查询，或至少有错误日志记录了失败认证。
- 需要回答“攻击源 IP”和/或“首次爆破成功时间”。
- 日志时间戳的时区可确认（UTC 或本地）。

## 利用步骤

1. 定位日志：Windows 看 `C:\ProgramData\MySQL\MySQL Server 8.0\Data` 下的 `err`、`general`、`slow`；Linux 看 `/var/lib/mysql`、`/var/log/mysql`，并核对 `my.cnf` 的 `log_error`、`general_log_file`。
2. 统计 IP 出现次数，找出异常高频来源：
   ```bash
   grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' general | sort | uniq -c | sort -nr
   ```
3. 提取认证失败记录，按 IP/用户聚合，确认爆破形态：
   ```bash
   grep "Access denied for user" general | grep "using password: YES" | head
   ```
4. 找该 IP 的成功连接：过滤 `Connect` 且不含 `Access denied` 的行；成功行通常是 `Connect user@10.10.88.101 on ... using TCP/IP`。
5. 从成功连接向下找第一条 `Query`（不是 `Quit`），记录其时间作为首次成功登录时间；常见首批语句为 `SHOW VARIABLES`、`SHOW WARNINGS`、`SET NAMES utf8mb4`。
6. 时区换算：若时间戳为 `T...Z`（UTC），北京时间 = UTC + 8；把换算后的时间与主机本地时间、Web 日志、文件落地时间交叉验证。
7. 继续统计成功后的查询，还原攻击者执行了哪些库表操作、是否导出数据或写入文件。

## PoC

```bash
# 1) IP 频次
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' general \
  | sort | uniq -c | sort -nr | head -20

# 2) 爆破失败记录（按 IP 汇总）
grep "Access denied for user" general \
  | grep "using password: YES" \
  | grep -Eo "user '[^']+'@'[^']+'" | sort | uniq -c | sort -nr

# 3) 某 IP 的成功连接与后续查询（按日志顺序）
grep -n "10.10.88.101" general | grep -v "Access denied" | head -50

# 4) 首个成功时间（示例：先定位成功 Connect 行号，再看其后第一条 Query）
grep -n "Connect.*10\.10\.88\.101" general | grep -v "Access denied" | head -3
```

```python
import re
from datetime import datetime, timedelta, timezone

ip = "10.10.88.101"
lines = open("general", encoding="utf-8", errors="ignore").read().splitlines()
success = None
for i, line in enumerate(lines):
    if ip in line and "Connect" in line and "Access denied" not in line:
        success = i
        break
if success is not None:
    for line in lines[success:success + 20]:
        if "Query" in line:
            ts = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)", line)
            if ts:
                utc = datetime.fromisoformat(ts.group(1).replace("Z", "+00:00"))
                print("UTC:", utc, "北京时间:", utc + timedelta(hours=8))
            print(line)
            break
```

说明：字段解析依赖实际 `general_log` 格式，PoC 为示例，未在原文日志上复跑。

## 变体与关联

- 只有 `err` 错误日志：仍可按 `Access denied`/`Aborted connection` 定位爆破源，但无法精确到成功查询；结合 `binlog`、审计插件或应用日志补全。
- `general_log` 未开启：用 `performance_schema` 历史、连接审计插件、网络侧 MySQL 流量或主机进程日志替代。
- 日志轮转：把 `general.1`、`.gz` 等按时间合并后再统计。
- 时间基准：`log_timestamps=SYSTEM` 时为本地时间；`UTC` 时带 `Z`，换算前先确认，避免重复偏移。
- 关联：[[defense-forensics-mysql-binlog-delete-row-recovery]]（登录成功后的数据删除恢复）、[[defense-detection-ssh-bruteforce-alert-iptables-block]]（同类爆破检测思路）、[[web-generic-sqli-mysql-outfile-general-log-webshell]]（general_log 被滥用写 WebShell 的反向场景）。

## 检测与防御

- 检测：同一 IP/用户在短窗口内大量 `Access denied ... using password: YES` 后出现成功连接，立即告警；成功后执行 `SHOW VARIABLES`、`SELECT ... INTO OUTFILE`、`LOAD_FILE`、大批量 `SELECT` 也要关注。
- 防御：MySQL 只监听内网/本机，禁止 root 远程登录；强口令与最小权限；失败登录限速/封禁；生产环境默认关闭 `general_log`，确需开启时限制文件权限与保留周期。
- 日志：集中采集 `err`、`general`、`slow`、`binlog` 到 SIEM，防止本地篡改；统一 NTP 与时区，保留 ≥90 天。
