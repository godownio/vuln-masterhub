---
id: cloud-public-rds-snapshot-restore-master-password-data-loot
title: 公共 RDS 快照还原到自建 VPC + 改主密码 + psql 连接读取业务/flag 数据
type: scenario
domain: cloud
path: cloud
technique: public-rds-snapshot-restore-master-password-loot
tags:
- cloud
- aws
- rds
- aurora
- snapshot
- postgresql
- vpc
- credential
- data-loot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:08:33+08:00'
  notes: 已对照原文核对：公有快照 arn:...:cluster-snapshot:orders-private(引擎 14.11/Aurora PostgreSQL 14.11)、还原 pwnlabs-cluster、自设主密码、psql 16.8 连 server 14.11 后 \l/\c/\dt/select * from flag 全部有图；注：图 30 的公开访问单选为否，实际连通靠同 VPC EC2，卡中『公开访问选是』属措辞不精确但不影响链路；与 EBS 快照卡为 related 但对象是托管数据库，不合并。
url: /docs/cloud/cloud-public-rds-snapshot-restore-master-password-data-loot/
draft: false
kb_aliases:
- 公共 RDS 快照
- 公有快照还原
- 修改数据库主密码
- psql endpoint 5432
- cust_orders flag 表
- 同 VPC EC2 连接
---

## 一句话结论

当只拿到目标 AWS Account ID 时，可在 RDS 控制台「公有快照」按该账号 ID 搜索公共数据库快照；任何账号都能把公共快照还原到自己新建的 VPC/集群里，还原过程中可**自行设置主密码**并开启公开访问、绑定一个同 VPC 的 EC2，随后用 `psql -h <endpoint> -U postgres` 连上，即可读取快照里的全部业务库与表（含 flag/订单数据）。

## 原理

- RDS/Aurora 快照可被设为「公有」，任意 AWS 账号在「公有快照」列表里按 owner 账号 ID 过滤即可看到（本文命中 `arn:aws:rds:<region>:<account>:cluster-snapshot:orders-private`）。
- 「还原快照」是在**攻击者自己的账号下**创建一个新数据库集群/实例，因此与原账号完全隔离：攻击者拥有该新实例的全部管理权限，包括**重置主用户密码**、选 VPC、子网、是否公开访问、安全组等。
- 数据库要可连，需让它与发起连接的 EC2 在同一 VPC；RDS 提供「设置 EC2 连接」自动创建/选择同 VPC 的 EC2。若客户端缺失 psql，`apt install -y postgresql-client` 即可。
- 连接串由 RDS 的「终端节点(endpoint)」+ 端口 5432 给出；连上后用 `\l` 列库、`\c <库>` 切换、`\dt` 列表、`select * from <表>` 直接读取数据。
- 根因是数据库快照被误设为 public + 快照内含未脱敏业务数据；重置密码能力使「不知道原口令」不再是障碍。

## 触发条件

- 目标账号存在「公有」RDS/Aurora（DB 或 cluster）快照，且攻击者知道其 Account ID 或能按前缀搜索。
- 攻击者有自有 AWS 账号，可新建 VPC、EC2 与还原 RDS 实例。
- 还原出的实例与连接用 EC2 处于同一 VPC/可达网络，且安全组允许 5432。

## 利用步骤

1. 拿到目标 AWS Account ID（可由公开 S3 桶枚举得到，本批另有对应卡）。
2. RDS 控制台 → 快照 → 「公有」标签 → 按 Account ID 搜索，找到公共快照。
3. 选中快照 → 操作 → 「还原快照」，填数据库实例/集群标识符（如 pwnlabs）。
4. 连接设置：新建 VPC、数据库子网组、公开访问选「是」、按需选证书；提交并等待还原完成（Aurora 会生成区域集群 + 写入器实例）。
5. 操作 → 「设置 EC2 连接」→ 创建/选择同 VPC 的 EC2 实例。
6. 修改数据库集群 → 凭证管理选「自我管理」，设置新的主密码并应用。
7. 在 EC2 上 `apt install -y postgresql-client`，`psql -h <endpoint> -U postgres`（端口 5432）输入新密码连接。
8. `\l` → `\c <业务库>` → `\dt` → `select * from <flag表>;` 读取数据。

## PoC

```text
# RDS 控制台：公有快照(按 104506445608 过滤) → 还原快照 → 标识符 pwnlabs
#            新建 VPC + 公开访问「是」→ 设置 EC2 连接(同 VPC) → 修改主密码
psql -h <endpoint> -U postgres -p 5432
\l                       # cust_orders, postgres, rdsadmin ...
\c cust_orders
\dt                      # flag, orders
select * from flag;      # 读到 flag
```

（最小化示意，endpoint/账号 ID/密码为占位，未执行任何 PoC。）

## 变体与关联

- 变体：MySQL/RDS 快照同理（用 mysql 客户端）；若已有同 VPC EC2 可跳过创建；也可用快照导出到 S3 再离线分析。
- 关联：前置常接「从公开 S3 桶枚举 AWS Account ID」（用 Account ID 过滤公有快照）；与「公开 EBS 快照 → 挂载挖凭据」同属「公共快照数据泄露」族，但对象是托管数据库而非块设备。
- 关联：与「MSSQL/PostgreSQL 低权登录跨库读凭据」等数据库后渗透卡互补——本卡通过「还原 + 改主密码」直接取得管理员级访问。
- 边界：读取的是快照副本数据（可能非最新），不含对原生产库的写入。

## 检测与防御

- 检测：CloudTrail 监控 `RestoreDBClusterFromSnapshot` / `RestoreDBInstanceFromDBSnapshot`、`ModifyDBCluster`（改密码）、异常「设置 EC2 连接」；审计是否有快照被设为 public。
- 防御：禁止公开 RDS 快照、仅按明确账号共享；对含敏感数据的快照加密并管控 KMS 密钥；生产数据脱敏后再做快照；启用数据库审计与网络最小暴露（不轻易开公开访问）。
