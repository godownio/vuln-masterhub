---
id: cloud-cloud-iam-access-key-info-account-id-password-reuse-console
title: 泄露 AK 缺少 SK：sts get-access-key-info 反查账号 ID，口令复用登录 AWS 控制台读 Secrets Manager 并连 RDS 取数
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: sts-get-access-key-info-account-id-console-password-reuse
aliases:
- get-access-key-info 查账号
- AK 反查 Account ID
- .env 泄露 AK
- AWS 控制台口令复用
- Secrets Manager 读 RDS 口令
- employee-database
- truffleHog
tags:
- cloud
- aws
- iam
- sts
- access-key
- account-id
- password-reuse
- secrets-manager
- rds
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:37:08+08:00'
  notes: 已对照原文核对 get-access-key-info 反查账号、控制台口令复用、Secrets Manager 读 employee-database、RDS 取数；原文未展示 get-access-key-info 输出与登录过程，未实机复现
---

## 一句话结论

从泄露的 `.env` 里只拿到 `AWS_ACCESS_KEY_ID`（没有 Secret）时，仍可用 `aws sts get-access-key-info --access-key-id <AK>` 反查出它所属的 AWS 账号 ID；把同一份 `.env` 里的用户名/口令（常与 AWS 控制台口令复用）配上该账号 ID 登录控制台，即可查看并读取 Secrets Manager 中的 RDS 凭据，连接数据库导出含 PII/flag 的业务表。

## 原理

- **AK ID 本身是半公开标识**：`GetAccessKeyInfo` 只需要 AccessKeyId 就能返回其归属账号（无需该 AK 的 Secret），因此泄露的 AccessKeyId 不是"无用的半截凭据"，而是账号指纹，可用于后续钓鱼、快照/桶枚举与定向口令喷射。
- **口令复用**：开发/运维常把同一套用户名口令用于业务 `.env`、数据库和 AWS 控制台；拿到账号 ID 后即可对 `https://<account-id>.signin.aws.amazon.com/console` 尝试该口令（必要时结合 MFA 缺失）。
- **Secrets Manager 是数据入口**：控制台/API 可列出 secret 名称与描述（如 `employee-database`、`employee-database-admin`），有权限时 `get-secret-value` 直接返回 JSON（username/password/engine/host/port），等价于拿到数据库账号。
- **RDS 数据面**：用 secret 中的凭据连接 MySQL/MariaDB（本例 `employees.<id>.us-east-1.rds.amazonaws.com:3306`）即可 `select * from employees` 读取员工姓名、邮箱、电话、薪资等 PII，或直接读取 flag 表。
- **为什么成立**：`.env` 属于前端构建产物/仓库常见泄露点；长期 AK 与业务口令混放且复用，把"前端配置泄露"升级为"云账号控制台 + 数据库"双重入口。

## 触发条件

- 获取到含 `REACT_APP_AWS_ACCESS_KEY_ID`、数据库用户名/口令等字段的 `.env`/构建产物/仓库文件。
- 该 AccessKeyId 有效且未删除（能反查账号）；账号允许 IAM 用户控制台登录。
- 泄露的用户名/口令在 AWS 控制台复用且未强制 MFA；该身份有 Secrets Manager 读权限或至少列表权限。
- RDS 实例可公网/可达，secret 中的数据库账号可登录。

## 利用步骤

1. 从 `.env` 提取 `DB_USERNAME/DB_PASSWORD`、`REACT_APP_AWS_ACCESS_KEY_ID`、区域与桶名。
2. `aws sts get-access-key-info --access-key-id <AK>` 得到 Account ID。
3. 用 `https://<account-id>.signin.aws.amazon.com/console`（或普通登录页输入账号 ID）尝试 `DB_USERNAME/DB_PASSWORD` 登录控制台。
4. 进入 Secrets Manager，列出 secret（本例 `employee-database`、`employee-database-admin` 等），读取 `employee-database` 的 SecretString（含 username/password/host/port/masterarn）。
5. 用 MySQL 客户端连接 RDS：`mysql -u reports -p -h employees.<id>.us-east-1.rds.amazonaws.com`，执行 `select * from employees;` 读取 PII/flag。
6. 也可用 truffleHog 对前端构建目录做正则+熵扫描，批量发现同类泄露。

## PoC

```bash
# 1) 仅凭 AccessKeyId 反查账号
aws sts get-access-key-info --access-key-id AKIA...

# 2) 控制台口令复用（浏览器）
# https://<account-id>.signin.aws.amazon.com/console
#   账号: <DB_USERNAME>  口令: <DB_PASSWORD>

# 3) 读取 Secrets Manager 中的数据库凭据
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id employee-database

# 4) 连接 RDS
mysql -u reports -p -h employees.<id>.us-east-1.rds.amazonaws.com
```

```bash
# 前端构建目录批量扫描
truffleHog --regex --entropy=False ./aws-react-app
```

## 变体与关联

- 变体：只有 AK ID 时，还可用账号 ID 检索公共 EBS/RDS 快照（见关联卡）或做 S3 桶名/账号枚举。
- 变体：控制台登录受 MFA 限制时，转向 `iam:ListUsers`/`GetLoginProfile` 或直接对泄露的数据库口令做内网复用。
- 关联：[[cloud-public-ebs-snapshot-volume-mount-credential-loot]]（用账号 ID 找公共快照）、[[cloud-public-rds-snapshot-restore-master-password-data-loot]]（同以 RDS 数据为终点）、[[cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager]]（另一条 Secrets Manager 取数链）。

## 检测与防御

- 不在前端构建/env 中放长期 AWS 凭据，改用 Cognito/实例角色/STS；对已泄露 AK 立即停用。
- 强口令策略 + 唯一口令 + 强制 MFA；禁止将业务口令与云控制台口令复用。
- Secrets Manager 最小权限与资源策略，开启访问审计；RDS 不暴露公网，使用 IAM 认证/临时令牌。
- 检测：CloudTrail 中 `GetAccessKeyInfo` 针对本账号 AK 的异常查询、控制台登录异常源 IP/无 MFA 登录、随后 `GetSecretValue` 与 RDS 连接激增。
