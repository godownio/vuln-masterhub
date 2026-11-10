---
id: cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation
title: S3 桶匿名枚举 + shared 目录脚本/export.xml 凭据泄露 → 换管理员 AK/SK 读取 admin/flag.txt
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: s3-anonymous-enum-credential-export-privesc
tags:
- cloud
- aws
- s3
- iam
- anonymous-access
- credential-leak
- privilege-escalation
- path-style
- bucket-policy
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:08:35+08:00'
  notes: 已对照原文核对：path-style s3.amazonaws.com/dev.huge-logistics.com、匿名列前缀/递归 AccessDenied、shared/hl_migration_project.zip 内 migrate_secrets.ps1 硬编码 AK/SK、admin/flag.txt 403、test-export.xml 内 AWS IT Admin 凭据换权后读 flag，均与 44-53 图一致；卡内未复述真实密钥，PoC 仅留占位与结构。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation/
draft: false
kb_aliases:
- 老式路径式 S3 访问
- s3.amazonaws.com/桶名
- --no-sign-request
- migrate_secrets.ps1
- test-export.xml
- AWS IT Admin AK/SK
- admin/flag.txt 403
---

## 一句话结论

当一个静态站的图片用老式路径式 S3 地址 `s3.amazonaws.com/<桶名>/` 加载、且桶允许匿名列出部分前缀时，可 `--no-sign-request` 枚举 `shared/`、`static/` 等可匿名目录，从 `shared/` 下的迁移压缩包里解出含低权 AK/SK 的 PS1 脚本；配置该凭据后即可递归列出全桶，发现受限的 `admin/flag.txt`（匿名 403），再从可下载的 `migration-files/test-export.xml` 里找到更高权限的 AWS IT Admin AK/SK，换凭据后读取 flag。

## 原理

- 页面源码里 `<img src="https://s3.amazonaws.com/<桶名>/static/logo.png">` 暴露桶名；这是老式 **path-style** 访问（`s3.amazonaws.com/<桶名>/`），区别于现在常见的虚拟托管式 `<桶名>.s3.amazonaws.com`，但两者都指向同一桶，可换算成 `s3://<桶名>` 用 CLI 操作。
- 桶策略常是「部分前缀匿名可读、其余需鉴权」：`aws s3 ls s3://<桶名>/ --no-sign-request` 能列出 `admin/`、`migration-files/`、`shared/`、`static/` 等前缀，但加 `--recursive` 会 `AccessDenied`（ListObjectsV2 被拒）；需逐个前缀试探哪些可 `--no-sign-request` 读取（本文只有 `shared/`、`static/`）。
- 公开可读的 `shared/hl_migration_project.zip` 里含 `migrate_secrets.ps1`，其内容直接硬编码 `$accessKey/$secretKey/$region`——低权凭据；配置到 aws cli 后可递归列出整桶，定位到 `admin/flag.txt` 但 `s3 cp` 仍返回 403（HeadObject Forbidden），说明该低权身份无权读 admin 前缀。
- 迁移脚本还会从 `export.xml` 读取凭据数据；同一桶 `migration-files/test-export.xml` 可匿名/低权下载，其 `<CredentialsExport>` 含多组明文凭据（Oracle、HP、Iron Mountain、O365、Jira，以及 **AWS IT Admin** 的 AccountID/AccessKeyID/SecretAccessKey）。把其中高权 AK/SK 配置后即完成提权，`aws s3 cp s3://<桶名>/admin/flag.txt .` 成功。
- 根因是桶策略按前缀粗放授权 + 配置文件/脚本里长期堆放明文凭据 + 凭据权限范围超出需要。

## 触发条件

- 站点资源 URL 暴露 S3 桶名，且桶允许匿名（或低权）列出/读取部分前缀。
- 桶内存在含凭据的脚本或导出文件（zip/ps1/export.xml），且可下载。
- 泄露的凭据中存在权限更高、能读取受限前缀（如 `admin/`）的身份。

## 利用步骤

1. 查看页面源码，从 `<img src>` 取桶名（识别 path-style 地址）。
2. `aws s3 ls s3://<桶名>/ --no-sign-request` 列前缀；逐个试探哪些前缀可匿名读。
3. 下载 `shared/*.zip` 并解压，读取 PS1 / 脚本里的硬编码 AK/SK；`aws configure` 配置。
4. `aws s3 ls s3://<桶名> --recursive` 列出全部对象，发现 `admin/flag.txt`；尝试 `s3 cp` 得到 403。
5. 下载 `migration-files/test-export.xml`（或同名导出文件），解析 `<CredentialsExport>` 里各组凭据，找出高权 AWS IT Admin 的 AK/SK。
6. 用高权凭据重新 `aws configure`，`aws s3 cp s3://<桶名>/admin/flag.txt .` 并读取 flag。

## PoC

```text
aws s3 ls s3://<bucket>/ --no-sign-request          # PRE admin/ migration-files/ shared/ static/
aws s3 ls s3://<bucket>/ --no-sign-request --recursive   # AccessDenied
aws s3 ls s3://<bucket>/shared/ --no-sign-request  # hl_migration_project.zip
unzip hl_migration_project.zip && cat migrate_secrets.ps1   # $accessKey / $secretKey / $region
aws configure                                       # 配低权 AK/SK
aws s3 ls s3://<bucket> --recursive                 # admin/flag.txt 等
aws s3 cp s3://<bucket>/admin/flag.txt .           # 403 Forbidden
aws s3 cp s3://<bucket>/migration-files/test-export.xml . && cat test-export.xml
# <CredentialsExport> ... <ServiceType>AWS IT Admin</ServiceType> <AccessKeyID>..</AccessKeyID> ...
aws configure                                       # 换高权 AK/SK
aws s3 cp s3://<bucket>/admin/flag.txt . && cat flag.txt
```

（最小化示意，桶名/凭据/XML 内容为结构占位，未复述任何真实密钥，未执行任何 PoC。）

## 变体与关联

- 变体：虚拟托管式地址同样可换算成 `s3://<桶名>`；若匿名只能 `GetObject` 不能 `ListBucket`，可先从 HTML/JS 里收集具体对象键再逐个下载。
- 关联：与「前端页面源码泄露 S3 桶名」「从公开 S3 桶枚举 Account ID」同属 S3 侦察族；与「公开 EBS 快照挖硬编码 AK/SK」同属「云上明文凭据挖掘后提权」族，但载体是桶内脚本/导出文件。
- 关联：与库内「前端 JS 硬编码 AES 密钥与密文凭据挖掘」「搜索引擎批量发现泄露 AK/SK」等凭据泄露卡互补——本卡强调「同一桶内低权→高权凭据升级」的链。
- 边界：危害是桶内受限对象读取（信息泄露），不含对整个账号的控制。

## 检测与防御

- 检测：CloudTrail/S3 访问日志里异常 `--no-sign-request` 枚举、对 `*.ps1`/`export.xml`/`*.zip` 的批量下载、同一来源短时间内切换多组 AK/SK 访问同一桶。
- 防御：启用 S3 Block Public Access、按最小前缀授权且不给 `ListBucket`；脚本/导出文件绝不写入长期明文 AK/SK，改用 Secrets Manager/角色/短期凭证；对 `admin/` 等敏感前缀单独桶 + 严格桶策略；定期轮换并审计泄露密钥。
