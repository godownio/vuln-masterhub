---
id: cloud-cloud-iam-s3-account-id-enumeration-assumerole-oracle
title: 从公开 S3 桶枚举 AWS Account ID：AssumeRole + 桶策略权限 oracle（s3-account-search）
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: s3-public-bucket-account-id-enumeration
tags:
- cloud
- aws
- s3
- iam
- assume-role
- account-id
- enumeration
- recon
- side-channel
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:08:28+08:00'
  notes: 已对照原文核对：桶名来自源码 mega-big-tech.s3.amazonaws.com、匿名列举、自建角色 get-account-id(meth-big/rolepolicy)+信任关系、s3-account-search found 1→10 均与 01-11 图一致；属侦察原语，仅到 Account ID，severity medium 合理；无版本字段，目标环境仅 AWS 服务不涉及组件版本。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-s3-account-id-enumeration-assumerole-oracle/
draft: false
kb_aliases:
- s3-account-search
- 公开桶反查账号 ID
- AssumeRole 权限 oracle
- AWS Account ID 枚举
- S3 桶策略侧信道
- LeakyBucket
---

## 一句话结论

当目标只暴露一个公开 S3 桶、而需要拿到其所属 AWS Account ID 作为后续攻击（枚举 EBS/RDS 公共快照、角色名等）的入口时，可准备一个「对目标桶有 s3:GetObject 或 s3:ListBucket」的 IAM 角色 ARN，用 `s3-account-search` 反复以候选账号 ID 代入角色并尝试访问桶，把「桶策略是否放行」当作 oracle 逐位收敛，最终爆破出 12 位 AWS Account ID。

## 原理

- S3 桶策略/resource policy 常把访问权限授予特定 AWS 账号（Principal 或条件里含账号 ID）。若攻击者持有一个「能扮演某角色、且该角色被目标桶策略以账号 ID 为条件放行」的凭证，则「代入角色后能否成功访问桶」这一布尔结果就泄露了「目标桶所属账号是否等于猜测值」的信息。
- `s3-account-search` 正是利用这一点：对账号 ID 的每一位/每一段做候选，调用 `sts:AssumeRole` 取得临时凭证后 `HeadObject`/`ListBucket`，观察是否 AccessDenied，逐步收敛出正确账号 ID（AWS Account ID 是 12 位数字，搜索空间有限）。
- 前置条件是要有一个对目标桶具备 `s3:GetObject`/`s3:ListBucket` 的角色 ARN：可用靶场提供的公共 ARN（如 `arn:aws:iam::<id>:role/LeakyBucket`），或自建用户 + 两条策略（用户允许 `sts:AssumeRole`、角色策略允许对目标桶 GetObject/ListBucket）+ 角色信任关系（Principal 指向该用户、Action `sts:AssumeRole`）。
- 桶名本身常从站点资源 URL 得到：S3 虚拟托管式地址为 `<桶名>.s3.amazonaws.com`，从网页源码里 `<img src="https://<桶名>.s3.amazonaws.com/...">` 即可取出桶名，再用 `aws s3 ls s3://<桶名> --no-sign-request --recursive` 确认桶可匿名列举。
- Account ID 本身不是机密，但它是云侦察的关键跳板：拿到后可按 `--owner-ids` 查该账号的公共 EBS/RDS 快照、枚举 IAM 角色名等。

## 触发条件

- 目标存在可匿名访问（或至少可 HeadObject/ListBucket）的 S3 桶，且桶策略按账号 ID 授权。
- 攻击者有一个可对目标桶读/列举的角色 ARN（靶场提供或自建 AWS 账号配置）。
- 能运行 `s3-account-search`（或等价的 AssumeRole + 访问循环）并承受逐位爆破的耗时。

## 利用步骤

1. 从目标 IP/站点入手（ping 可能被禁，curl/nmap 仍可探到 80 端口静态站），在网页源码中找 S3 图片 URL，取桶名。
2. `aws s3 ls s3://<桶名> --no-sign-request --recursive` 确认公开可列。
3. 准备角色 ARN：自建 IAM 用户 + `sts:AssumeRole` 策略 + 对目标桶 `s3:GetObject`/`s3:ListBucket` 的角色策略 + 信任关系；或直接用靶场给的 LeakyBucket ARN。
4. 运行 `s3-account-search <角色ARN> s3://<桶名>`，等待逐位收敛（`found: 1`、`found: 10` … 直至完整 12 位）。
5. 用得到的 Account ID 进入后续链（查该账号公共 EBS/RDS 快照等）。

## PoC

```text
# 1. 源码里取桶名
<img src="https://<bucket>.s3.amazonaws.com/images/x.jpg">

# 2. 确认公开可列
aws s3 ls s3://<bucket> --no-sign-request --recursive

# 3. 用角色 ARN 枚举账号 ID
s3-account-search arn:aws:iam::<own-account>:role/<role> s3://<bucket>
# Starting search (this can take a while) → found: 1 → found: 10 → ... → 完整 12 位 Account ID
```

（最小化示意，ARN/桶名/账号 ID 为占位，未执行任何 PoC。）

## 变体与关联

- 变体：无自有 AWS 账号时可用靶场/社区提供的公共枚举角色 ARN；有账号时按上述两条策略 + 信任关系自建。
- 关联：与「公共 EBS 快照 / 公共 RDS 快照」链衔接——Account ID 常作为 `describe-snapshots --owner-ids`、RDS 公共快照搜索的过滤条件（本批另有对应卡）。
- 关联：与「前端页面源码泄露 S3 桶名」「S3 桶匿名枚举」同属云侦察族；本卡专攻「反查账号 ID」这一具体侧信道。
- 边界：本卡只到「拿到 Account ID」，不含后续提权；AWS 明确 Account ID 非敏感信息，价值在于作为其他资源枚举的索引。

## 检测与防御

- 检测：CloudTrail 中同一来源对大量候选账号的 `sts:AssumeRole` 与 S3 `HeadObject/ListBucket` 高频失败/成功模式、跨账号枚举行为。
- 防御：桶策略避免以账号 ID 作为可被外部探测的条件、对公开桶最小化 `ListBucket` 权限、启用 S3 公共访问块（Block Public Access）、对异常 AssumeRole 失败率告警。
