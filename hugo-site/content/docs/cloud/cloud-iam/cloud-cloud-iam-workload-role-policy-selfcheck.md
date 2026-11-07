---
id: cloud-cloud-iam-workload-role-policy-selfcheck
title: 云工作负载凭据的 IAM 策略自助枚举与危险权限判定
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: cloud-workload-role-policy-selfcheck
tags:
- cloud
- aws
- iam
- cloudtrail
- credential
- enumeration
- privilege
- post-exploitation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:38:59+08:00'
  notes: 已对照原文base64解码脚本核对：get-caller-identity解析角色名、list-attached-role-policies比对 AdministratorAccess/PowerUserAccess/AmazonS3FullAccess/IAMFullAccess/AWSLambdaFullAccess 等、无IAM权限时用 aws s3 ls / aws lambda list-functions 回退探测，均与原文一致。未验证点：未实际执行云API；该卡为权限侦察原语，后续危害取决于实际权限。无版本区间，未设versions。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-workload-role-policy-selfcheck/
draft: false
kb_aliases:
- IAM 角色策略自查
- list-attached-role-policies 探测
- 实例角色权限判定
- AWS 凭据价值评估
- 云主机权限侦察
---

## 一句话结论

攻陷云主机后，攻击者可用该主机的实例/任务角色凭据调用 `sts:GetCallerIdentity` 与 `iam:ListAttachedRolePolicies`，按托管策略名判断角色是否具备管理员/S3/Lambda 等高价值权限，再决定立即反弹 Shell 还是转为持久化与横向。

## 原理

- 云工作负载（EC2 实例、ECS 任务、Lambda 等）通常通过实例元数据、环境变量或凭据文件获得临时角色凭据。拿到主机 Shell 往往等于拿到该角色的权限。
- `aws sts get-caller-identity` 返回当前凭据对应的 ARN；若为 `assumed-role/<Role>/<Session>`，可从 ARN 解析角色名。
- `aws iam list-attached-role-policies --role-name <Role>` 列出直接附加到该角色的 AWS 托管策略。攻击者只需匹配策略名即可快速判断权限价值，例如：
  - `AdministratorAccess`：几乎全权限；
  - `PowerUserAccess`：除 IAM/组织外的广泛权限；
  - `AmazonS3FullAccess`：可读写所有桶，适合外泄；
  - `IAMFullAccess`：可创建/附加策略，进一步提权；
  - `AWSLambdaFullAccess`/`AWSLambda_FullAccess`：可修改函数代码，横向到其他角色。
- 如果没有 `iam:ListAttachedRolePolicies` 权限，攻击者用“API 是否成功”作为权限预言机：`aws s3 ls` 成功说明有 S3 读权限；`aws lambda list-functions` 成功说明有 Lambda 枚举权限。任一成功即认为凭据有利用价值。
- 判定结果直接决定后续策略：高价值凭据 → 立即反弹 Shell/外泄；低价值 → 先写 Cron 持久化、用 SSH 密钥横向，避免打草惊蛇。
- 该技术不需要外部扫描或漏洞利用，只依赖云 API 的合法调用；在 CloudTrail 中会留下 `GetCallerIdentity`、`ListAttachedRolePolicies`、`ListBuckets`、`ListFunctions` 等事件。

## 触发条件

- 已获得云工作负载的 Shell，且该工作负载绑定了可用的 IAM 角色/临时凭据。
- 主机可访问 AWS API（公网或 VPC Endpoint），并能运行/安装 AWS CLI。
- 角色至少具备 `sts:GetCallerIdentity`（通常默认允许）以及部分 IAM/S3/Lambda 权限。
- 攻击者能根据策略名/API 结果做分支决策。

## 利用步骤

1. 确认凭据与身份：
   `aws sts get-caller-identity --query Arn --output text`
2. 从 ARN 解析角色名（`assumed-role/<Role>/<Session>` 中的 `<Role>`）。
3. 列出附加的托管策略：
   `aws iam list-attached-role-policies --role-name <Role> --query 'AttachedPolicies[*].PolicyName' --output text`
4. 与高价值策略名单比对（AdministratorAccess、PowerUserAccess、AmazonS3FullAccess、IAMFullAccess、AWSLambdaFullAccess 等）。
5. 若无 IAM 权限，回退探测：
   `aws s3 ls`；`aws lambda list-functions`。
6. 根据结果选择：高价值 → 直接反弹 Shell/外泄；低价值 → 持久化 + SSH 横向（见关联卡片）。

## PoC

```bash
# 1. 当前身份
aws sts get-caller-identity --query Arn --output text
# 示例：arn:aws:sts::<account>:assumed-role/WebAppRole/i-0123456789abcdef0

# 2. 解析角色名并列出附加策略
ROLE_NAME=$(aws sts get-caller-identity --query Arn --output text | awk -F'/' '{print $2}')
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyName' --output text

# 3. 与高价值策略比对（示例）
for p in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyName' --output text); do
  case "$p" in
    AdministratorAccess|PowerUserAccess|AmazonS3FullAccess|IAMFullAccess|AWSLambdaFullAccess|AWSLambda_FullAccess)
      echo "high-value policy: $p";;
  esac
done

# 4. 无 IAM 权限时的回退探测
aws s3 ls && echo "S3 access"
aws lambda list-functions && echo "Lambda access"
```

```text
# 判定逻辑：
# 命中高价值策略，或 s3/lambda 探测成功 -> 立即反弹 Shell/外泄
# 全部失败 -> 转持久化 + SSH 横向，避免高噪声操作
```

## 变体与关联

- 变体：ECS 任务角色、Lambda 执行角色、GKE/其他云的 Workload Identity 也可用类似方式枚举（`gcloud auth list`、`gcloud projects get-iam-policy`、Azure `az role assignment list`）。
- 变体：不调用 IAM API，直接用 `aws s3 ls`、`aws ec2 describe-instances`、`aws lambda list-functions` 等业务 API 的成功/失败推断权限。
- 变体：结合 `aws iam list-role-policies`（内联策略）、`list-attached-user-policies`、`get-policy-version` 展开策略文档，判断具体 Action/Resource。
- 关联：[[pentest-lateral-movement-ssh-key-history-autospread-cron]]（低价值凭据时的持久化与横向分支）；[[defense-forensics-cloudtrail-s3-exfil-identity-trace]]（这些 API 调用在 CloudTrail 中的溯源）。
- 边界：角色无 `iam:ListAttachedRolePolicies` 且所有探测 API 都失败时，无法判断权限；凭据过期、被 SCP/permissions boundary 限制或网络不可达 AWS API 时也会失败。该技术是权限侦察，不是直接提权；后续危害取决于实际权限。

## 检测与防御

- 检测：监控工作负载角色调用 `sts:GetCallerIdentity`、`iam:ListAttachedRolePolicies`、`s3:ListAllMyBuckets`、`lambda:ListFunctions` 等枚举型 API；关注非预期时间/来源的调用；结合 GuardDuty 的凭据异常使用告警。
- 修复/加固：遵循最小权限，避免给工作负载附加 `AdministratorAccess`/`PowerUserAccess` 等宽泛托管策略；使用 permissions boundary 与 SCP 限制；定期审计未使用权限。
- 缓解：为工作负载使用短期凭据并限制 IMDS 访问（IMDSv2、hop limit）；监控凭据外泄；对敏感 API 加审批/告警。
