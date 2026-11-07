---
id: cloud-k8s-k8s-pod-sa-token-rbac-enumeration
title: Pod 内 ServiceAccount Token 权限枚举与利用路径判定
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-sa-token-rbac-enumeration
tags:
- kubernetes
- serviceaccount
- rbac
- token
- post-exploitation
- enumeration
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:31+08:00'
  notes: 已对照原文核对；SA token 挂载路径、SelfSubjectRulesReview 请求体、kubectl auth can-i、权限到后续路径映射均与原文一致；属枚举前置技法，原文未给真实环境回显，未本地复现
url: /docs/cloud/k8s/cloud-k8s-k8s-pod-sa-token-rbac-enumeration/
draft: false
kb_aliases:
- K8s SA token 枚举
- SelfSubjectRulesReview
- kubectl auth can-i
- Pod 内权限收集
---

## 一句话结论

拿到 Pod shell 后，默认挂载的 ServiceAccount Token 就是调用 apiserver 的身份；用 `SelfSubjectRulesReview` 或 `kubectl auth can-i --list` 枚举其 RBAC 权限，即可判断应该走读 Secret、建 Pod、访问 kubelet 还是直接绑定 cluster-admin 的后续路径。

## 原理

- 每个命名空间有默认 ServiceAccount `default`；Pod 未指定 `serviceAccountName` 时自动使用它，并把 Token、`ca.crt`、`namespace` 挂载到 `/var/run/secrets/kubernetes.io/serviceaccount/`。
- Pod 内的进程读取 Token 后，以 `Authorization: Bearer <token>` 调用 `https://kubernetes.default.svc`；apiserver 验签后按该 SA 绑定的 Role/ClusterRole 做 RBAC 授权。
- 因此 Token 的权限就是攻击者在集群内的权限边界。盲目尝试具体接口容易得到 403 而误判“没权限”；`SelfSubjectRulesReview` 会一次性返回当前 SA 在指定命名空间可执行的 verb/resource 列表，是判断后续路径的最准确方式。
- 返回 401 表示 Token 无效或过期，403 表示 Token 有效但该接口权限不足——403 不代表没有利用价值，只是需要换一个接口或命名空间继续枚举。
- 枚举结果直接对应后续链：能 `get/list secrets` 走凭据窃取；能 `create pods` 走恶意 Pod/逃逸；能 `get nodes/proxy` 走 kubelet 代理；能 `create clusterrolebindings` 直接绑 cluster-admin；权限很低则转向容器逃逸或网络横向。

## 触发条件

- 已通过应用层 RCE、文件上传、SSRF 等拿到 Pod 内命令执行。
- Pod 未设置 `automountServiceAccountToken: false`，Token 文件存在。
- apiserver 在集群内可达（`kubernetes.default.svc` 可解析）。
- Token 未过期，且对应 SA 绑定了至少一条有用权限。

## 利用步骤

1. 确认身处 Pod：`env | grep -i kubernetes`、检查 `/var/run/secrets/kubernetes.io/serviceaccount/`、`/proc/1/cgroup`、`/etc/resolv.conf`。
2. 读取 Token、CA、命名空间，设置变量：
   ```bash
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
   NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
   APISERVER=https://kubernetes.default.svc
   ```
3. 用 `GET /api` 测试 Token 是否可用，区分 200/401/403。
4. 调 `SelfSubjectRulesReview` 枚举当前命名空间权限；有 kubectl 时用 `kubectl auth can-i --list -n <ns>`。
5. 按权限映射后续路径（见下表），逐条验证，不要只凭规则列表假设可利用。
6. 若当前命名空间权限低，检查是否能枚举/读取其他命名空间，或转向工作负载配置与网络层。

```bash
curl --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"'"$NAMESPACE"'"}}'
```

## PoC

```bash
# 1) 确认 Token 可用
curl -s -o /dev/null -w '%{http_code}\n' --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" $APISERVER/api

# 2) 枚举规则（返回 resourceNames/verbs/resources 列表）
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"'"$NAMESPACE"'"}}'

# 3) 有 kubectl 时直接列全部权限
kubectl auth can-i --list -n "$NAMESPACE"
kubectl auth can-i --list -n kube-system
```

权限到后续路径的映射：

```text
get/list secrets              -> 读取 Secret、解码凭据、切换 SA 身份
create pods                   -> 创建 hostPath/privileged Pod 逃逸或挂高权限 SA
get nodes/proxy               -> 经 apiserver 代理访问 kubelet，读日志/信息/尝试 exec
create clusterrolebindings    -> 绑定 cluster-admin，直接接管集群
create rolebindings           -> 在命名空间内绑定高权限 Role
impersonate                   -> 伪装其他用户/SA
无有用权限                    -> 转容器逃逸或网络横向
```

## 变体与关联

- `automountServiceAccountToken: false` 时没有 Token，枚举路径失效，应转向工作负载配置与网络层。
- 旧版集群可能使用长期不过期的 Secret 型 SA Token；新版默认使用 projected bound token，有 audience/过期时间，但仍可在 Pod 内直接使用。
- 403 的接口可以换命名空间或换资源继续试；`SelfSubjectRulesReview` 只反映指定命名空间的规则，集群级权限需另查 ClusterRoleBinding。
- 关联：`[[cloud-k8s-k8s-rbac-secret-read]]`、`[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]`、`[[cloud-k8s-k8s-kubelet-unauth]]` 分别对应枚举出的主要利用路径；`[[cloud-container-k8s-workload-config-escape]]` 对应权限不足时的逃逸路径。

## 检测与防御

- 检测：Pod 内进程访问 apiserver 的 `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews`、`/api/v1/namespaces/*/secrets`、`/api/v1/namespaces/*/pods` 等敏感路径；审计日志中同一 SA 短时间内大量 403/枚举请求。
- 检测：容器内读取 `/var/run/secrets/kubernetes.io/serviceaccount/token` 的行为（需运行时安全工具），以及从 Pod 发往 `kubernetes.default.svc` 的异常请求。
- 防御：不需要访问 apiserver 的 Pod 设置 `automountServiceAccountToken: false`；为每个工作负载创建专用 SA，按最小权限绑定 Role，避免使用 default SA。
- 防御：默认 SA 不绑定任何写权限；禁用匿名访问；对 RBAC 高危 verb（`create clusterrolebindings`、`escalate`、`bind`、`impersonate`）单独审计与告警。
- 加固：使用 Pod Security Admission/OPA 限制特权与 hostPath；网络策略限制 Pod 到 apiserver 的访问；定期用 `kubectl auth can-i --list` 和 RBAC 审计工具复核权限。
