---
id: cloud-k8s-node-sa-token-harvest-rbac-combination-takeover
title: K8s 节点失陷后批量收割 kubelet Pod 目录 ServiceAccount 令牌，组合 RBAC 权限接管集群
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-node-kubelet-sa-token-harvest-rbac-combination
tags:
- kubernetes
- serviceaccount
- token
- kubelet
- rbac
- post-exploitation
- cluster-takeover
- enumeration
- argo-cd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Kubernetes v1.22+（原文：Pod 使用 projected volume 挂载 token/ca.crt/namespace；v1.22 前为自动创建的长期 service-account-token Secret）；原文研究环境 Kubernetes v1.26.1、kubeadm v1.26.1、containerd v1.6.15、Calico v3.25.0、etcd 3.5.6-0
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:36:21+08:00'
  notes: 已对照原文与2张架构图核对：原文明确写“从k8s v1.22开始，pods包括了projected volumes，其中包含1个提供API访问的token”，并有v1.22前自动创建长期service-account-token Secret、v1.22+推荐TokenRequest的版本分水岭注释，卡1 affected_versions 的 v1.22+ 与 v1.22 前表述均有原文依据；研究环境 Kubernetes v1.26.1、kubeadm v1.26.1、containerd v1.6.15、Calico v3.25.0、etcd 3.5.6-0 亦为原文第79-87行所列。令牌位置（每Pod含ca.crt/namespace/token）、kubelet-enum.sh 脚本、Argo-CD SA 实测 *.* [*]、auth can-i * * --all-namespaces、create Secret/create Pod/PV hostPath 组合路径均与原文一致；卡片使用正确的 kubernetes.io~projected 与 /var/run/secrets/kubernetes.io/serviceaccount 路径（原文文本写作 k8s.io，属原文笔误，卡片已按真实路径纠正）。dedup：与 cloud-k8s-k8s-pod-sa-token-rbac-enumeration 被判 likely_duplicate/append_scenario，但本卡获取面为节点root后批量遍历 /var/lib/kubelet/pods 收割全部Pod令牌并强调多SA权限组合，既卡为单Pod shell使用已挂载单令牌，dedup_review 理由成立，保留。未验证点：未在真实K8s环境复跑；frontmatter 无 sources/source_url。
url: /docs/cloud/k8s/cloud-k8s-node-sa-token-harvest-rbac-combination-takeover/
draft: false
kb_aliases:
- kubelet-enum.sh
- /var/lib/kubelet/pods 服务账户令牌收割
- kubelet projected volume token
- Argo-CD cluster-admin token
- 组合权限接管 K8s
---

# 一句话结论

攻击者拿到 K8s worker 节点 root（容器逃逸）后，遍历 `/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*` 即可批量收割该节点上所有 Pod 挂载的 ServiceAccount Token（每个含 ca.crt、namespace、token），用 `kubectl auth can-i --list` 逐个枚举权限；只要其中存在高权限应用（如 Helm 安装的 Argo-CD 拥有 `*.* [*]`），或在多个 SA 间组合出“创建 Pod/创建 Secret/读取 Secret/escalate”等权限，就能接管整个集群。

# 原理

- **令牌落盘位置**：Pod 内的 `/var/run/secrets/kubernetes.io/serviceaccount/` 实际来自节点上的 projected volume，宿主机路径为 `/var/lib/kubelet/pods/<podUID>/volumes/kubernetes.io~projected/kube-api-access-<rand>/`，包含 `ca.crt`、`namespace`、`token` 三个文件。该目录通常仅 root 可读，但攻击者逃逸到宿主机 root 后即可直接读取节点上所有 Pod 的令牌。
- **令牌即身份**：token 是 ServiceAccount 的 bearer 凭据，apiserver 验签后按该 SA 绑定的 Role/ClusterRole 授权。一个节点上常运行数十个不同应用的 Pod，可能对应几十个权限各异的 SA。
- **权限枚举**：对每个 token 执行 `kubectl --certificate-authority=<ca.crt> --token=$(cat token) --namespace=$(cat namespace) --server=https://<apiserver> auth can-i --list`，即可得到该 SA 在该命名空间内可执行的 resource/verb 列表；集群级权限再用 `auth can-i '*' '*' --all-namespaces` 验证。
- **权限组合**：单个 token 权限不足时，可把多个 SA 的权限串起来——例如一个 SA 可 `create pods`（用它创建挂载高权限 SA 的 Pod）/`create secrets`，另一个可 `get/list secrets`，即可通过为高权限 SA 铸造 token Secret 或读取既有 Secret 完成提权。集群管理员的判定特征是 `*.* [*]`（所有资源所有动词）以及 `auth can-i '*' '*' --all-namespaces` 返回 yes。
- **为什么高权限应用会成为跳板**：Helm 安装的 Argo-CD 等集群管理组件需要高权限 SA 才能管理集群；K8s 默认不保证这类 Pod 被调度到单独加固的节点，它可能和易受攻击的业务 Pod 同宿主机。攻击者从弱 Pod 逃逸到该节点后，就能拿到 Argo-CD 的集群管理令牌。
- **为什么这是默认配置风险而非漏洞**：kubelet 目录权限、projected token 挂载与 RBAC 授权都是 K8s 的既定行为；问题在于高权限工作负载与低安全 Pod 混部、以及缺少 Pod 安全标准/自动挂载限制，使一次节点逃逸放大为集群接管。

# 触发条件

- 攻击者已获得某 worker 节点上的 root/主机文件系统访问（容器逃逸、节点漏洞、特权 Pod 等），且 `/var/lib/kubelet` 可读。
- 节点上运行着挂载了 ServiceAccount Token 的 Pod（未设置 `automountServiceAccountToken: false`）。
- 从节点可访问 apiserver 的 6443（或通过代理/内网可达）；token 未过期（projected bound token 会自动轮换，但挂载文件在有效期内可用）。
- 集群中存在高权限 SA（集群管理组件、CI/CD、监控等）或其权限可组合。

# 利用步骤

1. 在宿主机上定位 apiserver 地址（`netstat -n | grep 6443` 或查看 kubelet 配置/环境变量）。
2. 遍历 `/var/lib/kubelet/pods` 下每个 pod 的 projected volume，设置 `cert/token/namespace/apiserver` 变量。
3. 逐个执行 `kubectl --certificate-authority=$cert --token=$(cat $token) --namespace=$(cat $namespace) --server=https://$apiserver auth can-i --list`，记录每个令牌的权限。
4. 标记集群管理员令牌（`*.* [*]`）；同时对每个令牌跑 `auth can-i '*' '*' --all-namespaces` 确认集群级权限。
5. 直接使用高权限令牌操作集群；若权限分散，按下列组合路径提权：
   - 有 `create secrets`：为高权限 SA（如 `argocd-application-controller`、`clusterrole-aggregation-controller`）创建 `kubernetes.io/service-account-token` Secret 并读取其 token；
   - 有 `create pods`：创建 `serviceAccountName: <高权限SA>` 且 `automountServiceAccountToken: true` 的 Pod，进入后读取 token；
   - 有创建 PV/PVC 权限：创建带 `hostPath` 的 PV/PVC 并挂载到 Pod，获得宿主机文件系统访问。
6. 用最终令牌做后渗透：创建后门 SA/ClusterRoleBinding、读取全部 Secret、创建 DaemonSet 覆盖所有节点等。

# PoC

```bash
# 节点 root 后批量枚举每个 Pod 的 SA 令牌权限（原文 kubelet-enum.sh 核心）
for mydir in $(find /var/lib/kubelet/pods -name namespace -exec dirname {} \;); do
  echo "Checking $mydir"
  export cert=$mydir/ca.crt
  export token=$mydir/token
  export namespace=$mydir/namespace
  export apiserver=$(netstat -n | grep 6443 | awk '{print $5}' | uniq)
  kubectl --certificate-authority=$cert --token=$(cat $token) \
    --namespace=$(cat $namespace) --server=https://$apiserver auth can-i --list
done
```

原文实测输出中 Argo-CD 的 SA 权限为 `*.* [*]`，即该命名空间（及其集群级验证）的完整 admin。

# 变体与关联

- 为高权限 SA 铸造 token Secret：见 [[cloud-k8s-create-sa-token-secret-privesc]]。
- 读取已有 Secret 切换 SA：[[cloud-k8s-k8s-rbac-secret-read]]；单 Pod 内令牌枚举：[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]；TokenRequest：[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]。
- Pod 创建/主机逃逸：[[cloud-k8s-taint-toleration-nodeaffinity-master-escape]]、[[cloud-k8s-mysql-loadfile-sa-token-kubectl-hostpath-escape]]。
- 后渗透：控制面 CA 证书伪造 system:masters（[[cloud-k8s-control-plane-ca-system-masters-cert-forge]]）、控制 ETCD 修改集群数据（[[cloud-k8s-k8s-etcd-unauth]]）、DaemonSet 覆盖所有节点。

# 检测与防御

- 检测：审计日志中同一源 IP（尤其 worker 节点 IP）短时间内用多个不同 SA 身份调用 `selfsubjectrulesreviews`、`selfsubjectaccessreviews`、`secrets`、`pods` 等 API；`auth can-i --list` 会产生大量 SelfSubjectRulesReview。正常应用很少查询自身权限，这是强信号。
- 检测：Pod 创建时 `serviceAccountName` 与工作负载不匹配、创建 `kubernetes.io/service-account-token` 类型 Secret、异常 `escalate`/`bind` 与 ClusterRole 更新。
- 检测：主机侧监控对 `/var/lib/kubelet/pods/**/volumes/kubernetes.io~projected/**/token` 的批量读取（需运行时安全工具/auditd）。
- 防御：执行 Pod 安全标准（Baseline/Restricted）阻止特权 Pod 与常见逃逸；不需要访问 apiserver 的 Pod 设置 `automountServiceAccountToken: false`；每个工作负载专用 SA 并最小权限；高权限组件（Argo-CD、CI/CD、监控）调度到专用加固节点并限制同节点混部；加密 Secret；网络策略限制 Pod/节点到 apiserver 的访问；开启审计（audit policy）并对接 Falco 等告警。
