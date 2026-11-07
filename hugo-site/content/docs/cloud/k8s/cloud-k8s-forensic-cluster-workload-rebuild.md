---
id: cloud-k8s-forensic-cluster-workload-rebuild
title: K8s 服务器检材业务重建：Dashboard Token、PVC 宿主机路径与离线镜像导入
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-forensic-cluster-workload-rebuild
tags:
- cloud
- k8s
- forensics
- kubernetes
- pvc
- dashboard
- docker
- incident-response
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:31:18+08:00'
  notes: 已对照原文与图01-20核对：master/node1/node2 v1.28.15、mysql NodePort 30627/php-nginx 31669/redis 31678/dashboard 30001、imagePullPolicy Never与docker load、PVC NFS路径/data/k8s_data/default/dujiaoka、docker.service代理192.168.0.99:4780、yum.log 04月08日、/var/log/secure root改密09:35:59均一致；无CVE、无sources/source_url；未实跑kubectl/docker。
url: /docs/cloud/k8s/cloud-k8s-forensic-cluster-workload-rebuild/
draft: false
kb_aliases:
- K8s 服务器取证
- Kubernetes 检材重建
- dashboard token 登录
- imagePullPolicy Never
- PVC 宿主机路径
- 离线镜像 docker load
---

## 一句话结论

拿到 K8s 服务器磁盘检材后，先在离线环境恢复控制面与节点，再用 `kubectl get nodes/services/pvc` 还原集群拓扑；对于起不来的业务 Pod，把 `imagePullPolicy` 改为 `Never` 并用节点上已有的镜像（或 `docker load` 导入离线 tar）启动，最后通过 `kubectl create token` 登录 Dashboard、通过 Deployment 环境变量与 PVC 的 NFS 路径读取应用配置和数据。

## 原理

- K8s 检材通常包含 master 与 node 的系统盘/数据盘：`/var/lib/kubelet`、`/var/lib/containerd` 或 `/var/lib/docker`、`/etc/kubernetes`、etcd 数据、以及 NFS/本地 PV 目录。恢复集群后，API 对象（Deployment/Service/PVC/Secret/ConfigMap）能直接还原业务拓扑。
- **Service 暴露面**：`kubectl get services -A` 可看到 ClusterIP/NodePort/ExternalIP；案例 mysql 为 NodePort 30627、php-nginx 31669、redis 31678、dashboard 30001，这些端口是后续连接业务与判断架构的入口。
- **Pod 起不来的常见原因**：节点上没有镜像且 `imagePullPolicy: Always`，而检材环境无外网/代理失效。把策略改为 `Never`，并在 Pod 调度到的节点上确认镜像存在；若只在另一个节点有镜像，可 `docker save`/`docker load` 或从镜像仓库离线导入。
- **Dashboard 登录**：`kubectl create token <serviceaccount> --namespace kube-system` 生成短期 Bearer Token，替代旧版 `kubectl get secret` 取 token；案例 ServiceAccount 为 `dashboard-admin`。
- **配置与数据**：Deployment 的 `env` 常含数据库 root 密码、Redis 地址、应用 key；PVC 的 `kubectl describe pv` 会给出 NFS Server 与 Path（案例 `/data/k8s_data/default/dujiaoka`），可直接在宿主机挂载点读取，或用临时 Pod 挂载 PVC。
- **服务器侧证据**：`/lib/systemd/system/docker.service` 可看到 `HTTP_PROXY/HTTPS_PROXY`（案例 `192.168.0.99:4780`）；`/var/log/yum.log` 可定位 Docker 安装日期（案例 04 月 08 日）；`/var/log/secure` 可见 root 改密与登录来源。

## 触发条件

- 有 K8s master/node 的磁盘镜像或虚拟机快照，且能启动控制面与至少一个工作节点。
- 业务镜像/数据在节点本地或 NFS 上，外网不可用，需要离线重建。
- 需要读取的业务数据位于容器内、PVC 或数据库，且原 Pod 已停止/CrashLoopBackOff。
- 有权限执行 `kubectl`、`docker`/`ctr`，并能访问 kubeconfig 或 apiserver。

## 利用步骤

1. **恢复集群**：启动 master 与 node，确认 `kubectl get nodes` 为 Ready；记录节点名、版本、角色（案例 master/node1/node2，v1.28.15）。
2. **盘点对象**：`kubectl get deploy,sts,ds,pod,svc,pvc,pv -A -o wide`；记录 NodePort、镜像、挂载与调度节点。
3. **修复镜像**：对 `ImagePullBackOff` 的 Deployment 执行 `kubectl edit deployment <name> -n <ns>`，把 `imagePullPolicy` 改为 `Never`；在目标节点 `docker images` 确认镜像，缺失时从其它节点 `docker save` 后 `docker load`，或导入离线 tar。
4. **起数据库与依赖**：按检材中的 YAML 顺序 apply（ConfigMap/Secret/PVC/Deployment/Service）；从 Deployment env 读取 root 密码，用 NodePort 连接验证。
5. **挂载/读取业务数据**：`kubectl describe pvc <name> -n <ns>` 与 `kubectl describe pv <pv>` 获取 NFS Server/Path；在宿主机对应目录读取，或创建临时 Pod 挂载 PVC（注意不要写入生产数据）。
6. **登录 Dashboard**：`kubectl create token dashboard-admin -n kube-system`，在 Dashboard 登录页粘贴 Token；若 Dashboard 镜像缺失，同样用本地镜像 + `imagePullPolicy: Never` 修复。
7. **补服务器侧证据**：检查 `docker.service` 代理、`yum.log` 安装时间、`/var/log/secure` 登录/改密记录、容器运行时目录，形成时间线。

## PoC

```bash
# 集群与暴露面
kubectl get nodes -o wide
kubectl get svc -A
kubectl get pod -A -o wide
kubectl get pvc,pv -A

# 修复离线镜像
kubectl edit deployment kubernetes-dashboard -n kubernetes-dashboard   # imagePullPolicy: Never
docker images | grep -E 'dashboard|php-nginx|mysql|redis'
docker save webdevops/php-nginx:7.4 -o php-nginx-7.4.tar
# 在缺少镜像的节点：
docker load -i php-nginx-7.4.tar

# Dashboard Token
kubectl create token dashboard-admin --namespace kube-system

# PVC 宿主机路径
kubectl describe pvc dujiaoka -n default
kubectl describe pv <pv-name>        # 查看 NFS Server / Path

# 服务器侧配置证据
grep -R "PROXY" /lib/systemd/system/docker.service
grep -i docker /var/log/yum.log
grep -E "password changed|Accepted" /var/log/secure
```

本卡为离线取证/恢复流程，不针对在线生产集群执行。

## 变体与关联

- 容器运行时可能是 containerd/CRI-O：用 `ctr -n k8s.io images`、`crictl images` 替代 `docker`。
- 集群可能使用静态 Pod、etcd 快照、外部数据库；恢复顺序与对象来源不同。
- PVC 可能是 local-path、hostPath、Ceph RBD、云盘；先看 PV 的 `Source` 再决定挂载方式。
- 关联：[[cloud-k8s-dashboard-skip-login-cluster-admin-takeover]]（Dashboard 未授权/跳过登录攻击面）、[[cloud-container-docker-privileged-host-disk-escape]]（容器逃逸到宿主机磁盘）、[[defense-forensics-c2-server-sqlite-conf-artifacts]]（服务端配置取证）。
- 边界：若 etcd 数据损坏、镜像与 PV 均缺失，只能从备份/快照恢复；修改 Deployment/PVC 可能改变证据状态，应先做磁盘快照或只读挂载。

## 检测与防御

- 集群侧：启用 RBAC 最小权限、审计日志、Secret 加密；禁止普通用户创建高权限 ServiceAccount/Token；限制 NodePort 暴露。
- 镜像侧：使用私有仓库与镜像签名，固定 digest；节点预拉取关键镜像，避免离线时不可用。
- 数据侧：PVC 使用加密存储与备份；NFS 导出限制来源 IP；敏感 env 改用 Secret 并加密。
- 取证侧：先对磁盘做只读镜像/快照，再启动集群；记录所有 `kubectl edit/apply` 操作，避免污染证据。
