---
id: cloud-container-docker-environment-identification-dockerenv-cgroup
title: 判断当前是否在 Docker 容器内：/.dockerenv 空文件与 /proc/1/cgroup 的 docker 前缀两条判据
type: scenario
domain: cloud
path: cloud/container
technique: docker-container-environment-identification
tags:
- docker
- container
- recon
- post-exploitation
- environment-identification
- linux
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:38:04+08:00'
  notes: 已对照原文与截图核对：img02 ls -a / 显示 .dockerenv、img03 /proc/1/cgroup 的 /docker/<id> 路径与卡内PoC一致；cgroup v2/overlay/12位hostname等辅助判据为补充背景，技术上成立；与既有逃逸卡非同链，属独立前置识别技巧；未实际演练
url: /docs/cloud/container/cloud-container-docker-environment-identification-dockerenv-cgroup/
draft: false
kb_aliases:
- 判断是否 docker 容器
- .dockerenv 检测
- /proc/1/cgroup 看容器
- 容器环境识别
- 渗透前置判定
---

## 一句话结论

拿到 shell 后先确认自己是否在 Docker 容器内：`ls -a /` 看根目录是否存在空文件 `/.dockerenv`，以及 `cat /proc/1/cgroup | grep docker` 看 1 号进程的 cgroup 路径是否带 `docker/<容器ID>` 前缀；命中任一条即可判定为容器环境，从而决定走逃逸（privileged、宿主机目录挂载、docker.sock 等）还是横向（容器网段探测）路线。

## 原理

- **`/.dockerenv`**：Docker 启动容器时会在根文件系统创建该空标记文件，容器内普通用户可见。它没有内核级强制力，但足以作为第一判据。
- **`/proc/1/cgroup`**：容器的 1 号进程属于 Docker 为该容器创建的 cgroup（如 `/docker/b965d37095adeaa...`），宿主机进程的 cgroup 路径不含 `docker/<id>` 前缀；`cat /proc/1/cgroup` 直接暴露该路径。
- **两条判据互补**：`/.dockerenv` 可能被镜像/攻击者伪造或删除；cgroup 路径在 cgroup v2 或特殊运行时（如部分 Kubernetes/containerd 配置）可能不再显示 `docker/` 前缀，因此需要结合 `/proc/self/mountinfo` 中的 overlay 挂载、异常短的 12 位 hostname、`CapEff` 能力集等辅助判断。
- **为什么要先判**：容器内的提权/逃逸路径（挂载宿主机磁盘、docker.sock、procfs core_pattern）与普通 Linux 主机完全不同，误判会浪费攻击面或触发告警。

## 触发条件

- 已通过 Web 漏洞/弱口令/命令执行等方式获得 Linux shell；
- 需要判断当前环境是物理机、虚拟机还是容器，以选择提权/逃逸/横向路径。

## 利用步骤

1. `ls -a /`，观察是否存在 `/.dockerenv`。
2. `cat /proc/1/cgroup | grep -i docker`，观察是否输出 `/docker/<容器ID>` 路径。
3. 二者命中即判定为 Docker 容器；未命中但 hostname 为 12 位十六进制、根文件系统为 overlay 时，结合 `/proc/self/mountinfo` 进一步确认。
4. 判定为容器后，按 `CapEff`、挂载情况、docker.sock 是否存在等选择逃逸或横向路线。

## PoC

```bash
# 判据一：容器根目录存在空文件 .dockerenv
ls -a /
# .  ..  .dockerenv  bin  boot  dev  etc  home  ...

# 判据二：1 号进程 cgroup 路径带 docker 前缀
cat /proc/1/cgroup | grep -i docker
# 12:pids:/docker/b965d37095adeaa51bac3b1079e5a08b62e1a0c8f53f0ec67afdcf589a9bac6e
# 11:hugetlb:/docker/b965d37095adeaa51bac3b1079e5a08b62e1a0c8f53f0ec67afdcf589a9bac6e
# ...

# 辅助判据
cat /proc/self/status | grep -i capeff
hostname   # 常见 12 位容器 ID
```

## 变体与关联

- 判定为特权容器后挂载宿主机磁盘逃逸，见 [[cloud-container-docker-privileged-host-disk-escape]]；
- 发现 docker.sock 或 TCP 2375 后接管 Docker，见 [[cloud-container-docker-socket-tcp-escape]]；
- 挂载宿主机 procfs 时利用 core_pattern 逃逸，见 [[cloud-container-docker-procfs-core-pattern-escape]]；
- 非特权容器误挂宿主机目录的识别与利用，见 [[cloud-container-host-dir-bind-mount-etc-crontab-escape]]。

## 检测与防御

- 容器内 `/.dockerenv` 与 cgroup 路径属于运行时固有痕迹，防守方难以完全隐藏；重点应放在检测随后的逃逸动作（mount 宿主磁盘、chroot /host、写宿主机 crontab/authorized_keys、访问 docker.sock）；
- 对容器内执行 `ls /proc/1/cgroup`、`fdisk -l`、`capsh --print` 等探测命令做审计与告警（结合 EDR/auditd）；
- 生产容器遵循最小权限：非 privileged、只读根文件系统、不挂载 docker.sock 与宿主机目录，降低被判定为容器后的可利用面。
