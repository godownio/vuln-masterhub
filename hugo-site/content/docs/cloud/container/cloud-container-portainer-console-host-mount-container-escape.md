---
id: cloud-container-portainer-console-host-mount-container-escape
title: 拿到 Portainer 控制台后创建宿主机目录挂载容器：容器 console 内 chroot /host 接管宿主机
type: scenario
domain: cloud
path: cloud/container
technique: portainer-console-create-host-mount-container-escape
tags:
- docker
- container
- escape
- portainer
- docker-api
- host-mount
- chroot
- management-console
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:38:02+08:00'
  notes: 已对照原文与5张截图核对：原文仅一句话给出Portainer控制台→创建容器挂载宿主机目录→chroot思路并附首页截图，未逐步演示；卡内步骤标注为通用操作、confidence medium，原理与触发条件无误，与docker.sock/TCP 2375等既有卡入口不同非同链；未实际演练
url: /docs/cloud/container/cloud-container-portainer-console-host-mount-container-escape/
draft: false
kb_aliases:
- Portainer 逃逸
- Portainer 创建容器挂载宿主机
- Portainer chroot 宿主机
- Portainer 容器管理面滥用
- docker 管理面板逃逸
---

## 一句话结论

拿到 Portainer 控制台的访问权后（其本身不设默认账号密码、首次访问才设置管理员，弱口令/会话泄露/未授权等场景均可获得），攻击者可以在 Containers 页面新建一个容器，把宿主机根目录 `/` 绑定到容器内的 `/host`（可选 privileged），部署后进入该容器 console 执行 `chroot /host /bin/bash`，即从管理面板拿到宿主机 root 文件系统；Portainer 只是 Docker API 的可视化外壳，逃逸能力完全继承自 Docker daemon 的 root 权限。

## 原理

- **Portainer 的权限模型**：Portainer 通过挂载的 `/var/run/docker.sock`（或配置的 TCP endpoint）控制宿主机 Docker daemon。能在 Portainer 里创建容器，等价于能向 Docker API 提交任意 `HostConfig`。
- **bind mount 跨越隔离边界**：创建容器时 `HostConfig.Binds: ["/:/host"]` 由 dockerd（宿主机 root）执行，容器启动后宿主机完整文件树出现在 `/host`。Docker 默认保留 `CAP_SYS_CHROOT`，容器内 root 可直接 `chroot /host`，之后的命令在宿主机根文件系统内执行。
- **为什么 privileged 可选**：仅做宿主机文件读写/chroot 时不需要 `--privileged`；加 privileged 还能访问块设备、直接 mount 分区，属于同一配置错误的加强版。
- **为何是完整逃逸**：宿主机 `/etc/shadow`、`/var/spool/cron`、`/root/.ssh` 都可读写，攻击者可改口令、写计划任务、写公钥，最终取得宿主机 root 控制权，且过程中不依赖任何 Docker 漏洞。

## 触发条件

- Portainer Web 端口可从攻击网络访问，且攻击者已获得有效登录会话（弱口令、凭据泄露、未授权/漏洞、会话劫持等）；
- 该 Portainer endpoint 对应的 Docker daemon 正常可用（能拉取或已有镜像）；
- 目标没有限制容器 bind mount 宿主机根目录或 privileged（默认 Docker 不做限制）。

## 利用步骤

1. 登录 Portainer，确认 `Home → Endpoints` 中的 primary endpoint 处于 `up`，能看到容器/镜像数量。
2. 进入 `Containers → Add container`，选择任意可用镜像（如 alpine/nginx），名称随意。
3. 在 `Volumes`/`Binds` 处添加 bind：host 路径 `/`，container 路径 `/host`；如需设备访问再勾选 privileged。
4. `Deploy the container` 启动，然后打开该容器的 `Console`（/bin/sh）。
5. 在 console 内执行 `chroot /host /bin/bash`，或直接 `cat /host/etc/shadow`、向 `/host/var/spool/cron/root` 写反弹任务、向 `/host/root/.ssh/authorized_keys` 写公钥。
6. 清理创建的容器与挂载（授权测试后）。

等价 Docker CLI（有 docker 客户端时）：

```bash
docker -H tcp://TARGET:2375 run -it --rm -v /:/host alpine chroot /host /bin/bash
```

## PoC

Portainer UI 操作即最小 PoC（原文仅给出 Portainer 首页截图和"创建容器挂载宿主机目录后 chroot"的一句话思路，未逐步演示创建过程；上述步骤为 Portainer 通用操作）。创建后的验证命令：

```bash
chroot /host /bin/bash
id                # uid=0(root)
cat /host/etc/shadow | head -1
```

## 变体与关联

- 直接利用暴露的 docker.sock 或 TCP 2375 创建宿主挂载容器，见 [[cloud-container-docker-socket-tcp-escape]]；
- 非特权容器误挂宿主机目录后写 /etc/crontab 逃逸，见 [[cloud-container-host-dir-bind-mount-etc-crontab-escape]]；
- 特权容器挂载宿主磁盘逃逸，见 [[cloud-container-docker-privileged-host-disk-escape]]；
- Docker TLS 2376 + 泄露 CA 私钥接管 API，见 [[cloud-container-docker-tls-ca-key-client-cert-api]]。

## 检测与防御

- Portainer 设置强口令、启用 MFA、限制管理端口来源 IP，不使用默认/共享管理员账号；
- 审计 Docker 事件中 `Binds` 含宿主机 `/` 或 `Privileged=true` 的容器创建，发现即告警并阻断；
- Portainer 关联的 endpoint 使用最小权限（只读 endpoint、受限 daemon），生产与管理面网络隔离；
- 监控容器内 `chroot /host`、读取 `/host/etc/shadow`、写 crontab/authorized_keys 等行为；
- 及时更新 Portainer（历史版本存在未授权/认证绕过类问题），并避免将管理面板直接暴露在公网。
