---
id: defense-forensics-overlayfs-mount-shadowing-log-hide
title: OverlayFS/挂载覆盖隐藏 /var/log 的识别与恢复
type: scenario
domain: defense
path: defense/forensics
technique: overlayfs-mount-shadowing-log-hide
aliases:
- 挂载覆盖隐藏日志
- mount shadowing
- OverlayFS 日志隐藏
- tmpfs 覆盖 /var/log
- 反取证日志隐藏
tags:
- forensics
- anti-forensics
- linux
- overlayfs
- mount
- log-analysis
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:38:56+08:00'
  notes: 已对照原文与14张图核对：findmnt 显示 /var/log 被两处 overlay 挂载，umount 后 auth.log 恢复；恢复后可见 postgresql-user 于 2025-05-04 从 102.54.197.238 Accepted publickey。原理/步骤/PoC与原文一致。未验证点：未实际执行mount/umount；原文为CTF靶场，真实环境需root/CAP_SYS_ADMIN。无版本区间，未设versions。
---

## 一句话结论

攻击者获得 root 后可把空的 tmpfs 或 OverlayFS 挂载到 `/var/log` 上，让 `ls`/`cat` 只能看到“覆盖层”，原始日志仍留在下层磁盘但被 VFS 遮蔽；应急时用 `findmnt` 找到异常挂载并 `umount` 即可恢复原始日志。

## 原理

- Linux 的路径解析由挂载表决定：在某个目录上挂载新的文件系统后，该路径的查找会落到新挂载的根，而不是原目录的内容。这就是“挂载覆盖”（mount shadowing）。
- 攻击者把空的 `tmpfs` 或 `overlay` 挂到 `/var/log` 后，读取 `/var/log` 看到的是空目录/覆盖层；原始 `auth.log`、`syslog` 等仍在下层文件系统中，只是暂时不可见。
- OverlayFS 通过 `lowerdir`/`upperdir`/`workdir` 合并多层目录：如果攻击者把原始日志目录作为 lower、空的 upper 放到别处，或反过来用一个空层覆盖，读取结果取决于挂载配置。案例中 `findmnt` 显示 `/var/log` 被 overlay 挂载，源路径位于 `/work/storage/.../log` 与 `/work/rootfs/tmp/.../mnt`，`umount` 后原始 `auth.log` 重新可见。
- 这种做法比 `rm -rf /var/log/*` 更隐蔽：文件没有被删除，文件完整性监控可能看不到内容被清空；常规 `ls` 也看不到异常，除非检查挂载表。
- 如果攻击者在独立的 mount namespace 中操作（容器/`unshare -m`），宿主机进程的 `/proc/<pid>/mountinfo` 仍能看到该 namespace 的挂载；需要进入对应 namespace 或读取其 `/proc/<pid>/root`。

## 触发条件

- 攻击者已获得 root（或具备 `CAP_SYS_ADMIN`）并能执行 `mount`。
- 目标未限制 mount 操作（无只读根、无 seccomp/AppArmor 阻断 `mount`）。
- 原始日志所在文件系统仍可访问；攻击者只是覆盖视图，没有删除/格式化底层数据。
- 应急人员能以 root 检查挂载表并执行 `umount`（或从其他 namespace/宿主机查看）。

## 利用步骤

1. 攻击者创建空目录/文件系统作为覆盖层：
   `mkdir -p /tmp/empty && mount -t tmpfs tmpfs /var/log`
   或使用 overlay：
   `mount -t overlay overlay -o lowerdir=/var/log,upperdir=/tmp/up,workdir=/tmp/work /var/log`
2. 确认覆盖生效：`ls -la /var/log` 只看到空/覆盖层内容。
3. 原始日志仍在下层；攻击者可继续操作，常规查看看不到历史日志。
4. 应急人员检查挂载：`findmnt /var/log`、`cat /proc/self/mountinfo | grep /var/log`。
5. 解除覆盖：`umount /var/log`（busy 时 `umount -l /var/log`），再次查看原始日志。
6. 若挂载位于其他 namespace：进入 namespace 或读取 `/proc/<pid>/root/var/log`。

## PoC

```bash
# 攻击者：用空 tmpfs 覆盖日志目录（需 root）
mkdir -p /tmp/empty
mount -t tmpfs tmpfs /var/log
ls -la /var/log          # 只看到空目录/覆盖层

# 应急：发现异常挂载
findmnt /var/log
# 示例输出：
# TARGET   SOURCE   FSTYPE   OPTIONS
# /var/log overlay[/work/storage/.../log] overlay rw,relatime

# 恢复原始日志
umount /var/log
ls -la /var/log          # 原始 auth.log/syslog 重新出现
grep sshd /var/log/auth.log
```

```bash
# 查看所有进程的挂载命名空间差异（发现隐藏挂载）
for p in /proc/[0-9]*; do
  findmnt -N "$(readlink -f "$p/ns/mnt")" /var/log 2>/dev/null && echo "pid=$p"
done
```

## 变体与关联

- 变体：`tmpfs`、`overlay`、`bind mount` 都可以覆盖目录；bind mount 一个空目录到 `/var/log` 同样能遮蔽。
- 变体：只覆盖 `/var/log/audit`、`/var/log/auth.log` 等关键文件/子目录，降低被整体巡检发现的概率。
- 变体：在容器内挂载，利用 mount namespace 让宿主机常规 `ls` 看不到，但宿主机 `/proc/<pid>/mountinfo` 仍可发现。
- 关联：[[defense-forensics-multisource-timeline-log-clear]]（日志被删除后的多源时间线重建）；[[defense-forensics-ansi-escape-log-poisoning]]、[[defense-forensics-carriage-return-output-overwrite]]（其他日志反取证手法）。
- 边界：需要 root/CAP_SYS_ADMIN；底层文件若被删除/格式化，umount 也无法恢复；只读根、无 CAP_SYS_ADMIN、seccomp 阻断 mount 时无法实施。

## 检测与防御

- 检测：监控 `mount`/`umount` 系统调用（auditd、eBPF）；定期比对 `/proc/self/mountinfo` 与基线，告警 `/var/log`、`/var/log/audit` 上出现的 tmpfs/overlay/bind 挂载；检查异常 mount namespace；对日志目录做 inode/文件数基线。
- 修复/加固：限制普通账户与服务的 `CAP_SYS_ADMIN`；使用只读根/只读日志分区；容器使用 `PrivateTmp`、只读挂载与 seccomp 阻断 mount。
- 缓解：日志实时转发到远程 SIEM/对象存储，保留独立副本；启用文件完整性监控；应急时先保存 `/proc/*/mountinfo` 再卸载。
