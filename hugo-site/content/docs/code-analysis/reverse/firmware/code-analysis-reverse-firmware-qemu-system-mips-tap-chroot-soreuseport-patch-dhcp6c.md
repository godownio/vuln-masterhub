---
id: code-analysis-reverse-firmware-qemu-system-mips-tap-chroot-soreuseport-patch-dhcp6c
title: qemu-system MIPS 仿真 ER605 固件：brctl/tunctl 搭 tap 桥接 + chroot 启动 dhcp6c，patch setsockopt(SO_REUSEPORT) 失败分支绕过旧内核限制
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: qemu-system-mips-tap-chroot-soreuseport-patch-dhcp6c
tags:
- firmware
- emulation
- qemu
- mips
- tap
- bridge
- chroot
- patching
- dhcpv6
- router
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:47:41+08:00'
  notes: 已对照原文核对：br0/tap0 建桥命令、qemu-system-mips -M malta 启动参数、mount proc/dev + chroot、空 dhcp6c.conf 手动启动、setsockopt(SO_REUSEPORT) 失败分支 <0→>=0 patch（010 Editor 改字节）与 netstat 546 监听均一致；dedup 与既有 qemu-system-mipsel-router-httpd 为 related（该卡用 netplan+'-net bridge,br=br0'、无 chroot/SO_REUSEPORT patch、目标为 httpd），非重复。注：SO_REUSEPORT 于 Linux 3.9 引入为卡片补充背景，原文未明写；真实设备复现需自行定位 patch 偏移，未在本机复跑
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-qemu-system-mips-tap-chroot-soreuseport-patch-dhcp6c/
draft: false
kb_aliases:
- qemu-system MIPS 跑 dhcp6c
- ER605 固件仿真
- SO_REUSEPORT patch
- brctl tunctl tap 固件模拟
- dhcp6c 启动失败 patch
---

## 一句话结论

仿真 TP-Link ER605 这类 MIPS 小端固件里的网络守护进程时，用 `brctl`+`tunctl` 建 `br0`/`tap0` 给 `qemu-system-mips` Malta 虚拟机联网，挂载 proc/dev 后 `chroot` 进 `squashfs-root` 手动启动；若 `dhcp6c` 因 `setsockopt(SO_REUSEPORT)` 在旧 Malta 内核（3.2）上返回失败而退出，把该失败判断的分支条件反转（`<0` 改为 `>=0`，用十六进制编辑器改，IDA patch 不成功），即可让 `dhcp6c` 成功监听 `:::546` 并接收构造的 DHCPv6 报文。

## 原理

- **系统级仿真的必要性**：`dhcp6c` 需要配置文件、网络接口与 socket 选项，且要接收 UDP 546 的 DHCPv6 报文；user-mode 仿真虽可跑单进程，但网络与 socket 行为更接近真机的是 `qemu-system` + 桥接网络。
- **网络链路**：宿主机把物理网卡 `ens32` 加入 `br0`，用 `tunctl` 创建 `tap0` 也加入 `br0`；QEMU 以 `-net nic -net tap,ifname=tap0,script=no,downscript=no` 把虚拟机网卡挂到 tap 上，虚拟机内 `eth0` 配 `192.168.10.200/24` 后即可与宿主机互发以太网帧。
- **rootfs 运行**：`binwalk` 解包得到 `squashfs-root` 后，`mount -t proc /proc ./squashfs-root/proc`、`mount -o bind /dev ./squashfs-root/dev`，再 `chroot ./squashfs-root/ sh`，使固件的 `/etc`、`/lib`、`/usr/sbin/dhcp6c` 都在预期路径。
- **启动方式**：该固件 rootfs 没有 `/etc/init.d/rcS`，自带 `/etc/init.d/dhcp6c` 也启动失败，因此手工创建空的 `/tmp/dhcp6c/dhcp6c.conf` 后直接执行 `/usr/sbin/dhcp6c -c /tmp/dhcp6c/dhcp6c.conf -Df eth0`。
- **SO_REUSEPORT 失败根因**：`dhcp6c` 启动时调用 `setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, ...)`，而 Malta 使用的 Linux 3.2 内核尚未支持 SO_REUSEPORT（该选项 3.9 才引入），调用返回失败，程序把失败当成致命错误退出；把失败判断的分支条件反转后，失败不再阻止后续初始化，`dhcp6c` 正常挂到 `:::546`。
- **为什么用十六进制编辑器**：IDA 的 patch 功能对这段 MIPS 代码应用失败，原文改用 010 Editor 直接改文件字节；关键是反转条件分支，而不是改调用本身。

## 触发条件

- 已从固件解包出可写的 `squashfs-root`，且宿主机有 root 权限（建桥、tunctl、chroot、改文件）。
- 有匹配架构的 `qemu-system-mips` 与 Malta 内核/`debian_wheezy_mips` qcow2 镜像。
- 目标守护进程在模拟内核上因缺少 socket 选项/网络能力而启动失败，且该失败可被定位到条件分支。
- 需要发送/接收二层或 UDP 报文验证服务已启动。

## 利用步骤

1. 解包固件，确认 `squashfs-root` 与 `/usr/sbin/dhcp6c` 的架构（MIPS 小端）。
2. 宿主机建桥与 tap：
   `ifconfig ens32 down`、`brctl addbr br0`、`brctl addif br0 ens32`、`ifconfig br0 0.0.0.0 promisc up`、`ifconfig ens32 0.0.0.0 promisc up`、`dhclient br0`、`tunctl -t tap0`、`brctl addif br0 tap0`、`ifconfig tap0 0.0.0.0 promisc up`。
3. 启动 QEMU：
   `qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1" -net nic,macaddr=00:16:3e:00:00:01 -net tap,ifname=tap0,script=no,downscript=no -nographic`。
4. 虚拟机内 `ifconfig eth0 192.168.10.200/24 up`，挂载 proc/dev 并 `chroot` 进 `squashfs-root`。
5. 直接启动 `dhcp6c` 观察失败；用 IDA/GDB 定位 `setsockopt(SO_REUSEPORT)` 调用后的失败分支，把条件由 `<0` 改为 `>=0`（IDA patch 失败时用 010 Editor 改字节）。
6. 重新执行 `/usr/sbin/dhcp6c -c /tmp/dhcp6c/dhcp6c.conf -Df eth0`，`netstat -unap` 确认监听 `:::546`，即可向 546 发送 DHCPv6 报文做漏洞复现。

## PoC

```bash
# 宿主机建桥 + tap
sudo ifconfig ens32 down
sudo brctl addbr br0 && sudo brctl addif br0 ens32
sudo ifconfig br0 0.0.0.0 promisc up
sudo ifconfig ens32 0.0.0.0 promisc up
sudo dhclient br0
sudo tunctl -t tap0 && sudo brctl addif br0 tap0
sudo ifconfig tap0 0.0.0.0 promisc up

# 启动 QEMU Malta
sudo qemu-system-mips -M malta \
  -kernel vmlinux-3.2.0-4-4kc-malta \
  -hda debian_wheezy_mips_standard.qcow2 \
  -append "root=/dev/sda1" \
  -net nic,macaddr=00:16:3e:00:00:01 \
  -net tap,ifname=tap0,script=no,downscript=no -nographic

# 虚拟机内
ifconfig eth0 192.168.10.200/24 up
mount -t proc /proc ./squashfs-root/proc
mount -o bind /dev ./squashfs-root/dev
chroot ./squashfs-root/ sh
# patch setsockopt 失败分支后：
/usr/sbin/dhcp6c -c /tmp/dhcp6c/dhcp6c.conf -Df eth0
netstat -unap | grep 546
```

## 变体与关联

- **变体**：用 `-net bridge,br=br0` 或 user-mode 端口转发替代 `tunctl`+tap；单纯分析单个二进制时也可先试 `qemu-user`。
- **变体**：若守护进程因其他 socket 选项（如 `SO_BINDTODEVICE`、IPv6 选项）失败，同样可以用“定位失败分支并反转条件”的方式绕过。
- **关联**：通用 MIPS 系统级仿真流程见 [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]；另一类启动死循环 patch 见 [[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]；本环境复现的漏洞见 [[code-analysis-cve-2024-1179-tplink-er605-dhcpv6-aftr-name-stack-overflow]]。
- **边界**：patch 后只是让程序在仿真环境继续运行，真实设备内核支持 SO_REUSEPORT 时不需要该修改；原文字节级 patch 位置与完整 dhcp6c.conf 未公开，需按各自固件重新定位。

## 检测与防御

- **研究侧**：仿真环境放进隔离网络/虚拟机，tap/bridge 不要桥到生产网；修改固件二进制前备份原文件并记录 patch 偏移。
- **防守侧**：固件发布前避免依赖宿主内核不支持的 socket 选项作为硬失败条件；对守护进程的启动失败做可观测日志，便于发现异常配置。
- **检测信号**：设备或仿真环境中 `dhcp6c` 异常退出、`setsockopt(SO_REUSEPORT)` 报错、546 端口未监听；固件二进制中相关条件分支被改动。
