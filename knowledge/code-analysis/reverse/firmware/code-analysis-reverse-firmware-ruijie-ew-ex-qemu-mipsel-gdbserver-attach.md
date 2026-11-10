---
id: code-analysis-reverse-firmware-ruijie-ew-ex-qemu-mipsel-gdbserver-attach
title: 锐捷 EW 固件 QEMU mipsel 系统级仿真跑起 unifyframe-sgi：bind proc/dev + chroot 启 ubusd/lighttpd，再 gdbserver --attach 远程跟 Lua→libuflua→ufm_popen 链路
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: ruijie-ew-qemu-mipsel-chroot-gdbserver-attach
aliases:
- 锐捷 EW 固件仿真
- unifyframe-sgi 调试
- qemu-system-mipsel br0 tap0
- chroot 固件 rootfs
- gdbserver attach 固件进程
tags:
- reverse
- firmware
- emulation
- qemu
- mips
- gdbserver
- ruijie
- router
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:36+08:00'
  notes: 已对照原文核对：qemu-system-mipsel -cpu 74Kf -M malta 内核/镜像/append 与 -net nic -net tap,ifname=tap0 启动参数、brctl addif br0 eth0/stp off/setfd/sethello/ifconfig promisc/dhclient/tunctl -t tap0/brctl addif br0 tap0 桥接命令、scp 旧算法选项、chmod -R 777 与 mount --bind proc dev 后 chroot、init/lighttpd pid 先 touch/ubusd/mkdir coredump 与 rg_device/拷 rg_device.json/unifyframe-sgi start 的启动顺序、gdbserver --attach 与 gdb-multiarch 的 set architecture 与 endian little 与 follow-fork-mode parent，均与正文一致；卡内对「FAT 仿真失败改 system-mode」「缺运行时文件导致服务不响应」「桥接会掉需重配」的说明也来自正文。已按「只是取证环境版本」清空该卡的 affected_versions（原文只给出固件系列名，未给受影响版本区间）。本次核对未读取图片，qemu 启动成功与 gdbserver 附加截图（img/04-05）未核实；未启动虚拟机、未执行命令。
---

## 一句话结论

把锐捷 EW 固件（先按尾部 `0x80` 反推单字节异或解密）用 `qemu-system-mipsel -M malta` 启动 Debian mipsel 虚拟机、配好 br0/tap0 与静态 IP 后，把 rootfs 传进去 `chmod -R 777` 并 `mount --bind /proc /dev` 再 `chroot`，手工按顺序拉起 `/sbin/init`、`lighttpd`（先 `touch /var/run/lighttpd.pid`）、`ubusd`、`unifyframe-sgi`（先建 `/tmp/coredump`、`/tmp/rg_device` 并把 `rg_device.json` 拷进去），Web 与后端就完整跑起来；再把 `gdbserver --attach` 挂到 `unifyframe-sgi.elf`，宿主机用 `gdb-multiarch` 连 `target remote`，即可顺着 `uf_socket_msg_read → parse_content → parse_obj2_cmd → uf_cmd_call → ufm_handle → ufm_popen` 动态确认命令注入点。

## 原理

- **为什么用 system-mode 而不是 FAT/qemu-user**：这类固件的 Web 前端是 lua（luci）、后端是多个通过 unix socket/信号量协作的进程（`unifyframe-sgi` 依赖 `ubusd`、`lighttpd`、`/tmp/rg_device/rg_device.json` 等运行时文件），只跑单个二进制无法复现跨进程调用链；system-mode 提供完整 init 环境。
- **chroot 前必须 bind 伪文件系统**：固件 rootfs 里的 `/proc`、`/dev` 若不在宿主机挂载，`/sbin/init` 与依赖它们的守护进程会失败；`mount --bind /proc proc`、`mount --bind /dev dev` 是标准做法。
- **手工补运行时痕迹**：`lighttpd` 启动脚本会检查 `/var/run/lighttpd.pid`，固件正常启动时由 init 创建，仿真里需 `touch`；`unifyframe-sgi` 需要 `/tmp/coredump`、`/tmp/rg_device/rg_device.json`（来自 `/sbin/hw/<型号>/`），缺一个就起不来——这是固件仿真最常见的「服务不响应」原因。
- **gdbserver 附加而非重跑**：`unifyframe-sgi.elf` 由 init 脚本拉起并 fork，直接 `qemu-mipsel -g` 不好接；`gdbserver 0.0.0.0:9999 --attach <pid>` 把调试器挂到已在跑的进程，宿主机 `gdb-multiarch` 设好 `architecture mips`/`endian little` 与 `follow-fork-mode parent` 后即可断点。
- **交叉架构要点**：目标是 MIPS little-endian，宿主机 gdb 必须先 `set architechture mips`、`set endian little`，否则反汇编与寄存器解读全错。
- **网络是关键易错点**：QEMU 用 `-net nic -net tap,ifname=tap0,script=no` 时，宿主机需先 `brctl addbr br0`+绑物理网卡+`tunctl -t tap0`+`brctl addif br0 tap0`，并给虚拟机 `ifconfig eth0 <ip> up`，否则仿真环境与宿主机互相不可达；桥接会因宿主机网络变化掉线，需重配。

## 触发条件

- 已取得目标固件并完成解密（`binwalk` 可正常解包出 `squashfs-root`）。
- 目标为 MIPS little-endian（QEMU `malta` 支持），且固件 rootfs 是 glibc/uClibc 均可运行的形态（Debian mipsel qcow2 提供内核与基础库）。
- 宿主机具备 `qemu-system-mipsel`、`gdb-multiarch`、`bridge-utils`、`uml-utilities`（`tunctl`）、`binwalk`。
- 固件启动依赖的运行时文件（pid 文件、json 配置、目录）可从 rootfs 内找到并补齐。

## 利用步骤

1. 解密并解包固件，得到 `squashfs-root`；确认架构为 MIPS LE。
2. 启动系统级虚拟机：`qemu-system-mipsel -cpu 74Kf -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_squeeze_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic`。
3. 宿主机配桥：建 `br0`、绑 `eth0`、`ifconfig ... promisc up`、`dhclient br0`、`tunctl -t tap0 -u root`、`brctl addif br0 tap0`，再给虚拟机 `ifconfig eth0 192.168.111.123 up`；用 `scp -o HostKeyAlgorithms=+ssh-rsa` 传 rootfs。
4. `cd squashfs && chmod -R 777 ./ && mount --bind /proc proc && mount --bind /dev dev && chroot . /bin/sh`。
5. 按依赖顺序拉起服务：`/sbin/init &` → `touch /var/run/lighttpd.pid` → `/etc/init.d/lighttpd start` → `/sbin/ubusd &` → `mkdir /tmp/coredump /tmp/rg_device` → `cp /sbin/hw/<型号>/rg_device.json /tmp/rg_device/` → `/etc/init.d/unifyframe-sgi start`。
6. 从宿主机验证 Web：`curl http://192.168.111.123/cgi-bin/luci/`，能拿到前端即仿真成功。
7. 传 `gdbserver` 进虚拟机，`gdbserver 0.0.0.0:9999 --attach $(pidof unifyframe-sgi.elf)`；宿主机 `gdb-multiarch unifyframe-sgi.elf` 后 `set architecture mips`、`set endian little`、`set follow-fork-mode parent`、`target remote 192.168.111.123:9999`。
8. 在 `uf_socket_msg_read`、`parse_obj2_cmd`、`uf_cmd_call`、`ufm_popen` 下断，发送 PoC 请求，观察 `data` 如何被拼进命令串。

## PoC

```bash
# 宿主机：桥接 + QEMU
sudo brctl addbr br0 && sudo brctl addif br0 eth0 && sudo ifconfig br0 0.0.0.0 promisc up
sudo ifconfig eth0 0.0.0.0 promisc up && sudo dhclient br0
sudo tunctl -t tap0 -u root && sudo brctl addif br0 tap0 && sudo ifconfig tap0 0.0.0.0 promisc up
sudo qemu-system-mipsel -cpu 74Kf -M malta \
  -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_squeeze_mipsel_standard.qcow2 \
  -append "root=/dev/sda1 console=tty0" \
  -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic
```

```bash
# 虚拟机内：chroot + 启动服务链
cd squashfs && chmod -R 777 ./
mount --bind /proc proc && mount --bind /dev dev
chroot . /bin/sh
ifconfig eth0 192.168.111.123 up
/sbin/init &
touch /var/run/lighttpd.pid && /etc/init.d/lighttpd start
/sbin/ubusd &
mkdir -p /tmp/coredump /tmp/rg_device
cp /sbin/hw/60010081/rg_device.json /tmp/rg_device/rg_device.json
/etc/init.d/unifyframe-sgi start
```

```bash
# 调试：附加到目标进程
gdbserver 0.0.0.0:9999 --attach $(pidof unifyframe-sgi.elf)
# 宿主机
gdb-multiarch unifyframe-sgi.elf
(gdb) set architecture mips
(gdb) set endian little
(gdb) set follow-fork-mode parent
(gdb) target remote 192.168.111.123:9999
```

## 变体与关联

- **FAT 仿真失败时**：固件依赖多进程/init 脚本时 FAT（firmware analysis toolkit）常起不来，退回手工 system-mode + chroot 更可控。
- **缺文件导致服务不响应**：先看 init 脚本里 `mkdir`/`touch`/`cp` 的动作，把缺失的运行时文件补齐，再重启对应服务；这是「仿真成功但接口 404」的典型原因。
- **其它架构**：ARM/MIPSEL 的等价做法是 `qemu-system-arm/-mipsel` + 对应内核镜像与 Debian 根文件系统；`qemu-user` 只适合单进程（见异构架构调试卡）。
- 关联：[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（同为 QEMU malta 系统级仿真，那条针对 DIR-815 的 httpd/cgibin，本卡针对锐捷多进程 unifyframe-sgi 与 gdbserver 附加）、[[code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch]]（qemu-user + gdb-multiarch 的架构/字节序设置）、[[iot-ruijie-eweb-api-auth-merge-jsonrpc-ufm-popen-cmd-injection]]（本仿真环境里验证的那条命令注入链）。

## 检测与防御

- 本题属授权研究/取证流程，无直接攻击面；对防守方的意义是：厂商固件一旦泄露即可被完整仿真，worse 的是默认口令（原文 qcow2 用 root/root）与 init 脚本补齐即可跑通，因此固件内不应硬编码任何密钥或可复用凭据。
- 加固：固件加密不要用可反推的单字节异或；Debug 接口/gdbserver 位不要留在发布固件；默认口令必须按设备唯一生成。
- 研究侧：把「桥接配置、bind 挂载、pid/配置补齐、gdbserver attach」写成可复用脚本，能大幅缩短固件复现时间。
