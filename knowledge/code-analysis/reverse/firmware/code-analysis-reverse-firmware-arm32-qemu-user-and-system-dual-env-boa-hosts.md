---
id: code-analysis-reverse-firmware-arm32-qemu-user-and-system-dual-env-boa-hosts
title: ARM32 固件双环境仿真：qemu-arm-static chroot 跑 boa httpd（补 boa.conf/hosts 修 gethostbyname）+ qemu-system-arm versatile 桥接网络
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: arm32-qemu-user-system-dual-environment-boa
aliases:
- qemu-arm-static chroot
- qemu-system-arm versatile
- ARM 固件仿真
- boa.conf 修复
- gethostbyname Success
- tap0 桥接网络
- Debian armel 固件环境
- Vivotek CC8160 仿真
tags:
- firmware
- iot
- qemu
- arm
- emulation
- boa
- tap
- chroot
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:46:06+08:00'
  notes: 已对照原文 content.md 与 24 张图片核对：img04/05/09/10 的 qemu-arm-static chroot + boa.conf（/etc/conf.d/boa/boa.conf，缺失即 Could not open boa.conf）+ /etc/hosts（192.168.100.2 DESKTOP-6B71JP4 localhost 修 gethostbyname）；img11/13/14/15/16 的 qemu-system-arm versatilepb + tap0 192.168.100.254/24 + 虚拟机 192.168.100.2 + gdbserver 1234 均与卡一致。该卡为 ARM32 固件 user-mode+system-mode 双环境仿真工作流，技术原子独立、粒度合格；dedup 仅 related（arm32 chroot patch br0、MIPS LD_PRELOAD、MIPS malta），触发/修复点不同，并列保留。未验证点：未重跑仿真环境。
---

## 一句话结论

对 ARM32 小端固件可以先用 `qemu-arm-static` + `chroot` 直接跑单个 boa httpd（从 defconfig 包补 `/etc/conf.d/boa/boa.conf`，并把本机名写入 `/etc/hosts` 让 `gethostbyname` 成功），再搭 `qemu-system-arm -M versatilepb` + Debian armel 虚拟机、用 `tap0` + NAT 桥接网络、`scp` 传入 rootfs 后在虚拟机内 `chroot` 启动 httpd，即可获得更接近真实设备的可调试漏洞复现环境。

## 原理

- **user-mode 仿真**：`qemu-arm-static` 把 ARM 指令翻译到宿主 CPU，`chroot .` 让解包出的 `squashfs-root` 成为 `/`，从而加载固件自带的 `/lib/ld-uClibc.so.0` 等库；适合只跑 httpd/CGI 的快速验证。局限性是共享宿主内核，部分 `/proc`、网络接口、NVRAM/设备节点行为与真机不同。
- **boa.conf 缺失**：httpd 启动时 `fopen("/etc/conf.d/boa/boa.conf","r")`，失败即打印 `Could not open boa.conf for reading.` 并 `exit(1)`。固件主 rootfs 可能只带运行配置的一半，`defconfig` 包（如 `defconfig/CC8160.tar.bz2`）里才有完整 `etc`；把它复制到 rootfs 或合并 etc 即可。
- **gethostbyname 失败**：httpd 初始化会用 `gethostname` 取本机名再 `gethostbyname` 解析；若 `/etc/hosts` 没有本机名或 IP 不一致，会打印 `gethostbyname:: Success`（errno 被覆盖的误导性输出）并继续失败。把 `127.0.0.1 <hostname> localhost` 或 `<qemu_ip> <hostname> localhost` 写入 hosts，保证解析成功。
- **system-mode 仿真**：`qemu-system-arm -M versatilepb` 模拟 ARM 开发板，加载 Debian armel 的 `vmlinuz-3.2.0-4-versatile` + `initrd.img` + qcow2 rootfs；虚拟机内是完整 Linux，可运行固件 rootfs 的 init 脚本、网络服务与 gdbserver，适合复现依赖内核/网络行为的漏洞。
- **网络**：宿主机创建 `tap0`（`ip tuntap add mode tap name tap0`），开启 `ip_forward` 并加 `MASQUERADE`/FORWARD 规则，给 tap0 配 `192.168.100.254/24`；QEMU `-net nic -net tap,ifname=tap0` 接入；虚拟机内 `ifconfig eth0 192.168.100.2/24` + 默认路由到 254，即可从宿主机访问 192.168.100.2 的服务，也可 `scp` 传 rootfs。
- **为什么要双环境**：user-mode 启动快、适合先验证服务能跑；system-mode 提供完整内核/网络/进程环境，适合调试栈溢出、gdbserver attach、ASLR/网络交互等真机行为。两者互补，可先用 user-mode 排配置，再用 system-mode 复现漏洞。

## 触发条件

- 固件已用 binwalk 解包出 ARM32 小端 rootfs（`file bin/busybox` 显示 ELF 32-bit LSB ARM EABI5、uClibc）。
- 宿主机有 root 权限、qemu-user/qemu-system、binwalk、bridge/tap 工具；有匹配的 Debian armel 内核/镜像（versatilepb）。
- 固件 httpd 依赖 `boa.conf`、`/etc/hosts` 或网络接口；主 rootfs 配置不全时能从 defconfig/其他分区补齐。
- 仅用于授权固件分析与漏洞复现；网络需隔离，避免把仿真设备暴露到公网。

## 利用步骤

1. `binwalk -Me CC8160-VVTK-0113b.flash.pkg`，进入 `squashfs-root`；`file bin/busybox` 确认 ARM32 小端/uClibc。
2. 复制 `qemu-arm-static` 到 rootfs 根目录，`sudo chroot . ./qemu-arm-static ./usr/sbin/httpd`；若报 `Could not open boa.conf`，从 defconfig 包（如 `defconfig/CC8160.tar.bz2` 解出的 `etc/conf.d/boa/boa.conf`）复制/合并到 rootfs 的 `/etc/conf.d/boa/`。
3. 若报 `gethostbyname` 相关错误，把 `受控IP 主机名 localhost` 写入 rootfs `/etc/hosts`（文章用 `192.168.100.2 DESKTOP-6B71JP4 localhost`），再次启动直到 httpd 监听 80；浏览器访问确认页面。
4. 系统级环境：宿主机 `ip tuntap add mode tap name tap0; ip link set tap0 up; sysctl -w net.ipv4.ip_forward=1`，配置 iptables NAT/FORWARD，`ifconfig tap0 192.168.100.254/24`。
5. 启动 `qemu-system-arm -M versatilepb -kernel vmlinuz-3.2.0-4-versatile -initrd initrd.img-3.2.0-4-versatile -hda debian_wheezy_armel_standard.qcow2 -append "root=/dev/sda1" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic`。
6. 虚拟机内 `ifconfig eth0 192.168.100.2/24; route add default gw 192.168.100.254`；宿主机 `scp -r squashfs-root root@192.168.100.2:/root`。
7. 虚拟机内 `chmod -R 777 squashfs-root; chroot ./squashfs-root/ /bin/sh; ./usr/sbin/httpd`，宿主机访问 `http://192.168.100.2/` 验证；之后可 gdbserver attach 调试/复现漏洞。

## PoC

```bash
# 1) user-mode 快速验证
binwalk -Me CC8160-VVTK-0113b.flash.pkg
cd _CC8160-VVTK-0113b.flash.pkg.extracted/_31.extracted/_rootfs.img.extracted/squashfs-root
cp /usr/bin/qemu-arm-static .
sudo chroot . ./qemu-arm-static ./usr/sbin/httpd
# 若 boa.conf 缺失：从 defconfig 包复制 etc/conf.d/boa/boa.conf
# 若 gethostbyname 失败：echo "192.168.100.2 <hostname> localhost" > etc/hosts

# 2) system-mode 网络
sudo ip tuntap add mode tap name tap0
sudo ip link set tap0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE   # eth0 改成宿主上网卡
sudo iptables -I FORWARD 1 -i tap0 -j ACCEPT
sudo ifconfig tap0 192.168.100.254 netmask 255.255.255.0

# 3) 启动 Debian armel 虚拟机
sudo qemu-system-arm -M versatilepb \
  -kernel vmlinuz-3.2.0-4-versatile \
  -initrd initrd.img-3.2.0-4-versatile \
  -hda debian_wheezy_armel_standard.qcow2 \
  -append "root=/dev/sda1" \
  -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic

# 4) 虚拟机内
ifconfig eth0 192.168.100.2 netmask 255.255.255.0
route add default gw 192.168.100.254
# 宿主机: scp -r squashfs-root root@192.168.100.2:/root
chmod -R 777 squashfs-root
chroot ./squashfs-root/ /bin/sh
./usr/sbin/httpd
```

## 变体与关联

- 变体：user-mode 下 httpd 若因 NVRAM/接口检查卡在 sleep 循环，需要 patch 条件跳转或伪造接口（见关联卡）；system-mode 更适合这类依赖。
- 变体：无 Debian armel 镜像时可用 Buildroot/BusyBox 自建 rootfs，或把固件 rootfs 做成 initramfs 直接启动；网络也可用 `-net user` 端口转发替代 tap 桥接（但部分 CGI 需要真实源 IP/接口时不够）。
- 变体：boa.conf 可能来自其他分区/压缩包，`find / | grep boa.conf` 在解包目录里找；hosts 也可用 `-append` 或启动脚本注入。
- 关联：[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]（ARM32 qemu-user chroot + patch 网络等待循环 + br0 绑定）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（MIPS malta 系统级仿真 + 桥接网络 + httpd）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（SquashFS 服务仿真）、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（user-mode + LD_PRELOAD + gdb）。

## 检测与防御

- 检测：仿真环境本身是分析工具；防御方关注设备上未签名/异常 httpd、boa.conf 被替换、hosts 被改写，以及暴露到公网的调试端口（gdbserver/1234、tap 网段）。
- 防御：分析时隔离网络（host-only/无外网）、使用快照、避免把仿真设备桥接到生产网；设备侧限制 upgrade.cgi 等管理接口的访问来源并启用认证。
- 说明：本文是固件仿真环境搭建技术，severity 记为 info；仅用于授权固件分析。
