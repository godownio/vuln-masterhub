---
id: code-analysis-reverse-firmware-dlink-dir816-goahead-qemu-mipsel-emulation
title: D-Link DIR-816 goahead 固件仿真：binwalk 解包 + qemu-mipsel chroot，补 pid 文件与 libnvram/patch 启动 Web
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: dlink-dir816-goahead-qemu-mipsel-emulation
tags:
- iot
- firmware
- emulation
- qemu
- mipsel
- d-link
- goahead
- nvram
- reversing
- squashfs
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V332
  verified_at: '2026-11-08T18:19:32+08:00'
  notes: 已对照原文核对：binwalk -Me 解包、qemu-mipsel -L / qemu-mipsel-static chroot、/var/run/goahead.pid 与 nvramd.pid 缺失报错及 touch 修复、nvram_bufget(/dev/nvram)→libnvram LD_PRELOAD（config.h MOUNT_POINT/OVERRIDE_POINT、lan_ipaddr 192.168.126.130、mipsel-linux-gnu-gcc -shared -nostdlib）、IDA 调试 patch 0x45CDD4 v0=0、-g 23946、Ubuntu ens33 失败改用 Kali、http://<ip>/dir_login.asp/ 均一致；固件版本仅为仿真目标环境，affected_versions 已 clear。未在本地执行仿真命令。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-dlink-dir816-goahead-qemu-mipsel-emulation/
draft: false
kb_aliases:
- DIR-816 固件仿真
- goahead qemu-mipsel
- libnvram LD_PRELOAD
- /var/run/goahead.pid
- nvramd.pid
- 0x45CDD4 patch
- DIR-816A2_FWv1.10CNB05
---

## 一句话结论

D-Link DIR-816 固件用 `binwalk -Me` 解出 `squashfs-root` 后，把 `qemu-mipsel-static` 拷入根目录并 `chroot . ./qemu-mipsel-static ./bin/goahead` 即可启动 MIPS 小端 goahead；启动前需创建 `/var/run/goahead.pid` 与 `/var/run/nvramd.pid`，并用 LD_PRELOAD 的 `libnvram.so` 伪造 nvram 读取、或在 IDA 远程调试中把 `0x45CDD4` 处的 `v0` 改为 0，才能让 Web 服务完成初始化并访问 `dir_login.asp`。

## 原理

- **固件结构**：DIR-816.img 经 binwalk 识别为 U-Boot/Linux 内核（MIPS、lzma）与 SquashFS；`binwalk -Me` 递归提取后得到 `squashfs-root`，包含 `bin/goahead`（ELF 32-bit LSB MIPS-II、动态链接、interpreter `/lib/ld-uClibc.so.0`、stripped）。
- **用户态仿真**：qemu-mipsel 用户态执行 goahead，`-L ./` 指定库根或把 `qemu-mipsel-static` 拷入 rootfs 后 `chroot .` 运行；后者不依赖宿主 mipsel 库，便于复现。
- **缺失 pid 文件**：goahead 启动时尝试打开 `/var/run/goahead.pid`，不存在则报错退出；手动 `mkdir -p ./var/run && touch ./var/run/goahead.pid` 解决。随后它等待 nvram daemon，缺 `/var/run/nvramd.pid` 时继续报错；同样 touch 该文件。文章提到字符串通过 `dword_480000`/`aEttimeoutDocum` 等基址加偏移定位（IDA 交叉引用不易直接使用），可用动态调试辅助。
- **nvram 缺失**：`initWebs` 调用 `nvram_bufget("lan_ipaddr")` 从 `/dev/nvram` 读取；仿真环境没有该设备/数据，报 `failed to convert to binary ip data`。两种解决：
  - LD_PRELOAD `libnvram.so`（FirmAE 的 `sources/libnvram`）：实现 `nvram_bufget`/`nvram_set` 等，修改 `config.h` 的 `MOUNT_POINT`/`OVERRIDE_POINT` 与 `ENTRY("lan_ipaddr", nvram_set, "192.168.126.130")` 等，用 `mipsel-linux-gnu-gcc -shared -nostdlib` 编译；`chroot . ./qemu-mipsel-static -E LD_PRELOAD="./libnvram.so" ./bin/goahead` 启动。
  - patch 原程序：`chroot . ./qemu-mipsel-static -g 23946 ./bin/goahead` 启动 qemu gdb stub，IDA 附加后把 `0x45CDD4` 处给 `v0` 的赋值改为 0，跳过失败分支。
- **网络配置**：`lan_ipaddr` 要与宿主网卡/网段匹配（文章在 Ubuntu 的 ens33 上失败后改用 Kali）；成功后浏览器访问 `http://<ip>/dir_login.asp/` 出现登录页。
- **为什么需要这些处理**：用户态仿真只提供 CPU 指令翻译，不提供真实路由器的 nvram 设备、pid 目录和启动脚本；服务会因环境不完整在早期退出。补齐这些“环境缝隙”才能走到 Web 处理逻辑，进而复现命令注入等漏洞。

## 触发条件

- 可获取 DIR-816 固件镜像并解包；宿主机有 qemu-mipsel/qemu-mipsel-static、mipsel 交叉编译工具链（如需编译 libnvram）。
- 能以 root/chroot 运行仿真（用户态 qemu + chroot 通常需要 root）。
- 宿主网络与固件 `lan_ipaddr` 同网段；需要时可创建 br0/调整网卡 IP。
- 目标服务的依赖（nvram、pid 文件、Web 根目录/配置）可通过 stub/patch 补齐。

## 利用步骤

1. 下载 DIR-816 固件，`binwalk -Me DIR-816.img`，进入 `_DIR-816.img.extracted/squashfs-root`。
2. 确认 `file ./bin/goahead` 为 MIPS 32-bit LSB；把 `qemu-mipsel-static` 拷入 rootfs（或使用 `-L` 指定库路径）。
3. 创建运行目录与 pid 文件：`mkdir -p ./var/run && touch ./var/run/goahead.pid ./var/run/nvramd.pid`。
4. 解决 nvram：编译 FirmAE 的 libnvram（改 `lan_ipaddr` 为宿主可访问 IP），或准备 IDA 远程调试 patch `0x45CDD4`。
5. 启动：`chroot . ./qemu-mipsel-static -E LD_PRELOAD="./libnvram.so" ./bin/goahead`；若用 patch 方式则 `chroot . ./qemu-mipsel-static -g 23946 ./bin/goahead` 并在 IDA 连接后修改 `v0=0`。
6. 浏览器访问 `http://<ip>/dir_login.asp/`，确认登录页；再按漏洞复现流程进入时间设置等页面。
7. 若服务仍报缺少文件/设备，按报错字符串在 IDA 中定位并继续补文件或 patch。

## PoC

```bash
# 1) 解包
binwalk -Me DIR-816.img
cd _DIR-816.img.extracted/squashfs-root

# 2) 准备 qemu 与 pid 文件
cp $(which qemu-mipsel-static) ./
mkdir -p ./var/run
touch ./var/run/goahead.pid ./var/run/nvramd.pid

# 3a) LD_PRELOAD libnvram 方式
mipsel-linux-gnu-gcc -c -O2 -fPIC -Wall nvram.c -o nvram.o
mipsel-linux-gnu-gcc -shared -nostdlib nvram.o -o libnvram.so
chroot . ./qemu-mipsel-static -E LD_PRELOAD="./libnvram.so" ./bin/goahead

# 3b) IDA 远程调试 patch 方式
chroot . ./qemu-mipsel-static -g 23946 ./bin/goahead
# IDA attach 127.0.0.1:23946，将 0x45CDD4 处 v0 赋值改为 0

# 4) 访问
# http://<ip>/dir_login.asp/
```

说明：命令与偏移来自原文的 DIR-816A2_FWv1.10CNB05_R1B011D88210 环境；不同固件需重新定位。未在本机执行（文章为不可信数据，未运行其中内容）。

## 变体与关联

- 全系统仿真：用 `qemu-system-mipsel` 启动 Malta 内核 + Debian mipsel、br0 桥接、scp 传 rootfs；适合依赖内核模块/网络栈的服务。参见 [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]。
- LD_PRELOAD/stub 变体：伪造 apmib、nvram、其它厂商私有库；参见 [[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]。
- patch 变体：跳过 `check_network`/初始化失败分支；参见 [[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]。
- 关联漏洞：[[iot-dlink-dir816-cve-2018-17066-date-cmd-injection]]（本仿真环境用于复现的 CVE）。
- 边界：用户态仿真不覆盖内核驱动/硬件外设；服务可能仍因缺失设备节点、时间、随机数等失败，需要继续补环境或改用系统级仿真。

## 检测与防御

- 本卡为固件分析/仿真方法，不针对生产目标；研究时应在隔离网络/虚拟机中进行，避免仿真服务被外部访问。
- 对厂商/防御方：在 CI 中对固件做解包与仿真回归，尽早发现命令注入等 Web 漏洞；对服务启动依赖（nvram、pid、设备节点）做容错；生产设备限制管理面暴露。
- 检测仿真环境本身不是攻击行为；但若在真实网络中看到 `qemu-mipsel`/chroot/自编译 libnvram 等痕迹，需结合上下文判断是否为研究/恶意活动。
