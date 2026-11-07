---
id: code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0
title: ARM32 路由器固件 qemu-user chroot 模拟：patch 网络等待死循环 + br0 绑定 httpd
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: arm32-qemu-user-chroot-patch-br0
aliases:
- qemu-arm-static chroot
- 固件模拟
- BGT patch
- br0 httpd
- Tenda AC15
tags:
- firmware
- iot
- qemu
- arm
- emulation
- ida
- patching
- router
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:26+08:00'
  notes: 已对照原文与图03-42核对：binwalk uImage/TRX→squashfs-root、file 显示 ARM 32-bit LSB、chroot+qemu-arm-static 卡在 Welcome；图13/17 BGT loc_2E528 在 .text:2E518、N=0/Z=1 不跳转，keypatch 改 B（02 00 00 EA）；图41 get_eth_name(0)=br0，创建 br0 192.168.0.1 后 httpd 监听成功。未在本机复跑模拟；patch 偏移/编码已按原文截图核对。
---

## 一句话结论

对 ARM 32-bit 小端路由器固件，`binwalk -Me` 解包出 `squashfs-root` 后，把 `qemu-arm-static` 拷入根目录并用 `chroot . ./qemu-arm-static ./bin/httpd` 运行；httpd 常因 `check_network()` 返回失败在 `sleep(1)` 循环中卡住，IDA 远程 GDB（`qemu -g 1234`）定位后把 `BGT loc_2E528` patch 成 `B` 跳过等待；httpd 随后绑定 `g_lan_ip`（来自 `getLanIfName()` → `get_eth_name(0)` = `br0`），在宿主机创建 `br0` 并配 `192.168.0.1/24`，再把 `webroot_ro` 复制到 `webroot`，即可访问 Web。

## 原理

- **固件结构**：binwalk 识别 `uImage`（LZMA、ARM、load `0x80000000`、entry `0xC0008000`）和 TRX 容器（2 个分区），解包后得到 `partition_0/1` 与 `squashfs-root`；`file bin/httpd` 显示 ELF 32-bit LSB ARM EABI5、动态链接 uClibc。
- **qemu-user 模拟**：`qemu-arm-static` 在宿主机上解释 ARM 指令，`chroot .` 把解包根目录作为 `/`，从而找到 `/lib/ld-uClibc.so.0` 与依赖库；不需要内核/设备树，适合单个 httpd 服务。
- **启动死循环**：`httpd` 启动后打印 `Yes: ****** WeLoveLinux****** Welcome to ...`，然后进入 `loc_2E504`：`check_network()` 返回值 <=0 时走 `else`，`sleep(1)` 后跳回 `loc_2E504`。IDA 中 `.text:0002E518 BGT loc_2E528`（仅当 `N=0,Z=0` 才跳转）；由于寄存器 `N=0,Z=1`，分支不成立。patch 为 `B loc_2E528`（ARM 编码 `EA 00 00 02`）即可无条件跳过等待。
- **监听地址**：`v8 = inet_ntoa(s.sa_data[2])`、`printf("httpd listen ip = %s port = %d\n", v8, ntohs(s.sa_data))`；`s.sa_data[2]` 来自 `inet_addr(a1)`，而 `a1 = g_lan_ip`。`g_lan_ip` 未初始化，赋值路径为 `LanIfName = getLanIfName(); getIfIp(LanIfName, v18)`，成功则 `vos_strcpy(g_lan_ip, v18)`，失败则 `GetValue("lan.ip", s); strcpy(g_lan_ip, s)`。
- **为什么是 br0**：`getLanIfName()` 只是 `get_eth_name(0)`；在 `libChipApi.so` 中 `get_eth_name(0)` 返回字符串 `"br0"`（1=`br1`、6=`vlan1` 等）。因此宿主机创建 `br0` 并配置 IP，qemu 内的 `getIfIp("br0")` 就能取到该地址，httpd 绑定成功。
- **Web 根**：`rcS` 启动时执行 `cp -rf /webroot_ro/* /webroot`；手工模拟时需要自己复制，否则页面 404。

## 触发条件

- 固件为 ARM 32-bit 小端（或可用对应 qemu-<arch>-static 模拟），已解包出可写根文件系统。
- 宿主机有 root 权限（创建 bridge、配置 IP、chroot）。
- httpd 启动时依赖网络接口/NVRAM；`check_network` 失败会进入 sleep 循环。
- 有 IDA/GDB 或可静态定位 patch 点；需要读写并回写二进制。

## 利用步骤

1. `binwalk -Me firmware.bin` 解包，进入 `squashfs-root`，`file bin/httpd` 确认架构。
2. `cp /usr/bin/qemu-arm-static .`，`chroot . ./qemu-arm-static ./bin/httpd` 观察输出；若卡在 `Welcome to ...` 后，说明进入网络等待循环。
3. `chroot . ./qemu-arm-static -g 1234 ./bin/httpd` 启动 gdbstub；IDA 选择 Remote GDB debugger，host `127.0.0.1`、port `1234`，在 `Welcome` 字符串上方或 `check_network` 调用处下断。
4. 单步确认 `BGT loc_2E528` 未跳转、走 `sleep(1)`；用 keypatch 把 `BGT` 改成 `B`（或直接 NOP/改条件），`Apply patches to input file` 保存。
5. 宿主机创建 `br0` 并配置 IP：
   `sudo ip link add name br0 type bridge`、`sudo ip link set br0 up`、`sudo ip addr add 192.168.0.1/24 dev br0`。
6. `cp -rf webroot_ro/* webroot/`，再次 `chroot . ./qemu-arm-static ./bin/httpd`；日志应显示 `httpd listen ip = 192.168.0.1 port = 80`。
7. 浏览器访问 `http://192.168.0.1/`，确认 Web 服务可用，再进入漏洞复现。

## PoC

```bash
# 1) 解包
binwalk -Me ./US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
cd _US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root

# 2) 确认架构并模拟
file ./bin/httpd
cp /usr/bin/qemu-arm-static ./
chroot . ./qemu-arm-static ./bin/httpd

# 3) 调试（另开 IDA Remote GDB 127.0.0.1:1234）
chroot . ./qemu-arm-static -g 1234 ./bin/httpd

# 4) keypatch: .text:0002E518  BGT loc_2E528  ->  B loc_2E528
#    ARM 编码：02 00 00 CA -> 02 00 00 EA

# 5) 创建 br0 并配置 IP
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up
sudo ip addr add 192.168.0.1/24 dev br0

# 6) 复制 Web 根并启动
cp -rf webroot_ro/* webroot/
chroot . ./qemu-arm-static ./bin/httpd
```

说明：qemu-user 下 `/proc` 相关报错（core_pattern、tcp_timestamps 等）通常可忽略；若 `getIfIp` 失败会回退到 NVRAM `lan.ip`，也可通过配置该值改变绑定地址。

## 变体与关联

- **qemu-system 系统级仿真**：需要内核/设备树/网桥，适合依赖内核模块的固件；见 [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]。
- **LD_PRELOAD 伪造依赖**：qemu-user 缺少厂商 NVRAM/APMIB 库时，用预加载 stub 返回配置；见 [[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]。
- **MIPS/AArch64 固件**：换 `qemu-mipsel-static`/`qemu-aarch64-static`，patch 点同样先定位启动等待循环。
- **启动脚本**：先读 `etc_ro/init.d/rcS`，确认需要复制哪些目录、启动哪些服务，再决定模拟单个二进制还是整机。

## 检测与防御

- 固件模拟是分析手段；防守方应减少调试口/未初始化全局变量依赖，增加启动完整性校验与反调试。
- 设备固件中避免用未初始化 `g_lan_ip` 直接绑定；网络不可用时应有超时/降级策略，而不是死循环。
- 研究侧：保留解包原始镜像与 patch 备份，记录 patch 偏移/编码，便于复现与他人复核。
