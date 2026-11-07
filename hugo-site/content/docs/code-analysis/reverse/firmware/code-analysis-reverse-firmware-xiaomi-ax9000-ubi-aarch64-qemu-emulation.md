---
id: code-analysis-reverse-firmware-xiaomi-ax9000-ubi-aarch64-qemu-emulation
title: 小米 AX9000（AArch64）UBI 固件解包、Lua 反编译与 QEMU 系统级仿真
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: xiaomi-ubi-squashfs-unluac-aarch64-qemu-procd-sysapihttpd-emulation
tags:
- firmware
- ubi
- squashfs
- lua
- luci
- decompilation
- qemu
- aarch64
- emulation
- xiaomi
- router
- iot
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:49:08+08:00'
  notes: 已对照原文与61张图片核对：binwalk UBI 0x2B4、ubireader_extract_images、unluac_miwifi 批量反编译、AArch64el QEMU 网络配置、procd/ubusd/sysapihttpd 启动顺序、/var/lock/procd_sysapihttpd.lock 与 /tmp/sysapihttpd/lock/sysapihttpd.lock.accept、/tmp/run/sysapihttpd.pid、/var/run/ubus.sock、flock 缺失、sysapihttpd sub_27570 0x278F4 CBZ→CBNZ、XQPreference.INITTED=1、admin 哈希 b3a4190199d9ee7fe73ef9a4942a69fece39a771 与图39一致。未在本机复跑仿真。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-xiaomi-ax9000-ubi-aarch64-qemu-emulation/
draft: false
kb_aliases:
- 小米 AX9000 固件仿真
- miwifi_ra70_firmware
- ubireader_extract_images
- unluac_miwifi
- sysapihttpd
- procd
- ubusd
- qemu-system-aarch64
- AArch64el
---

## 一句话结论

小米 AX9000 固件是 UBI 卷封装的 AArch64el 系统，需先用 `binwalk` + `ubireader_extract_images` 取出 ubifs、再解出 SquashFS rootfs；其中的 LuCI Lua 是编译后的字节码，要用 `unluac_miwifi` 反编译；在 Ubuntu 20.04 上用 QEMU 系统级虚拟机加载 rootfs 后，按 `procd → ubusd → sysapihttpd` 顺序启动服务，并补齐锁文件、`flock` 与 `/dev/nvram` 相关缺失，即可得到可访问管理页面、可复现漏洞的仿真环境。

## 原理

- **固件封装**：小米固件先被 `binwalk -Me` 识别为 UBI erase count header，递归提取得到 `.ubi` 卷；`ubireader_extract_images` 把 UBI 镜像拆成多个 `.ubifs`，其中 `*-ubi_rootfs.ubifs` 再经 `binwalk -Me` 解出 SquashFS rootfs。直接对顶层 bin 用 `unsquashfs` 是解不开的。
- **Lua 保护**：LuCI 的 `.lua` 文件是编译后的 Lua 字节码（以 `.dis` 形式批量反编译），标准 Lua 解释器不能直接读源码，需要用针对小米固件改造的 `unluac_miwifi` 还原。
- **为什么必须系统级仿真**：固件是 AArch64el，管理面依赖 `procd` 进程管理、`ubus` 总线、`sysapihttpd`（小米定制 Nginx）以及 `/dev/nvram` 等设备节点；`qemu-user` + chroot 无法提供这些内核/设备语义，必须用 `qemu-system-aarch64` 完整虚拟机。Ubuntu 18 自带的 QEMU 版本过低，会出现 `rom: requested regions overlap (rom bootloader...)` 之类的启动错误，Ubuntu 20.04 的 QEMU 可直接启动预配置镜像。
- **服务启动顺序**：直接执行 `/etc/preinit` 会导致虚拟机重启，因此跳过它，只启动其关键组件 `/sbin/procd`；`sysapihttpd` 启动时通过 `ubus` 总线通信，必须先启动 `/sbin/ubusd`，且 `ubusd` 需要 `/var/run/ubus.sock` 路径存在（缺失时 `usock` 报 `No such file or directory`）。
- **启动失败的连锁缺失**：`procd` 脚本依赖 `flock`（固件 rootfs 未带该命令及其 aarch64 库）；`sysapihttpd` 需要 `/var/lock/procd_sysapihttpd.lock`、`/tmp/sysapihttpd/lock/sysapihttpd.lock.accept`、`/tmp/run/sysapihttpd.pid` 等锁/pid 路径；缺少 `/dev/nvram` 时会进入崩溃循环，可 patch 二进制跳过该检查。
- **跳过初始化与设置密码**：管理页面通过 `XQSysUtil.getInitInfo()` 读取 uci `xiaoqiang.common.INITTED` 判断是否已初始化；将其设为 1 即可绕过初始化向导。登录校验为 `SHA1(nonce .. stored_password)` 与前端 `SHA1(nonce + SHA1(plain + key))` 比对，因此直接把 `account.common.admin` 设为 `SHA1("admin" + key)` 即可用 `admin` 登录并取得 `stok`。

## 触发条件

- 已获取小米 AX9000 固件（`miwifi_ra70_firmware_cc424_1.0.168.bin` 或同系列 UBI 封装固件）。
- 宿主机为 Ubuntu 20.04（或 QEMU 版本足够新的 Linux），具备 root、KVM/libvirt 与约数十 GB 磁盘空间。
- 有可用的 AArch64 QEMU 系统镜像/预配置环境（含 `net.sh`、`start.sh` 等启动脚本）。
- 固件 rootfs 与宿主机 libc/架构匹配，或能从同架构系统中补齐缺失命令与库。

## 利用步骤

1. **解包固件**：`binwalk -Me <firmware>.bin --run-as=root`，进入 `_<firmware>.bin.extracted`；对识别出的 `.ubi` 执行 `ubireader_extract_images ./<volume>.ubi`，得到若干 `.ubifs`；再对 `*-ubi_rootfs.ubifs` 执行 `binwalk -Me`，得到 SquashFS rootfs。
2. **反编译 Lua**：编译 `unluac_miwifi`（`javac` + `jar`），用脚本遍历 rootfs 中所有 `.lua`，逐个 `java -jar unluac.jar <file.lua> > <file.lua>.dis`；后续审计以 `.dis` 为准。
3. **启动 QEMU**：宿主机安装 `libvirt-daemon-system libvirt-clients virt-manager`，执行预配置环境的 `./net.sh`、`./start.sh` 启动 AArch64 虚拟机；虚拟机内给网卡分配与 `virbr0` 同网段地址，例如 `ip addr add 192.168.122.130/24 dev enp0s1; ip link set enp0s1 up; ip route add default via 192.168.122.1`，宿主机 `ping` 验证互通。
4. **传入 rootfs 并 chroot**：`scp -r squashfs-root <user>@<vm_ip>:/home/<user>/`；虚拟机内 `mv` 到 root 家目录、`chmod -R 777`，执行 `mount --bind /proc proc`、`mount --bind /dev dev`、`chroot . /bin/sh`。
5. **启动基础服务**：不要执行 `/etc/preinit`；先 `/sbin/procd &`，再创建 `/var/run/ubus.sock`（`touch`）并 `/sbin/ubusd &`；若 `procd` 脚本报 `flock: not found`，从同架构宿主复制 `/bin/flock` 及 `librt.so.1`、`libc.so.6`、`libpthread.so.0`、`ld-linux-aarch64.so.1` 到 rootfs 对应目录。
6. **启动管理面**：创建 `/var/lock/procd_sysapihttpd.lock` 后执行 `/etc/init.d/sysapihttpd start`；若仍崩溃，直接运行 `/usr/sbin/sysapihttpd`，按报错依次创建 `/tmp/sysapihttpd/lock/sysapihttpd.lock.accept`、`/tmp/run/sysapihttpd.pid`。缺少 `/dev/nvram` 导致崩溃循环时，用 IDA/KeyPatch 把 `sysapihttpd` 中 `sub_27570` 的 `CBZ W0, loc_27920`（偏移约 `0x278F4`）改为 `CBNZ W0, loc_27920`。
7. **跳过初始化向导**：`uci set xiaoqiang.common.INITTED=1 && uci commit`，刷新页面应跳转到登录页而非 `/init.html`。
8. **设置管理员密码**：`uci set account.common.admin=<SHA1("admin"+key)> && uci commit`；对本文固件 key 为 `a2ffa5c9be07488bbb04a3a47d3c5f6a`，对应哈希为 `b3a4190199d9ee7fe73ef9a4942a69fece39a771`，之后用 `admin` 登录并记录返回的 `stok`。
9. **验证**：访问 `http://<vm_ip>/cgi-bin/luci/web`，确认管理页面与 API 可用；如需调试，用 `gdbserver-8.1.1-aarch64-le` + `gdb-multiarch` 附加目标进程。

## PoC

```bash
# 1. 解包
binwalk -Me ./miwifi_ra70_firmware_cc424_1.0.168.bin --run-as=root
cd _miwifi_ra70_firmware_cc424_1.0.168.bin.extracted
ubireader_extract_images ./2B4.ubi
binwalk -Me ./img-*-ubi_rootfs.ubifs --run-as=root

# 2. 批量反编译 Lua
find ./squashfs-root -name '*.lua' -print0 | while IFS= read -r -d '' f; do
  java -jar unluac.jar "$f" > "$f.dis"
done

# 3. 虚拟机内 chroot 并启动服务
mv /home/<user>/squashfs-root ./
cd squashfs-root && chmod -R 777 ./
mount --bind /proc proc && mount --bind /dev dev
chroot . /bin/sh
# chroot 内：
/sbin/procd &
touch /var/run/ubus.sock
/sbin/ubusd &
mkdir -p /var/lock && touch /var/lock/procd_sysapihttpd.lock
/etc/init.d/sysapihttpd start
# 若直接运行：mkdir -p /tmp/sysapihttpd/lock /tmp/run
# touch /tmp/sysapihttpd/lock/sysapihttpd.lock.accept /tmp/run/sysapihttpd.pid
# /usr/sbin/sysapihttpd

# 4. 跳过初始化并设置 admin 密码
uci set xiaoqiang.common.INITTED=1
uci set account.common.admin=b3a4190199d9ee7fe73ef9a4942a69fece39a771
uci commit
```

## 变体与关联

- **封装变体**：其他小米/OpenWrt 衍生固件可能用 UBI、SquashFS、JFFS2 或厂商自定义头；先看 `binwalk` 输出，再决定 `ubireader`、`unsquashfs` 或 `sasquatch`。
- **架构变体**：AArch64 换成 ARM/MIPS/MIPSEL 时，改用对应的 `qemu-system-*` 与同架构 Debian/Ubuntu 镜像；预配置环境可用 FirmAE/firmadyne 替代。
- **Lua 变体**：不同固件版本的 LuCI 字节码格式可能不同，`unluac_miwifi` 需与固件版本匹配；若反编译失败，可退回动态调试或 IDA 分析 `.dis`。
- **服务启动变体**：`sysapihttpd` 的锁/pid 路径、`nvram` 检查偏移随版本变化；按实际报错定位，不要照搬偏移。
- **关联卡片**：[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（SquashFS/MIPS 仿真）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（QEMU 系统级路由器 httpd 仿真）、[[iot-xiaomi-ax9000-cve-2023-26315-xqdatacenter-plugincenter-command-injection]]（本仿真环境上复现的命令注入）。

## 检测与防御

- **研究侧**：仿真环境放在隔离网络/虚拟机中，不要桥接到生产网；QEMU 镜像做快照，rootfs 保留原始备份；`chmod -R 777` 与 patch 只用于本地分析。
- **厂商侧**：固件签名与完整性校验只能提高分析成本，不能替代服务侧输入校验；应移除或加固调试接口，管理面限制在可信网段，服务以最小权限运行。
- **检测信号**：固件中出现 UBI 卷、编译 Lua、`procd`/`ubus`/`sysapihttpd` 等组件；管理面存在 `/init.html` 初始化绕过与默认/可写 uci 配置项。
