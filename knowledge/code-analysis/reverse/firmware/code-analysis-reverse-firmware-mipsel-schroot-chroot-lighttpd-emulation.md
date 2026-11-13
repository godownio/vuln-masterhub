---
id: code-analysis-reverse-firmware-mipsel-schroot-chroot-lighttpd-emulation
title: MIPSEL 路由器固件轻量模拟：debootstrap+schroot 建 qemu-user 环境，binwalk 解包后 chroot 直接跑 lighttpd
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: mipsel-debootstrap-schroot-chroot-lighttpd-emulation
aliases:
- schroot 模拟固件
- debootstrap mipsel
- qemu-user chroot 跑路由器固件
- lighttpd 固件模拟
- binwalk squashfs-root chroot
- TOTOLINK 固件模拟
tags:
- firmware
- emulation
- mipsel
- schroot
- chroot
- qemu-user
- lighttpd
- router
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:41:24+08:00'
  notes: 已逐张核对16张图（10张超1200px读img_small，无失败）与content.md：img01 debootstrap mipsel目录、img02 schroot -l显示chroot:mipsel、img03 schroot进入、img05 binwalk -Me 固件TOTOLINK_A3700R_V9.1.2u.6165_20211012.web解出内核3.4.11、img06/07 squashfs-root含lighttpd目录与lighttpd.conf、img08拷贝到chroot、img09 chroot squashfs-root后BusyBox v1.24.2、img10 lighttpd -f lighttp/lighttpd.conf并输出server started、img11/14浏览器访问TOTOLINK登录页，全部与卡片步骤一致。核对补充：原文安装命令仅写schroot debootstrap，未显式安装qemu-user-static；卡片补入qemu-user-static/binfmt_misc为前提（chroot内外MIPSEL二进制能运行所必需，属合理补全，confidence已标medium）；原文命令路径lighttp/lighttpd.conf与目录lighttpd不完全一致，卡片照录原文并注明预建/var/run/lighttpd.pid。去重：与code-analysis-reverse-firmware-dlink-dir816-goahead-qemu-mipsel-emulation（qemu-mipsel-static拷入rootfs+chroot，无debootstrap/schroot）、ARM32 qemu-user chroot、qemu-system malta等卡方法/环境不同，均related或new，dup-scan无本卡pair，保持独立新卡。本卡为研究方法类，不属于DoS/未打通排除项；无组件版本，affected_versions不设。
---

## 一句话结论

对 MIPS 小端路由器固件，不必每次都起 qemu-system：用 `debootstrap --arch=mipsel` 建一个 Debian 根文件系统并配好 schroot，宿主机安装 qemu-user-static（注册 binfmt_misc）后即可在其中直接执行 MIPSEL 二进制；再把 `binwalk -Me` 解出的 `squashfs-root` 拷进 chroot、`chroot` 进去，按固件自带配置启动 `lighttpd -f lighttp/lighttpd.conf`（预建 `/var/run/lighttpd.pid`），就能用浏览器访问路由器管理界面做漏洞复现。

## 原理

- **qemu-user + binfmt_misc**：Linux 内核的 binfmt_misc 可把特定魔数的可执行文件交给 `qemu-mipsel-static` 解释执行；Debian 的 qemu-user-static 包会注册这些 handler。因此一个 mipsel 架构的 Debian rootfs 可以直接在 x86 宿主机上 chroot 运行 MIPS 程序，不需要模拟完整系统与外设。
- **debootstrap + schroot**：`debootstrap --arch=mipsel bookworm <dir> <mirror>` 生成最小 mipsel Debian；schroot 通过 `/etc/schroot/chroot.d/*.conf` 描述 chroot（type=directory、directory、users、root-groups），`schroot -c chroot:mipsel -u root` 进入，省去手工 mount /proc、/dev 等步骤（schroot 自带 fstab 设置）。
- **固化固件到 chroot**：`binwalk -Me firmware.web` 解出 squashfs-root（固件根文件系统）后，将其复制到 mipsel chroot 的某个目录，配好 rootfs 内的 `etc_ro`/`etc`；进入后 `chroot squashfs-root/` 即把固件的 BusyBox 环境当 rootfs。
- **Web 服务启动**：固件通常带 lighttpd（放在 `/lighttpd`，含 `lighttpd.conf`），配置里以 `lighttpd -f lighttp/lighttpd.conf` 启动；首次运行若报 pid 文件相关错误，先在 `/var/run` 建空 `lighttpd.pid` 即可。启动后监听固件配置的端口（常见 80），浏览器访问即见管理页面。
- **优势与限制**：比 qemu-system 快、配置少，适合纯用户态 CGI/Web 漏洞复现；但内核驱动、NVRAM 实现、硬件相关路径需要打桩（补文件/占位 NVRAM），且依赖宿主机的 binfmt 配置——换机器时要重新安装 qemu-user-static。

## 触发条件

- 拿到固件镜像（如厂商 .web/.bin），架构为 MIPS 小端（binwalk/readelf 确认）。
- 宿主机为 Debian/Ubuntu 系，可安装 debootstrap/schroot/qemu-user-static 并注册 binfmt_misc。
- 目标服务为用户态（lighttpd/CGI），不依赖专有内核模块或硬件外设。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 安装依赖：`apt-get install schroot debootstrap qemu-user-static`（后者确保 binfmt 注册）。
2. 建 mipsel rootfs：`debootstrap --arch=mipsel bookworm /iotconfig/debootstrap/mipsel https://mirrors.aliyun.com/debian`。
3. 配置 schroot：写 `/etc/schroot/chroot.d/mipsel.conf`（type=directory、directory=…、users=root、groups=root、root-groups=root），`schroot -l` 应看到 `chroot:mipsel`。
4. `binwalk --run-as=root -Me firmware.web` 解包，确认 `squashfs-root`（里面应有 `lighttpd/`、`etc_ro/`、`www/` 等）。
5. `cp -r squashfs-root /iotconfig/debootstrap/mipsel/root/`，`schroot -c chroot:mipsel -u root` 后 `cd ~ && chroot squashfs-root/`。
6. 启动 Web：`lighttpd -f lighttp/lighttpd.conf`；若失败，`mkdir -p /var/run && touch /var/run/lighttpd.pid` 后重试；浏览器访问 `http://127.0.0.1/` 确认管理页面。
7. 按管理面流程登录/绕过（空密码、authCode、默认口令）后复现目标 CGI 漏洞；必要时用 `qemu-mipsel-static` 直接跑单个 CGI 做调试。

## PoC

```bash
# 1) mipsel rootfs + schroot
sudo apt-get install schroot debootstrap qemu-user-static
sudo debootstrap --arch=mipsel bookworm /iotconfig/debootstrap/mipsel https://mirrors.aliyun.com/debian
sudo tee /etc/schroot/chroot.d/mipsel.conf <<'EOF'
[mipsel]
type=directory
directory=/iotconfig/debootstrap/mipsel/
users=root
groups=root
root-groups=root
EOF
sudo schroot -l            # chroot:mipsel（schroot -c chroot:mipsel -u root 进入）

# 2) 解包固件并放入 chroot
sudo binwalk --run-as=root -Me TOTOLINK_A3700R_V9.1.2u.6165_20211012.web
sudo cp -r squashfs-root /iotconfig/debootstrap/mipsel/root/
sudo schroot -c chroot:mipsel -u root
cd ~ && chroot squashfs-root/

# 3) 启动 lighttpd（固件内）
lighttpd -f lighttp/lighttpd.conf
# 若报 pid 错误：
mkdir -p /var/run && touch /var/run/lighttpd.pid && lighttpd -f lighttp/lighttpd.conf
```

```text
# 成功标志
2024-02-15 16:46:32: (log.c.97) server started
# 浏览器 http://127.0.0.1/ 出现 TOTOLINK 登录页（固件版本 V9.1.2u.6165）
```

## 变体与关联

- 变体：MIPS 大端用 `mips` 架构与 `qemu-mips-static`；ARM 固件用 `armhf`/`armel` 或 `qemu-arm-static`，方法相同。
- 变体：固件 BusyBox 是静态链接时可直接 qemu-user 跑单个程序（`qemu-mipsel-static ./cstecgi.cgi`），但 CGI 依赖 Web 服务器环境变量/标准输入，通常仍需 lighttpd。
- 变体：schroot 不便时可用 `proot`/`chroot + mount --bind` 手动搭；需要网络/内核行为时改用 qemu-system（malta 等）。
- 关联：[[iot-totolink-a3700r-cstecgi-uploadfirmwarefile-filename-command-injection]]（用本环境复现的 CVE-2023-46574）、[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]（ARM32 同类 chroot 模拟）、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（MIPS qemu-user 调试）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（需要系统态时的完整模拟）。

## 检测与防御

- 检测：无（这是防御方/研究方的复现方法）；防御侧可关注固件解包/模拟环境的隔离性。
- 防御：研究环境用独立网络与快照；不要在含真实凭据的生产网段运行模拟的脆弱固件；模拟器中的服务不要暴露到公网。
- 说明：本文是 MIPSEL 路由器固件的 qemu-user chroot 轻量模拟方法，severity low、confidence medium（原文为复现过程，宿主机 binfmt 配置为前提）；仅用于授权测试与自有设备研究。
