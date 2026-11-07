---
id: code-analysis-reverse-firmware-openwrt-squashfs-jffs2-overlay
title: OpenWrt 固件取证：binwalk 拆 SquashFS + JFFS2 overlay/sysupgrade.tgz 恢复 /etc 配置
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: openwrt-squashfs-jffs2-overlay-config-recovery
aliases:
- OpenWrt 固件提取
- SquashFS 解包
- JFFS2 overlay
- sysupgrade.tgz
- 路由器配置取证
- /etc/config 恢复
tags:
- firmware
- openwrt
- squashfs
- jffs2
- overlay
- router
- forensics
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:37+08:00'
  notes: 已对照原文与图片22/62核对：OpenWrt 23.05.0、squashfs-root、jffs2-root/upper/sysupgrade.tgz、network/wireless/firewall 配置均一致；PoC 未在本库复跑。
---

## 一句话结论

OpenWrt 路由器固件通常是“只读 SquashFS 根文件系统 + 可写 JFFS2/overlay 分区”；用 binwalk 拆出 SquashFS 并用 unsquashfs 解包得到基础系统，再从 overlay（常见 `upper/sysupgrade.tgz`）恢复用户修改过的 `/etc/config/network`、`wireless`、`firewall`、`shadow` 等，即可还原 PPPoE 账号、WiFi 口令、端口转发和管理员哈希。

## 原理

- **OpenWrt 分区结构**：SquashFS 是只读压缩根文件系统，包含 `/bin`、`/etc`、`/usr` 等基础文件；overlay（JFFS2/UBIFS）挂载在其上，保存用户修改/新增的文件。系统通过 OverlayFS 把两者合并成可写根。
- **overlay 的目录形态**：`upper/` 保存新增/修改文件，`work/` 是 OverlayFS 工作目录；升级备份常生成 `upper/sysupgrade.tgz`，里面是 `/etc` 配置的归档，是恢复配置的最快入口。
- **JFFS2 不是 1:1 目录树**：`jffs2-root/work/work` 下的文件名可能是 inode/哈希编号（如 `#4/network`），不能按路径直接找；可以用 `strings` 扫描所有文件内容，或解析 JFFS2 元数据恢复原始路径。
- **关键配置文件**：
  - `/etc/openwrt_release`：OpenWrt 版本、revision、target、arch。
  - `/etc/config/network`：WAN/LAN 接口、PPPoE 用户名/口令、静态 IP。
  - `/etc/config/wireless`：SSID、加密方式、WiFi 口令。
  - `/etc/config/firewall`：DNAT/redirect 规则（WAN→LAN 端口转发）。
  - `/etc/shadow`：root 口令哈希（可能是基础镜像中的旧值，真实值在 overlay/sysupgrade.tgz 中）。
- **为什么基础 SquashFS 的 shadow 可能是错的**：用户改过 root 密码后，新 `/etc/shadow` 会落在 overlay；SquashFS 里仍是出厂/基础镜像的旧哈希。只解 SquashFS 会得到错误口令。
- **内核版本**：可从 `/lib/modules/<version>`、`/etc/openwrt_release` 或内核镜像字符串获取；用于判断漏洞/模块。

## 触发条件

- 拿到路由器固件镜像（`.bin`、`.img`、厂商升级包）或备份文件。
- 固件未加密/未签名，或可解密；binwalk 能识别 SquashFS/JFFS2/UBI 等。
- 有 binwalk、unsquashfs、jefferson/jffs2dump、strings 等工具。
- 目标配置（PPPoE/WiFi/防火墙/口令）保存在 overlay 或 sysupgrade.tgz 中。

## 利用步骤

1. `binwalk -e firmware.bin` 拆包，记录偏移与文件系统类型；常见输出 `SquashFS filesystem`、`JFFS2 filesystem`、`UBI erase count header`。
2. 对 SquashFS 执行 `unsquashfs -d squashfs-root <image>`；查看 `etc/openwrt_release` 获取版本/target/arch，查看 `/lib/modules` 获取内核版本。
3. 找到 overlay/JFFS2 分区：`binwalk` 输出的 JFFS2 段、`jffs2-root/`、或 `upper/` 目录；检查 `upper/sysupgrade.tgz`。
4. 解压 `sysupgrade.tgz`（gzip+tar）到独立目录，直接读取 `etc/config/network`、`wireless`、`firewall`、`shadow`、`passwd`。
5. 若没有 sysupgrade.tgz，用 `jefferson`/`jffs2dump` 解 JFFS2；若文件名是 `#N`，用 `strings` 扫描内容或按 JFFS2 inode 元数据恢复路径。
6. 解析配置：PPPoE `option username/password`、WiFi `option ssid/key`、firewall `config redirect` 的 `src_dport/dest_ip/dest_port`、shadow 的 root 哈希。
7. 交叉验证：基础 SquashFS 与 overlay 的 shadow 对比，取 overlay 中的最新值；用 `strings` 全盘搜索 `password`、`ssid`、`pppoe`、`root:` 等关键字。

## PoC

```bash
# 1) 拆包
binwalk -e firmware.bin
# 输出示例：42C2C8.squashfs、JFFS2 段

# 2) 解 SquashFS
unsquashfs -d squashfs-root 42C2C8.squashfs
cat squashfs-root/etc/openwrt_release
ls squashfs-root/lib/modules

# 3) 找 overlay / sysupgrade.tgz
find . -name 'sysupgrade.tgz' -o -name 'upper' -o -name 'jffs2-root'
mkdir -p overlay && tar -xzf jffs2-root/upper/sysupgrade.tgz -C overlay
cat overlay/etc/config/network
cat overlay/etc/config/wireless
cat overlay/etc/config/firewall
cat overlay/etc/shadow

# 4) JFFS2 备选
jefferson -d jffs2-out jffs2.img
# 或
jffs2dump -c -b jffs2.img > jffs2.txt
strings -a jffs2.img | grep -Ei 'pppoe|ssid|password|root:'
```

配置判读示例：

```text
config interface 'wan'
    option proto 'pppoe'
    option username 'yohZ5ah'
    option password 'ae-h+i$i^Ngohroorie!bieng6kee7oh'

config wifi-iface 'default_radio0'
    option ssid 'VLT-AP01'
    option key 'french-halves-vehicular-favorable'

config redirect
    option name 'DB'
    option src 'wan'
    option src_dport '1778'
    option dest_ip '192.168.1.184'
    option dest_port '5881'
```

## 变体与关联

- **UBI/UBIFS**：NAND 路由器常用 UBI 容器；用 `ubireader_extract_images`/`ubireader_extract_files` 解包，再找 overlay。
- **加密/签名固件**：厂商可能 AES/RSA 加密或签名；需先逆向升级程序/提取密钥，再解包。
- **JFFS2 路径恢复**：`#N` 文件名是 inode 编号；用 `jffs2dump -c` 或脚本按 dirent 重建路径。
- **配置取证**：除 `/etc/config` 外，检查 `/etc/passwd`、`/etc/shadow`、`/etc/dropbear`、`/etc/rc.local`、crontab、`/root/.ssh`。
- **关联卡片**：[[code-analysis-reverse-firmware-xiaomi-ax9000-ubi-aarch64-qemu-emulation]]（小米 UBI 固件解包与仿真）；[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（魔改 SquashFS 解包）；[[iot-hardware-bes2300-rom-bootloader-uart-dump]]（UART 提取 Flash）。

## 检测与防御

- **固件保护**：对固件签名/加密，关闭调试接口；不要把明文口令写入可读配置或备份。
- **配置安全**：PPPoE/WiFi 口令使用强随机值；root 口令哈希使用强算法（sha512/yescrypt），禁用默认口令。
- **备份管理**：`sysupgrade.tgz`/overlay 备份含敏感配置，按密钥材料保管；退役设备彻底擦除。
- **取证规范**：保留原始固件哈希与解包产物；记录工具版本、偏移、文件系统类型，确保可复现。
