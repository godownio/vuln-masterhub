---
id: iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh
title: ZKTeco 生物识别终端 eMMC 拆读取固件：binwalk 定位 rootfs，/etc/shadow 破解 SSH 账号
type: scenario
domain: iot
path: iot/hardware
technique: zkteco-emmc-dump-binwalk-shadow-ssh
tags:
- iot
- hardware
- emmc
- firmware
- binwalk
- shadow
- ssh
- zkteco
- physical-access
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:55:24+08:00'
  notes: 已对照 img29-34 与原文核对 THGBMJG6C1LBAIL eMMC、binwalk 分区、/etc/shadow 与 3718 Dropbear/zkteco 登录；已修正 dd count 为 0x1800000（按 img31 EXT 镜像大小）；未实际拆机复跑。UART 辅助路线与 img09/10 一致。
url: /docs/iot/hardware/iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh/
draft: false
kb_aliases:
- eMMC 固件提取
- THGBMJG6C1LBAIL
- binwalk 分区
- shadow 破解
- ZKTeco UART 启动日志
- Dropbear 3718
---

## 一句话结论

对 ZKTeco 生物识别终端做物理接触时，可拆下 BGA-153 封装的 eMMC（THGBMJG6C1LBAIL）用编程器读全盘；`binwalk` 能识别出 U-Boot、uImage/Linux zImage、DTB 与 ext4 rootfs，挂载 rootfs 读取 `/etc/shadow`，破解 `$6$` 哈希得到 `zkteco` 用户口令，再从 3718/TCP 的 Dropbear SSH 登录；设备上服务均以 root 运行，物理接触即等于完全失守。

## 原理

- **eMMC 未加密**：终端主板的 THGBMJG6C1LBAIL 是 BGA-153 eMMC，固件以未加密形式保存；拆焊后用通用 eMMC 编程器可读出整盘镜像（也可通过板上测试点/ISP，视板型而定）。
- **binwalk 识别分区**：整盘镜像中 `binwalk` 可看到 gzip 压缩的 `u-boot.bin`、uImage 头、Linux ARM zImage、Flattened Device Tree、ext4 文件系统等；偏移与大小可用于 `dd` 切出 rootfs。
- **rootfs 中的凭据**：挂载 ext4 rootfs 后 `cat etc/shadow` 可见 `root` 与 `zkteco` 的 `$6$` SHA-512 crypt 哈希；原文通过破解得到 `zkteco` 用户口令。
- **SSH 与权限**：设备在 3718/TCP 运行 Dropbear sshd 2018.76，`zkteco` 可登录；登录后 `id` 为 uid=1000，但 `ps` 显示 `main`、`hub`、`pushcomm`、`standalonecomm`、`biometric`、`tuyacomm` 等服务全部以 root 运行，任何服务漏洞都能升级为 root。
- **UART 辅助路线**：主板上标有 UART 测试点，示波器确认 TX 后可按波特率（启动初期 57,600，之后切到 115,200）读取完整启动日志，识别 U-Boot 2016.11（hi3516dv300）；该 U-Boot 配置 `bootdelay=-2` 禁止中断，不能直接拿 shell，但可确认硬件型号/固件版本并观察私有协议数据包（以 `0x53 0x53` 开头）。
- **为什么有效**：物理访问绕过了所有网络认证；未加密存储 + 可破解弱口令 + 全 root 服务，使设备边界完全失效。

## 触发条件

- 攻击者能物理接触设备主板（拆机）。
- 有 eMMC 编程器/读卡器与 BGA 返修能力，或板上有可用的 eMMC 测试点。
- rootfs 未加密，`/etc/shadow` 中账号使用可破解口令（或可改为已知口令后重写）。
- 设备 SSH 端口 3718 可从攻击者位置访问（物理接触后通常在同一网络）。

## 利用步骤

1. 拆机，识别主板上的 eMMC 芯片（原文 THGBMJG6C1LBAIL，BGA-153）与 UART 测试点。
2. 用编程器读取整盘镜像 `dump_flash.bin`；或用 UART 读取启动日志确认 U-Boot/内核/固件版本。
3. `binwalk dump_flash.bin` 查看分区；按偏移 `dd` 切出 ext4 rootfs，`mount -o loop` 挂载。
4. `cat etc/shadow` 取 `root`/`zkteco` 哈希，用 hashcat/john 破解（`$6$` 用 `-m 1800`）。
5. `ssh -p 3718 zkteco@target` 登录，`id`、`ps` 确认权限与服务；进一步可通过服务漏洞或可写配置提权到 root。
6. 测试后恢复设备、清理改动；仅在授权物理评估中操作。

## PoC

```bash
# 1. 读取 eMMC 后分析分区
binwalk dump_flash.bin
# 输出示例：gzip u-boot.bin、uImage、Linux ARM zImage、Flattened device tree、Linux EXT filesystem

# 2. 切出并挂载 rootfs（偏移/大小按 binwalk 结果调整；原文 EXT 镜像约 0x1800000 字节）
dd if=dump_flash.bin of=rootfs.ext4 bs=1 skip=$((0x600000)) count=$((0x1800000))
mkdir -p ext-root && sudo mount -o loop rootfs.ext4 ext-root

# 3. 读取并破解 shadow
sudo cat ext-root/etc/shadow
hashcat -m 1800 shadow.txt wordlist.txt

# 4. SSH 登录
ssh -p3718 zkteco@192.168.1.201
id    # uid=1000(zkteco)
ps    # main/hub/pushcomm/standalonecomm 等均以 root 运行
```

```text
# UART 路线（辅助）
# 示波器接 TX 测试点 -> 57600/115200 8N1 -> 读启动日志
# U-Boot 2016.11-svn1034 (Aug 10 2020) hi3516dv300，bootdelay=-2 不可中断
```

## 变体与关联

- 变体：部分板型可通过 eMMC 测试点/ISP 读取，无需拆焊；UART 若可中断（bootdelay 非负）可直接进 U-Boot。
- 变体：rootfs 加密或 secure boot 时，需先找密钥/绕过；`/etc/shadow` 口令强随机时改用服务漏洞/配置提权。
- 关联：[[iot-hardware-bes2300-rom-bootloader-uart-dump]]（UART 读取 bootloader 的同类硬件路线）、[[iot-hardware-saleae-logic-uart-decode]]（逻辑分析仪解 UART）、[[code-analysis-reverse-firmware-zkteco-updatepackage-xor-keysize-decrypt]]（更新包静态解密的另一条固件获取路线）、[[iot-protocol-zkteco-pushcomm-shell-command-server-hijack]]（登录后利用 root 服务）。
- 边界：无法物理接触、eMMC 加密/安全启动、口令强随机且服务无漏洞时，该链不成立。

## 检测与防御

- 检测：设备被拆机/主板痕迹；eMMC 被读取（离线无法从设备侧检测，需资产巡检与封条）；异常 SSH 登录 3718 与 `zkteco` 账号；`/etc/shadow` 被读取。
- 防御：物理安全（机柜锁、防拆封条、外壳检测开关）；固件加密与 secure boot；每台设备唯一强口令并强制修改默认密码。
- 防御：关闭不必要的 SSH 或改为密钥认证/内网限制；服务以最小权限运行，降低单点漏洞的提权收益。
- 加固：定期更新固件、审计服务与账号；对设备网络做隔离，限制 3718/4370 等管理端口暴露。
