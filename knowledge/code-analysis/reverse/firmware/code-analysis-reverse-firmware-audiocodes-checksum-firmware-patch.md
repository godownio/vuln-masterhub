---
id: code-analysis-reverse-firmware-audiocodes-checksum-firmware-patch
title: AudioCodes 桌面电话固件仅校验和、无可信根：拆镜像改 rootfs 后重算 section 校验和即可刷入恶意固件（CVE-2023-22955）
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: audiocodes-firmware-section-checksum-patch
aliases:
- CVE-2023-22955
- AudioCodes 固件篡改
- AudioCodes 固件校验和绕过
- CRC Error Upgrade Failed
- AudioCodes rootfs 修改
- SYSS-2022-055
tags:
- firmware
- reverse
- audiocodes
- voip
- checksum
- patch
- cve-2023-22955
- trusted-root
cve:
- CVE-2023-22955
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: AudioCodes C450HD UC 3.4.6.604.1（原文测试版本）
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:44:00+08:00'
  notes: 已对照原文与截图核对：flasher/run_ramfs_for_upgrade.sh 流程(lseek分段)、section头(FC 39 05 41/0x17/rootfs.ext4)、校验和规则'从偏移0x60起字节和'、CRC Error/Upgrade Failed(图23)、重算后3D 3E EF 78→C2 DA 4C 7A(图24/27)、改rootfs后成功刷入(图26/28)均一致；CVE-2023-22955=SYSS-2022-055映射正确。affected_versions'UC 3.4.6.604.1'为原文/etc/release截图测试版本(图28)，非受影响区间，卡片已标注'原文测试版本'。原文未提供可直接运行的校验和脚本，卡内PoC如实标注为归纳未复现，confidence medium合理。dedup最近候选为CRC16硬件U盘/FortiGate改包等不同产品链，非同链。
---

## 一句话结论

AudioCodes C450HD 的固件镜像没有签名/不可变可信根，只按 section 头部的简单校验和校验：直接修改镜像会报 `CRC Error / Upgrade Failed`，但只要按「从偏移 0x60 起的字节和」重算并回填校验和，改过 `rootfs.ext4`（加入启动脚本）的固件就能被设备正常安装并执行，形成持久 root 后门（CVE-2023-22955，SYSS-2022-055）。

## 原理

- 升级流程：`/home/ipphone/scripts/run_ramfs_for_upgrade.sh` 检查 `/tmp/flasher_ext` 是否存在，存在则执行它，否则执行 `/bin/flasher`；脚本调用 `flasher u /tmp upgrade.img` 与 `flasher r /tmp upgrade.img` 完成刷写。`flasher` 中大量使用 `lseek` 在镜像内定位各区域，说明镜像是分段结构。
- 镜像结构（原文逆向结果）：头部含版本/型号/日期等元信息，随后是 `bootloader.img`、`rootfs.ext4`、`phone.img`、`section.map`、`flasher`、`release`、`end.section` 等 section。
- section 头格式（原文 24/25 号图）：4 字节 section magic（如 `FC 39 05 41`）、4 字节 section header size（0x17）、section 名字符串（如 `rootfs.ext4`），校验和在偏移 0x60 处（8 字节对齐）。原文说明校验和等于该 section「从偏移 0x60 开始的所有字节之和」。
- 设备对固件只做这个校验和比对，没有厂商签名验证，硬件也没有不可变可信根（CWE-1326）。因此任何能改写镜像的人都能通过重算校验和让设备接受。
- 验证过程：直接改镜像不重算时设备屏幕显示 `CRC Error / Upgrade Failed`；重算后校验和字段从 `3D 3E EF 78` 变为 `C2 DA 4C 7A`，固件安装成功，设备启动后 `/etc/release`、文件系统内容与改动一致。
- 原文的改动示例：把 `rootfs.ext4` 挂载到本机，向 `/home/ipphone/` 下新增文件、在 `rcS` 中加入启动项，重新打包并重算校验和，刷入后获得 root 权限命令执行。

## 触发条件

- 目标为受影响 AudioCodes 设备（原文测试 C450HD UC 3.4.6.604.1；SYSS-2022-055 属未修复项）。
- 攻击者能触达固件升级入口：设备 Web 管理界面上传固件，或能替换升级流程中的 `upgrade.img`（本地/中间人/上游投递）。
- 攻击者拿到官方固件镜像并能用十六进制编辑器/脚本修改、重算校验和。
- 设备没有启用额外的签名校验/安全启动（该型号原文确认没有）。

## 利用步骤

1. 从厂商下载门户获取对应型号官方固件，确认镜像 section 布局与校验和算法（可对比 `flasher` 的 `lseek` 读取位置和 section 头）。
2. 从镜像中提取 `rootfs.ext4` 并挂载，修改文件系统（如加入启动脚本、改配置、开调试服务）。
3. 重新打包 `rootfs.ext4` 并替换回镜像对应 section。
4. 按 section 逐个重算校验和：对每个 section，从其偏移 0x60 起按字节求和，把结果回填到该 section 头部 0x60 处的校验和字段（具体字段宽度/对齐按固件版本核对）。
5. 通过设备 Web 界面上传修改后的镜像或替换升级源文件，执行升级；设备不再报 CRC Error。
6. 升级重启后验证改动生效（如 `/etc/release`、启动脚本、root shell）。

## PoC

原文验证方式（摘要）：

```text
# 1) 官方固件 → 改 rootfs.ext4（挂载后新增文件/改 rcS）→ 重新打包进镜像
# 2) 重算 section 校验和（从偏移 0x60 起字节和）并回填
# 3) Web 界面上传固件
```

不重算校验和时设备显示：

```text
CRC Error
Upgrade Failed
```

重算后的差异（原文截图）：

```text
section checksum: 3D 3E EF 78  ->  C2 DA 4C 7A
Upgrade successful
```

说明：原文未给出可直接运行的通用校验和脚本，字段布局随固件版本变化；本卡为归纳，未复现。

## 变体与关联

- 变体：只改 `phone.img` 或其它 section 也能通过同样方式重算；若设备允许降级，可刷回带漏洞的旧版本再叠加攻击。
- 变体：把恶意固件托管在攻击者服务器，通过云 ZTP 配置模板下发（见 [[iot-zoom-ztp-mac-claim-malicious-firmware-takeover]]），无需接触设备 Web 界面。
- 关联：[[iot-hardware-spi-firmware-crc16-patch-aes-key-extract]]——硬件加密 U 盘固件完整性只用 CRC-16 的同类「校验和≠签名」问题。
- 关联：[[code-analysis-reverse-firmware-fortigate-firmware-patch-smartctl-shell]]——固件改包后重新打包刷入的同类方法。

## 检测与防御

- 防御：固件镜像必须带厂商数字签名并由设备端验证，信任根不可变（secure boot/TPM/efuse 公钥哈希），校验和只用于完整性快速检查，不能作为唯一信任依据。
- 防御：升级过程加防降级版本号与签名清单校验；限制固件 URL 为厂商域名。
- 检测：审计设备升级来源与镜像哈希，出现「校验和正确但签名缺失/不匹配」即拒绝；监控升级后 `/home/ipphone/rcS`、`scripts` 等启动路径的异常修改。
- 检测：网络侧识别设备从非厂商地址下载固件；对同一型号大量设备短时间升级到非官方镜像告警。
