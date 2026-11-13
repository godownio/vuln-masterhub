---
id: defense-forensics-volatility2-usbstor-usb-device-history
title: Volatility2 usbstor 插件从内存镜像恢复 USB 存储设备接入历史：序列号、厂商型号与最后连接时间
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-usbstor-memory-usb-device-history
tags:
- windows
- forensics
- memory
- volatility2
- usbstor
- usb
- registry
- incident-response
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:43:44+08:00'
  notes: 已对照原文与5图核对：usbstor在Win7SP1x64镜像上输出SanDisk Extreme_SSD/SES_Device两条(Serial 32313131373430343234313260/...281)、Revision 1012、同一ContainerID {ad409054-19e5-5dd9-ade9-925239576e82}、Friendly Name、Device Last Connected 2023-06-20 17:01:25 UTC+0000均与图02一致；ASCII十六进制序列号解码为21117404241260已独立验证；USBSTOR与USB HUB区分与原文注意事项一致。未验证点：未对真实镜像复跑；usbstor为第三方插件，无受影响版本；frontmatter无sources/source_url。
url: /docs/defense/forensics/defense-forensics-volatility2-usbstor-usb-device-history/
draft: false
kb_aliases:
- usbstor 插件
- USB 设备接入记录取证
- USBSTOR 注册表内存解析
- U盘使用痕迹
- USB 存储设备时间线
---

## 一句话结论

对 Windows 内存镜像运行 Volatility2 的 `usbstor` 插件，插件会扫描内存中缓存的 SYSTEM 注册表 hive 里的 `Enum\USBSTOR` 项，输出每个曾接入的 USB 存储设备的序列号、厂商、产品型号、修订号、ContainerID 与最后连接时间，不依赖目标机磁盘即可回答“什么时候插过哪个 U 盘”，用于数据外带、U 盘传播恶意软件与内鬼调查。

## 原理

- Windows 在设备枚举时把 USB 存储设备写入注册表 `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<设备类>\<实例ID>`；实例 ID 通常由设备序列号构成，设备类/实例键下保存 `DeviceDesc`、`Mfg`、`FriendlyName` 等描述，`Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064` 保存最后连接时间的 FILETIME。
- 系统运行时 SYSTEM hive 常驻内存（注册表缓存），Volatility2 的 `usbstor` 插件直接扫描内存中的 hive 页定位 USBSTOR 键并解析上述字段，输出 `Serial Number / Vendor / Product / Revision / ClassGUID / ContainerID / Friendly Name / Device Last Connected`。
- 因为解析的是内存里的 hive 副本，设备已拔出、注册表文件被删改、磁盘被加密都不影响；离线分析也不需要目标机在线。
- 截图中的 `Serial Number: 32313131373430343234313260` 是 ASCII 十六进制编码，逐字节解码即 `21117404241260`——USB 设备报告的序列号不是可打印字符串时，Windows 会以十六进制形式写进实例键名，与磁盘/USBSTOR 键比对时要按同样方式换算。
- 同一物理设备可能枚举出多个条目（如截图里的 `Extreme_SSD` 与 `SES_Device`，序列号相邻且 ContainerID 相同 `{ad409054-19e5-5dd9-ade9-925239576e82}`），用 ContainerID 归组可避免把一块盘误判为多块。
- 注意区分：只有 `USBSTOR` 项能证明接入过 USB **存储**设备；仅出现 `USB`/`USB HUB` 项只能说明接入过 USB 设备（键鼠、Hub 等），这也是取证时容易混淆的点。

## 触发条件

- 已获取 Windows 内存镜像（raw/dmp，DumpIt、WinPmem、VM 快照或休眠文件），Volatility2 能按 profile 解析。
- 目标系统运行期间接入过 USB 存储设备，且 SYSTEM hive 的相关页未被后续分配覆盖。
- 需要证明 USB 接入历史、关联数据拷贝时间，或为 CTF/取证题还原设备信息。
- 系统多次重启、hive 页被大量覆盖时结果可能缺失；此时应改用磁盘上的 SYSTEM hive 离线解析。

## 利用步骤

1. `vol.py -f <image> imageinfo` 确认 profile（本例 `Win7SP1x64`）。
2. 运行 `vol.py -f <image> --profile=<Profile> usbstor`，逐条记录 Serial Number、Vendor、Product、Revision、Device Last Connected。
3. 按 ContainerID 归组同一物理设备的多接口条目；对 Serial Number 做十六进制解码。
4. 把解码后的序列号与磁盘取证结果（SYSTEM hive 的 USBSTOR 键名、`setupapi.dev.log`、文件系统 USN/日志）比对，确认设备身份。
5. 用 `Device Last Connected` 与文件拷贝/删除时间、登录日志、网络外联时间串时间线。
6. 若插件无输出，退化为 `printkey -K "ControlSet001\Enum\USBSTOR"` 直接看键值，或导出 SYSTEM hive 后离线解析。

## PoC

```bash
vol.py -f memdump.mem --profile=Win7SP1x64 usbstor
```

输出示例（截图字段）：

```text
Found USB Drive: 32313131373430343234313260
Serial Number:   32313131373430343234313260   # 十六进制解码为 21117404241260
Vendor:          SanDisk
Product:         Extreme_SSD
Revision:        1012
ClassGUID:       Extreme_SSD
ContainerID:     {ad409054-19e5-5dd9-ade9-925239576e82}
Friendly Name:   SanDisk Extreme SSD USB Device
Device Last Connected: 2023-06-20 17:01:25 UTC+0000
```

## 变体与关联

- **Volatility3**：无同名插件时用 `windows.registry.printkey` 按 `ControlSet001\Enum\USBSTOR` 路径取键；也可先 `windows.registry.hivelist` 定位 hive 后再解析。
- **磁盘侧**：Registry Explorer/RegRipper 解析 SYSTEM hive 的 USBSTOR；`setupapi.dev.log` 记录设备安装时间；USB 相关事件日志可补充接入/拔出时间。
- **时间线组合**：与 `userassist`（程序执行）、`mftparser`（文件访问）、`shellbags`（目录浏览）交叉，形成“插盘→拷贝→运行”的证据链。
- 关联卡片：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（同镜像的综合排查）、[[defense-forensics-volatility2-userassist-execution-history]]（用户行为时间线）、[[defense-forensics-ventoy-log-partition-history]]（U 盘启动/分区痕迹）。

## 检测与防御

- **取证规范**：先采集内存再关机；记录镜像哈希、采集时间与工具版本；内存结果与磁盘注册表交叉验证。
- **防御**：不需要 USB 存储的主机用组策略设备安装限制/块设备策略禁用；对敏感主机启用设备审计并在 DLP 侧监控大文件外拷。
- **检测**：监控 `SYSTEM\CurrentControlSet\Enum\USBSTOR` 注册表变更（Sysmon 12/13/14），结合终端日志告警非授权 U 盘接入。
- **响应**：确认未授权存储设备接入后，核查同期文件访问与外发记录，按证据保全流程提取设备镜像。
