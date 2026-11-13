---
id: defense-forensics-volatility2-userassist-execution-history
title: Volatility2 userassist 插件从内存镜像恢复程序执行记录：运行次数、聚焦时长与最后更新时间
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-userassist-program-execution-history
tags:
- windows
- forensics
- memory
- volatility2
- userassist
- registry
- execution-history
- incident-response
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:43:46+08:00'
  notes: 已对照原文与5图核对：图04中IDRIX.VeraCrypt条目Count=2、Focus Count=16、Time Focused=0:01:14.288000、Last updated=2023-06-20 16:47:41 UTC+0000与卡内PoC逐字段一致；ROT13示例VQEVK.IrenPelcg解码正确；UserAssist键路径/REG_BINARY结构/两个常见GUID与Windows取证常识一致。原文问'最后一次更新'，卡内按'最后更新时间通常等于最后一次执行时间'表述并保留局限说明。未验证点：未对真实镜像复跑；无受影响版本；frontmatter无sources/source_url。
url: /docs/defense/forensics/defense-forensics-volatility2-userassist-execution-history/
draft: false
kb_aliases:
- userassist 插件
- UserAssist 注册表取证
- 程序执行记录恢复
- 程序最后运行时间
- ROT13 值名解析
---

## 一句话结论

对 Windows 内存镜像运行 Volatility2 的 `userassist` 插件，插件解析当前用户 NTUSER.DAT 中 `Explorer\UserAssist\<GUID>\Count` 键（值名为 ROT13 编码的程序路径，值为二进制计数/时间结构），输出每个程序的运行次数、焦点次数、聚焦时长和最后更新时间，可在不登录目标用户、不依赖磁盘的情况下证明某程序何时运行过，例如本例中 `IDRIX.VeraCrypt` 的最后更新时间为 2023-06-20 16:47:41 UTC+0000。

## 原理

- Explorer 在用户启动程序时维护 UserAssist 记录：`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`。值名是程序路径的 ROT13 编码（如 `IDRIX.VeraCrypt` 在注册表里存为 `VQEVK.IrenPelcg`），插件会解码后显示。
- 值数据是 `REG_BINARY` 结构：Windows 7 及以后包含运行次数（Count）、焦点次数（Focus Count）、聚焦毫秒数（Time Focused）与最后执行的 FILETIME 等字段；不同系统版本布局略有差异，Volatility 按 profile 中的结构定义解析，因此 profile 选错会解析出荒谬数值。
- 统计按会话/用户 hive 分开：`userassist` 会遍历内存中所有可识别的用户 NTUSER.DAT hive，每个用户名下列出程序条目；同一程序在不同用户下各有一条。
- 该注册表位于用户 hive，运行时驻留内存；内存镜像保存了 hive 页，离线即可恢复。即使磁盘上的 NTUSER.DAT 被清理，内存里的旧页仍可能保留记录。
- 价值点：绿色软件、临时目录程序、加密/擦除工具、远控工具往往没有安装记录，但经 Explorer 双击/开始菜单启动就会留下 UserAssist 条目；“最后更新时间”即该 Count 键的最后写入时间，通常等于最后一次执行时间，可用于回答“某软件最后一次使用/更新是什么时候”。
- 局限：只记录经 Explorer 启动的程序，命令行/服务启动可能不记录；记录有数量上限，旧条目会被挤掉；攻击者可删除 Count 键反取证。

## 触发条件

- 已获取 Windows 内存镜像（raw/dmp），Volatility2 profile 匹配（本例 `Win7SP1x64`）。
- 目标用户曾交互式登录并通过 Explorer 启动过目标程序。
- 对应用户 hive 的相关页未被覆盖；镜像中至少有一个可解析的用户 hive。

## 利用步骤

1. `vol.py -f <image> imageinfo` 确定 profile。
2. 运行 `vol.py -f <image> --profile=<Profile> userassist`，按用户分组浏览条目，记录程序名、Count、Focus Count、Time Focused、Last updated。
3. 按优先级筛选：加密工具（VeraCrypt/TrueCrypt/BitLocker 管理端）、浏览器、远程控制/内网穿透工具、文件擦除工具、黑客工具、临时目录下的可执行文件。
4. 交叉验证：`cmdline`/`cmdscan` 看是否命令行启动、`mftparser` 看文件创建/修改时间、`shellbags` 看目录浏览、`netscan` 看外联；Last updated 与登录日志、Prefetch（磁盘侧）比对。
5. 若插件无输出，用 `printkey`/`dumpregistry` 导出 NTUSER.DAT hive，再用 Registry Explorer/RegRipper 解析 UserAssist 键。
6. 记录命令、profile、用户 hive 与输出，作为证据固化。

## PoC

```bash
vol.py -f memdump.mem --profile=Win7SP1x64 userassist
```

输出示例（截图字段，VeraCrypt 条目）：

```text
REG_BINARY   IDRIX.VeraCrypt :
Count:            2
Focus Count:      16
Time Focused:     0:01:14.288000
Last updated:     2023-06-20 16:47:41 UTC+0000
```

即该用户经 Explorer 启动 VeraCrypt 2 次、累计聚焦约 74 秒，最后一次记录更新于 2023-06-20 16:47:41 UTC。

## 变体与关联

- **Volatility2 同族插件**：`shellbags`（资源管理器目录访问）、`cmdscan`/`consoles`（命令历史与输出）、`iehistory`/`chromehistory`（浏览器历史）、`shutdown`（开关机时间）、`sessions`（登录会话），可与 UserAssist 拼出用户行为时间线。
- **磁盘侧**：Registry Explorer/RegRipper 解析 NTUSER.DAT；Windows 7+ 常见 GUID 为 `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`（执行计数）与 `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}`（UAC 快捷方式计数）。
- **Volatility3**：`windows.registry.printkey` 按路径读取 UserAssist 键，或用 `windows.registry.userassist`（若版本提供）。
- 关联卡片：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（同镜像综合排查）、[[ctf-forensics-volatility-cmdscan-consoles-command-history]]（命令历史互补）、[[defense-forensics-volatility2-usbstor-usb-device-history]]（U 盘接入时间线）。

## 检测与防御

- **取证价值**：UserAssist 可证明恶意程序、加密工具、擦除工具的执行与最后使用时间；也可用于判断攻击者是否清理过痕迹（Count 键缺失与其 hive 时间戳矛盾）。
- **反取证检测**：监控 `Explorer\UserAssist` 键被整体删除/清空；与 Prefetch、Amcache、事件日志（4688/Sysmon 1）交叉，UserAssist 缺失但有执行日志即为可疑。
- **防御**：启用进程创建审计与 EDR 遥测（比 UserAssist 更完整）；限制本地管理员对用户 hive 的直接修改；定期采集内存/注册表快照保留证据。
