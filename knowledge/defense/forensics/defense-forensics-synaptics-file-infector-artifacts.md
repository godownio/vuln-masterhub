---
id: defense-forensics-synaptics-file-infector-artifacts
title: Synaptics/Synares 类文件感染病毒的主机取证：落盘、Run 键、缓存副本与版本伪装
type: scenario
domain: defense
path: defense/forensics
technique: synaptics-file-infector-forensics
aliases:
- Synaptics 病毒
- Synares 病毒
- 蛀虫病毒
- 文件感染型病毒取证
- 感染型病毒排查
tags:
- windows
- malware
- forensics
- file-infector
- persistence
- registry-run
- procmon
- synaptics
- synares
- timestomp
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:58:47+08:00'
  notes: 已对照原文与17张图片核对；Synaptics.exe、HKCU Run键、._cache_花.exe、HD_X.dat/HD_*.exe、版本8.9.8.9/RuntimeBroker、时间戳与ProcMon/火绒日志均有证据；原文末段关于另一安装包的总结与正文不一致且无截图，卡片未收录；仅行为/AV层证据，无二进制逆向。
---

## 一句话结论

Synaptics/Synares 类文件感染病毒会释放 `C:\ProgramData\Synaptics\Synaptics.exe`、写入伪装成 “Synaptics Pointing Device Driver” 的 HKCU Run 自启动项、在样本同目录生成 `._cache_<原名>.exe` 缓存副本，并遍历目录感染 EXE（落 `HD_X.dat`、生成 `HD_xxx.exe`），同时把被感染文件的版本信息改写为 `8.9.8.9`/`RuntimeBroker`、时间戳更新为感染时刻；这些工件可作为主机取证与排查清单。

## 原理

- 文件感染型病毒需要在不破坏宿主可执行性的前提下把自身代码写入目标 PE，并在运行宿主时获得执行机会；为持续感染，它通常保留一份未被感染的“缓存副本”继续运行，同时把原文件替换为感染体。
- 持久化使用用户级 Run 键：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Synaptics Pointing Device Driver`，值为 `C:\ProgramData\Synaptics\Synaptics.exe`，伪装成 Synaptics 触摸板驱动，降低用户警觉。
- 感染时重写 PE 版本资源（文件版本/产品版本 `8.9.8.9`、产品名/版权 `RuntimeBroker`）和文件时间戳，使被感染程序看起来像正常系统组件，且修改时间集中在感染时段。
- 主程序释放 `HD_X.dat` 等数据文件，被感染后的宿主运行时会生成 `HD_<原名>.exe` 等衍生文件；Prefetch 目录会出现对应的 `.pf` 记录，可作为执行痕迹。
- 该类样本常带 VMProtect 等壳；仅靠静态文件类型判断可能不可靠，需结合行为与 AV 日志。

## 触发条件

- Windows 主机执行了被感染的 EXE；
- 样本对用户目录、桌面、`C:\ProgramData` 及目标 EXE 所在目录有写权限；
- 用户级自启动（HKCU Run）未被策略禁用；
- 未部署对文件写入、Run 键与批量 EXE 修改的行为监控。

## 取证步骤

1. 用 Process Monitor 过滤样本进程，记录 `CreateFile`/`WriteFile`/`SetBasicInformationFile`/`RegSetValue` 等事件；确认释放路径与注册表写入。
2. 检查 `C:\ProgramData\Synaptics\`：是否存在 `Synaptics.exe` 与空的 `WS` 子目录；对比 AV 告警中的路径与哈希。
3. 查询 HKCU Run 键，确认是否存在名为 `Synaptics Pointing Device Driver`、值为 `C:\ProgramData\Synaptics\Synaptics.exe` 的项。
4. 在样本同目录、桌面及常用目录查找 `._cache_<原名>.exe`；这类缓存副本通常与原始样本同大小或近似大小。
5. 在 `%TEMP%`、桌面及感染目录查找 `HD_*.dat`、`HD_*.exe`、`hd.log` 等衍生文件；在 `C:\Windows\Prefetch` 查找 `HD_*.pf`、`._CACHE_*.pf` 执行痕迹。
6. 批量检查 EXE 的文件版本/产品名（是否变为 `8.9.8.9`/`RuntimeBroker`）与修改时间（是否集中在同一时段），并计算哈希；不要直接运行疑似被感染文件。
7. 结合火绒等 AV 日志中的病毒名（如 `Virus/Synares.a$SA`）、处理结果与进程链，确认感染范围。
8. 隔离主机，使用干净介质离线扫描；从可信备份恢复被感染文件，清除 Run 键与释放目录，重置用户口令并排查横向移动。

## PoC

无 PoC（行为取证场景）。常用排查命令：

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Synaptics Pointing Device Driver"
Get-ChildItem C:\ProgramData\Synaptics -Force -Recurse
Get-ChildItem C:\Users -Recurse -Force -Filter "._cache_*.exe" -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Force -Filter "HD_*"
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" | Where-Object Name -match 'HD_|_CACHE_'
```

```powershell
# 批量检查版本资源与修改时间（示例）
Get-ChildItem C:\Users -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
  ForEach-Object {
    $v = $_.VersionInfo
    if ($v.FileVersion -eq '8.9.8.9' -or $v.ProductName -eq 'RuntimeBroker') {
      [pscustomobject]@{Path=$_.FullName; Modified=$_.LastWriteTime; Version=$v.FileVersion}
    }
  }
```

## 变体与关联

- 同类文件感染型病毒（如 Neshta、Parite、Virut）也会批量感染 EXE、写入自启动项并伪装版本信息；具体落盘路径与缓存命名可能不同。
- 变种可能通过 U 盘、共享目录或压缩包传播；排查时应覆盖可移动介质与网络共享。
- 关联：Windows 持久化排查、ProcMon 行为取证、PE 版本资源异常检测、批量文件完整性校验。
- 边界：本卡基于行为监控与 AV 日志，未做二进制级逆向；不同变种的释放路径、注册表键名、衍生文件名可能变化，需结合哈希与 AV 命名交叉确认。

## 检测与防御

- 检测：监控 `C:\ProgramData\Synaptics\Synaptics.exe` 的创建、HKCU Run 中伪装成 Synaptics 的项、样本同目录 `._cache_*.exe`、`%TEMP%` 下 `HD_*` 文件，以及短时间内大量 EXE 的修改时间/版本资源变化。
- 检测：Prefetch 中出现 `HD_*.pf`、`._CACHE_*.pf`；AV 日志出现 `Virus/Synares` 类命名；进程链中样本释放并执行同名缓存副本。
- 防御：禁止普通用户对 ProgramData 与安装目录的任意写入；启用应用控制/白名单，阻止未签名 EXE 执行；定期校验关键 EXE 的哈希与版本资源。
- 处置：隔离主机、离线全盘扫描、从可信备份恢复被感染文件；清除 Run 键和释放目录；检查是否存在其它持久化与横向移动痕迹。
