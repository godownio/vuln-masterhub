---
id: code-analysis-reverse-windows-swift-ransomware-startup-wallpaper-oeminfo-legalnotice
title: SWIFT 勒索软件持久化与勒索展示：启动目录 [ID].exe、ProgramData 壁纸、OEMInformation/legalnotice 注册表
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: swift-ransomware-startup-wallpaper-oeminfo-legalnotice
tags:
- windows
- ransomware
- persistence
- startup-folder
- wallpaper
- oeminformation
- legalnotice
- registry
- malware-analysis
- swift
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:14:35+08:00'
  notes: 已对照原文全文与32张截图逐张核对：GetKeyboardLayoutList 1065退出(img02)、互斥体GUID(img03)、CopyFileW到Startup img11、ProgramData <ID>.bmp 5.8MB壁纸(img27/28)、OEMInformation Manifest/SupportPhone(img30)、Policies\System legalnoticecaption/legalnoticetext(img29)、#SWIFT-Help.txt 2KB(img19/20/25)、ShellExecuteW open(img31)。前置vssadmin/bcdedit/wmic命令与原文一致。未执行样本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-swift-ransomware-startup-wallpaper-oeminfo-legalnotice/
draft: false
kb_aliases:
- SWIFT 勒索壁纸
- OEMInformation 勒索信息
- legalnotice 勒索
- 启动目录 [ID].exe
- '#SWIFT-Help.txt'
- 勒索软件注册表展示
---

## 一句话结论

SWIFT 勒索样本在加密前后用一整套 Windows 原生机制持续展示勒索信息：把自身复制到 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<ID>.exe` 实现登录自启；在 `C:\ProgramData\<ID>.bmp` 生成勒索壁纸并替换桌面背景；把勒索文本写入 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation` 的 `Manifest`/`SupportPhone` 与 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` 的 `legalnoticecaption`/`legalnoticetext`；最后 `ShellExecuteW("open")` 打开 `#SWIFT-Help.txt`。

## 原理

- **启动目录持久化**：样本把自身复制到当前用户的 Startup 目录，命名为此前生成的 `[ID].exe`。登录时 Explorer 会执行该目录下的可执行文件，样本得以在重启后再次运行；与注册表 Run 键相比，启动目录文件更直观，也常被 EDR 作为高价值监控点。
- **壁纸替换**：样本在 `C:\ProgramData` 生成 `<ID>.bmp`（截图约 5.8MB），通过系统 API/注册表把桌面背景指向该图。壁纸是用户每次登录都会看到的持久展示面，不依赖勒索信文件是否被删除。
- **OEMInformation 注册表**：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation` 的 `Manifest`（REG_SZ）被写成 `~~~ SWIFT ~~~`，`SupportPhone`（REG_SZ）被写成整段勒索说明（含 `swift_1@tutamail.com`、备用邮箱 `swift@onionmail.com`、受害者 ID）。该位置通常用于 OEM 厂商信息，系统属性/关于页面会展示，用户不易察觉被篡改。
- **legalnotice 注册表**：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` 的 `legalnoticecaption`/`legalnoticetext` 被写成勒索标题与正文。Windows 会在用户登录时弹出“法律声明”对话框展示这两项，形成强制可见的勒索入口。
- **勒索信文件**：目录中写入 `#SWIFT-Help.txt`（约 2KB），内容包含 “What happened/How to recover/What guarantees/How to contact” 与个人 ID；样本通过 `ShellExecuteW` 以 `open` 动作弹出记事本展示。
- **前置行为配合**：样本先检查键盘布局语言 ID（`GetKeyboardLayoutList`，`LOWORD == 1065` 即 0x429 波斯语时 `ExitProcess`），再创建互斥体 `48991369-7C7C-47AA-A81E-EF6ED1F5E24C` 保证单实例；随后清空回收站、用 `vssadmin Delete Shadows /All /Quiet`、`bcdedit /set {default} recoveryenabled No`、`bcdedit /set {default} bootstatuspolicy ignoreallfailures`、`wmic SHADOWCOPY /nointeractive` 破坏恢复能力，并终止数据库/备份/杀软进程、停止依赖服务，最后遍历磁盘与共享目录加密。
- **为什么有效**：这些展示面都是 Windows 原生、无需额外组件、权限足够即可写入；即使受害者删除 `#SWIFT-Help.txt`，壁纸、OEM 信息与登录法律声明仍会持续提示，增加联系攻击者的概率。

## 触发条件

- 样本以管理员/SYSTEM 权限运行（写 HKLM 注册表、替换系统壁纸、复制到 Startup 需要相应用户权限）。
- 目标为 Windows 主机，`ProgramData` 与当前用户 Startup 目录可写。
- 系统未对 OEMInformation/Policies\System 注册表键做完整性监控，未限制壁纸修改。
- 受害者登录交互式桌面（壁纸与法律声明才会展示）。

## 利用步骤

1. 生成受害者 ID，把自身复制到 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<ID>.exe`。
2. 在 `C:\ProgramData` 生成 `<ID>.bmp` 勒索壁纸并设置为桌面背景。
3. 写入 `HKLM\...\OEMInformation` 的 `Manifest`/`SupportPhone`，以及 `HKLM\...\Policies\System` 的 `legalnoticecaption`/`legalnoticetext`。
4. 在目标目录写入 `#SWIFT-Help.txt`，用 `ShellExecuteW("open")` 打开。
5. 配合前置反恢复命令与进程/服务终止，进入文件加密阶段。

## PoC

原文为样本逆向，无武器化 PoC。关键注册表与路径（仅作检测/复盘参考）：

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<ID>.exe
C:\ProgramData\<ID>.bmp
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation
    Manifest      = "~~~ SWIFT ~~~"
    SupportPhone  = "We encrypted and stolen all of your files.Our email address: swift_1@tutamail.com..."
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    legalnoticecaption = "~~~ SWIFT ~~~"
    legalnoticetext    = "We encrypted and stolen all of your files..."
#SWIFT-Help.txt（2KB）
```

前置命令（截图可见）：

```text
vssadmin Delete Shadows /All /Quiet
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
wmic SHADOWCOPY /nointeractive
```

## 变体与关联

- 关联：GhostLocker 2.0 同样使用 Startup 目录持久化并在桌面写 `Ransomnote.html` 后 `cmd /c start` 打开，见 `defense-detection-ghostlocker2-go-ransomware-behavior-ioc`；本样本的差异是额外使用壁纸与 OEMInformation/legalnotice 注册表。
- 关联：勒索前置反取证（删除卷影、禁用恢复、停备份服务）的通用行为与检测见 `defense-incident-response-ransomware-pre-encryption-cleanup`，本卡的 `vssadmin`/`bcdedit`/`wmic` 命令属于该场景的变体。
- 变体：展示面可换成 `HKCU\Control Panel\Desktop\Wallpaper`、桌面快捷方式、计划任务弹窗、`legalnotice` 等。

## 检测与防御

- 检测：Startup 目录新增 `<ID>.exe`；`C:\ProgramData` 新增 `<ID>.bmp`；注册表 `OEMInformation\Manifest`/`SupportPhone` 与 `Policies\System\legalnoticecaption`/`legalnoticetext` 被改写为非厂商内容；目录中出现 `#SWIFT-Help.txt`。
- 检测：`vssadmin Delete Shadows`、`wmic SHADOWCOPY`、`bcdedit recoveryenabled` 等高权限命令的进程创建链；短时间内大量进程被 `TerminateProcess`、服务被 `ControlService` 停止。
- 防御：限制普通用户/非管理员服务账户写 HKLM OEMInformation 与 Policies\System；对启动目录、壁纸与法律声明键做完整性监控；离线备份与快速隔离。
