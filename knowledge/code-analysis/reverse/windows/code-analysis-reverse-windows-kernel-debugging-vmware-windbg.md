---
id: code-analysis-reverse-windows-kernel-debugging-vmware-windbg
title: VMware 串口命名管道 + bcdedit 搭建双机内核调试环境（WinDbg 连接）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windbg-dual-machine-kernel-debugging
aliases:
- 双机内核调试
- WinDbg 内核调试
- bcdedit dbgsettings SERIAL
- VMware 串口命名管道
- COM1 named pipe
- Windows kernel debugging setup
tags:
- reverse-engineering
- windows
- kernel
- windbg
- vmware
- bcdedit
- debugging
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:53:36+08:00'
  notes: 已对照原文与 img/02-10 核对：移除打印机、添加串行端口、VMware 命名管道 \.\pipe\com_1 且虚拟机端为服务器/另一端为应用程序、msconfig 调试 COM1+115200、WinDbg COM Pipe 115200 + Break on connection 均与原文一致；bcdedit 命令与原文逐条一致。原文未给受影响版本，非漏洞卡，未设 affected_versions；命令未执行。
---

## 一句话结论

把 VMware 虚拟机的串口设备映射到主机命名管道 `\\.\pipe\com_1`，再用 `bcdedit` 打开内核调试并复制一个专用 Debug 启动项，主机新版 WinDbg 通过 COM/Pipe 连接该管道，就能在目标虚拟机启动早期接管内核、下断并查看驱动与通知回调。

## 原理

- Windows 内核调试（KD）通过调试传输层把内核事件发给调试器；串口调试时目标机把 KD 包写到 `COM1`，主机调试器从对应串口/命名管道读取。VMware 的“使用命名的管道”把虚拟串口的两端拆成“虚拟机端（服务器）”与“主机应用端”，因此主机 WinDbg 只需连接同名管道。
- `bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200` 在启动配置数据库（BCD）中写入调试传输参数；`bcdedit /debug {GUID} on` 只对指定启动项开启内核调试，避免影响正常启动项。
- `bcdedit /copy {current} /d "Debug"` 复制当前启动项并返回新 GUID，配合 `bootmenupolicy Legacy` 让开机时出现传统启动菜单，手动选择 Debug 项进入被调试状态。
- 调试器连接成功后，目标机内核在启动时等待调试器，WinDbg 可加载 `nt` 与驱动符号，使用 `u`、`dq`、`dps` 等命令查看内核数据结构与回调注册表。

## 触发条件

- 目标为 VMware 虚拟机中的 Windows（文章环境：主机 Windows 11，虚拟机 Windows 10）。
- 主机安装新版 WinDbg（旧版对串口/管道支持不佳），并以管理员权限运行。
- 能修改虚拟机硬件（移除打印机、添加串口）、能修改目标机 BCD 并重启。
- 目标机与主机之间可建立本地命名管道；调试串口参数两端一致（COM1、115200）。

## 利用步骤

1. 关闭虚拟机，在虚拟机设置中移除打印机（文章指出不移除会占用设备位置）。
2. 添加硬件 → 串行端口；连接方式选“使用命名的管道”，管道名填 `\\.\pipe\com_1`，虚拟机端为“该端是服务器”，另一端为“应用程序”。
3. 启动虚拟机，以管理员身份打开命令提示符，设置传统启动菜单与串口调试参数：
   ```bat
   bcdedit /set "{current}" bootmenupolicy Legacy
   bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200
   bcdedit /copy "{current}" /d "Debug"
   ```
4. 记下 `bcdedit /copy` 返回的 GUID，对复制出的启动项开启调试：
   ```bat
   bcdedit /debug "{返回的GUID}" on
   ```
5. 运行 `msconfig` → 引导 → 选中 Debug 项 → 高级选项，确认“调试”勾选、调试端口 COM1、波特率 115200（与 bcdedit 参数一致）。
6. 主机打开新版 WinDbg → Kernel Debug → COM 选项卡，勾选 Pipe，Port 填 `\\.\pipe\com_1`，Baud Rate 115200，勾选 Break on connection，点击连接。
7. 重启虚拟机，在启动菜单选择 Debug；WinDbg 显示 `connect` 即连接成功，可用 `kd>` 命令开始分析。

## PoC

```bat
:: 目标虚拟机内（管理员）
bcdedit /set "{current}" bootmenupolicy Legacy
bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200
bcdedit /copy "{current}" /d "Debug"
bcdedit /debug "{上一步返回的GUID}" on
msconfig
```

```text
WinDbg (new version) → Kernel Debug → COM
  [x] Pipe
  Port:       \\.\pipe\com_1
  Baud Rate:  115200
  [x] Break on connection
```

```text
连接成功后的提示（示例）
Connected to Windows 10 ... target machine
kd>
```

## 变体与关联

- 变体：WinDbg 的 COM 页提示串口内核调试“不推荐”，网络内核调试（KDNET）更快更稳定；若目标与主机网络互通，可改用 `bcdedit /dbgsettings NET HOSTIP:<host> PORT:<port> KEY:<key>` 并在 WinDbg 的 Net 页连接。
- 变体：虚拟机端/应用端角色、管道名两端必须匹配；管道名不一致或权限不足会连不上，WinDbg 会提示需要提权。
- 变体：不复制启动项而直接对 `{current}` 开启调试也能连，但每次正常启动都会等待调试器，建议保留独立 Debug 项。
- 边界：目标机启用 Secure Boot/某些虚拟化安全功能时，内核调试可能受限；生产机不应长期保留调试启动项。
- 关联：[[code-analysis-reverse-windows-process-notify-callback-analysis]]、[[code-analysis-reverse-windows-thread-notify-callback-analysis]]（用本环境枚举并分析杀软回调）。

## 检测与防御

- 检测：`bcdedit /enum {current}`、`bcdedit /dbgsettings` 可看到 debug 是否开启及串口参数；BCD 中出现名为 Debug 的额外启动项、`debug` 值为 on、`bootmenupolicy` 被改为 Legacy，都是可疑迹象；虚拟机配置中出现命名管道串口也值得审计。
- 修复：生产环境保持 `bcdedit /debug off` 并删除多余调试启动项；限制管理员对 BCD 的修改权限；虚拟机模板不要保留调试串口。
- 加固：监控 `bcdedit` 与 BCD 注册表变更；内核调试会暴露内核内存与调试接口，应在用完即关，避免长期开启。
