---
id: defense-detection-agenttesla-web-panel-stealer-behavior-ioc
title: AgentTesla 变体（Web Panel 回传）：多阶段 .NET 加载后反调试/反沙箱、终端窃密与 %APPDATA%\Adobe 自启动检测
type: scenario
domain: defense
path: defense/detection
technique: agenttesla-web-panel-stealer-detection
aliases:
- AgentTesla 检测
- AgentTesla Web Panel
- Zhrp.exe
- bfb5da9f-48ba-40d7-85d4-7ec204e8e6d3.exe
- Adobe.exe 自启动
- AgentTesla IOC
- 窃密木马 Web Panel 回传
tags:
- malware
- agenttesla
- stealer
- rat
- dotnet
- detection
- ioc
- persistence
- exfiltration
- anti-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:58:22+08:00'
  notes: 已逐张核对全部 51 张图：01-04 AgentTesla 3.2.9 安装/凭据/通信/杀软测试；05-06 混淆与去混淆代码；07 off 资源解密循环（first 13B+second 9B=22B 滚动 key，异或后减后一字节）；08/09 SimpleLogin.dll（MD5 DAD76A...）；10-11 first/second 数组与解密代码；12 Justy 参数 6643416A/687077/AndroidSignTool；13 Key0 GZIP；14-15 ReactionVessel/CausalitySource 调用；16-18 fCAj/hpw 与 hex→ascii；19 SearchResult 解密；20-22 fCAj 位图→Tyrone.dll PE；23-24 Assembly.Load 与 gfjFseo7ilTwA8Y0nJ.Oex9YxVO6h；25 配置串；26 计划任务 XSYZHcH→AppData\Roaming\XSYZHcH.exe；27-30 PVrTN→bfb5da9f...exe（MD5 ABE56...）与解密算法；31-33 CreateProcessA/WriteProcessMemory/GetThreadContext/SetThreadContext/ResumeThread；34 单实例杀进程；35-36 api.ipify.org；37 CheckRemoteDebuggerPresent；38-39 ip-api.com/line/?fields=hosting（截图为 http）；40 Thread.Sleep(10)+Ticks 差值；41 cmdvrt32/SbieDll/Sf2/snxhkj DLL；42 WMI VIRTUAL/vmware/VirtualBox；43 calc.exe 下载；44-45 %APPDATA%\Adobe\Adobe.exe 与 Run/StartupApproved 键；46 配置项；47 键盘特殊键；48 CopyFromScreen；49 浏览器列表；50 剪贴板；51 POST dancingtutorial 面板。修正：原理与 PoC 中 ip-api.com 由 https 改为截图所示 http。dedup
    唯一 related 为 eBPF 运行时检测框架（cos 0.8867），非同一检测特征集；dup-scan 与 14416 AgentTesla 阶段 DLL 解密卡为 related（检测行为 vs 脱壳还原），均保留。路径 defense/detection 合法。未验证点：未运行样本；IOC 为原文节选（BQc 块部分哈希未列入）；样本无组件版本故 affected_versions 为空。无 sources/source_url。
---

## 一句话结论

AgentTesla 最新变体（样本 Zhrp.exe → SimpleLogin.dll → Gamma.dll → Tyrone.dll → bfb5da9f-48ba-40d7-85d4-7ec204e8e6d3.exe）在内存中多阶段释放最终窃密载荷后，会做 `CheckRemoteDebuggerPresent`/`ip-api.com` 托管商检测/`cmdvrt32.dll` 等沙箱 DLL 检查/WMI 虚拟机检测与计时器休眠，复制自身到 `%APPDATA%\Adobe\Adobe.exe` 并写 `HKCU\...\Run` 的 `Adobe` 项（另有计划任务 `XSYZHcH`），窃取键盘、屏幕、剪贴板与多款浏览器凭证，最后 POST 到 `https://dancingtutorial.com.ng/blackmarket/inc/ed02af730792a8.php` 等 Web Panel；检测可围绕这些文件/注册表/网络/进程与 IOC 特征。

## 原理

- **加载链（简要）**：Zhrp.exe 用 de4dot 去混淆后从资源 `off` 解出 SimpleLogin.dll（22 字节滚动 key 异或+减后一字节）；SimpleLogin.dll 从资源 `Key0` GZIP 解出 Gamma.dll；Gamma.dll 的 `SearchResult` 用 `hpw` 解密从位图资源 `fCAj` 中隐写的 Tyrone.dll；Tyrone.dll 从资源 `PVrTN` 解出最终 `bfb5da9f-...exe` 并以挂起方式 `CreateProcessA` + `VirtualAllocEx`/`WriteProcessMemory`/`SetThreadContext`/`ResumeThread` 做进程替换。加载链细节另见关联卡。
- **单实例与自身清理**：最终载荷启动后枚举同名进程并杀掉其它实例（`Process.GetProcessesByName(...).Kill()`），避免多次运行互相干扰。
- **反分析/反沙箱**：
  - `CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref flag)` 判断远程调试；
  - 请求 `http://ip-api.com/line/?fields=hosting`，含 `true` 视为托管/数据中心 IP，直接退出或改变行为；
  - 通过 `Win32_ComputerSystem` 的 `Manufacturer`/`Model` 包含 `VIRTUAL`/`VMWARE`/`VirtualBox`、`Win32_VideoController` 名称含 `VMware`/`VirtualBox` 判断虚拟机；
  - 加载/检查 `cmdvrt32.dll`（Comodo）、`SbieDll.dll`（Sandboxie）、`Sf2.dll`、`snxhk.dll`（Avast）等沙箱/杀软注入 DLL；
  - `Thread.Sleep(10)` 后比较 `DateTime.Now.Ticks`，差值过小说明时间被加速，判断沙箱；
  - 访问 `https://api.ipify.org` 获取公网 IP，用于回传标记受害者。
- **下载与自启动**：从 `https://mzcomedy.com.ng/wp/wp-content/uploads/calc.exe` 下载到 `%TEMP%\calc.exe` 并执行（原文实际已失效）；把宿主复制到 `%APPDATA%\Adobe\Adobe.exe`，写 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Adobe` 指向该路径（并写 `StartupApproved\Run` 的允许值）；Tyrone.dll 阶段还会复制到 `%APPDATA%` 并创建计划任务 `XSYZHcH`。
- **窃密与回传**：内置配置控制键记录（`EnableKeylogger`、`EnableScreenLogger`、`EnableClipboardLogger` 等），截屏用 GDI `CopyFromScreen`，键盘记录把按键转成 `[BACK]`/`[DEL]`/`[Insert]`/`[ALT+TAB]`/`[NumLock]`/`[F12]` 等标记；浏览器凭证目标覆盖 Chrome/Chromium/Edge/Opera/Firefox/Brave/360 等 40 余款。数据以 `p=<序列化字段>` 形式 POST 到 Web Panel（原文 `dancingtutorial.com.ng/.../ed02af730792a8.php`，另有 `mailx.org.ng/.../812961c72ca62b.php`）。
- **为什么可检测**：这些行为在终端上有稳定落点——特定文件路径、Run 键值、计划任务名、WMI/网络查询、浏览器数据库/Login Data 访问、异常 POST 到低信誉域名；即使加载链每层都加密，运行时行为和网络仍暴露。

## 触发条件

（检测/狩猎的适用条件）

- 具备终端遥测：Sysmon/EDR 进程创建、文件写入、注册表、网络连接（含 DNS/HTTP），或可对样本做动态分析。
- 能采集 `%APPDATA%\Adobe\Adobe.exe`、计划任务、Run 键、浏览器配置目录访问等证据。
- 有网络侧日志（代理/DNS/防火墙）可匹配 Web Panel 域名/IP 与 `api.ipify.org`、`ip-api.com` 查询。
- 样本/主机处于授权分析或应急响应范围；不要在生产主机执行样本。

## 利用步骤

（检测与排查步骤）

1. 进程/文件：查 `%APPDATA%\Adobe\Adobe.exe` 是否存在、创建时间与签名；查 `%TEMP%\calc.exe` 及异常下载文件；查同名进程多实例与父进程链（Office/压缩包/邮件附件释放的 Zhrp/IhKL/txEV/BQc 等）。
2. 自启动：检查 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 的 `Adobe` 值、`StartupApproved\Run` 对应项，以及计划任务 `XSYZHcH`（动作指向 `%APPDATA%\...\*.exe`）。
3. 网络：检索对 `api.ipify.org`、`ip-api.com/line/?fields=hosting` 的请求，及对 Web Panel 路径（`/blackmarket/inc/*.php`、`/original/inc/*.php`）的 POST；核对域名 `dancingtutorial.com.ng`、`mailx.org.ng`、`mzcomedy.com.ng`。
4. 行为：查浏览器 `Login Data`/`cookies`/`Web Data` 等文件的异常读取、GDI 截屏、`CheckRemoteDebuggerPresent` 调用、WMI `Win32_ComputerSystem`/`Win32_VideoController` 查询与沙箱 DLL 加载。
5. IOC 匹配：用样本 MD5/URL/域名做全网狩猎（IOC 见 PoC）。
6. 处置：隔离主机、删除自启动与计划任务、重置被盗浏览器/邮箱/FTP/WiFi 凭据、封禁 Web Panel 与下载域名。

## PoC

IOC（原文）：

```text
# Zhrp.exe            F8C9DFD7934FF3F3688E61D599A15424
# IhKL.exe            6EF956ED9F5E1FF71A1E484902A6D1A5
# txEV.exe            ACE7F45CC6EEED16FC511CDA50BDD226
# BQc.exe             7EF2ACB1BC18A7F27832AED85092C0B5
# SimpleLogin.dll     9E4AEA62EE76EFB9013E6440AFD8FFE6 / DAD76A28B6FC51471A1A834C6524E806
# Gamma.dll           E4B5D57E9E46A4E76075B5B92F71577F / 28B43A10958CAEF0465F7B93BE0A0D77
# Tyrone.dll          DD277CD241B6D02B873DA7D0AFA6D2A4 / F68A6DB52DD1425A4E7F0326277111F6
# final payload       ABE56DDEE7C45D74EA2A4416DA6387A4
# download            https://mzcomedy.com.ng/wp/wp-content/uploads/calc.exe
# Web Panel           https://dancingtutorial.com.ng/blackmarket/inc/ed02af730792a8.php
# Web Panel 2         https://mailx.org.ng/original/inc/812961c72ca62b.php
```

关键命令/行为（检测点）：

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Adobe = %APPDATA%\Adobe\Adobe.exe
计划任务 XSYZHcH -> C:\Users\<user>\AppData\Roaming\XSYZHcH.exe
GET https://api.ipify.org
GET http://ip-api.com/line/?fields=hosting
POST https://dancingtutorial.com.ng/blackmarket/inc/ed02af730792a8.php   body: p=...
```

## 变体与关联

- 加载链还原（SimpleLogin/Gamma 解密、Bitmap 资源、多阶段 Assembly.Load）见 `code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive` 与 `code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump`。
- 反调试/反沙箱通用手法见 `code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum`、`code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks`。
- 同类窃密木马检测：RedLine（`defense-detection-redline-stealer-yara-pe-strings`）、AMOS（macOS）等；本卡的差异是 AgentTesla 的 `%APPDATA%\Adobe\Adobe.exe`/Run 键与 Web Panel 路径特征。
- 进程替换（CreateProcess 挂起 + WriteProcessMemory + SetThreadContext）的通用实现见 C2 注入/镂空相关卡。

## 检测与防御

- 终端：启用 Sysmon/EDR 并对上述文件路径、Run 键、计划任务、浏览器数据库访问、WMI 查询建立规则；限制 `%APPDATA%` 与 `%TEMP%` 可执行文件运行（AppLocker/WDAC）。
- 网络：封禁 IOC 域名/URL，监控 `api.ipify.org`、`ip-api.com` 与低信誉 PHP Web Panel 的 POST；启用 DNS 日志与 TLS SNI 检测。
- 账号：发现感染后立即重置浏览器保存的密码、邮箱/FTP/VPN/WiFi 凭据，检查邮箱异常登录。
- 邮件/投递：拦截带 Office 宏、压缩包内可执行文件、快捷方式的附件；对下载的 `calc.exe` 类伪装文件做沙箱分析。
- 检测验证：用 IOC 与行为规则在历史日志中回溯；对 `Adobe.exe` 做哈希/签名/PE 检查，避免误报合法 Adobe 组件。
