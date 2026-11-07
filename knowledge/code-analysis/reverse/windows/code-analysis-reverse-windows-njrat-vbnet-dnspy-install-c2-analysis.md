---
id: code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis
title: NjRAT 0.7d VB.NET 客户端 dnSpy 逆向：OK.ko 入口定位安装例程、C2 收发与键盘记录线程
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: njrat-vbnet-dnspy-install-c2-analysis
aliases:
- NjRAT 0.7d Green Edition
- Bladabindi 分析
- OK.ko 入口
- NjRAT INS 安装函数
- NjRAT RC 收包线程
- kq.WRK 键盘记录
- mgr.protect 进程自保
- VB.NET RAT 逆向
tags:
- windows
- malware-analysis
- reverse-engineering
- dotnet
- vbnet
- dnspy
- rat
- njrat
- c2
- persistence
- keylogger
cve: []
severity: medium
confidence: high
affected_versions: NjRAT 0.7d Green Edition（原文分析变种；其他 0.7d 改版方法名可能不同）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T23:10:33+08:00'
  notes: 已对照原文与53张图核对：DIE识别PE32/VB.NET/.NET2.0/NjRAT 0.7D、熵5.575未加壳、sha256匹配；dnSpy main→OK.ko、Interaction.Command写HKCU\di+Sleep(5000)、Mutex(OK.RG)、OK.INS/UNS、OK.RC/kl.WRK/mgr.protect三线程、OK.ENB/DEB、主循环每秒/每5轮MinWorkingSet/每8轮act、SessionEnding+OK.pr(1)、OK.pr类29均与截图一致；C2流量与安装例程细节见另两卡；PoC为行为还原未执行
---

## 一句话结论

NjRAT 0.7d Green Edition 是一个用 VB.NET 编译、依赖 .NET Framework 2.0 的 Win32 GUI 远控客户端；dnSpy 反编译后从 `main()` → `OK.ko()` 入手，可沿着 `OK.INS()`（自复制/持久化/防火墙放行/杀进程/USB 传播）、`OK.RC()`（C2 收包线程）、`kq.WRK()`（键盘记录线程）和 `mgr.protect()`（进程自保线程）四条主线还原其全部落地行为与 Base64 通信方式。

## 原理

- **语言与元数据可读性**：样本被编译为 MSIL 而不是原生机器码，程序集保留完整的类名、方法名和大部分变量名；`main()` 只做一件事——调用 `OK.ko()`。`OK` 是 NjRAT 的全局工作类，后续安装、收包、发送、Base64 编解码都以 `OK.xxx` 静态方法/字段组织。这是 VB.NET RAT 常见结构，反编译成本远低于原生 PE。
- **启动参数与 `di` 标记**：`OK.ko()` 先用 `Interaction.Command()` 判断是否存在命令行参数。带参数启动时在 `HKCU` 写入 `di="!"` 并 `Thread.Sleep(5000)`，再继续安装流程。`di` 既是“已安装/已启动”标记，也可被样本自身用于区分首次运行与副本运行；延迟 5 秒则给父进程（宏、下载器、脚本宿主）留出退出和清理时间。
- **单实例互斥体**：`new Mutex(true, OK.RG, ref createdNew)` 创建命名互斥体；`createdNew` 为假说明已有实例，`ProjectData.EndApp()` 直接退出。`OK.RG` 是编译期生成的随机串，既是互斥体名，也被用作启动目录副本文件名和注册表值名，可作为家族/样本指纹。
- **安装例程 `OK.INS()`**：先取自身路径与文件名（`OK.EXE`/`OK.DR`），把自身复制到 `OK.DR` 指向的目录（Builder 默认 `%TEMP%`），以隐藏窗口方式执行复制体并结束当前进程，完成“从原始投放位置迁移到可写目录”。
- **C2 收发线程 `OK.RC()`**：独立线程建立到 Builder 中配置的 Host:Port 的原始 TCP 连接，读取 C2 下发的文本命令；`OK.ENB`/`OK.DEB` 分别封装 `Convert.ToBase64String` 与 `Convert.FromBase64String`，即协议只在字段级做 Base64，不是加密。
- **键盘记录线程 `kq.WRK()`**：`kl` 类在后台线程中记录击键，C2 下发 `kl` 命令后把日志以 Base64 回传；`kq` 与 `mgr` 均为独立类，便于按 Builder 选项裁剪功能。
- **进程自保 `mgr.protect()`**：当 Builder 勾选 Anti Kill/Protect Process 时启动，结合 `NtSetInformationProcess(..., 29, ...)` 把自身标记为关键进程，使常规结束进程触发蓝屏；并在 `SystemEvents.SessionEnding` 中调用 `OK.pr(1)` 区分正常关机与强制终止。
- **主循环**：`for(;;)` 每秒一轮：`Thread.Sleep(1000)`、`Application.DoEvents()`；每 5 轮把 `MinWorkingSet` 设为 1024 降低内存占用；每 8 轮调用 `OK.ACT()` 读取当前前台窗口标题，与上次缓存比较，变化时发送 `act` + 分隔符 + 标题到 C2；同时周期性复查 HKCU/HKLM Run 键，缺失就重写，形成自修复持久化。

## 触发条件

- 目标为 Windows，安装有 .NET Framework 2.0 及以上；样本为 Win32 PE32 GUI 程序。
- 受害者执行 Builder 生成的客户端 EXE，或经 Office 宏/脚本宿主等投递链拉起。
- 分析者具备 dnSpy（或 ILSpy）与基础 VB.NET/IL 阅读能力；样本未加壳（本例香农熵约 5.57，DIE 识别为 VB.NET、未加壳）。
- 需要动态验证时，准备 Procmon、Wireshark 与隔离虚拟机；关键进程选项已开启的样本不要直接 `taskkill`。

## 利用步骤

（以下为样本行为还原与分析方法，不是在本机执行恶意代码。）

1. **静态识别**：DIE 显示 PE32、Microsoft Visual Basic .NET、.NET Framework 2.0，特征库直接命中 NjRAT 0.7D Green Edition；pestudio 可见 `netsh firewall add allowedprogram`、`taskkill /F /IM`、`svchost.exe`、`shutdown -s -t 00`、Dropbox 密码窃取地址等字符串，熵值低于 5 说明没有压缩壳。
2. **定位入口**：dnSpy 打开程序集，`w.<Module>.main()` 只有一行 `OK.ko();`；双击进入 `OK` 类。
3. **梳理 `ko()`**：确认命令行参数分支、`HKCU\di="!"`、`Thread.Sleep(5000)`、命名互斥体与 `ProjectData.EndApp()` 退出逻辑。
4. **跟进 `INS()`**：读取自复制目标目录/文件名，确认 `File.Copy` → `Process.Start` → `EndApp` 的迁移链；继续展开 `netsh firewall add allowedprogram`、HKCU/HKLM Run、启动目录隐藏副本、`taskkill /F /IM`、盘符遍历写 `svchost.exe`+`autorun.inf`。
5. **展开线程**：在 `ko()` 后半段确认 `new Thread(new ThreadStart(OK.RC))`、`new kl().WRK()`、`new mgr().protect()` 三个线程的启动条件（Builder 勾选项对应 `OK.task` 等字段）。
6. **还原协议**：查看 `OK.ENB`/`OK.DEB` 确认 Base64 封装；结合 Wireshark 抓包确认首包字段、第二包 Base64 受害者信息、`act/kl/pas` 命令与 `CAP|'|'|` JPEG 帧。
7. **动态验证**：Procmon 过滤样本进程，核对 `HKCU\di`、`netsh`、Run 键、启动目录、`taskkill`、盘符写入；Wireshark 过滤 C2 端口，按 `|'|'|` 分隔符拆包并 Base64 解码。

## PoC

无漏洞利用 PoC；以下是可据此识别的反编译调用链（方法名来自样本元数据）：

```text
main()                      // w.<Module>
└─ OK.ko()
   ├─ if (Interaction.Command() != null)
   │    Registry.CurrentUser.SetValue("di", "!"); Thread.Sleep(5000)
   ├─ new Mutex(true, OK.RG, ref createdNew); if (!createdNew) EndApp()
   ├─ OK.INS()              // 自复制 + netsh 防火墙 + Run/启动目录 + taskkill + USB
   ├─ new Thread(OK.RC).Start()          // C2 收包
   ├─ new kl().WRK()  ->  Thread.Start() // 键盘记录
   ├─ if (OK.task) new mgr().protect()   // 进程自保
   └─ for (;;) { Sleep(1000);
        num==5 -> MinWorkingSet = 1024;
        num>=8 -> text=OK.ACT(); if (text != left) OK.Send("act"+sep+text);
        if (OK.Isu) 复查 HKCU/HKLM Run 并重写; }
```

Base64 封装：

```text
ENB(s) = Convert.ToBase64String(SB(s))
DEB(s) = BS(Convert.FromBase64String(s))
```

最小化识别特征（不执行样本）：DIE/pestudio 命中 VB.NET + NjRAT 0.7D；字符串包含 `netsh firewall add allowedprogram`、`taskkill /F /IM`、`svchost.exe`、`autorun.inf`；注册表出现 `HKCU\di` 与随机名 Run 值；启动目录出现与 Run 值同名的隐藏 EXE。

## 变体与关联

- **同源改版**：NjRAT 0.7d 的 Danger/Golden/Green/Lime 等 Edition 共享同一套 `OK` 类与 `INS/RC/WRK/protect` 方法骨架，差异主要在 Builder 配置、字符串与少量功能开关；2013 年源码泄露后衍生版本很多，方法名可能被重命名或混淆。
- **协议变体**：分隔符、端口、首包字段顺序可由 Builder 改变；部分改版把 Base64 换成自定义异或或压缩，需以 `ENB/DEB` 实现为准。
- **投递变体**：本例的 ANY.RUN 参考样本是启用宏的 PowerPoint 插件（`.ppam`），由 `POWERPNT.EXE` 加载宏后释放并拉起后续载荷；与本地直接运行 EXE 相比多一层 Office 宏投递。
- 关联：[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（Remcos 配置资源提取）、[[code-analysis-reverse-anti-debug-critical-process-window-title-av-detection]]（关键进程防杀与反分析组合）、[[defense-forensics-njrat-c2-traffic-base64-decode]]（本样本的流量侧解析）、[[pentest-persistence-njrat-install-firewall-run-startup-usb]]（安装例程的持久化细节）。

## 检测与防御

- **静态特征**：DIE/PEiD 的 NjRAT 0.7D 特征、VB.NET + .NET 2.0、低熵未加壳；pestudio 字符串中的 `netsh firewall add allowedprogram`、`taskkill /F /IM`、`svchost.exe`、`autorun.inf`、Dropbox `Pass.exe` 地址；互斥体/启动项/启动目录共用的随机串 `OK.RG`。
- **主机行为**：非安装程序调用 `netsh firewall add allowedprogram`；进程自复制到 `%TEMP%`、启动目录或盘符根目录并设置隐藏；写 `HKCU\di`；创建 `HKCU\Software\<随机串>` 配置键；`taskkill /F /IM` 结束安全软件；对自身调用 `NtSetInformationProcess` 类 29。
- **网络行为**：原始 TCP 到非标准高端口，首包以 Base64 机器 ID 开头并用 `|'|'|` 分隔明文主机信息；后续出现 `act/kl/pas` 短命令与 `CAP|'|'|` JPEG 帧；DNS 查询/下载 `dl.dropbox.com` 上的 `Pass.exe`。
- **分析防护**：在快照虚拟机中运行；用 dnSpy 静态跟踪优先，动态阶段用 Procmon/Wireshark 交叉验证；已开启关键进程选项的样本用挂起或 PCHunter 清 critical 标志后再结束，避免蓝屏丢失现场。
