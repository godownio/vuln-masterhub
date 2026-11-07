---
id: code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation
title: 银狐样本 CEF Helper 白加黑：512MB 文件膨胀、导出表伪造与 TLS/CFF 反分析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-cef-dll-sideload-file-inflation
aliases:
- 银狐样本
- pcRFjwAb.exe
- libcef.dll
- Webview Helper
- 白加黑 DLL 侧加载
- 文件膨胀 File Inflation
- CEF Helper 侧加载
tags:
- windows
- malware-analysis
- silverfox
- dll-sideloading
- file-inflation
- anti-sandbox
- control-flow-flattening
- tls-callback
- service-persistence
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:54:29+08:00'
  notes: 已对照全文与 7 张图片核对：事件 1074 SYSTEM 关机、C:\Users\Public\Videos\5933Xnen 落地、libcef.dll 524345KB/604KB exe、PID 8872 Session0 + 20020 Session1、192.229.116.49:30003 ESTABLISHED、威胁情报银狐标签、Autoruns Webview Helper 服务与隐藏目录均吻合；README/View.conf 解密与多记事本现象原文未还原，卡片已明确标注为未证实，未当作事实。样本未执行
---

## 一句话结论

银狐（SilverFox）样本把合法的 JetBrains CEF Helper（伪装名 `pcRFjwAb.exe`，服务名 `Webview Helper`）放在可写的 `C:\Users\Public\Videos\<随机目录>` 中，借助同目录恶意 `libcef.dll` 完成 DLL 侧加载；恶意 DLL 用 512MB 文件膨胀、38 个伪造导出（11 个关键函数仅 `retn`）、MinGW 编译、CFF 控制流平坦化、TLS 回调与父进程看门狗对抗沙箱/杀软/分析，最后以 Windows 服务 SYSTEM 权限驻留并连接 C2。

## 原理

- **DLL 侧加载（白加黑）**：Windows 加载器优先从可执行文件所在目录按名称解析依赖 DLL。样本使用带合法签名/版本信息的 CEF Helper 作为白宿主，加载同目录的 `libcef.dll`；杀软与用户看到的是可信程序的签名与描述，容易放行。
- **导出表伪造维持宿主运行**：白宿主导入 38 个 `libcef.dll` 导出函数。恶意 DLL 导出了完全同名的 38 个函数，其中 11 个关键函数（`cef_execute_process`、`cef_get_path`、`cef_log` 等）全部指向同一地址 `0x180003B40`，该地址只有一条 `retn`——空壳实现，仅用于满足导入表、避免宿主启动失败。宿主还会调用 `cef_api_hash(0)` 并把返回值与硬编码 `504dbb53deeebd11a16ea01533c5d9ecfa6be555` 比较；恶意 DLL 返回该值通过校验，恶意逻辑则可能藏在 `cef_api_hash`、`DllMain` 或 TLS 回调中。
- **文件膨胀（File Inflation/Pumping）**：恶意 DLL 的 `.text` 段声明为 `0x20008000`（512MB），但真实有效代码仅 67 个函数，其余为填充数据。目的是超过杀软/沙箱的文件大小扫描阈值（很多沙箱默认跳过 >100MB 文件）、增加上传在线分析平台的时间与成本、拖慢 IDA 等工具的加载。受害机上 `libcef.dll` 为 524,345 KB；沙箱中释放的同名 DLL 只有 102MB 且 MD5 不同，说明投放器会按环境改变文件大小或样本存在多个变体。
- **编译器差异化**：白宿主由 MSVC 编译，恶意 DLL 由 MinGW-w64（GCC）编译。大量针对 MSVC 的 PE 启发式规则（入口点、异常处理表、CRT 初始化特征）对 MinGW 样本命中率下降，属于低成本绕过。
- **控制流平坦化（CFF）**：`cef_api_hash` 仅返回一个哈希字符串却膨胀到 1551 字节、106 个基本块；`DllMain`、`sub_180001BC0`（2413 字节、98 块）、`sub_180002530`（1501 字节、58 块）均使用 switch-case 状态机和魔数（如 3689580290、-605387006）打散真实控制流，显著拉长静态分析时间。
- **TLS 回调前置执行**：DLL 注册了两个 TLS 回调，在 `DllMain` 之前运行；`TlsCallback_0` 在 `DLL_PROCESS_ATTACH` 时执行初始化。未模拟 TLS 回调的沙箱/调试器会漏掉这段行为。初始化链还使用 `VirtualProtect` 修改内存页为可执行（为内存 shellcode 做准备）、`Sleep(0x3E8)` 循环等待、`VirtualQuery` 查询页属性、`_InterlockedCompareExchange64` 做线程安全初始化锁。
- **父进程看门狗自清理**：EXE 启动后先用 `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` 遍历进程找到自身父进程 PID，再以 `SYNCHRONIZE` 权限 `OpenProcess` 父进程句柄，`_beginthreadex` 创建监控线程执行 `WaitForSingleObject(父进程句柄, INFINITE)`；父进程退出（被杀软拦截或人工关闭）后立即 `ExitProcess(0)`。这样木马不会作为孤儿进程留在任务管理器里，也增加沙箱关联分析难度。
- **落地与持久化**：样本落在 `C:\Users\Public\Videos\5933Xnen`。`C:\Users\Public` 是所有用户可写的目录，写入不会触发 UAC，类似 Linux 的 `/tmp`；`Videos` 子目录和随机 8 位字母文件名进一步降低肉眼可疑度。目录被设置系统/隐藏属性（`+s +a +h`），默认资源管理器不可见，`attrib -s -a -h` 才显示。持久化通过创建名为 `Webview Helper` 的 Windows 服务实现，服务路径直接指向 `C:\Users\Public\Videos\5933Xnen\pcRFjwAb.exe`，由 SCM 在开机时以 `NT AUTHORITY\SYSTEM`（Session 0）拉起，先于用户登录连接 C2。
- **载荷分离**：核心远控代码与配置不在 DLL 中，而是放在两个二进制伪装文件里：`View.conf`（约 510B，疑似加密 C2 配置/密钥）与 `README.md`（约 281KB，内容为二进制而非 Markdown）。README 的分段结构与解密方式目前未还原；所谓“打开 README 弹出多个记事本”的原因也没有定论，卡内不把任何推测当作事实。
- **网络与家族特征**：受害机上 `pcRFjwAb.exe` 有两个实例，PID 8872 位于 Session 0（服务），PID 20020 位于 Session 1（用户桌面）；PID 20020 建立 `192.168.1.16:49369 -> 192.229.116.49:30003` 的 ESTABLISHED 连接，威胁情报将该 IP 标记为恶意，标签包含远控、黑产团伙、银狐。事件日志 1074 显示 `pcRFjwAb.exe` 以 `NT AUTHORITY\SYSTEM` 身份发起关机。

## 触发条件

- 受害者为 Windows 主机，攻击者可向其可写目录投放白宿主 + 恶意 DLL，或通过钓鱼包/下载器释放。
- 白宿主从自身目录加载 `libcef.dll`，且宿主导入的函数能被恶意 DLL 以同名导出满足。
- 恶意 DLL 的大小/结构能绕过目标杀软或沙箱的扫描阈值；宿主可执行文件带合法签名或版本信息，能通过信誉检查。
- 攻击者已获得管理员权限（用于创建 SYSTEM 服务持久化）；初始落地本身只需普通用户可写的 `C:\Users\Public`。
- 主机能访问 C2（本例 `192.229.116.49:30003`）。
- 分析侧触发条件：需要样本文件与隔离环境；完整载荷解密需要动态调试或找到 `View.conf`/`README.md` 的密钥。

## 利用步骤

1. 准备白宿主：选择会从自身目录加载 DLL 的合法签名程序（本例为 CEF Helper，版本信息伪装为 JetBrains `Webview Helper`，文件名 `pcRFjwAb.exe`）。
2. 编写恶意 DLL：导出与宿主导入表一致的 38 个函数名；将被宿主直接调用的 11 个关键函数实现为 `retn` 空壳；在 `cef_api_hash` 返回硬编码哈希；把真实逻辑放入 `cef_api_hash`/`DllMain`/TLS 回调。
3. 抗分析处理：用 MinGW-w64 编译；把 `.text` 段填充到 512MB；对所有有效函数做 CFF 平坦化；注册 TLS 回调；在初始化链中使用 `VirtualProtect`/`Sleep`；EXE 中加入父进程监控线程，父进程退出即自尽。
4. 投放：把白宿主、恶意 DLL、`View.conf`、`README.md` 放入 `C:\Users\Public\Videos\<随机8位目录>`，并设置 `+s +a +h` 隐藏属性。
5. 持久化：以管理员权限创建服务 `Webview Helper`，`binPath` 指向该目录下的白宿主，启动类型设为自动；服务由 SCM 以 SYSTEM 权限启动。
6. 上线：恶意 DLL 解密 `View.conf`/`README.md` 中的配置与载荷，建立 C2 通道（本例 `192.229.116.49:30003`），接受远控指令。
7. 分析/复现核对：用 `tasklist`/`netstat -ano` 关联进程与连接；用 Autoruns 查服务与启动项；用 `attrib` 查看隐藏属性；用 `dumpbin /exports libcef.dll` 核对导出表；用 PE 工具核对 `.text` 大小与实际函数数量。

## PoC

无 PoC（样本未公开，关键载荷未解密）。可用以下最小命令核对同类样本特征：

```bat
:: 进程与网络关联
tasklist | findstr /i "pcRFjwAb libcef"
netstat -ano | findstr <PID>

:: 服务路径与状态
sc qc "Webview Helper"
sc query "Webview Helper"

:: 隐藏目录与属性
dir /a C:\Users\Public\Videos
attrib C:\Users\Public\Videos\<随机目录>

:: 导出表与区段大小
dumpbin /exports libcef.dll
```

IDA 侧核对点：`cef_api_hash` 是否异常膨胀（本例 1551 字节/106 基本块）、`DllMain` 是否 CFF、是否存在 TLS 回调、导入表是否包含 `VirtualProtect`/`VirtualQuery`/`CreateToolhelp32Snapshot`/`OpenProcess`/`WaitForSingleObject`/`ExitProcess`。

## 变体与关联

- 变体：同一家族会按环境改变 DLL 大小（受害机 512MB、沙箱 102MB，MD5 不同），检测不能只依赖哈希或固定文件大小。
- 变体：白宿主可替换为其他会从自身目录加载 DLL 的签名程序；导出表可按宿主导入表定制，空壳函数数量随宿主而变。
- 变体：持久化可从服务改为计划任务、Run 键或 COM Handler；本例选择服务是为了获得 SYSTEM 权限与开机即启动。
- 关联卡片：[[pentest-c2-dll-sideload-export-forwarding-host-whitelist]]（导出转发代理 DLL 通用手法）、[[pentest-c2-silverfox-hellogpt-installer-dropper-chain]]（同家族 HelloGPT 投放链）、[[code-analysis-reverse-windows-doubao-imposter-configmanager-uac-amsi-driver]]（仿冒 AI 客户端投放链）、[[pentest-persistence-dll-search-order-hijack-proxy-forwarding]]（DLL 搜索顺序劫持）、[[pentest-persistence-windows-nine-mechanism-persistence-combo]]（Windows 多重持久化）。
- 未证实点：`README.md` 的多段加密容器格式与“打开文件弹出多个记事本”的解释来自 AI 推测且互相矛盾；`View.conf` 的具体算法、密钥和 C2 配置均未还原。卡内只把静态/主机证据确认的部分当作事实。

## 检测与防御

- 检测可执行文件来源：签名进程从 `C:\Users\Public\*`、`%TEMP%`、`%APPDATA%` 等用户可写目录运行；服务 `binPath` 指向 Public/Videos、Temp 等异常路径；服务名与二进制描述/版本信息不一致（如 `Webview Helper` 指向随机名 EXE）。
- 检测 DLL 侧加载：白进程目录中出现与系统 DLL 同名但签名/版本/哈希不符的文件；进程加载的 DLL 路径位于用户可写目录；DLL 导出表函数数量与系统同名 DLL 不一致或大量导出指向同一 `retn` 地址。
- 检测文件膨胀：PE `.text` 声明大小远超文件实际有效代码或异常巨大（数百 MB）；同一进程目录下小 EXE + 超大 DLL 的组合。
- 检测反分析行为：TLS 回调在 `DllMain` 前执行、`VirtualProtect` 将匿名/映射内存改为可执行、父进程句柄 + `WaitForSingleObject` 后 `ExitProcess`、沙箱中长时间 `Sleep`；EDR 可对进程快照枚举 + 父进程同步 + 自我退出序列告警。
- 检测隐藏落地：`dir /a` 与 `attrib` 发现 `+s +a +h` 的异常目录；文件系统监控对 `C:\Users\Public\Videos` 下新增可执行文件告警。
- 网络检测：对 `192.229.116.49:30003` 等已知 C2 做情报匹配；监控服务进程（Session 0）在用户登录前发起的非常规出站连接；同一 EXE 在 Session 0 与 Session 1 同时存在也可疑。
- 防御：禁止或限制从用户可写目录执行程序（AppLocker/WDAC）；服务创建与修改需要审批与监控；启用基于行为的 EDR 与内存扫描；对超大 PE 文件强制扫描而非按大小跳过；限制 MinGW/无签名 DLL 在白进程目录加载；及时隔离受感染主机并检查服务、计划任务、隐藏目录与凭据。
- 响应：禁用并删除恶意服务（`sc delete "Webview Helper"`）、结束进程、取消隐藏属性后取证打包、封禁 C2、检查同一目录与其他 Public/Temp 落地、轮换可能泄露的凭据。
