---
id: code-analysis-reverse-windows-redline-native-multistage-shellcode-clr-resource-loader
title: RedLine 原生多级加载链：GlobalAlloc 分块解密 shellcode、0x400000 映像映射、RCDATA+CLR 宿主加载 .NET Reactor 载荷
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: redline-native-multistage-shellcode-clr-loader
aliases:
- RedLine 原生加载器
- 多级 shellcode 分块解密
- GlobalAlloc 可执行内存
- VirtualAlloc 二级 shellcode
- payload 映射到 0x400000
- RCDATA 资源解密 .NET 载荷
- CLR 非托管宿主加载内嵌程序集
- mscoree CLRCreateInstance v4.0.30319
- .NET Reactor 未注册版 14 天校验
- Opera GX Stable Login Data
- 钱包扩展 ID 解密
tags:
- windows
- reverse
- malware-analysis
- redline
- stealer
- shellcode
- multi-stage
- loader
- pe-mapping
- clr-hosting
- dotnet-reactor
- resource
- virtualalloc
- globalalloc
- credential-theft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:31:40+08:00'
  notes: 已对照原文全文与33/33图核对；为具体样本的完整原生加载链（GlobalAlloc分块解密→VirtualProtect 0x40→二级shellcode→0x400000映射→RCDATA+CLR宿主→.NET Reactor 14天校验→RedLine收集面），与dedup报告中最相近的RedLine .NET AES dropper、RedLine收集面、通用RCDATA/CLR卡均为不同链；卡片无sources/文章ID/URL/长段摘录，路径合法，原文未标注组件受影响版本故versions为空；未执行样本
---

## 一句话结论

该 RedLine Stealer 样本是一条完全驻留内存的原生加载链：无壳 Win32 GUI 样本的 `main` 用 `GlobalAlloc` 分配内存，把 .data 中的加密 shellcode 拷贝进去并分块解密，`VirtualProtect(…, 0x40, …)` 改为可执行后用函数指针直接调用；一级 shellcode 自解析 API、解密第二段 shellcode 并经 `VirtualAlloc` 执行；二级 shellcode 把内嵌 payload 按固定 `ImageBase=0x400000` 装载到该地址并跳入口；payload 再读取自身 `RCDATA` 资源解密，通过 CLR 非托管接口（`CLRCreateInstance`、mscoree `v4.0.30319`、SAFEARRAY 传字节）在内存中载入 .NET 程序集；该程序集受 .NET Reactor 保护（未注册版带 14 天日期校验），脱壳后为 RedLine Stealer，枚举 Chrome/Opera GX Stable 的 `Login Data`/`Web Data`/`Cookies` 并解密 30 余个加密钱包扩展 ID 列表。

## 原理

- **外层 PE 为何能直接执行堆内存**：样本为 PE32、`ImageBase=0x400000`、MSVC 编译、GUI 子系统、无壳（编译时间 2022-01-13）。`sub_4051E0` 调用 `GlobalAlloc(0, dwSize)` 取得一块堆内存；随后把 .data 中的加密数据逐字节拷贝到该地址（拷贝源为镜像内固定偏移处），并在 `VirtualProtect(lpAddress, dwSize, 0x40, &flOldProtect)` 之后执行解密循环——`0x40` 即 `PAGE_EXECUTE_READWRITE`。Windows 默认堆内存不可执行，正是这一步改权限使后续函数指针调用成立。核心解密函数按 8 字节一块被循环调用（`v2 = dwSize >> 3; do { sub_404ED0(v1); v1 += 8; } while (--v2)`），调试中可见逐字节 XOR 的循环与密钥字节。
- **一级 shellcode 的 API 自解析**：解密后的 shellcode 不依赖原 PE 导入表，而是自己定位 `kernel32` 等模块并解析 `LoadLibrary`/`GetProcAddress`/`VirtualAlloc` 等函数地址；随后在自身载荷中定位第二段密文，解密后调用 `VirtualAlloc` 分配 RWX 内存、拷贝并跳转。内存视图中可直接看到解析出的 `kernel32.VirtualAlloc`、`kernel32.GetProcAddress` 等符号，这是跟踪此阶段的抓手。
- **二级 shellcode 的固定基址映像映射**：二级 shellcode 中可见 `mov dword ptr [ebp-40h], 0E2Dh`（载荷长度）与 `mov dword ptr [ebp-58h], 400000h`（目标基址），随后把 payload 数据搬运到 `0x400000`。内存窗口在 `0x400000` 处出现完整 `MZ`/`PE` 头与 `.text`、`.rdata` 节区，最后 `push offset sub_40A30` 一类入口指针并跳入执行。由于内嵌 PE 的链接基址就是 `0x400000`，直接放到该地址即可在其链接期地址上运行，无需重定位；该样本中未见重定位/导入修复细节，分析时应在跳转前后核对 IAT 与节区权限。
- **payload 读自身 RCDATA 资源再解密**：payload 的 `main` 先做常量数组字符串解密（`sub_401650` 一类），再调用 `FindResourceA` → `LoadResource` → `SizeofResource` → `LockResource` 取出类型为 `RCDATA`（资源类型 10）、名字随机的资源；资源内容为密文，解密后得到 .NET 程序集。资源名/类型在 PE 资源目录中可见，是静态定位载荷的入口。
- **CLR 非托管宿主加载托管载荷**：payload 从 `mscoree.dll` 解析 `CLRCreateInstance`，以 `CLSID_CLRMetaHost`/`IID_ICLRMetaHost` 取得元宿主，用版本串 `v4.0.30319` 取运行时并拿到接口；随后 `SafeArrayCreate(VT_UI1=0x11, 1, &bound)` + `SafeArrayAccessData` + `memcpy` 把 .NET 程序集字节放入 SAFEARRAY，经 vtable 调用交给运行时加载。托管侧代码再从清单资源流读取字节并 `Assembly.Load`，同时挂 `AppDomain.CurrentDomain.ResourceResolve`/`AssemblyResolve` 处理依赖解析，并对 `PresentationFramework` 的 `System.Windows.Application.ResourceAssembly` 属性做特殊处理——这是“原生进程内跑托管载荷、磁盘上不落 .NET 文件”的典型做法。
- **.NET Reactor 的未注册日期闸门**：被加载的 .NET 程序集经过 .NET Reactor 混淆保护，其中可见一段校验：`if (Math.Abs((DateTime.Now - new DateTime(2023, 6, 6)).Days) >= 14) throw new Exception("This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"! …")`。也就是说该构建在 2023-06-20 之后直接抛异常不工作；分析/复现时必须先 patch 该分支或用 de4dot/.NET Reactor Slayer 脱壳，否则动态行为会被保护壳提前终止。这个异常字符串本身也是样本指纹。
- **最终载荷为 RedLine Stealer**：脱壳后的 .NET 程序集字符串包含 `Login Data`、`Web Data`、`Cookies`、`Opera GX Stable`（含其下的 `Login Data`/`Web Data`/`Cookies`）、`Local Extension Settings`、`Local Storage\leveldb`、`cookie.sqlite` 等路径，并内置一张加密的加密钱包扩展 ID 列表，运行时解密后按 Chromium 扩展目录查找。该行为与 RedLine 家族的信息窃取面一致，说明前四级加载链的最终目的就是浏览器凭据与钱包数据窃取。

## 触发条件

- 目标为 Windows 主机（样本为 32 位 GUI 程序，可在 x86/x64 上运行），系统装有 .NET Framework 4.0.30319（CLR 宿主按该版本取运行时）。
- 用户执行样本，且 `0x400000` 地址空间可用（多数 32 位进程默认可用）；若被占用或映射失败，二级 shellcode 的固定基址装载会失败。
- 样本自身的 .NET Reactor 校验：构建日期基准为 2023-06-06，超过 14 天即抛异常；复现/分析时需要 patch 日期判断或先脱壳。
- 分析环境需要 IDA/x64dbg（或同类调试器）、内存 dump 工具、dnSpy/de4dot/.NET Reactor Slayer，以及可断在间接 `call`/`jmp` 与 `VirtualAlloc` 返回处的能力。

## 利用步骤

1. **静态识别外层**：确认 PE32、无壳、MSVC、GUI；在 `main` 中找到 `GlobalAlloc` → 拷贝 → `VirtualProtect(…, 0x40, …)` → 解密循环 → 间接调用序列。样本 `main` 用 `dwSize` 分支布置多组 API 调用与字符串，属于花指令式干扰，真正的装载逻辑集中在 `sub_4051E0`/`sub_405200`/`sub_404ED0`。
2. **断在解密后的跳转**：在 `GlobalAlloc` 返回值处下内存写断点，或在函数指针 `call`/`jmp` 处下断；等解密循环跑完后把该内存块按长度 dump 为一级 shellcode。也可直接在 `VirtualProtect` 返回后 dump。
3. **跟一级 shellcode**：单步进入 shellcode，观察其自解析 `kernel32` 函数的过程；在 `VirtualAlloc` 返回处或第二段解密函数返回处下断，dump 二级 shellcode。
4. **抓 0x400000 映像**：在二级 shellcode 执行时对 `0x400000` 下硬件写断点/内存断点；等 `MZ` 与节区出现后按 PE 结构 dump payload（必要时用 Scylla 一类工具修复 IAT），再跟到入口点。
5. **取 RCDATA 明文**：在 payload `main` 中对 `FindResourceA`/`LoadResource`/`LockResource` 下断，导出资源密文；在解密函数返回处下断取明文 .NET 程序集并 dump。
6. **脱 .NET Reactor**：用 dnSpy 打开 dump 的 .NET 程序集；若被 .NET Reactor 保护，先用 de4dot 或 .NET Reactor Slayer 处理；遇到 “unregistered version … 14 days” 异常时 patch 日期校验分支或直接改跳转，使载荷可运行。
7. **确认家族与窃取面**：在脱壳结果中检索浏览器路径字符串与钱包扩展列表解密函数，在解密返回处下断导出扩展 ID；结合 `Login Data`/`Web Data`/`Cookies`、`Opera GX Stable`、`Local Extension Settings` 等特征确认 RedLine 家族，并记录样本 SHA-256 便于关联。

## PoC

无 PoC。样本分析未提供可直接复现的脚本，仅给出样本 SHA-256 `f22e976a3cc892e7c21cf6e222d0cf2e0e6c0dc0f7b882c7ac8d365a1e3b4cd1` 与手工调试路径；上述断点位置可作为最小化复现步骤。样本具有真实窃密行为，禁止在生产环境运行，动态分析应在隔离虚拟机中进行。

## 变体与关联

- 关联加载器：[[code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper]] 是另一条 RedLine 加载链（.NET 侧 `ResourceManager`+AES 解密资源并落盘启动），与本卡的原生多级 shellcode 路线不同，可对照家族演化。
- 关联技术：[[pentest-c2-clr-hosting-embedded-dotnet-assembly-reflection-loader]] 讲通用的 CLR Hosting 内存加载 .NET 程序集；[[code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump]] 讲多阶段 .NET 资源加载与 .NET Reactor 处理；[[code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe]]、[[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]、[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]] 分别覆盖多级 shellcode、内嵌 PE 解密映射与二阶段 PE 加载的其他变体。
- 关联窃取面：[[defense-forensics-redline-stealer-collection-geofence]]、[[defense-forensics-wallet-extension-id-local-extension-settings-collection]]、[[defense-detection-redline-stealer-yara-pe-strings]]。
- 变体：外层可能加壳或更换编译器；块解密可能换成 XOR/RC4/AES 等算法；二级 shellcode 也可能改为反射加载或线程注入而不是固定 `0x400000` 映像映射；CLR 宿主可能改用 `ICLRRuntimeHost::ExecuteInDefaultAppDomain` 或 `ICorRuntimeHost::Load_3` 等接口；.NET Reactor 可能是注册版（无日期闸门）；最终载荷可能是其他 Stealer。
- 边界：`0x400000` 被占用、目标机缺少 .NET Framework 4.0、Reactor 日期过期、资源名/密钥随构建变化时，链条会中断或行为不可见。

## 检测与防御

- **静态特征**：YARA 组合 `MZ` 头、`CLRCreateInstance`、`v4.0.30319`、`mscoree.dll`、`RCDATA` 高熵资源、`.NET Reactor`/`unregistered version of Eziriz` 字符串、`Login Data`/`Opera GX Stable`/`Local Extension Settings` 等浏览器与钱包路径；无壳 PE 同时导入 `GlobalAlloc`/`VirtualProtect`/`FindResourceA`/`LoadResource` 也值得告警。
- **主机行为**：监控 `GlobalAlloc` → `VirtualProtect(RWX)` → 间接调用；`VirtualAlloc(RWX)` 后立即跳转；在 `0x400000` 处出现新的 PE 映像；非托管进程加载 `mscoree`/CLR 并执行托管代码；进程读取浏览器 `Login Data`/`Web Data`/`Cookies` 与 `Local Extension Settings`。可结合 Sysmon 8/10/11 事件与 EDR 内存扫描。
- **网络侧**：RedLine 会上传窃取的凭据与钱包数据；本样本未展示 C2 细节，检测应结合家族情报与出站行为基线。
- **防御与响应**：启用应用控制阻止未签名样本执行；EDR 开启内存扫描与 AMSI/ETW 对 CLR 程序集加载的观测；隔离浏览器凭据与钱包扩展数据；主机失陷后立即轮换账号口令、迁移钱包资产并排查持久化。
