---
id: code-analysis-reverse-anti-debug-clr-profiling-env-jit-module-checks
title: CLR 环境反调试双检查：Cor_Enable_Profiling 环境变量启用即退出 + 进程已加载 mscorjit/clrjit 即返回
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: clr-profiling-env-jit-module-anti-analysis
tags:
- windows
- reverse
- anti-debug
- dotnet
- clr
- environment-variable
- module-enumeration
- malware-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:51:48+08:00'
  notes: 已对照原文与图03-06核对：FUN_XorDecode解出Cor_Enable_Profiling(图03/05)、getenv判断(图03)、CreateToolhelp32Snapshot+Module32First/Next比对mscorjit.dll/clrjit.dll(图04/06)均与卡一致；原文为样本分析无版本区间；dedup候选CLR宿主加载卡、调试器窗口检测卡均非同链。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-clr-profiling-env-jit-module-checks/
draft: false
kb_aliases:
- Cor_Enable_Profiling
- CLR profiling 环境检测
- mscorjit.dll 检测
- clrjit.dll 检测
- .NET 加载器反调试
- JIT 模块枚举反分析
---

## 一句话结论

该 C++ 加载器在解密载荷前做两道 CLR 环境检查：先异或解密字符串 `Cor_Enable_Profiling` 并读取同名环境变量，变量处于启用（非零）状态就停止执行；再对当前进程做模块快照，一旦发现 `mscorjit.dll` 或 `clrjit.dll` 已加载就关闭句柄并返回 0，只有两道检查都“干净”时才继续从资源解密 .NET 勒索模块。

## 原理

- **`Cor_Enable_Profiling` 是 CLR 的 profiling 开关**：.NET 运行时通过该环境变量控制是否启用 profiler。动态分析、APM、代码覆盖率、部分调试/插桩工具会把它设为非零值；恶意加载器把它当作“当前进程是否处于 .NET 分析/插桩环境”的探针，读到启用态就退出，避免在分析环境里继续解密后续载荷。
- **JIT 模块存在性反映托管运行时已被加载**：`mscorjit.dll`/`clrjit.dll` 是 .NET JIT 编译器组件。加载器用 `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId())` + `Module32First/Next` 遍历自身模块；若发现这两个模块，说明当前进程已经承载 CLR（常见于托管调试器、.NET 插桩宿主、把样本注入到托管进程等场景），于是 `CloseHandle` 后 `return 0`，不走解密分支。
- 两道检查互补：环境变量覆盖“以 profiler 方式启动”的分析，模块枚举覆盖“运行中被 CLR 宿主/调试器接管”的分析；它们不检查常见的 `IsDebuggerPresent`，因此静态看导入表时容易被忽略。
- 代码上表现为返回值门控：`getenv` 结果与预期值不相等/为空才继续；模块比对使用异或解密后的字符串常量，静态字符串扫描看不到 `mscorjit.dll` 明文。

## 触发条件

- 样本为原生（C/C++）加载器，运行在 Windows 上，后续载荷为 .NET 程序集；
- 分析/沙箱环境设置了 `Cor_Enable_Profiling`（非零）或使用 profiler 类工具启动进程；
- 或分析时把样本附加/注入到已加载 CLR 的进程（进程模块列表中存在 `mscorjit.dll`/`clrjit.dll`），加载器会直接返回，表现为“什么都没发生”。
- 普通双击运行、环境干净时两道检查均通过，加载器继续解密载荷。

## 利用/分析步骤

1. 在 IDA/Ghidra 中定位 `getenv` 调用点，回溯其参数字符串来源，识别异或解密函数（本案形如 `FUN_XorDecode(&v36, v100)`，逐字节异或常量数组）；
2. 还原字符串后确认比较逻辑：变量启用（非零）→ 退出；禁用/为空 → 继续；
3. 定位 `CreateToolhelp32Snapshot`、`Module32First/Module32Next`、`strcmp` 序列，确认比对目标为 `mscorjit.dll`、`clrjit.dll`；
4. 动态绕过：把 `getenv` 返回值改为“未启用”，或在比较后修改跳转；对模块检查可 patch `strcmp` 返回值/条件跳转，或在干净进程（未加载 CLR）中调试，避免在 dnSpy 托管调试器里直接附加原生加载器；
5. 注意这两道检查只是前置门控，通过后还有资源定位与多段异或解密，需继续跟 `FindResourceA`/`LockResource`/解密函数。

## PoC

无独立 PoC。原文关键代码形态：

```c
v3 = (const char *)FUN_XorDecode(&v36, v100);   // 解密出 "Cor_Enable_Profiling"
if ( getenv(v3) != (char *)&unk_41B2A0 ) {      // 变量未处于启用态才继续
    CurrentProcessId = GetCurrentProcessId();
    Toolhelp32Snapshot = CreateToolhelp32Snapshot(8u, CurrentProcessId);
    // Module32First/Next 比对 mscorjit.dll / clrjit.dll
    // 命中则 CloseHandle(snapshot); return 0;
}
```

## 变体与关联

- 其他 CLR 相关探针：`COR_PROFILER`、`COMPLUS_ProfAPI_ProfilerCompatibilitySetting`、`COMPLUS_ReadyToRun`、`DOTNET_*` 环境变量；模块侧可检查 `mscoree.dll`、`clr.dll`、`coreclr.dll`；
- 与常见反调试组合：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess(DebugPort)`、窗口标题/进程名检测；本卡的双检查可与库内“Loader 反沙箱与反调试：时间加速、桌面/主机名与 DebugPort 检测”串联使用；
- 分析对抗：用干净快照 + 单步 patch 通过门控，避免在托管调试器中加载样本。

## 检测与防御

- EDR 监控进程对 `Cor_Enable_Profiling` 等 CLR 环境变量的读取与 `CreateToolhelp32Snapshot`+模块枚举组合行为；这类组合在非开发进程中较罕见；
- 沙箱/分析平台默认不设置 profiler 环境变量，并对加载器返回 0 的“静默退出”保留内存快照与调用栈，便于识别门控位置；
- 防御侧：.NET 应用启用强名称/完整性校验，监控异常进程加载 CLR 并调用 `CLRCreateInstance` 的行为；对勒索相关文件写入与删除做批量行为告警。
