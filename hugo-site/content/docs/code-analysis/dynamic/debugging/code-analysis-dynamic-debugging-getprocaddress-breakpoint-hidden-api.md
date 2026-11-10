---
id: code-analysis-dynamic-debugging-getprocaddress-breakpoint-hidden-api
title: 调试器里用 GetProcAddress 断点捕获动态解析的隐藏 API：读栈上函数名、Ctrl+F9 取 EAX 返回地址后下断
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: getprocaddress-breakpoint-hidden-api-capture
tags:
- windows
- debugging
- ollydbg
- getprocaddress
- anti-debug
- dynamic-analysis
- api-resolution
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:55:24+08:00'
  notes: 已对照原文与图13-22/29-31核对：BP GetProcAddress 即使名称窗口不显示也可下断、命中时栈上 hModule=0x76BC0000 与 lpProcName 字符串、Ctrl+F9 后 EAX 得 EnumProcesses=0x76BC3A76/EnumProcessModules=0x76BC1EF4/GetModuleBaseNameA=0x76BC2132、在返回地址下断并注释均与原文一致；x64 读 RCX/RDX 与 LdrGetProcedureAddress 变体已注明；与既有 FSG 断点/PEB EAT 等卡不同，dedup 全 new；原文无版本；无 URL/文章 ID/长段摘录；未复跑
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-getprocaddress-breakpoint-hidden-api/
draft: false
kb_aliases:
- GetProcAddress 断点
- 隐藏 API 捕捉
- 动态解析函数定位
- OD 断点 GetProcAddress
- 反调试隐藏函数
- EAX 返回地址下断
---

## 一句话结论

当样本把敏感 API 名藏起来、在调试器的名称窗口里看不到可疑函数时，可以在尚未运行时先对 `GetProcAddress` 下断点：每次命中时读栈上的 `hModule` 与 `lpProcName` 就能看到它动态请求了哪个函数（如 `EnumProcesses`/`EnumProcessModules`/`GetModuleBaseNameA`），按 `Ctrl+F9` 执行到函数返回再从 EAX 取解析到的地址，随后在那个地址下断点并加注释，就能把“隐藏函数”还原成可跟踪的调用点。

## 原理

- **GetProcAddress 是动态解析的必经点**：无论样本用 `LoadLibrary`+`GetProcAddress`，还是只导入 `GetProcAddress` 再按名字取函数，最终都要把函数名交给它。断在这里等于在“名字 → 地址”的转换处截获全部解析行为，不依赖导入表或名称窗口是否显示。
- **参数位置可预测**：x86 stdcall 下入口时 `[ESP+4]=hModule`、`[ESP+8]=lpProcName`（x64 下为 RCX/RDX），`lpProcName` 指向的 ASCII 字符串就是请求的函数名；若为序号则低字为序号值。
- **返回地址获取**：`GetProcAddress` 返回 `FARPROC`，在 x86 中放在 EAX。用调试器的“执行到返回”（OD 的 `Ctrl+F9`）让函数跑完，EAX 即目标函数地址；把它记录为“名字→地址”映射。
- **转到真实调用点**：由于地址是运行时解析的，OD 不会自动给它加符号注释；在地址处下断点（`bp <地址>`）并手动注释函数名，之后程序真正调用该 API（如枚举进程）时就会断下，便于观察参数与返回。
- **为什么反调试样本也挡不住**：这类样本只隐藏了“函数从哪里来”，没有隐藏“函数被调用”本身；只要在动态解析层截获名字，再在解析结果上下断，后续行为就完全可见。除非样本完全手写 PEB/导出表遍历、不经过 GetProcAddress，此时需要改用 API Monitor/内核断点或在目标 API 上下断。

## 触发条件

- 目标 PE 的导入表很小或名称窗口里没有可疑函数，但行为上明显在做进程/模块枚举、窗口查找等操作。
- 样本在运行早期动态解析 API（常见于反调试、加载器、壳）。
- 调试器支持在任意导出上下断（OD 可直接在命令框输入 `BP GetProcAddress`，即使名称列表里没有）。

## 利用步骤

1. 把样本载入 OD，先不运行；在命令框执行 `BP GetProcAddress`（名称窗口不显示也可下断）。
2. 运行后每次在 `GetProcAddress` 断下，查看栈：`[ESP+4]` 为模块句柄（可对照 user32/kernel32 基址），`[ESP+8]` 为函数名字符串；记录请求的函数名。
3. 对可疑名字（如 `EnumProcesses`）执行 `Ctrl+F9` 到返回，记下 EAX 中的函数地址（例如 `0x76BC3A76`）。
4. 在命令框对地址下断：`BP 0x76BC3A76`，并在断点/注释窗口标注函数名。
5. 继续运行，在目标 API 断下后观察参数、返回值与调用栈；必要时配合内存断点（如对 PID 数组下内存访问断点）跟踪结果使用。
6. 若样本解析了很多 API，可只对关键名字下条件断点/记录，避免频繁中断。

## PoC

OD 操作要点（x86）：

```text
BP GetProcAddress                ; 名称列表没有也能下
; 命中后栈: [ESP+4]=hModule, [ESP+8]=lpProcName(ASCII)
Ctrl+F9                          ; 执行到返回，EAX=函数地址
BP <EAX>                         ; 在解析结果处下断并注释函数名
```

观察到的示例映射（原文环境）：

```text
GetProcAddress(hModule=0x76BC0000, "EnumProcesses")      -> EAX=0x76BC3A76
GetProcAddress(hModule=0x76BC0000, "EnumProcessModules") -> EAX=0x76BC1EF4
GetProcAddress(hModule=0x76BC0000, "GetModuleBaseNameA") -> EAX=0x76BC2132
```

## 变体与关联

- 关联：捕获到这些隐藏 API 后如何分析其反调试逻辑与绕过，见 [[code-analysis-reverse-anti-debug-debugger-process-window-detect-rename-bypass]]。
- 变体：x64dbg 中在 `GetProcAddress` 下断、读 `RCX/RDX` 或使用“在返回处下断点”功能；也可用 Frida hook `GetProcAddress` 打印参数与返回值、API Monitor 直接记录全部 API 调用。
- 变体：样本若用 `LdrGetProcedureAddress`/手写 PEB 导出遍历，不经过 `GetProcAddress`，可改为对 `LoadLibrary`/目标 API 下断或在导出表遍历循环处下断。
- 关联：PEB 字段类反调试（BeingDebugged/NtGlobalFlag/Heap Flags）的识别与补丁见 [[code-analysis-reverse-anti-debug-peb-fields-patch]]。

## 检测与防御

- 这是分析侧技术，不产生攻击面；对恶意样本作者而言，只要经过 GetProcAddress 就会暴露 API 名，手写解析只能提高成本。
- 检测（针对反调试样本）：导入表极小但运行时出现大量 API 解析、对调试器进程/窗口的枚举，可作为可疑反分析特征；分析时优先在动态解析层截获。
