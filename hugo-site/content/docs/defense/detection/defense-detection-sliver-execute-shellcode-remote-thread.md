---
id: defense-detection-sliver-execute-shellcode-remote-thread
title: Sliver execute-shellcode 注入检测：notepad 进程内 VirtualAllocEx RW→VirtualProtect RX→CreateRemoteThread
type: scenario
domain: defense
path: defense/detection
technique: sliver-execute-shellcode-injection-detection
tags:
- defense
- detection
- sliver
- c2
- shellcode-injection
- windows
- edr
- sysmon
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:08:14+08:00'
  notes: 已对照原文与图片核对：execute-shellcode 默认注入 notepad.exe，VirtualAllocEx(PAGE_READWRITE)→WriteProcessMemory→VirtualProtect(PAGE_EXECUTE_READ)→CreateRemoteThread 序列与原文一致；ExecuteShellcodeCmd/PrintExecuteShellcode 源码描述、--pid/--rwx-pages/rdi-shellcode 变体均与原文一致。未验证点：Sysmon 8/10 规则为概念配置，未复跑；affected_versions 已 --clear。
url: /docs/defense/detection/defense-detection-sliver-execute-shellcode-remote-thread/
draft: false
kb_aliases:
- Sliver execute-shellcode
- Sliver shellcode 注入检测
- notepad.exe 注入
- VirtualAllocEx PAGE_READWRITE
- CreateRemoteThread 检测
- 跨进程内存属性变化
---

## 一句话结论

Sliver 的 `execute-shellcode` 默认把 shellcode 注入 `notepad.exe`：对目标进程 `VirtualAllocEx` 申请 `PAGE_READWRITE` 内存、`WriteProcessMemory` 写入、`VirtualProtect` 改为 `PAGE_EXECUTE_READ`、最后 `CreateRemoteThread` 执行；在 EDR/Sysmon 中监控跨进程内存写入与 RW→RX 属性变化、以及无用户交互 notepad 进程的远程线程，即可识别这类注入。

## 原理

- **Sliver 的默认注入链**：`execute-shellcode` 在客户端读取 shellcode 文件后下发任务，由植入体在目标主机执行。文章描述其默认行为是启动/选择 `C:\windows\system32\notepad.exe`，在目标进程中：
  1. `VirtualAllocEx(..., PAGE_READWRITE)` 分配可读写内存；
  2. `WriteProcessMemory` 写入 shellcode；
  3. `VirtualProtect(..., PAGE_EXECUTE_READ)` 把该区域改为可执行只读；
  4. `CreateRemoteThread` 从该区域起线程执行 shellcode。
  这是典型的远程 shellcode 注入，代码不在磁盘上、不加载 DLL，规避基于进程/文件的检测。
- **为什么可检测**：正常 notepad 进程不会收到其他进程的 `PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION`/`PROCESS_CREATE_THREAD` 请求，也不会出现由匿名可执行内存发起的线程。内核/EDR 能看到跨进程句柄打开、内存分配/写入/保护变更与远程线程创建；Sysmon 提供 Event ID 8（CreateRemoteThread）与 10（ProcessAccess），EDR 还能看到内存区域的起始地址是否属于已加载模块（unbacked）。
- **补充证据**：注入源进程通常是 Sliver 植入体（临时目录、随机名、有 C2 外联）；notepad 在没有用户打开文档的情况下出现 CPU/网络/异常子进程；内存扫描可发现 shellcode/反射 DLL 特征。
- **边界**：攻击者可用 `--pid` 指定其他目标进程、用 `--rwx-pages` 直接申请 RWX、改用反射 DLL（rdi-shellcode）或线程劫持/共享节注入；这些变体会改变具体 API 序列，但跨进程内存操作与远程线程/无后备可执行内存的检测点仍然适用。

## 触发条件

- 受害主机为 Windows，具备 Sysmon（8/10）或 EDR 的进程访问、内存与线程遥测。
- 攻击者执行 Sliver `execute-shellcode`，默认注入 notepad.exe（或指定了其它目标进程）。
- 注入源进程有权限打开目标进程（同用户/管理员/SeDebugPrivilege）。
- 分析者能将注入事件与植入体的网络外联、进程来源关联。

## 检测步骤

1. 采集 Sysmon/EDR 事件：Event ID 10（ProcessAccess，含 `GrantedAccess`）、Event ID 8（CreateRemoteThread，含源/目标进程与起始地址）、内存分配/保护变更遥测。
2. 对 `TargetImage` 为 `notepad.exe` 的进程访问，筛选 `GrantedAccess` 含 `PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION`、`PROCESS_CREATE_THREAD` 的源进程；确认 notepad 是否由用户正常启动、是否有文档打开。
3. 对目标进程检查内存区域：新出现的匿名可执行区域（RW→RX 或直接 RWX），线程起始地址不属于任何已加载模块（unbacked）。
4. 关联源进程：临时目录/随机名二进制、无签名、存在 C2 外联；检查其父进程链与持久化。
5. 对可疑 notepad 进程做内存转储与字符串/特征扫描，确认 shellcode 或反射 DLL。

## PoC

```xml
<!-- Sysmon 过滤概念配置：关注 notepad 的远程线程与进程访问 -->
<Sysmon>
  <EventFiltering>
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="end with">notepad.exe</TargetImage>
    </CreateRemoteThread>
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">notepad.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

```text
# 分析时重点字段
EventID 10: SourceImage, TargetImage, GrantedAccess (0x1F0FFF / VM_WRITE|VM_OPERATION|CREATE_THREAD)
EventID 8:  SourceImage, TargetImage, StartAddress (是否落在模块外/匿名内存)
```

说明：检测逻辑依据文章对 Sliver 注入 API 序列的描述整理；未在真实 Sliver 会话中复跑。

## 变体与关联

- **变体：指定 PID/RWX**：`--pid` 注入其他进程、`--rwx-pages` 直接用 RWX，检测时不要只盯 notepad 与 RW→RX，应覆盖任意跨进程可执行内存。
- **变体：反射 DLL 注入**：Sliver 的 rdi-shellcode 走反射加载，不调用 CreateRemoteThread 的典型路径，需结合模块列表异常与内存特征。
- **关联**：ETW 线程创建事件被 patch 的绕过见 [[pentest-c2-etwpcreateetwthread-shellcode-exec]]；无后备线程起始地址绕过见 [[defense-detection-unbacked-thread-start-address-injection-bypass]]；Sliver 的 PowerShell 与令牌检测见 [[defense-detection-sliver-powershell-child-process-cmdline]] 与 [[defense-detection-sliver-impersonate-token-owner-mismatch]]。
- **对照**：经典远程线程 DLL 注入的攻击侧细节见 [[pentest-c2-classic-remote-thread-dll-injection]]。

## 检测与防御

- **检测**：notepad 等无害进程的跨进程写/执行权限访问；远程线程起始地址不在已加载模块；匿名 RWX/RW→RX 内存；注入源进程的 C2 外联与临时目录来源。
- **防御**：EDR 内存扫描与远程线程拦截；对高价值进程启用 ACG/CIG 等缓解；限制 `SeDebugPrivilege`；应用白名单；及时升级 EDR 以覆盖 ETW patch 等绕过。
- **响应**：隔离主机、转储并分析 notepad 与注入源进程内存、定位 C2 与持久化，排查同批次横向移动。
