---
id: code-analysis-reverse-windows-safeseh-heap-handler-bypass
title: SafeSEH 堆指针 handler 特权绕过：溢出改写 SEH handler 指向堆上 shellcode，DEP 关闭时校验放行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: safeseh-heap-handler-execute
tags:
- windows
- seh
- safeseh
- exception-handler
- stack-overflow
- heap
- shellcode
- mitigation-bypass
- x86
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:42:29+08:00'
  notes: 已对照原文与13张截图核对：/GS-、/DYNAMICBASE:NO、/NXCOMPAT:NO 设置与截图一致；SEH链0x19FF54为记录起始、handler字段在+4；堆缓冲0x006879A0与payload末4字节一致；payload 408字节偏移404附近的描述成立。已补充记录/字段区分，并修正一句话结论中栈上 handler 拒绝阶段（RtlDispatchException，而非 RtlIsValidHandler）。原文未贴shellcode成功执行截图，DEP关闭前提已写明。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-safeseh-heap-handler-bypass/
draft: false
kb_aliases:
- SafeSEH 堆绕过
- 异常处理指针指向堆区
- SafeSEH 终极特权
- SEH handler 堆地址
- 堆上 shellcode 执行
- RtlIsValidHandler 绕过
---

## 一句话结论

SafeSEH 的校验按"handler 是否位于加载模块内"分流：指向当前栈的 handler 在 `RtlDispatchException` 阶段被直接拒绝，模块内 handler 由 `RtlIsValidHandler` 查安全 SEH 表；而当 handler 指向堆区（既不在栈也不在模块）时，只要 DEP 未开启，校验放行并直接调用。利用栈溢出改写当前 SEH 记录的 handler 为堆上 payload 起始地址（该处放 shellcode），触发除零异常即可在堆上执行 shellcode。

## 原理

- **SEH 与 SafeSEH**：x86 的 SEH 记录位于栈上，结构为 `[next SEH 指针][handler 指针]`。开启 SafeSEH 后编译器把所有合法异常处理地址编成"安全 SEH 表"放入 PE 映像；异常分发由 `RtlDispatchException` → `RtlIsValidHandler` 校验。
- **`RtlDispatchException` 前置检查**：(1) 异常处理链必须位于当前程序栈中，否则终止；(2) handler 指针不能指向当前栈，否则终止。这挡掉了"handler 指回栈上 shellcode"的经典 SEH 覆盖。
- **`RtlIsValidHandler` 分流**：先判断 handler 是否位于当前加载模块的内存空间；在模块内则检查 `IMAGE_DLLCHARACTERISTICS_NO_SEH`、再与安全 SEH 表匹配、再检查是否不可执行页与 DEP；**不在任何加载模块内（如堆地址）时，校验逻辑只看该地址所在页是否可执行——DEP 关闭（`/NXCOMPAT:NO`）时堆页可执行，handler 被直接放行执行**。
- **为什么成立**：SafeSEH 的信任模型是"合法 handler 必然在模块代码段"，对模块外地址没有白名单；该设计在 DEP 关闭的进程里等价于"任意可执行地址均可作为 handler"。文章为隔离变量关闭了 GS、DEP、ASLR（VS 设置 `/GS-`、`/NXCOMPAT:NO`、`/DYNAMICBASE:NO`），只保留 SafeSEH，因此堆地址 handler 必然通过。
- **堆上 payload 的作用**：`test()` 中 `char str[200]` 被 `strcpy` 溢出，主函数另有一个 500 字节堆缓冲 `MyPayload`，读入同一份 payload 文件；payload 布局为 `[shellcode][NOP 填充][堆缓冲起始地址]`。溢出把栈上 SEH 记录的 handler 字段改成堆缓冲起始地址，堆缓冲开头正是 shellcode，异常分发跳过去即执行。
- **为什么 handler 不改回栈**：`RtlDispatchException` 第二项检查会拒绝指向当前栈的 handler；堆区不属于"当前程序栈"，恰好落在检查盲区。

## 触发条件

- Windows x86 进程开启 SafeSEH，但 **DEP 关闭**（`/NXCOMPAT:NO` 或系统未对该进程启用 DEP）；若 DEP 开启，堆页不可执行，`RtlIsValidHandler` 会拒绝该 handler（需先用 VirtualProtect 把堆页改为可执行，另见变体）。
- 存在可覆盖栈上 SEH 记录的溢出（本例 `strcpy` 到 `char str[200]`），且偏移可计算。
- 攻击者能把 shellcode 放进堆缓冲（本例程序自己 malloc + ReadFile 读入可控文件；真实漏洞中可用堆喷、上传内容、解压数据等可控堆块）。
- 能触发异常（本例 `int b = 1 / a` 除零）使分发走到被覆盖的 SEH 记录。
- 进程无 ASLR（`/DYNAMICBASE:NO`）或可预测堆地址；GS 关闭或已绕过。

## 利用步骤

1. 确认保护：`/GS-`、`/NXCOMPAT:NO`、`/DYNAMICBASE:NO`，SafeSEH 开启（链接器 `/SAFESEH` 默认对 x86 生效）。
2. 调试定位：test 的栈缓冲起始地址、到最近 SEH 记录 handler 字段的偏移（原文 payload 408 字节，堆地址写在最后 4 字节，即 handler 偏移 404 附近，按实际帧布局确认；注意 OllyDbg SEH 链窗口显示的"地址"是记录起始的 next 指针字段，handler 字段在记录 +4，偏移要按 handler 字段本身计算）；堆缓冲 `MyPayload` 的起始地址（原文 0x006879A0）。
3. 构造 payload 文件：`shellcode + NOP 填充到 (handler 偏移) + p32(堆缓冲起始地址)`；总长不超过堆缓冲 500 字节。
4. 让程序把同一 payload 读入堆缓冲并调用溢出的 `test()`；`strcpy` 覆盖栈上 SEH 记录。
5. 触发除零异常，`RtlDispatchException` 跳过栈上 handler（被覆盖为堆地址），`RtlIsValidHandler` 因堆地址不在模块内且页可执行而放行，EIP 跳到堆缓冲开头的 shellcode。

## PoC

```python
import struct
p32 = lambda x: struct.pack("<I", x)

shellcode = b"\x90" * 16            # 占位：实际 shellcode（如 MessageBox/WinExec）
handler_offset = 404                # 栈缓冲到 SEH handler 字段的偏移（按实际调试确定）
heap_buf = 0x006879A0               # 堆缓冲起始地址（放 payload 的位置）

payload = shellcode + b"\x90" * (handler_offset - len(shellcode))
payload += p32(heap_buf)            # SEH handler -> 堆上 shellcode
open("111.txt", "wb").write(payload)
```

```text
# 程序侧（原文）：
# MyPayload = malloc(500); ReadFile(111.txt, MyPayload, 500, ...);
# test(MyPayload);  // char str[200]; strcpy(str, szBuffer); int b = 1/0;
# 触发异常后 handler 从栈被改写为 0x006879A0（堆缓冲），shellcode 在堆上执行
```

原文给出完整 payload 十六进制与地址（栈缓冲 0x19Fxxx 区、堆缓冲 0x006879A0），但未贴 shellcode 最终效果截图；控制流劫持路径完整。

## 变体与关联

- 变体一：DEP 开启时，先把堆页改为可执行（`VirtualProtect(heap, size, PAGE_EXECUTE_READWRITE, ...)`）或在堆上布置 ROP 链，再让 handler 指向堆；否则堆 handler 会被 DEP 拒绝。
- 变体二：handler 指向任意模块外可执行地址（内存映射文件、RWX 区）同理绕过 SafeSEH，见关联的未注册模块/映射区跳板卡。
- 关联：[[code-analysis-reverse-windows-safeseh-unregistered-module-trampoline-bypass]]（借未启用 SafeSEH 的 DLL 跳板）、[[code-analysis-reverse-windows-sehop-chain-forge-bypass]]（SEHOP 链伪造，需与 SafeSEH 同时考虑）、[[binary-pwn-stack-win-dep-ret2libc-virtualprotect-bypass]]（DEP 绕过，处理本卡 DEP 开启的边界）。
- 边界：DEP 开启且堆不可执行、SafeSEH+SEHOP+ASLR 全开且无信息泄露、无法触发异常时本手法失败；x64 使用表驱动异常处理，栈上 SEH 覆盖不适用。

## 检测与防御

- 检测：异常发生前 `ExceptionList` 链中 handler 指向堆/映射区等非模块地址；进程异常处理期间 EIP 落在堆区；栈上 SEH 记录被写、handler 字段为堆地址。
- 防御：保持 DEP 开启（`/NXCOMPAT`）并配合 SafeSEH、SEHOP、ASLR、GS；对关键进程启用 AlwaysOn DEP；监控并阻断向堆页添加执行权限的调用。
- 加固：异常处理器注册走编译器安全表，避免自定义 SEH；及时更新系统并避免关闭保护机制做兼容；对 `strcpy` 类溢出点做安全函数替换与代码审计。
