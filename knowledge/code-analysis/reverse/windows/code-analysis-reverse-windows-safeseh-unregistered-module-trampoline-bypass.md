---
id: code-analysis-reverse-windows-safeseh-unregistered-module-trampoline-bypass
title: SafeSEH 绕过：SEH handler 指向未启用 SafeSEH 的 DLL 中 pop pop ret 跳板，再跳栈上 shellcode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: safeseh-unregistered-module-trampoline
aliases:
- SafeSEH 未启用模块绕过
- 未注册 SafeSEH 的 DLL 跳板
- pop pop ret SEH 跳板
- SafeSEH 模块检查绕过
- Map 映射文件跳板
- 异常处理跳板
tags:
- windows
- seh
- safeseh
- exception-handler
- stack-overflow
- trampoline
- pop-pop-ret
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
  verified_at: '2026-11-11T15:31:08+08:00'
  notes: 已对照原文与13张截图核对并修正：OllyDbg链地址0x19FE80是SEH记录起始(next指针)，handler字段在记录+4(0x19FE84,偏移212)；原文payload跳板实际落在偏移212，记录起始仅4个NOP，pop pop ret后ret到EstablisherFrame=记录起始，会撞上handler地址字节(EE 15 91 56=out dx,al)，原文未证明进入shellcode、无成功截图；已按EB 06短跳越过handler字段的布局修正原理/步骤/PoC/证据，confidence降为medium。跳板地址0x560C15EE(静态反汇编与payload)与截图运行地址0x569115EE仅DLL基址不同。
---

## 一句话结论

SafeSEH 的 `RtlIsValidHandler` 只在 handler 所属模块"存在安全 SEH 表"时查表；若 handler 指向一个**没有启用 SafeSEH 的模块**（或 Map 类型的内存映射文件），校验直接放行。加载这样一个 DLL，在其中找 `pop eax; pop eax; retn`（pop pop ret）跳板作为 SEH handler；跳板的 retn 会返回 EstablisherFrame（即 SEH 记录起始的 next 指针字段），因此还需在记录起始处布置短跳（如 `EB 06 90 90`）越过记录 +4 的 4 字节 handler 字段、落到其后的栈上 shellcode，即可在 SafeSEH 开启时执行任意代码。

## 原理

- **SafeSEH 的分支校验**：`RtlDispatchException` 先检查异常链在栈上、handler 不指向当前栈；随后 `RtlIsValidHandler` 判断 handler 是否位于当前加载模块的内存空间。只有"在模块内"才继续检查 `IMAGE_DLLCHARACTERISTICS_NO_SEH` 与安全 SEH 表；**handler 位于未启用 SafeSEH 的模块（该模块无安全 SEH 表）时，表项匹配无从进行，校验放行**。
- **为什么能借刀**：SafeSEH 是每个模块自己的编译/链接属性，主程序开启 SafeSEH 不代表它加载的第三方 DLL 也开启；老版本或未加 `/SAFESEH` 的 DLL 天然是合法跳板来源。DLL 代码段本身可执行，DEP 不会拦截。
- **跳板的选择与作用**：DLL 中 `void jump(){ __asm { pop eax; pop eax; retn } }` 编译出 `pop eax; pop eax; retn`。异常分发调用该 handler 时，栈上依次是返回地址与 `ExceptionRecord` 等参数；两次 `pop` 消耗 8 字节后，`retn` 跳到 `EstablisherFrame`——即 SEH 记录起始的 next 指针字段地址（原文截图中 EIP 落在 0x0019FE80）。因此 next 字段必须放一条短跳（如 `EB 06 90 90`）跳过紧随其后的 4 字节 handler 字段，才能落入 handler 字段之后的 shellcode。
- **payload 布局**：`test()` 的栈缓冲 `str[200]` 起始 0x19FDB0；最近 SEH 记录的起始（next 指针字段，也是 OllyDbg SEH 链窗口显示的地址）在 0x19FE80，偏移 208；handler 字段在记录 +4，即 0x19FE84，偏移 212。原文 payload 实际把跳板 `0x560C15EE` 写在偏移 212、216 起 8 字节 NOP、224 起 shellcode，但偏移 208 处（next 字段）只填了 NOP，没有跳过 handler 字段的跳转——按此布局 `retn` 落到记录起始后执行 4 个 NOP 即撞上 handler 字段的地址字节（截图中 `EE 15 91 56` 即 `out dx, al`），并不能落入 shellcode。
- **调试证据**：原文 OllyDbg 截图显示异常触发后 EIP 落在 `dll1.jump+1E`（截图运行中 DLL 基址为 0x56910000，即 0x569115EE；payload 十六进制与静态反汇编中的地址为 0x560C15EE，两者只是 DLL 加载基址不同），pop pop ret 后 EIP=0x0019FE80（SEH 记录起始）。截图只证明到这一步：接下来 4 字节 NOP 后是 handler 字段的地址字节，原文"紧接着后面就是 shellcode"的说法不成立，也没有 shellcode 成功执行截图；按本卡修正的布局（记录起始放短跳越过 handler 字段）才能落到 shellcode。
- **Map 映射文件变体**：类型为 Map 的内存映射文件（VMMap 中显示 MAP/-R--）不对应已加载模块，SafeSEH 对其地址同样不做校验；在其中找 gadget 可达到相同效果。

## 触发条件

- Windows x86 进程开启 SafeSEH，且能加载或已加载一个**未启用 SafeSEH 的模块**（第三方 DLL、老组件、内存映射文件）。
- 存在可覆盖栈上 SEH 记录的溢出（`strcpy` 到 `char str[200]` 等），偏移可计算。
- 能触发异常（除零、访问违例）进入异常分发。
- DEP 关闭或跳板/shellcode 位于可执行页（本例 `/NXCOMPAT:NO`）；ASLR 关闭或地址可预测（本例 `/DYNAMICBASE:NO`）；GS 关闭或已绕过。
- 能获得 DLL 跳板地址与栈 buffer 地址（无 ASLR 时固定，或配合泄露）。

## 利用步骤

1. 确认主程序开启了 SafeSEH（linker `/SAFESEH`），并准备/寻找一个未启用 SafeSEH 的 DLL；用调试器或静态工具确认其代码段有 `pop eax; pop eax; retn` 等跳板，记录地址（原文 0x560C15EE）。
2. 调试定位溢出缓冲起始（0x19FDB0）到最近 SEH 记录起始（0x19FE80，next 指针字段）的偏移 = 208；handler 字段在记录 +4（0x19FE84，偏移 212），宽度 4 字节。注意 OllyDbg SEH 链窗口的"地址"是记录起始，不是 handler 字段。
3. 构造 payload：NOP 填充到 208，在记录起始写短跳 `EB 06 90 90`（从记录起始跳过 4 字节 handler 字段），偏移 212 写跳板地址，偏移 216 起放 shellcode。
4. 程序 `strcpy` 溢出覆盖 SEH 记录；触发除零异常，`RtlDispatchException` 校验：链在栈上、handler 不在当前栈、handler 位于无 SafeSEH 表的模块 → 放行。
5. 调用跳板 `pop eax; pop eax; retn`，retn 落到记录起始的短跳，短跳越过 handler 字段后执行栈上 shellcode（DEP 关闭前提）。
6. 若目标无合适 DLL，检查 Map 类型映射文件中的 gadget 作为替代跳板。

## PoC

```python
import struct
p32 = lambda x: struct.pack("<I", x)

shellcode = b"\x90" * 16          # 占位：实际 shellcode（WinExec/下载执行等）
trampoline = 0x560C15EE           # 未启用 SafeSEH 的 DLL 中 pop eax; pop eax; retn
record_offset = 208               # 栈 buffer 到 SEH 记录起始（next 指针字段）的偏移

payload = b"\x90" * record_offset
payload += b"\xEB\x06\x90\x90"    # next 字段：短跳，越过记录 +4 处的 4 字节 handler 字段
payload += p32(trampoline)        # handler 字段（记录 +4）-> DLL 跳板
payload += shellcode              # 短跳落点：记录 +8 起的栈上 shellcode
open("111.txt", "wb").write(payload)
```

```text
# 触发路径：
# EIP = 0x560C15EE  dll1.jump+1E   pop eax; pop eax; retn
# retn -> 0x0019FE80（SEH 记录起始 / next 字段）：
#   原文 payload 在此只有 4 个 NOP，随后撞 handler 字段的地址字节，不能进入 shellcode
#   正确布局在此放 EB 06 90 90，越过记录 +4 的 handler 字段，落到记录 +8 的 shellcode
```

## 变体与关联

- 变体一：跳板可换 `pop; pop; ret`、`add esp,8; ret`、`leave; ret` 等能跳过异常分发栈残留并接上 shellcode 的指令序列。
- 变体二：无第三方 DLL 时，在 Map 类型映射文件（VMMap 显示 MAP）中找 gadget；SafeSEH 对非模块映射地址同样不做校验（原文只给原理，未演示）。
- 变体三：DEP 开启时跳板后接 ROP 链（VirtualProtect 等）而非栈上 shellcode。
- 关联：[[code-analysis-reverse-windows-safeseh-heap-handler-bypass]]（handler 指向堆的 SafeSEH 绕过）、[[code-analysis-reverse-windows-sehop-chain-forge-bypass]]（SEHOP 链伪造，与本卡组合时还需处理链尾校验）、[[binary-pwn-stack-win32-aslr-partial-overwrite-jmp-eax]]（Windows 32 位 ASLR 部分覆盖）。
- 边界：不存在未启用 SafeSEH 的可执行模块、SafeSEH+SEHOP+DEP+ASLR 全开且无信息泄露、或异常无法触发时本手法失败；x64 表驱动异常处理不适用。

## 检测与防御

- 检测：SEH handler 指向的模块不在安全 SEH 表/无 SafeSEH 属性（可用 `!exploitable`、PE 头 `DllCharacteristics`/Load Config 目录核对）；异常处理期间 EIP 落在 DLL 跳板后立即转到栈区；进程加载无 SafeSEH 的第三方 DLL。
- 防御：所有加载模块统一启用 `/SAFESEH`（x86）或改用 x64 SEH；启用 SEHOP、DEP、ASLR、GS；限制 LoadLibrary 白名单，避免加载不受控 DLL。
- 加固：审计第三方组件是否启用 SafeSEH；对关键进程启用 Exploit Protection 的 SEHOP 与强制 ASLR；及时淘汰无保护的老旧 DLL。
