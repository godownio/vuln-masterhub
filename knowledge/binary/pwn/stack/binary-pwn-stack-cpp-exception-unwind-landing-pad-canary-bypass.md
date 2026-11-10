---
id: binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass
title: C++ 异常展开伪造调用帧：把返回地址改成 catch landing pad 跳过 canary 校验并 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: cpp-exception-unwind-landing-pad-canary-bypass
aliases:
- C++ 异常处理 canary 绕过
- __gxx_personality_v0 栈展开利用
- catch landing pad 劫持
- 异常展开伪造返回地址
- __cxa_throw pwn
- C++ exception pwn
- 异常展开 ROP
tags:
- pwn
- stack
- canary
- cpp
- exception
- unwind
- landing-pad
- rop
- libstdc++
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:56:49+08:00'
  notes: 已对照原文与 img01-08 核对：mini_email 0x402EDE call edit/0x402EE3 landing pad、GFCTF exception PIE+0x1408 canary 校验与 add rsp,0x18;pop rbx;pop rbp;ret、GFCTF control 0x402237 leave;ret 均符；羊城杯 logger 异常对象 sink 仅作边界引用，已由 ctf-pwn-cpp-exception-payload-src-system-command 覆盖；staging 草稿已同步为知识库版本；未执行
---

## 一句话结论

在启用 C++ 异常（Itanium ABI / libstdc++）且开启栈 canary 的程序里，栈溢出覆盖“抛出异常的函数”的保存返回地址为调用方 try 块的 catch landing pad 入口（通常就是 `call 漏洞函数` 的下一条指令地址），可让 `_Unwind_RaiseException` 的 personality routine 把伪造的调用帧识别为带匹配 catch 的帧，控制流直接跳到 landing pad，从而完全跳过漏洞函数正常尾声里的 canary 校验；再控制保存 RBP 和栈布局，可让 catch 结束后的尾声 `ret` 进入 ROP 链。

## 原理

- C++ 异常（GCC/Clang Itanium ABI）的处理链是：`throw` → `__cxa_allocate_exception` 分配异常对象 → `__cxa_throw(obj, typeinfo, dtor)` 初始化异常头 → `_Unwind_RaiseException(&header->unwindHeader)`。
- `_Unwind_RaiseException` 分两阶段。第一阶段 SEARCH：沿调用链逐帧重建上下文（CFA + 保存的返回地址），对每帧调用 personality routine `__gxx_personality_v0`；personality 用该帧的 PC（对上层帧而言就是当前帧里的保存返回地址）去查 `.eh_frame` 的 FDE 和 `.gcc_except_table` 的 LSDA call-site 表，判断 PC 是否落在 try 覆盖范围、以及是否有类型匹配的 catch。找到后返回 `_URC_HANDLER_FOUND`。
- 关键点：unwinder 判断“上层函数是哪个、有没有 catch”依据的是栈上保存的返回地址，而这个值可以被栈溢出改写。把返回地址写成“调用方 try 块里 `call 漏洞函数` 的下一条指令地址”（landing pad 入口/join 点），personality 就会认为该帧属于带 catch 的调用方，并选中对应的 landing pad。
- 第二阶段 UNWIND：unwinder 重新走栈、执行清理，最后把寄存器恢复成该帧的上下文并跳到 landing pad；landing pad 以 `rax` = 异常对象指针、`rdx` = action 选择子进入（`rdx==1` 走 catch，否则 `call _Unwind_Resume` 继续展开）。
- 因为控制流不是从漏洞函数 `ret` 返回，漏洞函数自己的函数尾声（典型形式 `mov rcx,[rbp-0x18]; xor rcx, fs:0x28; jz ok; call __stack_chk_fail`）根本没有执行——这就是 canary 被绕过的本质。canary 本身没有被改写，被改写的是“代码路径”。
- landing pad 头部通常也包含编译器插入的 canary 校验与 join 点（因为它是 try 块结束后正常执行流的入口）。此时校验用的 `[rbp-0x18]` 依赖展开恢复的 `rbp`，而 `rbp` 来自被溢出的保存 RBP：让保存 RBP 指向攻击者放在栈上的 canary 副本，`[rbp-0x18]` 就会读到正确值而通过校验（前提是先泄露 canary）。
- 校验通过后，join 点的尾声（如 `add rsp, 0x18; pop rbx; pop rbp; ret`）从被覆盖的栈帧取返回地址，进入预先布置的 ROP 链。整个过程不需要知道 canary 的“原始内存位置”，只需知道它的值。

## 触发条件

- Linux ELF，C++ 编译且启用异常：二进制/依赖中出现 `__cxa_throw`、`__cxa_allocate_exception`、`__cxa_begin_catch`、`__cxa_end_catch`、`_Unwind_Resume`、`__gxx_personality_v0` 等符号。
- 漏洞函数被调用方的 `try` 块包住（或调用链上存在可被伪造帧命中的 try/catch），且漏洞函数内有可达的栈溢出（`read`/`strcpy`/`memcpy` 等），能覆盖保存 RBP 与返回地址。
- 能把返回地址精确写成 landing pad 头部地址；PIE 下需泄露 PIE 基址，非 PIE 可用固定地址。原文实测写成 landing pad 内部的偏移地址会失败，必须命中头部/join 点。
- 若 landing pad 头部有 canary 校验，需要泄露 canary，并控制保存 RBP 使其 `[rbp-0x18]` 指向栈上的 canary 副本；若目标 landing pad 不校验 canary（某些编译布局），则可直接进入 ROP。
- 能触发异常：常见有超长输入触发 `std::length_error`（如 `std::string` 分配/长度检查）、显式 `throw`、或程序自身会调用 `__cxa_throw` 的分支。

## 利用步骤

1. 逆向定位异常结构：找漏洞函数调用点的 `call` 指令和下一条指令地址（landing pad/join 点），确认 `__gxx_personality_v0`、`__cxa_throw`、`__cxa_begin_catch`、`_Unwind_Resume` 的交叉引用；用 IDA 的异常视图或 `.gcc_except_table` 验证 catch 类型和 landing pad。
2. 找栈溢出点，计算缓冲区到保存 canary / 保存 RBP / 返回地址的偏移，确认溢出长度足够覆盖到调用方栈帧。
3. 泄露所需地址：canary、PIE 基址、栈地址（格式化字符串、越界读、`puts` 打印 GOT 等），并找 `pop rdi; ret`、`ret`、`system`/`execve` 或 ORW gadget。
4. 构造第一段溢出：填充 + 保存 canary（若后续路径会校验）+ 伪造保存 RBP + 返回地址 = landing pad 头部 + 第二段栈数据（canary 副本 + ROP）。
5. 让程序进入抛异常路径（输入触发 `std::length_error`、选择 throw 分支等）。unwinder 沿伪造帧找到 catch，跳到 landing pad。
6. landing pad 的 canary 校验通过后，catch 代码执行 `__cxa_begin_catch`/catch 体/`__cxa_end_catch`，再跳回 join 点，尾声 `ret` 进入 ROP，完成 libc 泄露后 `system("/bin/sh")` 或 ORW。

## PoC

以下为按原文 GFCTF exception 场景提取的最小结构（偏移/地址为原题示例，必须按目标重算；未在本机复跑）：

```python
# 溢出位于 vuln，调用方 main 在 pie+0x1403 call vuln，pie+0x1408 是 landing pad 头
payload  = b'A' * 0x68           # 到 canary
payload += p64(canary)           # 漏洞函数 canary（若后续路径需要）
payload += p64(stack + 0xa0)     # 伪造 saved rbp：landing pad 检查 [rbp-0x18] 时读到 stack+0x88
payload += p64(pie + 0x1408)     # 保存返回地址 = call vuln 的下一条指令 = catch landing pad 头
payload += b'A' * 8
payload += p64(canary)           # 放在 stack+0x88 的 canary 副本，供 landing pad 校验
payload += b'A' * 0x18
payload += p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)  # catch 后 join 点 ret 进入
p.send(payload)
```

变体要点（landing pad 不做 canary 校验时更简单）：

```python
# 无 PIE 的 mini_email 类布局：把 edit 的返回地址写回 call edit 的下一条指令
payload  = b'A' * 0x128
payload += p64(0x402ee3)         # call edit 之后、landing pad/jmp 入口
payload += b'A' * 0x20
payload += p64(puts_got) + ...   # 调用方栈帧的返回地址处布置 ROP
```

## 变体与关联

- **mini_email 型**：`vuln` 内 `call edit` 后紧跟 `jmp goto_start`（landing pad），溢出把 `edit` 的返回地址写回该地址；`vuln` 帧的保存返回地址处放 ROP。抛异常后展开跳过 canary 检查，退出后先 `puts` 泄 libc，再 `system("/bin/sh")`。
- **GFCTF exception 型**：保存返回地址必须精确为 `PIE+0x1408`（不能在 landing pad 内部加偏移）；landing pad 头先做 `[rbp-0x18] xor fs:0x28` 校验，因此把保存 RBP 指向栈上 canary 副本，catch 后由 `add rsp,0x18; pop rbx; pop rbp; ret` 进入 ROP。
- **GFCTF control 型**：返回地址本身就是 `leave; ret`（`call vuln` 的下一条指令），无需覆盖返回地址；partial overwrite 保存 RBP，让 `leave; ret` 把栈迁到 `read` 写入的 ROP 上，1/16 概率爆破。
- **关联卡片**：[[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]]、[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（其余 canary/栈帧绕过思路）。
- **边界（另一原子）**：同一原文中“异常对象保存指向可控全局缓冲区的指针，catch 把 `__cxa_begin_catch` 返回值交给 `system`”属于异常对象 sink，不是本卡的伪造调用帧原子；该原子已由 [[ctf-pwn-cpp-exception-payload-src-system-command]] 覆盖，本卡不重复展开。

## 检测与防御

- **代码层**：所有外部输入使用有界读写（`fgets`/`read` 严格限制长度、C++ 用 `std::string`/`std::vector` 而非裸数组）。
- **编译与缓解**：不需要异常时使用 `-fno-exceptions` 缩小攻击面；`-fstack-protector-strong/all` 不能防御本手法（正常 epilogue 被异常展开跳过），只能提高其它路径的门槛；开启 PIE/ASLR 并避免地址泄露；启用 CET/CFI 可提高 landing pad 与 gadget 劫持门槛。
- **检测特征**：二进制中同时存在 `__cxa_throw`/`__gxx_personality_v0` 与无界 `read`/`strcpy`；崩溃回溯中 RIP 落在 `.gcc_except_table` 对应的 landing pad 且 RBP 异常；异常抛出前后的栈帧返回地址指向非正常调用者；日志中出现 `std::length_error`/`std::out_of_range` 且伴随超长输入。
