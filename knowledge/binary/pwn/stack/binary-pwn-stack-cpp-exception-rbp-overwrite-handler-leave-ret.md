---
id: binary-pwn-stack-cpp-exception-rbp-overwrite-handler-leave-ret
title: 异常处理中的 saved RBP 劫持：溢出改写 rbp，handler 尾声 leave;ret 从 [rbp+8] 取返回地址调用任意 GOT 函数
type: scenario
domain: binary
path: binary/pwn/stack
technique: cpp-exception-handler-rbp-overwrite-leave-ret
aliases:
- 异常处理 rbp 覆盖
- handler leave ret 劫持
- C++ 异常栈帧劫持
- 溢出 rbp 控制返回地址
- exception unwind rbp hijack
tags:
- pwn
- stack
- cpp
- exception
- unwind
- rbp
- leave-ret
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
  verified_at: '2026-11-13T08:36:58+08:00'
  notes: 已对照原文与全部17张截图核对：img03 栈结构（rbp 距 buf 0x30，canary 蓝框）、img04 送 0x31 字节后 saved rbp=0x7fffffffdd0a（低字节 0x0a）、img05 崩溃于 main+233 0x5555555553f4 ret、img06 IDA loc_13EF mov rbx,[rbp+var_8]; leave; retn、img07 handler __cxa_begin_catch 处 RBP=0x7fffffffdd0a、img08 rbp=GOT-8 后 ret 跳入 puts（RSP=0x404048 __cxa_end_catch@got.plt）——均与卡内一致。boundary：与既有 binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass（覆盖返回地址选 landing pad）被覆盖字段与劫持点不同，dedup related/new 成立；dup-scan无涉及本卡pair。原文未标版本/组件区间（仅 Ubuntu 22.04 测试环境），未设 affected_versions。内部链接均存在。PoC未复跑。
---

## 一句话结论

C++ 程序在溢出后 `throw` 异常时，控制流不会经过漏洞函数的 `ret`（canary 校验被跳过），但异常 handler 的尾声常用 `leave; ret`：`leave` 把 `rbp` 恢复为栈上被溢出的 saved RBP，`ret` 再从 `[rbp+8]` 取返回地址——因此覆盖 saved RBP 为「目标地址 - 8」（如 GOT 项地址 - 8）就能在 handler 返回时跳到 `[rbp+8]` 指向的函数指针（原文把 rbp 指向 GOT，成功在异常处理中调用 `puts`），实现与栈迁移前半段类似的控制流劫持。

## 原理

- **异常路径绕过函数尾声**：`throw` 之后走 `__cxa_throw` → unwind → 找到 handler，漏洞函数剩余的尾声（含 canary `__stack_chk_fail` 检查）根本不会执行；但 handler 结束后仍要恢复被展开的栈帧上下文，其尾声通常是 `mov rbx,[rbp-8]; leave; ret`。
- **leave 的语义**：`leave` 等价于 `mov rsp, rbp; pop rbp`——它先用当前 `rbp` 设置栈指针并弹出 saved RBP。若溢出改写了漏洞函数的 saved RBP，unwind 后 handler 使用的 `rbp` 就是攻击者控制的值（原文 0x31 长度输入把 rbp 低字节改成 `0x0a` 后，handler 入口处 rbp 已是被覆盖值，见原文图 04/07）。
- **ret 取址**：`leave` 后 `rsp = 旧 rbp + 8`，随后 `ret` 从 `[rbp+8]`（新 rbp 的值 + 8）取返回地址。把 saved RBP 覆盖为 `X - 8`，`ret` 就会跳到地址 `X` 处存放的指针所指向的函数——将 `X` 选为 GOT 表项即可调用对应 libc 函数（原文关闭 PIE 后把 rbp 指向 GOT，成功调用 `puts`）。
- **为什么能成立**：unwinder 恢复的 callee-saved 寄存器（含 rbp）来自被溢出的栈帧；handler 尾声信任这些值并按 ABI 使用。只要溢出能写到 saved RBP，就能让 handler 的 `leave;ret` 变成一次受控的间接跳转。
- **前提**：目标用帧指针（`-fno-omit-frame-pointer`）保存栈帧；若程序只用 rsp 加减固定偏移表示帧（省略帧指针优化），该手法失效（原文注明）。

## 触发条件

- 存在栈溢出且溢出点位于会触发 C++ 异常的代码路径（例如 `read` 后 `if(len > n) throw ...`，溢出在检查前已发生）。
- 二进制使用帧指针并开启 C++ 异常（Itanium ABI/libstdc++），handler 尾声为 `leave;ret`。
- 攻击者能控制溢出内容到 saved RBP（通常 offset = 缓冲区到 rbp 的距离，原文 rbp 距 buf 0x30）。
- 目标函数指针地址可预测（non-PIE）或已泄露基址。

## 利用步骤

1. 触发并分析 crash：发送 `'a'*0x30 + '\n'` 使 `read` 覆盖 saved RBP 低字节为 `0x0a`，程序在异常 handler 返回处崩溃（原文图 01/05）。
2. 定位 handler 尾声：在 IDA/GDB 中找到异常处理结束后的 `mov rbx,[rbp-8]; leave; ret`（原文 `0x5555555553f4` 附近），确认 `rbp` 来自被覆盖的 saved RBP。
3. 计算偏移：缓冲区到 saved RBP 的距离（原文 rbp 距 buf 0x30），payload = 填充 + `p64(目标-8)`。
4. 选目标：把 rbp 指向 GOT 表项 - 8，则 `ret` 读取 GOT 中的函数地址并跳转（原文用 `p64(0x000000000404038)` 让 rbp+8 落在 GOT，测试调用 `puts`）。
5. 触发异常（输入超过检查长度使 `throw` 执行），观察 handler 返回值跳转到目标函数；进一步可把 rbp 指向可控内存中的函数指针链，或落到栈上 ROP 布局。

## PoC

```python
from pwn import *
# 关闭 PIE 的测试程序：溢出覆盖 saved rbp，令 handler 尾声 leave;ret 跳到 GOT 中的 puts
payload = b'a' * 0x30            # 填满 buf 到 saved rbp（原文 rbp 距 buf 0x30）
payload += p64(0x404038)         # saved rbp = GOT项地址-8，使 [rbp+8] 命中 GOT
io.send(payload)
# 异常抛出后 handler 执行 leave;ret，成功调用 puts（原文图 08）
```

说明：原文以 `b'a'*n + p64(0x000000000404038)` 验证调用 puts；实际利用还需按目标栈布局微调并保证异常被抛出。

## 变体与关联

- 与 [[binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass]] 的区别：那张卡覆盖「返回地址」为 catch landing pad 并绕过 canary；本卡覆盖「saved RBP」，利用 handler 尾声 `leave;ret` 从 `[rbp+8]` 取址调用任意指针，二者是异常处理中两个不同的可写帧字段。
- 与常规栈迁移（leave;ret pivot）同源：正常返回地址被 canary 保护，但异常路径让 saved RBP 成为绕过点。
- 进一步：配合 CHOP（[[binary-pwn-stack-chop-cxa-call-unexpected-golden-gadget]]）可实现任意指针调用。
- 边界：省略帧指针（`-fomit-frame-pointer`）或 handler 用 rsp 相对寻址时失效；开启 shadow stack/CFI 可拦截。

## 检测与防御

- 检测：崩溃现场 `RBP` 为攻击者填充值（如 `0x6161...`）且崩溃点是 handler 尾声 `leave;ret`；异常路径上出现异常的超长输入；`.eh_frame`/handler 代码被用作跳板。
- 修复：源码层先校验长度再 `read`（原文代码的 `if(len > 0x10) throw` 在拷贝之后，不能阻止溢出），改用安全的读取接口（`fgets`/`read` 限定长度）。
- 加固：编译开启 `-fstack-protector-strong` 与 `-fomit-frame-pointer` 只能降低局部可用性；真正的防护是 Intel CET shadow stack / 向后边沿 CFI（如 LLVM CFI）与 ASLR/PIE；及时更新 libstdc++。
