---
id: binary-pwn-stack-cpp-unwind-destructor-vtable-hijack-skip-canary
title: 栈上 C++ 对象的虚表指针被溢出改写 + raise() 抛异常走 unwind 跳过 __stack_chk_fail：unique_ptr 析构时的虚调用变成任意代码执行（自定义 canary 也拦不住）
type: scenario
domain: binary
path: binary/pwn/stack
technique: cpp-object-vtable-overwrite-destructor-call-via-exception-unwind
aliases:
- n1canary
- 自定义 canary 绕不过异常展开
- 析构函数虚调用劫持
- unique_ptr 析构 call rdx
- 栈上对象虚表指针覆盖
- 异常展开跳过 stack_chk_fail
- default_delete 函数指针调用
tags:
- pwn
- stack
- canary
- cpp
- exception
- unwind
- vtable
- destructor
- unique_ptr
- rop
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:55:31+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；demo 源码（read 0x100 到 buf[0x10]、len>0x10 时 throw）、canary 保护输出、0x70 输入点到目标指针距离、getrandom 64 字节 sys_canary + 用户 64 字节 user_canary 的 getCanary=(addr>>4)&7 索引异或、check()→raise()、default_delete::operator() 的 call *(*(a2)+8)、_Unwind_RaiseException+463 返回地址检查需填回 0x403407、user_canary 0x4F4AA0 与 backdoor 0x403387 均与正文一致；正文最终 exp 里第二次 sendlineafter 是注释状态（作者未把该行写全），卡片 PoC 已补上该发送动作，属还原；未在本地复跑二进制
---

## 一句话结论

C++ 程序把对象指针（如 `std::unique_ptr<BOFApp>` 的 `v6`）**放在栈上**，而该对象在栈溢出范围内可达时，即使程序自己实现了「自定义 canary + 系统 canary」双重校验，也能靠**让溢出必然篡改 canary、从而必然在 `check()` 里走 `raise()` 抛异常**把控制流送进异常展开：栈回退不执行漏洞函数的正常尾声，`__stack_chk_fail` 与自定义 canary 校验一起被跳过，最后 `unique_ptr` 析构经 `default_delete::operator()` 的 `call *(vtable+8)` 调用被改写过的虚表指针，直接落到后门函数。

## 原理

- **溢出点与对象指针同栈**：`BOFApp::launch()` 里 `scanf("%[^\n]")` 相当于 `gets()`，输入缓冲区到目标指针距离 0x70；被测对象是 `std::make_unique<BOFApp>(&v6)` 生成的堆对象，其指针 `v6` 就落在同一栈帧上。溢出既能改缓冲区内的自定义 canary，也能改 `v6`。
- **自定义 canary 的构造**：`init_canary()` 用 `getrandom` 取 64 字节 `sys_canary`，再读用户提交的 64 字节 `user_canary`（写进 `.bss`），`getCanary(addr) = user_canary[(addr>>4)&7] ^ sys_canary[(addr>>4)&7]`；`ProtectedBuffer::check()` 比较栈上保存的副本与重算值，不等就 `raise("*** stack smash detected ***")`。**只要溢出长度必然越过自定义 canary 字段，就必然触发 raise**——这不是要绕过的障碍，而是利用链的开关。
- **异常展开为什么能跳过 canary**：`raise()` 调 `__cxa_allocate_exception` + `__cxa_throw`，进入 `_Unwind_RaiseException` 两阶段展开。从抛出点到 `__teminate`/handler，沿途函数的**正常尾声（`leave; ret` 与 `__stack_chk_fail` 调用）根本不会执行**；程序沿着调用链回退去找 catch，找不到就由 handler 负责清理（包括析构已构造的对象），于是 `__stack_chk_fail_local` 与自定义 `check()` 的后续逻辑全被跳过。
- **析构处的函数指针调用**：`std::unique_ptr<BOFApp>::~unique_ptr()` → `std::default_delete<BOFApp>::operator()(a1,a2)` 里 `if (a2) return (*(...)(*(_QWORD*)a2 + 8))(a2);`——即 `call *(vtable+8)`，`a2` 就是那个栈上的 `v6`。因此**控制 `v6` 的值就控制了解引用位置，进而控制 `rdx`/调用目标**：把 `v6` 指向 `.bss` 里攻击者自己的 `user_canary` 缓冲区，并在该处伪造虚表（`[0]=0`、`[1]=后门地址`），`call *(vtable+8)` 就跳到后门。
- **为什么必须把 `v6` 指到可控区而不是直接塞后门地址**：解引用是「两次」——先读 `*(_QWORD*)a2` 得到虚表指针，再加 8 取出函数指针。所以 `a2` 必须是「一个存放着虚表地址的可读地址」，即伪造虚表的起点；把 `user_canary` 写成 `p64(fake_vtbl+8) + p64(backdoor)*2` 正好满足「`[a2]` = 指向后门的槽」。
- **返回地址不能乱填**：unwind 会沿栈上的返回地址逐帧检查是否有匹配 catch，填垃圾会让 `_Unwind_RaiseException` 在检查阶段崩掉（实测在 `+463` 处），所以溢出里被覆盖的调用者返回地址要填回原值（本例 `0x403407`），只让 `v6` 与 canary 被改。

## 触发条件

- C++ 程序，存在能覆盖到栈上「对象指针/虚表指针」的溢出（`scanf("%[^\n]")`、`gets`、无界 `read`、`memcpy`）。
- 程序有抛异常路径，且该路径**必然被触发**（本例：溢出一定破坏 canary → `check()` → `raise()`）；或攻击者能主动触发 `throw`。
- 抛出点向上到 handler 的调用链上没有能捕获该异常类型的 catch（否则会正常进 catch），最终由运行时 handler 负责析构清理。
- 攻击者能写一段可控内存（`.bss`、`.data`、堆）并在其中伪造虚表；非 PIE 可直接用固定地址，PIE 下需要泄露。
- 被析构对象的指针在溢出范围内（本例 `v6` 偏移 0x70 处）。

## 利用步骤

1. 逆向确认三处：溢出点偏移（到 canary、到 `v6`、到 saved rbp/ret）、`check()`→`raise()` 的触发条件、析构路径 `~unique_ptr` → `default_delete::operator()` 里的 `call *(*(a2)+8)`。
2. 找一个**可写且地址已知**的伪造虚表落点：本例 `user_canary` 在 `.bss`（`0x4F4AA0`），因为程序会把攻击者第一次输入写进去，正好当「攻击者可控数据区」。
3. 第一次输入（`give me your canary`）布置伪造虚表：`p64(fake_vtbl+8) + p64(backdoor)*2`，补齐 0x40。
4. 第二次输入（`launch()` 的 `scanf`）构造溢出：`'a'*(0x70-8)` 填到返回地址字段 + `p64(原返回地址)`（让 unwind 的返回地址检查通过）+ `p64(user_canary)`（改写栈上的 `v6`）。中途必然打坏自定义 canary，这正是要的。
5. 触发后：`check()` 失败 → `raise()` → 展开跳过 `__stack_chk_fail` → handler 里析构 `unique_ptr` → `call *(user_canary+8)` → 后门（本例后门直接执行 `/readflag`）。
6. 若目标析构路径不同（例如 `delete p` 直接调 `~T()` 而非经 `default_delete`），把伪造虚表的槽位对齐到实际被取的偏移（`call *(vtbl+0)` 表示析构函数槽，`+8` 表示 deleting destructor 槽）。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p = process('./n1canary')

backdoor   = 0x403387          # 后门函数（程序里没有任何引用）
user_canary = 0x4F4AA0         # .bss 里由第一次输入写入的可控缓冲区

# 第一次输入：伪造虚表（[0] 指向 +8 槽，[1] 与 [2] 都放后门）
payload  = p64(user_canary + 8) + p64(backdoor) * 2
payload  = payload.ljust(0x40, b'a')
p.sendafter(b'canary\n', payload)

# 第二次输入：0x70 处是栈上的 BOFApp *v6，把它改成伪造虚表地址
payload  = b'a' * (0x70 - 0x8)
payload += p64(0x403407)       # 原调用者返回地址：unwind 检查返回地址时必须合法
payload += p64(user_canary)    # 覆盖栈上的对象指针 v6 -> 伪造虚表
p.sendlineafter(b' to pwn :)\n', payload)

p.interactive()
```

对应的关键汇编语义（等价伪代码）：

```c
// default_delete<BOFApp>::operator()
if (a2)                                   // a2 == 被覆盖的 v6
    return (*(__int64 (**)(__int64))(*(_QWORD *)a2 + 8))(a2);
//                                    ^^^^^^^^^^^^ 伪造虚表 +8 = 后门
```

## 变体与关联

- **变体（只改 rbp 的栈迁移）**：若溢出只能改到 saved rbp 而改不到返回地址，就把 rbp 改成 `&目标函数指针 - 8`，利用 handler 尾声的 `leave; ret` 让 `[rbp+8]` 当返回地址（原文 demo 用 `padding + p64(0x404050-0x8)` 调到 GOT 里的 `puts`）。前提是调用链上存在能匹配该异常类型的 catch（否则走 `__terminate`）。
- **变体（借一个不存在的 catch）**：把返回地址写成某个函数 **try 块入口**（左开区间，实测写成 try 内部偏移会失败），unwind 的 personality 会认为该帧带匹配 catch 从而执行该函数的 catch 体——即使这个函数从未出现在调用链上（可用来触发从未被引用的后门代码）。
- **变体（自定义 canary 是可预测的）**：本例 `getCanary` 用 `(addr>>4)&7` 索引 `user_canary^sys_canary`，若同一地址反复使用，可直接算出正确值从而**不触发**异常；但那样就走不到析构路径，「故意打坏 canary 触发 unwind」才是本链的关键。
- **关联**：[[binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass]]（同属「C++ 异常展开跳过 canary」，但那条改的是**返回地址指向 landing pad**、依赖 `__gxx_personality_v0` 认可的 try 范围；本卡改的是**栈上对象指针/虚表**，靠运行时 handler 里的析构虚调用收尾，不需要伪造调用帧）、[[ctf-pwn-cpp-exception-payload-src-system-command]]（同一原文系列的 catch 后门 sink 变体）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（同为函数指针劫持，那条在堆上）。
- **边界**：`-fno-exceptions` 编译时无 unwind 可借；析构对象若在堆上且指针不在溢出范围，需要另找可控指针；启用了 CFI/CET 时伪造虚表的间接调用会被拦；unwind 检查返回地址，溢出里被覆盖的 ret 必须填回合法值。

## 检测与防御

- **代码层**：`scanf("%[^\n]", buf)` 一律换 `fgets`/`std::string` 限长读；对象不要以裸指针形式放在溢出可达的栈槽里（用 `unique_ptr` 的成员而非栈上的裸指针，或把对象完全放堆上并让指针不可覆盖）。
- **缓解**：`-fstack-protector-strong` 与自实现 canary 都不防本手法（异常展开绕过正常尾声），必须靠 CFI/CET（`-fsanitize=cfi`、`-fcf-protection`）与 `-fno-exceptions` 缩小面；堆指针/虚表放只读段。
- **检测**：崩溃回溯里 RIP 落在 `_Unwind_RaiseException`/`__cxa_throw` 且栈上出现被改写的对象指针；程序日志出现 `stack smash detected` 类自定义告警后紧接后门执行（应为 `abort`）；二进制里同时存在 `__cxa_throw`、虚调用（`call qword ptr [rax+8]`）与无界 `%[^\n]` 读入，是审计优先级最高的组合。
- **运行期**：对 `default_delete`/`delete` 路径的间接调用开启 CFI 后校验目标是否在合法虚表集合内；把 `__cxa_throw` 异常路径打点监控（正常业务不应在输入校验失败时抛异常）。
