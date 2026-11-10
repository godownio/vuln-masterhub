---
id: binary-pwn-heap-environ-leak-fixed-offset-stack-hijack
title: 用 environ 作 libc↔栈地址桥：泄露 environ 得栈地址 + 固定偏移定位函数 epilogue 的 rsp，再用任意地址写覆盖返回地址劫持控制流
type: scenario
domain: binary
path: binary/pwn/heap
technique: environ-leak-fixed-offset-stack-return-hijack
aliases:
- environ 打栈
- environ 泄露栈地址
- 堆题攻击栈空间
- 固定偏移覆盖 rip
- tcache 打到栈
- environ 到 rsp 偏移
tags:
- pwn
- heap
- environ
- stack-leak
- arbitrary-write
- tcache
- stack-hijack
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:31:48+08:00'
  notes: 已对照原文核对；本次核对未读取图片；environ 作为 libc↔栈桥梁、0x138 与 0x188 固定偏移、tcache 毒化任意地址写、先申请到 environ-0x400 避开 memset、2.35 safe-linking 异或编码、写 rsp+0x10 跳过 canary 与索引槽均与正文一致。未验证点：例题与 EzHeap 的 EXP 未执行，具体偏移与 gadget 值未实测
---

## 一句话结论

`environ` 是 libc 里的全局变量，其值是指向栈上环境变量数组的指针，因此「libc 地址 → environ 内容 → 栈地址」构成一条把 libc 世界与栈世界连起来的固定桥梁；只要程序同时具备任意地址写与一处栈地址泄露，就能毒化分配器把 chunk 落到某个函数 epilogue 的 `rsp` 附近，覆盖返回地址完成控制流劫持。

## 原理

- `environ`（`__environ`）与 libc 同处一个映射，`environ` 符号地址 = libc 基址 + 固定偏移；它保存的**值**是栈上 `envp` 数组的起始指针，所以一次 8 字节读就同时得到「libc 的具体版本位置」与「当前进程栈的大致位置」。
- 栈地址与某个函数栈帧之间的距离在**同一二进制、同一启动方式**下是常量：`main`/目标函数执行到 `leave; ret` 时 `rsp` 与 environ 指向地址之差固定（例题为 `0x138`，CISCN2024-EzHeap 为 `0x188`）。这正是把「能泄露的栈地址」换算成「要写的返回地址」的关键，偏移需自行 gdb 标定，环境变量条数与长度变化会改变该偏移。
- 任意地址写的通用来源是分配器元数据劫持：tcache 从链表中取块时不校验 `fd` 指向是否属于堆，把 `fd` 改成目标地址即可让下一次 `malloc` 返回该地址。glibc 2.32+ 的 safe-linking 把 `fd` 变成 `next ^ (fd字段地址 >> 12)`，因此需要先用「已知的 chunk 地址 >> 12」做异或编码；2.31 及更早无此编码，直接写裸地址。
- 直接写到 `environ` 上会踩两个坑：一是多数菜单题的 `add` 在 `malloc` 后会 `memset(ptr, 0, size)`，目标 chunk 覆盖到 `environ` 就把栈指针清零；二是栈帧上 `rsp-0x8` 常放着程序自身的索引/局部变量，`rsp-0x10` 之后是 canary 与保存的 `rbp`。因此正确做法是把 chunk 起点放到目标地址**之前**一段（如 `environ-0x400`），先把这段填满再让读取越过它读到 `environ`；写返回地址时则精确落在 `rsp+0x10`（跳过 canary 与索引槽），并保证 canary/rbp 不被破坏以便 epilogue 正常返回。
- 为什么必须「函数自己返回」而不是直接跳栈：覆盖点在返回地址处，`leave; ret` 先按未破坏的 `rbp` 恢复栈帧再 `ret` 取值，控制流才会走到 ROP 链；若 canary 被覆盖则先触发 `__stack_chk_fail`。

## 触发条件

- glibc 堆题具备：可泄露 libc 地址（unsorted/largebin、单元素 tcache fd 等）、可泄露堆地址（用于 safe-linking 编码与布局计算）、可任意地址写（UAF + tcache 毒化，或可控长度的堆溢出改 `fd`）。
- 存在 `show`/`printf` 类输出接口能越界读到 `environ` 的值；或存在其它读原语可读取 libc 数据段。
- 目标二进制与服务端拉起方式固定（决定 environ→rsp 偏移），并有与目标一致的 libc 便于取 `environ` 与 gadget 偏移。
- 开启 canary 时，写入点必须能精确跳过 canary 与保存的 `rbp`（写 `rsp+0x10` 起），或干脆不触碰其所在位置。
- 若启用 seccomp 只允许 read/write/open/mprotect，ROP 需用 syscall gadget 组 ORW；否则可直接 ret2system。

## 利用步骤

1. 泄露 libc：释放大块进 unsorted/largebin，用 `show` 读 `fd` 擦出的 `main_arena+96` 等指针，减去目标 libc 偏移得基址。
2. 计算 `environ = libc_base + libc.sym['environ']`。
3. 泄露栈：毒化 tcache `fd` 到 `environ - N`（N 取 0x400 量级），`malloc` 两次让第二次落到该地址，先把数据区填满非 0，再用 `show` 的 printf 越界读出 `environ` 中的 8 字节栈指针。
4. gdb 在目标函数 `leave; ret` 处读 `rsp`，算出 `rsp - environ_value` 的固定偏移（例题 0x138，EzHeap 0x188），反推 `stack_addr` 与返回地址位置。
5. 再次毒化 tcache `fd` 到 `stack_addr + 0x10`（跳过 canary 与索引槽，2.32+ 需 0x10 对齐并用 chunk>>12 异或）。
6. `malloc` 消费一次链头，再 `malloc` 让数据区直接落在返回地址处，写入 ROP/ORW 链。
7. 让该函数正常返回，`leave; ret` 进入链；ORW 场景用 `open/read/write` 依次读 flag。

## PoC

最简流程（glibc 2.31 教学例题，无 safe-linking；偏移需按目标重标定）：

```python
# 1) libc：largebin/unsorted 泄露
add(0, 0x420); add(1, 0x10); dele(0); add(2, 0x430)
show(0); libc_base = l64() - 0x1ecfd0

# 2) 毒化到 environ-0x400，填满后越界读 environ 的值
environ = libc_base + libc.sym['environ']
edit(2, 0x10, p64(environ))      # 改 tcache fd
add(1, 0x60); add(2, 0x60)
show(2); stack_addr = l64() - 0x138     # 0x138 = gdb 标定的 rsp 偏移

# 3) 二次毒化到返回地址处写入 ROP
attack = p64(ret) + p64(rdi) + p64(binsh) + p64(system)
edit(1, 0x10, p64(stack_addr))
add(0, 0x80); add(1, 0x80)
edit(1, 0x100, b'a'*0x18 + attack)
```

2.35 版差异（safe-linking + 前置 chunk）：`fake_fd = (chunk>>12) ^ target`，chunk 起点取 `environ-0x400` 以免 memset 清零 environ，写入点取 `stack_addr+0x10` 以跳过 canary 与索引槽。

## 变体与关联

- 变体：无 `show` 时可用 `printf` 不遇 0 不停的特性做越界读；有 `write` 且长度可控时更直接。
- 变体：seccomp 只放行 ORW 时，用 `pop rax/rdi/rsi/rdx` + `syscall` 组链，不要用 libc wrapper（wrapper 会额外用栈破坏已覆盖的栈帧）。
- 关联：[[binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw]]（CISCN2024-EzHeap 同一手法的完整 2.35 落地，偏移 0x410/0x188 与 safe-linking 细节）。
- 关联：[[binary-pwn-heap-glibc235-tcache-counts-key-clear-environ-rop]]（用 tcache key/计数清零绕过检测后再打 environ）。
- 关联：[[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]（safe-linking fd 做栈地址泄露的替代读法）。

## 检测与防御

- 防御（题目侧即缓解项）：开启 canary + PIE，避免把 libc 数据段指针通过 `puts`/`printf` 直接暴露；避免 `show` 输出未截断的堆内容。
- 防御：`edit` 严格按 chunk 实际 size 限制长度，`add` 后不要用 `memset` 掩盖真实边界，避免形成「可读越界 + 可写越界」组合。
- 检测（真实服务侧）：进程出现 `environ` 附近地址被 `malloc` 返回属异常行为，可用分配器加固（如 `glibc.malloc.tcache_count=0`）降低 tcache 毒化利用面。
- 检测：崩溃样本中回到栈的 `ret` 目标落在栈页、栈帧被 ROP 链覆盖（`__stack_chk_fail` 未触发但返回地址非代码段），结合 core dump 的 `rsp`/返回地址可判定为栈劫持。
