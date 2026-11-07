---
id: binary-pwn-sandbox-mailbox-toctou-jump-table-parent-rop
title: 沙箱共享 mailbox TOCTOU：command 二次读取跳转表越界 → 无 seccomp 父进程 ROP
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: sandbox-shared-mailbox-toctou-jump-table
aliases:
- libsandbox mailbox race
- handle_ipc_command TOCTOU
- 共享内存 command 竞态
- 跳转表越界
- 父进程无 seccomp
- /proc/self/mem 写 shellcode
- Not So Boring
tags:
- pwn
- sandbox-escape
- toctou
- race
- shared-memory
- jump-table
- seccomp
- ld-preload
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:52:59+08:00'
  notes: 已对照原文 Not So Boring 核对：libsandbox fork child(seccomp)/parent(无 seccomp)、共享 mailbox handle_ipc_command 两次读 command 的 TOCTOU、jump_table+command*4 落 msg+0x100、parent gadget 0x101cbd 使 rsi=r12=parent 栈 pollfd、read(0,r12,0x200)、父栈 payload 0x68 canary+0x28 填充+0x98 ROP、execve(/getflag,argv,NULL) 及 system 因 LD_PRELOAD hook 失败的差异均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

沙箱库用共享内存 mailbox 在 seccomp child 与 supervisor parent 之间传命令；`handle_ipc_command()` 先从共享内存读 `command` 做 `<=7` 范围检查，随后又重新从共享内存读一次 `command` 去查跳转表，child 在两次读之间把 command 从合法值改成大值，就能让 parent 的跳转表索引越界到共享内存中的攻击者可控字，劫持到 libc gadget；由于 parent 没有 seccomp，最终在 parent 栈上 ROP 执行 `/getflag`。

## 原理

- `libsandbox.so` 在 constructor 中建立 IPC、pipe、fork：
  - child 设置 `SANDBOX_ACTIVE=1`、关闭管道读端、保存 notify/error 写端，安装 seccomp（只允许 `read/write/pwrite64/pread64/open/openat/brk/exit/exit_group`）。
  - parent 运行 `run_supervisor()`，poll seccomp error pipe 与 notify pipe；child 的 system/execve/open 等请求写入共享 mailbox，再写 notify pipe 唤醒 parent。
- mailbox 结构：
  ```c
  typedef struct {
      int is_ready;
      ipc_message_t message;
  } ipc_mailbox_t;
  ```
  `handle_ipc_command(shm+8)` 处理命令。
- 编译后的 `handle_ipc_command()`：
  ```asm
  cmp    QWORD PTR [rdi],0x7
  ja     default
  ...
  mov    rax,QWORD PTR [rdi]        ; 第二次读取共享内存
  movsxd rax,DWORD PTR [rdx+rax*4]  ; jump_table[command]
  add    rax,rdx
  jmp    rax
  ```
  第一次读用于范围检查，第二次读用于跳转表索引，中间共享内存没有锁/无副本 → TOCTOU。
- 攻击者不能直接写 jump_table 附近，但可以选择 `command = k`，使 `jump_table + k*4` 落到共享 mailbox 内部（如 `msg+0x100`）；child 在 `msg+0x100` 写入 `gadget - jump_table`，parent 第二次读取时就会跳转到 libc gadget。
- child 已有代码执行（通过 `/proc/self/mem` + `pwrite64` 把 shellcode 写进自己的 text 段，因为 seccomp 允许 open/pwrite64，不需要 mprotect），然后用 race 循环在合法 command `0` 和大值 `k` 之间切换。
- parent gadget（libc `0x101cbd`）进入时 `rbx=msg`，执行：
  ```asm
  xor edx,edx
  mov rax,[rbx+0x38]
  mov rdi,[rbx+0x18]
  lea rcx,[rbx+0x28]
  mov rsi,r12
  mov edx,[rax+rdx]
  call [rbx+0x40]
  ```
  `rsi=r12` 来自 parent supervisor 循环中的 `lea r12,[rsp+0x20]`，指向 parent 栈上的 `struct pollfd fds[2]`。因此把 `msg+0x18=0`（fd 0）、`msg+0x38=msg+0xa0`（长度 0x200）、`msg+0x40=&read`，即可执行 `read(0, r12, 0x200)`，从网络 stdin 读数据覆盖 parent 栈。
- fork 后 parent/child 共享 canary；child 已 leak canary，parent 栈 payload 在偏移 0x68 放 canary、0x98 放 ROP 首地址，调用 `execve("/getflag", argv, NULL)`。parent 没有 seccomp，且 socket fd 0/1/2 继承自 socat，flag 直接回连。
- 为什么不在 child 直接 `execve`：libsandbox 的 `execve` hook 会在 `SANDBOX_ACTIVE` 下拦截并写 CMD_EXECVE；parent 未设置该环境变量且没有 seccomp，直接 libc `execve` 可绕过。`system("/getflag")` 会因 `LD_PRELOAD=/app/libsandbox.so` 被 shell 继承而再次触发 hook，所以用 `execve` 且 `envp=NULL`。

## 触发条件

- 沙箱使用共享内存 + 通知管道在受限 child 与不受限 parent 之间通信。
- parent 处理函数对共享字段存在“检查后再次读取”的 TOCTOU，且用该字段做跳转表/函数指针索引。
- child 在 seccomp 下仍能写共享内存并通知 parent（通常允许 write/pwrite64）。
- parent 没有 seccomp/权限限制，且继承了网络 fd 或可执行目标程序。
- 攻击者已获得 child 内代码执行；能预测/泄露 libc 基址与 gadget。

## 利用步骤

1. 分析 libsandbox：确认 fork 关系、seccomp 只装在 child、共享 mailbox 布局、`handle_ipc_command()` 的跳转表与两次读取。
2. 在 child 内用允许的 syscall 写 shellcode：`open("/proc/self/mem", O_RDWR)` + `pwrite64(fd, shellcode, len, pie+0x1230)`，再跳到该地址执行。
3. shellcode 计算 `k = ((msg+0x100 - jump_table)/4) mod 2^64`，在 `msg+0x100` 写入 `gadget - jump_table` 的低 32 位。
4. 填 mailbox 参数：`msg+0x18=0`、`msg+0x38=msg+0xa0`、`*(uint32*)(msg+0xa0)=0x200`、`msg+0x40=&read`；把 `command` 先设为 0，`is_ready=1`，写 notify pipe。
5. race：等 parent 进入 `handle_ipc_command()` 后，在 `0` 与 `k` 之间反复切换 `msg->command`；命中后 parent 跳 gadget 执行 `read(0, r12, 0x200)`。
6. 通过 socket 发送 parent 栈 payload：`b"A"*0x68 + p64(canary) + b"B"*0x28 + rop`；ROP 为 `execve(msg+0x80, msg+0x90, NULL)`，路径/argv 已由 child 写入共享 mailbox。
7. parent 执行 `/getflag`，stdout 继承 socket，flag 回连；失败则重连重试（race 有概率）。

## PoC

```python
# child shellcode 关键常量
ctrl = msg + 0x100
k = ((ctrl - jump_table) // 4) & ((1 << 64) - 1)
off = (gadget - jump_table) & 0xFFFFFFFF

# mailbox 布局（parent gadget 使用）
msg+0x18 = 0                 # read 的 fd
msg+0x38 = msg + 0xA0        # 长度指针
*(uint32_t*)(msg+0xA0) = 0x200
msg+0x40 = libc + read
```

```python
# parent 栈 payload
rop = flat(
    libc + POP_RDI, msg + 0x80,
    libc + POP_RSI, msg + 0x90,
    libc + POP_RDX, 0,
    libc + LIBC.sym["execve"],
)
payload = b"A" * 0x68 + p64(canary) + b"B" * 0x28 + rop
```

完整 EXP 见原文（含 CBOR 栈泄漏、dlsym 解析 `g_shm_mailbox`/`g_ipc_notify_pipe`、race shellcode 汇编、重试逻辑）。PoC 未在本机执行；race 命中依赖调度，需多次重试。

## 变体与关联

- 变体：共享内存中任何“检查后用”的字段（命令号、长度、指针、标志）都可能被 child 竞态改写；不限于跳转表。
- 变体：parent 若也装了 seccomp，可尝试在 child 内直接利用被允许的 syscall 组合（open/pwrite）写 text 或数据；本例 parent 无 seccomp 是提权关键。
- 变体：没有 `/proc/self/mem` 时可用 `pwrite64` 到可写映射、`openat` 写临时文件后 mmap 等；或利用 JIT/可执行堆。
- 关联卡片：[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（constructor/seccomp 时序）、[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（沙箱监控绕过）、[[binary-pwn-sandbox-escape-dsh-exec-agent-ctx-subprocess-rce]]（宿主逃逸）。
- 注意：本例为 Hackropole FCSC 2026 Not So Boring 题；真实沙箱需具体分析 IPC 实现与 seccomp 范围。

## 检测与防御

- 防御：parent 从共享内存读取消息时先复制到本地栈变量，之后只使用本地副本；不要对共享字段做二次读取/二次索引。
- 防御：共享内存使用 seqlock/版本号/双缓冲，写入方与读取方约定原子快照；对 command 做白名单校验后直接 switch 本地值。
- 防御：parent 也安装 seccomp/降权，不继承不必要的网络 fd；对 child 的 IPC 请求做参数与频率校验；限制 `/proc/self/mem` 访问。
- 防御：不要依赖 `LD_PRELOAD` 作为唯一 sandbox；使用内核 seccomp/user namespace/容器隔离；对 execve 目标做签名校验。
- 检测：child 高频切换共享 command、异常 notify pipe 写入、parent 跳转表索引越界（KASAN/CFI）；`/proc/self/mem` 写入 text 段；parent 异常 execve。
- 响应：隔离进程、禁用沙箱、检查 parent 是否被执行任意命令、修复 IPC 竞态。
