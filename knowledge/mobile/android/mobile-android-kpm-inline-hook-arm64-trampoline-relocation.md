---
id: mobile-android-kpm-inline-hook-arm64-trampoline-relocation
title: APatch/KPM 内核 InlineHook：ARM64 trampoline、PC 相对重定位与页表改权限
type: scenario
domain: mobile
path: mobile/android
technique: kpm-inline-hook-arm64-trampoline-relocation
aliases:
- KPM InlineHook
- APatch KPM
- ARM64 inline hook
- trampoline 重定位
- 内核 inline hook
- KernelPatch
tags:
- android
- apatch
- kpm
- kernel
- inline-hook
- arm64
- trampoline
- relocation
- root
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:26:35+08:00'
  notes: 已对照原文与14张截图核对：APatch/KPM 部署、KPM 编译加载、hook_prepare 备份12条指令/branch_from_to/relocate_inst/返回跳转、B 指令重定位展开、PTE 去只读+TLB/icache 刷新、transit 链与状态机、dmesg 中 arg0=20/arg1=10/ret=30 均一致。未验证点：未在设备上编译加载 KPM；部分指令类型重定位细节原文未逐条展开。
---

## 一句话结论

在 APatch 的 KPM 内核模块里实现 ARM64 inline hook：先备份原函数开头 12 条指令（48 字节），生成跳向替换函数的 trampoline，逐条重定位 PC 相对指令（B/BL/ADRP/LDR literal 等），再通过页表项临时去掉只读、写入跳转指令、刷新 TLB 与 icache；链式 hook 用 transit 函数按 before→原函数→after 顺序分发回调。

## 原理

- **KPM 模块形态**：KPM 是 APatch/KernelPatch 提供的内核模块，用 ARM GNU 交叉工具链编译成 `.kpm`，由 APatch Manager 加载；模块通过 `KPM_INIT`/`KPM_CTL0`/`KPM_EXIT` 暴露 init/control/exit。
- **安装流程**：`hook_wrap2(func, before, after, udata)` → `hook_wrap` → `hook_prepare` → `hook_install`。
- **hook_prepare**：
  1. 校验原函数/替换函数/trampoline 地址（`is_bad_address`）；
  2. 备份 `TRAMPOLINE_NUM=12` 条 32 位指令（48 字节）；
  3. `branch_from_to(tramp_insts, origin_addr, replace_addr)` 生成从原函数跳到替换函数的 trampoline；
  4. 对备份的每条指令调用 `relocate_inst(hook, inst_addr, inst)` 做重定位——ARM64 指令大量使用 PC 相对寻址，直接搬走会指向错误地址；
  5. 生成从重定位区跳回 `origin_addr + tramp_insts_len*4` 的返回跳转。
- **B 指令重定位示例**：原 `B <offset>` 不能直接复制；重定位后展开为“条件 B + B #24 + LDR X17,#8 + B #12 + 目标地址低/高 32 位 + BLR/BR X17 + NOP”，用 X17 装载绝对地址再跳转。`relo_in_tramp` 用指令类型表 `relo_len` 计算 trampoline 内某地址在重定位副本中的新地址。
- **指令解码**：用位宏 `bits32(n, high, low)`、`bit(n, st)`、`sign64_extend(n, len)` 提取 B 的 26 位立即数，左移 2 位并符号扩展为 64 位偏移。
- **hook_install（写内核代码段）**：
  1. `pgtable_entry_kernel(va)` 取页表项，保存原值；
  2. `*entry = (ori_prot | PTE_DBM) & ~PTE_RDONLY` 去掉只读、设置脏位；
  3. `flush_tlb_kernel_page(va)`；
  4. 把 trampoline 指令逐条写到原函数首地址；
  5. `flush_icache_all()` 刷新指令缓存（关键，否则 CPU 可能执行旧指令）；
  6. 恢复页表项并再次刷新 TLB。
- **链式 hook 的 transit**：替换地址指向 `transit` 函数；`transit` 用 `adr` 取当前 PC，向前扫描 `ARM64_NOP` 标记，`local_container_of` 找到 `hook_chain_t`；按 `states[i]==READY` 正向执行 before 回调，可选执行原函数，再反向执行 after 回调。槽位用 `EMPTY/BUSY/READY` 状态机 + `dsb(ish)` 保证并发安全。
- **为什么需要重定位/icache**：内核函数可能被其他模块/内联调用，覆盖首指令后必须保证跳转、返回、PC 相对引用都正确；不刷新 icache 会导致部分核心执行旧指令，表现为随机崩溃。

## 触发条件

- Android 设备已解锁 Bootloader，使用 APatch（或 KernelPatch）获得内核级 root，KPM 模块加载可用。
- 目标内核函数地址可获取（kallsyms/符号表/模块导出），且代码段可写（通过页表临时改权限）。
- 有对应架构的交叉编译工具链与内核头文件；KPM 模块与内核版本匹配。
- 仅用于授权安全研究/逆向分析；内核 hook 可能导致设备崩溃/变砖。

## 利用步骤

1. 部署 APatch：用原厂 boot.img 在 APatch Manager 中修补，`fastboot flash boot` 刷入，验证 `su`。
2. 准备 KPM 工程（KernelPatch `kpms/demo-hello` 为模板），配置 `TARGET_COMPILE`、`KP_DIR`、include 路径，`make` 生成 `.kpm`。
3. 实现 hook 框架：备份 12 条指令、生成 trampoline、逐条 `relocate_inst`、生成返回跳转；实现 `hook_install` 的页表/ TLB/ icache 操作。
4. 对目标函数调用 `hook_wrap2(func, before, after, udata)`；链式 hook 用 transit + 状态机管理多组回调。
5. `adb push` 模块到设备，在 APatch Manager 加载；`dmesg | grep -i kp`/`grep inline` 确认加载与 hook 成功。
6. 触发目标函数，观察 before/after 日志与返回值；若崩溃，检查重定位长度表、icache/TLB 刷新、页表恢复顺序。

## PoC

```c
// hook_prepare 核心：备份 + trampoline + 重定位 + 返回跳转
for (int i = 0; i < TRAMPOLINE_NUM; i++)
    hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);

hook->tramp_insts_len = branch_from_to(hook->tramp_insts, hook->origin_addr, hook->replace_addr);

for (int i = 0; i < hook->tramp_insts_len; i++) {
    uint64_t inst_addr = hook->origin_addr + i * 4;
    uint32_t inst = hook->origin_insts[i];
    relocate_inst(hook, inst_addr, inst);
}

uint64_t back_src = hook->relo_addr + hook->relo_insts_len * 4;
uint64_t back_dst = hook->origin_addr + hook->tramp_insts_len * 4;
hook->relo_insts_len += branch_from_to(buf, back_src, back_dst);

// hook_install 核心：改 PTE -> 写指令 -> flush icache -> 恢复 PTE
uint64_t *entry = pgtable_entry_kernel(va);
uint64_t ori_prot = *entry;
*entry = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
flush_tlb_kernel_page(va);
for (int32_t i = 0; i < hook->tramp_insts_len; i++)
    *((uint32_t *)hook->origin_addr + i) = hook->tramp_insts[i];
flush_icache_all();
*entry = ori_prot;
flush_tlb_kernel_page(va);

// B 指令立即数解码
#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
uint64_t imm26 = bits32(inst, 25, 0);
uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
```

加载与验证：

```bash
adb push inline_hook.kpm /storage/emulated/0/Download
# APatch Manager -> 模块 -> 从存储加载
adb shell su -c 'dmesg | grep -i inline'
adb shell su -c 'dmesg | grep -i kp'
```

## 变体与关联

- **指令变体**：B/BL、B.cond、CBZ/CBNZ、TBZ/TBNZ、ADRP/ADD、LDR literal、PRFM 等；每种 PC 相对指令都要按 `relo_len` 表重定位。
- **架构变体**：x86-64 常用 5 字节 `jmp rel32` + 长度解码；ARM32 用 4 字节 B/BLX；RISC-V 用 AUIPC/JALR。
- **hook 方式变体**：inline hook、函数指针 hook（syscall）、ftrace/kprobes、eBPF、PLT/GOT hook；内核态优先 ftrace/kprobes，KPM 适合无 LKM 环境。
- **关联卡片**：[[mobile-android-kpm-syscall-function-pointer-hook-transit]]（KPM syscall 函数指针 hook）、[[mobile-android-zygote-ptrace-dlopen-injection]]（zygote 注入）、[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（x86 inline hook 对比）。
- **边界**：内核代码段只读且无法改 PTE、KPM 与内核版本不匹配、目标函数被内联/被其他 hook 覆盖、未刷新 icache 时失败或崩溃。

## 检测与防御

- **检测特征**：内核函数首字节出现跳转/trampoline、PTE 的 RDONLY 位被临时清除、`flush_icache_all`/`pgtable_entry_kernel` 调用、APatch/KPM 模块加载记录、`dmesg` 中 kp/inline 日志。
- **防御**：内核代码完整性校验（text hash/签名）、只读页表与 CR0/PTE 保护、KPM/LKM 加载白名单、Play Integrity/硬件证明、检测 APatch/KernelPatch 特征。
- **研究建议**：在测试设备上先备份 boot.img；hook 前用 `dmesg`/断点确认目标地址与指令；每次修改后验证返回跳转与 icache。
