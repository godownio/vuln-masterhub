---
id: mobile-android-kpm-syscall-function-pointer-hook-transit
title: APatch/KPM SyscallHook：sys_call_table 函数指针替换 + transit 链 before/after 回调
type: scenario
domain: mobile
path: mobile/android
technique: kpm-syscall-function-pointer-hook-transit
aliases:
- KPM SyscallHook
- sys_call_table hook
- 函数指针 hook
- fp_hook_wrap
- transit 链
- APatch syscall hook
- openat hook
tags:
- android
- apatch
- kpm
- kernel
- syscall
- function-pointer
- hook
- transit
- root
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:26:40+08:00'
  notes: 已对照原文与截图核对：fp_hook_syscalln(__NR_openat,4,...)、fp_hook_wrap 建链/替换函数指针、fp_hook 改 PTE 备份并写 transit、_fp_transit4 的 adr+反向扫 NOP+container_of、before→origin→after 顺序、0/4/8/12 参数分派、EMPTY/BUSY/READY 状态机均与原文一致。未验证点：未在设备上加载 syscall hook 模块实测 dmesg 输出。
---

## 一句话结论

在 APatch KPM 模块里做 syscall hook，可以不改 `sys_call_table` 入口指令，而是把表项函数指针替换成 `transit` 跳板：`fp_hook_wrap` 首次 hook 时分配 hook 链、把 `replace_addr` 指向 `_fp_transitN`、改页表权限后替换函数指针；`transit` 通过 `adr` + 反向扫 `ARM64_NOP` + `container_of` 找到链，按 before→原函数→after 顺序执行回调，从而支持多组 hook 链式叠加。

## 原理

- **函数指针 hook 与 inline hook 的区别**：syscall 入口在 `sys_call_table[__NR_xxx]` 里是一个函数指针；直接替换该指针即可让内核跳到 `transit`，不需要覆盖代码段指令、也不需要处理 PC 相对重定位。
- **安装流程**：`fp_hook_syscalln(__NR_openat, 4, before, after, udata)` → `fp_hook_wrap(fp_addr, argno, before, after, udata)`。
- **fp_hook_wrap**：
  1. 校验地址；
  2. `hook_get_mem_from_origin(fp_addr)` 查是否已有链；没有则 `hook_mem_zalloc` 分配 `fp_hook_chain_t`；
  3. `chain->hook.replace_addr = (uint64_t)chain->transit`；`hook_chain_prepare(chain->transit, argno)` 按参数个数选择 `_fp_transit0/4/8/12`；
  4. `flush_icache_all()`；
  5. `fp_hook(fp_addr, replace, &origin_fp)` 替换函数指针；
  6. 在链的 `states[]` 中找空槽，`BUSY→设置 udata/befores/afters→READY`，`dsb(ish)` 保证并发安全。
- **fp_hook**：取页表项 `pgtable_entry_kernel(fp_addr)`，临时 `|PTE_DBM & ~PTE_RDONLY`，`flush_tlb_kernel_page`，备份原函数指针到 `origin_fp`，写入 `replace`，`dsb(ish)`，恢复页表项并刷新 TLB。
- **transit 机制**：以 `_fp_transit4(arg0..arg3)` 为例：
  1. `asm volatile("adr %0, ." : "=r"(this_va))` 取当前 PC；
  2. `uint32_t *vptr = (uint32_t*)this_va; while (*--vptr != ARM64_NOP);` 向前找到标记 NOP；
  3. `local_container_of((uint64_t)vptr, fp_hook_chain_t, transit)` 得到链结构；
  4. 填 `hook_fargs4_t`（`skip_origin=0`、参数、chain）；
  5. 正向遍历 `befores[i]`（仅 READY 槽），回调可修改 `skip_origin`/参数/返回值；
  6. 若未跳过，调用 `origin_fp(arg0..arg3)`；
  7. 反向遍历 `afters[i]`，最后返回 `fargs.ret`。
- **参数个数分派**：0 参数 `_fp_transit0`、1–4 参数 `_fp_transit4`、5–8 `_fp_transit8`、9+ `_fp_transit12`；每个 transit 放在独立 section（如 `.fp.transit4.text`），`noinline` 防止被内联。
- **链状态机**：`EMPTY`/`BUSY`/`READY` 三态，写回调前 `BUSY` + `dsb(ish)`，写完 `READY`；transit 只执行 READY 槽，避免读到半初始化函数指针。
- **hook 类型选择**：KPM init 根据模块参数选择 `function_pointer_hook`（函数指针链）或 `inline_hook`（inline 链）；syscall hook 用前者。

## 触发条件

- Android 设备已用 APatch/KernelPatch 获得内核 root，KPM 模块可加载。
- 目标 syscall 在 `sys_call_table` 中可定位（`kallsyms_lookup_name` 或架构相关表地址），且表项所在页可写（通过页表临时改权限）。
- 有对应内核版本的 KPM 工程与交叉编译工具链；模块参数/控制接口可传 hook 类型。
- 仅用于授权安全研究/逆向分析；错误 hook 可能导致系统崩溃。

## 利用步骤

1. 部署 APatch，编译 KPM 模板模块，确认 `su` 与模块加载正常。
2. 实现 `fp_hook_chain_t`、`fp_hook_wrap`、`fp_hook`、`_fp_transit0/4/8/12`；transit 用 `adr` + NOP 反向扫描 + `container_of` 定位链。
3. 在 `syscall_hook_demo_init` 中解析模块参数，选择 `function_pointer_hook`；用 `fp_hook_syscalln(__NR_openat, 4, before, after, udata)` 安装多组回调。
4. `make` 生成 `.kpm`，push 到设备，APatch Manager 加载；`dmesg | grep syscall`/`function pointer hook` 确认。
5. 触发 `openat`，观察 before/after 日志、`skip_origin` 效果与返回值；用 `open_counts` 等 udata 统计。
6. 卸载时按相反顺序移除链项/恢复原函数指针，刷新 TLB/icache。

## PoC

```c
// 安装：首次 hook 建链并替换函数指针，后续 hook 追加链项
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno,
                        void *before, void *after, void *udata)
{
    if (is_bad_address((void *)fp_addr)) return -HOOK_BAD_ADDRESS;
    fp_hook_chain_t *chain = hook_get_mem_from_origin(fp_addr);
    if (!chain) {
        chain = (fp_hook_chain_t *)hook_mem_zalloc(fp_addr, FUNCTION_POINTER_CHAIN);
        if (!chain) return -HOOK_NO_MEM;
        chain->hook.fp_addr = fp_addr;
        chain->hook.replace_addr = (uint64_t)chain->transit;
        hook_chain_prepare(chain->transit, argno);
        flush_icache_all();
        fp_hook(chain->hook.fp_addr, (void *)chain->hook.replace_addr,
                (void **)&chain->hook.origin_fp);
    }
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] == CHAIN_ITEM_STATE_EMPTY) {
            chain->states[i] = CHAIN_ITEM_STATE_BUSY;
            dsb(ish);
            chain->udata[i] = udata;
            chain->befores[i] = before;
            chain->afters[i] = after;
            if (i + 1 > chain->chain_items_max) chain->chain_items_max = i + 1;
            dsb(ish);
            chain->states[i] = CHAIN_ITEM_STATE_READY;
            return HOOK_NO_ERR;
        }
    }
    return -HOOK_CHAIN_FULL;
}

// 替换函数指针：改 PTE -> 备份原指针 -> 写 transit -> 恢复 PTE
void fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    uint64_t *entry = pgtable_entry_kernel(fp_addr);
    uint64_t ori_prot = *entry;
    *entry = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(fp_addr);
    *(uintptr_t *)backup = *(uintptr_t *)fp_addr;
    *(uintptr_t *)fp_addr = (uintptr_t)replace;
    dsb(ish);
    *entry = ori_prot;
    flush_tlb_kernel_page(fp_addr);
}

// transit4：定位链 -> before -> 原函数 -> after
uint64_t __attribute__((section(".fp.transit4.text"))) __attribute__((__noinline__))
_fp_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {}
    fp_hook_chain_t *chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);

    hook_fargs4_t fargs = { .skip_origin = 0, .arg0 = arg0, .arg1 = arg1,
                            .arg2 = arg2, .arg3 = arg3, .chain = chain };
    for (int i = 0; i < chain->chain_items_max; i++)
        if (chain->states[i] == CHAIN_ITEM_STATE_READY && chain->befores[i])
            ((hook_chain4_callback)chain->befores[i])(&fargs, chain->udata[i]);
    if (!fargs.skip_origin)
        fargs.ret = ((transit4_func_t)chain->hook.origin_fp)(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    for (int i = chain->chain_items_max - 1; i >= 0; i--)
        if (chain->states[i] == CHAIN_ITEM_STATE_READY && chain->afters[i])
            ((hook_chain4_callback)chain->afters[i])(&fargs, chain->udata[i]);
    return fargs.ret;
}
```

```bash
adb push syscall_hook.kpm /storage/emulated/0/Download
# APatch Manager -> 模块 -> 加载，参数 function_pointer_hook
adb shell su -c 'dmesg | grep syscall'
adb shell su -c 'dmesg | grep "function pointer hook"'
```

## 变体与关联

- **hook 点变体**：`sys_call_table` 函数指针、模块导出函数指针、VFS/file_operations 函数表、网络协议 ops 表；共同点是替换指针而非改指令。
- **参数变体**：0/4/8/12 参数 transit；更多参数需要扩展 fargs/transit。
- **链式变体**：多组 before/after 叠加，`skip_origin` 跳过原函数；after 反向执行便于恢复/统计。
- **替代方案**：ftrace/kprobes/eBPF（内核原生）、inline hook（改指令）、LD_PRELOAD/PLT hook（用户态）。
- **关联卡片**：[[mobile-android-kpm-inline-hook-arm64-trampoline-relocation]]（KPM inline hook）、[[mobile-android-zygote-ptrace-dlopen-injection]]（zygote 注入）、[[pentest-c2-indirect-syscall-ntdll-hook-bypass]]（用户态 syscall hook 绕过对比）。
- **边界**：`sys_call_table` 地址不可得、表项页不可写、KPM 与内核版本不匹配、transit 的 NOP 标记/结构布局不匹配、未处理并发/卸载时可能崩溃。

## 检测与防御

- **检测特征**：`sys_call_table` 表项指向非内核 text 的 transit section、`fp_hook`/`pgtable_entry_kernel`/`flush_icache_all` 调用、KPM 模块加载、`dmesg` 中 syscall/function pointer hook 日志。
- **防御**：内核只读页表与 CR0/PTE 保护、sys_call_table 完整性校验、KPM/LKM 加载白名单、Play Integrity/硬件证明、检测 APatch/KernelPatch 特征与异常 transit section。
- **研究建议**：先在小范围 syscall（如 `openat`）验证链与 `skip_origin`；确保卸载时按相反顺序恢复，避免悬空函数指针。
