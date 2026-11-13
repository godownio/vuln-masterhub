---
id: binary-pwn-format-string-teegris-stst-driver-arbitrary-rw-custom-printf-rce
title: TEEgris STST 可信驱动任意读写到 RCE：ioctl 逐字节改栈上指针链 + %pU/%hn 任意读写 + 注册自定义 printf 格式规范劫持函数指针
type: scenario
domain: binary
path: binary/pwn/format-string
technique: teegris-stst-ioctl-stack-pointer-write-printf-custom-format-rce
aliases:
- STST 驱动漏洞
- TEE 驱动任意读写
- 自定义 printf 格式规范
- custom_formats_tab
- ldm.w ip gadget
- '%pU 任意读'
- TEEgris 提权
tags:
- pwn
- format-string
- tee
- teegris
- trustzone
- arm
- driver
- ioctl
- rop
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: Android P - Android R（STST 随该区间固件发布，Android S 及以后已修复）
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:14+08:00'
  notes: 已对照原文与图05/06/07核对：I=&J/J=&K/K三词链、逐字节覆盖J低字节递增提升K、%pU/%hn任意读写、.got无PIE定址泄libteesl/libtzsl基址、register_printf_format与custom_formats_tab、printf分发调用自定义handler、r12→.got vasprintf_ptr(0x1F860)、[libteesl.so:thumb]0x48f9a ldm.w ip gadget、recvmsg不可动等均一致。affected_versions=Android P - Android R与原文“随Android P到Android R发布、Android S及之后不受影响”一致，已用set-versions按原文再确认。dedup与KEYMST卡为链式两阶段非同一漏洞。未实测（无真机/模拟器运行）。
---

## 一句话结论

TEEgris 的特权可信驱动 STST 注册了 ioctl 回调，其栈上存在三个相互指向的词（`I=&J`、`J=&K`、`K`），且驱动进程在多次 ioctl 之间不退出/不复位这些值；攻击者可以反复调用 ioctl，每次只覆盖 `J` 的最低字节并递增，逐字节把“栈上的指针 `K`”改成任意地址 A——之后用 `printf` 的 `%pU` 读任意地址、`%hn` 写任意地址，泄露 .got 得到库基址；由于 `libtzsl.so` 实现了可注册的“自定义 printf 格式规范”（`custom_formats_tab`），注册一个格式符指向受控函数，再用 `ldm.w ip, {...sp, pc}` gadget（自定义处理器调用时 r12 指向 .got 中的 vasprintf 指针）做栈转储跳 ROP，最终在安全世界任意代码执行。

## 原理

- **ioctl 栈上指针链**：STST 的 `TA_CreateEntryPoint` 用 `TEES_RegisterDriver(&drv)` 注册 `open_f/ioctl_f`；两个 ioctl 命令最终调用 `log_msg`。多次调用之间进程存活，栈上深处的 `I = &J`、`J = &K`、`K` 三词关系保持不变（见原文示意图）。攻击者把目标地址 A 逐字节写入：每次 ioctl 覆盖 `J` 的低字节为递增值，使 `K` 逐步变成 A——不需要一次写全，靠重复调用累积。
- **任意读写**：一旦栈上可控任意地址，`printf` 的 `%pU`（指针解引用）提供任意读，`%n`/`%hn` 提供任意写；驱动无 PIE，`.got` 固定，读 `.got` 两个字即可推算 `libteesl.so` 与 `libtzsl.so` 的随机化基址。
- **自定义 printf 格式规范**：`libtzsl.so` 按 glibc 机制实现了格式注册函数 `register_printf_format(char spec, int handler)`，把 `(spec, handler)` 写进全局 `custom_formats_tab[8*i]`（10 个槽）。printf 内部遍历该表，命中当前格式符时执行 `(*handler)(&current_pos)`——攻击者控制的函数指针被直接调用。
- **为什么 r12 是 .got 指针**：内部调用 `vasprintf` 时经由 `.plt` veneer 分支，veneer 用 `ip`（r12）保存 `.got` 中 `vasprintf_ptr` 的地址（`libtzsl.so` 的 `.got:0x1F860`）。在调用自定义 handler 时 r12 仍指向该 `.got` 项。
- **gadget 选择**：`[[libteesl.so]:thumb] 0x48f9a: ldm.w ip, {r0, r1, r3, r4, r5, r6, r8, sb, fp, ip, sp, pc}` 会从 r12 指向的地址（`.got` 表项）批量加载寄存器并设置 sp/pc，等于把 `.got` 当栈转储并跳入 ROP。`.got` 上不能动 `recvmsg`（驱动还在用它收 ioctl），但 `vasprintf` 前后的布局允许控制 sp 与 pc 而不立刻崩溃。
- **版本**：STST 随 Android P 到 Android R 的固件发布，Android S 及之后修复。

## 触发条件

- 目标为搭载 TEEgris 的三星 Exynos 设备（Android P–R），STST 驱动存在且可被低权限 TA 触达。
- 攻击者已在安全世界取得一个能调用 ioctl 的立足点（如利用 KEYMST 栈溢出控制一个 TA，再让它与 STST 通信）。
- 驱动无 PIE、`.got` 固定，且 `libtzsl.so` 的自定义 printf 格式注册机制可用。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 在模拟器/设备中确认 STST 的 ioctl 命令，找到调用 `log_msg` 的两个入口，验证多次调用间栈上 `I/J/K` 链保持稳定。
2. 通过反复 ioctl 逐字节改写 `J` 的低字节，把 `K` 提升为任意地址 A；先用 A 指向已知可读地址验证。
3. 用 `%pU` 读任意地址、`%hn` 写任意地址（先读写自检，如读 .got）；泄露 `libteesl.so`/`libtzsl.so` 基址。
4. 在可写内存布置 ROP 链；把 `custom_formats_tab` 的某个槽注册为指向 `ldm.w ip` gadget 的 handler（或经任意写直接改表项）。
5. 触发 printf 打印该自定义格式符：r12 指向 `.got` 中 `vasprintf_ptr`，gadget 从该处加载寄存器并设 sp/pc，跳入 ROP 链。
6. 在 ROP 链中完成安全世界操作（调用系统调用/加载库 gadget），验证代码执行；注意不要改 `recvmsg` 等正在使用的 GOT 项。

## PoC

```text
# 栈上指针链（多次 ioctl 之间稳定）
I = &J
J = &K
K = 目标地址 A

# 逐字节提升：
ioctl(...)  # 覆盖 J 的最低字节 J0 = v1
ioctl(...)  # J0 = v2 （递增）
...         # K 逐步变为 A
```

```c
// 自定义 printf 格式规范注册（libtzsl.so 反编译）
int register_printf_format(char spec, int handler) {
  for (int i = 0; i != 10; ++i) {
    char *slot = &custom_formats_tab[8 * i];
    if (!*((_DWORD *)slot + 1)) {       // 空槽
      custom_formats_tab[8 * i] = spec; // 格式符
      *((_DWORD *)slot + 1) = handler;  // 函数指针
      return 0;
    }
  }
  return 1;
}

// printf 分发：命中格式符时调用自定义 handler
result = (*(int (__fastcall **)(unsigned int *))&custom_formats_tab[8 * v44 + 4])(&current_pos);
```

```text
# .got 布局（libtzsl.so，调用 handler 时 r12 -> vasprintf_ptr）
.got:0001F860 vasprintf_ptr       DCD vasprintf    ; r12 指向此处
.got:0001F864 recvmsg_ptr         DCD recvmsg      ; 不能改（ioctl 仍在用）
...
# gadget: [libteesl.so:thumb] 0x48f9a
# ldm.w ip, {r0, r1, r3, r4, r5, r6, r8, sb, fp, ip, sp, pc}
```

## 变体与关联

- 变体：没有自定义 printf 格式机制时，任意写可直接改 GOT/函数指针再触发；有 PIE 时先泄露再写。
- 变体：ioctl 栈指针链的逐字节写也可换成其他“跨调用保持状态”的原语（全局缓冲、会话结构）。
- 变体：`%pU` 是 TEE 实现特有的指针格式符；通用 glibc 场景用 `%s`/`%n` 组合。
- 关联：[[binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop]]（链式利用的前半段，先控制一个 TA 才能触达 STST）、[[code-analysis-reverse-firmware-samsung-teegris-ta-extraction]]（提取 STST/库）、[[binary-pwn-rop-thumb2-ldm-gadget-tool-blindspot]]（ldm.w gadget 的工具盲区）。

## 检测与防御

- 检测：TA/驱动侧监控高频 ioctl 与异常地址写入；TA 崩溃日志；设备完整性（root/内核失陷）检测；固件版本低于 Android S 的 TEEgris 设备重点排查。
- 防御：驱动编译开启 PIE/RELRO/canary；ioctl 参数做完整校验，不把用户可控指针/长度直接用于栈写入；禁用不必要的自定义 printf 格式注册或限制 handler 只能指向内部合法函数；TA 间调用做权限校验（TEES_ExecuteCustomHandler 的权限检查应覆盖到所有驱动）；及时更新固件。
- 说明：本文是 TEEgris STST 驱动从任意读写到安全世界 RCE 的场景，severity high、confidence high（三星确认影响 Android P–R）；仅用于授权测试与自有设备研究。
