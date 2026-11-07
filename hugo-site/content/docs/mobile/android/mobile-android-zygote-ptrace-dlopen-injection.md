---
id: mobile-android-zygote-ptrace-dlopen-injection
title: Android Zygote ptrace 注入：ARM32 shellcode dlopen SO，fork 后全应用继承
type: scenario
domain: mobile
path: mobile/android
technique: zygote-ptrace-dlopen-injection
tags:
- android
- mobile
- zygote
- ptrace
- process-injection
- shellcode
- arm32
- dlopen
- hook
- root
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:12:37+08:00'
  notes: 已对照原文核对：Zygote fork/COW 继承原理、ptrace ATTACH/GETREGS/远程mmap/POKEDATA写shellcode/清CPSR Thumb位/CONT执行/munmap/恢复寄存器/DETACH、ARM32 PIC shellcode 的 dlopen→dlsym→入口函数→dlclose、CPSR 与 R0-R12/LR/PC 恢复、zygote32/zygote64 架构匹配、PIE 要求、SELinux 临时关闭与恢复、测试命令与 maps/logcat 输出均与原文一致；原文测试显示注入 zygote PID 1180 后 /proc/1180/maps 出现 testSo.so，属已打通。未验证点：未在本机复跑；原文 4 处图片为空引用无图可核；原文 5.1.1 称 Android 5.0+ 非 PIE loader 会被拒，但 5.2.1 又标注测试 loader 为非 PIE，原文自身表述不一致，卡片按 5.1.1 描述。
url: /docs/mobile/android/mobile-android-zygote-ptrace-dlopen-injection/
draft: false
kb_aliases:
- Zygote 注入
- zygote fork 继承
- ptrace 注入 Zygote
- ARM32 shellcode dlopen
- PIE 注入器
- zygote32/zygote64
- 全局 SO 注入
---

## 一句话结论

root 下用 ptrace attach 32 位 zygote，远程 `mmap` 分配 RWX，`PTRACE_POKEDATA` 写入 ARM32 shellcode，shellcode `dlopen` 目标 SO 并调用入口函数；SO 驻留后，zygote fork 出的所有 32 位应用进程都继承该模块，实现一次注入全局生效。

## 原理

- **Zygote 是应用进程祖先**：Android 所有应用进程由 zygote `fork()` 派生；fork 后子进程通过 COW 获得与父进程相同的内存映射。向 zygote 注入 SO 后，后续 fork 出的每个应用进程都会继承该 SO，无需逐个注入。
- **ptrace 注入流程**：`PTRACE_ATTACH` 暂停目标 → `PTRACE_GETREGS` 保存原始寄存器 → 用 `PTRACE_SETREGS` + `PTRACE_SYSCALL` 触发远程 `mmap(0, 0x4000, PROT_EXEC|READ|WRITE, MAP_ANONYMOUS|MAP_PRIVATE)`，从 R0 读回分配地址 → `PTRACE_POKEDATA` 把 shellcode 写到该地址 → 设置 PC 指向 shellcode、清 CPSR 的 Thumb 位 → `PTRACE_CONT` 执行 → 完成后 `munmap`、恢复原始寄存器、`PTRACE_DETACH`。
- **ARM32 shellcode**：位置无关代码，ARM 模式指令固定 4 字节，避免 Thumb 变长带来的偏移计算问题；`LDR R0, _so_path_addr` 间接取参数地址，`LDR R3, _dlopen_addr; BLX R3` 调用远程 `dlopen`，再 `dlsym` 取入口函数并 `BLX R0` 执行；`dlclose` 释放句柄，但 SO 中的 Hook 已驻留。
- **无痕恢复**：shellcode 保存原始 CPSR 与 R0–R12/LR/PC，退出时 `MSR CPSR_fsxc` 恢复状态、`LDMIA` 恢复通用寄存器、`LDR PC, [R0, #60]` 恢复 PC，使目标进程继续正常运行。
- **架构匹配**：32 位 loader 只能注入 `zygote`（32 位，PID 如 1180），不能注入 `zygote64`（64 位，PID 如 1179）；注入器与 SO 都需 armeabi-v7a。Android 5.0+ 要求可执行文件为 PIE，旧版非 PIE loader 会被拒绝执行，需 `-fPIE -pie` 重新编译。
- **SELinux/root**：注入器需要 root；SELinux 可能阻止 ptrace，注入前临时关闭/放宽，注入后恢复。

## 触发条件

- 设备已 root，注入器可 ptrace zygote（SELinux permissive/关闭或策略允许）。
- 注入器与目标 SO 架构匹配（32 位注入器 → zygote32；64 位 → zygote64）。
- 知道 SO 路径与入口函数名（如 `JNI_OnLoad` 或自定义函数）。
- Android 5.0+ 的注入器已启用 PIE。

## 利用步骤

1. `ps -A | grep -E "zygote|PID"` 找到 `zygote`/`zygote64`；`file loader testSo.so` 确认架构。
2. 用 NDK 编译 32 位 PIE loader（`APP_ABI := armeabi-v7a`、`LOCAL_ARM_MODE := arm`、`-fPIE -pie`）。
3. `adb push loader testSo.so /data/local/tmp/zygote/`，`chmod +x`。
4. 临时关闭/放宽 SELinux，root 执行 `./loader <zygote32_pid> <so_path> <entry_func> <args>`。
5. loader attach、远程 mmap、写 shellcode、`dlopen`/`dlsym`/调用入口函数、恢复寄存器、detach。
6. `cat /proc/<pid>/maps | grep testSo` 确认 SO 已映射；启动新应用，检查其子进程 maps 是否继承。
7. `adb logcat -s debug` 查看入口函数日志，确认 Hook/初始化逻辑执行。

## PoC

```asm
@ ARM32 位置无关 shellcode（节选）
_inject_code_start:
    LDR     R0, _so_path_addr
    LDR     R1, _dlopen_param2        @ RTLD_NOW
    LDR     R3, _dlopen_addr
    BLX     R3                        @ dlopen(so_path, RTLD_NOW)
    MOV     R4, R0
    CMP     R4, #0
    BEQ     _dlopen_fail
    MOV     R0, R4
    LDR     R1, _so_init_func_addr
    LDR     R3, _dlsym_addr
    BLX     R3                        @ dlsym(handle, entry_func)
    CMP     R0, #0
    BEQ     _cleanup
    LDR     R1, _so_func_arg_addr
    BLX     R0                        @ entry_func(arg)
_cleanup:
    MOV     R0, R4
    LDR     R3, _dlclose_addr
    BLX     R3
    MOV     R0, #0
    B       _exit
```

```bash
./loader 1180 /data/local/tmp/zygote/testSo.so log args
cat /proc/1180/maps | grep testSo
```

## 变体与关联

- **架构变体**：zygote64 需 arm64 shellcode 与 64 位 loader；也可注入 `system_server`、`webview_zygote` 等系统进程。
- **写入变体**：用 `/proc/<pid>/mem` 替代 `PTRACE_POKEDATA`；用 `process_vm_writev`；用 `PTRACE_POKETEXT` 写 `syscall; int3` 触发远程 syscall。
- **驻留变体**：SO 入口函数安装 inline hook/PLT hook/GOT hook；也可只注入一次到 zygote 后由子进程继承。
- **对抗变体**：Android 高版本 SELinux 限制 ptrace、`ptrace_scope`、隐藏 API、Play Integrity；可配合 Magisk/Zygisk、改名、反检测。
- **关联卡片**：[[pentest-c2-linux-ptrace-poketext-shellcode-injection]]（通用 ptrace POKETEXT 注入）、[[pentest-c2-linux-remote-mmap-syscall-injection]]（远程 mmap + /proc/mem）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（Android 逆向/脱壳）、[[mobile-android-anti-detection-root-emulator-proxy]]（root/反检测）。
- **边界**：无 root/无法关闭 SELinux 时 ptrace 被拒；架构不匹配会注入失败；Android 10+ 对 zygote ptrace 有更严格限制；Hook 冲突可能导致目标进程崩溃重启。

## 检测与防御

- **检测**：监控 `/proc/<zygote_pid>/maps` 出现非系统路径 SO；检测 zygote 被 ptrace（`TracerPid` 非 0）；监控 `PTRACE_ATTACH`/`PTRACE_POKEDATA` 行为；检查 `/data/local/tmp` 下的 loader/SO；Play Integrity/ SafetyNet 与 root 检测。
- **防御**：保持 SELinux enforcing；限制 `ptrace_scope`；禁止 root/解锁 bootloader；对 zygote 做完整性校验；应用侧检测注入/Hook 与异常 SO 映射。
- **注意**：本文是攻击技术说明，PoC 未在本库执行；实际测试需在授权环境进行。
