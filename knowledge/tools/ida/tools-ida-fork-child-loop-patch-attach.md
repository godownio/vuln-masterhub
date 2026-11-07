---
id: tools-ida-fork-child-loop-patch-attach
title: IDA-Fork 双进程调试：把子进程首指令 patch 成死循环，附加后 SetIP 恢复
type: scenario
domain: tools
path: tools/ida
technique: ida-fork-child-loop-patch-attach
aliases:
- IDA-Fork 双进程调试
- fork 子进程调试
- 子进程 patch 死循环
- 附加 fork 子进程
- SetIP 跳出死循环
- Android fork 调试
tags:
- ida
- fork
- debugging
- android
- reverse
- patch
- attach
- setip
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:34:20+08:00'
  notes: 已对照原文及图07-12核对：fork 子进程首指令 BL __android_log_print patch 为 B 自身死循环、Detach 父进程、按 PID 附加、SetIP 恢复；Android JNI 样本场景与截图一致；未复跑
---

## 一句话结论

fork 出来的子进程无法直接启动调试且往往瞬间退出；先把子进程第一条指令 patch 成跳回自身的死循环，让进程停留，再在循环处下断点、从主进程 Detach、按 PID 附加子进程，命中断点后用 SetIP 跳到正常代码并恢复原指令，就能调试子进程逻辑。

## 原理

- **fork 子进程的调试困境**：子进程由父进程 `fork()` 产生，IDA 默认调试的是启动的父进程；子进程没有独立启动入口，且执行完分支逻辑后很快 `exit()`，手动附加经常来不及。
- **patch 首指令为死循环**：把子进程入口的第一条指令改成 `B <self>`（ARM64）或 `jmp $`（x86 `EB FE`），子进程会原地循环、不会退出；这给了调试器充足的附加时间。
- **断点 + Detach 父进程**：在死循环地址下断点，先让父进程运行到 fork 之后；此时子进程已在循环中。对父进程 Detach（不要 Terminate），避免父进程被调试器控制影响子进程。
- **按 PID 附加子进程**：通过进程列表/`ps`/`adb shell ps` 找到子进程 PID，IDA `Attach to process` 附加；子进程会停在死循环断点。
- **SetIP 恢复执行**：在断点处把 IP 设置到原本要执行的代码（或恢复被 patch 的原指令后单步），再继续调试；调试结束后把 patch 的字节改回原值，避免破坏样本/目标。
- **为什么可行**：patch 只改代码字节，不改变进程创建与权限；死循环让子进程存活，附加后调试器拥有完整寄存器/内存上下文，SetIP 直接改 PC 即可跳过补丁。

## 触发条件

- 目标为 Linux/Android 等支持 `fork()` 的原生进程，且待调试逻辑在子进程分支中。
- 使用 IDA 远程调试（android_server/gdbserver/lldb）或本地 Linux 调试，能附加已存在进程。
- 能定位子进程入口第一条指令并修改内存（需要写权限；只读代码段可用 IDA patch 或 mprotect）。
- 子进程不会在 patch 前执行破坏性逻辑；首指令通常是日志/初始化等可安全跳过的指令。
- 目标未启用强反调试/完整性校验；否则 patch 可能被检测。

## 利用步骤

1. 在 `fork()` 调用处下断点，运行到断下；确认子进程分支的入口地址与第一条指令（本文为 ARM64 `BL __android_log_print` 日志调用）。
2. 把子进程第一条指令 patch 为死循环：ARM64 用 `B loc_<自身地址>`，x86 用 `jmp $`（字节 `EB FE`）；IDA 中右键 → `Patch program` → `Assemble`。
3. F9 让程序继续运行，使子进程进入死循环；随后对主/父进程执行 `Detach from process`（不要终止）。
4. 在死循环地址设置断点；通过 `ps`/`adb shell ps` 找到子进程 PID，IDA `Debugger → Attach to process` 附加子进程。
5. 子进程命中断点后，用 `SetIP`（右键 → `Set IP`/`Jump to IP`）跳到死循环之后原本要执行的指令，或先恢复原指令再单步。
6. 继续调试子进程；结束后把 patch 的字节恢复为原始指令，保存/清理调试环境。

## PoC

```text
# ARM64 示例：子进程入口
原指令:  BL __android_log_print
patch 后: B  loc_734235A0D0      ; 跳回自身，形成死循环

# x86/x64 等价写法
原指令:  call __android_log_print
patch 后: jmp $                  ; 机器码 EB FE
```

```bash
# 查找子进程 PID（Android）
adb shell ps -A | grep <process_name>
# 或进入设备 shell
ps -ef | grep <process_name>
```

```text
IDA 操作：
1. 在 fork 调用处 F2 断点，F9 断下
2. 子进程首指令 Patch program → Assemble 为 B self
3. F9 运行；Debugger → Detach from process（父进程）
4. 在死循环地址 F2；Debugger → Attach to process → 选择子进程 PID
5. 命中后右键 Set IP 到死循环的下一条正常指令
6. 恢复原始指令，继续调试
```

原文在 Android JNI 样本上以 `BL __android_log_print` → `B loc_...` 完成验证；本卡未复跑。

## 变体与关联

- **变体：patch 成 `sleep`/阻塞调用**：把首指令改为 `sleep(3600)` 或 `getchar()`，同样能让子进程停留；需要能调用 libc。
- **变体：不 patch，改用 `fork` 后 `raise(SIGSTOP)`**：若能在 fork 返回点插入 `int3`/`SIGSTOP`，子进程会暂停等待附加，无需死循环。
- **变体：多级 fork/exec**：若子进程随后 `execve`，patch 会随新映像失效；可在 exec 后的入口（如 linker）再下断点，或改用 `strace`/`gdbserver --attach`。
- **关联**：[[tools-ida-python-conditional-breakpoint-register]]（条件断点筛选）、[[tools-ida-trace-instruction-basicblock-function-export]]（Trace 观察子进程执行流）。
- **边界**：代码段只读时 patch 可能失败；子进程 PID 复用/快速退出；父进程 Detach 后可能继续 fork 新子进程，需按 PID/进程名区分；patch 后忘记恢复会改变样本行为。

## 检测与防御

- 这是逆向调试技巧，不是攻击链；用于分析 Android/Linux fork 型恶意样本、JNI 逻辑与子进程协议。
- 注意事项：patch 前记录原始字节与地址；附加前确认 PID 对应正确进程；Detach 父进程后不要误杀；调试结束恢复代码段并校验文件哈希。
- 对抗视角：样本若检测调试器、校验代码段或使用双进程互相 ptrace，patch/attach 可能失败；可改用内核态 trace、Frida spawn/gating 或模拟执行。
