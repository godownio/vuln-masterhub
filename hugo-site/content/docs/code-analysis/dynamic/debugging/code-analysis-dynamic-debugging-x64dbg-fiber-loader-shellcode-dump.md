---
id: code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump
title: x64dbg 动态提取纤程 Loader 解密后的 shellcode：断点 ConvertThreadToFiber/VirtualAlloc/memcpy
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: x64dbg-fiber-loader-shellcode-dump
tags:
- reverse-engineering
- x64dbg
- dynamic-analysis
- debugging
- shellcode
- fiber
- memory-dump
- rust
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:53:33+08:00'
  notes: 已对照原文与25张图核对：x64dbg 在 ConvertThreadToFiber 下断后单步至 VirtualAlloc，RAX=0x18C9C5E0000，memcpy 后在内存窗口 dump 得到 weixin_000018C9C5E0000.bin；导出 shellcode 提交沙箱 0/28、天穹判安全，均与截图一致。未验证点：未复跑调试流程；断点/寄存器细节依赖具体样本，卡片已注明对抗与替代 API。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump/
draft: false
kb_aliases:
- 动态 dump shellcode
- x64dbg 提取内存 shellcode
- 纤程 loader 调试
- ConvertThreadToFiber 断点
- VirtualAlloc 返回地址 dump
- 内存转储 shellcode
---

## 一句话结论

面对“解密后直接在内存执行”的纤程 shellcode loader，不必逆向出完整解密算法：在 x64dbg 中对 `ConvertThreadToFiber` 下断，单步到随后的 `VirtualAlloc` 并取返回值，再在 `memcpy` 执行后转储该地址的内存，就能直接拿到解密后的 shellcode 原始字节。

## 原理

- **loader 的必经路径**：无论加密算法多复杂，最终都要把明文 shellcode 放进可执行内存。常见顺序是 `VirtualAlloc`（分配 RW）→ `memcpy`（写入明文）→ `VirtualProtect`（改为 RX）→ `CreateFiber`/`CreateThread`/`QueueUserAPC`（执行）。在这些 API 前后下断，明文必然出现在内存中。
- **纤程 loader 的锚点**：`ConvertThreadToFiber(0)` 把当前线程转成纤程，后续必然出现 `CreateFiber(0, shellcode, 0)` 和 `SwitchToFiber`。在 `ConvertThreadToFiber` 下断，可以快速越过前面的反沙箱延迟、Rust 运行时初始化和垃圾代码；单步到下一个 `VirtualAlloc` 调用时，函数返回值（RAX）就是即将写入 shellcode 的缓冲区地址。
- **memcpy 后转储**：在 `memcpy` 返回处下断，此时源缓冲区已复制到目标可执行内存；用 `dump` 命令或内存窗口按目标地址和长度导出，即可得到完整 shellcode。
- **对抗点**：若 loader 使用 `VirtualAllocEx`/`NtAllocateVirtualMemory`/分段解密/边执行边解密，断点位置需相应调整；若样本有反调试（`IsDebuggerPresent`、PEB 检查、`NtQueryInformationProcess`），需先绕过或 patch。

## 触发条件

- 样本是用户态 Windows loader，会在本机（或可控虚拟机）执行；
- 调试器能附加/启动样本，且未被反调试阻止（本案例样本只做了反沙箱延迟，未阻止 x64dbg）；
- 样本确实通过 `VirtualAlloc` + `memcpy` 准备内存（多数 shellcode loader 如此）；
- 调试环境断网或已隔离，避免 shellcode 上线造成真实外连。

## 利用步骤

1. 在隔离虚拟机中用 x64dbg 打开样本，先让程序停在入口/系统断点。
2. 在 `ConvertThreadToFiber` 下断点并运行；命中后单步（或直接对 `VirtualAlloc` 下断）越过反沙箱延迟和初始化代码。
3. 在 `VirtualAlloc` 返回处读取 RAX，记录缓冲区地址与大小（size 参数通常在 RDX/RCX，视调用约定）。
4. 在 `memcpy`（或 `RtlMoveMemory`）下断；命中并执行完复制后，转到 RAX 指向的内存，确认出现 shellcode 特征（如 `FC 48 83 E4`、`55 48 8B EC` 等）。
5. 在内存窗口右键选择“转储到文件”，或用命令 `dump <addr>, <addr>+<size>, "weixin_shellcode.bin"` 导出。
6. 对导出的 bin 做静态分析/沙箱提交；也可继续在 `VirtualProtect` 后对内存下执行断点，或用 `CreateFiber` 的入口参数直接定位。
7. 若在 `ConvertThreadToFiber` 之前就命中 `VirtualAlloc`，说明样本不是纤程 loader；改为在 `CreateThread`/`QueueUserAPC`/回调注册处下断。

## PoC

x64dbg 命令示例：

```text
bp ConvertThreadToFiber
bp VirtualAlloc
bp memcpy
run

# 命中 VirtualAlloc 返回后，假设 RAX=0x18C9C5E0000，size=0x...：
dump 0x18C9C5E0000, 0x18C9C5E0000+0x20000, "C:\analysis\shellcode.bin"

# 或者在内存窗口选中目标地址，右键 -> Dump to file
```

辅助判断：`memcpy` 命中时 RCX/RDX 分别指向目标/源（x64 调用约定），目标地址通常就是 `VirtualAlloc` 的返回值；复制完成后该地址内容应与解密缓冲区一致。

## 变体与关联

- 变体：APC/线程 loader 在 `CreateThread`/`QueueUserAPC`/`NtCreateThreadEx` 下断，dump 其入口地址；回调 loader 在 `EnumWindows`/`CreateTimerQueueTimer` 注册处下断。
- 变体：`VirtualAllocEx` + `WriteProcessMemory` 的远程注入，改为在目标进程内存中 dump；可用 Process Hacker/PE-sieve 辅助。
- 变体：边解密边执行的 loader，需要在 `VirtualProtect(PAGE_EXECUTE_*)` 后下内存执行断点，或对解密循环的写入地址下硬件断点。
- 关联：[[pentest-c2-rust-fiber-shellcode-loader-base64-aes-switchtofiber]]（本案例的 loader 本体）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（VirtualProtect 运行时解密还原）、[[pentest-c2-shellcode-loader-rx-sleep-etw-encryption]]（RW→RX 加载器）。

## 检测与防御

- **分析侧**：该方法是取证/逆向手段，不是攻击；对恶意样本应在隔离环境执行，断网或使用 INetSim 模拟网络，避免 shellcode 回连。
- **样本侧对抗**（防御方需了解）：loader 可用 `IsDebuggerPresent`、PEB `BeingDebugged`、`NtQueryInformationProcess`、硬件断点检测、分段解密/边执行边解密、`VirtualAlloc` 后立即 `VirtualProtect` 并跳转，增加 dump 难度；可用 ScyllaHide/TitanHide 等插件对抗常见反调试。
- **防御检测**：EDR 监控 `VirtualAlloc(PAGE_READWRITE)` 后 `memcpy` 再 `VirtualProtect(PAGE_EXECUTE_READ)`、随后 `CreateFiber`/`SwitchToFiber` 的序列；对非模块内存执行告警；定期做内存扫描与 PE-sieve 提取。
- **应急**：从可疑进程 dump 出的 shellcode 可进一步提取 C2、配置与加密密钥；保留内存镜像与导出文件哈希，便于溯源。
