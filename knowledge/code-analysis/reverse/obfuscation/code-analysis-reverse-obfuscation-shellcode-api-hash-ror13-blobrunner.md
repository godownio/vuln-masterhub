---
id: code-analysis-reverse-obfuscation-shellcode-api-hash-ror13-blobrunner
title: 裸 Shellcode 的 API 哈希解析：Ghidra 定位 PUSH hash + CALL reg，ROR13 类散列还原并 blobrunner 动态验证
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: shellcode-api-hash-ror13-static-dynamic-recovery
aliases:
- ShellCode hash 获取 API
- API 哈希解析
- ROR13 API hash
- PUSH hash CALL RBP
- blobrunner 调试 shellcode
- Cobalt Strike/Meterpreter API hash
- 0xa779563a InternetOpenA
- 0x726774c LoadLibraryA
tags:
- windows
- malware-analysis
- shellcode
- api-hashing
- ror13
- ghidra
- blobrunner
- debugging
- reverse
- cobalt-strike
- meterpreter
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T08:04:52+08:00'
  notes: 已对照原文全文及图 01-23 核对：Ghidra x86 32 raw、d 反汇编/f 定义函数、FUN_0000008f 伪代码中 (*unaff_retaddr)(0x726774c,...)/(0xa779563a,...)、图06 hash 脚本 0x726774c→LoadLibraryA、图07 SpeakEasy 输出 LoadLibraryA("wininet")/InternetOpenA/InternetConnectA、图12 blobrunner Base 0x011a0000、图15/19 断点 011A0086、图19/20 EAX kernel32.LoadLibraryA 与栈 "wininet"、图21 wininet.InternetOpenA、图22 wininet.InternetConnectA(0xC69F8957)、图23 ROR EDI,0xd 散列循环，均与卡片一致。dedup 仅自匹配 duplicate，无 likely_duplicate；嵌入式 PE 字节还原、多层 shellcode 解码、分片 XOR、汇编反弹 shell 等候选均为不同链。未验证点：未在本机运行 Ghidra/blobrunner/样本，PoC 未复跑；原文未给受影响版本，未设 affected_versions 正确。
---

## 一句话结论

对没有 PE 头的 32 位 shellcode，Ghidra 以 raw x86 反汇编（`d` 反汇编、`f` 定义函数）可以看到大量 `PUSH <常量>` + `CALL RBP/EAX` 的调用点；这些常量是 API 名的散列（文章归为 Cobalt Strike/Meterpreter 常用的 ROR13 类），用哈希还原脚本/工具解出 `LoadLibraryA`（文章记作 `0x726774c`）、`InternetOpenA`（`0xa779563a`）、`InternetConnectA`（`0xC69F8957`），再用 blobrunner 把 shellcode 加载到固定地址、在 `jmp eax` 处下断点单步，观察被解析函数与栈参数（`wininet` 字符串、InternetOpenA、InternetConnectA），即可还原恶意 shellcode 的 API 调用链与 C2 行为。

## 原理

- **为什么用 API 哈希**：Windows shellcode 没有正常导入表，也不希望在代码里出现 `LoadLibraryA`/`InternetOpenA` 等明文字符串。它通过 PEB 遍历（`fs:[0x30]` → `PEB->Ldr` → 模块导出表）拿到目标 DLL 的导出名列表，对每个导出名计算散列，与调用点压栈的常量比较；命中后返回函数地址，再用 `call reg`/`jmp eax` 调用。这样逆向者看不到函数名，只能看到一堆 32 位常量。
- **静态识别模式**：在 shellcode 中，典型的调用点形如：
  ```asm
  push 0x0A779563A      ; API 哈希
  call ebp              ; ebp 指向解析函数（或先 call 解析、再 jmp eax）
  ```
  文章在 Ghidra 里从 `FUN_00000000` 跟进到 `FUN_0000008f`，看到通过函数指针 `unaff_retaddr` 传递 hash 间接调用不同函数；反汇编视图里 `PUSH` 内部就是哈希常量，紧接 `CALL RBP`。
- **raw shellcode 的 Ghidra 处理**：没有文件头时 Ghidra 不知道代码起点，需要手动 `d` 反汇编；如果反编译后没有函数，用 `f` 在代码起始处定义函数，才能得到伪代码。这个步骤对任何“裸 bin”样本都适用。
- **ROR13 类散列**：文章指出该样本使用 `ROR 13`（循环右移 13 位）这类散列，Cobalt Strike 与 Meterpreter 的 shellcode API 哈希也属于这一族。散列循环通常对每个字符做“旋转 + 累加/异或”，最终得到一个 32 位常量；用公开的哈希还原脚本/工具（文章参考了 cnblogs 上的思路）把常量反查为 API 名。文章给出的观测映射是：`0x726774c` → `LoadLibraryA`、`0xa779563a` → `InternetOpenA`、`0xC69F8957` → `InternetConnectA`。
- **注意实现差异**：ROR13 只是这一族的统称，实际样本可能在旋转方向、加法/异或、初始种子、大小写或宽字符上做变体；因此不能拿一份通用的 ROR13 脚本硬套，必须以样本里的散列循环（或 HashDB 一类工具）为准。文章通过 SpeakEasy 仿真验证了解析结果（看到 `LoadLibraryA`），再用动态调试确认了 `InternetOpenA`/`InternetConnectA`。
- **blobrunner 动态验证**：blobrunner 是“把裸 shellcode 加载到进程并挂起/触发调试器”的工具。文章运行 `blobrunner.exe shellcode.bin` 后，shellcode 被加载到 `0x011a0000`；把调试器附加到 blobrunner 进程，在 shellcode 的 `jmp eax` 偏移（文章为 `+0x86`）下断点，继续执行后命中断点；用 `f7` 进入第一个解析函数，跟踪 `call ebp`，在栈上看到待解析的哈希值；单步到 `jmp eax` 时，调试器注释/寄存器显示解析出的函数地址；继续执行即可看到传给 `LoadLibraryA` 的 `wininet` 字符串，随后是 `InternetOpenA`、`InternetConnectA` 的调用与参数。
- **为什么动态能补静态的不足**：静态只能看到常量，若哈希算法未知/被改，反查会很慢；动态在解析函数返回处直接看到“哈希 → 函数地址 → 参数”，可以快速确认调用链，再用静态把整条链补全。两者结合是恶意 shellcode 分析的常规路线。
- **攻防含义**：ROR13 是 CS/Meterpreter 的常见特征，安全设备可用它做检测；文章也提到可以修改散列算法/常量来绕过这类检测。对分析者而言，识别散列循环并还原 API 名是理解样本行为的关键一步。

## 触发条件

- 目标是裸 shellcode（`.bin`，无 PE 头）或内存中的 shellcode，32 位 x86，使用哈希方式动态解析 API；导入表/明文字符串很少。
- 分析环境具备 Ghidra/IDA、调试器（x64dbg/WinDbg）和 blobrunner（或等效的 shellcode loader）；样本可在隔离虚拟机中运行。
- 散列算法可识别（ROR13 族、CRC32+XOR 等），或能从样本的解析函数中逆出旋转/累加/异或循环。
- 样本未启用强反调试/反虚拟机；若有，需要先绕过或用纯静态/仿真（SpeakEasy）辅助。

## 利用步骤

1. 在 Ghidra 中以 x86 32 位 raw binary 导入 `.bin`；光标放到代码起始处按 `d` 反汇编；若无函数，按 `f` 定义函数，再打开反编译窗口。
2. 从入口函数跟进，找到解析函数：通常读取 `fs:[0x30]`/PEB、遍历 `PEB->Ldr`、访问导出表；调用点表现为 `PUSH <hash>` 后 `CALL RBP`/`CALL EAX`，或解析后 `jmp eax`。
3. 提取所有 `PUSH` 的 32 位常量，记录调用顺序；用哈希还原脚本/工具（或 HashDB）按样本的散列算法反查 API 名。文章示例得到 `LoadLibraryA`、`InternetOpenA`、`InternetConnectA`。
4. 用 SpeakEasy 等仿真器跑一遍样本，观察解析函数返回的模块/函数名，与静态反查结果交叉验证。
5. 动态确认：`blobrunner.exe shellcode.bin`，记下加载基址（文章 `0x011a0000`）；把调试器附加到 blobrunner 进程，在基址 + `jmp eax` 偏移（文章 `+0x86`）下断点；继续执行。
6. 命中断点后用 `f7` 单步进入解析函数/`call ebp`，在栈窗口读取待解析的哈希值；继续到 `jmp eax`，确认寄存器/注释给出的函数地址。
7. 继续执行并在 `LoadLibraryA`、`InternetOpenA`、`InternetConnectA` 等调用处观察参数：`wininet` 模块名、User-Agent、服务器地址、端口等；据此还原 C2 连接与后续行为。
8. 若样本的散列循环被修改，先在反汇编里还原循环（旋转位数、加法/异或、种子），再批量反查所有常量；必要时 patch 散列或跳过反调试。

## PoC

文章给出的是分析流程而非攻击 PoC；最小复现命令与常量表如下：

```bash
# 1) blobrunner 加载裸 shellcode，记录输出中的加载基址（文章为 0x011a0000）
blobrunner.exe shellcode.bin

# 2) 调试器附加到 blobrunner 进程后，在 shellcode 的 jmp eax 偏移处下断点
#    文章样本的 jmp eax 偏移为 0x86
bp 0x011a0000 + 0x86
g

# 3) 命中断点后 f7 单步进入解析函数，观察栈上的 hash 与解析结果
```

```python
# 文章通过哈希还原得到的常量 → API 名对应关系（具体算法以样本散列循环为准）
hash_to_api = {
    0x0726774C: "LoadLibraryA",
    0xA779563A: "InternetOpenA",
    0xC69F8957: "InternetConnectA",
}
print(hash_to_api[0xA779563A])   # InternetOpenA
```

```text
# 动态观察到的调用链（文章）：
# LoadLibraryA("wininet") -> InternetOpenA(...) -> InternetConnectA(server, port, ...)
```

## 变体与关联

- **散列算法变体**：ROR13 族（CS/Meterpreter）、`crc32(name) ^ key`（Dridex）、自定义 rotate/add/xor；识别方法是看解析函数里的循环，或用 HashDB/脚本枚举候选算法。
- **静态/动态变体**：纯静态反查适合不能运行的样本；SpeakEasy/unicorn 仿真适合 API 解析阶段；blobrunner/x64dbg 适合观察完整调用链与参数。
- **裸 shellcode 变体**：多层编码（hex/RC4/ASCII85）先解码再分析；反射 PE/内存加载需要先 dump 再按 PE 分析；分片/自修改 shellcode 需要动态跟踪。
- **关联**：[[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（CRC32+XOR 的 API hash 还原与 HashDB 用法）、[[code-analysis-reverse-windows-amadey-api-hash-loader-c2-config]]（PEB/API hash 加载器完整样本分析）、[[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]（多层编码 shellcode 解码与内存 dump）、[[code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump]]（x64dbg 跟踪 fiber loader）。
- **边界**：若样本使用强反调试、VM 检测、哈希算法每次运行变化或 API 解析走 syscall 直调，本文的静态+blobrunner 路线需要先做反调试绕过或改用仿真/符号执行。

## 检测与防御

- **检测（防守方）**：YARA/内存扫描关注 PEB 遍历（`fs:[0x30]`）、导出表解析、`ror 13`/循环移位+累加的哈希循环、`call reg`/`jmp eax` 的 API 解析模式；监控 `LoadLibraryA("wininet")`、`InternetOpenA`、`InternetConnectA` 等连续调用；对无 PE 头的可执行内存页做重点告警。
- **检测（分析方）**：保留样本的散列循环与常量表，建立 hash→API 的映射库；对 CS/Meterpreter 常见 ROR13 常量做快速匹配；动态断点应下在解析函数返回处，避免被反调试干扰。
- **防御**：终端启用 AMSI/ETW/API 监控与内存扫描；限制脚本/宏/未签名可执行内存；对可疑 shellcode 做沙箱仿真与网络阻断。
- **注意**：本文是恶意样本分析/授权研究场景；不要在生产环境运行未知 shellcode，样本应在隔离虚拟机中处理。
