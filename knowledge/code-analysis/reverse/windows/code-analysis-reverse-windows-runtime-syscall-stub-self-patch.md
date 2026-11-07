---
id: code-analysis-reverse-windows-runtime-syscall-stub-self-patch
title: 运行时自修复 syscall stub：扫描自身内存把 6B 00 00 73 6B 00 00 74 占位字节替换为 syscall;ret
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: runtime-syscall-stub-self-patch
aliases:
- 修复 syscall 调用代码
- 6B 00 00 73 6B 00 00 74
- 0F 05 90 90 C3 90 CC CC
- syscall stub 自修改
- 自修复 syscall
- BGL.exe syscall
- UPX 后 syscall 补丁
tags:
- windows
- malware-analysis
- reverse
- syscall
- self-modifying-code
- anti-hook
- upx
- obfuscation
- evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:47+08:00'
  notes: 已对照原文与图08-11核对；占位6B0000736B000074→0F059090C390CCCC与自进程Read/WriteProcessMemory一致；未复跑。
---

## 一句话结论

恶意样本在磁盘上把系统调用存根的真实字节 `0F 05 ...` 替换成占位序列 `6B 00 00 73 6B 00 00 74`，运行时再扫描自身内存，命中后用 `ReadProcessMemory`/`WriteProcessMemory` 改写回 `0F 05 90 90 C3 90 CC CC`（`syscall; nop; nop; ret; nop; int3; int3`），之后才通过函数指针调用这些存根。静态看是无效指令，动态/内存里才是真正的 syscall，既绕过静态检测，也让只读文件的逆向分析看不到系统调用。

## 原理

- **静态占位、运行时还原**：样本中需要 syscall 的位置在文件中以 8 字节 `6B 00 00 73 6B 00 00 74` 存在；这不是合法的 `syscall` 指令，直接执行会出错，静态反汇编也看不到 `0F 05`。程序在入口早期运行一个“修复”函数，把占位字节替换成 `0F 05 90 90 C3 90 CC CC`：`0F 05` 是 x64 `syscall`，`90 90` 为 nop，`C3` 为 ret，`90` 为 nop，`CC CC` 为 int3 填充。
- **修复函数的位置无关扫描**：`sub_...` 先 `GetCurrentProcess()`，用 `EnumProcessModules` + `GetModuleInformation` 取得自身各模块的基址与映像大小；然后以 1 字节步长遍历模块内存，对每个偏移 `ReadProcessMemory(hProcess, base+off, buffer, 8, ...)`，用 `memcmp(buffer, pattern, 8)` 与占位序列比较；命中后 `WriteProcessMemory(hProcess, base+off, stub, 8, ...)` 写回真实 syscall 存根。
- **对自身进程写入**：`GetCurrentProcess()` 返回伪句柄，`WriteProcessMemory` 对自身地址空间通常可直接写；若目标页只读，样本可能先 `VirtualProtect`，原文在 UPX 脱壳后的代码中直接读写，说明所在节区可写或已被改为可写。
- **为什么用“占位 + 自修复”**：① 静态扫描/杀软看不到 `0F 05` 或敏感 syscall 序列；② 反汇编器把占位当作数据/无效代码，控制流难以恢复；③ 运行时修复后的存根仍然是普通 syscall，不依赖 ntdll 的导出/SSN，天然绕过用户态 hook；④ UPX 脱壳后如果只看文件字节，仍然看到占位，必须动态调试或内存 dump 才能看到真实调用。
- **与直接/间接 syscall 的区别**：直接 syscall 通常在代码里显式写 `mov eax, SSN; syscall`；本手法把 `syscall` 指令本身藏起来，运行时才补上，属于自修改代码（self-modifying code）而非 SSN 解析。样本仍需通过 `eax` 传入 syscall 号，修复只是让指令合法。
- **样本实例**：`BGL.exe`（134,144 字节，UPX 壳）脱壳后可见修复函数；动态调试在某模块内存 `...4917CC` 处命中 `0F 05 90 90 C3 90 CC CC`，IDA 将其识别为 `syscall`。

## 触发条件

- 目标为 Windows x64 恶意样本；文件中存在 `6B 00 00 73 6B 00 00 74` 占位序列（或其变体）。
- 样本能在自身进程内调用 `ReadProcessMemory`/`WriteProcessMemory`；目标内存可写，或样本先改内存保护。
- 修复函数在首次使用 syscall 存根之前执行（通常在入口/初始化阶段）。
- 分析侧需要 UPX 脱壳、IDA/x64dbg 动态调试或内存 dump；只做静态字符串/反汇编容易漏掉。

## 利用步骤

1. UPX 脱壳（`upx -d` 或动态 dump），确认文件中有 8 字节占位序列；用 YARA/`grep -abo` 定位所有出现位置。
2. 在 IDA 中定位 `GetCurrentProcess`、`EnumProcessModules`、`GetModuleInformation`、`ReadProcessMemory`、`WriteProcessMemory` 的调用链；找到 `memcmp` 的 8 字节常量和写入的 8 字节常量。
3. 在 `WriteProcessMemory` 返回后下断点，或在修复函数返回后 dump 模块内存，确认占位已被替换为 `0F 05 90 90 C3 90 CC CC`。
4. 对每个修复点记录模块基址 + 偏移、调用者与 `eax` 中的 syscall 号；按 Windows syscall 表还原实际调用的内核服务。
5. 若要静态分析，可先把文件中所有占位序列批量替换为真实存根，再让 IDA 重新分析（生成副本，不要修改原始证据）。
6. 关联后续行为：修复后的 syscall 常用于进程/内存/文件操作，可结合调用参数还原完整行为链。

## PoC

原文伪代码对应的最小修复逻辑（仅示意，未执行样本）：

```c
#include <windows.h>
#include <psapi.h>

static const BYTE kPlaceholder[8] = {0x6B,0x00,0x00,0x73,0x6B,0x00,0x00,0x74};
static const BYTE kSyscallStub[8] = {0x0F,0x05,0x90,0x90,0xC3,0x90,0xCC,0xCC};

void repair_syscall_stubs(void) {
    HANDLE h = GetCurrentProcess();
    HMODULE mods[1024]; DWORD needed = 0;
    EnumProcessModules(h, mods, sizeof(mods), &needed);
    for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
        MODULEINFO mi = {0};
        if (!GetModuleInformation(h, mods[i], &mi, sizeof(mi))) continue;
        BYTE *base = (BYTE *)mi.lpBaseOfDll;
        for (SIZE_T off = 0; off + 8 <= mi.SizeOfImage; off++) {
            BYTE buf[8];
            if (!ReadProcessMemory(h, base + off, buf, 8, NULL)) continue;
            if (memcmp(buf, kPlaceholder, 8) == 0) {
                WriteProcessMemory(h, base + off, kSyscallStub, 8, NULL);
            }
        }
    }
}
```

静态辅助：批量把占位替换为 syscall 存根后再反汇编（在副本上操作）：

```python
data = bytearray(open('BGL.unpacked.exe', 'rb').read())
old = bytes.fromhex('6B0000736B000074')
new = bytes.fromhex('0F059090C390CCCC')
n = data.count(old)
data = data.replace(old, new)
open('BGL.fixed.exe', 'wb').write(data)
print('patched', n)
```

## 变体与关联

- 变体：占位序列/真实存根可换（不同 nop/int3 组合、`syscall; ret` 或 `syscall; jmp`）；也可在运行时按 syscall 号生成存根。
- 变体：只在堆/私有内存中构造存根，代码节保持只读；或先 `VirtualProtect` 再写。
- 变体：与 UPX/Themida 等壳叠加，壳解压后才暴露修复函数；也可把修复函数放在 TLS 回调中先于入口执行。
- 关联：[[code-analysis-reverse-obfuscation-linux-dynamic-api-hash-syscall-stub]]（Linux 运行时 syscall stub）、[[pentest-c2-indirect-syscall-ntdll-hook-bypass]]（SSN + 间接 syscall）、[[pentest-c2-hells-gate-neighbor-ssn-recovery]]（邻居 stub 恢复 SSN）、[[pentest-c2-freshycalls-export-sort-ssn]]（按导出排序取 SSN）、[[code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe]]（本例 BGL.exe 的完整链）。
- 边界：内存页不可写且样本不改保护、修复函数未被调用、占位序列被加密/压缩、目标不是 Windows x64 时，该手法不成立。

## 检测与防御

- **静态检测**：YARA 匹配 `6B 00 00 73 6B 00 00 74` 与 `0F 05 90 90 C3 90 CC CC` 的组合；检查 UPX 壳与异常的自修改代码；对 `ReadProcessMemory` + `WriteProcessMemory` 同进程组合告警。
- **动态检测**：监控进程对自身内存的 `WriteProcessMemory`、`VirtualProtect` 改可写可执行、在非映像/私有内存出现 `0F 05`；ETW/Sysmon 关注进程内存写与模块加载；内存扫描可在修复后捕获 syscall 存根。
- **防御**：启用 ACG/CIG/CFG 限制非映像内存执行与动态代码生成；EDR 对自进程写入与 RWX 内存告警；应用白名单阻止未知 UPX 样本；对高价值主机做定期内存扫描。
- **响应**：内存 dump 后搜索 `0F 05` 与占位序列，定位修复函数与调用点；结合 syscall 号还原行为；隔离样本并提取 C2/持久化配置。
