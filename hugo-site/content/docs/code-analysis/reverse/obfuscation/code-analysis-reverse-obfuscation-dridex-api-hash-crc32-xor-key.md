---
id: code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key
title: Dridex API Hash 还原：crc32(name) ^ 0x7AF3DA47 与 HashDB XOR Key
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: api-hash-crc32-xor-key
tags:
- windows
- malware-analysis
- dridex
- api-hashing
- hashdb
- crc32
- ida
- obfuscation
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:27:04+08:00'
  notes: 已对照原文与图04-14核对：sub_55303C双常量函数199处引用、sub_5503C4的v3=a1^0x7AF3DA47、设XOR Key后HashDB识别为crc32并命中NtMapViewOfSection(0xFE338407,0xDEE5E4FB)均一致；已用zlib.crc32独立复算crc32('ntdll.dll')^key=0xFE338407、crc32('NtMapViewOfSection')^key=0xDEE5E4FB，与截图相符；未在样本上执行。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key/
draft: false
kb_aliases:
- Dridex API hash
- crc32 API hash
- HashDB XOR key
- API hash 还原
- 2062801479
- PEB 遍历 API 解析
- API hashing
---

## 一句话结论

Dridex 用 `hash = crc32(名称) ^ 0x7AF3DA47` 隐藏模块名与 API 名，遍历 PEB 的导出表逐个计算哈希后比对；在 IDA 中把 HashDB 的 XOR Key 设为 `0x7AF3DA47` 再 Hunt Algorithm，即可把算法识别为 crc32 并反查出 `ntdll.dll!NtMapViewOfSection` 等真实函数名，批量恢复全部动态解析的 API。

## 原理

- **隐藏导入**：样本只导入极少量函数，大量敏感 API 通过“模块名哈希 + API 名哈希”在运行时解析。哈希函数（示例 `sub_55303C`）先读 `fs:[0x30]` 找到 PEB，再经 `PEB->Ldr->InLoadOrderModuleList` 遍历已加载模块，对每个导出名计算哈希并与调用点传入的两个 32 位常量比较；匹配后返回函数地址。
- **加了一层 XOR**：哈希比较前有 `v3 = a1 ^ 0x7AF3DA47`，即样本里存的不是裸 `crc32(name)`，而是 `crc32(name) ^ 0x7AF3DA47`。因此直接对常量做 HashDB Hunt 会命中错误算法（示例给出 `ror7_add`）且反查不到函数名；把 `0x7AF3DA47` 设为 HashDB 的 XOR Key 后重新 Hunt，算法变为 `crc32`，常量被正确还原并命中 `NtMapViewOfSection`。
- **可验证的哈希关系**：对示例的两个常量做逆运算可得到标准 CRC32：
  - `crc32("ntdll.dll") = 0x84C05E40`，`0x84C05E40 ^ 0x7AF3DA47 = 0xFE338407`；
  - `crc32("NtMapViewOfSection") = 0xA4163EBC`，`0xA4163EBC ^ 0x7AF3DA47 = 0xDEE5E4FB`。
  - 即调用 `mw_get_api_by_hash_v2(0xFE338407, 0xDEE5E4FB)` 对应 `ntdll.dll!NtMapViewOfSection`，与 HashDB 结果一致。
- **为什么 XOR Key 是全局突破口**：这一族样本把同一个 XOR Key 用在所有哈希常量上，找到一处 `^ key` 就能批量还原；HashDB 的 XOR Key 选项正是为这种“哈希值再异或”的混淆设计。
- **规模**：示例样本有 199 个哈希调用点，逐个手工按 `M` 命名不现实，必须在 HashDB 命中后用模块批量导入/IDAPython 批量回填。

## 触发条件

- 目标为 Windows PE（示例为 32 位 DLL），导入表很小，存在一个被大量调用的“双常量”函数，内部读取 PEB/Ldr。
- 该函数在比较哈希前对参数或计算结果做了固定常量 XOR；XOR Key 可从反编译代码中直接读出。
- IDA 已安装 HashDB 插件并加载了对应 Windows 模块的哈希库（示例为 ntdll.dll/kernel32.dll），且哈希库覆盖样本使用的算法（crc32）。
- 样本未被强混淆/虚拟化到无法辨认哈希函数；若哈希函数被内联，需要先按 PEB 访问与常量模式定位。

## 利用步骤

1. 在 IDA 中打开样本，先把 Hex-Rays 的 `Default radix` 改为 16（或在反编译窗口中按 `H`），便于观察 32 位哈希常量。
2. 通过交叉引用找到被频繁调用的双常量函数（示例 `sub_55303C`，199 处引用），确认它遍历 PEB/Ldr 并计算导出名哈希。
3. 对其中一个哈希常量右键 → `HashDB` → `HashDB Hunt Algorithm`。若未设 XOR Key，可能只得到错误算法（如 `ror7_add`），且用返回的哈希值查不到函数。
4. 回到哈希函数内部找 XOR 常量，例如 `v3 = a1 ^ 0x7AF3DA47`；右键该常量 → `HashDB set XOR key`，把 `0x7AF3DA47` 设为 XOR Key。
5. 再次对哈希常量执行 `HashDB Hunt Algorithm`，此时应识别为 `crc32` 并命中真实函数名（如 `NtMapViewOfSection_0`）。
6. 接受 HashDB 的模块导入提示（示例导入 ntdll.dll 全量函数哈希），或按 `M` 将常量转成枚举/符号；对其余调用点重复，或用 IDAPython 批量按“哈希→名称”表回填。
7. 用标准 CRC32 独立复算若干条（`crc32(name) ^ key`）验证映射无误，再继续分析上层注入/网络逻辑。

## PoC

用标准库复算并验证哈希关系：

```python
import zlib

KEY = 0x7AF3DA47

def api_hash(name: str) -> int:
    return zlib.crc32(name.encode()) ^ KEY

assert api_hash("ntdll.dll") == 0xFE338407
assert api_hash("NtMapViewOfSection") == 0xDEE5E4FB
print(hex(api_hash("kernel32.dll")), hex(api_hash("GetProcAddress")))
```

批量反查思路（把样本中的常量映射回名称）：

```python
import zlib

KEY = 0x7AF3DA47
names = ["ntdll.dll", "kernel32.dll", "NtMapViewOfSection", "NtOpenProcess",
         "GetProcAddress", "LoadLibraryA", "VirtualAlloc"]
lookup = {zlib.crc32(n.encode()) ^ KEY: n for n in names}
for h in (0xFE338407, 0xDEE5E4FB):
    print(hex(h), "->", lookup.get(h))
```

IDA 侧的最小操作序列：`HashDB Hunt Algorithm` → 右键 XOR 常量 `HashDB set XOR key` → 再次 Hunt → 模块批量导入。PoC 未在样本上执行，哈希关系已用 `zlib.crc32` 独立验证。

## 变体与关联

- **算法变体**：同一手法可换 djb2、fnv1a、ror7_add、murmur 等；若 HashDB 首轮命中的算法反查不到名称，优先怀疑存在 XOR/加减常量，而不是直接认定算法错误。
- **Key 变体**：XOR Key 可能按样本生成、按调用点轮换或与模块名相关；先在一个函数内确认 Key 的作用范围，再决定是否能全局批量套用。
- **数据变体**：有的样本哈希宽字符（UTF-16）导出名、有的只哈希小写名或去掉扩展名；哈希库与样本的大小写/编码必须一致。
- **关联卡片**：[[code-analysis-reverse-windows-go-dll-init-export-loader-analysis]]（Go DLL 的全局 API 指针解析）、[[pentest-c2-peb-ldr-export-dynamic-api-resolution]]（PEB/Ldr 手工解析导出表的攻击侧实现）、[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（API wrapper 型隐藏）。
- **边界**：本卡解决的是“哈希常量→函数名”的静态还原，不解决哈希函数被 VM 化或运行时才解密哈希表的情况；那时需要动态断点或先脱混淆。

## 检测与防御

- **静态检测**：YARA/IDA 特征可组合“PEB 访问（`fs:[0x30]`/`gs:[0x60]`）+ Ldr 遍历 + 大量 32 位立即数比较 + 固定 XOR 常量”。示例 XOR Key 的小端字节为 `47 DA F3 7A`，可作为样本族特征之一（需按样本核验，不能单独作为通用规则）。
- **行为检测**：进程启动后无对应 IAT 导入却调用敏感 API、频繁读取 PEB、解析导出表；EDR 可对 `NtMapViewOfSection`/`NtOpenProcess` 等调用与调用栈中无模块符号的地址做关联告警。
- **防御**：启用 EDR/内存扫描与 API 调用监控；对银行木马常用注入链（进程镂空、APC、映射注入）做行为拦截；限制未知 DLL 加载。
- **分析侧**：优先用 HashDB 的 XOR Key 功能恢复符号，再用标准 CRC32 复算交叉验证；不要运行样本，哈希常量与字符串均视为不可信数据。
