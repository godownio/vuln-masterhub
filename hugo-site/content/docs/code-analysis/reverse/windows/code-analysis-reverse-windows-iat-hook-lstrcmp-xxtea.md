---
id: code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea
title: IAT 槽位 Hook 识别与还原：VirtualProtect xref 定位 lstrcmpA 劫持 + 魔改 XXTEA 解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: iat-hook-lstrcmp-xxtea-recovery
tags:
- reverse
- windows
- iat-hook
- virtualprotect
- xxtea
- import-table
- anti-analysis
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:55+08:00'
  notes: 已对照原文Flow段与图13/16核对：VirtualProtect xref定位sub_1400016C0、导入表hash_ascii(0x5EDB0676→lstrcmpA)、IAT槽写reed_gate并先恢复原指针、delta=0x61C88647的魔改XXTEA、reeds/silt/foam密钥恢复与sink_mark解密均一致。未验证点：PoC未本机复跑，原文未给完整二进制；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea/
draft: false
kb_aliases:
- Flow
- IAT hook
- lstrcmpA 劫持
- VirtualProtect IAT 槽
- 导入表哈希
- 魔改 XXTEA
- reed_gate
---

## 一句话结论

样本在构造函数/启动时遍历导入表，对每个导入函数名做哈希，命中 `lstrcmpA` 后用 `VirtualProtect` 把 IAT 槽改成可写、写入 `reed_gate` 地址并恢复权限；`reed_gate` 先恢复原 `lstrcmpA` 指针，再执行真正的检查（魔改 XXTEA）。逆向时从 `VirtualProtect` 的 xref 定位 Hook 安装器，识别被劫持的 IAT 槽与原函数，再按 XXTEA 逆变换解密。

## 原理

- **IAT Hook**：PE 的导入地址表（IAT）保存外部函数真实地址。攻击者/保护壳遍历 `IMAGE_IMPORT_DESCRIPTOR`，按 `OriginalFirstThunk/FirstThunk` 找到每个导入项，用自定义哈希匹配函数名；命中后 `VirtualProtect` 把目标 IAT 槽改为 `PAGE_READWRITE`，写入自己的函数地址，再恢复原权限。
- 案例的 `hash_ascii` 对函数名做大小写归一后 `h = rol32(h ^ c, 7) + 0x9E3779B9`，目标 `NEEDLE_HASH = 0x5EDB0676` 对应 `lstrcmpA`。
- `reed_gate` 被调用时先通过 `g_cmp_slot/g_real_cmp` 把 IAT 槽恢复为原始 `lstrcmpA`，避免重复劫持；然后执行 `deep_cast()`（魔改 XXTEA）校验输入。
- **魔改 XXTEA**：`delta = 0x61C88647`（注意与标准 0x9E3779B9 不同），`rounds = 6 + 52/n`，`mesh_word` 在标准 XXTEA 混合上又加了一层 `rol32(key[(p^e)&3]+z, (sum+p)&7)`；密钥 16 字节由 `reeds/silt/foam/pick/swap/roll` 数组按 `rol8((reeds[pick[i]]+silt[swap[i]])&0xff, roll[i]) ^ foam[i]` 恢复。
- 密文/目标为 24 字节 `sink_mark`，解密时按 `sum` 递减、`p` 逆序执行 `v[p] -= mesh_word(...)`，最后 `sum -= delta` 直到 0。
- 逆向要点：`VirtualProtect` 的 xref 通常直接暴露 Hook 安装器；IAT 槽地址、原函数指针与 Hook 函数是识别/还原的关键；不要只静态看 `lstrcmpA` 调用，它可能已被替换。

## 触发条件

- Windows PE，导入表中有 `VirtualProtect`、`GetModuleHandleA`、`LoadLibraryA` 等 API。
- 存在构造函数/启动代码遍历导入表、按哈希匹配函数名并写 IAT 槽。
- 目标函数（如 `lstrcmpA`/`memcmp`）的 IAT 槽在运行时被改为非系统模块地址。
- 后续校验使用自定义分组密码（XXTEA/TEA 变体）或类似可逆变换。

## 利用步骤

1. 在 IDA/Ghidra 中查看 `VirtualProtect` 的 xref，定位写 IAT 槽的安装器函数（案例 `sub_1400016C0`）。
2. 还原 `hash_ascii` 与 `NEEDLE_HASH`，确认被劫持的导入函数（案例 `lstrcmpA`）。
3. 找到 Hook 函数（案例 `reed_gate`/`sub_140001830`），确认它先恢复原 IAT 指针，再调用真实校验。
4. 逆向真实校验：识别 XXTEA 的 `delta`、`rounds`、`mesh_word` 变体与密钥恢复数组。
5. 从密文/目标常量按 XXTEA 逆变换（`sum` 递减、`p` 逆序）解出明文。
6. 动态验证：在 `reed_gate` 下断点，观察 IAT 槽恢复前后的值；用解密结果验证程序输出。

## PoC

```python
import struct

def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> ((8 - r) & 7))) & 0xFF

def rol32(v, r):
    r &= 31
    return ((v << r) | (v >> ((32 - r) & 31))) & 0xFFFFFFFF

def mesh_word(z, y, sum_, key, p, e):
    mix = ((((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) +
            ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^
           ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
    mix ^= rol32((key[(p ^ e) & 3] + z) & 0xFFFFFFFF, (sum_ + p) & 7)
    return mix & 0xFFFFFFFF

def recover_key(reeds, silt, foam, pick, swap, roll):
    return bytes(rol8((reeds[pick[i]] + silt[swap[i]]) & 0xFF, roll[i]) ^ foam[i]
                 for i in range(16))

def decrypt_xxtea(sink_mark, key_bytes):
    key = list(struct.unpack("<4I", key_bytes))
    v = list(struct.unpack("<6I", sink_mark))
    delta = 0x61C88647
    n = len(v)
    rounds = 6 + 52 // n
    sum_ = (delta * rounds) & 0xFFFFFFFF
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mesh_word(z, v[(p + 1) % n], sum_, key, p, e)) & 0xFFFFFFFF
        v[0] = (v[0] - mesh_word(v[n - 1], v[1], sum_, key, 0, e)) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF
    return struct.pack("<6I", *v)
```

案例 `sink_mark = 46d414392650daf1875cb27d362d6ea3342336cc741f845c`，恢复 key 为 `y@ua1eg0od@Tfind`，解密得到 `flag{Y0u@regrEatreveRser_1145}`。

## 变体与关联

- 变体：Hook 目标可能是 `memcmp`、`strcmp`、`IsDebuggerPresent` 或加密函数；按哈希/字符串 xref 识别。
- 变体：IAT Hook 可能改为 Inline Hook（5 字节 E9）、EAT Hook 或延迟导入（delay-load）；检查 `VirtualProtect` 目标地址属于哪个表。
- 变体：XXTEA 变体可能改 delta、rounds、mesh_word 或密钥派生；先识别常量与轮函数，再写逆变换。
- 关联：[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（Inline Hook）、[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（改版 UPX）、[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（XXTEA 变体）。

## 检测与防御

- 防御：对 IAT/EAT/Inline Hook 做完整性校验（比较磁盘与内存中的 IAT、代码段哈希）；使用 CFG/Control Flow Guard。
- 防御：关键比较不要依赖单一 API；对返回值做多路校验，减少 Hook 单点。
- 检测：`VirtualProtect` 对 IAT 槽的写入、IAT 项指向非模块地址、构造函数/启动期导入表遍历；EDR 监控 IAT hook 行为。
- 响应：dump 内存 IAT 并恢复原始指针，定位 Hook 函数与安装器；在隔离环境分析 XXTEA 解密逻辑。
