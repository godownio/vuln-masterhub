---
id: code-analysis-reverse-vm-unity-compute-shader-bytecode-il2cpp
title: Unity IL2CPP + Compute Shader 自定义 VM：DXBC 还原 32 寄存器字节码并逆出三轮加密
type: scenario
domain: code-analysis
path: code-analysis/reverse/vm
technique: unity-compute-shader-vm-il2cpp-bytecode-reverse
tags:
- reverse-engineering
- unity
- il2cpp
- compute-shader
- dxbc
- vm
- bytecode
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:15:12+08:00'
  notes: 已对照 pixelflow 段核对：Il2CppDumper、AssetRipper、DXBC VM 32 寄存器与 opcode、三轮可逆变换、ciTex.png 解密脚本均吻合；PoC 未执行
url: /docs/code-analysis/reverse/vm/code-analysis-reverse-vm-unity-compute-shader-bytecode-il2cpp/
draft: false
kb_aliases:
- Unity Compute Shader VM
- IL2CPP 逆向
- DXBC 反编译
- 32 寄存器字节码
- 自定义 VM 逆向
- pixelflow
---

## 一句话结论

Unity3D 程序可以把 flag 校验放进 Compute Shader 的自定义 VM：用 Il2CppDumper 还原符号、定位 `Check` 异步状态机，AssetRipper 解包资源并用 DXBC 反编译还原 VM 的 32 个寄存器与 opcode（LOAD_IMM/LOAD_FLAG/XOR/ROTL/MUL_IMM/ADD_IMM/ADD/STORE_OUT/CMP_LT_IMM/JNZ/HALT），再对 `ciTex.png` 的 16 字节密文按每轮“减索引、乘 7 的逆元、循环右移、异或滚动 key”逆三轮，即得 flag。

## 原理

- **IL2CPP 定位**：Unity IL2CPP 把 C# 转成 C++ 再编译，符号被裁剪但 `Il2CppDumper` 可从 `global-metadata.dat` 与二进制恢复类/方法/字符串；`Check` 方法常被编译器转成异步状态机（`MoveNext`），需要跟状态机字段找到 flag 长度、Buffer 与 Compute Shader 调用。
- **Compute Shader 资源**：`AssetRipper` 解包 Unity 资源，提取 `.compute` 对应的 DXBC 字节码；用 `dxc`/`3Dmigoto`/`RenderDoc` 反编译，得到 HLSL 伪代码。
- **VM 结构**：示例 VM 有 32 个 `uint regs[32]`、16 字节输出 `enc[16]`；`ReadInstr(CoTex, pc)` 从纹理读指令，`op/a/b/imm` 四字段；循环最多 1024 步，`pc >= codeW` 或 `HALT` 停止。opcode 包括：
  - `LOAD_IMM regs[a]=imm`、`LOAD_FLAG regs[a]=ReadByteRW(WorkTex, regs[b]&0xF)`；
  - `XOR/ROTL/MUL_IMM/ADD_IMM/ADD` 在 8 位内运算；
  - `STORE_OUT enc[regs[a]&0xF]=regs[b]&0xFF`；
  - `CMP_LT_IMM`、`JNZ`（带符号偏移跳转）、`HALT`。
- **加密流程**：`Check` 把 16 字节 flag 写入 Buffer，重复调用三次 `Compute Shader` 加密，得到 `enc[16]`；`K1` 把 `enc[i]` 与 `i` 做加法后与 `CiTex` 比较。因此密文是 16 字节，三轮变换可逆。
- **逆变换**：每轮对字节 `c`：`v=(c-i) mod 256`、`v*=INV_7 (183，7 的模 256 逆元)`、`rotr8(v,i)`、`out=v^key`，然后 `key=(key+c) mod 256`；初始 key 0x2A。逆三轮后得到 `alictf{...}`。
- **为什么可逆**：所有运算都在 8 位域（模 256），乘法 7 与 183 互逆，循环移位可逆，XOR 自逆；滚动 key 只依赖密文字节，可在解密时同步重算。

## 触发条件

- 目标是 Unity IL2CPP 构建，含 Compute Shader 资源；可获取 `GameAssembly.dll`/`global-metadata.dat` 与资源包。
- 校验逻辑在 Shader VM 中，opcode 集合有限且可反编译；密文/比较数据在资源或纹理中（示例 `ciTex.png`）。
- 变换为 8 位可逆运算，轮数固定；flag 长度/格式已知或可爆破。
- 有 Il2CppDumper、AssetRipper、DXBC 反编译工具与 Python 图像库。

## 利用步骤

1. **Dump IL2CPP**：用 Il2CppDumper 处理 `GameAssembly.dll` + `global-metadata.dat`，恢复类/方法；搜索 `Check`、`Buffer`、`ComputeShader`、`Dispatch` 等字符串/调用。
2. **定位状态机**：`Check` 的异步状态机 `MoveNext` 中找 flag 长度检查（16）、Buffer 写入、三次 `ComputeShader.Dispatch`、最终比较。
3. **解包资源**：AssetRipper 导出 `ciTex.png` 与 compute shader；DXBC 反编译得到 `RunVM` 与 `K0/K1`。
4. **还原 opcode**：按 `switch(op)` 建立 opcode 表/解释器；必要时用 RenderDoc 抓 dispatch 参数、用已知输入验证 VM 行为。
5. **提取密文**：读取 `ciTex.png` 前 16 个像素的红通道（或按 `K1` 的比较逻辑取字节）。
6. **逆三轮**：实现 `decrypt_round`，初始 key 0x2A；对密文做三次逆变换，得到 16 字节明文。
7. **拼 flag**：按格式 `alictf{plain}` 输出。

## PoC

```python
from PIL import Image

INV_7 = 183  # 7 * 183 ≡ 1 mod 256

def rotr8(x, k):
    x &= 0xFF; k &= 7
    return ((x >> k) | (x << (8 - k))) & 0xFF

def decrypt_round(enc_bytes, key_init=0x2A):
    key = key_init & 0xFF
    out = bytearray(16)
    for i in range(16):
        c = enc_bytes[i] & 0xFF
        v = (c - i) & 0xFF
        v = (v * INV_7) & 0xFF
        v = rotr8(v, i)
        out[i] = (v ^ key) & 0xFF
        key = (key + c) & 0xFF
    return bytes(out)

img = Image.open("ciTex.png").convert("RGBA")
stored = [px[0] & 0xFF for px in img.getdata()][:16]
enc = bytes(((b - i) & 0xFF) for i, b in enumerate(stored))

plain = enc
for _ in range(3):
    plain = decrypt_round(plain, 0x2A)

print("alictf{" + plain.decode("ascii") + "}")
```

原文的 `K1` 还可能对字节做 `(enc[i]+i)` 比较，脚本已先减去 `i`；具体以反编译结果为准。本卡不执行 PoC。

## 变体与关联

- **其它 Shader VM**：用纹理/缓冲区存字节码、寄存器机/栈机、不同 opcode 集合；核心方法相同：反编译 shader → 还原解释器 → 提取密文 → 逆变换。
- **反调试/混淆**：IL2CPP 加密、metadata 混淆、shader 字符串加密；可先脱壳/dump 内存再分析。
- **非可逆变换**：若含哈希/非线性 S 盒，需要暴力/符号执行/Z3；示例为纯可逆 8 位运算。
- **关联**：[[ctf-reverse-custom-python-vm-bytecode-disassembler]]（自定义 VM 反汇编）、[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（VM/ WASM 协同）、[[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]（Unity IL2CPP 动态分析）。
- **边界**：需要能获取 IL2CPP 元数据与 shader 资源；若 shader 被加密/远程下发、VM 含不可逆运算，静态逆向难度大幅上升。

## 检测与防御

- **对防御方**：这不是攻击场景，而是逆向分析方法；若需保护 Unity 逻辑，可使用 IL2CPP 加密、metadata 混淆、shader 资源加密、服务端校验与反调试，但不能替代真正的密钥保护。
- **检测**：客户端出现 Il2CppDumper/AssetRipper/RenderDoc 特征、频繁 dump 进程内存、修改 shader/资源；服务端校验应独立于客户端。
- **响应**：对作弊/逆向样本做哈希与行为分析，更新资源加密与校验策略。
