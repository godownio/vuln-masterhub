---
id: ctf-reverse-peloader-dump-custom-arx-round-inverse
title: PELoader 内存 dump 脱壳 + 自定义 64 位 ARX 轮函数逆序还原 16 字节口令
type: scenario
domain: ctf
path: ctf/reverse
technique: peloader-dump-custom-arx-round-inverse
aliases:
- ISCC 2025 线下逆向
- PELoader 脱壳
- 内存 dump 二阶段 PE
- 自定义 ARX 加密逆向
- ror8 轮函数求逆
- Matryoshka2025
tags:
- ctf
- reverse
- unpacking
- pe-loader
- memory-dump
- arx
- ror8
- block-cipher
- inverse
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:32+08:00'
  notes: 已对照原文核对：0x47C27 分配/0x47C00 复制/就地 XOR 解密、PELoader MZ/PE 检查/区段复制/重定位/导入/VirtualProtect、SizeOfImage=0x4C000 dump、二阶段 12 轮 ror8+乘法+异或 ARX、key1=0x628591E23EE9495F/key2=0x11F7DF7B7133A3F0、目标 0x741DD6EDF0798EB1/0x455249FABE301CE1、逆得 Matryoshka2025!!，与原文一致。未验证点：未复跑样本；原文未给最终 flag 值；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

样本主函数把内嵌密文复制到堆上做就地异或解密，再交给一个自实现的 PE Loader（`VirtualAlloc` 映射、复制区段、修重定位、解析导入、跳入口）执行；在调用 Loader 前用调试器按 `SizeOfImage` dump 解密缓冲区即可得到二阶段 PE。二阶段对 16 字节输入做 12 轮 64 位 ARX 变换（`ror8(c1*(d^k),47)` + 乘法/异或混合），比较两个 8 字节常量；按轮依赖倒序求逆即可恢复输入 `Matryoshka2025!!`。

## 原理

- **一阶段是自解密 + PELoader**：`main` 分配 `0x47C27` 字节，复制 `0x47C00` 的内嵌数据，然后在原缓冲区上做异或解密（标量尾部为 `^ ((0xC0DEC0DEBADC0FFE >> (7*i)) ^ 0xA5)`，向量路径用 SIMD 移位/异或做同样运算），最后把缓冲区传给 PELoader 函数。
- **PELoader 特征**：检查 `MZ`（0x5A4D/23117）与 `PE`（0x4550/17744）；`VirtualAlloc(SizeOfImage, PAGE_READWRITE)`；按区段表把 `PointerToRawData/SizeOfRawData` 复制到 `VirtualAddress`；若 `ImageBase` 与加载地址不同则遍历重定位表，对 `0xA000` 类型项按 delta 修正；遍历导入表 `LoadLibraryA` + `GetProcAddress` 填 IAT；最后按区段 `Characteristics` 调 `VirtualProtect`，再 `((entry)(...))()` 跳转。
- **dump 时机**：在 `sub_...PE_loader(buffer)` 调用前断下，`buffer` 指针处的内存已经是解密后的完整 PE（含原始头），从头部读 `SizeOfImage`（本例 `0x4C000`），用调试器脚本（如 IDAPython `dbg_read_memory`）按该长度 dump 到文件即可；不要在 Loader 把区段映射并改写重定位/IAT 之后 dump。
- **二阶段输入与密钥**：程序读取 32 个十六进制字符（即 16 字节输入），由内部常量/字符串派生两个 64 位 key（key1、key2），对 16 字节做两段 8 字节 ARX 变换。
- **自定义 ARX 轮函数**：每轮先 `d1 = ror8(c1 * (x ^ round_key), 47)`，再 `y = (c2 * (d1 ^ (d1 >> 31))) ^ prev ^ ((c2 * (d1 ^ (d1 >> 31))) >> 33)`，其中 `c1=0xA24BAED4963EE407`、`c2=0x9FB21C651E98DF25`，round_key 由 `key1/key2` 与 `0x61C8864680B583EB` 等常量交替加减得到；共 12 轮，d3/d4 交替更新。
- **为什么能逆**：每轮对输入 `x` 是“异或轮密钥 → 乘常数 → ror8 → 再乘常数/右移混合后异或到另一状态”，乘法在 64 位模 2^64 下可逆（c1、c2 为奇数），`ror8` 可逆，`d ^ (d >> 31)` 可逆；因此按轮倒序、用已知的上一轮状态即可逐轮还原，而不用整体暴力。
- **比较与还原**：最终两段 8 字节输出分别等于 `0x741DD6EDF0798EB1` 与 `0x455249FABE301CE1`；倒序执行 12 轮后得到两个 64 位输入值，按大端拼回 16 字节即 `Matryoshka2025!!`。

## 触发条件

- 目标为 Windows PE，主函数包含“大块内嵌数据 + 分配/复制 + 就地解密 + 调用加载器”的模式。
- 加载器具备 `VirtualAlloc`、区段复制、重定位修正、`LoadLibraryA`/`GetProcAddress` 导入解析等手工 PE 加载特征。
- 二阶段输入长度固定（本例 16 字节），校验为固定 8 字节常量比较。
- 轮函数由可逆的 `ror/乘法/异或` 组成，且轮密钥可从二进制常量或已恢复 key 推导。
- 允许本地调试/内存 dump（弱反调试；本例仅检查 `MATRY_NO_ADB` 环境变量，可直接跳过）。

## 利用步骤

1. 定位 `main`：识别内嵌密文复制与解密循环，确认解密后的缓冲区指针。
2. 识别 PELoader：确认 `MZ/PE` 检查、`VirtualAlloc`、区段复制、重定位与导入解析、`VirtualProtect`、入口调用。
3. 在 `call PELoader` 前下断，从缓冲区头读 `SizeOfImage`（先 dump 前 `0x1000` 字节解析 DOS/NT 头得到，本例 `0x4C000`），按该长度 dump 完整 PE。
4. 用 IDA/Ghidra 静态分析 dump 出的二阶段，定位输入读取、key 派生与两段 8 字节比较常量。
5. 反编译轮函数，确认 12 轮、`c1/c2`、`ror8(...,47)`、`d^(d>>31)` 与轮密钥常量序列。
6. 按轮倒序实现逆变换（每轮先撤销另一状态的异或，再对 `ror`/乘法求逆，最后异或回轮密钥），从两个目标常量还原 16 字节输入。
7. 将恢复的输入（字符或 `hex:` 前缀的十六进制）送入程序，获取 flag。

## PoC

逆变换核心（C，按轮倒序；与原加密轮对称）：

```c
static uint64_t ror8(uint64_t x, int n){ return (x >> n) | (x << (64 - n)); }

/* key1=0x628591E23EE9495F, key2=0x11F7DF7B7133A3F0
   c1=0xA24BAED4963EE407, c2=0x9FB21C651E98DF25
   目标：d3=0x455249FABE301CE1（第二段）, d4=0x741DD6EDF0798EB1（第一段） */
d1 = ror8(c1 * (d3 ^ (key2 - 0x339DC50787CCAB19ULL)), 47);
d4 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d4 ^ (key1 + 0x2E2AC13EF8E8D8D2ULL)), 47);
d3 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d3 ^ (key2 - 0x700CB87A8661A343ULL)), 47);
d4 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d4 ^ (key1 - 0x0E44323405AC1F58ULL)), 47);
d3 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d3 ^ (key2 + 0x538454127B096493ULL)), 47);
d4 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d4 ^ (key1 - 0x4AB325A704411782ULL)), 47);
d3 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d3 ^ (key2 + 0x1715609F7C746C69ULL)), 47);
d4 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d4 ^ (key1 + 0x78DDE6E5FD29F054ULL)), 47);
d3 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d3 ^ (key2 - 0x255992D382208BC1ULL)), 47);
d4 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d4 ^ (key1 + 0x3C6EF372FE94F82AULL)), 47);
d3 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (d3 ^ (key2 - 0x61C8864680B583EBULL)), 47);
input02 = (c2*(d1^(d1>>31))) ^ d4 ^ ((c2*(d1^(d1>>31)))>>33);
d1 = ror8(c1 * (key1 ^ input02), 47);
input01 = (c2*(d1^(d1>>31))) ^ d3 ^ ((c2*(d1^(d1>>31)))>>33);
/* input01=0x4D617472796F7368, input02=0x6B61323032352121 -> "Matryoshka2025!!" */
```

说明：原文在本地复现出 `01: 0x4D617472796F7368 02: 0x6B61323032352121`（`Matryoshka2025!!`），输入后成功输出 flag；本库未复跑样本。

## 变体与关联

- 变体：PELoader 可换成 aPLib/UPX 等壳，dump 点改为 `VirtualProtect` 入口或解压完成处；关键是拿到“已解密、未映射改写”的镜像。
- 变体：ARX 轮函数可换成标准 TEA/XTEA 或其它 `ror/乘法/异或` 组合；只要每步可逆，都能按轮倒序还原。
- 关联：[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（PE Loader + ChaCha20 解密二阶段）、[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（VirtualAlloc/VirtualProtect 断点 dump）、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（魔改 TEA + 异或）、[[ctf-reverse-custom-vm-tea-like-30round-block-bruteforce]]（TEA-like 轮函数逆向）。
- 限制：本例输入长度为 16 字节、比较常量为固定值；真实目标需按实际轮数/常量/字节序调整。

## 检测与防御

- 检测：PE 中出现大块高熵/内嵌数据、`VirtualAlloc` + 区段复制 + `LoadLibraryA`/`GetProcAddress` 手工加载特征、入口前就地解密循环。
- 防御：EDR 监控内存中 `MZ` 镜像生成与自映射执行；限制可执行内存与动态导入解析；对样本做内存扫描与 dump 分析。
- 逆向侧：dump 要在 Loader 改写重定位/IAT 前完成；按 `SizeOfImage` 读取，避免截断区段。
