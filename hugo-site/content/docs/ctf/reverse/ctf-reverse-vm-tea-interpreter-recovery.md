---
id: ctf-reverse-vm-tea-interpreter-recovery
title: VM 解释器中的 TEA 识别与解密：从 opcode 分发器还原 sum/delta 轮函数，按魔改 delta 与 36 轮反推 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: vm-tea-interpreter-recovery
tags:
- ctf
- reverse
- vm
- tea
- interpreter
- bytecode
- crypto
- windows
- dll
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:29+08:00'
  notes: 已对照原文核对：VM opcode 9/11 的加载与 36 轮计数、delta=0x1919810、keys 与逆向轮公式均与原文一致；本地复算逆向轮输出 flag{Be@ut1fuL-Ex2cpti0n-Vi3tual-F10wer}。外层链式 XOR 的加密索引与文章解密脚本写法不完全对称，卡内已注明以二进制加密循环为准。
url: /docs/ctf/reverse/ctf-reverse-vm-tea-interpreter-recovery/
draft: false
kb_aliases:
- VM 实现 TEA
- VM TEA 逆向
- 魔改 TEA
- DllMain VM
- delta 0x1919810
- TEA 36 轮
- 解释器还原加密
---

## 一句话结论

当样本把 TEA 藏在自定义 VM 里时，先把 VM 的 opcode 分发器还原成伪代码，识别出 `sum += delta` 与两半轮函数（移位 3/4/5/6、与 key/sum 异或相加），再按实际参数（示例 delta=`0x1919810`、36 轮、4 个 32 位 key）写逆向轮即可解密；外层若还有 DLL 文件加密，可先用已知 PE 头恢复链式 XOR 密钥解出 DllMain.dll，再分析其中的 VM。

## 原理

- **VM 解释器结构**：样本 DllMain 中的 `sub_100012C0` 维护一个字节码数组（示例 `v6[72]`）与 `pc`，`switch(v6[pc])` 分发：
  - `0` add、`1` xor、`2` lshift、`3` rshift、`5` copy、`6` sub、`7` mul、`8` div；
  - `9` 把输入两半与 4 个 key 装入 VM 寄存器/内存；
  - `11` 递增轮计数器，到达 36 后比较结果并决定成功/失败。
  其余字节是操作数索引/立即数，`pc` 按指令长度推进。
- **还原成 TEA**：把字节码逐条翻译后，轮函数呈现标准 TEA 形状（示例注释）：
  ```text
  sum += delta
  input0 += ((input1 << 3) + key0) ^ (input1 + sum) ^ ((input1 >> 4) + key1)
  input1 += ((input0 << 5) + key2) ^ (input0 + sum) ^ ((input0 >> 6) + key3)
  ```
  这是 TEA 的变体：标准 TEA 常用移位 4/5，示例为 3/4/5/6；`sum` 每轮加 `delta`，轮数 36（标准 TEA 常用 32）。
- **参数提取**：delta `0x1919810`、轮数 36、keys `{0x1234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210}`；密文为 10 个 32 位字（5 对/40 字节）。这些常量可能直接出现在 VM 的加载指令或数据段中，也可能在调试时从寄存器读出。
- **逆向轮**：TEA 的 ARX（加/异或/移位）全部可逆。解密时 `sum = delta * 轮数`，每轮先逆第二半、再逆第一半，最后 `sum -= delta`：
  ```text
  v1 -= ((v0 << 5) + k2) ^ (v0 + sum) ^ ((v0 >> 6) + k3)
  v0 -= ((v1 << 3) + k0) ^ (v1 + sum) ^ ((v1 >> 4) + k1)
  sum -= delta
  ```
  对每对 32 位字执行 36 轮后按小端输出 4 字节，即还原明文/flag。
- **外层文件加密**：`encrypt` 文件本身不是 DLL，而是 DllMain.dll 经过链式 XOR 的密文：
  `Buffer[i+1] ^= key[(Size-2-i) % a2] ^ Buffer[i] ^ 0x66`；
  由于 PE/DLL 文件头固定（`MZ`、`PE\0\0`、节表等），可用已知明文反推 key（文章得到类似 `gaLf_ek@f_AsI_s1hT{galf}` 的循环 key），再按相同链式公式逐字节解密出 DllMain.dll。注意文章给出的加密索引与解密脚本索引写法不完全一致，实际应以二进制中的加密循环为准。
- **为什么可行**：VM 只是把 TEA 的加/异或/移位拆成 opcode，运算本身没有改变；识别出轮函数与参数后，逆向轮即可，不需要 Z3 或爆破。

## 触发条件

- 目标为 VM/字节码解释器，opcode 覆盖算术、逻辑、移位、内存读写与轮计数；存在成对的 32 位字与 4 个 key、delta/轮数常量。
- 加密数据在文件/数据段中；外层可能是加密的 PE/DLL，需先解密或动态 dump。
- 能还原 opcode 语义（静态反编译 switch 或动态 trace），并识别 TEA 的 `sum += delta` 与移位/xor 结构。
- 已知或可推导 delta、轮数、key、字节序（示例小端）。

## 利用步骤

1. 若外层是加密文件：用已知 PE/DLL 头与链式 XOR 公式恢复 key，解出 DllMain.dll；或直接在内存中 dump 解密后的模块。
2. 在 DllMain 中定位 VM 解释器；dump 字节码数组；按 `switch` 把 opcode 映射为 add/xor/lshift/rshift/copy/sub/mul/div/load/check。
3. 用 C/Python 复刻 VM 循环，逐条打印操作（如 `a[i]+a[j]`、`a[i]<<n`、`a[i]^a[j]`），把字节码还原成高级伪代码。
4. 识别 TEA：`sum += delta`、两半交替、移位 3/4/5/6、与 key/sum 的异或相加、轮计数 36；提取 delta、keys、密文块。
5. 写逆向轮：`sum = delta * rounds`，每轮先逆 v1 再逆 v0，`sum -= delta`；对每组 32 位字按小端输出。
6. 用正向 TEA 重新加密 flag，确认与密文一致；若不一致，检查移位方向、轮数、key 顺序与字节序。

## PoC

TEA 逆向轮（文章示例参数；输出即 flag）：

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t v[10] = {
        0x0D9D29102, 0x0DC34518C, 0xc3e171aa, 0x665d20e0, 0x926a7765,
        0x139332ee, 0xf00faf61, 0x16b72b82, 0x529fe600, 0x2ba3db0c
    };
    uint32_t k0 = 0x1234567, k1 = 0x89ABCDEF, k2 = 0xFEDCBA98, k3 = 0x76543210;
    uint32_t delta = 0x1919810;

    for (int m = 0; m < 10; m += 2) {
        uint32_t sum = delta * 36;
        for (int i = 0; i < 36; i++) {
            v[m + 1] -= ((v[m] << 5) + k2) ^ (v[m] + sum) ^ ((v[m] >> 6) + k3);
            v[m]     -= ((v[m + 1] << 3) + k0) ^ (v[m + 1] + sum) ^ ((v[m + 1] >> 4) + k1);
            sum -= delta;
        }
    }
    for (int i = 0; i < 10; i++)
        for (int m = 0; m < 4; m++)
            putchar((v[i] >> (8 * m)) & 0xff);
    // flag{Be@ut1fuL-Ex2cpti0n-Vi3tual-F10wer}
    return 0;
}
```

VM opcode 还原示意（按 `switch` 翻译字节码，实际索引/长度按目标）：

```text
0  add(a[x], a[y])      1  xor(a[x], a[y])     2  a[x] <<= y
3  a[x] >>= y           5  a[x] = a[y]         6  a[x] -= a[y]
7  a[x] *= a[y]         8  a[x] /= a[y]        9  load input/key
11 round++ / compare
```

外层链式 XOR 解密原则（文章脚本示例，索引/密钥需按二进制核对）：

```python
data = bytearray(open('encrypt', 'rb').read())
key = list(b'gaLf_ek@f_AsI_s1hT{galf}')   # 由已知 PE 头反推
for i in range(len(data) - 1):
    data[i + 1] ^= data[i] ^ key[i % len(key)] ^ 0x66
open('DllMain.dll', 'wb').write(data)
```

`encrypt` 的加密循环实际为 `Buffer[i+1] ^= key[(Size-2-i)%a2] ^ Buffer[i] ^ 0x66`；文章的解密索引写法与加密不完全对称，必须以目标二进制/调试结果为准。

## 变体与关联

- **标准/其他 TEA 变体**：标准 TEA delta `0x9E3779B9`、32 轮、移位 4/5；XTEA 使用不同的轮 key 调度；XXTEA 按块长循环。识别时以 `sum += delta`、两半交替、移位/xor 结构为准，不要只认常量。
- **VM 语义还原**：若 opcode 较多/有自修改，参考 [[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]；若不想还原，可用 [[ctf-reverse-vm-instrumentation-instruction-count-bruteforce]] 的侧信道爆破（仅适用于逐字节校验）。
- **TEA 相关卡**：[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（虚表 + 魔改 TEA 掩码）、[[ctf-crypto-self-referential-key-tea-variant]]（自参考密钥 TEA）。
- **外层文件解密**：已知 PE/PNG 头恢复密钥的通用思路见 [[ctf-reverse-go-pic-rc4-short-key-png-header-bruteforce]]；本卡是链式 XOR + DLL 头的变体。
- 边界：外层 XOR 索引可能随文件大小变化；VM 可能对 key 做二次变换；字节序可能是大端；需用正向加密闭环验证。

## 检测与防御

- 对题目设计：VM/TEA 只是混淆，不构成密码学安全；若需保护 flag，使用标准密码学与外部密钥，并做完整性校验。
- 对分析者：优先识别 TEA 常量/轮结构，再决定逆向轮还是符号执行；外层文件加密先用已知头恢复 key。
- 检测思路：二进制中出现 `delta` 常量、移位 3/4/5/6 与 xor/add 组合、VM 分发器与 4 个 key 的加载；文件头与密文不符（MZ/PE 缺失）提示外层加密。
