---
id: ctf-reverse-tea-delta-gettickcount-fixed-value
title: 魔改 TEA 逆向：delta 取 GetTickCount 但环境固定为 0x68547369，按 48 轮逆推解密
type: scenario
domain: ctf
path: ctf/reverse
technique: tea-delta-gettickcount-fixed-decrypt
aliases:
- QRS
- 魔改 TEA
- GetTickCount delta
- TEA 解密
- 1750365033
- TEA 逆向
- mark2
tags:
- ctf
- reverse
- tea
- gettickcount
- delta
- custom-crypto
- rust
- decrypt
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:05+08:00'
  notes: 已对照原文与图13核对；48轮、key[(((sum+tick)>>9)&0xC)/4]索引已按原文修正并实测解出a4747f82be106d3f8c4d747c744d7ee5；domain修正为ctf；PoC未在靶场复跑
---

## 一句话结论

目标用 TEA 加密网页提交的 `input`，但把标准 TEA 的常数 delta `0x9E3779B9` 换成了运行时 `GetTickCount()`；调试发现该环境返回的 TickCount 固定为 `0x68547369`，因此可以按 48 轮、4 个 32 位密钥字、每轮 `v28 -= TickCount` 的逆运算，从硬编码的 8 个密文 dword 还原明文，得到 `NepCTF{...}`。识别点是 TEA 典型的 `(v<<4) ^ (v>>5)`、`v + key[...]`、`+delta` 结构与 32/48 轮循环。

## 原理

- **TEA 结构**：标准 TEA 每轮：
  ```c
  sum += delta;
  v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
  v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
  ```
  `delta = 0x9E3779B9`，常用 32 轮。原文的 `mark2` 把 `sum` 的累加改成 `v28 -= TickCount`（从 `TickCount * 48` 开始递减），每轮 `v28 -= TickCount`，轮数 48，密钥为 4 个 dword。
- **delta 来自 GetTickCount**：正常 `GetTickCount()` 随时间变化，攻击者无法预测；但原文调试发现该 Windows 环境的 `GetTickCount()` 在运行期间返回固定值 `0x68547369`（可能被 hook/沙箱/题目环境固定），因此 delta 可视为已知常数。
- **识别方法**：在 IDA 中看到 `(v24 << 4) ^ (v24 >> 5)`、`v28 + TickCount + key[...]`、循环 48 次、`v28 = TickCount * 48`，即可判定为 TEA 的变体；`GetTickCount` 调用点确认 delta 来源。
- **解密**：加密的最后一轮是 `v1 += f(v0, sum)`, `v0 += f(v1, sum - delta)`；解密从 `sum = delta * 48` 开始，每轮先 `v1 -= f(v0, sum)`，再 `v0 -= f(v1, sum - delta)`，`sum -= delta`，共 48 轮。原文的 `Dec` 函数：
  ```c
  v28 = TickCount * 48;
  do {
      v28 -= TickCount;
      v25 -= (v24 + ((16*v24) ^ (v24 >> 5))) ^ (v28 + TickCount + key[(((v28 + TickCount) >> 9) & 0xC) / 4]);
      v24 -= (v25 + ((16*v25) ^ (v25 >> 5))) ^ (key[v28 & 3] + v28);
  } while (--v26);
  ```
  注意下标/key 选择与原文加密代码一一对应；解密时按同样表达式逆序即可。
- **密文/密钥**：原文从 `xmm` 比较处提取 8 个 dword 密文（`0x083EA621, 0xC745973C, ...`），密钥为 `0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210`；每两个 dword 一组解密，输出 32 字节明文。
- **为什么可行**：TEA 是对合结构（加密/解密顺序对称），只要知道 delta、轮数、密钥和字节序，逆运算唯一；delta 虽来自运行时函数，但环境固定值使其可离线计算。

## 触发条件

- 目标使用 TEA/TEA-like 分组密码，delta 来自 `GetTickCount`/`time()` 等运行时函数，但实际环境返回固定/可预测值（题目环境、沙箱、hook）。
- 能通过调试/静态分析拿到密钥、轮数、密文和字节序；密钥通常硬编码为 4 个 dword。
- 加密与解密使用同一套运算（TEA 对合），或能根据加密代码写出逆运算。
- 密文是 8 字节分组的整数倍，且明文可打印（flag 格式）可验证结果。
- 若是真实环境且 delta 随机，需要额外泄露 delta 或改为爆破/已知明文攻击，本卡不适用。

## 利用步骤

1. 在 IDA 中定位输入处理函数，识别 `(x << 4) ^ (x >> 5)`、`+ key[...]`、`+ delta`、循环 32/48 次等 TEA 特征。
2. 找到 delta 来源（`GetTickCount`/`time`/全局变量），动态调试确认运行时值；原文为 `0x68547369`。
3. 提取 4 个 32 位密钥字、轮数（48）、密文 dword 序列与字节序（小端）。
4. 按加密的逆序写解密：`sum = delta * rounds`，每轮先逆 `v1` 再逆 `v0`，`sum -= delta`；注意 key 下标/移位与原文一致。
5. 解密后按小端拼接字节，检查 `NepCTF{...}` 格式；若乱码，检查字节序/轮数/key 顺序/delta 符号。
6. 用加密函数正向验证：对解密明文重新加密应得到原密文，确认逆运算正确。

## PoC

```c
#include <stdio.h>
#include <stdint.h>

void dec(uint32_t *v24, uint32_t *v25, uint32_t tick) {
    uint32_t key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    uint32_t sum = tick * 48;
    int rounds = 48;
    do {
        sum -= tick;
        *v25 -= (*v24 + ((16 * *v24) ^ (*v24 >> 5)))
              ^ (sum + tick + key[(((sum + tick) >> 9) & 0xC) / 4]);
        *v24 -= (*v25 + ((16 * *v25) ^ (*v25 >> 5)))
              ^ (key[sum & 3] + sum);
    } while (--rounds);
}

int main(void) {
    uint32_t enc[8] = {0x083EA621,0xC745973C,0xE3B77AE8,0xCDEE8146,
                       0x7DC86B96,0x6B8C9D3B,0x79B14342,0x2ECF0F0D};
    for (int s = 0; s < 4; s++) {
        uint32_t a = enc[2*s], b = enc[2*s+1];
        dec(&a, &b, 0x68547369);
        enc[2*s] = a; enc[2*s+1] = b;
    }
    printf("NepCTF{%.32s}\n", (char *)enc);
}
```

原文输出 `NepCTF{a4747f82be106d3f8c4d747c744d7ee5}`；本卡未复跑。

## 变体与关联

- **delta 变体**：`time(NULL)`、`rand()`、`QueryPerformanceCounter`、全局 seed；若可预测/固定，同样可解；若随机，需要泄露/爆破或已知明文。
- **轮数变体**：TEA 常用 32 轮，原文 48 轮；解密循环的 `sum = delta * rounds` 必须匹配。
- **XTEA/XXTEA**：结构不同（XTEA 有 `sum` 分段、XXTEA 有长度），不要套用 TEA 逆运算；先确认算法。
- **关联**：`[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]`（另一魔改 TEA）、`[[ctf-reverse-custom-vm-tea-like-30round-block-bruteforce]]`（TEA-like 30 轮）、`[[ctf-reverse-apk-native-tea-gf256-matrix-lcg]]`（TEA 与其他运算组合）。
- **识别提示**：TEA 的 `16*x` 就是 `x<<4`，`x>>5`，`sum` 每轮加/减 delta；只要看到这三个特征，优先怀疑 TEA 家族。

## 检测与防御

- **对逆向方**：先静态识别 TEA 特征，再动态确认 delta/轮数/密钥；用正向加密验证逆运算；注意字节序与有符号/无符号运算。
- **对防守方（软件保护）**：不要把 delta 固定为可预测值；使用标准库的成熟算法（AES/ChaCha20）并正确实现；对密钥做白盒/混淆时仍要保证算法语义；不要把关键密文/密钥硬编码在易提取的位置。
- **检测**：二进制中出现 TEA 常数/结构、`GetTickCount` 参与加密、硬编码 4 个 dword 密钥；动态调试时对加密函数下断观察输入输出。
