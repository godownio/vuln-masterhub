---
id: ctf-reverse-sm4-srand-seed-key-schedule
title: 木马标准 SM4 密钥逆向：握手 4 字节种子经 glibc srand/rand 生成 128 位密钥
type: scenario
domain: ctf
path: ctf/reverse
technique: sm4-srand-seed-key-derivation
tags:
- reverse
- sm4
- prng
- srand
- malware
- key-schedule
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:22+08:00'
  notes: 已对照原文 sub_13B4/sub_15A9 反汇编与 seed/rand 输出核对；密钥 ac46... 与截图一致；PoC 未复跑。
url: /docs/ctf/reverse/ctf-reverse-sm4-srand-seed-key-schedule/
draft: false
kb_aliases:
- SM4 密钥逆向
- srand(seed) rand 密钥
- 木马 SM4 key schedule
- 882188358
- 握手种子派生密钥
- SnakeBackdoor-5
---

## 一句话结论

木马没有硬编码 SM4 密钥，而是从握手包读取 4 字节种子，经字节序转换后 `srand(seed)`，再用 4 次 `rand()` 生成 16 字节 128 位密钥，随后用 `sub_13B4`（SM4 密钥扩展，32 轮）和 `sub_15A9`（SM4 加密）处理命令；只要从流量中取出种子并用相同 libc 复现 `rand()`，就能算出密钥并解密 C2 指令。

## 原理

- **握手读种子**：`sub_18ED(fd, &v7, 4, 0, 0)` 读取 4 字节到 `v7`；随后 `seed = (v7 >> 8) & 0xFF00 | (v7 << 8) & 0xFF0000 | (v7 << 24) | HIBYTE(v7)`，即按字节序翻转（大端/小端转换）。
- **PRNG 生成密钥**：`srand(seed)`，循环 `for(i=0;i<=3;i++) v8[i] = rand();`，4 个 32 位随机数共 16 字节，作为 SM4 的 128 位初始密钥。
- **SM4 密钥扩展**：`sub_13B4(a1, a2, a3)` 中 `v5` 每次取 4 字节并按 `(b1<<8)|(b2<<16)|(b3<<24)|b4` 打包，异或常量 `dword_2120`；`a3==0` 时正向生成 32 轮密钥，`a3==1` 时反向生成解密轮密钥，每轮用 `sub_1311(v8^v7^v6^dword_2140[i])` 做 T 变换/S 盒查表。这与标准 SM4 的密钥扩展结构一致。
- **SM4 加密**：`sub_15A9(a1, a2, a3, a4)` 取 4 个 32 位字并 `_byteswap_ulong`，循环 32 轮 `v10 = v6 ^ sub_125E(v9^v8^v7^round_key[i])`，最后按大端输出 16 字节密文；`sub_125E` 是 SM4 的 T 变换（S 盒 + 线性变换）。
- **命令协议**：循环 `recv(fd, &v6, 4, 0)` 读 4 字节长度，字节序转换后检查 `v6 <= 0x1000 && (v6 & 0xF) == 0`，再按该长度读命令、用 SM4 解密并执行。长度必须 16 字节对齐，是 SM4 分组加密的特征。
- **为什么能恢复**：密钥空间不是随机的 128 位，而是由 4 字节种子（32 位）经确定性 `srand/rand` 派生，实际熵只有 32 位；种子又在握手包里明文传输。复现时必须使用与目标相同的 `rand()` 实现（glibc），否则随机序列不同。
- **流量中的种子**：原文握手包偏移 0 处为 `34 95 20 46`，长度字段 `00 00 00 10`；按公式得到 `seed = 0x34952046`，4 次 `rand()` 输出拼成 `ac46fb610b313b4f32fc642d8834b456`。

## 触发条件

- 恶意样本/CTF 题给出一个网络木马二进制，协议中先接收 4 字节种子，再调用 `srand`/`rand` 生成密钥。
- 二进制中存在 SM4 的常量（FK/CK/S 盒）、32 轮循环和 `_byteswap_ulong`/大端打包特征，或密钥扩展函数与加密函数成对出现。
- 有对应的 pcap/握手流量，能取出 4 字节种子。
- 运行环境与目标一致（glibc 版本），或能确认 `rand()` 算法；样本可能静态链接或使用自定义 PRNG。
- 命令长度 16 字节对齐、上限 0x1000，符合分组密码协议。

## 利用步骤

1. 在 IDA 中定位握手函数：找 `recv` 4 字节、字节序转换、`srand` 调用；记录种子到 `v8[0..3]` 的数据流。
2. 识别 SM4：搜索 `0x3A5C3A5C`?（不强制）或观察 32 轮循环、`_byteswap_ulong`、S 盒常量、`dword_2120`/`dword_2140` 轮常量；确认 `sub_13B4` 是密钥扩展、`sub_15A9` 是加密。
3. 从 pcap 中找到握手包，按偏移取 4 字节种子（注意大小端/字节序转换公式）。
4. 用 C 程序或 Python `ctypes` 调用 libc 的 `srand/rand`，生成 4 个 32 位值并按内存小端拼成 16 字节密钥。
5. 用标准 SM4（或复刻样本的 S 盒/轮常量）按密钥扩展生成轮密钥，解密密文命令；若样本是标准 SM4，可直接用 Python `gmssl`/`pycryptodome` 的 SM4。
6. 解密出的命令按时间排序，还原下载地址、解压密码、执行路径；用 `flag{}` 包裹密钥/结果提交（按题目要求）。

## PoC

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(void) {
    uint32_t v8[4];
    srand(0x34952046);              // 从握手包取得的种子
    for (int i = 0; i < 4; ++i)
        v8[i] = (uint32_t)rand();
    for (int i = 0; i < 16; ++i)
        printf("%02x", ((uint8_t *)v8)[i]);
    printf("\n");
    return 0;
}
```

输出（原文）：

```text
ac46fb610b313b4f32fc642d8834b456
```

用该 16 字节作为 SM4 密钥，按 `sub_13B4` 的轮密钥扩展和 `sub_15A9` 的解密流程处理命令密文。原文最终以 `flag{...}` 包裹该结果提交。

## 变体与关联

- 变体：种子可能来自时间戳、PID、固定常量或握手字段的 XOR/字节序变换；先逆向种子公式，再复现 PRNG。
- 变体：SM4 可能是标准实现，也可能是自定义 S 盒/轮数/常量；若标准库解密失败，按 `sub_1311`/`sub_125E` 的 S 盒和线性变换逐轮复刻。
- 变体：密钥可能只取 `rand()` 的低 16 字节、或与固定常量异或；按样本的数据流确认。
- 关联：[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（标准 SM4 常量识别）、[[ctf-reverse-custom-sm4-24round-native-so-decrypt]]（自定义 SM4 变体）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（时间种子 `rand()` 预测）。
- 边界：`rand()` 的实现依赖 libc；Windows CRT 与 glibc 序列不同，样本静态链接时要按其自带实现复现；若种子不是 4 字节或经过额外变换，按反汇编调整。

## 检测与防御

- **恶意样本分析**：关注 `srand`/`rand` 与网络接收缓冲区的数据流；若密钥由少量字节派生，视为可预测密钥。
- **协议设计**：不要用 `srand(seed)` + `rand()` 派生加密密钥；使用 CSPRNG（`/dev/urandom`、`getrandom`）生成 128 位密钥，并通过安全信道协商。
- **检测**：二进制中出现 `srand`/`rand` 紧邻 `recv`/密钥扩展；SM4 常量与网络协议同现；命令长度 16 字节对齐、上限固定。
- **响应**：提取种子和密钥，解密历史 C2 流量；轮换被样本接触过的凭据；排查下载的压缩包与解压密码。
