---
id: ctf-reverse-ransomware-xor-crc32-mt19937-keystream
title: CTF 勒索软件逆向：XOR 字符串 + CRC32 种子 + MT19937 流 XOR 解密
type: scenario
domain: ctf
path: ctf/reverse
technique: ransomware-xor-crc32-mt19937-decrypt
tags:
- ctf
- reverse
- ransomware
- crc32
- mt19937
- xor
- file-decrypt
- static-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:59:45+08:00'
  notes: 已对照原文 ransomware 与 8 张图核对：byte_4061C0=92 9F 90 9F E9 90 9C 9A、byte_4061B4=6F 11 61 6F 63 10 6F 66 63，经 ^0xAA/^0x55 得 85:5C:60:D4:6E:36（zlib.crc32 复算=812059967）；文件时间 2026-08-30 10:58 UTC+8=1788058680，seed=1525977351；样本 twist 经 dword_40801C=dword_408020-1 别名后等价标准 MT19937(M=397)，1000 次预热后逐字节 XOR。核对中修正卡片 PoC：原稿直接以 mt[0..623] 为状态却沿用反编译的 396，实测会得到不同密钥流；已改为标准偏移 397 并在说明中解释 396 的来源，knowledge 与 staging 同步。未复跑完整文件解密（无 flag.encrypted 附件）；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-ransomware-xor-crc32-mt19937-keystream/
draft: false
kb_aliases:
- ransomware 逆向
- 勒索软件解密
- CRC32 种子
- 梅森旋转 XOR 流
- MT19937 逆向
- 时间戳种子恢复
- 异或加密文件还原
---

## 一句话结论

一个 CTF 勒索样本先用两段 XOR（`0xAA`/`0x55`）还原出种子字符串 `85:5C:60:D4:6E:36`，对该串做 CRC32 得到 `v17`，再把 `v17 ^ time(0)` 作为 MT19937 的种子、丢弃 1000 个输出后按字节 XOR 加密文件；从 `flag.encrypted` 的文件修改时间恢复 `time`，按同一流程重放即可解密出 flag。

## 原理

- 样本中 `Str` 的前 8 字节与后 9 字节分别由常量数组与 `0xAA`/`0x55` 异或得到，拼成 17 字节字符串 `85:5C:60:D4:6E:36`（看起来像 MAC/标识，实际只是 KDF 输入）。
- 对 `Str` 执行标准 CRC32：初值 `0xFFFFFFFF`，逐字节异或后按 8 位右移，多项式 `0xEDB88320`，最后取反，得到 `v17 = 812059967`。
- 种子为 `seed = v17 ^ time(0)`；`time(0)` 是加密发生时的 Unix 时间戳。样本用该种子初始化 MT19937 的 624 字状态数组，执行标准 twist 与 1000 次预热，然后每加密一个明文字节就取一个 MT19937 输出低 8 位做 XOR。
- 因此解密是对称的：只要恢复 `time(0)`，用同一种子重建 MT19937、跳过 1000 个输出，再对密文逐字节 XOR 即可。`time(0)` 可从 `flag.encrypted` 的文件修改时间、文件系统时间线或样本运行日志恢复。
- 三个易错点：
  1. 反编译中的 `dword_40801C` 与 `dword_408020` 是同一块内存的相邻视图（`dword_40801C = dword_408020 - 1`），不能当成两个独立数组，否则初始化循环读到全 0；
  2. MT19937 的 tempering 表达式有大量位运算，C 语言中优先级为 `& > ^ > |`，移植时需按原式补括号；
  3. `MessageBoxA` 等 Windows API 在 Linux/自建 C 环境不存在，改成 `printf`/空实现即可。

## 触发条件

- 拿到勒索样本与至少一个加密文件（案例为 `ransomware.exe` 与 `flag.encrypted`）。
- 能静态反编译/动态调试样本，定位字符串还原、CRC32、MT19937 初始化与 XOR 循环。
- 能恢复加密时刻的 Unix 时间戳（文件修改时间、时间线、日志等）；时间误差会直接导致解密失败。
- 样本无额外文件头/分块随机数；若每个文件使用不同时间或 nonce，需要按文件分别恢复。

## 利用步骤

1. 在样本中搜索字符串/常量，定位 XOR 还原逻辑；提取常量数组，按 `^0xAA`、`^0x55` 还原出种子字符串。
2. 识别 CRC32 循环（多项式 `0xEDB88320`、初值 `-1`、末尾取反），计算 `v17`。
3. 识别 MT19937 初始化：`state[0] = v17 ^ time`，之后 `state[i] = i + 1812433253 * (prev ^ (prev >> 30))`，共 624 项；确认 twist 与 1000 次预热。
4. 从 `flag.encrypted` 的修改时间恢复 `time`；案例文件时间为 `2026-08-30 10:58:00`（UTC+8），对应 Unix `1788058680`，`seed = 812059967 ^ 1788058680 = 1525977351`。
5. 用恢复的种子重建 MT19937，跳过 1000 个输出，对密文逐字节 XOR，写出明文。
6. 校验明文格式（flag/文件头），若失败则检查时区、文件时间精度（秒/毫秒）、预热次数与数组偏移。

## PoC

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t mt[624];
static int idx = 624;

static void mt_init(uint32_t seed) {
    mt[0] = seed;
    for (int i = 1; i < 624; i++)
        mt[i] = 1812433253u * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i;
    idx = 624;
}

static uint32_t mt_next(void) {
    if (idx >= 624) {
        for (int i = 0; i < 624; i++) {
            uint32_t y = (mt[i] & 0x80000000u) | (mt[(i + 1) % 624] & 0x7fffffffu);
            mt[i] = mt[(i + 397) % 624] ^ (y >> 1);
            if (y & 1) mt[i] ^= 0x9908b0dfu;
        }
        idx = 0;
    }
    uint32_t y = mt[idx++];
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= y >> 18;
    return y;
}

int main(void) {
    const uint32_t seed = 812059967u ^ 1788058680u; // CRC32 ^ time(0)
    FILE *f = fopen("flag.encrypted", "rb");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    unsigned char *buf = malloc(n);
    fread(buf, 1, n, f);
    fclose(f);

    mt_init(seed);
    for (int i = 0; i != 1000; ++i) mt_next();     // 样本的 1000 次预热
    for (long i = 0; i != n; ++i) buf[i] ^= (unsigned char)mt_next();
    fwrite(buf, 1, n, stdout);
    return 0;
}
```

```text
# 案例中的关键值
Str            = 85:5C:60:D4:6E:36
CRC32(Str)     = 812059967
time           = 1788058680  (2026-08-30 10:58:00 UTC+8)
seed           = 812059967 ^ 1788058680 = 1525977351
```

说明：以上为标准 MT19937 等价实现；样本把状态数组写成 `dword_40801C = dword_408020 - 1` 的相邻视图，反编译里的源偏移 396 是别名偏移导致的，直接以 `mt[0..623]` 为状态时应使用标准偏移 397（写回下标也随之后移一位），移植时需按原始写回顺序核对下标。原文已用该逻辑成功还原 flag。

## 变体与关联

- 变体：种子不来自时间，而来自文件大小、机器名、用户名、PID、`GetTickCount`、`QueryPerformanceCounter` 等；需从样本或环境恢复对应值。
- 变体：使用 CRC32 的其他变体（初值/异或值/反射不同）、Adler32、FNV、MD5/SHA256 截断作为 KDF；先识别常量与多项式。
- 变体：MT19937 之外还可能是 LCG、xorshift、RC4；按状态更新与输出函数识别。
- 变体：每个文件使用独立随机种子并写入文件头/nonce；此时需解析文件头或从内存/日志恢复。
- 关联：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（可逆变换求逆）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（常量识别）、[[defense-forensics-ransomware-entry-host-encrypted-last]]（勒索软件主机取证）。

## 检测与防御

- 防御：勒索软件防护应拦截异常文件批量加密、可疑 MT19937/XOR 循环与时间种子；保留文件修改时间/卷影副本有助于恢复时间戳。
- 检测：样本中出现 `IsDebuggerPresent`/VM 检测、CRC32 常量 `0xEDB88320`、`1812433253`（MT19937 乘数）、`0x9908B0DF`/`0x9D2C5680`/`0xEFC60000`（tempering 常量）等特征。
- 响应：隔离样本与加密文件，记录文件时间线；用恢复的时间戳重放解密流程，验证明文哈希后固定证据。
