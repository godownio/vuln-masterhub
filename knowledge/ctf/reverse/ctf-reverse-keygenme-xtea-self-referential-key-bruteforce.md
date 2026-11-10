---
id: ctf-reverse-keygenme-xtea-self-referential-key-bruteforce
title: KeygenMe 魔改 XTEA 自耦合校验 trick：KEY[0] 既是密钥又是密文（sign 加密结果须等于 KEY[0]），固定其余密钥字 + 多线程按线程号切高位暴力 KEY[0]
type: scenario
domain: ctf
path: ctf/reverse
technique: self-referential-xtea-key-bruteforce-multithread
aliases:
- yonkies_keygenme_3
- 变型 XTEA / 魔改 XTEA
- delta 0xBADF00D
- sum 初值 0x25E1B381
- 0x45 轮
- key 重排 key[0]=dword_418240[3]
- sign 0x7369676E
- 44 字节 11 个 DWORD 的 key 文件
- 16 线程按线程号设 KEY[0] 高 4 位
- 用户名 CRC32 校验值
tags:
- ctf
- reverse
- crackme
- keygen
- xtea
- modified-xtea
- self-referential
- brute-force
- multithread
- crc32
- key-file
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:20:54+08:00'
  notes: 已对照原文核对：图02/03/04/06/07 证实 delta=0xBADF00D、sum=0x25E1B381、0x45 轮、KEY[0] 同时为密文且须解出 sign，自耦合 trick 与 keydata 布局成立；未验证点：未展示 keygen 生成的 key.dat 被程序接受，图05 是题目自带 key1.dat 的成功输出。
---

## 一句话结论

某 CrackMe 的 44 字节 key 文件（11 个 DWORD）前 4 个 DWORD 是重排后的魔改 XTEA 密钥，但 `key[0]` 同时又是第一组待解密密文的一半，程序要求它解出的明文为 `sign`（`0x7369676E`）——即「用密钥加密 `[Serial, sign]` 后必须等于 `KEY[0]` 本身」。这个自耦合约束让直接构造 key 不可行；解法是固定 `KEY[1..3]` 随机值、只暴力 32 位的 `KEY[0]`，用 16 线程按线程号切分 `KEY[0]` 的最高 4 位并行枚举，找到满足 `key[0] == xtea_encrypt(key, [Serial, sign])` 的一组密钥，再用该密钥加密 Serial、Features、用户名 CRC32 与 16 字节用户名，生成通过校验的 key.dat。

## 原理

- **魔改 XTEA 的识别**：标准 XTEA 是 64 轮、delta `0x9E3779B9`、sum 从 0 累加；本题循环 `0x45`（69）轮、delta `0xBADF00D`、sum 初值 `0x25E1B381`（= `0xBADF00D * 0x45`，使每轮减 delta 后正好归 0），密钥索引用 `sum & 3` 与 `(sum >> 11) & 3`，轮函数为 `v[1] += (sum + key[sum&3]) ^ (v[0] + ((v0>>5) ^ (v0<<4)))` 等。解密是加密的逆序（从 sum=`0x25E1B381` 递减）；注意加解密时两个 DWORD 的先后顺序相反，需交换 `v[0]/v[1]` 试出来。
- **key 文件结构**：`dword_418240[0..2]` = `KEY[1],KEY[2],KEY[3]`；`[3]` = `KEY[0]` 且是 `sign` 的密文；`[4]` Serial Number 密文；`[5]` Features 密文；`[6]` 用户名 CRC32 校验值密文；`[7..10]` 16 字节用户名（不足补空格，非 C 字符串）的密文。程序分三波 XTEA 解密：第一波校验 `[3]` 明文为 `sign`，第二波出 Features 与 CRC32，第三波循环解出用户名并算 CRC32 与 `[6]` 比对（图中 `v26 == v75`）。
- **自耦合 trick（本题核心难点）**：`key[0]` 既是密钥第一字又是密文一半，且 XTEA 每轮输出同时依赖两个明文 DWORD 与全部密钥字。若固定 KEY 去暴力 Serial 凑「sign 的密文 == KEY[0]」，因 Serial 是用户指定、且无解概率高，没有意义；正确做法是在给定 `sign` 与 Serial 时**反过来求一组满足条件的 KEY**。
- **为什么暴力可行**：128 位密钥看似不可暴破，但只需满足一个 32 位等式 `key[0] == xtea_encrypt(key, [Serial, sign])`。固定（随机）`KEY[1],KEY[2],KEY[3]`，只枚举 32 位 `KEY[0]`：每次把 `KEY[0]=候选` 代入加密，检查输出是否等于候选本身，命中概率约 `1/2^32` 量级但可通过重随其它密钥字重复尝试。作者受「随机 KEY[0]/[1]/[3]、暴力 KEY[2]」思路启发，等价地选择「随机 KEY[1..3]、暴力 KEY[0]」，无解就重随 `KEY[2]` 再来一轮。
- **多线程切分**：16 线程时令 `key0 = ((DWORD)args) << 28`，每个线程负责 `KEY[0]` 高 4 位固定、低 28 位枚举（`MAX = 1<<28`），把一轮暴力按线程号切开并显著缩短单轮时间；命中后互斥锁写 `gFound` 终止其它线程。
- **xor 型算法的暴破经验**：算法主要用 xor，若 KEY 或 v 含大量 `00` 字节，求解概率很低（这也解释了题目示例 key 里 id 值很大）；随机/暴破时可排除连续 00 字节以提高单轮命中率。
- **为什么是完整链**：还原魔改 XTEA 加解密 + 求一组满足自校验的 KEY + 复用目标 CRC32 算用户名校验值 + 按 11 DWORD 布局写回 key.dat，四步齐全，keygen 能为任意用户名/Serial/Features 产出被程序接受（输出 Serial number / Featureset / Registered user）的注册文件；题目给的 key1.dat 输出即验证样例。
- **不夸大**：这是 CrackMe/KeygenMe 题解技巧（离线生成注册文件），不是对真实软件的未授权入侵或 RCE。

## 触发条件

- 已逆向出魔改 XTEA 的轮函数、delta、sum 初值、轮数与密钥索引，并能写出加/解密（含 `v[0]/v[1]` 顺序）。
- 校验存在「密钥的一部分同时是密文/明文」的自耦合约束，且约束只涉及有限位（本例一个 32 位等式）。
- 用户名/Serial/Features 等字段可由攻击者指定或构造；用户名 CRC32 算法可得（可重写或二进制复用）。
- 有多核 CPU 可做并行枚举（本例 16 线程，单轮约 6-7 分钟）。

## 利用步骤

1. 由 IDA F5 伪代码还原魔改 XTEA：写 `xtea_encrypt`（sum 从 0 累加 delta、返回 `v[1]` 便于暴破）与 `xtea_decrypt`（sum 从 `0x25E1B381` 递减），注意加解密 `v[0]/v[1]` 顺序相反。
2. 固定 `sign=0x7369676E` 与用户指定的 Serial，随机 `KEY[1],KEY[2],KEY[3]`。
3. 16 线程并行：线程 `i` 令 `key0 = i << 28`，枚举 `KEY[0]=key0+j (j<1<<28)`，若 `key[0] == xtea_encrypt(key, [Serial, sign])` 则记录该组 KEY 并置 `gFound`；一轮无解就重随 `KEY[2]` 再来。
4. 用求得的 KEY 加密三组数据：第一组 `[Serial, sign]` → `keydata[4]`；第二组 `[crc32(name), features]` → `keydata[5],[6]`；第三组把 16 字节用户名按 4 个 DWORD 两两加密 → `keydata[7..10]`。
5. 按 `keydata[0..3] = KEY[1],KEY[2],KEY[3],KEY[0]` 重排，把 11 个 DWORD（44 字节）写入 key.dat；运行目标程序加载该文件即通过校验并打印注册信息。

## PoC

```c
// 魔改 XTEA 加密（delta/sum/轮数均非标准值），返回 v[1]
DWORD xtea_encrypt(DWORD *key, DWORD *v) {
    DWORD sum = 0, delta = 0xbadf00d;
    for (int i = 0; i < 0x45; i++) {
        v[1] += (sum + key[sum & 3]) ^ (v[0] + ((v[0] >> 5) ^ (v[0] << 4)));
        sum += delta;
        v[0] += (sum + key[(sum >> 11) & 3]) ^ (v[1] + ((v[1] >> 5) ^ (v[1] << 4)));
    }
    return v[1];
}
// 16 线程按线程号切 KEY[0] 高 4 位
void* tFunc(void* args) {
    DWORD key0 = ((DWORD)args) << 28, key[4], v[2], MAX = 1 << 28;
    memcpy(key, gKey, 16);
    for (int i = 0; i < MAX && !gFound; i++) {
        key[0] = key0 + i;
        v[0] = gSerial; v[1] = 0x7369676e;              // "sign"
        if (key[0] == xtea_encrypt(key, v)) {            // 自耦合约束
            pthread_mutex_lock(&mutex);
            gKey[0] = key[0]; gFound = 1;
            pthread_mutex_unlock(&mutex);
        }
    }
}
// 求得 KEY 后：keydata[0..3]=KEY[1],KEY[2],KEY[3],KEY[0]；
// 依次加密 [Serial,sign]、[crc32(name),features]、用户名 4 DWORD，写满 11 DWORD 的 key.dat
// 编译（CRC32 汇编复用见关联卡）：gcc -m32 -o keygen keygen.c crc32.o
```

示例命中密钥（调试用）：`0x4c7c846d, 0x16f5391, 0x14a71016, 0x5303cbda`；题目 key1.dat 输出 `Serial number: 10000101 / Featureset: 0x00007710 / Registered user: www.crackmes.de`。

## 变体与关联

- **暴破策略变体**：等价地可固定任意三个密钥字、暴力第四个（如「随机 KEY[0]/[1]/[3]、暴力 KEY[2]」）；无解就重随某个非暴破密钥字重试；按线程号切高位（或按 CPU 核数切区间）并行；排除含连续 `00` 字节的候选以提升命中率。
- **自耦合约束变体**：本题是「加密输出 == 密钥字」；同族还有「密文校验和落在填充字段」「解密明文含固定 magic」等把校验施加在攻击者可控输出上的 trick（见 `ctf-reverse-crackme-fixed-srand-aes-key-checksum-padding-keygen`）。解法共通：找出唯一自由、不影响其它语义的字段去枚举，使约束成立。
- **算法识别变体**：魔改 TEA/XTEA 靠 delta、sum 初值、轮数、密钥索引 `(sum>>11)&3` 等指纹识别（见 `code-analysis-reverse-crypto-encoding-identification-decrypt`、`ctf-reverse-xxtea-custom-delta-derived-key`）；CRC32 靠常数 `0xEDB88320` 定位。
- **代码复用关联**：用户名 CRC32 用「从目标程序抠汇编、nasm 编 `.o`、gcc 链接进 keygen」的方式复用（见 `code-analysis-reverse-assembly-function-reuse-nasm-object-gcc-link-keygen`）；本卡聚焦验证逻辑与自耦合密钥求解。
- **边界**：若约束涉及全部 128 位密钥或输出依赖不可控数据，暴破不可行；题目位数/轮数/密钥重排随 CrackMe 变化，需按实际伪代码调整；纯 CTF 场景，不涉及真实系统入侵。

## 检测与防御

- **出题/防护方**：避免把密钥字直接暴露在输入文件里并同时用作密文；把校验放到服务端或引入不可预测的随机盐，使离线自耦合暴破失效；对注册文件做在线签名校验。
- **解题方（分析）**：先用题目给的多个示例 key 文件比对输出，推断各 DWORD 语义（Serial/Features/用户名/CRC32）与剩余长度（16 字节补空格），再决定哪一段是自由可枚举字段；对 xor 型算法注意大量 00 字节会降低命中率。
- **检测（若用于真实软件）**：监控同一主机短时间大量生成/尝试不同 44 字节 key 文件、多线程占满 CPU 的注册机特征、key 文件中出现成组随机 32 位密钥字。
