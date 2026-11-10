---
id: code-analysis-reverse-chacha20-binary-identification-features
title: 二进制中识别 ChaCha20：魔数常量、状态布局与 32 次 ARX 特征
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: chacha20-binary-identification
aliases:
- expand 32-byte k
- ChaCha20 逆向识别
- 32 次加异或循环移位
- quarter round 内联特征
tags:
- chacha20
- 流密码
- 逆向识别
- 魔数
- ARX
- quarterround
- rotl
- 常量
- ida
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:57:55+08:00'
  notes: 已对照原文核对；魔数 expand 32-byte k 与小端字 0x61707865/0x3320646e/0x79622d32/0x6b206574(原文 xmmword_2130=6B20657479622D323320646E61707865)、ctx+128 状态布局、position=64、编译器内联后10轮约32次 __ROL4__ 16/12/8/7、_mm_add_epi32 加回、counter 溢出 assert、64位counter高32位叠加nonce变体均与正文 Ginurx/chacha20-c 源码及 HTB 反编译代码一致；dedup_review对比crypto-encoding-identification-decrypt(仅列MD5/AES/DES/RC4/SM4等S盒与Feistel常量，未含无S盒ARX流密码)、apk-chacha20-counter-one-native/sparc-chacha8-fakeflag-xor/rust-chacha20poly1305-string-decrypt(绑定具体样本求flag或批量解密字符串)成立，本卡为通用系统ChaCha20专项识别清单不绑定题目不求flag，非同一利用链；confidence为high原文用反编译代码逐项对照验证；非DoS崩溃或仅资源耗尽、非未打通理论链；非组件漏洞省略affected_versions；未验证点：PoC为特征结构示意未运行目标样本，本篇0张图片无需逐图阅读
---

## 一句话结论

即使二进制被去符号、函数被编译器内联，仍可用一组固定特征判定其中实现了 ChaCha20 并定位密钥与加解密函数：16 字节魔数 `expand 32-byte k`、按"常量+key+counter+nonce"排布的 64 字节状态矩阵、每 64 字节重新生成密钥流的循环、10 次双轮内联后出现的 32 次"加法-异或-循环左移（常量 16/12/8/7）"、以及末尾把工作矩阵与原始状态相加。

## 原理

- ChaCha20 用 4x4 的 32 位字矩阵作状态：`state[0..3]` 是固定 ASCII 常量 `"expand 32-byte k"`，`state[4..11]` 是 32 字节密钥，`state[12..15]` 是计数器与 12 字节 nonce。这个 16 字节常量在任何标准实现里都相同，反编译后表现为一段固定的 128 位数据（小端下字节序列 `6B20657479622D323320646E61707865`），是最高辨识度的锚点。
- 初始化函数会先把这块常量写入结构体某偏移（示例为 `ctx+128`），随后按偏移连续填入 key、counter、nonce，并把 `position` 置为 64 以强制首次异或时先生成第一个密钥流块；看到"大量变量名+固定偏移赋值"通常就是该上下文结构体。
- 加密循环按字节异或，并用 `position<=63` 判断当前 64 字节密钥流块是否用完，用完则调用块函数重新生成。
- 块函数做 20 轮 Quarter Round（ARX：Add-Rotate-XOR），每轮 8 个 quarterround，每个 quarterround 含 4 次 `rotl32(...,16/12/8/7)`。开启优化后编译器把 8 个 quarterround 内联展开，10 次双轮循环里就集中出现 8*4=32 次 `__ROL4__`/`rotl` 与加法、异或组合——这是"函数被内联后"最醒目的特征。
- 20 轮结束后把混淆矩阵与原始 state 逐字相加（SSE 下呈 `_mm_add_epi32`），并对计数器溢出做 `assert`，随后 `position=0`、counter 自增。原文用 HTB 的 ELF 加密器反编译结果逐项对照了上述特征。

## 触发条件

- 逆向一个无符号/去符号的 ELF、APK native 库、PE 或固件，怀疑内部有自定义或标准对称加密。
- 需要定位加解密函数、判断算法族、提取硬编码 key/nonce 以还原被加密数据。
- 二进制未被加壳/字符串加密完全隐藏常量（若已隐藏需先脱壳或运行时 dump）。

## 利用步骤

1. 全局搜索 16 字节常量 `expand 32-byte k`（或其 4 个 32 位小端字 `0x61707865 0x3320646e 0x79622d32 0x6b206574`），定位初始化函数。
2. 从该常量所在偏移向下观察连续赋值：16 字节常量 → 32 字节 key → 4 字节 counter → 12 字节 nonce，确认 4x4 状态矩阵布局；把相关内存重命名为 `chacha20_context` 结构体辅助阅读。
3. 找到逐字节 `buf[i] ^= keystream[position]`、`position` 与 64 比较的循环，确认是流密码异或加密。
4. 在块生成分支里数 `__ROL4__` 常量（16/12/8/7）出现次数；若被内联为约 32 次且循环 10 轮，即可判定 ChaCha20 而非 Salsa20/其他 ARX 算法。
5. 从初始化函数参数/常量引用处提取 key 与 nonce（含 counter 初值），据此在本地复现密钥流、还原密文。
6. 注意变体：IETF 版 counter 32 位，某些实现把 64 位 counter 的高 32 位与 nonce 前 4 字节相加，属同一算法的实现差异。

## PoC

```text
# IDA/二进制中搜索的常量（ASCII 与小端 32 位字）
"expand 32-byte k"  ==  65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b
0x61707865 0x3320646e 0x79622d32 0x6b206574

# Quarter Round 的 ARX 特征（滚动常量 16/12/8/7）
x[a]+=x[b]; x[d]=rotl32(x[d]^x[a],16);
x[c]+=x[d]; x[b]=rotl32(x[b]^x[c],12);
x[a]+=x[b]; x[d]=rotl32(x[d]^x[a], 8);
x[c]+=x[d]; x[b]=rotl32(x[b]^x[c], 7);

# 判定要点：10 次双轮循环内联后约 32 次 rol + 结尾 state 相加 + position=64 判断
```

（以上为特征与结构示意，未执行任何目标样本或 PoC。）

## 变体与关联

- 变体：ChaCha8/ChaCha12 轮数不同（4/6 次双轮），但魔数、状态布局、Quarter Round 常量一致；Salsa20 常量为 `expand 32-byte k` 同源但轮函数不同。
- 变体：ChaCha20-Poly1305（如 Rust 恶意样本硬编码 32 字节 key 的字符串解密）、PE 加载器用 LCG 派生 ChaCha20 key/nonce 解密二阶段载荷，识别特征相同、key 来源不同。
- 变体：DJB 原版把 `state[12..13]` 都作计数器，IETF(RFC 8439) 版是 32 位 counter + 96 位 nonce；本文示例实现把 64 位 counter 高 32 位叠加到 nonce 前 4 字节，属非标准变体。
- 关联：识别出算法后可接"流密码异或可逆、相同 key/nonce 对密文再加密即解密""已知明文/固定 nonce 复用导致 keystream 泄露"等还原手法。
- 关联：与 RC4 类比——都是"由 key 生成 keystream 后逐字节异或"，但 RC4 有 256 字节 S 盒、ChaCha20 基于 ARX 置换，无 S 盒。

## 检测与防御

- 确认：识别后用 RFC 8439 标准测试向量在本地复算一段密钥流比对，避免把 Salsa20/魔改 ARX 误判为 ChaCha20；注意编译器内联、SIMD 展开会改变外观但保留常量与 rol 次数。
- 逆向侧：常量被拆分/加密时先脱壳或在运行时 dump 已解密的 state；结合动态调试在 `chacha20_xor` 处下断点直接拿 key/明文。
- 开发侧（增加识别成本）：不要硬编码 key，用白盒密码、常量拆分、控制流混淆隐藏魔数与轮常量；但这只是提高成本，不能替代密钥管理。
- 开发侧（真正安全）：nonce 每次加密唯一、禁止 key/nonce 复用、配合 Poly1305 等认证标签，避免仅靠"算法不公开"保护数据。
