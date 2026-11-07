---
id: mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer
title: Android JNI 多层自定义加密逆向：运行时提取 XXTEA key + Block-TEA 变体 + AES S-box 8 轮白化
type: scenario
domain: mobile
path: mobile/android
technique: jni-xxtea-blocktea-aes-sbox-multilayer
aliases:
- libxxmobile01
- Block-TEA 变体
- AES S-box 8 轮
- secondEncrypt
- so 调试取 key
tags:
- mobile
- android
- jni
- reverse
- xxtea
- tea
- aes-sbox
- custom-cipher
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:28+08:00'
  notes: 已对照原文核对：libxxmobile01 JNI、libc_malloc dump 的 16 字节 XXTEA key(78 56 34 12...)、Block-TEA 变体 rounds=6+52/n 且 sum-=DELTA、secondEncrypt 8 轮 AES S-box/seed=0x89ABCDEF/白化 k=sbox32(rol32(seed,24))^0xF1BBCDC8、target 57898bb6... 与逆变换，与原文/截图一致。未验证点：未本机复跑 APK；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Java 层调用两个 native 函数：`firstEncrypt` 是 Block-TEA 变体，`secondEncrypt` 是 8 轮 AES-Sbox 自定义分组算法；XXTEA key 在 native 运行时才出现在 `libc_malloc`，用 IDA so 调试 dump 出 16 字节 key 后，按两套算法的逆变换即可从 target 还原 inner 和 flag。

## 原理

- `MainActivity` 加载 `libxxmobile01`，声明 native `firstEncrypt`/`secondEncrypt`；校验逻辑比较 `secondDecrypt(target)` 与 `firstEncrypt(inner)`，因此需要同时逆掉两层。
- **Block-TEA 变体**：`rounds = 6 + 52/n`，`DELTA = 0x9E3779B9`；本题加密每轮 `sum -= DELTA`，解密每轮 `sum += DELTA`（与常见 XXTEA 的加法方向相反，必须按样本实现）。
- **key 只在运行时可见**：静态字符串搜不到；在 so 下断点后 dump `[anon:libc_malloc]` 得到 16 字节：
  `78 56 34 12 F0 DE BC 9A A9 CB ED 0F 21 43 65 87`，
  按小端解释为 4 个 32-bit 字 `{0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321}`。
- **secondEncrypt**：4×32-bit 状态，8 轮；每字节用 AES S-box 做 `sub_bytes`（不是标准 AES 轮）；`seed=0x89ABCDEF`，轮常数 `t = rol32(seed, rotacc)`、`rotacc += 3 (mod 32)`；`sum -= DELTA`；扩散层用多组 `rol32` 与 XOR；末尾白化
  `k = sbox32(rol32(seed,24)) ^ 0xF1BBCDC8`，
  `out[i] = in[i] ^ rol32(k, {0,25,18,11})`。
- 全流程只有 XOR、ROL32、模 2^32 加法与可逆 S-box，所以逆运算存在：先撤销白化，倒序 8 轮（逆扩散 + `inv_sbox32`），再按 XXTEA 变体解密。
- 目标值 `57898bb607933b0d49ac35b2998d59c3` 是 `secondEncrypt` 的 16 字节输出；`second_decrypt` 后得到 32 个十六进制字符，按 8 位一组转 4 个 32-bit 字，再 XXTEA 解密即可得到 `inner`。

## 触发条件

- Android APK 使用 JNI 原生库做核心校验，Java 层只负责调用与比较。
- 密钥/IV 不是硬编码明文字符串，而是在 native 运行时构造或从堆内存读取；需要动态调试/内存 dump。
- 自定义算法由可逆的 XOR/ROL/ADD/S-box 组成，且能拿到目标密文或校验值。
- 有 IDA/Ghidra + 可调试的 so（或 Unicorn 模拟）。

## 利用步骤

1. jadx 查看 `MainActivity`，定位 JNI 方法与校验关系（`secondDecrypt(target)` vs `firstEncrypt(inner)`）。
2. IDA 打开 `libxxmobile01.so`，在 `firstEncrypt`/`secondEncrypt` 下断点，运行时 dump `[anon:libc_malloc]` 的 16 字节 key。
3. 按 Block-TEA 变体实现 `xxtea_decrypt_words`（注意 `sum += DELTA` 方向与 `rounds = 6 + 52/n`）。
4. 按 `secondEncrypt` 的 8 轮结构实现 `second_decrypt`：撤白化、倒序轮、逆扩散、`inv_sbox32`。
5. 对 target 先 `second_decrypt` 得到 H，再把 H 的 32 个 hex 字符转 4 个 32-bit 字，XXTEA 解密得到 `inner`。
6. 拼成 `ISCC{inner}`，用 Java 校验或直接提交。

## PoC

```python
KEY = [0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321]

def u32s_to_bytes_le(words):
    out = bytearray()
    for w in words:
        out += w.to_bytes(4, "little")
    return bytes(out)

target = "57898bb607933b0d49ac35b2998d59c3"
H = second_decrypt(target)                 # 逆 8 轮 AES-Sbox 算法，返回 32 hex
words = [int(H[i:i + 8], 16) for i in range(0, 32, 8)]
inner = u32s_to_bytes_le(xxtea_decrypt_words(words, KEY)).decode()
print("ISCC{" + inner + "}")
```

`second_decrypt` 的核心步骤：`k = sbox32(rol32(seed,24)) ^ 0xF1BBCDC8`；`v0 ^= k`、`v1 ^= rol32(k,25)`、`v2 ^= rol32(k,18)`、`v3 ^= rol32(k,11)`；随后 8 轮倒序执行 `diffusion_layer_inverse` 与 `inv_sbox32`。完整逆函数按原文 exp 截图实现，未在本机复跑原 APK。

## 变体与关联

- **标准 XXTEA/TEA**：本题把 `sum` 方向与轮数改掉，直接套标准库会失败；先动态确认加减方向。
- **AES S-box 复用**：只把 AES 的 S-box 当作混淆层，轮函数/扩散层完全自定义；不要按标准 AES 轮密钥恢复。
- **Android JNI 常量提取**：若 key 在 native 常量表而非堆，可用 Unicorn 模拟或 IDA 交叉引用提取；见 [[mobile-android-jni-native-unicorn-emulation-constant-extraction]]。
- **多层校验**：Java 层哈希/比较 + native 加密 + 资源文件 key 的组合很常见；逐层逆运算并保持字节序一致。

## 检测与防御

- 检测：APK 含 JNI 原生库、Java 层只做结果比较、字符串表中缺少关键 key、so 中出现 AES S-box/ROL 常量。
- 分析：动态调试优先于纯静态；先确认数据流（谁调用谁、输入输出编码）再实现逆算法。
- 防御（对恶意样本）：密钥在运行时生成并避免长期驻留内存；自定义算法不能替代标准密码学，仍需完整性校验与反调试。
