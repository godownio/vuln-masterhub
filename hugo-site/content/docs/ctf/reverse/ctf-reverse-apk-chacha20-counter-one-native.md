---
id: ctf-reverse-apk-chacha20-counter-one-native
title: APK 原生 ChaCha20 校验：识别 expand 常量与 counter=1 后异或还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-native-chacha20-counter-one
tags:
- ctf
- reverse
- android
- apk
- jni
- chacha20
- stream-cipher
- native
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:52:57+08:00'
  notes: 已对照 CrackMe_1_3 原文与图片核对：JNI_OnLoad→RegisterNatives 三方法、c 为校验、expand 32-byte k、key/nonce 与 counter=1、hex 比较均吻合；PoC 中 target hex 用省略号截断（完整值需取自原文），PoC 未本机执行
url: /docs/ctf/reverse/ctf-reverse-apk-chacha20-counter-one-native/
draft: false
kb_aliases:
- CrackMe_1_3
- JNI_OnLoad RegisterNatives
- ChaCha20 魔数
- expand 32-byte k
- counter 从 1 开始
- 流密码自反
---

## 一句话结论

APK 的 Java 层只是壳，`JNI_OnLoad` 用 `RegisterNatives` 注册了 `NativeBridge.a/b/c`；签名 `(Ljava/lang/String;)Z` 的 `c` 是真正校验函数。它把输入字符串交给 `sub_257A0` 做标准 ChaCha20（RFC 8439）加密——状态常量 `expand 32-byte k`、32 字节 key、12 字节 nonce、20 轮、quarter-round 旋转 16/12/8/7，唯一非标是块计数器从 1 开始——再把密文转 hex 与 8 个目标串比较。由于 XOR 流密码自反，用同一 key/nonce/counter 对目标 hex 解密即得 flag。

## 原理

- **JNI 定位**：`JNI_OnLoad` 调用 `FindClass("com/cr/myapplication/NativeBridge")` 和 `RegisterNatives(..., off_57214, 3)`；`off_57214` 是 `JNINativeMethod[3]`，每项 `{name, signature, fnPtr}`：`a ([B)[B -> 0x25110`、`b ([B)[B -> 0x25250`、`c (Ljava/lang/String;)Z -> 0x25390`。`stringFromJNI` 只返回 `"Hello from C++"`，是干扰项。
- **校验流程**：`GetStringUTFChars` 取输入 -> `sub_257A0(obj, data, len)` 做 ChaCha20 变换 -> `sub_27590` 把字节转小写 hex -> 循环 8 次与 `std::array<std::string,8>`（`0x5A1CC`）比较，命中任一即返回 1。
- **ChaCha20 识别**：`sub_26D20` 把 `"expand 32-byte k"` 拷进 state[0..3]，key 放 state[4..11]，counter 放 state[12]，nonce 放 state[13..15]；10 次双轮（列轮 + 对角轮），quarter-round 旋转 16/12/8/7，最后 state + 初始 state；字读写为小端。这就是标准 ChaCha20，唯一非标是计数器初值 1。
- **解密**：`hex(ChaCha20_XOR(flag)) == target_hex`，XOR 流密码满足 `C = P ^ KS`、`P = C ^ KS`；用相同 key/nonce、counter=1 重新生成 keystream，与 `bytes.fromhex(target_hex)` 异或即可。
- **为什么成立**：key/nonce 硬编码在 so 的 `.data`（`unk_F345`/`unk_F365`），可从 IDA 直接提取；计数器偏移不影响识别，只要复现初值。

## 触发条件

- APK 的 Java 层没有实质校验，`JNI_OnLoad` 通过 `RegisterNatives` 动态注册 native 方法。
- native 校验把输入经过流密码后与固定 hex 比较，key/nonce 硬编码在二进制中。
- 算法为标准/可识别流密码（ChaCha20/Salsa20/RC4/AES-CTR），且加密自反或可逆。
- 目标串数量任意（本例 8 个，命中任一即可）。

## 利用步骤

1. 解压 APK，提取 `lib/*/libmyapplication.so`，在 IDA 中看 `JNI_OnLoad` 与 `JNINativeMethod` 表，确定校验函数。
2. 反编译校验函数：确认输入 -> `sub_257A0` -> hex -> 与目标数组比较。
3. 在 `sub_26D20` 中核对 `expand 32-byte k`、key/nonce 地址、counter 初值、20 轮与 QR 旋转量。
4. 从 `.data` 提取 32 字节 key 与 12 字节 nonce；从目标数组取一个 hex 串。
5. 用 ChaCha20（counter=1）对目标 hex 解密，得到 flag。

## PoC

```python
import struct

def rotl(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl(s[b], 7)

def block(key, counter, nonce):
    s = list(struct.unpack("<4I", b"expand 32-byte k"))
    s += list(struct.unpack("<8I", key))
    s += [counter]
    s += list(struct.unpack("<3I", nonce))
    w = list(s)
    for _ in range(10):
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + s[i]) & 0xffffffff for i in range(16)])

def chacha20(key, nonce, data, counter=1):
    out, ctr = bytearray(), counter
    for i in range(0, len(data), 64):
        ks = block(key, ctr, nonce); ctr += 1
        out += bytes(c ^ k for c, k in zip(data[i:i + 64], ks))
    return bytes(out)

key = bytes.fromhex("149263a16f2d89cbf0375b1ca94e78d3226017ee9abc4d0853e1762a8dc4903f")
nonce = bytes.fromhex("44332211abcdef668899aa55")
target = bytes.fromhex("d097c3f6d229da23ab72ad35ebe68198...")
print(chacha20(key, nonce, target, counter=1).decode())
```

## 变体与关联

- 其他流密码：Salsa20、RC4、AES-CTR、自定义 xor-rotate；先看常量/轮函数/状态布局识别。
- 计数器初值可换成 0/随机/从密文块读取；必须按二进制实际值复现。
- 若目标 hex 是密文但 key 也参与 KDF，先恢复 KDF；若算法被魔改（轮数/旋转量），按实际实现重写。
- 关联：APK JNI 逆向、ChaCha20 识别、流密码自反解密卡。

## 检测与防御

- 不要把 flag 校验完全放在客户端；关键逻辑放服务端或做白盒/混淆。
- 硬编码 key/nonce 可被静态提取；使用服务端密钥/设备绑定/完整性校验。
- 检测：APK 中出现 `expand 32-byte k`/ChaCha 轮常量、JNI RegisterNatives 动态注册、hex 目标数组。
