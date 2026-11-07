---
id: ctf-reverse-apk-jni-username-xtea-hex-sse-compare
title: Android JNI 登录校验逆向：用户名派生 XTEA key + hex 编码 + SSE 常量比较（getFlag 直读捷径）
type: scenario
domain: ctf
path: ctf/reverse
technique: jni-username-xtea-hex-sse-compare
aliases:
- FlagVault
- JNI verifyLogin
- 用户名派生 XTEA key
- XTEA 16 轮
- std::hex 密文比较
- SSE ptest 比较
- getFlag XOR 0x7
tags:
- ctf
- reverse
- apk
- android
- jni
- xtea
- native
- sse
- hex
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:14:41+08:00'
  notes: 已对照原文与图02（雷电模拟器登录成功弹窗 flag{alg0rithm_mast3r_2026}）核对：JNI 导出名、GetStringUTFChars +1352/ReleaseStringUTFChars +1360、用户名 admin 零填充为 16 字节 key（k0=0x696d6461/k1=0x0000006e）、XTEA 16 轮轮函数与 delta、hex 目标串 ef639eee55113f2549554199fff1d33f、SSE xor+or+ptest、getFlag 字符串 XOR 0x7 均与原文一致；逆出密码 r3vers3_m4st3r 与原文一致。PoC 未在本机复跑；原文未标注组件版本。
---

## 一句话结论

Java 层只做 UI 与 JNI 桥接，`verifyLogin` 在 native 层把用户名零填充成 16 字节作为 XTEA 密钥，对按 8 字节对齐并补零的密码做 16 轮加密，再把密文格式化成 32 位小写 hex，用 SSE `xor+or+ptest` 与两段 16 字节常量比较；正确用户名是 `admin`，逆 XTEA 即得密码 `r3vers3_m4st3r`。若只求 flag，可直接读 `getFlag` 中 XOR `0x7` 的字符串。

## 原理

- **JNI 桥接**：导出名 `Java_com_example_re_1flagvault_MainActivity_verifyLogin` 说明未动态注册；反编译里的 `+1352` 虚表调用是 `GetStringUTFChars`，`+1360` 是 `ReleaseStringUTFChars`，把这两个偏移认出来后函数骨架就清晰了。
- **用户名派生密钥**：`v45 = 0; memcpy(&v45, user, min(strlen(user),16))`，用户名不足 16 字节补零；`admin` 展开为 `61 64 6d 69 6e 00...`，按小端拆成 `k0=0x696d6461`、`k1=0x0000006e`、`k2=k3=0`。
- **XTEA 风格加密**：密码复制到 `(len+7)&~7` 的零填充缓冲区，每 8 字节取两个 uint32；16 轮中 `v0 += ((k0 + (v1<<4)) ^ (v1+sum) ^ (k1 + (v1>>5)))`、`v1 += ((k2 + (v0<<4)) ^ (sum+v0) ^ (k3 + (v0>>5)))`，`sum` 初值 `0x9E3779B9`，每轮递减 `0x61C88647`（即 `-0x9E3779B9`）。
- **hex 编码**：`std::hex + setfill('0') + setw(2)` 把每个密文字节输出为两位小写 hex；16 字节密文对应 32 字符，因此明文密码对齐后必须是 16 字节（`r3vers3_m4st3r` 正好 14 字符 + 2 个零填充）。
- **SSE 比较**：把 32 字符 hex 当成两个 16 字节向量，分别与 `xmmword_41D20`（`ef639eee55113f25`）和 `xmmword_41CD0`（`49554199fff1d33f`）异或，两个结果 OR 后 `_mm_testz_si128` 判断是否全零；等价于 `memcmp(hex, "ef639eee55113f2549554199fff1d33f", 32) == 0`，不依赖 `\0` 截断。
- **getFlag 捷径**：`strcpy(v4, "akf`|fk`7unsojXjfts4uX5751z")` 后逐字符 XOR `0x7`，直接还原 `flag{alg0rithm_mast3r_2026}`；赛场上可跳过登录逻辑。

## 触发条件

- APK 的 Java 层只有 `native verifyLogin`/`native getFlag` 等少量 JNI 方法，核心逻辑在 `.so`。
- native 中出现 TEA 家族常量（`0x9E3779B9`/`-1640531527`）、`<<4`/`>>5` 轮函数、8 字节分组。
- 密文以 hex 字符串常量或 SSE 常量对形式出现。
- 存在一个独立的 `getFlag`/`showFlag` 导出函数，可能是最短路径。

## 利用步骤

1. jadx 反编译 APK，确认 `MainActivity` 只调用 `verifyLogin` 与 `getFlag`，加载 `libre_flagvault.so`。
2. 在 IDA/Ghidra 中定位 `Java_..._verifyLogin`，识别 `GetStringUTFChars`/`ReleaseStringUTFChars` 偏移，剥离 JNI 噪音。
3. 读用户名派生密钥逻辑，确认 `strcmp(user,"admin")==0`；按小端拆出 4 个 uint32 key。
4. 识别 XTEA 轮函数与轮数 16，取目标 hex 常量（可能拆成两个 16 字节 SSE 常量，按内存序拼接）。
5. 按 8 字节分组逆 XTEA：`sum = delta*16`，每轮先逆 `v1` 再逆 `v0`，`sum -= delta`；拼接并去掉尾部 `\0`。
6. 若只想拿 flag，直接定位 `getFlag`，提取其中的字符串并按相同 XOR 还原；两条路径互相验证。

## PoC

```python
import struct

hexs = "ef639eee55113f2549554199fff1d33f"
ct = bytes.fromhex(hexs)
key = b"admin" + b"\x00" * 11
k0, k1, k2, k3 = struct.unpack("<4I", key)

DELTA = 0x9E3779B9
SUM = (DELTA * 16) & 0xFFFFFFFF
pt = bytearray()
for off in range(0, len(ct), 8):
    v0, v1 = struct.unpack("<2I", ct[off:off+8])
    s = SUM
    for _ in range(16):
        v1 = (v1 - ((k2 + ((v0 << 4) & 0xFFFFFFFF)) ^ ((s + v0) & 0xFFFFFFFF) ^ (k3 + (v0 >> 5)))) & 0xFFFFFFFF
        v0 = (v0 - ((k0 + ((v1 << 4) & 0xFFFFFFFF)) ^ ((v1 + s) & 0xFFFFFFFF) ^ (k1 + (v1 >> 5)))) & 0xFFFFFFFF
        s = (s - DELTA) & 0xFFFFFFFF
    pt += struct.pack("<2I", v0, v1)

print(pt.rstrip(b"\x00"))  # b'r3vers3_m4st3r'

# getFlag 捷径
print("".join(chr(ord(c) ^ 7) for c in "akf`|fk`7unsojXjfts4uX5751z"))
```

## 变体与关联

- **算法变体**：TEA/XTEA/XXTEA 轮数与常量不同；key 可能来自用户名、包名、签名 SHA1；密文可能 hex/base64 或直接二进制比较。
- **比较变体**：SSE `ptest`、`memcmp`、`strcmp`、逐字节循环；常量可能拆成多段或运行时解密。
- **捷径变体**：`getFlag` 可能做 XOR/ROL/Base64/字符串反转；也可能被混淆或依赖登录状态。
- **关联卡片**：[[ctf-reverse-apk-native-tea-gf256-matrix-lcg]]（APK native TEA+GF(2^8)+LCG）、[[ctf-reverse-apk-chacha20-counter-one-native]]（APK native 流密码）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（JNI native 模拟执行）。
- **边界**：若 key 派生依赖运行时值或 native 做了反调试，需动态 dump；若 `getFlag` 也有状态校验，捷径可能不可用。

## 检测与防御

- **CTF 验证**：逆出的密码应满足 8 字节对齐长度、正向 XTEA 后 hex 等于目标常量；`getFlag` 的 XOR 结果应与登录后弹窗一致。
- **防御**：不要把 flag 生成与校验全部放客户端 native；关键校验放服务端；对 native 做混淆/加固并移除明显的 `getFlag` 捷径；避免用户名直接作为密钥材料。
- **检测信号**：APK 中 JNI 方法极少、`.so` 含 TEA 常量与 SSE 比较；存在可直接调用的 `getFlag` 导出函数。
