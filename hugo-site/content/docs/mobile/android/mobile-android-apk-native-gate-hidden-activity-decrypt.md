---
id: mobile-android-apk-native-gate-hidden-activity-decrypt
title: APK 长按隐藏 Activity + JNI 本地门校验与静态可逆解密
type: scenario
domain: mobile
path: mobile/android
technique: apk-native-gate-static-decrypt
tags:
- android
- apk
- jni
- native
- anti-debug
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:32:00+08:00'
  notes: 已对照原文核对：包名 com.ctf.artgallery、GalleryActivity 长按延迟 800ms 启动 CanvasActivity、g() 的 nativeLoaded/反调试/runtimeSignal/verifyGateNative/decryptFlagNative 流程、verifyGateNative 的 x^=0x6c8e9cf5+mix32==0xd15ea5ed、decryptFlagNative 不使用 signal、三段 11 字节交错/33 字节 perm/LCG 0x19660d/0x3c6ef35f/nibble sbox/ror8 与 flag VishwaCTF{secret_gallery_exposed} 均一致。未验证点：无 APK 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-apk-native-gate-hidden-activity-decrypt/
draft: false
kb_aliases:
- ArtGallery
- JNI 本地门
- 隐藏 Activity
- APK 静态解密 flag
- 反调试绕过
---

## 一句话结论

APK 的 flag 藏在一个需长按图片才进入的隐藏 `CanvasActivity` 里，界面逻辑用 JNI 做“签名派生 signal + mix32 门校验”和反调试，但 `decryptFlagNative` 实际不使用 signal；只要静态分析 `libartvault.so`，按 `.rodata` 的三段数据、置换表、LCG、nibble S-box 与循环右移逆序还原，即可直接解出 flag。

## 原理

- `GalleryActivity` 的长按事件延迟 800ms 启动 `CanvasActivity`，这是隐藏入口；正常流程不会到达。
- `CanvasActivity.g()` 检查 native 是否加载、`Debug.isDebuggerConnected()`/`waitingForDebugger()` 与计时反调试，然后计算 `runtimeSignal`（签名 SHA-256 前 4 字节 + 包名 hash + 常数异或/rotate），交给 `verifyGateNative(signal)` 与 `decryptFlagNative(signal)`。
- `verifyGateNative` 是本地门：`x ^= 0x6c8e9cf5; x = mix32(x); return x == 0xd15ea5ed;`，其中 `mix32` 为 murmur 风格混合。它只决定是否返回结果，不影响解密。
- `decryptFlagNative` 的参数 signal 未参与解密；算法完全静态：
  1. `.rodata` 三段 11 字节 `a/b/c` 按 `a[0],b[0],c[0],a[1],...` 交错成 33 字节；
  2. 33 字节置换表 `out[i]=tmp[perm[i]]`；
  3. LCG `state = state*0x19660d + 0x3c6ef35f mod 2^32`，`key = (state >> ((i&3)*8)) & 0xff`，再异或 `((i*31)+0x11)&0xff`；
  4. 16 字节 nibble S-box 对高低 4 位分别替换；
  5. 每字节按 `(i%5)+1` 循环右移。
- 因此不需要真机/原签名/过反调试；静态逆算法即可。

## 触发条件

- 拿到 APK，包含多个架构的 JNI so（如 `libartvault.so`）。
- 能反编译 DEX 找到隐藏 Activity 与 JNI 调用，能反汇编 so 提取 `.rodata` 常量。
- 解密算法是静态可逆的（不依赖运行时密钥/服务器）。

## 利用步骤

1. 解包 APK，查看 `AndroidManifest.xml` 与 Activity；在 `GalleryActivity` 找长按/延迟启动 `CanvasActivity` 的逻辑。
2. 反编译 `CanvasActivity.g()`，确认 native 门与 `decryptFlagNative`。
3. 用 Ghidra/IDA 分析 `x86_64/libartvault.so`，定位两个 JNI 函数与 `.rodata` 中的三段 11 字节、33 字节 perm、16 字节 sbox。
4. 按交错 → 置换 → LCG XOR → nibble S-box → ROR 的顺序实现解密。
5. 输出明文 flag。

## PoC

```python
def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xff)) & 0xff

a = bytes.fromhex("c1e81ff4ac02c6080f6135")
b = bytes.fromhex("999f79b553f3dedc237cf9")
c = bytes.fromhex("9a105eee235d979e4b1fb3")
perm = bytes.fromhex("201c1110080713010500040f12150e1d02160d031e061b090b19140c1f1a180a17")
sbox = bytes.fromhex("06040c050007020e010f030d080a090b")

tmp = bytearray(33)
for i in range(33):
    tmp[i] = (a, b, c)[i % 3][i // 3]

buf = bytes(tmp[p] for p in perm)
state = 0x7f4a7c15
out = bytearray(33)
for i in range(33):
    state = (state * 0x19660d + 0x3c6ef35f) & 0xffffffff
    key = ((state >> ((i & 3) * 8)) & 0xff) ^ (((i * 31) + 0x11) & 0xff)
    x = buf[i] ^ key
    x = (sbox[x >> 4] << 4) | sbox[x & 0xf]
    out[i] = ror8(x, (i % 5) + 1)
print(out.decode())
```

## 变体与关联

- 门校验可换成真实参与解密的 KDF；此时需要动态 hook 或复现签名派生。
- 反调试可用 Frida 绕过 `Debug.isDebuggerConnected`、替换返回值。
- 关联：[[mobile-android-apk-signature-sha1-xor-key-decrypt]]（签名派生密钥）、[[ctf-reverse-apk-chacha20-counter-one-native]]（APK native 解密）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（JNI 常量提取）。

## 检测与防御

- 不要只靠本地门/反调试保护敏感逻辑；密钥应由服务器下发或使用硬件密钥库。
- 对 so 做加固/混淆，移除明文常量表。
- 检测：APK 中存在隐藏 Activity、JNI 门校验与静态常量表；运行时无网络/签名依赖即可解密。
