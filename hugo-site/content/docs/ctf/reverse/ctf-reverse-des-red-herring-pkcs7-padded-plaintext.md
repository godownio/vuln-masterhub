---
id: ctf-reverse-des-red-herring-pkcs7-padded-plaintext
title: DES-ECB 纯干扰：比较对象是 PKCS#7 填充后的明文 hex，不是密文
type: scenario
domain: ctf
path: ctf/reverse
technique: des-red-herring-pkcs7-padded-plaintext
tags:
- ctf
- reverse
- android
- apk
- des
- pkcs7
- red-herring
- dynamic-dex
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:53:00+08:00'
  notes: 已对照 CrackMe_2_2 原文与图片核对：动态加载 classes3.dex、PKCS#7(块8)、DES-ECB key 12345678、bytesToHex 实参为填充明文 ptr、目标 hex 与解出 flag{HNCTF62RDYNTFMZ1TF} 均一致；PoC 未本机执行
url: /docs/ctf/reverse/ctf-reverse-des-red-herring-pkcs7-padded-plaintext/
draft: false
kb_aliases:
- CrackMe_2_2
- DES-ECB 幌子
- PKCS#7 填充
- bytesToHex 明文
- 动态加载 dex
- classes3.dex
---

## 一句话结论

APK 的 `onCreate` 动态加载 `classes3.dex`，真正校验在 `com.cr.test.wide` 与 `libcrackme2.so` 的 `verifyFlag`。函数先做 PKCS#7 填充（块大小 8），再用硬编码 key `"12345678"` 做 DES-ECB 得到 `ptr_1`；但 `bytesToHex` 的实参是 `ptr`（填充后的明文）而不是 `ptr_1`（密文），且 `ptr_1` 计算后立即 `free`，从未参与比较。因此 DES 是纯干扰，真实判定是 `hex(PKCS7_pad(flag)) == 目标串`；直接 hex 解码再剥掉 PKCS#7 填充即可。

## 原理

- **动态 dex**：`MainActivity.b()` 反射调用 `PathClassLoader` 加载 `classes3.dex`（`com.cr.test.wide`），`verifyFlag` native 方法在 libcrackme2.so；静态看主 dex 的 `verifyFlag` 是未调用的干扰。
- **PKCS#7**：`sub_24440` 计算 `pad = 8 - len % 8`（1..8），`size = len + pad`，用 `pad` 值填满；当 `len` 是 8 的倍数时补一整块 8 个 `0x08`。
- **DES 干扰**：`des_ecb_encrypt(ptr, size, "12345678", ptr_1)` 确实执行，但随后 `bytesToHex(v10, ptr, size)` 的第二个参数是 `ptr`（填充明文），不是 `ptr_1`；`ptr_1` 在 `free` 后再无引用。
- **目标串**：`byte_58010` 在 `sub_23DF0`（`__cxa_atexit` 注册）中初始化为 `"666c61677b484e43544636325244594e54464d5a3154467d0808080808080808"`；hex 解码后直接是 `flag{HNCTF62RDYNTFMZ1TF}` + 8 个 `0x08` 填充。
- **为什么能直接解**：比较值就是填充后明文的 hex，DES 不参与；剥掉末尾 `pad` 个 `pad` 字节即可。

## 触发条件

- APK 使用动态 dex/反射加载，真实校验在 native 层。
- native 函数做了多种密码学操作，但比较对象/数据流与直觉不同（密文被丢弃或未参与）。
- 比较值是 hex 字符串，可直接解码验证是否为明文。
- 使用标准 PKCS#7 填充（块大小 8/16）。

## 利用步骤

1. 解压 APK，JEB 看 `MainActivity.b()` 动态加载的 `classes3.dex`，定位 `com.cr.test.wide` 与 native `verifyFlag`。
2. IDA 反编译 `verifyFlag`，确认 PKCS#7 -> DES-ECB -> `bytesToHex` 的实参；注意 `ptr_1` 是否被使用/释放。
3. 找到 `byte_58010` 的初始化函数（`__cxa_atexit` 注册），提取目标 hex。
4. `bytes.fromhex(target)`，读最后一个字节 `pad`，去掉末尾 `pad` 个字节，得到 flag。
5. 若目标不是明文，再考虑 DES 解密（key/nonce/模式按实际实现）。

## PoC

```python
h = "666c61677b484e43544636325244594e54464d5a3154467d0808080808080808"
b = bytes.fromhex(h)
pad = b[-1]
flag = b[:-pad]
print(flag.decode())   # flag{HNCTF62RDYNTFMZ1TF}
```

## 变体与关联

- 其他“幌子密码”：先加密再丢弃、比较明文哈希、只比较长度/前缀；关键是跟踪数据流，确认哪个变量进入比较。
- PKCS#7 可换成 ISO 7816-4、零填充、随机填充；剥填充前先验证 pad 值范围与一致性。
- 动态 dex 可换成插件化/热更新/DEX 加密；先找 ClassLoader 与真实入口。
- 关联：APK 动态加载、PKCS#7 填充、DES/AES 识别、干扰项分析卡。

## 检测与防御

- 不要把 flag 校验放在客户端；密码学操作要与比较对象一致，避免“算了不用”的无效逻辑。
- 对关键校验做完整性/混淆，但不要依赖干扰项作为安全边界。
- 检测：APK 中出现动态 dex 加载、硬编码 DES key、hex 目标串；native 函数中密码学结果未参与比较。
