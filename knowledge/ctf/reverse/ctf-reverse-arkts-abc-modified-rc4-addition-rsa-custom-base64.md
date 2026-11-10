---
id: ctf-reverse-arkts-abc-modified-rc4-addition-rsa-custom-base64
title: ArkTS ABC 三步串联加密逆向：KSA 下标互换 + 加法替代异或的 RC4、单字节 RSA 与换表 Base64
type: scenario
domain: ctf
path: ctf/reverse
technique: arkts-modified-rc4-addition-rsa-custom-base64
aliases:
- HarmonyOS ArkTS 加密逆向
- OHCTF arkts 题解
- 魔改 RC4 加法
- 单字节 RSA n=75067
- 自定义 Base64 字母表
tags:
- ctf
- reverse
- harmonyos
- arkts
- abc
- rc4
- modified-crypto
- rsa
- base64
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-16
  verified_at: '2026-11-08T08:06:03+08:00'
  notes: 已对照原文与25张图核对三层是否完整：KSA 图1 为『i=(i+objArr[i]+arg0.charCodeAt(i%len))%256 后交换 objArr[i3]/objArr[i]』，与卡内下标互换一致；PRGA 图6 为『(arg1.charCodeAt(i6)+objArr[(objArr[i4]+objArr[i5])%256])%256』即加法替代异或，卡内减法求逆正确；RSA 图7 为 modPow(arg0[i],7,75067) 逐字节，n=75067=271*277、e=7 与卡一致；换表图8 为 Array.from(abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/)，编码时 indexOf 标准表、输出取自定义表，卡内 CUSTOM→STD 翻译解码成立；密钥伪装 图4 构造函数 OHCTF2025、图5 onPageShow 改为 OHCTF2026（卡内写『OHCTF2025 一类』，实际诱饵 OHCTF2025/真值 OHCTF2026）。未验证点：图3 的 enc 反编译片段只显式看到 rc4Encrypt → 逐元素 customBase64(stringToUint8Array(...))，rsaEncrypt 未在该片段直接出现，卡内『customBase64(rsa(rc4(plain)))』的层序依据原文『RSA 对 RC4 结果逐字节加密』的文字描述，未见逐步对照图。另：文章后半 HMCTF ezAPP_And_SERVER（XOR 字符串→JWT 伪造→RSA2048+MD5 造 X-Sign→getflag，图16/20/25 已打通）未抽卡，已标 needs_extraction，不新增。
---

## 一句话结论

HarmonyOS 应用把加密逻辑写成 `enc = customBase64(rsa(customRC4(plain, key)))`，三处都被改动过——RC4 的 KSA 把 `S[i]` 与 `S[i3]` 的下标互换、PRGA 末尾用模 256 加法代替异或、RSA 只做逐字节 `m^7 mod 75067`、Base64 换成小写字母在前的表——按反编译出来的真实顺序逐层求逆即可还原明文。

## 原理

- **入口与结构**：HAP 解包后核心逻辑在 `ets/modules.abc`，用 ABC 反编译器（如基于 jadx 的 abcdecompiler）可直接读到 `Index` 类的方法表；`func_main_0` 里能看到 `rc4Encrypt`、`rsaEncrypt`、`customBase64`、`stringToUint8Array`、`enc` 等字段被挂到原型上，`enc` 的调用顺序就是加密顺序。
- **密钥伪装**：构造函数里初始化了一个 `secretKey`（`OHCTF2025` 一类），但真正参与运算的是 `onPageShow` 里重新赋的值；只读构造函数会拿到错 key，必须跟踪属性写入点。
- **KSA 被改**：标准 RC4 是 `i = (i + S[i3] + key[i3 % len]) % 256` 后交换 `S[i3]`/`S[i]`；这里写成 `i = (i + S[i] + key[i % len]) % 256`（把 `i3` 换成当前的 `i`，key 下标也从 `i3` 改成 `i`），交换仍是 `S[i3] ↔ S[i]`。两者生成的 S 盒完全不同，直接套标准 RC4 解不出来。
- **PRGA 被改**：标准是 `out = in ^ S[(S[i]+S[j])%256]`；这里是 `out = (in + S[(S[i]+S[j])%256]) % 256`，即用模 256 加法替换异或。求逆就是逐字节做 `(c - k + 256) % 256`，而不是再异或一次。
- **单字节 RSA**：`rsaEncrypt` 对每个字节做 `modPow(m, 7, 75067)`，`N=75067=271*277` 可在 factordb 直接分解，`e=7`，`d = e^{-1} mod φ(N)`；因为明文被限制在单字节，逐个字节解密即可，不需要处理分组填充。
- **换表 Base64**：`customBase64` 用 `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/` 代替标准表，索引映射关系不变，只需换成同一张表解码；`=` 填充仍按原逻辑追加。
- **为什么能还原**：三层都是确定性可逆变换，密钥与算法全部随包分发，没有任何服务端秘密；改动只是抬高阅读成本，不改可逆性。

## 触发条件

- 拿到目标 HAP，`modules.abc` 未加壳/未做强混淆，可反编译出方法体与字符串常量。
- 加密函数、密钥与密文都在客户端；算法为对称/可逆变换（流密码、模运算、编码）。
- 攻击者能读汇编级伪代码并手写逆变换。

## 利用步骤

1. 解包 HAP，反编译 `ets/modules.abc`，在 `pages/Index` 中找到 `enc`，确认调用顺序为 `customBase64(rsa(rc4(plain)))`。
2. 搜索 `secretKey` 的所有赋值点，取 `onPageShow` 中的真实值，忽略构造函数里的诱饵值。
3. 抄出 KSA/PRGA 的伪代码，逐行与标准 RC4 对比，标出下标替换与加法替换两处差异。
4. 读 `rsaEncrypt` 的 `modPow(m, e, n)` 常量，分解 `n` 求 `d`。
5. 读 `customBase64` 的字母表，按同一映射解码。
6. 逆序执行：换表 Base64 解码 → 逐字节 RSA 解密 → 魔改 RC4 减法解密，得到明文。

## PoC

```python
# 逆序：换表 base64 → 单字节 RSA → 魔改 RC4（加法版）
import base64

CUSTOM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
STD    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def unbase64(s):
    return base64.b64decode(s.translate(str.maketrans(CUSTOM, STD)))

def rsa_dec_bytes(data, n=75067, e=7):
    # n = 271 * 277, phi = 270 * 276
    d = pow(e, -1, 270 * 276)
    return bytes(pow(b, d, n) for b in data)

def rc4_custom_decrypt(key: str, data: bytes) -> bytes:
    S = list(range(256))
    i = 0
    for i3 in range(256):
        i = ((i + S[i]) + ord(key[i % len(key)])) % 256   # 注意：S[i] 而非 S[i3]
        S[i3], S[i] = S[i], S[i3]
    i4 = i5 = 0
    out = bytearray()
    for b in data:
        i4 = (i4 + 1) % 256
        i5 = (i5 + S[i4]) % 256
        S[i4], S[i5] = S[i5], S[i4]
        k = S[(S[i4] + S[i5]) % 256]
        out.append((b - k + 256) % 256)                    # 加法版求逆用减法
    return bytes(out)

if __name__ == "__main__":
    ct = unbase64("<CIPHERTEXT>")
    print(rc4_custom_decrypt("<REAL_KEY>", rsa_dec_bytes(ct)))
```

## 变体与关联

- 变体：KSA 只改 key 下标、只改交换对象、或把 `% 256` 换成 `& 0xFF`；PRGA 可换成减法/加法/异或与加法混合；RSA 可换成小指数逐字节、或分组但无填充；Base64 可换成大小写互换、逆序表、URL-safe 变体。
- 变体：同一函数内串联多层时，务必以反编译出的调用顺序为准，不要按常见密码学套件顺序假设。
- 关联：[[ctf-reverse-modified-rc4-keytable-subtract-xor]]、[[ctf-reverse-modified-rc4-rounds-sbox]]、[[ctf-reverse-miniprogram-variant-rc4-reverse-ksa]]（同属"魔改 RC4 逐行比对求逆"）；HAP/ABC 解包流程见 [[mobile-harmony-hap-abc-reverse-sourcemaps-workflow]]。

## 检测与防御

- 本题为 CTF 逆向题型，无服务端攻击面；对真实产品而言，客户端自实现加密不构成保护。
- 检测思路：ABC 中出现 `modPow`、`% 256`、自定义字母表常量与 `charCodeAt` 循环，通常是自实现的密码学；`secretKey` 存在多处赋值时要全部跟踪。
- 防御：不要在客户端保存密钥或用自研加密保护敏感数据；使用标准库算法并由服务端持有密钥。
