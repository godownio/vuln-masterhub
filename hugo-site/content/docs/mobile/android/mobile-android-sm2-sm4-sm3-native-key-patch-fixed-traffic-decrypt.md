---
id: mobile-android-sm2-sm4-sm3-native-key-patch-fixed-traffic-decrypt
title: Android 国密流量解密：patch so 将 SM2 包裹的 SM4 随机 key 固定为 32 个 A 后 ECB 解密
type: scenario
domain: mobile
path: mobile/android
technique: android-sm2-sm4-sm3-native-key-patch-traffic-decrypt
tags:
- android
- sm4
- sm2
- sm3
- native
- so
- traffic-decrypt
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V559
  verified_at: '2026-11-12T00:46:31+08:00'
  notes: '已对照原文与18张图核对：图05 telecomSMEncrypt(JNI) 调用点；图06 PEJniLibbckSM native 方法与 System.loadLibrary；图07/08 JNI_OnLoad 动态注册、off_1F7008 函数表定位；图10/11 getCipherValue 中 byte_1FFDB8 标志、time(0)+srand、32 次 byte_18703A[rand()%62] 生成 byte_1FFDB9 key；图12 EVP_sm4_128_ecb 与 EVP_CipherInit/Update/Final；图13/15 SM2Encrypt 包裹 32 字节 key（v12）、SM4 密文（v13）、standardHMAC（v8）；图14 snprintf(''%s|%s|%s'', v12, v13, v8)；图17/18 IDA Patch program→Change byte 将 byte_18703A 全改 0x41。已修正：原文抓包截图为 X-Madp-Encrypted: 1，原卡三处误写为 X-Mapd-Encrypted，已统一改正；并注明 v8 的 HMAC 为原文推测 SM3。技术点/参数一致。dedup：与 mobile-android-aes-random-key-hook-fixed-iv-decrypt（Java 层 hook getKey、key 明文随包、AES-CBC 固定 IV）算法/入口/key 传递均不同；与 DES 参数加密、encrypted-so 等卡不同链。未验证点：未复现样本、原文未展示最终解密明文；原文无 CVE/受影响版本（手法卡，未设 versions）；frontmatter 无 sources/source_url（库内惯例）。'
url: /docs/mobile/android/mobile-android-sm2-sm4-sm3-native-key-patch-fixed-traffic-decrypt/
draft: false
kb_aliases:
- SM4 流量解密
- 国密 SM2 SM4 SM3
- telecomSMEncrypt
- getNativeSM4EncryptValue
- EVP_sm4_128_ecb
- patch so 固定 key
- byte_18703A
- 32 个 A
---

## 一句话结论

App 用 native so 做国密流量加密：每次启动用 `time(0)+srand()` 从 62 字符表随机选 32 个字符作为 key，**SM2 加密该 key 串**后与 `base64(SM4(key, 明文))`、`base64(HMAC)` 以 `%s|%s|%s` 拼成请求体；由于 SM2 公钥加密的 key 只有服务端私钥能解，抓包者无法直接解密。把 so 中字符表数组（`byte_18703A`）整段 patch 成 `0x41`（'A'），随机结果恒为 'A'，key 固定为 32 个 A，即可用固定 key 做 SM4 ECB 解密与重放。

## 原理

- **Java 层只是壳**：`PEjniLibbckSM.telecomSMEncrypt(String)` 声明 native 并 `System.loadLibrary`，实际逻辑在 so 的 `JNI_OnLoad` 注册的 `getNativeSMEncryptValue`/`getSMValue` 等函数中；`JNI_OnLoad` 未混淆时可直接顺藤摸瓜。
- **key 生成**：`getCipherValue` 中首次调用时 `v15 = time(0); srand(v15); for i in 0..31: byte_1FFDB9[i] = byte_18703A[rand() % 62]`——`byte_18703A` 是 62 个可打印字符表，`byte_1FFDB9` 是 32 字符 key；`byte_1FFDB8` 标志保证每个进程只初始化一次。
- **加密与封装**：`CryptoService::SM4Encrypt(..., byte_1FFDB9, 16, 明文, ...)` 使用 OpenSSL `EVP_sm4_128_ecb`（16 字节 key、ECB、PKCS padding），结果 base64 得 `v13`；`CryptoService::SM2Encrypt(..., byte_1FFDB9, 32, ...)` 用内置 SM2 公钥加密 32 字节 key 串，base64 得 `v12`；`standardHMAC(..., byte_1FFDC9, 16, ...)` 计算校验 base64 得 `v8`（原文推测为 SM3）；最后 `snprintf("%s|%s|%s", v12, v13, v8)` 作为请求体（抓包可见 `X-Madp-Encrypted: 1`）。
- **为什么 patch 字符表可行**：`rand() % 62` 只是从表中取索引；若表内 62 个字节全为 'A'，无论 rand 取值如何，`byte_1FFDB9` 恒为 32 个 'A'。SM4 取前 16 字节 key（16 个 'A'），SM2 包裹的 key 串也恒为 32 个 'A'，服务端解出的 key 与客户端一致，因此密文仍可正常解密/重放。
- **为什么比 hook 更稳**：不依赖 Frida 注入与调试端口，直接改 so 后回填 APK 的 lib 目录，App 自己用固定 key 跑，抓包后离线解密即可。

## 触发条件

- 目标 App 流量加密实现位于 native so，Java 层仅声明 native 方法；`JNI_OnLoad` 或导出符号未强混淆，能定位到 key 生成与 SM4/SM2 调用。
- 抓包可见请求体为 `X|Y|Z` 三段 base64（`%s|%s|%s`），且加密头（如 `X-Madp-Encrypted: 1`）标识加密。
- so 中 key 字符表以明文数据段存在（可 patch）；设备可写入 App 的 `lib/` 目录（root）。
- 目标是分析/测试授权范围内的 App。

## 利用步骤

1. 反编译 APK（先脱壳），搜索 API 前缀（如 `mobile`）与 `telecomSMEncrypt`，确认 native 方法及 `System.loadLibrary` 的 so 名。
2. IDA 打开 so：若导出表搜不到目标函数，先看 `JNI_OnLoad`（常未混淆），通过 `RegisterNatives`/函数指针表找到 `getNativeSMEncryptValue` → `getSMValue` → `getCipherValue`。
3. 分析 key 生成与算法：`time(0)+srand` 随机取字符表 32 字符；`EVP_sm4_128_ecb`（ECB 无 IV）；SM2 加密 key；HMAC 校验；请求体 `%s|%s|%s`。
4. 在 IDA 中定位字符表 `byte_18703A`，`Edit → Patch program → Change byte` 将 62 字节全部改为 `0x41`（'A'），`Apply patches to input file` 保存新 so。
5. root 下把修改后的 so 覆盖到 `/data/app/~~xxxx==/<pkg>/lib/arm/`（或拆分 APK 的 `lib/arm`），重启 App。
6. 抓包后用固定 key（32 个 'A'，SM4 取前 16 字节）按 ECB 解密请求中的中间段，HMAC 段可校验；构造请求时按同样格式加密即可重放/改包。

## PoC

```text
# 请求体形态（原文抓包）
POST /mobile
X-Madp-Encrypted: 1
<base64(SM2(key))>|<base64(SM4_ECB(明文))>|<base64(HMAC)>

# key 生成（反编译）
srand(time(0));
for (i = 0; i < 32; ++i)
    byte_1FFDB9[i] = byte_18703A[rand() % 62];
SM4Encrypt(..., byte_1FFDB9, 16, plaintext, ...);   # EVP_sm4_128_ecb
SM2Encrypt(..., byte_1FFDB9, 32, ...);
snprintf(out, ..., "%s|%s|%s", v12, v13, v8);
```

```python
# patch 后 key 恒为 32 个 'A'，SM4 取前 16 字节做 ECB 解密
from Crypto.Cipher import AES  # 或用 gmssl 的 SM4
key = b"A" * 16
# pt = sm4_ecb_decrypt(b64decode(middle_segment), key)
```

原文在银行 App 样本中完成 so 分析、将 `byte_18703A` 全部改为 'A' 并回填 so；未展示最终解密出的明文包。

## 变体与关联

- **算法变体**：同样思路适用于 AES/3DES/RC4 等 native 加密；key 可能由 `rand`、`time`、设备信息派生，patch 派生输入或直接 patch 密钥缓冲区均可。
- **key 传递变体**：若 key 未用 SM2/RSA 包裹而是明文随包传输，可直接从请求中取 key 解密，见 [[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]；本卡针对 key 被非对称加密、抓包不可直接获取的情况。
- **关联**：[[mobile-android-frida-hook-native-key-material-precomputed-mapping]]（Frida hook native key）、[[mobile-android-jni-registernatives-static-real-function-locate]]（JNI 动态注册定位）、[[mobile-android-shell-so-embedded-elf-carve-extract-dat]]（so 提取）。
- **边界**：so 有完整性校验/签名校验、key 由服务端协商或白盒保护、SM2 公钥固定且服务端校验时间戳/随机数时，patch 后可能被检测或重放失败；ECB 无 IV 是本例可离线解密的前提。

## 检测与防御

- **检测**：请求体呈 `base64|base64|base64` 三段式与加密头；native 库中存在 `EVP_sm4_128_ecb`、`SM2Encrypt`、`rand()%62` 字符表等特征；客户端完整性校验失败/so 被替换告警。
- **防御**：对称 key 不与密文同包传输且不要用非对称公钥"包裹"后仍期待保密（客户端可 patch）；使用 TLS + 证书固定、服务端时间戳/nonce 防重放、native 完整性校验与代码混淆；敏感接口做服务端风控。
