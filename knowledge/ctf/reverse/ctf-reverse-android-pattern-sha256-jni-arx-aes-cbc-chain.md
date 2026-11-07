---
id: ctf-reverse-android-pattern-sha256-jni-arx-aes-cbc-chain
title: Android APK 三段校验链：手势 SHA-256 爆破 + JNI 可逆字节变换 + SQLite IV 的 AES-CBC 解密
type: scenario
domain: ctf
path: ctf/reverse
technique: android-three-stage-pattern-jni-arx-aes
aliases:
- Hook My Secret
- Android 手势密码 SHA-256
- JNI 可逆字节变换
- SQLite 取 AES IV
- AES-CBC 校验链
- APK 三段校验
tags:
- android
- reverse
- apk
- jni
- sha256
- aes-cbc
- sqlite
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:12:53+08:00'
  notes: 已对照原文核对：Stage1 SHA-256 手势枚举、Stage2 JNI rol8 状态变换与逐字节逆推公式、Stage3 SQLite IV+AES-CBC 解密均一致；原文无图片；PoC 中 SHA/密文用占位符，未实际运行。
---

## 一句话结论

Android APK 把校验拆成三段时，可以逐段独立求逆：手势点位拼串后与 SHA-256 常量比较（枚举 `P(9,k)` 即可爆破）、JNI native 对每个输入字节做可逆的 rol8/状态更新（按公式逐字节反推）、最后把第二段得到的 key 作为 AES Key、用 SQLite 中保存的 IV 做 AES-CBC 解密，与固定密文比较；三段全部逆完即可得到 flag。

## 原理

- **Stage1 手势**：3×3 手势点位编号 0~8，App 把点序列拼成逗号分隔字符串（如 `0,1,2,4,8`），计算 SHA-256 小写 hex 与常量比较。点位不重复且长度 1~9，搜索空间只有 `Σ P(9,k)`，用 `itertools.permutations` 枚举即可秒出。
- **Stage2 JNI**：Java 层调用 `NativeBridge.encryptStage2(input)`，`.so` 中的导出函数对输入逐字节做可逆变换：
  ```text
  d = 0x51
  t = rol8(((13*i + 0x42) ^ d ^ x), 3)
  out = (7*d + i + t) & 0xff
  d = (x + d + (out ^ i)) & 0xff
  ```
  其中 `d` 是跨字节的状态，`out` 与 16 字节常量数组比较。因为每一步都只依赖当前 `x` 和已知的 `d`/`i`/`out`，可以逐字节反推：
  ```text
  t = (out - (7*d + i)) & 0xff
  y = ror8(t, 3)
  x = y ^ d ^ (13*i + 0x42)
  d = (x + d + (out ^ i)) & 0xff
  ```
  不需要暴力搜索，也不需要符号执行。
- **Stage3 AES**：第二段得到的 key 被写入 `SharedPreferences("challenge_state")`；Stage3 从 SQLite `config.db` 的 `app_cfg` 表取 `stage3_iv`（Base64 存储），再对用户输入做 `AES/CBC/PKCS5Padding` 加密、Base64 编码，与固定密文比较。已知 key、IV、密文时直接解密即可。
- 三段链的设计意图是让每一段都可以独立求解，但必须按顺序拿到上一段的输出作为下一段输入；Stage3 的 IV 不在代码常量里，而在 SQLite 中，需要额外解包/读取 assets 或 databases 目录。
- 根因是“把校验逻辑和密钥/IV 全部放在客户端”，无论拆成多少段、是否放 native/SQLite，最终都能在本地复现。

## 触发条件

- 目标是 Android APK，校验逻辑分布在 Java/Kotlin、JNI `.so`、SQLite/SharedPreferences 等多处。
- 关键常量（SHA-256 目标、16 字节数组、AES 密文）硬编码在 dex/so/assets 中。
- JNI 变换是可逆的逐字节运算，没有不可逆哈希/签名。
- AES 使用对称加密且 key/IV 可从客户端获取（第二段输出、SQLite 配置）。
- 允许静态反编译与本地复现（CTF 场景）。

## 利用步骤

1. 用 jadx/apktool 解包 APK，定位 `PatternActivity`、`Stage2Activity`、`Stage3Activity`、`NativeBridge` 等类。
2. Stage1：提取目标 SHA-256 常量，枚举 3×3 点位序列（不重复）计算 SHA-256，匹配得到手势。
3. Stage2：从 `lib/*/libhookmysecret.so` 的导出函数 `Java_..._encryptStage2` 反汇编，提炼逐字节公式；按逆公式对 16 字节目标数组反推输入。
4. Stage3：读取 SQLite `config.db` 的 `app_cfg.stage3_iv`（Base64 解码），从 SharedPreferences/Stage2 结果取 key；用 AES-CBC 解密目标 Base64 密文并去 PKCS#5 padding。
5. 用 Stage2 正向公式验证反推结果与目标数组一致，确保没有笔误。
6. 按题目要求提交最终字符串（flag）。

## PoC

```python
import base64, hashlib, itertools
from Crypto.Cipher import AES

def rol8(x, n): return ((x << n) | (x >> (8 - n))) & 0xff
def ror8(x, n): return ((x >> n) | (x << (8 - n))) & 0xff

# Stage1
target_sha = "<SHA-256 常量>"
for k in range(1, 10):
    for p in itertools.permutations("012345678", k):
        s = ",".join(p)
        if hashlib.sha256(s.encode()).hexdigest() == target_sha:
            print("pattern:", s); break

# Stage2
target = [250, 113, 87, 185, 6, 125, 167, 156, 4, 0, 229, 239, 119, 155, 187, 95]
d, out = 0x51, bytearray()
for i, o in enumerate(target):
    t = (o - (7 * d + i)) & 0xff
    y = ror8(t, 3)
    x = y ^ d ^ ((13 * i + 0x42) & 0xff)
    out.append(x)
    d = (x + d + (o ^ i)) & 0xff
key = bytes(out)
print("stage2 key:", key)

# Stage3
iv = base64.b64decode("<SQLite 中 stage3_iv 的 Base64>")
ct = base64.b64decode("<目标密文 Base64>")
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print("flag:", pt[:-pt[-1]].decode())
```

## 变体与关联

- **Stage1 变体**：手势可能用 MD5/SHA-1、加盐、异或或自定义编码；枚举空间仍很小，可先爆破。
- **Stage2 变体**：JNI 变换可能是 TEA/XTEA、RC4、自定义 ARX、S-box；先确认是否可逆，再决定逐字节反推、Z3 或 Unicorn 仿真。
- **Stage3 变体**：AES 模式可能是 CBC/ECB/CTR/GCM；IV 可能在 SharedPreferences、SQLite、assets、BuildConfig 或 native 常量中。
- **关联**：[[ctf-reverse-apk-native-tea-gf256-matrix-lcg]]（APK native 三段校验的另一组合）；[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（JNI 复杂时用 Unicorn 仿真）；[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（JNI + 常量比较）。
- **边界**：若 native 变换包含不可逆哈希、服务端签名或硬件密钥，本路径失效；AES key 若由服务端动态下发且不落盘，也无法本地解密。

## 检测与防御

- **检测**：APK 中出现长 SHA-256 常量、16 字节比较数组、`AES/CBC/PKCS5Padding`、SQLite `stage3_iv` 字段；native 导出函数名为 `encryptStage2` 等。
- **防御**：不要把 flag 或可解密的密钥/IV 放在客户端；关键校验放服务端，客户端只保存短期令牌；对本地配置做完整性校验。
- **加固**：native 混淆、字符串加密、反调试只能提高成本；真正安全依赖服务端校验与密钥管理。
