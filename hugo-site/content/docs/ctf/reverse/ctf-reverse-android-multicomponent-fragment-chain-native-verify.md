---
id: ctf-reverse-android-multicomponent-fragment-chain-native-verify
title: Android 多组件分段校验题：ContentProvider/广播/Deep Link 三通道取片段 + 自定义 Base64 + native 链式收口
type: scenario
domain: ctf
path: ctf/reverse
technique: android-multicomponent-fragment-chain-native-verify
tags:
- ctf
- reverse
- android
- contentprovider
- broadcastreceiver
- deeplink
- custom-base64
- native
- jni
- signature
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:30+08:00'
  notes: 已对照原文核对：ContentProvider URI/keys/fragment、Receiver auth(token ISCC2026)→getkey(part=3)、deep link securevault://secret/unlock?token=RC4_KEY_PART4、自定义 Base64 反序表、SecureValidator.c 的 ISCC{}/magic 12/inner 24/7-5-5-7 分段、native Part1 签名 SHA-256/Part2 自定义 Base64+fragment2 异或/Part3 LFSR/Part4 RC4-like+总 SHA-256、四段 e5JXv2T|_qrGM|_iJ5n|_bD24iR 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-android-multicomponent-fragment-chain-native-verify/
draft: false
kb_aliases:
- 灰签名回廊
- SecureVault
- com.example.gnd
- SecretContentProvider
- SecretReceiver
- SecretActivity
- nativeVerifyPart1
---

## 一句话结论

APK 把 flag 拆成 4 段，分别由导出的 ContentProvider、两步广播和 deep link 三条独立通道生成并缓存，片段用大小写/数字全反序的自定义 Base64 表编码；必须按状态机顺序各触发一次，再按 7/5/5/7 拼接，native 层用签名 SHA-256、LFSR、RC4-like 链和总 SHA-256 收口。

## 原理

- **三个隐藏入口**：Manifest 中 Provider authority 为 `com.example.gnd.secret.provider`，查询路径 `/keys/fragment`；Receiver action 为 `com.example.gnd.SECRET_ACTION`；Activity 注册 deep link `securevault://secret/unlock`。三者都没有对调用者身份做额外检查，知道 URI/action 的任意应用都能触发。
- **Provider 的一次性状态**：查询 URI 会生成并缓存 `fragment2`，内容依赖 Provider 内部计数器；每查一次状态就变，正确链路里只能查询一次，否则后续 native 比较的片段不一致。
- **Receiver 两步状态机**：先发 `code=auth, token=ISCC2026` 置认证标志，再发 `code=getkey, part=3` 才会生成 `fragment3`；直接发 `getkey` 会被忽略。
- **Deep Link 参数**：`securevault://secret/unlock?token=RC4_KEY_PART4` 启动 `SecretActivity`，从 Intent 取 token，格式校验后写入 `fragment4`；token 错误时 Activity 仍启动，但写入无效值，导致第四段对不上。
- **自定义 Base64**：字母表为 `ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/`，即大写反序、小写反序、数字反序、`+/` 不变。编码/解码结构与标准 Base64 完全一致，只是字符表不同；直接用标准表解码会得到错误字节。
- **Java 层分段**：`SecureValidator.c()` 要求 flag 以 `ISCC{` 开头、`}` 结尾，取 `inner = flag[5:-1]`；`inner.length() == nativeGetMagicNumber() * 2`，magic 返回 12，所以 inner 长 24；切成 `7 / 5 / 5 / 7` 四段。前三段分别进 `nativeVerifyPart1/2/3`，第四段进 `nativeVerifyPart4`；`nativeComputeChainToken()` 把前三段的中间结果串成第四段的前置状态。
- **native 链**：Part1 通过 JNI 回调取当前 APK 签名，算 SHA-256 与 so 内硬编码值比较，因此重打包签名变化会直接失败；Part2 把输入按自定义 Base64 解码后与 `fragment2` 逐字节异或，再比对预设常量；Part3 对 `fragment3` 关联数据做 LFSR 变换后比对；Part4 用 chain token 与 `fragment4` 初始化 256 字节 S 盒，生成 RC4 风格密钥流约束第四段前几个字节，最后用整 flag 的 SHA-256 闭环。
- **结果**：四段为 `e5JXv2T | _qrGM | _iJ5n | _bD24iR`，拼接得 `ISCC{e5JXv2T_qrGM_iJ5n_bD24iR}`。

## 触发条件

- APK 的 AndroidManifest 中存在 exported 且无 permission 限制的 Provider/Receiver/Activity。
- 设备可安装并运行目标 APK，能用 adb 或同设备应用触发组件。
- 片段生成依赖组件内部状态，必须按 Provider 单次查询、广播 auth→getkey、deep link 带正确 token 的顺序执行。
- 能反编译 DEX/native，恢复分段规则、自定义编码表和校验逻辑。

## 利用步骤

1. 用 `apktool d` 或 jadx 读 Manifest，列出 `exported=true` 的 Provider/Receiver/Activity 及其 authority、action、intent-filter。
2. 用 `adb shell content query --uri content://com.example.gnd.secret.provider/keys/fragment` 触发 Provider，只查一次并记录返回值。
3. 先发认证广播，再发取 key 广播：
   `adb shell am broadcast -a com.example.gnd.SECRET_ACTION --es code auth --es token ISCC2026`
   `adb shell am broadcast -a com.example.gnd.SECRET_ACTION --es code getkey --es part 3`
4. 用 `adb shell am start -a android.intent.action.VIEW -d "securevault://secret/unlock?token=RC4_KEY_PART4"` 触发 deep link，写入第四段。
5. 对拿到的片段按自定义表映射回标准 Base64 再解码；若代码中片段是 hex/原始字节，按实际类型处理。
6. 按 `7/5/5/7` 切分并在本地复现 native 校验；Part1 受签名绑定，必须用原包签名计算，不能重打包后再算。
7. 拼接 `ISCC{...}`，用总 SHA-256 或 native 校验复核。

## PoC

```bash
adb shell content query --uri content://com.example.gnd.secret.provider/keys/fragment
adb shell am broadcast -a com.example.gnd.SECRET_ACTION --es code auth --es token ISCC2026
adb shell am broadcast -a com.example.gnd.SECRET_ACTION --es code getkey --es part 3
adb shell am start -a android.intent.action.VIEW -d "securevault://secret/unlock?token=RC4_KEY_PART4"
```

```python
import base64

CUSTOM = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
STD    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_custom(s: str) -> bytes:
    # 仅换表，算法与标准 Base64 相同
    return base64.b64decode(s.translate(str.maketrans(CUSTOM, STD)))

# 三通道拿到的片段按代码确认是否为自定义 Base64 文本；
# 本题最终四段：e5JXv2T | _qrGM | _iJ5n | _bD24iR
flag = "ISCC{" + "e5JXv2T" + "_qrGM" + "_iJ5n" + "_bD24iR" + "}"
print(flag)
```

## 变体与关联

- **状态变体**：Provider 计数器、广播认证标志、deep link token 校验都可以换成一次性 token、时间窗口或签名校验；触发顺序错就得到无效片段。
- **编码变体**：自定义 Base64 可只换表，也可同时改索引（异或/加 key）；本题只换表，识别特征是 64 字符表不是标准排列。
- **签名绑定变体**：Part1 用证书 SHA-256 与硬编码值比较；重打包后需 patch 比较或替换硬编码 hash，不能只改 Java 层。
- **关联卡片**：[[ctf-reverse-base64-table-index-mutation]]（换表/索引魔改还原）、[[mobile-android-apk-signature-sha1-xor-key-decrypt]]（签名作密钥/校验）、[[ctf-reverse-apk-chacha20-counter-one-native]]（APK native 校验）。
- **边界**：组件未导出或受 permission 保护时，需要 root、同签名或额外漏洞才能触发；片段内容依赖运行时状态，不能只靠静态 strings 拼 flag。

## 检测与防御

- **真实应用**：导出的 Provider/Receiver/Activity 应加 permission、签名校验或调用者包名校验；不要把敏感数据拆分到客户端组件中传递。
- **检测信号**：Manifest 中 `exported=true` 且无 permission 的组件；运行期异常的 `content query`、广播和 deep link 调用序列。
- **CTF 逆向**：先枚举所有组件，再按状态机逐个触发；不要直接 `strings` 找 flag，也不要重复查询有计数器的 Provider。
