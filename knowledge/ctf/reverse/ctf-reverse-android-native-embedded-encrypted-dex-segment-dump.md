---
id: ctf-reverse-android-native-embedded-encrypted-dex-segment-dump
title: so .rodata 内嵌加密 dex 分段广播拼装：dump 后 jadx 提取隐藏校验逻辑
type: scenario
domain: ctf
path: ctf/reverse
technique: native-embedded-dex-dump
aliases:
- native 内嵌 dex
- dex 分段 dump
- 动态加载 dex 提取
tags:
- ctf
- reverse
- android
- dex
- jni
- dump
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:21:11+08:00'
  notes: 已对照原文核对：图40 sendEncryptedSegments 按 index 分 7 段广播、图41-42 .rodata aDex035 dex 魔数与段长 1780、图43-45 dump 后 jadx+3DES 解出第一段 flag、图49-51 enreal 解密+3DES 得第二段，PoC 完整；与 first-gen-dex-packer 卡获取方式不同（so 内嵌分段离线 dump vs assets 运行时解密）；未验证点：未实际 dump
---

# so .rodata 内嵌加密 dex 分段广播拼装：dump 后 jadx 提取隐藏校验逻辑

## 一句话结论

native 层把完整 dex 文件以密文字节数组内嵌在 .rodata 中，`getEncryptedSegment(index)` 按 1780/254 字节分段返回，Java 层用 LocalBroadcast 逐段广播拼接，DexLoader 动态加载后调用其中的校验方法；从 so 数据段直接按偏移把各段 dump 出来拼接还原 dex，即可静态分析隐藏的第二段校验逻辑。

## 原理

把核心校验逻辑编成独立 dex 加密后藏进 so 的 .rodata，运行时 `System.loadLibrary` 的 JNI 函数按 index 返回对应密文段，Java 端 `sendEncryptedSegments` 循环 7 段通过 LocalBroadcast 发给接收器拼装、解密并 `DexClassLoader` 加载——静态反编译 dex 看不到任何逻辑，因为代码根本不在 classes.dex 里。但加密 dex 的本体与分段长度（首段 1780 字节、其余 254 字节，`n6 != 6` 时补 254）都硬编码在 so 中，且解密 key 在另一个 so 的 JNI 里以明文 `memcpy` 出现，因此攻击者可以脱离 App 运行：定位 `aDex035` 数据标签，按分段长度依次摘出各段，拼成完整 dex 后直接 jadx 反编译。

## 触发条件

- Java 层出现 `DexClassLoader`/`InMemoryDexClassLoader` 或来源可疑的广播拼装逻辑；
- so 存在按 index 返回字节数组的 JNI 函数与 .rodata 内的大段二进制数据；
- 解密 key 硬编码在任一 so 的 JNI 函数中。

## 利用步骤

1. jadx 发现 `registerReceiver(...DEX_SEGMENT)` 与 `sendEncryptedSegments` 循环 7 段广播，确认动态 dex 存在；
2. IDA 打开 libmobile04.so，分析 `getEncryptedSegment`：长度规则 `n1780=1780, n6!=6 时 v3+254`，数据源 `aDex035 + v3`；
3. 按长度规则从 .rodata 依次 dump 7 段（用 .rodata 中的 `dex\nc` 魔数定位起点），拼接得完整加密 dex；
4. 从 libSunday.so 的 JNI 函数 `memcpy(v3, "SgJvuvFJp4UBKtLPOySYoWZ8", 24)` 拿到 3DES key；
5. 3DES/ECB 解密各段拼出明文 dex，jadx 打开得到 `checkFlag`（3DESede 加密比较），或直接离线解密密文数组拿 flag。

## PoC

无 PoC（dump + 解密流程，脚本为按段长 memcpy 与标准 3DES 调用）。

## 变体与关联

- 同类隐藏手法：dex 藏于 assets/png 尾部、内存中释放后 dlopen/加载（见 ctf-reverse-android-encrypted-so-runtime-dlopen-extraction 的加密 so 变体）；
- 运行时替代方案：Frida `Java.enumerateClassLoaders` 或 hook DexClassLoader 构造函数直接抓字节参数 dump；
- 解密后的 dex 内可能再嵌一层校验（本题为 3DESede/ECB + native key）。

## 检测与防御

- 教学要点：JNI 返回 byte[] 的函数若按 index 分段且长度规则怪异（首段超长、尾段补齐），基本可断定内嵌文件；
- 防御侧：动态加载 dex 的 key 与密文同置应用内时保护失效；应使用 Play Integrity/服务端下发，或 R8+oat 优化减少 dex 特征。
