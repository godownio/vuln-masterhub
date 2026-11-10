---
id: ctf-reverse-android-so-rc4-derived-xtea-cbc-decrypt
title: Android so 层 RC4 解出 XTEA key/iv 后按魔改 XTEA-CBC 轮逆推解密
type: scenario
domain: ctf
path: ctf/reverse
technique: modified-xtea-cbc-decrypt
tags:
- ctf
- reverse
- android
- xtea
- rc4
- cbc
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:11:59+08:00'
  notes: 已对照原文核对：RC4(DoNotHackMe) 派生 XTEA key/iv、魔改点 v3+=(key[i%4]^i)-0x61C88647 与图18-22及解密脚本一致，flag 可复现；未验证点：未实际运行脚本验证 flag 输出
url: /docs/ctf/reverse/ctf-reverse-android-so-rc4-derived-xtea-cbc-decrypt/
draft: false
kb_aliases:
- 魔改 XTEA CBC
- so 层 XTEA 解密
- RC4 派生 XTEA 密钥
---

# Android so 层 RC4 解出 XTEA key/iv 后按魔改 XTEA-CBC 轮逆推解密

## 一句话结论

native 层校验逻辑先用同一 RC4（key 为 `DoNotHackMe`）分别解出 XTEA 的 16 字节密钥与 8 字节 IV，再用魔改版 XTEA-CBC 加密用户输入并与硬编码密文比对；从 so 数据段提取 RC4 密文、复现魔改细节（delta 常量取反做减法、轮密钥索引与轮数异或）写出逆轮解密脚本即可还原明文。

## 原理

Java 层无逻辑，校验全部在 so 的 `onCreat3` JNI 函数中：入口先做 antidebug/Frida 检测，随后初始化函数对两段 data 段密文各调用一次同一 RC4，分别得到 XTEA 密钥（16 字节）与 IV（8 字节）——即密钥材料并不直接存在，需先复现 RC4 才能拿到。XTEA 的魔改点在轮密钥调度：每轮 `sum += (key[i%4] ^ i) - 0x61C88647`，把标准 delta `0x9E3779B9` 换成其取反数且索引参与了异或；加密 32 轮后按 CBC 链接（前块密文作下一块输入异或源）。由于这些改动是确定性的，直接在解密脚本中逆序 32 轮（先逆 v4 再逆 v5，用预生成的 sum 轨迹）再做 CBC 链上异或即可还原。

## 触发条件

- 目标为 Android 应用，核心校验在 native so 内；
- so 数据段可提取（静态分析即可，无需运行）；
- 能识别 RC4 的 S 盒特征与 XTEA 的 `<<4 ^ >>5 + v` 轮函数特征。

## 利用步骤

1. IDA 打开 so，从 JNI 入口识别 `antidebug` 分支与 `encrypto(v15, key, iv, out)` 调用；
2. 定位初始化函数：两次 `Rc4(aDonothackme, 11, unk_11004, 16, unk_6F7B0)` 与 `Rc4(..., unk_11014, 8, unk_6F7C0)`，从数据段摘出两段密文（16 字节、8 字节）；
3. 用标准 RC4 + key `DoNotHackMe` 解出 XTEA key（如 `52756e74696d65537472696e67457874` = "RuntimeStringExt"）与 IV（`4c696e4b48405348` = "LinKbH@SH"）；
4. 阅读魔改 XTEA 轮函数，确认 delta 改动与 key 索引异或，写逆轮脚本：预生成 32 轮 sum 序列，逆序恢复 v5/v4，再按 CBC 用前一密文块异或；
5. 对 42 字节硬编码密文整体执行 CBC 解密得到明文 flag。

## PoC

解密脚本见正文方法（标准 XTEA 逆轮 + 自定义 sum 轨迹 + CBC 链接），CyberChef 可直接完成 RC4 两段解密。

## 变体与关联

- 同类变体：XXTEA 自定义 delta、密钥由用户名派生等（见 ctf/reverse 下其他 XTEA 卡）；
- RC4 材料隐藏手法也常见于 APK asset/资源文件场景；
- 反调试分支（Frida 检测打印后 abort）仅阻挡动态分析，静态路径不受影响。

## 检测与防御

- 教学场景关注点：密钥派生链（RC4→XTEA key/iv）与算法魔改点必须同时复现，漏一处即解密失败；
- 防御侧：native 校验避免把对称算法 key/iv 静态加密存放于同一 so，宜使用白盒密码或服务端校验；Frida/调试器检测只能提高门槛，不能替代算法强度。
