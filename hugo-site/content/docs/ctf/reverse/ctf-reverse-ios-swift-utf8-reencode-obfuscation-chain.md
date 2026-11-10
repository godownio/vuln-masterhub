---
id: ctf-reverse-ios-swift-utf8-reencode-obfuscation-chain
title: Swift String 迭代引发的 UTF-8 重编码混淆：c2/c3 前缀还原后逆向多层加密链
type: scenario
domain: ctf
path: ctf/reverse
technique: utf8-reencode-obfuscation-reverse
tags:
- ctf
- reverse
- ios
- swift
- utf8
- obfuscation
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:15:20+08:00'
  notes: 已对照原文核对：re!!!!! 链 RC4(Haruhikage)->base64->obfuscateString(+i+0xDEADBEEF)->transformString(奇偶异或0xEF/0xBE) 与伪代码一致，c2/c3 映射表图7-8 与 de_utf 脚本一致，图9 CyberChef base64+RC4 解出 flag，PoC 完整；未验证点：未实际运行脚本
url: /docs/ctf/reverse/ctf-reverse-ios-swift-utf8-reencode-obfuscation-chain/
draft: false
kb_aliases:
- Swift UTF-8 编码混淆
- c2 c3 前缀还原
- iOS Swift 多层加密链
---

# Swift String 迭代引发的 UTF-8 重编码混淆：c2/c3 前缀还原后逆向多层加密链

## 一句话结论

Swift 的 `String.Iterator.next()` 按 Unicode scalar 而非字节遍历，异或/加法后凡是落在 0x80-0xFF 的值经 `_uncheckedFromUTF8` 追加时会被重编码为 `c2 xx` / `c3 xx` 双字节序列，后续混淆层作用在重编码后的形态上；逆向时先按 c2/c3 前缀映射（c2→原值、c3→原值-0x40）还原字节流，再逐层逆转 RC4→base64→加索引常数→奇偶异或的加密链。

## 原理

Swift String 内部以 Unicode scalar 为元素。混淆函数对每个 scalar 异或 0xBE/0xEF（奇偶交替）后调用 `String._uncheckedFromUTF8` 追加：当结果超过 0x7F，UTF-8 编码自动把它变成两字节（0xC2/0xC3 前导 + 低 6 位）。下一轮迭代读回的是这个两字节 scalar 序列，因此"按字节混淆"的预期被打乱——0x80-0xBF 映射为 `c2 + (原值-0x40)`，0xC0-0xFF 映射为 `c3 + (原值-0x40)`，静态字符串里就出现大量 `c2xx c3xx` 前缀。这一行为可被有意用作混淆层：不解码 c2/c3 映射就不知道真正的中间密文。外层链依次为 RC4(key=Haruhikage)、base64、`+index+0xDEADBEEF 后 &0xFF`、最后 UTF-8 重编码混淆，全部可逆。

## 触发条件

- iOS/Swift 程序（或任何按 Unicode scalar 迭代处理字节的语言）；
- 混淆函数逐 scalar 异或后经 UTF-8 构造器追加；
- 静态字符串/密文呈 `c2xx`、`c3xx` 前缀交替形态。

## 利用步骤

1. IDA 分析 IPA，从 `ViewController.init` 提取 ivar 初值得到 RC4 key（本例 `Haruhikage`，注意伪代码中 8 字节立即数 + 后续 2 字节补全完整 key）；
2. 梳理 `complexEncrypt` 调用链：RC4 → base64 → obfuscateString（每字符 +index+0xDEADBEEF 后 &0xFF）→ transformString（奇偶异或 0xEF/0xBE，随后经 UTF-8 重编码）；
3. 对含 c2/c3 前缀的密文做逆映射：`c2 xx → xx`、`c3 xx → xx-0x40`（hex 循环里跳 4 位）；
4. 奇偶异或还原 → 再次 c2/c3 逆映射 → 每字节减 index 减 0xDEADBEEF 后 &0xFF → base64 解码 → RC4(key) 解密得明文。

## PoC

见方法步骤中的映射规则（c2/c3 前缀减法 + 链式逆运算），外层 RC4/base64 可用 CyberChef 完成。

## 变体与关联

- 同类编码层混淆：Latin-1/UTF-8 转换陷阱、JSON unicode escape、URL 双重编码等，本质都是"迭代单位与处理单位不一致"；
- 与 Android/iOS 其他多层加密链卡（RC4/XTEA/AES 变体）可组合比较；
- 检测要点：伪代码中 `__clz` 掩码与 `0xFEFEFEFEFEFEFF` 常量是 UTF-8 编码辅助，出现即提示存在重编码步骤。

## 检测与防御

- 逆向教学要点：先识别"迭代单位（scalar）≠ 加密单位（byte）"的结构性偏差，再逐层还原；
- 防御侧：混淆实现应显式按字节处理（`String.UTF8View`/`[UInt8]`），避免依赖隐式编码转换，否则行为依赖平台实现、易被模式化还原。
