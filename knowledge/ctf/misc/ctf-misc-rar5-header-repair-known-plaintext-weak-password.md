---
id: ctf-misc-rar5-header-repair-known-plaintext-weak-password
title: RAR5 加密归档 + 注释泄露内层文件头：弱口令爆破后修复图片文件头取二维码
type: scenario
domain: ctf
path: ctf/misc
technique: rar5-header-repair-known-plaintext-weak-password
aliases:
- RAR5 明文爆破
- 压缩包注释已知明文
- 二维码图片头修复
- RAR5 数据加密
- 弱口令压缩包
tags:
- ctf
- misc
- rar5
- archive
- known-plaintext
- weak-password
- header-repair
- qr
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:22+08:00'
  notes: 已对照原文与图6-10核对并修正卡片：RAR5 数据加密（AES-256），注释泄露内层 JPEG 头 FFD8FFE000104A46494600，弱口令 123456789；原文“010 修复文件头”发生在解压出二维码图片之后，卡内已改为修复图片头而非 RAR 头。未复跑爆破/修复。
---

## 一句话结论

题目给的文件没有 `.rar` 扩展名，但 010 查看开头是 `Rar!`；7z 识别为 RAR5 且数据加密（AES-256），归档注释里泄露了内层 JPEG 的文件头 `FFD8FFE000104A464946...`，可用来快速验证候选口令；对弱口令爆破得到 `123456789` 后解压，再用 010 修复解压出的二维码图片文件头，扫码即得 flag。

## 原理

- 文件识别：RAR5 签名是 `52 61 72 21 1A 07 01 00`（ASCII `Rar!` + 版本/标志）。题目故意改扩展名/加壳，先用 010 或 `file` 看魔数，再交给 7-Zip；7-Zip 的“属性”会显示 `Rar5`、`v6:128k AES-256`、`加密 +` 等。
- 数据加密与注释：7-Zip 属性显示“加密 +”与 `v6:128k AES-256`，说明归档数据已加密；注释仍可读，说明归档头/注释未被加密（原文未展示文件列表，是否启用“加密文件名”无法从截图确认）。因此可以先看到注释中的已知明文，再对归档做口令爆破。
- 已知明文/校验：7-Zip 属性里的“注释”给出了内层文件的文件头（JPEG 的 `FFD8FFE0...`）。RAR5 使用 PBKDF2-HMAC-SHA256 + AES-256-CBC，已知明文本身不能直接恢复密钥，但可在爆破时解密候选口令对应的数据块并与已知文件头比对，作为快速验证 oracle，省去完整解压；本题口令是弱口令 `123456789`，很快命中。
- 文件头修复：RAR 归档本身可被 7z 正常识别，原文的“010 修复文件头”发生在解压出二维码图片之后；应修复解压出的图片文件头（按 JPEG/PNG 等格式补齐签名与必要字段），而不是修改 RAR 头。修复后扫码得到 flag。
- 成立关键：归档使用弱口令 + 注释/题目提供了已知明文，使口令空间可被有效枚举；若口令强或没有校验线索，爆破不可行。

## 触发条件

- CTF misc 压缩包题：文件魔数与扩展名不一致，或文件头被截断/篡改。
- 归档为 RAR5（或 RAR3），数据加密；7z 提示输入口令。
- 归档注释、题目附件或已知文件格式泄露了内层文件的已知明文/文件头，可用于验证候选口令。
- 口令为弱口令/字典可覆盖（本题 `123456789`）。
- 解压出的图片文件头损坏、修复后能得到二维码等可解码内容。

## 利用步骤

1. 用 010/`file` 查看文件头：`52 61 72 21 1A 07 01 00` 判定 RAR5；用 7z 打开，确认数据加密（AES-256）与可读注释。
2. 查看 7-Zip 属性中的注释或题目提示，记录已知文件头（如 JPEG `FFD8FFE000104A464946...`）。
3. 对 RAR5 做弱口令爆破：`hashcat -m 13000`（RAR5）配 rockyou/掩码，或用带已知明文校验的爆破工具；原文得到口令 `123456789`。
4. 用口令解压；若解压出的二维码图片文件头损坏，按图片格式在 010 中补齐/修复文件头（必要时参考同版本正常图片的头部结构），不要修改 RAR 头。
5. 修复后的二维码图片用 QR Research 等扫码，得到 flag。

## PoC

```bash
# 1) 识别魔数（RAR5: 52 61 72 21 1A 07 01 00）
xxd -l 16 flag.blf

# 2) 7z 查看属性/注释，确认 Rar5 + AES-256（数据加密）
7z l flag.blf

# 3) RAR5 弱口令爆破（等价工具链；原文使用图形化爆破工具）
hashcat -m 13000 flag.blf rockyou.txt
# 或：rar2john flag.blf > rar.hash && john rar.hash

# 4) 原文结果
# 爆破成功，正确密码为：123456789
```

```text
# 5) 解压后用 010 修复二维码图片文件头；QR Research 扫码：
fxyj760umlfca9xdjl0cye7gde7d00c28da982d9ALW8InzKyYip6JShjP1qBVt9buXRMc4aZdlight
```

说明：原文未给出“明文爆破”的具体工具/算法与修复前后的字节差异，只给出结果截图；RAR5 AES 下已知明文只用于验证候选口令，并不直接恢复密钥，实际有效步骤是弱口令爆破。原文的“010 修复文件头”发生在解压出二维码图片之后，不能据此认定 RAR 头损坏。

## 变体与关联

- 变体（RAR3）：`hashcat -m 12500`；RAR3 的已知明文攻击/旧版漏洞与 RAR5 不同，需按版本选择。
- 变体（ZIP）：ZipCrypto 可用 bkcrack 已知明文攻击；伪加密可改标志位；见关联卡。
- 变体（文件头）：解压出的图片只缺若干字节时按图片签名补齐；RAR 头本身损坏时，才需要用同版本 RAR 的头部模板重建。
- 关联：[[ctf-forensics-bkcrack-d-raw-inflate-nested-zip]]（ZIP 已知明文）、[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（ZIP 头修复/伪加密）、[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]（图片尾附压缩包）。
- 边界：口令强且无字典/掩码线索时爆破不可行；RAR5 加密数据下无法只靠已知明文恢复密钥；图片文件头损坏严重时需完整重建。

## 检测与防御

- 这是 CTF 解题流程；对真实场景的启示是：压缩包口令强度决定离线爆破可行性，弱口令 + 已知明文会显著加速验证。
- 防御：使用强口令/密钥文件；不要把明文文件头、注释或可预测内容放进加密归档；对敏感归档使用现代加密工具并限制分发。
- 检测：监控高强度压缩包口令尝试、异常解压行为；DLP 关注带密码附件与注释中的明文特征。
