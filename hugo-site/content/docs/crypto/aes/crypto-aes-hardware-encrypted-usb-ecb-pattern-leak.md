---
id: crypto-aes-hardware-encrypted-usb-ecb-pattern-leak
title: 硬件加密 USB 盘使用 AES-ECB：相同 16 字节明文生成相同密文，密文保留数据模式
type: scenario
domain: crypto
path: crypto/aes
technique: aes-ecb-deterministic-pattern-leak
tags:
- crypto
- aes
- ecb
- hardware
- usb
- pattern-leak
cve:
- CVE-2022-28382
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:44:23+08:00'
  notes: 已对照原文与截图06/08：CVE-2022-28382 经 NVD 确认为 INIC-3637EN 固件使用 AES-256-ECB；原文向已解锁设备写已知模式后裸读 SSD，观察到相同 16 字节明文对应相同密文（hexdump 中 c41d4658... 在 0x0 与 0x1d0 重复），并给出 ECB Tux 图，与卡片一致。dedup 候选中 fixed-key ECB 复现、ECB 逐字节 oracle 等场景不同，非同链；硬件产品原文无固件版本，不设 affected_versions。
url: /docs/crypto/aes/crypto-aes-hardware-encrypted-usb-ecb-pattern-leak/
draft: false
kb_aliases:
- AES-ECB 模式泄露
- 硬件加密盘 ECB
- 相同明文相同密文
- 密文模式泄露
---

## 一句话结论

标称 AES-256 硬件加密的 USB 盘实际使用 ECB 模式（无 IV、无扩散）：向已解锁设备写入已知字节模式后，相同的 16 字节明文总是产生相同的 16 字节密文，裸读 SSD 时密文保留明文块的结构与重复模式，可据此推断文件类型、内容位置甚至轮廓。

## 原理

- **ECB 的确定性**：ECB 对每个 16 字节块独立加密，不使用 IV/nonce，相同密钥下相同明文块必然得到相同密文块；没有链式反馈，一块的变化不影响其他块，密文因此保留明文的数据模式。
- **原文验证**：对一个已解锁设备写入已知字节模式，再直接读取裸 SSD 做 hexdump，观察到相同 16 字节明文序列（如 `c4 1d 46 58 05 68 1d 9a 32 2d 29 04 f4 20 e8 4d`）在密文中连续重复数百次，确认加密为 16 字节分组、ECB 类模式（AES-256-ECB）。
- **泄露的后果**：全零块、文件系统结构、图片低熵区域在密文中同样重复；配合已知明文（文件头、固定文件名、可预测内容）可以定位和确认数据块，甚至在密文里看出明文轮廓（经典 ECB 加密企鹅图效应）。
- **成立前提**：攻击者能读取裸存储介质（物理接触、拆出 SSD、直接读块设备）或获得密文；要进一步推断内容通常还需要已知明文或可重复写入已知模式的能力。

## 触发条件

- 存储设备/软件使用 ECB 模式做全盘或文件加密，且宣称具有硬件加密强度。
- 攻击者可读取密文（裸盘、镜像、块设备）。
- 可写入已知模式（设备已解锁）或掌握部分已知明文用于比对。

## 利用步骤

1. 拆出存储介质或读取块设备，获取密文镜像。
2. 对密文 `hexdump -C`，观察 16 字节对齐的重复块（相同序列间隔重复、大量相同块）。
3. 对已解锁设备写入已知模式（全 0、递增字节、已知文件），再次读取并对比，确认相同明文块产生相同密文块 → 判定 ECB。
4. 结合已知明文/文件结构（文件头、清零区域）对密文块做匹配，推断存储内容布局与类型；ECB 下可直接对密文块做重排/裁剪攻击（不改变可解密性）。
5. 若目标是窃取内容，将 ECB 识别结果作为已知明文攻击/内容重建的前提。

## PoC

```text
# hexdump -C /dev/sda
00000000  c4 1d 46 58 05 68 1d 9a  32 2d 29 04 f4 20 e8 4d  |..FX.h..2-).. .M|
*
000001d0  c4 1d 46 58 05 68 1d 9a  32 2d 29 04 f4 20 e8 4d  |..FX.h..2-).. .M|
*
```

相同 16 字节密文块在地址 0x0 起与 0x1d0 起重复出现，说明对应明文块相同且加密为 ECB 类确定性分组模式。

## 变体与关联

- 变体：CBC 使用全零/固定 IV 时首块也会暴露相同模式；CTR 固定 nonce 会泄露相同计数块；识别思路相同——寻找 16 字节对齐的密文重复。
- 关联：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（二进制内固定 key/明文的 ECB 复现，ECB 确定性属性的另一利用面）、[[iot-hardware-usb-encrypted-drive-offline-passcode-crack]]（同设备的密码派生缺陷）、[[iot-hardware-spi-firmware-crc16-patch-aes-key-extract]]（固件取密钥后可完全解密）。
- 边界：使用 XTS/CBC 随机 IV/GCM 等带扩散的模式时不成立；仅有密文而无任何已知明文时，只能做块级模式统计。

## 检测与防御

- 修复：全盘/便携存储加密使用 XTS-AES（块存储标准）或带随机 IV 的 CBC/GCM；不要用 ECB。
- 加固：每设备唯一密钥、随机 IV/salt；对加密存储实现做密码学审查，验证不存在 ECB 指纹（密文重复块）。
- 检测：对加密磁盘镜像做密文重复块统计，16 字节对齐重复即为 ECB 强特征；代码审计中检查 `MODE_ECB` 的使用。
