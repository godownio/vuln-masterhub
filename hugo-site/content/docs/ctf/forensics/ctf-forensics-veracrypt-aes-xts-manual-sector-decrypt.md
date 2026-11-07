---
id: ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt
title: VeraCrypt AES-XTS 数据区手动解密：已知 master key 按扇区还原裸盘
type: scenario
domain: ctf
path: ctf/forensics
technique: veracrypt-aes-xts-manual-sector-decrypt
tags:
- ctf
- forensics
- veracrypt
- aes-xts
- disk-image
- sector
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:47+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt/
draft: false
kb_aliases:
- VeraCrypt 手动解密
- AES-XTS
- master key
- 数据区解密
- fruit.bin
- Cake
---

## 一句话结论

当拿到 VeraCrypt 容器的“数据区”（无 header）和 64 字节 master key（前 32 字节 AES-XTS data key、后 32 字节 tweak key）时，可按 512 字节扇区手动解密：tweak 取扇区号的 16 字节小端，AES-XTS 解密每个扇区，拼接后得到裸磁盘镜像，再解析文件系统/文本。

## 原理

- **VeraCrypt AES-XTS**：数据区按扇区加密，XTS 使用 64 字节 key（两个 32 字节 AES key：data key + tweak key）和 16 字节 tweak；tweak 通常由扇区号（little-endian）构成。
- **数据区偏移**：VeraCrypt 容器 = header（通常 128KB/0x20000）+ 数据区；若题目只给数据区（`fruit.bin`），则从偏移 0 开始，但扇区号仍从 header 后的绝对扇区号算（本题 `START_SECTOR=256`，因为 0x20000/512=256）。
- **手动解密**：对每个 512 字节扇区 `i`，`sector_no=START_SECTOR+i`，`tweak=sector_no.to_bytes(16,'little')`，`AES-XTS(key, tweak).decrypt(sector)`；拼接所有扇区得到 `fruit_decrypted.img`。
- **后续**：裸盘镜像可用 `file`/`mmls`/`fsstat`/`7z` 解析；本题解出 txt 数字 → 网站 → 坐标 (123,45) → 视频该像素通道提取 flag。
- **为什么成立**：XTS 是确定性可逆加密，key/tweak/扇区号正确时解密即得明文；不需要 VeraCrypt 挂载/密码。
- **边界**：key 顺序（data/tweak）或扇区号偏移错误会得到乱码；容器有 header 时需先解析 header/密钥；不同加密算法（Serpent/Twofish）不适用。

## 触发条件

- 有 VeraCrypt 数据区文件（可能无 header/被截断）和 64 字节 master key（128 hex 字符）。
- 已知/可推断数据区起始扇区（本题 256）与扇区大小（512）。
- 加密算法为 AES-XTS；key 顺序为 data key + tweak key。
- 有 `cryptography`/`pycryptodome` 等 AES-XTS 实现，或能调用 VeraCrypt。

## 利用步骤

1. 读取 key 文件（可能含 `key:` 前缀），转 64 字节；确认前 32 字节 data key、后 32 字节 tweak key。
2. 确认数据区偏移/起始扇区（本题 `0x20000` = 256 扇区）和扇区大小 512。
3. 对每个扇区构造 `tweak=sector_no.to_bytes(16,'little')`，用 AES-XTS 解密；拼接。
4. 保存为 `.img`，用 `file`/`fsstat`/`7z l`/`strings` 解析；本题得到 txt 数字。
5. 按后续提示（网站/坐标/视频像素）继续提取；本题最终 flag 在视频指定像素通道。
6. 若解密乱码，交换 data/tweak key、调整起始扇区/字节序、确认 key 是否被再哈希。

## PoC

```python
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SECTOR_SIZE = 512
START_SECTOR = 256

def load_master_key(path):
    text = Path(path).read_text().strip()
    key_hex = text.split(":", 1)[1].strip() if ":" in text else text
    key = bytes.fromhex(key_hex)
    assert len(key) == 64
    return key

def decrypt_sector(ciphertext, key, sector_no):
    tweak = sector_no.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

key = load_master_key("passwd.txt")
data = Path("fruit.bin").read_bytes()
enc = data[0x20000:0x2e0000]

out = bytearray()
for i in range(0, len(enc), SECTOR_SIZE):
    sector = enc[i:i + SECTOR_SIZE]
    sector_no = START_SECTOR + i // SECTOR_SIZE
    out += decrypt_sector(sector, key, sector_no)

Path("fruit_decrypted.img").write_bytes(out)
print("[+] decrypted -> fruit_decrypted.img")
```

## 变体与关联

- **变体（有 header）**：先解析 VeraCrypt header（salt/加密 header/密钥区），用密码派生 key 解密 header 得到 master key；或直接用 VeraCrypt 挂载。
- **变体（其他算法）**：Serpent/Twofish/AES 组合；XTS 结构相同但算法不同。
- **变体（后续隐写）**：裸盘中的文本/文件、视频单像素通道、图片 LSB；本题视频坐标为 `(123,45)`。
- **关联卡片**：[[defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence]]（VeraCrypt key 取证）、[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]（磁盘镜像取证）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层隐写）。
- **边界**：key 顺序/起始扇区/字节序错误会失败；数据区被截断/损坏时只能恢复部分；非 AES-XTS 不适用。

## 检测与防御

- **CTF 识别**：VeraCrypt + 64 字节 key + 无 header 数据区，按扇区 AES-XTS 手动解密。
- **取证**：保留原始容器/数据区与 key；记录起始扇区/算法；用多工具验证解密结果。
- **安全**：VeraCrypt 安全性依赖密码/header；master key 泄露即等同于容器失陷；不要把 master key 与数据区放在同一位置。
