---
id: code-analysis-reverse-firmware-ivanti-coreboot-initrd-xor-key-sector-iv-decrypt
title: Ivanti coreboot.img initrd 解密：内核 populate_rootfs 内 XOR 派生 AES key + 扇区号 IV 的链式分组解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: ivanti-coreboot-initrd-xor-key-sector-iv-decrypt
tags:
- firmware
- reverse
- ivanti
- initrd
- aes
- key-derivation
- sector-iv
- gzip
- zcat
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-ivanti-coreboot-initrd-xor-key-sector-iv-decrypt/
draft: false
kb_aliases:
- coreboot.img 解密
- Ivanti initrd 解密
- populate_rootfs 解密
- DSRAMFS_AES_KEY
- 扇区号 IV 链式 AES
- zcat 强制解压 initrd
---

## 一句话结论

Ivanti Connect Secure 启动分区的 `coreboot.img` 是加密的 initrd：内核 `populate_rootfs` 在 chroot 前用两组 64 位常量异或出 16 字节 AES key，再按 512 字节扇区、以扇区号的小端 16 字节值作 IV，对每个 16 字节块执行“密文异或 IV 派生值 → AES 解密 → 异或回 IV”的链式变换；解密结果是一个带脏数据的 gzip，`zcat` 强制解压即可得到 initrd 文件系统。

## 原理

- 设备的启动配置（grub 的 menuentry）把 initrd 指向 `coreboot.img`，内核启动后需要把 initrd 解包并 chroot 进去；`coreboot.img` 不是明文 cpio/gzip，而是被加密的容器。
- 内核中负责在 chroot 前处理 initrd 的函数是 `populate_rootfs`：它调用 `crypto_alloc_base("aes", 0, 0)` 申请 AES 变换，把两组 64 位常量 `DSRAMFS_AES_KEY` 和 `qword_FFFFFFFF81E00168` 分别与固定常量异或，拼成 16 字节 key（4 个 dword）：
  - key[0] = DSRAMFS_AES_KEY ^ 0x99ED2BF2
  - key[1] = HIDWORD(DSRAMFS_AES_KEY) ^ 0xAEEF41FE
  - key[2] = qword_FFFFFFFF81E00168 ^ 0x141058C7
  - key[3] = HIDWORD(qword_FFFFFFFF81E00168) ^ 0xD2ED180E
  随后把 key 交给 AES 变换的 setkey 指针（`tfm+8`）。
- 解密以 512 字节为一个扇区循环（`while (v14 > 0x1FF)`，每轮 `v14 -= 512`）：扇区索引 `v23` 被放进 16 字节 IV 的第一个 dword、其余清零，即 IV = sector_index（小端 16 字节）；先对 IV 做一次 AES 解密得到每扇区固定的 `pre_iv`；之后每个 16 字节密文块：
  - `ciphertext' = C ^ pre_iv`
  - `P = AES_decrypt(ciphertext') ^ IV`
  - `IV = C`（用原始密文块更新，形成块间链式）
- 因此它不是标准 CBC/CTR/ECB，而是“每扇区独立 IV + 块间用密文链式”的自定义分组模式；直接按标准 AES-ECB 解会得到乱码，必须先按上述顺序实现。
- 解密后的数据是 gzip 流，但末尾/中间混有未加密或填充的脏数据，`gzip -d` 会报 `unexpected end of file`；`zcat`（或 `gzip -dc -f`）可以忽略错误、尽可能输出已解压内容，从而拿到 initrd 文件系统目录。

## 触发条件

- 已获得 Ivanti Connect Secure 设备/固件镜像，能取出启动分区的 `coreboot.img`（或从磁盘镜像中定位）。
- 能取得对应的内核镜像（vmlinuz/bzImage）并定位 `populate_rootfs`，或已知该构建的 `DSRAMFS_AES_KEY`、`qword_FFFFFFFF81E00168` 与异或常量。
- 本机具备 Python 3 + pycryptodome（`Crypto.Cipher.AES`）与 tqdm，允许离线解密。
- 解密结果需要进一步 `zcat`/binwalk 提取；若 `coreboot.img` 已明文（未加密构建），则直接解包即可。

## 利用步骤

1. 从启动配置确认 initrd 文件名：grub 菜单中 `initrd /coreboot.img`；记录内核与 initrd 在分区中的路径。
2. 提取内核并用 IDA/Ghidra 搜索 `chroot` 字符串或 `populate_rootfs` 符号，定位 initrd 解密逻辑；对照 `crypto_alloc_base`、`DSRAMFS_AES_KEY`、扇区循环与 `0x1FF` 等特征确认。
3. 从反汇编读出两组 64 位常量与四个异或常量，按 key[0..3] 的公式拼出 16 字节 key；也可直接在调试器断在 AES setkey 处 dump key。
4. 按 512 字节扇区实现解密：IV = 扇区索引的小端 16 字节；`pre_iv = AES_decrypt(IV)`；对每个 16 字节块执行 `P = AES_decrypt(C ^ pre_iv) ^ IV`，再用原始 C 更新 IV；所有扇区按顺序拼接。
5. 输出文件用 `file` 检查：应为 `gzip compressed data`；直接 `gzip -d` 可能因脏数据报错，改用 `zcat new.gz > new` 或 `gzip -dc -f new.gz > new` 强制解压。
6. 对解出的 cpio/initramfs 用 `cpio -idm` 或 binwalk 提取，得到 `/bin`、`/lib`、`/modules` 等目录；随后即可分析 `libdsplibs.so`、`web` 等目标二进制。
7. 记录 key 常量与扇区参数；换固件版本时重新核对，不能直接套用旧 key。

## PoC

```python
from Crypto.Cipher import AES
from tqdm import tqdm

# 原文复现用的 16 字节 key（由内核中的两组 64 位常量异或得到；换构建需重新提取）
key = b'\xe1\xfc^\xb7\xd8AX\xda\xba\xd8\xeb\xbc\xf6\xcd*\x18'

encrypted_data = open('coreboot.img', 'rb').read()

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def decrypt_sector(sector):
    data = encrypted_data[sector * 512:(sector + 1) * 512]
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    def f(iv):
        pre_iv = cipher.decrypt(iv)
        for i in range(0, len(data), 16):
            ciphertext = xor(data[i:i+16], pre_iv)
            plaintext = cipher.decrypt(ciphertext)
            yield xor(plaintext, iv)
            iv = ciphertext

    iv = sector.to_bytes(length=16, byteorder='little')
    return b''.join(f(iv))

out = open('new.gz', 'wb')
for i in tqdm(range(1 + len(encrypted_data) // 512)):
    out.write(decrypt_sector(i))
out.close()
```

```bash
# 解密结果是带脏数据的 gzip，强制解压
zcat new.gz > new
# 或 gzip -dc -f new.gz > new
```

## 变体与关联

- 变体：不同构建的 `DSRAMFS_AES_KEY`/`qword_FFFFFFFF81E00168` 或异或常量不同，必须从对应内核重新提取；key 也可能在启动早期被替换。
- 变体：扇区大小不一定是 512（按 `while (v14 > 0x1FF)` 与 `v23 << 9` 判断为 512）；IV 也可能改用其他计数器字段，需对照反汇编。
- 变体：解密后若不是 gzip，可能是 cpio/lzma 等容器，用 `file`/binwalk 判断后再解包。
- 关联：[[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]]（另一种固件包的 AES-ECB + XOR 头密钥派生）、[[code-analysis-reverse-firmware-vmem-patch-console-script-shell]]（同设备 VMware 内存补丁取 Shell，可作为获取固件/文件的前置步骤）、[[binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop]]（解出 initrd 后分析 `web`/`libdsplibs.so` 的 CVE-2025-0282 利用链）。
- 边界：这是固件机密性保护而非漏洞；拿到设备或镜像即可离线解密，密钥必然存在于设备端。

## 检测与防御

- 检测（逆向侧）：内核引用 `coreboot.img`、`populate_rootfs` 中出现 `crypto_alloc_base`、`DSRAMFS_AES_KEY` 常量与 512 字节扇区循环；initrd 文件熵高且非 gzip/cpio 魔数。
- 防御（设备厂商）：固件加密只能提高分析成本，不能作为安全边界；密钥必须存放在设备端，攻击者获得镜像后可提取。
- 加固：把敏感逻辑/凭据放到安全区或服务端；对固件做签名与完整性校验；限制调试接口与镜像分发范围。
