---
id: ctf-forensics-lsb-watermark-timestamp-aesctr-permutation
title: LSB 截图水印提取：时间戳种子 AES-CTR + 置换索引 + 3 次重复，暴力时间戳还原姓名工号
type: scenario
domain: ctf
path: ctf/forensics
technique: lsb-watermark-timestamp-seeded-aesctr-permutation
tags:
- ctf
- forensics
- steganography
- lsb
- png
- aes-ctr
- timestamp
- bruteforce
- watermark
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:06:45+08:00'
  notes: 已对照原文与图06/07核对：蓝通道LSB、SHA-256(perm:perm-v1|ts|HxW)置换、3次重复多数表决、LSB3 magic+长度+CRC32、random.Random(ts)派生AES-CTR key/nonce、时间戳区间1757054010–1757054090逐秒爆破，原文输出刘晓艺:3009865，与卡一致。未验证点：未在本机复跑；frontmatter无sources/source_url；无版本。
url: /docs/ctf/forensics/ctf-forensics-lsb-watermark-timestamp-aesctr-permutation/
draft: false
kb_aliases:
- LSB3 水印
- 截图隐写 姓名工号
- 蓝通道 LSB 提取
- 时间戳暴力水印
- stegoexp
- AES-CTR 时间戳密钥
---

## 一句话结论

某 IM 截图工具把“姓名:工号”水印写入 PNG 蓝通道 LSB：比特先按 `SHA-256("perm:perm-v1|ts|HxW")` 种子的随机置换打散、每比特重复 3 次，再用 Python `random.Random(ts)` 派生的 AES-CTR key/nonce 加密，并带 `LSB3` magic、长度与 CRC32；由于时间戳同时决定置换和密钥，只要知道大致时间范围（文件 mtime/截图时间），逐秒暴力并用 magic+CRC 校验，就能解密出水印（原文还原出 `刘晓艺:3009865`）。

## 原理

- **载体与位序**：取 RGB 图像蓝通道 `arr[:,:,2].reshape(-1) & 1` 作为 LSB 比特流；载荷按行优先展平后的像素顺序写入。
- **随机置换**：`perm = np.random.default_rng(int.from_bytes(sha256(f"perm:{SALT}|ts:{H}x{W}").digest()[:8], "big")).permutation(H*W)`。时间戳 ts 参与种子，导致每次截图的水印位置不同；不知道 ts 就无法确定哪些像素承载载荷。
- **重复编码**：每个载荷比特重复写 3 次；提取时按 3 个一组做多数表决（`sum(chunk) > len(chunk)//2`），提高抗裁剪/压缩/噪声能力。
- **头部与完整性**：头部 32 字节 = magic `LSB3`(4) + 数据长度(4) + 其余；按长度再取密文与 CRC32。CRC 使得错误时间戳几乎必然被过滤，成为暴力搜索的判别器。
- **时间戳派生密钥**：`random.Random(ts)` 是 Mersenne Twister，`getrandbits(8)` 连续取 16 字节作 AES key、再取 8 字节作 CTR nonce；密钥完全由公开可猜的时间戳决定，没有任何秘密。
- **为什么能还原**：水印算法的安全性依赖“时间戳不可知”，但截图文件本身带有 mtime、聊天记录时间、文件名/目录名里的时间等线索；秒级时间戳空间很小，逐秒尝试即可。CRC 与 magic 使错误候选立即淘汰，正确候选解出 UTF-8 明文。

## 触发条件

- 拿到带水印的 PNG 截图（原图未被重新压缩/缩放破坏 LSB）。
- 知道水印算法或能猜测其结构（本卡对应 `LSB3` + 置换 + 3 次重复 + AES-CTR）。
- 知道大致时间范围（文件 mtime、截图时间、文件名中的时间戳等），可把暴力空间缩到秒/分钟级。
- 图像尺寸 H×W 已知（直接从 PNG 读取），用于复现置换种子。

## 利用步骤

1. 读取 PNG，转 RGB，取蓝通道 LSB 比特流；记录 H、W。
2. 设定时间戳候选区间（如文件 mtime 前后 60 秒；原文为 1757054010–1757054090）。
3. 对每个 ts：按 `perm:{salt}|ts:{H}x{W}` 的 SHA-256 前 8 字节作种子生成 permutation；取前 `32*8*3` 个位置，3 位一组多数表决得到 32 字节头部。
4. 校验头部前 4 字节是否为 `LSB3`；读取长度 L，计算总位数 `(8 + L + 4)*8*3`，提取完整比特流并按 3 位表决还原字节。
5. 解析密文与 CRC32，校验 `zlib.crc32(ciphertext)`；不匹配则换下一个 ts。
6. 用 `random.Random(ts)` 生成 16 字节 key + 8 字节 nonce，AES-CTR 解密，UTF-8 解码得到水印明文（姓名:工号）。

## PoC

```python
import struct, zlib, random
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from hashlib import sha256

MAGIC, REP, SALT = b"LSB3", 3, "perm-v1"

def prng_bytes(ts, n):
    rng = random.Random(ts)
    return bytes(rng.getrandbits(8) for _ in range(n))

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits):
                b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)

def vote(bits, rep):
    return [1 if sum(bits[i:i+rep]) > len(bits[i:i+rep]) // 2 else 0
            for i in range(0, len(bits), rep) if bits[i:i+rep]]

def perm_indices(ts, H, W, salt=SALT):
    seed = int.from_bytes(sha256(f"perm:{salt}|ts:{ts}|{H}x{W}".encode()).digest()[:8], "big")
    return np.random.default_rng(seed).permutation(H * W)

def extract(path, ts):
    arr = np.array(Image.open(path).convert("RGB"), dtype=np.uint8)
    H, W, _ = arr.shape
    lsb = (arr[:, :, 2].reshape(-1) & 1).astype(np.uint8)
    perm = perm_indices(ts, H, W)
    head = bits_to_bytes(vote(lsb[perm[:32 * 8 * REP]], REP))
    if head[:4] != MAGIC:
        return None
    length = struct.unpack(">I", head[4:8])[0]
    nbits = (8 + length + 4) * 8 * REP
    data = bits_to_bytes(vote(lsb[perm[:nbits]], REP))
    ct = data[8:8 + length]
    crc = struct.unpack(">I", data[8 + length:12 + length])[0]
    if zlib.crc32(ct) & 0xFFFFFFFF != crc:
        return None
    key, nonce = prng_bytes(ts, 16), prng_bytes(ts, 8)[:8]
    return AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct).decode("utf-8")

for ts in range(1757054010, 1757054091):   # 文件 mtime 附近
    r = extract("leak.png", ts)
    if r:
        print(ts, r)   # 原文输出：刘晓艺:3009865
        break
```

## 变体与关联

- 时间来源变体：PNG tEXt/EXIF 时间、文件名中的 Unix 时间戳、聊天记录发送时间、目录名 `1757561872...`；先缩小到分钟再逐秒。
- 编码变体：重复次数 1/5、LSB 取红/绿通道、行优先/列优先、MSB 优先；可先用已知明文/magic 试探位序。
- 密钥变体：AES-CBC/GCM、key 由时间戳+用户名派生、固定 nonce；只要密钥可预测就可解密。
- 关联：[[ctf-forensics-png-lsb-column-major-scan-order]]（列优先 LSB）、[[ctf-reverse-predictable-score-derived-aes-key-iv]]（可预测分数派生 AES key/IV）、[[ctf-misc-apng-fctl-delay-num-ascii-stego]]（其他 PNG 隐写）。
- 边界：截图被重新压缩/缩放/加噪会破坏 LSB；时间戳完全未知且范围很大时暴力成本上升；算法/盐值未知时需先逆向工具或做结构猜测。

## 检测与防御

- 取证检测：蓝通道 LSB 平面存在非随机分布/周期性；`LSB3` magic 或 CRC 结构；按时间戳候选能解出 UTF-8 明文。可用 `zsteg`、`stegsolve` 先做通道/位平面预览。
- 防御（水印工具设计者）：不要用公开时间戳直接派生密钥；使用秘密密钥/HMAC 或服务端密钥，时间戳只作 nonce 并签名；对水印载荷加密+认证。
- 防御（防泄露溯源）：水印应能抵抗压缩/裁剪（频域/鲁棒水印）；同时记录签发日志，避免仅依赖可伪造的截图水印。
- 响应：确认泄露截图的水印身份后，结合访问日志与工号追溯；轮换泄露账号权限并排查其他外发文件。
