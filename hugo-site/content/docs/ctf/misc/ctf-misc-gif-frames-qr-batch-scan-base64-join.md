---
id: ctf-misc-gif-frames-qr-batch-scan-base64-join
title: GIF 多帧二维码批量提取：分帧排序、pyzbar/OpenCV 双解码与 base64 片段拼接
type: scenario
domain: ctf
path: ctf/misc
technique: gif-frames-qr-batch-scan-base64-join
tags:
- ctf
- misc
- gif
- qr-code
- pyzbar
- opencv
- base64
- frame-extraction
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:26+08:00'
  notes: 已对照原文核对：GIF 分帧到 gifframe、pyzbar/OpenCV 双解码+旋转回退、按帧号排序拼接 base64、QnQSec{...}，与原文脚本/flag 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-gif-frames-qr-batch-scan-base64-join/
draft: false
kb_aliases:
- Catch Me
- GIF 分帧二维码
- 批量扫二维码
- pyzbar 批量解码
- QR base64 拼接
- 二维码分片 flag
---

## 一句话结论

当 GIF 的每一帧各含一个二维码、二维码内容只是 flag 的一段（常为 base64 片段）时，先按帧号导出全部帧并按数字排序，用 pyzbar 批量解码（失败时回退 OpenCV 并尝试 90/180/270 度旋转），再按帧序拼接各段并 base64 解码，即可还原完整 flag。

## 原理

- **GIF 分帧**：GIF 是多帧位图容器，`PIL.ImageSequence`/`ffmpeg`/ImageMagick 都能逐帧导出；题目通常把帧命名成 `0.png、1.png...`，需要按数字而非字典序排序，否则拼接顺序会错。
- **二维码承载分片**：单帧二维码容量有限，出题人把 flag 切段后分别编码进二维码；分片可能是明文片段，也可能是 base64（更常见，便于拼接任意字节）。
- **批量解码**：`pyzbar.decode()` 对清晰二维码成功率高；若某帧缩放/旋转/对比度异常，回退 `cv2.QRCodeDetector().detectAndDecodeMulti()`，并对帧做 90/180/270 度旋转再试。
- **拼接与解码**：按帧序收集所有二维码 payload，按题目约定拼接（直接连接、`|||` 分隔或先去重）；若拼接结果是 base64，`base64.b64decode` 后得到 flag；若含噪声，可按 flag 前缀定位有效片段。
- **为什么成立**：二维码是自同步的二维条码，单帧解码不依赖前后帧；只要每帧图像可读，批量脚本即可稳定提取；分片顺序由帧序号唯一确定。

## 触发条件

- 题目给出 GIF/APNG/视频，帧数较多且每帧含一个或多个二维码。
- 帧文件名或时间序可确定分片顺序；二维码内容为 flag 片段/base64。
- 本机可安装 `opencv-python`、`pyzbar`、`pillow`（pyzbar 还需系统 zbar 库）。
- 部分帧可能模糊、旋转或缺失，需要容错与多解码器回退。

## 利用步骤

1. 用 PIL 或 ffmpeg 导出全部帧到 `gifframe/`，按数字排序（`0.png ... 340.png`），记录缺失帧。
2. 对每帧先 `pyzbar.decode(PIL.Image.open(f).convert("RGB"))`；失败则用 OpenCV `QRCodeDetector` 的 `detectAndDecodeMulti`/`detectAndDecode`。
3. 仍失败时，把帧旋转 90/180/270 度重复步骤 2；记录每帧的解码结果与状态到 CSV/TXT 便于排查。
4. 按帧号排序收集 payload；若单帧有多个二维码，按检测顺序或题目约定排列。
5. 拼接所有片段（直接连接或按分隔符），尝试 `base64.b64decode(validate=True)`；失败则尝试去空白、补 `=`、URL-safe base64。
6. 用 `flag{`/`QnQSec{` 前缀校验结果；若顺序错乱，检查帧号排序与是否有多余/重复帧。

## PoC

```python
import base64, glob, os
import cv2
import numpy as np
from PIL import Image
from pyzbar import pyzbar

def decode_frame(path):
    pil = Image.open(path).convert("RGB")
    res = [d.data.decode("utf-8", "replace") for d in pyzbar.decode(pil)]
    if res:
        return res
    for angle in (0, 90, 180, 270):
        img = np.array(pil.rotate(angle, expand=True))[:, :, ::-1]
        ok, infos, *_ = cv2.QRCodeDetector().detectAndDecodeMulti(img)
        if ok and infos:
            return [s for s in infos if s]
    return []

frames = sorted(glob.glob("gifframe/*.png"),
                key=lambda p: int(os.path.splitext(os.path.basename(p))[0]))
parts = []
for f in frames:
    got = decode_frame(f)
    if got:
        parts.extend(got)
        print(f, got)

joined = "".join(parts)
for cand in (joined, joined.replace(" ", "")):
    try:
        print(base64.b64decode(cand, validate=True).decode())
        break
    except Exception:
        pass
```

## 变体与关联

- 变体：视频而非 GIF，用 ffmpeg 按帧率抽帧；二维码可能只出现在关键帧。
- 变体：二维码内容为十六进制/十进制坐标或密钥分片，需按题目规则重组（如按帧号 XOR、按序拼字节）。
- 变体：二维码被旋转/透视/遮挡，需 OpenCV 透视矫正或 `zxing-cpp` 解码。
- 关联：[[ctf-misc-png-trailing-data-lcg-xor-base62]]（图像载体分片 + 编码链）、[[ctf-forensics-video-single-pixel-channel-extraction]]（视频逐帧提取）、[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（分片拼接后的解密）。
- 边界：若二维码内容不是分片而是同一完整 flag 重复，直接取任一有效帧即可；若帧序无法确定，需要按内容语义/校验和排序。

## 检测与防御

- 检测（CTF）：GIF 帧数大、每帧中央高对比度方块；用 `zbarimg`/pyzbar 批量扫描可快速确认。
- 修复（出题/产品）：不要把敏感信息分片编码进可批量解码的二维码；二维码用于一次性令牌时应签名并限制有效期。
- 加固：对二维码内容做加密/签名，避免离线拼接；对批量扫描做速率限制与行为检测。
