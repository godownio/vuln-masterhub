---
id: ctf-forensics-video-8x8-block-bitmap-stego-xor-aa
title: 视频 8x8 块黑白位图隐写：逐帧采样还原文件并 XOR 0xAA
type: scenario
domain: ctf
path: ctf/forensics
technique: video-block-bitmap-file-stego
tags:
- ctf
- forensics
- stego
- video
- pixel-block
- bitmap
- xor
- opencv
- imageio
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:36:42+08:00'
  notes: 已对照原文re1与60张图核对：stager.py读取payload→8位二进制→每8位XOR 0xAA→640x480、8x8块、黑=1白=0、10fps写video.mp4；解码端逐帧取块左上像素、B+G+R<384判黑、8bit合成后XOR 0xAA；原文恢复出ELF(payload.dec)与卡内描述一致。未验证点：PoC未本机复跑（无原文视频样本）；CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-video-8x8-block-bitmap-stego-xor-aa/
draft: false
kb_aliases:
- 视频帧隐写
- 8x8 像素块编码
- 黑白位图视频
- file_to_video 逆向
- imageio 视频隐写
- XOR 0xAA 视频还原
---

## 一句话结论

把任意文件按字节转成二进制串、每 8 位与 `0xAA` 异或，再用每一位控制一个 8×8 像素块的黑/白（1=黑、0=白）写入 640×480 视频帧；分析时逐帧对每个块采样、按黑=1/白=0 还原比特流，每 8 位异或 `0xAA` 即可恢复原始文件（案例恢复出 ELF）。

## 原理

- 编码端（`file_to_video`）：
  1. 读取 `payload` 全部字节，转成 8 位二进制字符串；
  2. 每 8 位一组 `chunk_int ^ 0xAA`（`xor_key='10101010'`），重新格式化为 8 位，从而打散全 0/全 1 的长串；
  3. 以 640×480 帧、8×8 像素块为单位，每帧可承载 `(640/8)*(480/8)=80*60=4800` bit；
  4. `bit=1` 画黑块 `(0,0,0)`，`bit=0` 画白块 `(255,255,255)`；最后一帧不足补 0；
  5. 用 imageio + libx264、10 fps 写成 `video.mp4`。
- 解码端：
  1. OpenCV 逐帧读取，按 8×8 网格取每块左上角像素（块内颜色均匀，取边缘可避开压缩伪影）；
  2. `B+G+R < 128*3` 判为黑=1，否则白=0，按帧序拼接比特；
  3. 每 8 位合成字节后异或 `0xAA`，写入文件；
  4. 用文件头（ELF `7f 45 4c 46`、MZ、ZIP、PNG）验证并裁掉尾部补零。
- 为什么可行：视频编码保留了大面积纯色块的黑白对比；每块只承载 1 bit，冗余度高，即使 H.264 有损压缩也能通过阈值稳定判决。相比“单像素通道”隐写，本方法用空间块换鲁棒性，容量为 `帧数 × 块数` bit。
- 案例中 `payload.dec` 以 ELF 头开始，说明恢复成功；后续 IDA 分析该 ELF 得到 MD5 常量列表。

## 触发条件

- 拿到一个画面呈规则黑白方格/块状、且逐帧变化的视频（或拿到 `file_to_video` 生成脚本）；
- 知道或能推断帧尺寸与块大小（常见 640×480 + 8；也可尝试 4/8/16）；
- 视频未把黑白块压缩到难以区分（质量过低时需换采样点或阈值）；
- 能取得编码时的 XOR key（案例 `0xAA`；未知时可对 256 个单字节 key 试文件头）。

## 利用步骤

1. 用 `ffprobe`/OpenCV 读视频，确认帧尺寸、帧数、fps。
2. 观察首帧：统计 8×8 块的颜色方差，确认是纯黑/纯白块编码。
3. 逐帧按块采样，得到比特流；按 8 bit 一组转字节。
4. 对字节流尝试单字节 XOR（先从 0xAA 开始），检查常见文件头。
5. 命中文件头后按头部长度字段/格式解析裁掉补零，得到原始文件。
6. 若块大小未知，枚举 4/8/16 并重复，直到文件头出现。

## PoC

```python
import cv2
from pathlib import Path

cap = cv2.VideoCapture('video.mp4')
width, height, pixel_size = 640, 480, 8
blocks_x, blocks_y = width // pixel_size, height // pixel_size

bits = []
while True:
    ret, frame = cap.read()
    if not ret:
        break
    if frame.shape[1] != width or frame.shape[0] != height:
        frame = cv2.resize(frame, (width, height), interpolation=cv2.INTER_AREA)
    for r in range(blocks_y):
        y = r * pixel_size
        for c in range(blocks_x):
            x = c * pixel_size
            b, g, r_ = frame[y, x]
            bits.append('1' if int(b) + int(g) + int(r_) < 128 * 3 else '0')
cap.release()

out = bytearray()
for i in range(0, len(bits) - 7, 8):
    out.append(int(''.join(bits[i:i + 8]), 2) ^ 0xAA)
Path('payload.dec').write_bytes(out)
print('first bytes:', bytes(out[:8]).hex())
```

```python
# 编码端核心（原文 file_to_video 的逻辑还原）
xor_key = '10101010'
binary_string = ''.join(f'{b:08b}' for b in Path('payload').read_bytes())
binary_string = ''.join(
    f'{int(binary_string[i:i+8], 2) ^ int(xor_key, 2):08b}'
    for i in range(0, len(binary_string) - 7, 8)
)
# 每帧 4800 bit，1 -> 黑块，0 -> 白块，imageio 写 video.mp4
```

## 变体与关联

- 变体：块大小 4/8/16、彩色块编码多 bit、每帧多通道、用 QR/条码帧、在 LSB 而非块颜色存 bit。
- 关联 [[ctf-forensics-video-single-pixel-channel-extraction]]：同样从视频逐帧取像素，但那张卡是固定坐标单像素通道，本卡是 8×8 块位图编码。
- 关联 [[ctf-forensics-pdf-embedded-images-contact-sheet-vertical-strip]]：都是把文件编码进视觉载体后逆向提取。
- 边界：视频被强有损压缩、黑白块边界模糊或帧尺寸/块大小未知且试错成本高时，需要更稳的采样与纠错。

## 检测与防御

- CTF/取证检测：视频画面呈规则黑白块、块内方差接近 0、帧数 × 块数 ≈ 文件大小 × 8；用 OpenCV 统计块均值直方图可快速识别。
- 数据外带检测：监控生成的大帧数、纯黑白块视频文件；对视频重新编码后做块级熵分析，异常低熵块序列告警。
- 防御：隐写不是安全边界；敏感环境应限制大文件外传与视频编码工具，结合 DLP 对“文件→视频”转换行为审计。
