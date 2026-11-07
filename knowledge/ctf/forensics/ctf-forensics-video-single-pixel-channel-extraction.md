---
id: ctf-forensics-video-single-pixel-channel-extraction
title: 视频单像素通道隐写：逐帧读取指定坐标的 B/G/R 值还原字符流
type: scenario
domain: ctf
path: ctf/forensics
technique: video-single-pixel-channel-extraction
aliases:
- 视频像素隐写
- 单像素通道
- 逐帧取色
- OpenCV 视频隐写
- Cake
tags:
- ctf
- forensics
- stego
- video
- pixel
- channel
- opencv
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:52+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
---

## 一句话结论

当视频中某个固定坐标的像素颜色在每帧变化、而周围画面正常时，可以逐帧读取该像素的 B/G/R 值，把某个通道的数值按帧序转成字符/字节，还原隐藏的 flag；本题坐标来自前置层解出的 `(123,45)`，某个通道持续携带数据。

## 原理

- **单像素通道隐写**：视频编码器保留像素颜色（尤其无损/高质量编码）；把每个字符的 ASCII/字节写入固定坐标的某个颜色通道，逐帧变化即可传递数据。
- **为什么用单像素**：改动面积极小，肉眼不可见；压缩算法对单个像素的高频变化可能有一定容忍（高质量/无损时更可靠）。
- **提取**：用 OpenCV `cap.read()` 逐帧取 `frame[y,x]`，得到 `(b,g,r)`；观察哪个通道随帧变化且值在可打印 ASCII 范围，按帧序拼接。
- **本题**：VeraCrypt 层解出的 txt 数字经网站转换得到坐标 `(123,45)`；视频该位置一直有一个通道有数据，转字符得到 flag。
- **边界**：有损压缩（H.264 低码率）会改变像素值，需按最近值/阈值映射；坐标/通道/位序需按题目提示；帧率/分辨率变化会错位。

## 触发条件

- 视频文件体积/内容异常，或题目提示“视频/像素/坐标/帧”。
- 已知或可解出目标坐标 `(x,y)`；某个通道随帧变化。
- 视频编码质量足够（无损/高码率），或隐藏值用容错编码。
- 有 OpenCV/ffmpeg 逐帧读取能力。

## 利用步骤

1. 用 `ffprobe` 查看分辨率/帧率/编码；用 OpenCV 逐帧读取。
2. 对目标坐标 `(x,y)` 取每帧 `(b,g,r)`，输出 CSV/列表。
3. 观察哪个通道变化；把值映射到 ASCII（直接 `chr(value)`、`value-偏移`、或按阈值二值化）。
4. 按帧序拼接，检查 `flag{` 前缀；若乱码，尝试 B/G/R 顺序、反向、差值/异或。
5. 本题得到 flag；用前置层（VeraCrypt/网站/坐标）串联验证。
6. 若有损压缩导致值漂移，按最近可打印字符/聚类恢复。

## PoC

```python
import cv2

cap = cv2.VideoCapture("scream.avi")
x, y = 123, 45
chars = []
while True:
    ok, frame = cap.read()
    if not ok:
        break
    b, g, r = [int(v) for v in frame[y, x]]
    # 按题目选择通道；示例用 b 通道
    if 32 <= b < 127:
        chars.append(chr(b))
cap.release()
print("".join(chars))
```

## 变体与关联

- **变体（通道/位）**：B/G/R 任一通道、低位、通道差值；逐帧/逐像素块。
- **变体（编码）**：ASCII 直接写、二进制位、阈值二值化、CRC/纠错；按可读性尝试。
- **变体（视频容器）**：AVI 无损、MP4/H.264、GIF；无损优先。
- **关联卡片**：[[ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt]]（本题前置层）、[[ctf-forensics-png-lsb-column-major-scan-order]]（像素 LSB）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层媒体隐写）。
- **边界**：有损压缩/缩放/裁剪会破坏单像素值；坐标错误/帧序错位会得到乱码；需要原始视频。

## 检测与防御

- **CTF 识别**：视频 + 坐标 + 单像素通道变化，按帧提取。
- **取证**：保留原始视频；记录分辨率/帧率/编码；用多通道交叉验证。
- **安全**：单像素隐写容量低但隐蔽；DLP 可检测固定坐标时序异常；敏感数据不要用视频隐写。
