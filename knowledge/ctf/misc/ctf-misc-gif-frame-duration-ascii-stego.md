---
id: ctf-misc-gif-frame-duration-ascii-stego
title: GIF 帧间隔隐写：延迟时间按 10ms 单位编码 ASCII/二进制
type: scenario
domain: ctf
path: ctf/misc
technique: gif-frame-duration-ascii-stego
aliases:
- GIF 帧间隔隐写
- GIF 帧时长隐写
- GCE Delay 隐写
- 帧延迟 ASCII
- PuzzleSolver GIF帧间隔
tags:
- ctf
- misc
- gif
- stego
- frame-duration
- gce
- ascii
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:57:45+08:00'
  notes: 已对照原文与截图核对：delay序列720/650/800...÷10=HAPPYNEWYEAR2026，为ASCII十进制编码；卡内指出原文解码片段duration%10与截图的÷10编码不一致、%10恒0，属正确纠错；未验证点：未对gif复跑。
---

## 一句话结论

GIF 每帧的 Graphic Control Extension（GCE）延迟时间以 10ms 为单位，把 ASCII 码或二进制位写进延迟值，再按帧序读取每帧 `duration` 并除以 10（或取奇偶位）即可还原隐藏字符串。

## 原理

- GIF 动画由多帧组成，每帧前可带一个 GCE（`21 F9 04`），其中的 Delay Time 是 16 位无符号整数，单位为 1/100 秒（即 10ms）。
- Pillow 读取时把 `GifImageFile.info["duration"]` 换算成毫秒返回，因此 `duration // 10` 就是 GIF 里存的原始 delay 值；同样，保存时 `duration` 参数按毫秒给出，最终会量化回 10ms。
- 本次题目的编码是“delay = ASCII 码”：例如 `duration=720` → `720//10=72` → `chr(72)='H'`。连续读取得到 `720,650,800,800,890,780,690,870,890,...`，除以 10 后正好是 `HAPPYNEWYEAR2026`。
- 另一种常见变体是把 delay 的奇偶性当作 0/1 位：`bit = (duration // 10) & 1`，每 8 位转 ASCII。注意不要用 `duration % 10`：GIF 的量化单位是 10ms，毫秒值永远是 10 的倍数，`% 10` 恒为 0；即使某些库保存时保留了 1ms，也会在写 GIF 时被量化掉。
- 为什么隐蔽：帧延迟只影响播放速度，肉眼几乎察觉不到；常规图片查看器/缩略图不显示 delay，只有逐帧读取 GCE 或专用工具才能看到。

## 触发条件

- 文件确实是 GIF（`GIF89a`/`GIF87a`），帧数较多，且延迟值出现非整百、非标准的 10ms 倍数（如 480、650、720、890）。
- 帧数 × 每字符位宽与可疑明文长度匹配；题目提示“GIF/帧/间隔/时间”。
- 用 `identify -verbose`、`exiftool`、Pillow 或 PuzzleSolver 的“GIF 帧间隔”功能能看到每帧 delay。
- 文件可能被重新编码过；若延迟全被归一化为 100ms，则原始信号已被破坏。

## 利用步骤

1. 确认帧数与每帧 delay：
   ```bash
   python -c "from PIL import Image; g=Image.open('stego.gif'); print(g.n_frames); [ (g.seek(i), print(i, g.info.get('duration'))) for i in range(g.n_frames) ]"
   ```
2. 先尝试“ASCII 十进制”假设：`chr((duration // 10) & 0xFF)`，按帧序拼接，检查是否出现 `flag{` 或可读文本。
3. 若不可读，尝试二进制假设：`bit=(duration // 10) & 1`，每 8 位按 MSB-first 转字节；同时尝试 LSB-first、`duration//10` 的低 2/3 位、以及先取反。
4. 若帧数很多、字符集有限，可统计 delay 的唯一值并按出现频率/顺序建映射；也可以用 PuzzleSolver 的 `[10] GIF帧间隔` 直接输出 delay 列表。
5. 用 `flag{`、`}`、可打印率验证结果；必要时把 GIF 拆帧后逐帧 OCR/对比，排除帧内容本身的隐写。

## PoC

```python
from PIL import Image

g = Image.open("stego.gif")
chars = []
for i in range(g.n_frames):
    g.seek(i)
    delay = g.info.get("duration", 0) // 10   # 还原 GIF 原始 delay（1/100 秒）
    chars.append(chr(delay & 0xFF))
print("".join(chars))

# 二进制变体：delay 的奇偶作为 bit
bits = []
for i in range(g.n_frames):
    g.seek(i)
    bits.append(str((g.info.get("duration", 0) // 10) & 1))
bitstr = "".join(bits)
print("".join(chr(int(bitstr[i:i+8], 2)) for i in range(0, len(bitstr) - 7, 8)))
```

说明：PoC 按原文截图中的 720/650/800... 延迟序列重写，未在本机对附件复跑；若图像被重新编码，delay 可能已被归一化。

## 变体与关联

- **ASCII 十进制**：delay 直接存字符码，最直观；本题即此变体。
- **二进制位**：delay 的奇偶/低位存 bit，容量大但更依赖无损保存；也可用“基准 delay + bit×10ms”。
- **多圈/多轮**：GIF 可循环播放，若每圈 delay 序列不同，需按 `loop` 次数拼接。
- **APNG**：APNG 的 `fcTL` 用 `delay_num/delay_den` 表示帧延迟，也可承载数据，思路相同但字段不同。
- **关联**：[[ctf-forensics-video-single-pixel-channel-extraction]]（逐帧取像素值）、[[ctf-misc-pptx-slide-image-binary-separator]]（按顺序把多张图映射为 bit）；GIF 帧内容本身的差异可配合 `stegsolve`/逐帧对比排查。

## 检测与防御

- 防御/取证时对 GIF 重新编码或统一帧延迟（如全部设为 100ms）即可破坏该信道；也可用 `gifsicle --delay` 归一化。
- 检测：解析所有 GCE，统计 delay 的分布；正常动画的 delay 通常为 20/50/100/200/500/1000ms 等整百值，出现大量非整百值或与帧序号相关的规律即可疑。
- 对上传的 GIF 做重编码/抽帧校验，不要只检查文件头和尺寸；保留原始文件用于取证，避免在分析前被查看器/图床重编码。
