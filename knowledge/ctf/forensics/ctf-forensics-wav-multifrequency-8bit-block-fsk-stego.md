---
id: ctf-forensics-wav-multifrequency-8bit-block-fsk-stego
title: WAV 频域 8 频点并行 FSK 隐写：每 0.1s 用 8 个频率的开关还原 1 字节
type: scenario
domain: ctf
path: ctf/forensics
technique: wav-parallel-8fsk-byte-block-stego
aliases:
- WAV 多频点隐写
- 8 频点并行 FSK
- 音频频域字节隐写
- FFT 8 bit 还原
- 频点开关编码
tags:
- ctf
- forensics
- audio
- wav
- fft
- fsk
- frequency-domain
- stego
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T13:48:40+08:00'
  notes: 已对照原文与图04核对：4800样本/块、频点[100..12800Hz]、阈值1e6、低频=LSB、1189块还原PNG（Aztec），均与原文一致；内嵌 Aztec 图与 flag 截图经解码确认（卡片未写入 flag 明文）。PoC 未复跑；无 sources/source_url；affected_versions 未设置。
---

## 一句话结论

把 WAV 按固定时长（如 48kHz 下 0.1 秒 = 4800 样本）切块，每块内 8 个固定频点（100/200/400/800/1600/3200/6400/12800 Hz）是否存在表示 8 个 bit，频点幅值超过阈值记 1、低频对应 LSB，逐块拼成字节即可还原隐藏文件；本文 1189 块正好还原出一张 PNG（Aztec 码），再用 ZXing 解码得到 flag。

## 原理

- **并行频分复用**：在一个 block 内可同时叠加任意组合的 8 个正弦频率；对整块做 FFT，每个频点落在独立 bin 上，幅值互不干扰地反映该频率“开/关”。
- **8 个频点 = 1 字节**：每块 8 个 bit 正好编码 0–255；块长 0.1s 时每秒 10 字节，1189 块即 1189 字节，足以容纳一张小 PNG。
- **阈值判决**：生成端用固定幅值（如 >1e6）写入频点，提取端对每个频点 bin 的幅值做阈值判断；加 Hanning 窗可减少频谱泄漏，`bin = f / (sr / BLOCK)`（48kHz/4800 = 10Hz 分辨率）。
- **位序**：本文低频 = LSB，权重 `1 << 0..7`；若按相反顺序拼接，字节会呈 bit-reverse，解码失败时可反转位序重试。
- **为什么稳定**：每个 bit 占满整个 block，不依赖相位/符号定时，只需 FFT 幅值；即使音频有轻微噪声，固定频点与阈值仍易区分。
- **与“每字符单频”的区别**：单频逐字符是每个时间段只发一个频率、用频率值映射字符；本手法是每段同时发多个固定频率、用开关组合映射字节，吞吐更高、解码器不同。
- **边界**：音频被重采样/有损压缩、频点间隔小于 FFT 分辨率、块长未知或频点集合未知时，需要先做频谱分析/参数搜索。

## 触发条件

- 有 WAV 音频，听感为纯音/电子音；频谱图呈现 8 条等间隔离散水平线，按固定节奏亮灭。
- 采样率、声道、位深已知（本文 48000 Hz、单声道、16-bit），块长可由频谱节奏或题面推断。
- 能确定频点集合与判决阈值；或可通过频谱峰值/幅值直方图自动估计。
- 音频未被重采样、变速、MP3 有损压缩破坏。

## 利用步骤

1. 读取 WAV 参数：`soxi hidden.wav` 或 Python `wave`，确认声道/采样宽度/采样率。
2. 用 Audacity/Sox 看频谱图，确认 8 个固定频点及其亮灭节奏；本文频点为 100、200、400、800、1600、3200、6400、12800 Hz。
3. 按块长切分样本（4800 samples = 0.1s），不足一块的尾部丢弃。
4. 对每块加 Hanning 窗做 `rfft`，取各频点 bin 的幅值；幅值 > 阈值记 1，否则 0。
5. 按“低频 = LSB”打包字节（`sum(bit << i)`）；检查输出魔数，PNG 应为 `89 50 4E 47`。
6. 若魔数不对，尝试反转位序、调整阈值、把频点 bin 取 ±1 邻域最大值。
7. 把字节流写成文件（本文为 PNG），再用 ZXing 等解码器读取 Aztec 码得到 flag。

## PoC

```python
import io, wave
import numpy as np

FREQS = [100, 200, 400, 800, 1600, 3200, 6400, 12800]
THR = 1e6
BLOCK = 4800  # 0.1s @ 48kHz

wf = wave.open("hidden.wav", "rb")
assert wf.getnchannels() == 1 and wf.getsampwidth() == 2
sr = wf.getframerate()
samples = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16).astype(np.float32)
n = len(samples) // BLOCK
blocks = samples[:n * BLOCK].reshape(n, BLOCK)

window = np.hanning(BLOCK).astype(np.float32)
mag = np.abs(np.fft.rfft(blocks * window, axis=1))
bins = [int(f / (sr / BLOCK)) for f in FREQS]
bits = (mag[:, bins] > THR).astype(np.uint8)
weights = (1 << np.arange(8, dtype=np.uint8))
out = (bits * weights).sum(axis=1).astype(np.uint8).tobytes()
open("decoded.png", "wb").write(out)
print(out[:8].hex())  # 89504e470d0a1a0a
```

```python
# 解码得到的 Aztec 码
import zxingcpp
from PIL import Image
res = zxingcpp.read_barcode(Image.open("decoded.png").convert("RGB"))
print(res.text)
```

说明：原文脚本按 1189 块还原出 PNG，`zxingcpp` 解出 `alictf{...}`；本卡未对附件复跑。阈值 1e6 与频点集合来自原文，其他题目需按频谱重新标定。

## 变体与关联

- **编码变体**：4/16 个频点、每块多字节、幅度/相位调制、DTMF、FSK 单频逐字符；位序可能是高频=LSB 或按块内符号顺序重排。
- **块长变体**：0.05s/0.2s、非整数样本块、按秒对齐；块边界错位时所有字节都会错，需先用已知魔数/前导码校准偏移。
- **阈值变体**：固定阈值、双峰直方图/Otsu、按块归一化；频点 bin 可取 ±1 邻域最大值以抗频率漂移。
- **载体变体**：频谱图文字/图像（SSTV、频谱绘图）、DeepSound 等容器型音频隐写。
- **关联**：[[ctf-forensics-audio-per-char-single-frequency-fft]]（单频逐字符 FFT）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（PNG/WAV 多层频谱链）、[[ctf-forensics-deepsound-audio-stego-extract]]（音频容器隐写）、[[ctf-misc-png-invalid-chunk-type-zlib-wav-stego]]（本链上一层 PNG 非法 chunk 提取 WAV）。
- **边界**：音频重采样/有损压缩会破坏频点幅值；块长或频点未知时需做频谱聚类与参数搜索；多音混合/自然音频会引入大量干扰峰。

## 检测与防御

- **检测**：频谱图出现等间隔离散峰、按固定节奏亮灭；音频由纯正弦拼接，缺少自然泛音与包络；块边界处相位不连续。
- **防御**：不要把敏感数据用简单频率开关隐藏在音频中；必须隐藏时先加密并随机化频点/块长；发布前重编码或加噪会破坏该信道。
- **取证**：保留原始 WAV 与采样参数；记录频点集合、块长、窗函数、阈值与位序，保证可复现；对解出的二级文件继续按魔数分析。
