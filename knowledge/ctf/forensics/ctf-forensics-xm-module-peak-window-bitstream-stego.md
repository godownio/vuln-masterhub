---
id: ctf-forensics-xm-module-peak-window-bitstream-stego
title: XM 模块音乐渲染 WAV 后按窗口峰值还原比特流
type: scenario
domain: ctf
path: ctf/forensics
technique: xm-module-peak-window-bitstream-stego
aliases:
- Encoded in Melodies
- XM 隐藏信息
- 追踪峰值
- XM to WAV
- 音频峰值隐写
- I Feel Fantastic
tags:
- ctf
- forensics
- audio
- xm
- wav
- stego
- peak
- bitstream
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:51:03+08:00'
  notes: 已对照原文核对：XM 模块名/提示 strings、OpenMPT/MilkyTracker 渲染单声道 16-bit WAV、窗口峰值判决比特、offset 0..7 ASCII、结果 I Feel Fantastic heyheyhey 均一致；原文只给思路，卡内脚本为按原理重写，未对附件执行。
---

## 一句话结论

题目给的是 XM 模块音乐文件时，先用 OpenMPT/MilkyTracker 把异常规则的 sample 渲染成单声道 16-bit WAV，再按固定窗口统计采样绝对值峰值：峰值超过阈值记 1、否则记 0，拼成比特流后按 8 位 ASCII 并尝试不同偏移，即可还原被编码在波形包络里的隐藏短句。

## 原理

- **XM 是模块音乐，不是普通 PCM**：XM（Extended Module）保存的是样本、乐器、pattern 与播放指令，不能直接用 `wave` 库读取；必须用跟踪器/渲染器（OpenMPT、MilkyTracker）把目标 sample 或整段 pattern 渲染为 WAV，才能做采样级分析。
- **峰值承载比特**：编码端把每个 bit 映射到一段固定长度的窗口；bit=1 的窗口写入高幅值脉冲，bit=0 的窗口保持低幅值/静音。解码端对每个窗口取 `max(abs(sample))`，与阈值比较即可恢复 bit，不需要 FFT，也不需要精确相位。
- **窗口长度与阈值**：`SAMPLES_PER_BIT` 是每个 bit 占用的采样数（例如 44100Hz 下取 441 代表 10ms/bit，或按题目节奏取更长）；阈值通常取全局峰值的某个比例（如 0.3–0.6），也可用双峰分布（高/低两组）自动选阈值。
- **比特对齐**：比特流两端可能有长串 0 填充；去掉后按 8 位分组，ASCII 解析可能因起始偏移错位，需要尝试 `offset=0..7`，并优先选择可打印字符比例高、包含自然英文的候选。
- **为什么能藏**：XM 的 sample 可以做成“看似有规律的脉冲/条形波形”，在音频里听感可能只是节奏/噪声；峰值包络在时域上非常显眼，但在频谱或多轨混音中容易被忽略。题目提示 “trace the peaks” 直接指向时域峰值。
- **结果形态**：原文恢复出的隐藏消息为 `I Feel Fantastic heyheyhey`，与题目背景的都市传说一致；该消息作为密码/线索用于后续 OSINT 关卡。

## 触发条件

- 附件是 `.xm`、`.mod`、`.s3m`、`.it` 等模块音乐文件，或题目明确提到 tracker/module/XM。
- `strings` 能看到 “Extended Module”“How Do you Feel?” 等文本，或提示 “peaks”“waveform”“sample”。
- 用跟踪器打开后，某个 sample/pattern 呈现异常规则的脉冲、条形或方波，和正常乐器样本明显不同。
- 需要恢复的信息是短英文句子/密码，允许尝试窗口与阈值参数。

## 利用步骤

1. 用 `strings`/十六进制查看 XM，记录模块名、样本名、提示文本（如 “trace the peaks”）。
2. 用 OpenMPT 或 MilkyTracker 打开 XM，在 Samples/Patterns 中找到形状异常规则的 sample；只导出该段为单声道、16-bit PCM WAV（44.1k 或 48k），避免立体声/重采样干扰。
3. 用 `wave` + `struct`/`numpy` 读取采样，归一化到 `[-1,1]`；画波形/包络图，观察高幅值窗口的周期，估计 `SAMPLES_PER_BIT`。
4. 对每个窗口计算 `max(abs(window))`；用全局峰值比例或双峰分布选阈值，生成 bit 串（高=1，低=0）。
5. 去掉两端长串 0；按 8 位分组转 ASCII，尝试 `offset=0..7`，以及 bit 序反转（LSB-first/MSB-first）。
6. 从候选文本中筛选自然英文；若出现乱码，调整 `SAMPLES_PER_BIT`（常见为采样率的整数分之一）、阈值、窗口起点（是否有前导静音）。
7. 得到隐藏短句后，按题目要求作为密码/线索进入下一关。

## PoC

按原理重写的最小脚本（原文只给思路，未给完整脚本；未在本机对附件执行）：

```python
import wave
import struct

SAMPLES_PER_BIT = 441          # 需按题目节奏调整
THRESHOLD_RATIO = 0.4          # 相对全局峰值
OFFSET = 0                     # 起始采样偏移，可尝试 0..SAMPLES_PER_BIT-1

with wave.open("Feel.wav", "rb") as w:
    assert w.getnchannels() == 1 and w.getsampwidth() == 2
    n = w.getnframes()
    raw = w.readframes(n)
    samples = struct.unpack("<%dh" % n, raw)

peak = max(abs(s) for s in samples) or 1
thr = peak * THRESHOLD_RATIO
bits = []
for start in range(OFFSET, n - SAMPLES_PER_BIT + 1, SAMPLES_PER_BIT):
    win = samples[start:start + SAMPLES_PER_BIT]
    bits.append(1 if max(abs(s) for s in win) > thr else 0)

# 去两端 0
while bits and bits[0] == 0:
    bits.pop(0)
while bits and bits[-1] == 0:
    bits.pop()

for bit_offset in range(8):
    data = bytearray()
    for i in range(bit_offset, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        data.append(v)
    text = bytes(data)
    printable = sum(32 <= c < 127 for c in text) / max(len(text), 1)
    if printable > 0.8:
        print(bit_offset, text[:200])
```

若输出是倒序/反相，尝试把 bit 序反过来、把阈值判断取反，或从窗口中间而非起点对齐。

## 变体与关联

- **窗口变体**：固定采样数、固定毫秒、按 BPM/行时长对齐；`SAMPLES_PER_BIT` 可能不是采样率的整数分之一。
- **判决变体**：峰值阈值、RMS 能量、过零率、包络差分；bit=1 可能是高幅值也可能是长脉冲/特定频率。
- **容器变体**：MOD/S3M/IT、MIDI、视频中的音频轨；先渲染/提取为 PCM 再做时域分析。
- **关联**：[[ctf-forensics-wav-multifrequency-8bit-block-fsk-stego]]（频域 8 频点 FSK）、[[ctf-forensics-audio-per-char-single-frequency-fft]]（逐字符单频）、[[ctf-forensics-deepsound-audio-stego-extract]]（DeepSound 工具隐写）、[[ctf-forensics-sstv-audio-image-decode]]（SSTV 音频转图像）。
- **边界**：重采样、立体声混音、音量归一化、MP3 有损压缩都会破坏峰值窗口；必须保留原始渲染的 16-bit PCM。若窗口长度估计错误，比特流会整体错位，表现为乱码。

## 检测与防御

- **CTF 识别**：模块音乐 + “peaks/trace/waveform” 提示 + 规则脉冲 sample，优先做时域峰值分析；不要一上来就 FFT。
- **取证**：保留原始 XM 与渲染参数（采样率、声道、位深），记录窗口长度与阈值；用波形图/包络图辅助确认。
- **防御（真实系统）**：音频隐写检测可看时域包络的异常周期性、双峰幅值分布、样本直方图；对上传的模块音乐/音频做重编码会破坏此类编码（但会影响音质）。
- **出题思路**：用 tracker 模块做载体，把比特映射到 sample 峰值，配合 “trace the peaks” 提示；可通过改变 BPM/窗口长度增加调参成本。
