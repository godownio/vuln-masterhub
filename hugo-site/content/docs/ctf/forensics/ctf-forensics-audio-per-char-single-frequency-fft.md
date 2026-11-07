---
id: ctf-forensics-audio-per-char-single-frequency-fft
title: 单频正弦波逐字符音频：按 0.12s 分段 FFT 主频还原字符
type: scenario
domain: ctf
path: ctf/forensics
technique: audio-per-char-single-frequency-fft
tags:
- forensics
- audio
- wav
- fft
- frequency
- stego
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:34+08:00'
  notes: 已对照原文核对：每字符频率 freq=((ch^0xA5)+0x11)*9+500、44100Hz、每字符 0x14AC=5292 样本（0.12s）、正弦采样 sin(2πf i/44100)*28000、分段 FFT 主频反查字符、flag kashiCTF{MUSIC_VIBES_but_all_1_w4nt_15_a_MDrOrq} 均一致。未验证点：无 WAV 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-audio-per-char-single-frequency-fft/
draft: false
kb_aliases:
- 音频频率隐写
- 每字符单频
- FFT 主频还原
- WAV 字符频率表
---

## 一句话结论

当程序把每个字符映射成一个固定频率、按固定时长（如 0.12 秒）拼接成正弦波 WAV 时，按段做 FFT 取主频，再用同一映射表反查字符，即可还原整段 flag；关键是从二进制/源码中恢复 `freq = f(ch)` 的公式和每字符样本数。

## 原理

- 音频由一段段单频正弦波拼接：每个字符对应一个唯一频率，持续固定样本数（如 44100Hz × 0.12s = 5292 样本）。
- 对每段做 FFT，频谱峰值频率就是该字符的频率；加窗（Hanning）可减少频谱泄漏，跳过直流分量避免误判。
- 若已知映射公式（如 `freq = ((ch ^ 0xA5) + 0x11) * 9 + 500`），可预先为可打印 ASCII 建立“字符→频率”表，取最近邻反查。
- 为什么可行：频率是连续量，但每个字符映射到离散且间隔足够的频率；只要段长/采样率/公式正确，FFT 分辨率足以区分相邻字符。
- 若音频有噪声/多音轨/变速，需先滤波、估计基频或做时频分析；若字符频率间隔小于 FFT 分辨率，需增加段长/补零。

## 触发条件

- 有 WAV/音频文件，内容为分段单频正弦波；字符边界与段长可推断。
- 能从二进制/源码/题面恢复字符→频率映射公式或频率表。
- 采样率、每字符样本数已知；音频未被重采样/压缩破坏。

## 利用步骤

1. 用 `soxi`/`wave` 读取采样率、声道、位深；单声道 16-bit 最常见。
2. 从二进制反汇编/源码中找到频率公式与每字符样本数（如 `0x14ac = 5292`）。
3. 按段长切分音频；对每段加 Hanning 窗、做 `rfft`，取非直流最大峰对应频率。
4. 用频率表最近邻反查字符；按顺序拼接。
5. 若结果有噪声，调整段长/窗函数/峰值插值，或对相邻段做平滑；检查是否有静音/间隔段。
6. 输出 flag；必要时用已知前缀（如 `kashiCTF{`）校准偏移/频率表。

## PoC

```python
import wave
import numpy as np

w = wave.open("audio.wav", "rb")
sr = w.getframerate()
audio = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
seg_len = 5292                      # 0x14ac，按题目实际值

def ch_to_freq(ch):
    return (((ch ^ 0xA5) + 0x11) & 0xff) * 9 + 500

freq_map = {chr(i): ch_to_freq(i) for i in range(32, 127)}
freqs = np.fft.rfftfreq(seg_len, d=1 / sr)

out = []
for i in range(0, len(audio) - seg_len + 1, seg_len):
    seg = audio[i:i + seg_len] * np.hanning(seg_len)
    spec = np.abs(np.fft.rfft(seg))
    peak = freqs[np.argmax(spec[1:]) + 1]
    out.append(min(freq_map, key=lambda c: abs(freq_map[c] - peak)))
print("".join(out))
```

说明：PoC 为原文 exp 的结构化精简，未在本机执行；原文还原出 `kashiCTF{MUSIC_VIBES_but_all_1_w4nt_15_a_MDrOrq}`。

## 变体与关联

- 变体（编码）：频率映射到十六进制/多比特（如 4 个频率一组）、双音多频（DTMF）、FSK；需先做频谱聚类。
- 变体（载体）：SSTV、频谱图文字、WAV 频谱隐写；见关联卡。
- 关联：[[ctf-forensics-sstv-audio-image-decode]]（SSTV 音频图像）；[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（WAV 频谱字符表）；[[ctf-forensics-deepsound-audio-stego-extract]]（音频隐写容器）。
- 边界：音频被重采样/有损压缩、频率间隔小于分辨率、段长未知、或多音混合时，需要更精细的时频分析/参数搜索。

## 检测与防御

- 检测：WAV 频谱呈等间隔离散峰、每段主频恒定；音频由纯正弦拼接、无自然泛音/包络。
- 防御：不要用简单频率映射隐藏敏感信息；使用加密/随机化；发布前重编码/加噪会破坏该信道。
- 取证：保留原始音频与采样参数；记录段长、窗函数、频率表与最近邻判定，保证可复现。
