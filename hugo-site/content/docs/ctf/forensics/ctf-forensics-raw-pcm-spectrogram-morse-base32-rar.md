---
id: ctf-forensics-raw-pcm-spectrogram-morse-base32-rar
title: 1.2 MS/s 原始 PCM 转 WAV：频谱图 Morse 解出 Base32，掩码爆破频谱中的 RAR 密码
type: scenario
domain: ctf
path: ctf/forensics
technique: raw-pcm-spectrogram-morse-base32-rar
tags:
- ctf
- forensics
- audio
- spectrogram
- morse
- base32
- rar
- gnuradio
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:37+08:00'
  notes: 已对照原文与图 09-15 核对：1.2MS/s、GNU Radio 转 WAV、频谱 Morse→Base32→Rar!、ARCHPR 掩码 1d3c8c??82d? 恢复 1d3c8c7582dd 一致；已修正 numpy 位宽表述；未复跑附件。
url: /docs/ctf/forensics/ctf-forensics-raw-pcm-spectrogram-morse-base32-rar/
draft: false
kb_aliases:
- 1200000_fc.raw
- gnuradio raw 转 wav
- 频谱图摩斯
- Base32 解 RAR
- ARCHPR 掩码爆破
---

## 一句话结论

给定 `1200000_fc.raw` 这类文件名带采样率的原始 PCM 时，用 GNU Radio 的 File Source → WAV File Sink 把采样率设为 1.2 MS/s 转成 wav，在频谱图上按亮带长短读出 Morse，Morse 文本再做 Base32 得到 RAR 文件；RAR 密码藏在频谱右上方，读不清的部分用掩码（如 `1d3c8c??82d?`）爆破即可。

## 原理

- raw 文件没有 WAV 头，必须知道采样率/位宽/声道数才能正确回放；文件名 `1200000_fc.raw` 提示采样率 1,200,000 Hz。GNU Radio 的 File Source 与 WAV File Sink 都使用该 `samp_rate` 变量，转出的 wav 才能保持原始时间/频率关系。
- 时域听感是噪声或极短信号，频域上 Morse 的“点/划”表现为不同长度的亮带；把频谱缩放到亮带所在频段（本题约 10 kHz 附近）并调对比度，即可人工读出 `-.-.`、`---` 等符号。
- Morse 解码得到的字符串只含 `A-Z2-7`，是 Base32 字母表；Base32 解码后的字节流以 `52 61 72 21`（`Rar!`）开头，说明是 RAR 压缩包。
- 频谱右上角还叠加了一串数字（视觉隐写）。部分字符模糊时，先记录可读字符，把不确定位置写成 `?` 做掩码暴力（如 `1d3c8c??82d?`），ARCHPR 很快恢复完整密码。
- 这是一种“音频载体 + 频谱视觉隐写 + 压缩包”的复合链：音频层负责传 Morse/Base32，频谱层负责传密码。

## 触发条件

- 附件是 raw PCM，文件名/题目提示采样率（如 1200000）。
- 频谱图可见规则的点划亮带或文字/数字叠加。
- Base32 解码结果有 RAR/ZIP 等压缩包魔数；压缩包需要密码。
- 有 GNU Radio/sox/Audacity 与 ARCHPR 或 hashcat+rar2john 等工具。

## 利用步骤

1. GNU Radio Companion 建 `File Source → WAV File Sink`，`samp_rate=1200000`，运行得到 wav；也可用 numpy 按实际样本格式读取后写 WAV（位宽/格式须与文件一致）。
2. Audacity 打开 wav，切“频谱图”，放大到亮带频段，读出 Morse 并记录。
3. 去掉 Morse 的分隔符，按标准 Morse 表转成 `A-Z2-7` 字符串；Base32 解码，确认 `Rar!` 魔数。
4. 把频谱图拉到最右/右上角，记录密码区域的可读字符与不确定位，构造掩码。
5. 用 ARCHPR 掩码模式或 `rar2john` + `hashcat -a 3` 爆破密码，解压得到 flag。

## PoC

```python
import numpy as np, wave

raw = np.fromfile("1200000_fc.raw", dtype=np.uint8)  # 示意：实际位宽/格式需按文件调整
with wave.open("out.wav", "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(1)
    w.setframerate(1200000)
    w.writeframes(raw.tobytes())
```

```python
import base64

MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
         "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
         "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
         ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
         "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
         "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6",
         "--...": "7", "---..": "8", "----.": "9"}

morse_tokens = "...".split()          # 从频谱读出的 token
b32 = "".join(MORSE[t] for t in morse_tokens)
data = base64.b32decode(b32 + "=" * (-len(b32) % 8))
assert data[:4] == b"Rar!"
open("out.rar", "wb").write(data)
```

说明：raw 的位宽/格式必须按实际文件调整（原文 GNU Radio 流程为 complex 输入、16-bit WAV 输出，下方 numpy 读取仅为示意）；Morse 需人工从频谱核对，Base32 长度不足时补 `=`。

## 变体与关联

- **Morse → 数字口令**：若 Morse 直接解出数字，可直接作为压缩包密码；见 [[ctf-forensics-nbfm-iq-morse-digit-password-zip]]。
- **SSTV/多频点**：频谱若呈图像/多频点而非点划，改用 SSTV 或 FSK 解码；见 [[ctf-forensics-sstv-audio-image-decode]]、[[ctf-forensics-wav-multifrequency-8bit-block-fsk-stego]]。
- **频谱文字隐写**：频谱上叠加数字/文字时，先截图增强对比度，再用掩码爆破补全模糊位。
- **压缩包密码**：ARCHPR 掩码与 hashcat `-a 3` 等价；先 `rar2john` 取 hash 可离线跑。

## 检测与防御

- 音频隐写检测：观察频谱中的规则亮带、文字叠加与异常高频成分；对可疑音频做频谱图与 Morse/FSK 解码。
- 防御：涉密音频不要用无加密的裸 PCM 分发；压缩包使用强密码而非可掩码爆破的短口令。
- CTF 之外，该类技术常用于把口令藏在语音/音乐中，检测时应同时检查时域、频域与元数据。
