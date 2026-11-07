---
id: ctf-forensics-nbfm-iq-morse-digit-password-zip
title: I/Q 文件 NBFM 解调 + Morse 数字密码：从 192kHz 采样恢复压缩包口令
type: scenario
domain: ctf
path: ctf/forensics
technique: nbfm-iq-morse-digit-password
aliases:
- pcb5-ZipCracker
- NBFM 解调
- I/Q float32
- Morse 数字密码
- GNU Radio 流程图
- 192kHz 降采样
- 音频摩斯
tags:
- ctf
- forensics
- sdr
- nbfm
- iq
- morse
- audio
- zip
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:30+08:00'
  notes: 已对照原文脚本与图15-18核对：192kHz I/Q、相位差NBFM、4倍抽取、250-350Hz包络、Morse数字password 114514350234114514、bkcrack已知明文与flag一致
---

## 一句话结论

当压缩包里的 `flag1.txt`/`flag2.txt` 是 192 kHz 的 I/Q float32 流、且题目给了 GNU Radio NBFM 流程图时，把 I/Q 组成复数信号，用相邻样本相位差做 NBFM 解调、降采样到 48 kHz，再带通 250–350 Hz、取包络并阈值检测，按点划/间隔 run-length 解码 Morse 数字，即可得到压缩包口令（本题 `114514350234114514`），随后用已知明文攻击解 ZIP。

## 原理

- **I/Q 与 NBFM**：`flag1.txt`/`flag2.txt` 分别是 I、Q 两路 float32 采样；复信号 `I + jQ` 的相邻样本相位差 `angle(s[n] * conj(s[n-1]))` 近似瞬时频率，即 NBFM 解调输出；减去均值后按 4 倍抽取降到 48 kHz。
- **音频与 Morse**：解调后的音频在 250–350 Hz 附近有 Morse 音调；带通滤波后取 Hilbert 包络，平滑并设阈值（如 75 分位数的 0.3 倍），得到 tone on/off 序列。
- **run-length 解码**：统计 on/off 的持续时间，用中位数区分点/划（on）与字符内/字符间间隔（off）；按间隔把符号分组，再用数字 Morse 表（`-----`=0 … `----.`=9）映射为数字串。
- **为什么用 Morse 数字**：题目嵌入的是数字密码，Morse 数字码长度固定为 5 个符号，容错较好；即使音频有噪声，按中位数阈值也能稳定分割。
- **后续 ZIP**：得到口令后解压/用 bkcrack 已知明文（flag 头尾）解 `flag.zip`；本题最终 `flag{Y0u_r_th3_Z1p_k1ng!!!!!}`。
- **边界**：采样率/抽取倍数/音调频率必须与 GNU Radio 流程图一致；若 I/Q 是交错单文件而非两文件，需要按 `float32` 交替解析；噪声大时需调整带通/阈值或人工听音频。

## 触发条件

- 拿到 I/Q 两路 float32 文件（或交错 I/Q），采样率已知（本题 192 kHz）。
- 有 GNU Radio 流程图/题目提示说明是 NBFM，音频中嵌入 Morse。
- 能使用 numpy/scipy 做相位差解调、滤波、包络与 run-length。
- 压缩包加密且口令为 Morse 解出的数字串；或需要口令进行后续 bkcrack/解压。

## 利用步骤

1. **读取 I/Q**：`np.frombuffer(raw, dtype='<f4')` 分别读 I、Q，长度应一致。
2. **NBFM 解调**：`phase_diff = np.angle(s[1:] * np.conj(s[:-1]))`，减均值；`scipy.signal.decimate(..., 4)` 降到 48 kHz。
3. **带通/包络**：4 阶 Butterworth 250–350 Hz 带通，Hilbert 包络，10 ms 滑动平均平滑。
4. **阈值与 run-length**：阈值取包络 75 分位数的 0.3 倍；统计 on/off 段长度，用中位数分点/划、字符内/字符间间隔。
5. **Morse 解码**：按间隔分组符号，用数字 Morse 表转数字串。
6. **后续**：用数字串解 ZIP/或作为 bkcrack 的已知明文线索；本题得到口令 `114514350234114514`，解出 `flag.txt` 后用 bkcrack 得 flag。

## PoC

```python
import zipfile
import numpy as np
from scipy.signal import decimate, hilbert, butter, filtfilt

IF_RATE, DECIMATION = 192_000, 4
AUDIO_RATE = IF_RATE // DECIMATION
NUM_MORSE = {"-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",
             ".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}

def read_iq(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        i = np.frombuffer(z.read("flag1.txt"), dtype="<f4").astype(np.float64)
        q = np.frombuffer(z.read("flag2.txt"), dtype="<f4").astype(np.float64)
    return i + 1j * q

def nbfm(s):
    d = np.angle(s[1:] * np.conj(s[:-1]))
    d -= np.mean(d)
    return decimate(d, DECIMATION, ftype="fir", zero_phase=True)

def morse_digits(audio):
    b, a = butter(4, [250/(AUDIO_RATE/2), 350/(AUDIO_RATE/2)], btype="band")
    env = np.abs(hilbert(filtfilt(b, a, audio)))
    win = int(AUDIO_RATE * 0.01)
    env = np.convolve(env, np.ones(win)/win, mode="same")
    key = env > np.percentile(env, 75) * 0.3

    rle, cur, start = [], bool(key[0]), 0
    for idx in range(1, len(key)):
        if bool(key[idx]) != cur:
            rle.append((cur, start, idx)); cur = bool(key[idx]); start = idx
    rle.append((cur, start, len(key)))

    on = [(e-s)/AUDIO_RATE for st,s,e in rle if st]
    off = [(e-s)/AUDIO_RATE for st,s,e in rle if not st]
    dot, dash = np.median([d for d in on if d < 0.2]), np.median([d for d in on if d > 0.2])
    intra, inter = np.median([d for d in off if d < 0.2]), np.median([d for d in off if d > 0.2])
    thr, gap = (dot+dash)/2, (intra+inter)/2

    out, sym = [], ""
    for st,s,e in rle:
        dur = (e-s)/AUDIO_RATE
        if st:
            sym += "." if dur < thr else "-"
        elif dur > gap and sym:
            out.append(sym); sym = ""
    if sym: out.append(sym)
    return "".join(NUM_MORSE[x] for x in out)

audio = nbfm(read_iq("flag2.zip"))
print(morse_digits(audio))
```

原文输出：`password = 114514350234114514`；随后 `bkcrack -C flag.zip -x 0 666c61677b593075 -x 25 2121217d ...` 解出 `flag{Y0u_r_th3_Z1p_k1ng!!!!!}`。

## 变体与关联

- 变体：FM/AM/SSB 解调；I/Q 交错存储；不同采样率/抽取倍数；Morse 字母而非数字；用 FFT 找音调而不是固定 250–350 Hz。
- 关联：[[ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt]]（已知密码解 ZipCrypto）、[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（bkcrack 已知明文）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（音频/频谱隐写的另一类分析）。
- 同题：`pcb5-ZipCracker` 的 GNU Radio 流程图与 NBFM 参数。

## 检测与防御

- **CTF 之外**：无线电/音频隐写不是安全边界；对可疑 I/Q/音频文件做频谱、包络、Morse/FSK 分析。
- **取证**：保留原始 I/Q 与流程图参数；先解调再滤波，避免直接对 I/Q 做 Morse 检测。
- **检测**：监控异常音频/无线电文件中的周期性 tone；对压缩包口令尝试已知明文/字典攻击。
