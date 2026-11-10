---
id: ctf-misc-wav-every-fourth-byte-text-length-prefix
title: WAV PCM 每 4 字节首字节写文本：3 字节小端长度前缀 + 步长 4 提取
type: scenario
domain: ctf
path: ctf/misc
technique: wav-every-fourth-byte-text-length-prefix
tags:
- ctf
- misc
- stego
- wav
- pcm
- audio
- length-prefix
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:30+08:00'
  notes: 已对照原文 hiden 段与图 30 核对：ROT47/ROT13 解码出的 wave 脚本、file_len.to_bytes(3,'little')+txt、wav_data[index*4]=txt_data[index]、提取脚本与 DASCTF{12jkl-456m78-90n1234} 均一致；卡内步长 4/偏移 0 与原文一致。未验证点：未拿到 hiden.wav 复跑；16-bit 立体声/左声道低字节为常见格式推断（写入本身只依赖 stride=4）。
url: /docs/ctf/misc/ctf-misc-wav-every-fourth-byte-text-length-prefix/
draft: false
kb_aliases:
- hiden.wav
- WAV 每4字节隐写
- 音频采样字节隐写
- 3字节长度前缀
- wave 模块提取
---

## 一句话结论

把文本按“3 字节小端长度 + 文本数据”打包后，逐字节写入 WAV 音频每 4 字节组的第 0 字节（`wav_data[index*4] = txt_data[index]`），音频仍可正常播放；提取时按步长 4 读取第 0 字节，先取前 3 字节还原长度，再截取对应字节即可得到隐藏文本。

## 原理

- **WAV/PCM 的字节结构**：`wave` 模块读取的 `readframes(-1)` 是原始 PCM 采样字节流。对于常见的 16-bit 立体声，每帧 4 字节（左声道 2 字节 + 右声道 2 字节）；每 4 字节的第 0 字节是左声道样本的低字节。把该字节替换为文本字节，只会轻微改变波形，不会破坏 RIFF/WAV 头或帧长度。
- **容量与长度前缀**：1 个文本字节需要 4 个音频字节（1 个采样帧），因此 N 字节文本需要约 4N 字节 PCM；3 字节小端长度前缀让提取方知道有效文本长度，尾部多余的采样字节（原音频/填充）不会混入结果。
- **为什么能还原**：写入是按固定步长、固定偏移的确定性映射；读取时用同样的步长和偏移取回原字节，长度前缀用于截断。只要 WAV 没有被重新编码/重采样（未改变 PCM 字节布局），数据就保持不变。
- **隐蔽性**：文件头、采样率、声道数、时长都正常，普通播放器听不出明显异常；常规 `strings` 可能看不到连续文本，因为文本字节被每隔 4 字节分散。

## 触发条件

- 拿到 WAV 文件，`file`/`exiftool` 确认是 PCM WAV（未压缩、未重采样）。
- 文件大小约为可疑文本长度的 4 倍以上；每 4 字节的第 0 字节呈现 ASCII/长度规律。
- 题目提示“音频/波形/隐写/每 4 字节/采样”，或给出一个被编码的加密脚本（如 ROT47）。
- 原始 WAV 未被播放器/转码工具重新保存（重采样会破坏字节位置）。

## 利用步骤

1. 用 `wave` 打开 WAV，确认 `nchannels`/`sampwidth`/`framerate`；计算 `len(frames) // 4` 作为最大可提取长度。
2. 读取全部帧字节，按 `data[0::4]` 取每 4 字节的第 0 字节；若不可读，依次尝试偏移 1、2、3，或按实际声道/采样宽度调整步长（如 16-bit 单声道步长 2、8-bit 立体声步长 2）。
3. 取前 3 字节按小端 `int.from_bytes(..., 'little')` 得到长度 L；从第 4 字节起截取 L 字节，写入 `.txt`。
4. 检查文本是否为可打印/源码；若是一段被 ROT47/ROT13/Base64 混淆的脚本，先解混淆再按脚本复现。
5. 用 `file`/`xxd`/`strings` 复核提取出的文件；若长度异常，检查是否多读了尾部原音频或长度前缀被加密。
6. 需要验证时，用同一脚本反向嵌入一段已知文本，比较 WAV 字节差异是否只在 `index*4` 位置。

## PoC

```python
import wave

def extract(src, dst):
    with wave.open(src, "rb") as f:
        frames = bytearray(f.readframes(-1))
    raw = bytes(frames[0::4])              # 每 4 字节取第 0 字节
    length = int.from_bytes(raw[:3], "little")
    data = raw[3:3 + length]
    open(dst, "wb").write(data)
    print("length:", length, "preview:", data[:60])

extract("hiden.wav", "flag.txt")
```

```python
# 嵌入侧（理解编码方式即可，不需要对题目附件执行）
import wave

def embed(src, txt_path, dst):
    txt = open(txt_path, "rb").read()
    payload = len(txt).to_bytes(3, "little") + txt
    with wave.open(src, "rb") as f:
        params = f.getparams()
        frames = bytearray(f.readframes(-1))
    for i, b in enumerate(payload):
        frames[i * 4] = b
    with wave.open(dst, "wb") as f:
        f.setparams(params)
        f.writeframes(frames)
```

## 变体与关联

- **步长/偏移变体**：16-bit 单声道步长 2、8-bit 立体声步长 2、32-bit 立体声步长 8；偏移可能是第 0/1/2/3 字节（低字节/高字节/右声道）。先看 `sampwidth*nchannels` 再定步长。
- **长度前缀变体**：3 字节小端最常见，也可能是 4 字节大端、2 字节、或固定长度/终止符分隔；若前 3 字节解出的长度不合理，尝试其他宽度/端序。
- **混淆变体**：写入的文本/脚本本身可能经过 ROT47、ROT13、Base64、XOR；先按题目提示解一层，再执行/阅读脚本。
- **关联卡片**：[[ctf-misc-silenteye-wav-elf-aes-ecb-dirty-wrapper]]（SilentEye/WAV 多格式隐写）、[[ctf-forensics-audio-per-char-single-frequency-fft]]（频域逐字符）、[[ctf-forensics-deepsound-audio-stego-extract]]（DeepSound 音频隐写）、[[ctf-forensics-wav-multifrequency-8bit-block-fsk-stego]]（频域 FSK）。
- **边界**：WAV 被重采样/重新编码、文本超过音频容量、或写入位置不是每 4 字节第 0 字节时，直接按本卡提取会失败。

## 检测与防御

- **检测**：比较 WAV 每 4 字节组第 0 字节的分布，若大量落在可打印 ASCII 区间或呈现长度前缀/递增规律即可疑；检查文件大小与音频时长的比例是否异常；用 `sox`/`ffmpeg` 重采样后差异会暴露。
- **防御/取证**：对上传音频统一重编码/重采样（会破坏该信道）；保留原始文件用于取证，分析前不要用播放器另存；检查音频数据块中的字节级异常。
- **CTF 技巧**：先看容器参数（声道/位深）决定步长，再尝试偏移 0..(stride-1)；长度前缀/终止符是快速定位有效数据的常用手段。
