---
id: ctf-forensics-sstv-audio-image-decode
title: SSTV 慢扫描电视音频解码：从 WAV 还原图片与密码
type: scenario
domain: ctf
path: ctf/forensics
technique: sstv-audio-image-decode
tags:
- ctf
- forensics
- stego
- audio
- sstv
- image
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:43+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-sstv-audio-image-decode/
draft: false
kb_aliases:
- SSTV
- 慢扫描电视
- 音频转图像
- Robot36
- Scottie
- Do you know RA2
---

## 一句话结论

当附件是一段听似“啾啾/滴答”的音频、频谱呈周期性亮带、题目提示“电视/扫描/RA2/声音”时，可能是 SSTV（慢扫描电视）信号；用 SSTV 解码器（QSSTV/RX-SSTV/robot36）按对应模式（Robot36/Scottie 等）解调，即可还原出图片，图片中常带下一层密码。

## 原理

- **SSTV 调制**：图像逐行/逐像素转换为音频频率（亮度/色度对应不同频率），常见模式 Robot36、Scottie、Martin、PD 等；不同模式的扫描线数、时序、频率范围不同。
- **解码**：接收端按同步脉冲对齐行，按频率映射回像素亮度/色度，合成图像；音频质量/模式错误会导致图像倾斜/错色。
- **本题**：第一层 SSTV 解码出图片，图上有密码 `packed up and ready`；该密码用于 VeraCrypt 隐藏卷/幻影坦克层。
- **为什么成立**：SSTV 是标准模拟图像传输协议，音频中保留完整图像信息；用正确模式解调即可恢复。
- **边界**：音频被压缩/重采样会破坏同步；模式选错会得到斜纹/黑白；需要尝试多种模式。

## 触发条件

- 音频时长数十秒到数分钟，频谱有周期性同步脉冲/亮带；播放有“啾啾”扫描声。
- 题目提示“SSTV/慢扫描/电视/图像/声音”或文件名含 `.wav`/`.mp3`。
- 有 SSTV 解码工具（QSSTV、RX-SSTV、`sstv` Python 包、robot36 等）。
- 解码出的图片中有下一层密码/提示。

## 利用步骤

1. 用 Audacity/Sonic Visualiser 查看频谱，确认周期性同步脉冲/扫描线。
2. 用 QSSTV/RX-SSTV 打开音频，选择模式（先试 Robot36/Scottie/Martin），调整频率偏移/增益。
3. 解码出图片；若倾斜/错色，换模式或微调同步/采样率。
4. 查看图片文字/二维码/密码（本题 `packed up and ready`），进入下一层。
5. 用 Python `sstv` 包可批量尝试模式：
   ```bash
   pip install sstv
   sstv -d input.wav -o output.png
   ```
6. 本题最终通过后续幻影坦克/VeraCrypt 层得到 flag。

## PoC

```bash
# 方式一：QSSTV（GUI）打开 WAV，选择 Robot36/Scottie，保存解码图
# 方式二：Python sstv 包
pip install sstv
sstv -d input.wav -o output.png

# 方式三：robot36（Android/iOS）播放音频并录屏
```

## 变体与关联

- **变体（模式）**：Robot36、Robot72、Scottie 1/2/DX、Martin 1/2、PD90/PD120；逐个尝试。
- **变体（其他音频图像）**：APT/NOAA 气象卫星、WeFax、Hellschreiber；频谱特征不同。
- **变体（下一层）**：SSTV 图片密码用于 VeraCrypt/幻影坦克/压缩包；见 [[ctf-forensics-phantom-tank-rgba-parity-stego]]。
- **关联卡片**：[[ctf-forensics-deepsound-audio-stego-extract]]（音频隐写）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（音频频谱）。
- **边界**：模式/采样率错误、音频压缩/裁剪会失败；需要原始音频，避免转码。

## 检测与防御

- **CTF 识别**：音频有周期性“啾啾”扫描声/频谱同步脉冲，优先 SSTV。
- **信号取证**：保留原始 WAV，记录采样率/模式；用多种解码器交叉验证。
- **安全**：SSTV 是公开模拟协议，不提供保密性；敏感图像不要用 SSTV 传输。
