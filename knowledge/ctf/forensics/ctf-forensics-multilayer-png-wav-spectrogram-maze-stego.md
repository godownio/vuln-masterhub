---
id: ctf-forensics-multilayer-png-wav-spectrogram-maze-stego
title: 多层 PNG/WAV 隐写链：XMP 掩码口令 + 尾部逆序 nibble 交换 ZIP + 频谱字符表 + 伪造 IHDR 高度与 G^A 低位迷宫
type: scenario
domain: ctf
path: ctf/forensics
technique: multilayer-png-wav-spectrogram-maze-stego
aliases:
- 潮痕留声
- misc1
- data.png
- tide_trace.png
- EXIF LensMake 掩码
- 尾部逆序半字节交换
- WinZip AES 掩码爆破
- 频谱字符表
- IHDR 高度伪造
- G^A 低位迷宫
tags:
- ctf
- forensics
- stego
- png
- wav
- spectrogram
- exif
- zip
- aes
- ihdr
- lsb
- maze
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:27+08:00'
  notes: 已对照原文 misc1 一节与 01-04 图核对：XMP LensMake 2026_????_CHB、IEND 后尾部逆序+nibble 交换得 WinZip AES(method 99/0x9901)、口令 2026_D4fX_CHB、tide_trace.png IEND 后 645164 字节 WAV（16-bit 双声道 16kHz 161280 帧 10.08s）、STFT NFFT=2048/noverlap=1920、伪造 IHDR 960×448→960×960 与 CRC raw[12:29]/raw[29:33]、G^A bit0 迷宫、频谱字符表与完整/半迷宫图、UUID 与 a/f 歧义提示均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

“潮痕留声”是一张 PNG 套一条多层隐写链：先读 XMP `exifEX:LensMake` 得到口令掩码 `2026_????_CHB`，把 IEND 之后的尾部整体逆序并交换高低 4 bit 还原 WinZip AES ZIP，掩码爆破解出 `tide_trace.png`；该 PNG 的 IEND 后又藏一段 WAV，频谱旋转/镜像得到 6×6 字符表；同时伪造的 IHDR 高度把真实 960×960 画布截成 448，修复高度并重算 CRC 后，用 G^A 的最低位平面提取迷宫，按迷宫顺序读字符表得到 UUID。

## 原理

- **元数据当掩码**：PNG 的 XMP `exifEX:LensMake` 被写成 `2026_????_CHB`，不是相机型号，而是压缩包口令的固定前后缀；`?` 是 4 个未知字符，适合 ARCHPR 掩码爆破。
- **尾部变换**：PNG 逻辑结束于 `IEND`，之后可以附加任意数据。这里的尾部不是直接 ZIP，而是先整体逆序、再对每字节交换高低 4 bit；恢复后本地文件头以 `PK\x03\x04` 开始，method 99 + extra `0x9901` 表明是 WinZip AES 加密 ZIP，文件名 `tide_trace.png` 可见。
- **PNG 尾部再套 WAV**：`tide_trace.png` 的 IEND 后仍有 645,164 字节，以 `RIFF` 开始；直接截出保存为 WAV 即可。WAV 为双声道 16-bit PCM、16 kHz、161,280 帧、10.08 秒，无额外 chunk，隐藏内容在采样本身。
- **频谱字符表**：对左右声道做 STFT，`NFFT=2048`、`Fs=16000`、`noverlap=1920`（hop=128），保留字符轮廓；频谱中的字符相对标准阅读方向旋转，旋转 180° 再水平镜像后得到 6×6 字符表。镜像不能改变记录顺序，频谱横轴仍是时间轴。
- **伪造 IHDR**：IHDR 声称 960×448，但 IDAT 解压后扫描线长 `1+960*4=3841` 字节、总长恰好 960 行，真实画布是 960×960；IHDR CRC 也被故意写错。把高度改为 960 并重算 CRC（`crc32(raw[12:29])` 写到 `raw[29:33]`）后，PNG 正常解码，迷宫下半部分才出现。
- **通道对低位**：修复后 Alpha 只在 254/255 变化、Green 取值很窄，正常画面无法解释这种一位变化；枚举 `R^G/R^B/R^A/G^B/G^A/B^A` 的位平面，只有 `G^A` 的 bit 0 形成连续、带起止标记的线条，即迷宫。
- **迷宫定序**：圆环为起点、箭头为终点；把频谱得到的 6×6 字符表放入网格，沿迷宫路径读取，所有字符恰好用完，得到 UUID；加上 `flag{}` 提交。右下角可能存在 a/f 互换的歧义，两个结果都提交即可。

## 触发条件

- 题目附件是一张“看起来普通”的 PNG，但文件尺寸/尾部长度异常，元数据字段可疑。
- 尾部数据经过简单变换（逆序、异或、nibble 交换）后能识别出 ZIP/RIFF 等 magic。
- 压缩包使用 WinZip AES 或传统 ZipCrypto，口令有可推测的掩码/字典。
- 解出的图片/音频中存在频谱、LSB、通道差等隐写层；IHDR/CRC 可能被篡改。
- 最终需要一条排序规则（迷宫/路径/坐标）把字符表拼成 flag。

## 利用步骤

1. 检查 PNG 元数据，记录可疑字段（本题 `exifEX:LensMake=2026_????_CHB`）。
2. 取 IEND 之后的尾部，逆序 + nibble 交换，恢复 ZIP；识别 WinZip AES，按掩码 `2026_????_CHB` 爆破口令，解出 `tide_trace.png`。
3. 取 `tide_trace.png` IEND 之后的 RIFF 尾部保存为 WAV；用 STFT 画左右声道频谱，旋转/镜像读取 6×6 字符表。
4. 解压 IDAT，按扫描线长度推断真实高度；修改 IHDR 高度并重算 CRC，修复图片。
5. 枚举 RGBA 通道对的低位平面，找到形成连续线条的 `G^A` bit0，提取迷宫。
6. 按迷宫从圆环到箭头读取字符表，拼成 UUID，加 `flag{}` 提交。

## PoC

```python
from pathlib import Path
import zlib
import numpy as np
from PIL import Image

# 1) 尾部逆序 + nibble 交换 -> ZIP
blob = Path("data.png").read_bytes()
tail = blob[blob.find(b"IEND") + 8:]
restored = bytes(((v & 0x0F) << 4) | (v >> 4) for v in tail[::-1])
Path("payload.zip").write_bytes(restored)

# 2) PNG IEND 后的 WAV
blob = Path("tide_trace.png").read_bytes()
Path("tide_trace_tail.wav").write_bytes(blob[blob.find(b"IEND") + 8:])

# 3) 修复 IHDR 高度并重算 CRC
raw = bytearray(Path("tide_trace.png").read_bytes())
iend_end = raw.find(b"IEND") + 8
raw[20:24] = (960).to_bytes(4, "big")
raw[29:33] = zlib.crc32(raw[12:29]).to_bytes(4, "big")
Path("tide_trace_960.png").write_bytes(raw[:iend_end])

# 4) G^A 最低位迷宫
rgba = np.asarray(Image.open("tide_trace_960.png").convert("RGBA"))
maze = ((rgba[..., 1] ^ rgba[..., 3]) & 1) * 255
Image.fromarray(maze.astype("uint8")).save("maze.png")
```

频谱字符表用 `matplotlib.specgram(NFFT=2048, Fs=16000, noverlap=1920)` 画左右声道；原文实测最终 flag 为 `flag{60a8d749-3760-4560-8bc7-86f2faa7754d}`，未在本库复跑。

## 变体与关联

- **尾部变换变体**：逆序、nibble 交换、XOR、Base64、ROT；先看 magic，再决定逆变换。
- **压缩包变体**：WinZip AES（method 99/0x9901）、ZipCrypto、7z/rar；口令掩码来自元数据/题目提示。
- **隐写层变体**：频谱、LSB、通道差、DCT、EOF 附加、IHDR/CRC 篡改、调色板；按“异常统计”选择通道。
- **排序变体**：迷宫、二维码、坐标表、密码本；需要把字符表还原成顺序。
- **关联卡片**：[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 扫描顺序）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（文本零宽隐写）。

## 检测与防御

- **检测**：检查 PNG 尾部长度与 magic、IHDR/CRC 一致性、IDAT 扫描线与声明高度、Alpha/通道统计异常；对 WAV 做频谱/波形检查。
- **防御**：不要把秘密只藏在图片/音频的隐写层；需要隐写时使用带密钥的编码与加密，并对容器做完整性校验。
- **取证**：保留原始文件与每一步中间产物（尾部、ZIP、WAV、修复后的 PNG、迷宫图），逐步验证 magic/长度/CRC，避免一次性猜测。
