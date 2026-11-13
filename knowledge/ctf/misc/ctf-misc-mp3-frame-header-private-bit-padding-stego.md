---
id: ctf-misc-mp3-frame-header-private-bit-padding-stego
title: MP3 帧头 private_bit/copyright 位隐写：按 padding 位计算帧长逐帧取位、8 位一组还原 flag
type: scenario
domain: ctf
path: ctf/misc
technique: mp3-frame-header-private-bit-padding-stego
aliases:
- MP3 隐写
- private_bit
- private bit 隐写
- copyright 位隐写
- padding 帧长
- 010 Editor MPEG 模板
- mf[] 数组
tags:
- ctf
- misc
- stego
- mp3
- frame-header
- private-bit
- padding
- bit-extraction
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:40:38+08:00'
  notes: 已对照原文 content.md 与全部 8 张截图核对并复算：图2/3 mf[0] 起点 0x399D0、帧长 0x1A1，mf[11] 起点 0x3AA22、padding=1 时帧长 0x1A2；图5 mf[0] 起点 0xF05A4、帧长 0x414、帧数据 1040=0x414-4；帧长公式复算 144*128000/44100=417=0x1A1（+padding=0x1A2）、144*320000/44100=1044=0x414（+padding=0x415），与原文一致。取位复算：按 32 位帧头，padding 位于第 3 字节 bit1（[-2]）、private 位于第 3 字节 bit0（[-1]）、copyright 位于第 4 字节 bit3（[-4]），与两段 exp 及卡内 PoC 一致。图4 脚本输出 flag{0k4_Y0u_Seem_s0_cl3ver_t0_find_fl4g!}、图8 输出 flag{b3d7bed5-e8da-4d9c-848c-e5d332d63bcd}，与卡内两个 PoC 注释一致。核对中已修正：卡内帧头字段原写 sync(12)+version(2)（合计 33 位，与 32 位不符），改为按 010 模板 frame_sync(12)+mpeg_id(1)（合计 32 位，等价于标准 11 位 sync+2 位 version）；PoC 标题改为准确描述（private 变体原文无需修正拼接，copyright 变体原文 flag= 覆盖写才是待修正处）。dedup 仅自身 exact，其余为 WAV 频域 FSK、迷宫水平位移、CAN 重复帧、标点 2bit、APNG delay、WAV 定步长等不同载体，无同链重复。ctf/misc 路径合法。原文无软件版本概念，未设 affected_versions。未验证点：未取得原始 1.mp3/2.mp3 样本实跑脚本（按截图输出与公式复算一致）。
---

## 一句话结论

MP3 每帧开头的 4 字节帧头中有 1 位 `private_bit`（保留位）和 1 位 `copyright`（版权位），解码器不关心它们的值，常被用于 CTF 隐写；提取时必须先用同一帧头里的 `padding` 位判断该帧长度（示例帧长 `0x1A1`/`0x1A2` 或 `0x414`/`0x415`，padding=1 时多 1 字节）才能走到下一帧，逐帧取该位并每 8 位转一个字符即可还原 flag。

## 原理

- **MPEG 音频帧头结构**（32 bit，4 字节，按原文 010 Editor 模板字段）：`frame_sync(12) | mpeg_id(1) | layer(2) | protection(1) | bitrate_index(4) | sampling_frequency(2) | padding(1) | private(1) | mode(2) | mode_extension(2) | copyright(1) | original(1) | emphasis(2)`（模板把标准中的 11 位 sync + 2 位 version 拆成 12+1 共 32 位）。按位序，`padding` 是第 3 个字节的次低位（`...[-2]`），`private` 是第 3 个字节的最低位（`...[-1]`），`copyright` 是第 4 个字节的第 4 个低位（`...[-4]`）。
- **为什么能藏数据**：`private` 是标准中的保留/应用私有位，`copyright` 只表示版权状态，二者都不参与解码，随意改写不影响播放，因此是天然的隐蔽信道；CTF 中出题人把 flag 的比特按帧顺序写入这些位。
- **为什么必须读 padding**：MP3 帧长度由 bitrate、sampling rate 与 padding 决定（MPEG1 Layer III 为 `144*bitrate/samplerate + padding`）；在同一码率/采样率下，相邻帧长度只差 padding 的 0/1。示例文件帧长为固定值 `0x1A1` 或 `0x1A2`（第二组为 `0x414`/`0x415`），若按固定步长扫描会在 padding=1 的帧后错位，读到错误字节，所以每一步都要先取当前帧的 padding 再加到偏移上。
- **定位第一帧**：MP3 文件开头可能有 ID3v2 标签，需要跳过其头部声明的长度；示例第一帧在 `0x399D0`（第二组 `0xF05A4`）。010 Editor 的 MPEG 模板可以快速看出 `mf[]` 数组的重复结构与各帧大小。
- **取位方式**：从帧头偏移 +2 处读第 3 字节取 private/padding；从 +3 处读第 4 字节取 copyright。把每帧取到的 0/1 依次拼接，每 8 位用 `int(bits,2)` 转字符。

## 触发条件

- CTF Misc 附件为 MP3，播放正常但 010 Editor/MPEG 模板显示大量 `mf[]` 帧结构，或 private/copyright 取值异常分布（大量 0/1 混排）。
- 文件头存在 ID3v2 标签或首帧不在 0 偏移，需要先定位数据区。
- 需要已知的帧长基数（由 bitrate/samplerate 决定）与 padding 位配合扫描。

## 利用步骤

1. 用 010 Editor 打开 MP3，加载 MPEG 模板，记录 ID3v2 标签大小与第一帧（`mf[0]`）偏移。
2. 确定该文件的帧长基数：查看模板中相邻 `mf[]` 的偏移差，通常为 `0x1A1`/`0x1A2` 或 `0x414`/`0x415`。
3. 写脚本从第一帧帧头 +2 字节处读第 3 字节：取次低位作 padding、最低位作 private bit（若目标位是 copyright，则读帧头 +3 字节取第 4 个低位）。
4. 每读一帧后 `offset += 帧长基数 + padding`，循环到文件末尾，收集所有取到的位。
5. 按 8 位一组转 ASCII，去掉尾部填充字符即得到 flag；若出现乱序/错位，检查是否漏算 ID3v2 偏移或 padding 分支写反。

## PoC

private_bit 变体（按原文脚本整理，边界与步进一致）：

```python
import re

start = 0x399D0 + 2          # 第一帧帧头 + 2，跳过 sync/version/layer 等前 2 字节
end = 0x294c6b
base = 0x1A1                 # 帧长基数：padding=0 时的帧长
bits = ''
with open('1.mp3', 'rb') as f:
    n = start
    while n <= end:
        f.seek(n)
        b = f.read(1)[0]
        padding = (b >> 1) & 1      # 第 3 字节次低位
        bits += str(b & 1)          # 第 3 字节最低位 = private_bit
        n += base + padding

text = re.findall(r'\d{8}', bits)
flag = ''.join(chr(int(t, 2)) for t in text)
print(flag)   # flag{0k4_Y0u_Seem_s0_cl3ver_t0_find_fl4g!}
```

copyright 变体（修正原文 `flag=` 覆盖写导致只输出最后一个字符的问题；第 4 字节的第 4 个低位）：

```python
import re

start = 0xF05A4 + 2
end = 0xC1218E
base = 0x414
bits = ''
with open('2.mp3', 'rb') as f:
    n = start
    while n < end:
        f.seek(n)
        padding = (f.read(1)[0] >> 1) & 1
        f.seek(n + 1)
        b4 = f.read(1)[0]
        bits += str((b4 >> 3) & 1)      # 第 4 字节的 bit3 = copyright
        n += base + padding

flag = ''.join(chr(int(t, 2)) for t in re.findall(r'\d{8}', bits))
print(flag)   # flag{b3d7bed5-e8da-4d9c-848c-e5d332d63bcd}
```

## 变体与关联

- 变体：同一帧头的其他非解码字段（`original`、`emphasis`、`mode_extension`）也可藏位；先确定目标位在第几字节的第几位，再按相同帧长扫描。
- 变体：CBR 文件 padding 恒为 0 时可省略分支；VBR 文件帧长随 bitrate 变化，需要解析每帧的 bitrate_index 计算帧长（`144*bitrate/samplerate + padding`），不能只用固定基数。
- 变体：010 Editor MPEG 模板/`mp3` 解析脚本可直接导出全部帧头字段（`padding`/`private`/`copyright`），用这些字段做位流分析比手工偏移更快。
- 关联：[[ctf-misc-base64-padding-bit-stego-recover]]（按组取未用低位比特的同类比特隐写）、[[ctf-misc-apng-fctl-delay-num-ascii-stego]]（文件格式字段值隐写）、[[ctf-misc-wav-every-fourth-byte-text-length-prefix]]（音频文件定步长取字节）。
- 边界：需要正确的首帧偏移与帧长基数；ID3v2 标签、APEv2 尾标签、拼接的多段 MP3 会让偏移错位；重编码/转码会重写帧头、抹掉隐藏位。

## 检测与防御

- 出题/取证视角：解析全部帧头，统计 private/copyright 位的 0/1 分布与游程，正常音频中这些位往往恒定或呈随机低熵，若按帧序出现明显 ASCII 分组（每 8 位可打印）即可判定隐写。
- 防御视角：这类隐写只影响数据解读，不构成系统攻击面；对来源不明的媒体文件按不可信数据处理，避免在解析器中引入内存漏洞即可。
- 检测工具：010 Editor 模板、`mutagen`/`ffmpeg` 帧头导出脚本、自定义 bitstream 提取脚本。
