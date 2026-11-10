---
id: ctf-misc-wav-manchester-encoding-waveform-extraction
title: WAV 方波音频曼彻斯特隐写：读波形定起始时间与比特时长，多模式解码提取隐藏数据
type: scenario
domain: ctf
path: ctf/misc
technique: wav-manchester-waveform-decode
tags:
- manchester
- wav
- audio-stego
- audacity
- ieee8023
- ge-thomas
- differential
- misc
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-31
  verified_at: '2026-11-08T16:14:01+08:00'
  notes: 已对照原文与21张图核对：方波波形/起始0.1s/半周期0.005s×2=0.01s读参、四种解码器(ieee8023/ge_thomas/differential/non_standard)、tiqu.py实测输出0xGame{waw,this_is_manchesite}(240比特/30字节)、create.py ge_thomas编码往返还原NCTF{HAHAHAHA_CREATE}、参数br100/sr44100/a0.8/sl0.1均见图证。dedup无同链候选。未验证点：未本机复跑脚本；frontmatter无sources/source_url(原文为博主个人工具脚本)。
url: /docs/ctf/misc/ctf-misc-wav-manchester-encoding-waveform-extraction/
draft: false
kb_aliases:
- 音频曼彻斯特
- wav 隐写
- 波形解码
- 非标准曼彻斯特
---

## 一句话结论

CTF Misc 中把数据按曼彻斯特类线路编码调制成 WAV 方波（正负电平各半周期）即可实现音频隐写；解题时在 Audacity 中读波形确定信号起始时间与比特时长（最短电平段 × 2），再用支持 IEEE 802.3、G.E. Thomas、差分及非标准曼彻斯特四种模式的脚本逐段二值化解码，ASCII 预览判读即可还原隐藏文本或文件，0xGame 与 ISCC 赛题均验证可完整还原。

## 原理

- **编码如何进音频**：把原始比特按曼彻斯特规则展开为电平序列（每比特两个半周期），正电平（如 +0.8）表高、负电平表低，按固定比特率（如 100 bps）与采样率（如 44100 Hz）生成方波，前后各留静音（如 0.1 s）写成 16bit PCM WAV。波形在 Audacity 中呈规整矩形方波。
- **读波形定参数**：放大时间轴，信号起点即数据起始时间（如 0.1 s）；方波最短电平持续段是半个比特周期，量出其时长（如 0.105-0.100=0.005 s）后 ×2 得比特时长（0.01 s）。注意要纵观整段波形找"最短"的电平段，而不是只看开头。
- **逐段解码**：以比特时长为窗从起始时间滑窗采样，窗内按阈值（默认 0）二值化；中点前/中点后电平比较即可判 `01`/`10`（IEEE 802.3：`10`→0、`01`→1；G.E. Thomas 相反）；差分模式比较窗首电平与上一窗末电平，有跳变为 0、无跳变为 1（需指定初始边界电平）。还有一种非标准曼彻斯特（如 ISCC 某题）：整窗恒高电平判 0，窗内出现高→低跳变判 1。
- **多模式盲试**：题面通常不说明编码类型，用 `all` 模式跑全部四种解码器，各自转字节后做 ASCII 预览：正确模式输出可读文本（如 flag），错误模式为乱码。差分模式可能比其他模式多/少一个比特（初始电平引入的边界）。
- **判读辅助**：脚本在字节数 ≤50 时直接终端显示，否则存文件；`-eb` 可按期望比特数截断，避免尾部静音/杂音引入的多余比特。

## 触发条件

- WAV 附件波形是规整方波（两条电平轨，如 ±0.8），非音乐/语音；
- 题目名或描述暗示曼彻斯特/编码/信号（如文件名 `audio_with_flag_ieee8023_br100` 已暗示模式与比特率）。

## 利用步骤

1. Audacity 打开 WAV，放大波形：确定信号起始时间 `s`（如 0.1 s）与最短电平段时长（如 0.005 s），比特时长 `b` = 最短段 ×2（0.01 s）。
2. 运行解码脚本：`python tiqu.py xxx.wav all -s 0.1 -b 0.01`（可选 `-t` 阈值、`-dil` 差分初始电平、`-eb` 期望比特数）。
3. 对四种解码器的 ASCII 预览判读，取可读输出；若都不对，检查起始时间/比特时长是否读错，或改用非标准模式。
4. 数据较长时按输出文件取回（`recovered_data_<mode>.out`）。

## PoC

生成侧验证（编码脚本，用于比对参数或出题）：

```bash
python create.py -if flag.txt -o flag -et ge_thomas   # -br 100 -sr 44100 -a 0.8 -sl 0.1 均可调
```

提取侧（0xGame 样本实测输出）：

```text
$ python tiqu.py audio_with_flag_ieee8023_br100.wav ieee8023 -s 0.1 -b 0.01
解码得到的总比特数: 240 -> 30 字节
0xGame{waw,this_is_manchesite}
```

ISCC 风格非标准曼彻斯特样本与差分模式均可用同一脚本验证；编码/提取往返一致（flag.wav → 提取还原原文）。

## 变体与关联

- 编码模式除三种标准曼彻斯特外，还出现"整窗恒电平=0、窗内下降沿=1"的非标准变体（ISCC），脚本已内置。
- 同族音频隐写：LSB、SSTV、DTMF、摩斯电码、SilentEye；区别在于本题是"线路编码调制"而非最低位/频域隐写。
- 生成脚本还可指定任意文件（zip/jpg 等）编码进 WAV，与 01 串文本解码链（差分曼彻斯特→ZIP 修复）衔接。
- 关联：[[ctf-misc-differential-manchester-decode-zip-repair-pixeljihad]]、[[ctf-misc-wav-every-fourth-byte-text-length-prefix]]、[[ctf-misc-silenteye-wav-elf-aes-ecb-dirty-wrapper]]。

## 检测与防御

- 出题视角：可用更小的电平幅度、抖动的比特时长、混入背景噪声或移除静音段来提高读参难度；但防御视角应关注的是数据外带信道本身。
- 数据外带检测视角：方波型 WAV（极少见的长段双电平矩形波形）是隐蔽信道特征，可对音频做电平直方图/过零率检测；对可外传文件的通道做内容审计。
- 说明：仅适用于授权 CTF 竞赛与靶场环境。
