---
id: ctf-forensics-deepsound-audio-stego-extract
title: DeepSound 音频隐写：WAV 载体中提取隐藏文档与密码链
type: scenario
domain: ctf
path: ctf/forensics
technique: deepsound-audio-stego-extract
aliases:
- DeepSound
- 音频隐写
- WAV 隐藏文件
- DeepSound 2.2
- AD ASTRA
tags:
- ctf
- forensics
- stego
- audio
- wav
- deepsound
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:41+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
---

## 一句话结论

当 WAV/MP3 音频体积异常大、频谱/播放无明显异常但文件名或题目暗示“声音/星星/secret”时，可用 DeepSound 打开载体音频，提取隐藏文件；隐藏文件若加密，密码常来自图片文字/EXIF/题目提示（本题为 `To the stars we come from`），提取出的 DOCX 再用 office2john + hashcat 爆破。

## 原理

- **DeepSound**：Windows 音频隐写工具，把秘密文件编码进 WAV/MP3 的音频数据（利用人耳不敏感的低位/回声等），支持 AES 密码；`DeepSound 2.2` 界面可 `Open carrier files` → `Extract secret files`。
- **载体识别**：WAV 采样率/声道正常但文件大小远大于时长对应值；`binwalk`/`foremost` 可能看不到隐藏文件，因为它在音频采样域而非尾部追加。
- **密码链**：本题图片文字 `To the stars we come from` 是 DeepSound 密码；提取出 `flag.docx`；DOCX 打开需要密码，用 `office2john` 提取 hash，`hashcat -m 9600`/john + rockyou 爆破得到 `skadi2520`；打开后隐藏文字即 flag。
- **为什么成立**：音频隐写把文件编码进采样，常规文件尾扫描/strings 无效；工具与密码正确时提取是确定的。
- **边界**：DeepSound 版本/密码错误会失败；MP3 有损压缩可能破坏隐藏数据（优先 WAV）；隐藏文件可能被再次加密/分卷。

## 触发条件

- 音频文件（WAV/MP3）体积异常/题目提示音频隐写；有 DeepSound 或等价工具。
- 隐藏文件加密时，密码可从图片文字、EXIF、题目 hint、文件名获得。
- 提取出的文档（DOCX/PDF/ZIP）需要密码时，有 office2john/hashcat/john 环境。
- 目标环境允许运行 Windows GUI 工具或 Wine。

## 利用步骤

1. 用 `file`/`ffprobe` 查看音频格式、时长、大小；判断体积是否异常。
2. 用 DeepSound 2.2 打开载体 WAV，点击 `Extract secret files`；输入密码（本题 `To the stars we come from`）。
3. 提取出 `flag.docx`；用 `office2john.py flag.docx > hash.txt`，`hashcat -m 9600 hash.txt rockyou.txt` 或 `john --wordlist=rockyou.txt hash.txt` 爆破。
4. 用得到的密码 `skadi2520` 打开 DOCX；若正文是“FLAG NOT THERE”，检查图片/隐藏文字/文本框/批注。
5. 本题在图片中看到 `sdpcsec{AD_ASTRA_INFINITUM}`。
6. 若 DeepSound 不可用，尝试 `deepsound2john.py` 提取 hash 后用 hashcat 爆破密码，再回到 GUI 提取。

## PoC

```text
DeepSound 2.2:
  Open carrier files -> flag.wav
  Extract secret files -> 输入密码 To the stars we come from
  -> flag.docx

DOCX 密码爆破:
  office2john.py flag.docx > docx.hash
  hashcat -m 9600 docx.hash rockyou.txt
  # 或 john --wordlist=rockyou.txt docx.hash
```

## 变体与关联

- **变体（密码来源）**：图片文字/EXIF/文件名/题目描述/二维码；先收集所有可见线索。
- **变体（工具）**：SilentEye、OpenPuff、MP3Stego、`deepsound2john`；不同工具的容量/密码/格式不同。
- **变体（下一层）**：DOCX/PDF/ZIP 密码、图片隐藏文字、音频频谱；逐层剥离。
- **关联卡片**：[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 密码爆破）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（音频频谱）、[[ctf-misc-tupper-self-referential-formula-decode]]（本题前置 Tupper 密码）。
- **边界**：有损 MP3 可能破坏数据；DeepSound 密码错误/版本不兼容会失败；DOCX 密码可能不在 rockyou 中，需要规则/掩码。

## 检测与防御

- **CTF 识别**：音频体积异常 + 题目“声音/星星/secret” + 图片文字密码，优先 DeepSound/SilentEye。
- **数据防泄露**：DLP 可检测音频隐写工具特征/异常采样；敏感文件不要用音频隐写。
- **取证**：保留原始 WAV，避免转码/重采样；记录工具版本与密码来源。
