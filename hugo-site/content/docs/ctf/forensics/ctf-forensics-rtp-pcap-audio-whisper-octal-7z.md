---
id: ctf-forensics-rtp-pcap-audio-whisper-octal-7z
title: PCAP 中 RTP 语音导出与 Whisper 转写：八进制数字串还原 7z 密码
type: scenario
domain: ctf
path: ctf/forensics
technique: rtp-pcap-audio-whisper-octal-7z
tags:
- ctf
- forensics
- pcap
- rtp
- audio
- whisper
- octal
- 7z
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:35+08:00'
  notes: 已对照原文与图 02-07 核对：RTP_UDP/G.711 PCMA、rtpbreak+sox、Whisper 转写、八进制长串解出 5f3eb916bf08e610aeb09f60bc955bd8 一致（本地复算八进制解码通过）；未复跑 pcap。
url: /docs/ctf/forensics/ctf-forensics-rtp-pcap-audio-whisper-octal-7z/
draft: false
kb_aliases:
- RTP 流导出
- rtpbreak
- sox 语音增强
- Whisper 转写
- 八进制 ASCII 分组
---

## 一句话结论

全 UDP 的 pcap 若含 RTP 语音流，可在 Wireshark 启用 `RTP_UDP` 后按 RTP Streams 试听/导出，或用 `rtpbreak` 拆出 raw 再用 `sox` 转 wav 并归一化；对语音跑 Whisper 转写得到长串只含 `0-7` 的数字，按 2–3 位一组解释为八进制 ASCII，得到 16 字节十六进制口令，用它解 7z 取得下一层音频与文本。

## 原理

- RTP 把语音编码（本题为 G.711 PCMA/8000，Wireshark 显示 `PT=ITU-T G.711 PCMA`）封装在 UDP 里；Wireshark 默认不解析 RTP，需要在 `Analyze → Enabled Protocols` 勾选 `RTP_UDP`，再走 `Telephony → RTP → RTP Streams`。
- `rtpbreak` 按 SSRC/端口把 RTP 流拆成 raw payload；`sox` 以 `-r 8000 -c 1 -t ul`（8000 Hz、单声道、u-law）读取，`gain -n` 做归一化。原始录音音量很小，不增幅几乎听不清。
- Whisper 对每个 wav 做中文转写；大量转写结果是误导文本，唯一异常是一条只含 `0-7` 的长数字串。数字 8/9 不出现，说明它是八进制表示。
- 可打印 ASCII 的八进制码是 1–3 位（如 `5`=65、`f`=146、`3`=63）；把长串按 2–3 位分组、每组解释为一个八进制 ASCII，即可还原出 32 个十六进制字符（16 字节），正好是 7z 密码。因为字符集与分组长度受限，正确分组几乎唯一。
- 7z 解出的音频内容是社交工程对话（地点、日期、时间），文本用于补全历史背景；这部分是题目剧本，不属于通用技术。

## 触发条件

- pcap 以 UDP 为主，且题目描述暗示“监听/语音/通话”；Wireshark 能识别 RTP 流。
- 语音编码与采样率已知（或能从 RTP PT/SSRC 推断），可以导出为 wav。
- 转写文本中出现只含 `0-7` 的长数字串，且后续压缩包需要密码。
- 有 Whisper/ffmpeg 等离线环境（或可替换为人工听译）。

## 利用步骤

1. Wireshark 中启用 `RTP_UDP`，`Telephony → RTP → RTP Streams` 选中流，`Play Streams` 试听，或 `Export` 导出载荷。
2. 批量处理：`rtpbreak -r Data.pcap -g -m -d ./` 生成 `rtp.0.N.raw`。
3. 对每个 raw 执行 `sox -r 8000 -c 1 -t ul in.raw out.wav gain -n`。
4. 用 Whisper 逐文件转写，`language="zh"`；把结果写入文本后搜索只含 `[0-7]` 的长串。
5. 对该串做 2–3 位八进制 ASCII 分组解码，得到 32 位十六进制口令。
6. 用口令解 7z，读取下一层音频/文本，继续后续谜题。

## PoC

```bash
rtpbreak -r Data.pcap -g -m -d ./
for f in rtp.0.*.raw; do
  sox -r 8000 -c 1 -t ul "$f" "${f%.raw}.wav" gain -n
done
```

```python
import glob, whisper
model = whisper.load_model("large-v3")
for f in sorted(glob.glob("*.wav")):
    print(f, model.transcribe(f, language="zh")["text"])

s = "651466314514271616614214660701456661601411451426071146666014214371656514214470"
from functools import lru_cache

@lru_cache(None)
def decode(i):
    if i == len(s):
        return ""
    for width in (2, 3):
        g = s[i:i + width]
        if len(g) != width:
            continue
        v = int(g, 8)
        if 0o40 <= v <= 0o176:            # 可打印 ASCII
            rest = decode(i + width)
            if rest is not None:
                return chr(v) + rest
    return None

print(decode(0))   # 5f3eb916bf08e610aeb09f60bc955bd8
```

说明：RTP 载荷的采样率/编码按实际流量调整；八进制解码的 2–3 位分组用 DFS 保证输出为可打印 ASCII。未在本机复跑原题 pcap。

## 变体与关联

- **直接导出**：Wireshark `Play Streams`/`Export` 适合少量流；`rtpbreak` 适合批量拆流。
- **音频隐写**：若频谱不是语音而是 Morse/SSTV/多频点，转写无效，应改看频谱；见 [[ctf-forensics-nbfm-iq-morse-digit-password-zip]]、[[ctf-forensics-sstv-audio-image-decode]]。
- **口令编码**：八进制 ASCII 常被误认为十进制或十六进制；先看字符集（是否只含 0–7/0–9/a–f）再决定进制。
- **语音转写**：Whisper 对噪声/低音量敏感，先 `gain -n` 归一化再转写；也可用云端 ASR，但注意数据保密。

## 检测与防御

- 语音通话若包含口令/敏感信息，应使用端到端加密（SRTP）而非明文 RTP；G.711 无加密，抓包即可还原。
- 检测：pcap 中出现 RTP 明文流、大量语音流且无 SRTP；结合 DL/ASR 可批量提取口令。
- 防御：禁用不必要的语音服务、强制 SRTP、对通话内容做脱敏与访问控制。
