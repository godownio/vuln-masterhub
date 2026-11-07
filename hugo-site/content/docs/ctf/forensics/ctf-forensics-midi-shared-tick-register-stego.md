---
id: ctf-forensics-midi-shared-tick-register-stego
title: MIDI 多轨共享时钟隐写：note 事件异或寄存器 + 时间网格偏移还原隐藏消息
type: scenario
domain: ctf
path: ctf/forensics
technique: midi-shared-tick-register-stego
tags:
- ctf
- forensics
- midi
- steganography
- mido
- tick-grid
- register-model
- self-check
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:30+08:00'
  notes: 对照 Misc239：format1/5 track/division96、12 寄存器 BASE、tick 3072、48 网格、target 自校验一致
url: /docs/ctf/forensics/ctf-forensics-midi-shared-tick-register-stego/
draft: false
kb_aliases:
- Midnight Sonata
- MIDI 轨道隐写
- 共享 tick 时钟
- 寄存器异或 note 事件
- 八分音符网格
- target.txt 自校验
---

## 一句话结论

MIDI format 1 的多条轨道共享同一条绝对 tick 时钟；把每个 note-on 按 channel 映射到 32 位寄存器并异或和弦值，再用 48 tick（八分音符）网格读出正式段，就能从“练习段只是节拍器、正式段才携带信息”的 MIDI 里还原隐藏消息，并用 target.txt 的终态寄存器做自校验。

## 原理

- MIDI format 1 允许多条 track 并行播放，所有 track 的 delta-time 累加后落在同一套绝对 tick 时钟上。`division=96` 时，48 tick 等于一个八分音符；四个声部的 note-on 都落在 48 的整数倍网格上，形成隐藏的“共同时钟”。
- track0 的 marker 给出规则：12 个 32 位寄存器初值 `BASE=11111111,22222222,...,cccccccc`（规律 `BASE[i]=(i+1)*0x11111111`）；`EX1~EX6` 是练习段每小节结束后的寄存器状态；`target.txt` 是整曲跑完后的 12 个寄存器终值。
- 寄存器模型：每个 note 事件按所在 MIDI channel 选中 `S[channel]`，把该和弦的数值异或进去。例如 EX1 中 S0 从 `0x11111111` 变为 `0x33333333`，异或差为 `0x22222222`；EX6 两个声部在 ch7/ch8 同时落下，S7、S8 同步变化，说明同一和弦值会写进它涉及的每个 channel。
- 练习段和弦间隔 384 tick（一小节），正式段从 tick 3072 开始、间隔 48 tick；T1 是确定性琶音 `45+(5*i mod 18)`（周期 18），T4 是半音阶 `36+(i mod 12)`（周期 12），两者是纯节拍器，真正携带信息的是 T2、T3 以及 T2 力度相对共享时钟的偏移。
- 按同一 tick 网格读出正式段并跑完寄存器规则后，终态与 `target.txt` 完全吻合，说明解析模型（channel→寄存器、和弦值、网格）正确；这种“自校验终态”是 MIDI 隐写题常见的判据。

## 触发条件

- 拿到 MIDI 文件与配套的目标状态文件（如 target.txt）、marker 规则。
- 多轨 format 1，note-on 落在统一 tick 网格上；存在可识别的练习段/正式段分界。
- 规则可用寄存器/状态机建模，且有终态校验值。
- 无需播放音频，静态解析事件即可。

## 利用步骤

1. 用 `mido` 读取 MIDI，解析 track0 的 marker：BASE、EX1~EX6、target.txt。
2. 把每条 track 的 note-on 事件累加 delta-time，换算为绝对 tick、channel、note、velocity。
3. 统计 note-on 的 tick 分布，找公共网格（本题 48 tick）与练习段/正式段分界（tick 3072）。
4. 按 channel 映射寄存器，按规则异或和弦值；用 EX1~EX6 验证模型，跑完整曲后与 target.txt 比对。
5. 在正式段按 48 tick 网格读取 T2/T3 的音高与 T2 力度偏移，映射成明文字符；用已知 flag 前缀校验。

## PoC

```python
import mido

def note_events(track):
    at, out = 0, []
    for msg in track:
        at += msg.time
        if msg.type == "note_on" and msg.velocity > 0:
            out.append((at, msg.channel, msg.note, msg.velocity))
    return out

mid = mido.MidiFile("midnight.mid")
base, ex = None, []
for msg in mid.tracks[0]:
    if msg.type == "marker":
        if msg.text.startswith("BASE="):
            base = [int(x, 16) for x in msg.text[5:].split(",")]
        elif msg.text.startswith("EX"):
            ex.append(msg.text)

target = [int(l.strip(), 16) for l in open("target.txt") if l.strip()]
v1 = note_events(mid.tracks[1])
real = [e for e in v1 if e[0] >= 3072]      # 正式段起点 tick 3072

# 统计网格：所有 note-on 的 tick 是否落在 48 的倍数
assert all(t % 48 == 0 for t, *_ in v1)
```

```python
# 按 channel 更新寄存器：S[ch] ^= chord_value
S = base[:]
for t, ch, note, vel in all_note_events:
    S[ch] ^= chord_value(t, ch, note, vel)
assert S == target          # 自校验通过
```

## 变体与关联

- 变体：载体可换成力度、弯音轮、控制器事件、program change；网格可换成三连音/十六分音符；寄存器模型可换成 CRC/哈希链。
- 变体：用练习段作为“已知明文”恢复规则，再应用到正式段；用终态校验排除错误解析。
- 关联：[[ctf-forensics-fhir-observation-base4-affine-stego]]（结构化数据字段隐写）、[[ctf-forensics-openigtlink-position-trajectory-pixel-font]]（轨迹数据恢复文本）。
- 边界：不同 MIDI 的 division/format 不同；若 note-on 不在统一网格或存在大量装饰音，需要先降噪；规则未知时需从 marker 和已知状态反推。

## 检测与防御

- 检测：MIDI 中多条 track 的 note-on 精确落在同一 tick 网格、存在 marker 规则/目标状态文件、练习段与正式段节奏突变；事件值与文本字符存在映射关系。
- 防御/取证：对可疑 MIDI 保留原始文件与时间戳；用多轨绝对 tick 对齐分析；检查 marker、文本轨、力度/控制器异常；用终态校验确认模型。
- 加固（若用于隐蔽通信）：不要依赖公开的 MIDI 结构隐写；对导出文件做格式规范化会破坏隐写；检测工具可统计网格规律与事件分布。
