---
id: ctf-forensics-usb-hid-keyboard-reference-mapping
title: USB HID 键盘流量还原击键：参考 pcap 建立 Shift/非 Shift 键位映射
type: scenario
domain: ctf
path: ctf/forensics
technique: usb-hid-keyboard-pcap-reference-mapping
tags:
- ctf
- forensics
- usb
- hid
- keyboard
- pcap
- tshark
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:23+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
url: /docs/ctf/forensics/ctf-forensics-usb-hid-keyboard-reference-mapping/
draft: false
kb_aliases:
- USB HID 键盘取证
- usbhid.data 解码
- 键盘流量还原
- NewKeyboard
- 参考流量建映射
- 击键还原
---

## 一句话结论

USB 键盘流量里的 HID report 只包含“哪些键位被按下”和修饰键状态，不含字符；若题目同时给出一份“按已知字符顺序敲击”的参考 pcap，就可以用参考流量把每个键位（区分是否按 Shift）映射到字符，再用同一映射解码目标 pcap，还原完整击键串。

## 原理

- **USB HID 键盘报告格式**：Boot Keyboard 报告通常为 8 字节：第 0 字节是修饰键位图（bit0 Left Ctrl、bit1 Left Shift、bit2 Left Alt、bit3 Left GUI、bit4 Right Ctrl、bit5 Right Shift、bit6 Right Alt、bit7 Right GUI），第 1 字节保留，第 2~7 字节是当前按下的 6 个键码（HID Usage ID）。Wireshark 的 `usbhid.data` 字段会把报告显示为十六进制；有些抓包带 1 字节 Report ID，解析前要先剥掉。
- **按下沿检测**：每帧报告是“当前所有按下的键”的快照，长按会重复出现。用 `pressed = bits - prev_bits` 取新增按下的键位，才能得到一次击键；松开时 bits 减少，不产生字符。
- **Shift 映射**：同一个 HID 键码在按下/未按下 Shift 时对应不同字符（如 `1` 与 `!`、`-` 与 `_`）。参考 pcap 的每一帧同时给出键位和 Shift 状态，因此可以建立两张表：`unshift_map[键位] = 字符`、`shift_map[键位] = 字符`。
- **参考流量定序**：若参考 pcap 是按目标字符集顺序敲击的（例如文件名 `abcdefghijklmnopqrstuvwxyz1234567890-_!{}.pcapng`），则第 k 次“新增按键”就对应字符集第 k 个字符；把该次键位与字符绑定，即可得到映射。参考流量必须覆盖目标中出现的所有键位与 Shift 组合。
- **目标解码**：对目标 pcap 做同样的按下沿检测，按当前帧的 Shift 位选择映射表，查表拼接；遇到未覆盖键位输出占位符，人工补齐。
- **为什么可行**：HID 键码与物理键位一一对应，键盘布局固定；参考流量提供了“键位→字符”的标定，绕过了手工查 HID Usage 表的步骤，也自动处理了 Shift 变体。

## 触发条件

- 抓到 USB 键盘的 pcap/pcapng，且能看到 `usbhid.data` 字段（通常为 USBPcap 在 Windows 上抓取，或 Linux usbmon）。
- 题目/场景同时提供一份参考流量，其输入字符顺序已知（常见为文件名即字符集）。
- 目标流量与参考流量使用同一键盘布局/同一套键位编码。
- 目标输入只包含参考字符集覆盖的字符；若含功能键、组合键、Ctrl 快捷键，需要额外处理。
- 抓包包含完整的按下/松开帧，未严重丢包。

## 利用步骤

1. 确认抓包中有键盘设备：Wireshark 过滤 `usbhid.data`，观察报告长度与 Report ID。
2. 用 tshark 导出所有 `usbhid.data` 十六进制值：`tshark -r ref.pcapng -Y usbhid.data -T fields -e usbhid.data`。
3. 对每行 hex 去掉 Report ID 字节，转成 bit 集合；用 `pressed = bits - prev` 取新增键位，过滤修饰键 bit1（Left Shift）。
4. 按参考字符集顺序，把第 k 次新增键位记录到 `unshift_map` 或 `shift_map`（依据该帧是否含 Shift 位）。
5. 对目标 pcap 重复步骤 2~3，按映射表逐键解码；未命中时打印键位编号，人工查 HID Usage 表补齐。
6. 检查结果是否包含 flag 格式/可读文本；若字符顺序错乱，检查 Report ID 剥离、长按重复、丢帧与 Shift 键位。

## PoC

```python
import subprocess
from pathlib import Path

REF = Path("abcdefghijklmnopqrstuvwxyz1234567890-_!{}.pcapng")
TARGET = Path("newkeyboard.pcapng")
CHARSET = "abcdefghijklmnopqrstuvwxyz1234567890-_!{}"

def reports(path: Path):
    out = subprocess.check_output([
        "tshark", "-r", str(path), "-Y", "usbhid.data",
        "-T", "fields", "-e", "usbhid.data",
    ], text=True, stderr=subprocess.DEVNULL)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        payload = bytes.fromhex(line)[1:]  # 去掉 Report ID
        bits = set()
        for i, b in enumerate(payload):
            for bit in range(8):
                if b & (1 << bit):
                    bits.add(i * 8 + bit)
        yield bits

def build_maps(ref_reports, charset):
    unshift, shift = {}, {}
    prev, idx = set(), 0
    for bits in ref_reports:
        pressed = bits - prev
        keys = [b for b in pressed if b != 1]  # bit1 = Left Shift
        if keys and idx < len(charset):
            key, ch = keys[0], charset[idx]
            idx += 1
            (shift if 1 in bits else unshift)[key] = ch
        prev = bits
    return unshift, shift

def decode(target_reports, unshift, shift):
    prev, out = set(), []
    for bits in target_reports:
        pressed = bits - prev
        keys = [b for b in pressed if b != 1]
        if keys:
            key = keys[0]
            table = shift if 1 in bits else unshift
            out.append(table.get(key, f"<UNK_{key}>"))
        prev = bits
    return "".join(out)

u, s = build_maps(reports(REF), CHARSET)
print(decode(reports(TARGET), u, s))
```

手工查表时可用 HID Usage ID：`0x04~0x1d` 对应 `a~z`，`0x1e~0x27` 对应 `1~0`，`0x2d` 为 `-`/`_`，`0x2f` 为 `[`/`{`，`0x30` 为 `]`/`}`，`0x34` 为 `'`/`"` 等；Shift 位为 bit1。

## 变体与关联

- **无参考流量**：直接按 HID Usage ID + Shift 表解码；需要处理键盘布局（US/UK/DE）与 OS 层映射差异。
- **Report ID 变体**：部分抓包首字节是 Report ID，部分是纯报告；长度 8/9 字节时先判断并剥离。
- **NKRO 键盘**：报告可能扩展为位图（每个键一位），不是 6 键数组；解析逻辑要按位图处理。
- **组合键/快捷键**：Ctrl/Alt/GUI 修饰位需要单独建模；可还原 `Ctrl+C`、`Win+R` 等。
- **关联卡片**：[[pentest-initial-access-usb-hid-keyboard-injection-powershell-scheduled-task]]（USB HID 注入攻击面）；[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]（RDP scancode 还原键盘输入）。

## 检测与防御

- **取证价值**：USB 键盘流量可还原口令、聊天内容、命令行；抓到 pcap 后应优先检查 `usbhid.data`、设备描述符与时间线。
- **物理安全**：限制未知 USB 设备接入（USB 端口管控、设备白名单、Endpoint Detection）；BadUSB/键盘注入设备可在数秒内执行命令。
- **抓包与留存**：在授权范围内部署 USBPcap/usbmon 作为取证手段；注意 pcap 本身可能含敏感击键，按敏感数据保管。
- **检测**：监控异常的 HID 设备插入、短时间大量击键、键盘设备与脚本/计划任务创建的时间关联。
