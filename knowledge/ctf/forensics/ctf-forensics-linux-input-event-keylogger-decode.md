---
id: ctf-forensics-linux-input-event-keylogger-decode
title: Linux input_event 键盘记录还原：24 字节 struct + Shift 状态还原按键序列
type: scenario
domain: ctf
path: ctf/forensics
technique: linux-input-event-keylogger-decode
aliases:
- NepBotEvent
- input_event
- Linux 键盘记录
- /dev/input/event
- keylogger 取证
- struct input_event 解析
tags:
- ctf
- forensics
- linux
- keylogger
- input-event
- keyboard
- struct
- misc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:03+08:00'
  notes: 已对照原文核对；24字节input_event、EV_KEY过滤、Shift状态与keycode映射、还原命令与flag均一致；已修正frontmatter domain为ctf；PoC未复跑
---

## 一句话结论

Linux 键盘记录通常直接保存 `/dev/input/event*` 的原始 `struct input_event` 流；该结构在 64 位 Linux 上是 24 字节：`timeval`（16 字节）+ `type`（u16）+ `code`（u16）+ `value`（s32）。按 `<qqHHI` 逐条解析，只处理 `type==1`（EV_KEY）且 `value==1`（按下）的事件，维护 Shift（code 42/54）状态并用 keycode→字符映射，即可把二进制事件流还原成用户输入的文本/命令，从记录中提取口令、数据库名、flag 等信息。

## 原理

- **结构布局**：`struct input_event { struct timeval time; __u16 type; __u16 code; __s32 value; }`。64 位 Linux 的 `timeval` 是 `long tv_sec; long tv_usec`（各 8 字节），所以总长 24 字节；Python `struct.unpack("<qqHHI", data)` 正好对应。
- **事件语义**：`type==1` 是 `EV_KEY`；`value==1` 表示按下，`value==0` 表示释放，`value==2` 表示自动重复。通常只取按下事件；Shift 的 code 为 42（左）/54（右），按下时置位、释放时清零，用于切换大小写/符号映射。
- **keycode 映射**：Linux input keycode 是内核键码（不是 ASCII），需要一张映射表（如 code 2→'1'，16→'q'，30→'a'，57→空格，28→回车）。原文用 `NORMAL_KEYMAP` 与 `SHIFT_KEYMAP` 两张表，Shift 状态决定用哪张。
- **为什么要过滤**：事件流里还有 `EV_SYN`（type 0，同步）、`EV_MSC`、`EV_LED` 等非按键事件；不过滤会把同步码/扫描码误当输入。只处理 `EV_KEY` + 按下，能得到干净的按键序列。
- **还原结果**：原文从记录中还原出 `whoami`、`ifconfig`、`uname -a`、`ps -aux`、`cat /etc/issue`、`pwd`、`mysql -uroot -proot`、`show databases;`、`use NepCTF-20250725-114514;`、`show tables;` 等命令，最终 flag 为 `NepCTF{NepCTF-20250725-114514}`（数据库名部分）。
- **退格/控制键**：`[BKSP]`（code 14）需要按文本编辑语义删除上一个字符；`[CTRL]`（29）等修饰键需要维护状态；若记录里包含 `[CTRL]c`，说明用户按了 Ctrl-C。
- **为什么成立**：input_event 是内核到用户态的原始事件，捕获后无法从记录本身判断“哪些是敏感输入”；只要完整记录按键，就能离线还原。

## 触发条件

- 拿到 Linux 键盘记录文件（原始 `/dev/input/event*` 二进制、或某 keylogger 保存的同样格式数据），且记录包含 `EV_KEY` 事件。
- 记录来自 64 位 Linux（24 字节结构）；32 位 Linux 的 `timeval` 为 8 字节，结构总长 16 字节，需改用 `<IIHHI`/`<llHHI` 等格式。
- 按键映射与目标键盘布局一致（US 布局的 keycode 表；非 US 布局需换表）。
- 记录中有足够上下文（命令、路径、口令）可还原；若只有部分事件/加密，不能还原。
- 需要处理 Shift、Backspace、Ctrl 等修饰键；否则大小写/符号/编辑结果会错。

## 利用步骤

1. 确认文件大小是 24 的整数倍（64 位）或 16 的整数倍（32 位），用 `xxd`/`struct` 试解析前几条，确认 `type` 多为 0/1/4、`code` 在键码范围。
2. 按 24 字节循环读取，`struct.unpack("<qqHHI", data)` 得到 `sec, usec, type_, code, value`。
3. 跳过 `type_ != 1` 的事件；维护 `shift` 状态（code 42/54：value==1 置位，value==0 清零）。
4. 只处理 `value == 1` 的按下事件，按 `shift` 选择 `SHIFT_KEYMAP`/`NORMAL_KEYMAP`，追加字符；未映射的 code 记为 `[code]`。
5. 对 `[BKSP]` 执行删除上一个字符；对 `[CTRL]`/`[CAPSLOCK]` 维护状态；把结果按行输出。
6. 从还原文本中提取命令、数据库名、口令、flag 等关键信息。

## PoC

```python
import struct

NORMAL_KEYMAP = {
    2:'1',3:'2',4:'3',5:'4',6:'5',7:'6',8:'7',9:'8',10:'9',11:'0',12:'-',13:'=',14:'[BKSP]',
    15:'\t',16:'q',17:'w',18:'e',19:'r',20:'t',21:'y',22:'u',23:'i',24:'o',25:'p',26:'[',27:']',
    28:'\n',30:'a',31:'s',32:'d',33:'f',34:'g',35:'h',36:'j',37:'k',38:'l',39:';',40:"'",41:'`',
    44:'z',45:'x',46:'c',47:'v',48:'b',49:'n',50:'m',51:',',52:'.',53:'/',57:' ',58:'[CAPSLOCK]',
    42:'[LSHIFT]',54:'[RSHIFT]',29:'[CTRL]',55:'*',74:'-',78:'+',83:'.',96:'\n'
}
SHIFT_KEYMAP = {
    2:'!',3:'@',4:'#',5:'$',6:'%',7:'^',8:'&',9:'*',10:'(',11:')',12:'_',13:'+',
    16:'Q',17:'W',18:'E',19:'R',20:'T',21:'Y',22:'U',23:'I',24:'O',25:'P',26:'{',27:'}',
    28:'\n',30:'A',31:'S',32:'D',33:'F',34:'G',35:'H',36:'J',37:'K',38:'L',39:':',40:'"',
    41:'~',44:'Z',45:'X',46:'C',47:'V',48:'B',49:'N',50:'M',51:'<',52:'>',53:'?',57:' '
}

def decode(path):
    out, shift = "", False
    with open(path, "rb") as f:
        while True:
            data = f.read(24)
            if len(data) < 24:
                break
            sec, usec, type_, code, value = struct.unpack("<qqHHI", data)
            if type_ != 1:
                continue
            if code in (42, 54):
                shift = (value == 1)
                continue
            if value != 1:
                continue
            ch = (SHIFT_KEYMAP if shift else NORMAL_KEYMAP).get(code, f"[{code}]")
            if ch == "[BKSP]":
                out = out[:-1]
            else:
                out += ch
    return out

print(decode("NepBot_keylogger"))
```

原文输出包含 `mysql -uroot -proot`、`use NepCTF-20250725-114514;` 等，flag 为 `NepCTF{NepCTF-20250725-114514}`；本卡未复跑原始记录。

## 变体与关联

- **32 位记录**：`struct input_event` 的 timeval 为 8 字节，总长 16 字节；用 `<llHHI` 或 `<IIHHI` 解析。
- **非 US 布局**：替换 keycode 映射表；也可用 `xkb`/`evdev` 库的键码表自动映射。
- **自动重复/释放**：若需要处理长按，可对 `value==2` 去重或按时间间隔合并；一般取证只取按下。
- **其他输入设备**：鼠标/触摸事件也走 input_event，可按 `type`（EV_REL/EV_ABS/EV_MSC）区分；本卡只处理键盘。
- **关联**：`[[defense-forensics-memory-netscan-malfind-dump-injected-process]]`（内存取证）、`[[ctf-forensics-pcap-shell-history-base64-nc-image-exfil]]`（命令历史取证）、`[[ctf-forensics-memory-image-flag-keyword-search]]`（内存镜像关键字检索）。
- **边界**：若记录只含部分事件、或 keylogger 对数据做了加密/压缩，需先解密；若目标使用非 US 布局，映射表必须匹配。

## 检测与防御

- **检测**：主机上出现读取 `/dev/input/event*` 的进程、异常 keylogger 文件（24 字节对齐、包含大量 EV_KEY）；EDR 监控 `open("/dev/input/event")` 与输入设备读取；CTF/取证中按文件大小与事件结构识别。
- **防御**：限制普通用户读取输入设备（`/dev/input/event*` 权限）、使用安全输入/受保护输入、检测并阻断 keylogger；对敏感输入使用一次性/虚拟键盘。
- **取证注意**：解析时保留原始文件哈希与时间戳；对 `[BKSP]`/`[CTRL]` 等做语义还原，但不要篡改原始记录；把还原结果与进程/网络/文件时间线关联。
