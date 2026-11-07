---
id: ctf-reverse-ios-swift-nine-grid-path-weight-encoding
title: iOS Mach-O Swift 九宫格手势逆向：路径数字串加权编码与 target_all 反查
type: scenario
domain: ctf
path: ctf/reverse
technique: ios-swift-nine-grid-path-weight-encoding
tags:
- ctf
- reverse
- ios
- mach-o
- swift
- gesture
- path-encoding
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:47:58+08:00'
  notes: '已对照原文 Nineapple 节与图 24 核对：Mach-O/IDA、Right! flag is : XREF、current_key += digit*weight[idx]、weights 9 个 u64（10564859903...3）、target_all 33 个 u64、map_list Swift small string、偏移 0x10340/0x103B0/0x104E0/0x109C0 与 enc(path) 反查，均与原文 exp 一致。未验证点：PoC 未本机复跑、未读取附件二进制；CTF 题无组件版本；frontmatter 无 sources/source_url。'
url: /docs/ctf/reverse/ctf-reverse-ios-swift-nine-grid-path-weight-encoding/
draft: false
kb_aliases:
- iOS 九宫格手势逆向
- Swift small string
- 手势路径加权编码
- target_all 反查
- Nineapple
---

## 一句话结论

iOS App Bundle 的 Mach-O 若校验“九宫格手势路径”，通常会把路径数字串（如 `1478`）按固定权重数组算成一个整数 `sum(digit[i]*weight[i])`，再与内置 `target_all` 逐项比较；从二进制数据区读出 `weights`、`map_list`（路径↔字符）和 `target_all`，建立 `enc(path)->char` 反查表即可还原每个字符，拼出 flag，无需模拟 UI 画图。

## 原理

- **iOS App Bundle**：包含 `_CodeSignature/`、`embedded.mobileprovision`、`Info.plist`、主二进制（Mach-O）、`PkgInfo`；主二进制可用 IDA/Ghidra 打开。
- **Swift 字符串**：Swift 的短字符串（≤15 字节）内联在 16 字节结构中，常见布局为最后字节最高位 tag、低 4 位存长度，前 `len` 字节为 ASCII；本题 `map_list` 以 `(char, digitstr)` 成对存放。
- **手势编码**：每次画一个点（数字 1–9），`current_key += digit * weight[idx]`，`idx++`；`weight` 固定（本题 `[10564859903, 880404991, 67723460, 4837390, 322492, 20155, 1185, 65, 3]`），等价于 `enc(dstr)=Σ digit[i]*weight[i]`。
- **校验**：`map_list` 把路径数字串映射到字符；`target_all` 是 33 个 u64，每个对应 flag 一个字符的 `enc(path)`。程序逐项比较 `key_all` 与 `target_all`，全部匹配则输出 `Right! flag is : <current_flag>`。
- **反查**：对 `map_list` 中每个 `(char, path)` 计算 `enc(path)`，得到 `enc(path)->char`；再对 `target_all[i]` 查表，拼出 flag。
- **为什么可行**：加权编码是确定性的；`weights`、`map_list`、`target_all` 都静态存放在二进制数据区，不需要运行 App 或模拟手势。

## 触发条件

- 拿到 iOS App Bundle/IPA，主二进制为 Mach-O；字符串可见“Please draw an unlock pattern”“Right! flag is :”等。
- 校验函数中出现 `current_key += digit * weight[idx]`、`target_all` 数组和 `map_list` 路径↔字符表。
- `weights` 为 9 个 u64（对应最多 9 个节点）；`target_all` 长度等于 flag 字符数。
- `map_list` 以 Swift small string（16 字节内联）成对存储。

## 利用步骤

1. 用 `file`/`otool`/IDA 确认 Mach-O 与架构；从字符串 `Right! flag is :` 做 XREF 定位校验函数。
2. 在校验函数/初始化（如 `LockViewModel`）中定位 `weights`、`target_all`、`map_list` 的地址/偏移。
3. 从二进制数据区按 9 个 u64 读 `weights`；按 flag 长度读 `target_all`。
4. 解析 `map_list`：每 16 字节按 Swift small string 解析，成对得到 `(char, digitstr)`。
5. 对每个 `(char, digitstr)` 计算 `enc=Σ int(digit)*weight[i]`，建立 `enc -> char` 字典。
6. 遍历 `target_all`，用 `enc` 查表拼出 flag；若查不到，检查权重/长度/字节序或路径对顺序。
7. 用程序逻辑复验（重新计算 `key_all` 与 `target_all` 比较）。

## PoC

```python
import struct

data = open("Nine", "rb").read()
WEIGHTS_OFF, TARGETS_OFF = 0x10340, 0x103B0
MAP_START, MAP_END = 0x104E0, 0x109C0

weights = [struct.unpack_from("<Q", data, WEIGHTS_OFF + i*8)[0] for i in range(9)]
targets = [struct.unpack_from("<Q", data, TARGETS_OFF + i*8)[0] for i in range(33)]

def parse_swift_small_string_16(chunk):
    last = chunk[-1]
    if not (last & 0x80):
        raise ValueError("not small-string")
    return chunk[:last & 0x0F].decode("ascii", "ignore")

ss = [parse_swift_small_string_16(data[o:o+16]) for o in range(MAP_START, MAP_END, 16)]
pairs = [(ss[i], ss[i+1]) for i in range(0, len(ss), 2)]  # (char, digitstr)

def enc_path(dstr):
    return sum(int(c) * weights[i] for i, c in enumerate(dstr) if i < len(weights))

rev = {enc_path(dstr): ch for ch, dstr in pairs}
print("".join(rev[t] for t in targets))
```

说明：偏移来自原文静态分析，实际题目需按二进制调整；`parse_swift_small_string_16` 假设小字符串 tag 布局。未在本机对附件复跑。

## 变体与关联

- **Swift 长字符串**：超过 15 字节会走堆分配，结构不同；需按 Swift ABI 解析。
- **路径编码**：加权和、base-N、哈希、CRC 等；先识别 `weights`/`target_all` 的数据布局。
- **Android 对应**：九宫格手势常在 Java/Kotlin 层，用 `PatternView` 回调 + 数组校验；可参考 [[ctf-reverse-ios-macho-unicorn-mach-ipc-rc4]]（iOS Mach-O 逆向）。
- **关联**：[[ctf-reverse-android-apk-environment-state-derived-keystream]]（移动端路径/环境绑定校验）。

## 检测与防御

- 识别：Mach-O 中 Swift small string 表、`weights`/`target_all` 常量；字符串 XREF 定位校验函数。
- 防护：不要把 `target_all`/`map_list` 以明文常量放在二进制；可用服务端校验、白盒/混淆、运行时完整性检查。
- CTF：即使 App 有反调试，静态数据区仍可直接读取；必要时用 Frida hook 校验函数。
