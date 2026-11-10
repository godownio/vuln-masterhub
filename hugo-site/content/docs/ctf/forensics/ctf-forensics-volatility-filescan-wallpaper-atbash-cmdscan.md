---
id: ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan
title: Volatility filescan 定位用户壁纸文件，按 cmdscan 提示做 Atbash 解码
type: scenario
domain: ctf
path: ctf/forensics
technique: volatility-filescan-wallpaper-cmdscan-atbash
tags:
- ctf
- forensics
- memory
- volatility2
- filescan
- dumpfiles
- cmdscan
- atbash
- wallpaper
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:10:40+08:00'
  notes: 已对照图06 cmdscan 的 Atbash wallpaper 提示、图04 filescan 的 TranscodedWallpaper.jpg/物理地址 0x000000003e1a4d00、图05 壁纸字符串 azt12vwgjh56g7ts5v4d2qsx 核对；Atbash 解码 zag12edtqs56t7gh5e4w2jhc 经逐字母复算正确。属 raw3 单一挑战链，未拆分。未复现。
url: /docs/ctf/forensics/ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan/
draft: false
kb_aliases:
- 内存取证壁纸文件
- TranscodedWallpaper
- Volatility filescan dumpfiles
- cmdscan Atbash 提示
- Atbash 换位密码
---

## 一句话结论

从内存镜像的 `conhost` 命令历史（`cmdscan`）看到“Atbash wallpaper”提示后，用 `filescan` 枚举到当前用户的 `TranscodedWallpaper.jpg` 文件对象，再按物理地址用 `dumpfiles` 导出壁纸；壁纸上的字符串 `azt12vwgjh56g7ts5v4d2qsx` 做 Atbash 反向字母替换得到 `zag12edtqs56t7gh5e4w2jhc`。

## 原理

- **cmdscan 读命令历史**：Volatility2 的 `cmdscan` 从 `conhost.exe` 内存中恢复命令行窗口输入过的命令；攻击者/出题人留下的“Atbash wallpaper”直接提示了解码方式与载体。
- **filescan 枚举文件对象**：Windows 把打开的或缓存的文件以文件对象形式保存在内存中，`filescan` 会列出文件名、物理地址与偏移；当前壁纸通常被转码缓存为 `%APPDATA%\Microsoft\Windows\Themes\TranscodedWallpaper.jpg`。
- **dumpfiles 按物理地址导出**：`dumpfiles -Q <physical offset>` 依据文件对象中的物理页信息，把文件内容从内存中拼接出来；得到的 JPG 可直接查看。
- **Atbash 为什么能解**：Atbash 是单表替换，字母表首尾互换（a↔z、b↔y、c↔x……），非字母字符不变；`azt12vwgjh56g7ts5v4d2qsx` 逐字母替换后即为 `zag12edtqs56t7gh5e4w2jhc`。本题两个字符串的差异只在字母部分，数字 `12/56/7/5/4/2` 原样保留，符合 Atbash 特征。

## 触发条件

- 有 Windows 内存镜像，且 `conhost.exe`/命令历史仍驻留（未重启或未被覆盖）。
- 目标用户设置过壁纸，且转码缓存文件存在内存中（或文件对象仍可枚举）。
- Volatility2 profile 与镜像版本匹配。
- 题目/线索提示古典密码（本题为 Atbash），或可观察字符串的字母反向特征。

## 利用步骤

1. 运行 `cmdscan`，在命令历史中找提示；本题出现 `Atbash wallpaper`。
2. 运行 `filescan`，过滤 `Themes`/`TranscodedWallpaper`，得到文件对象与物理地址（如 `0x000000003e1a4d00`）。
3. 用 `dumpfiles -Q <地址> -D dump/` 导出文件，确认是 JPG/PNG 并打开。
4. 读取壁纸上的隐藏字符串。
5. 对字符串做 Atbash（字母反转）：`a↔z, b↔y, c↔x …`；数字与符号保留。
6. 若结果仍不是最终 flag，按题目后续编码/格式继续处理。

## PoC

```bash
# 1) 命令历史提示
vol.py -f ez_raw.raw --profile=Win7SP1x64 cmdscan
# Cmd #0 @ 0x...: Atbash wallpaper

# 2) 枚举壁纸文件对象
vol.py -f ez_raw.raw --profile=Win7SP1x64 filescan | grep -iE 'TranscodedWallpaper|Themes'

# 3) 按物理地址导出
vol.py -f ez_raw.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003e1a4d00 -D dump/
```

Atbash 解码：

```python
s = "azt12vwgjh56g7ts5v4d2qsx"
out = "".join(
    chr(ord('z') - (ord(c) - ord('a'))) if c.islower()
    else chr(ord('Z') - (ord(c) - ord('A'))) if c.isupper()
    else c
    for c in s
)
print(out)   # zag12edtqs56t7gh5e4w2jhc
```

## 变体与关联

- **壁纸不是唯一载体**：`filescan` 同样可定位桌面文件、下载目录、临时图片；`dumpfiles -r` 可按正则批量导出。
- **整屏截图**：Volatility2 `screenshot` 可直接重建桌面，若壁纸无法导出可试。
- **其他古典密码**：cmdscan/filescan 的提示也可能是 Caesar、栅栏、摩斯；先识别字符集与提示词。
- 关联：[[ctf-forensics-process-memory-dump-gimp-raw-image]]（从进程内存恢复画面）、[[ctf-forensics-memory-image-flag-keyword-search]]（内存关键词搜索）。

## 检测与防御

- 对 CTF：先读 `cmdscan`/`consoles` 找提示，再 `filescan` 定位缓存文件；导出后核对文件头与哈希。
- 对实际防护：用户壁纸/缓存文件中可能包含敏感信息，企业终端应规范壁纸来源；内存镜像取证需授权并加密保管。
- 检测：`TranscodedWallpaper` 等缓存文件的异常写入、命令历史中出现古典密码关键词只能作为题目线索，实际环境应结合文件来源与内容判断。
