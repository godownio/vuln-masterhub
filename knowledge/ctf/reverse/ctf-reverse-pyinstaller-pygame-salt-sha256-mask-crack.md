---
id: ctf-reverse-pyinstaller-pygame-salt-sha256-mask-crack
title: HZNUCTF 2023 snake 逆向：PyInstaller pygame 程序 pyc 提取 + 游戏内盐值 + sha256(salt+flag) 掩码爆破
type: scenario
domain: ctf
path: ctf/reverse
technique: pyinstaller-pygame-embedded-salt-sha256-crack
aliases:
- HZNUCTF 2023 snake
- pygame exe 逆向
- PyInstaller pyc 提取
- 游戏内盐值
- sha256 加盐掩码爆破
- salt_1 salt_2 salt_3
tags:
- ctf
- reverse
- pyinstaller
- pyc
- sha256
- hashcat
- bruteforce
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:09:14+08:00'
  notes: 已对照原文与 img/14（源码中三行 salt 提示）核对：salt_1=mxx307shuai、salt_2=mxx407shuai，salt_3 由 mhigexn|irlt 逐字符 -i 得 mggdashuaibi；独立复算 sha256(salt+'HZNUCTF{1s_R4}')=c08521f3c380906d05ee8afbc7fa2943afb3788d9cec94c1b86771ee35ca4738 与原文目标一致。注意：原文只说'python 写的 exe，反编译一下'，未明写 PyInstaller，卡片按常见 PyInstaller/pyc 流程补全，属合理推断（卡内边界亦提示打包方式可能不同）。PoC 未实际执行爆破（已用目标 flag 反向验证盐值与摘要）。dedup：PyInstaller 总览/加密 PYZ 等既有卡为通用解包技巧，非同链；dup-scan 无 pair。
---

## 一句话结论

题目是一个 PyInstaller 打包的 pygame 贪吃蛇：解包提取 pyc 后反编译，源码里 `FLAG_IS_ME` 给出了 `sha256(salt_1 + salt_2 + salt_3 + data)` 的目标值；salt_1/salt_2 直接显示在游戏得分 10/20 的提示文本里，salt_3 以 `chr(ord(c)+i)` 逐字符变换后显示为 `mhigexn|irlt`，逆变换得 `mggdashuaibi`；拼出盐后用 hashcat/脚本对 5 位 `[0-9A-Za-z_]` 掩码爆破，得到 `HZNUCTF{1s_R4}`。

## 原理

- **PyInstaller 程序的提取**：PyInstaller 把 Python 脚本编译成 pyc 放进 PYZ（嵌入在 exe 的 CArchive 中）；用 pyinstxtractor 等工具解包 CArchive/PYZ 得到 pyc，再用 pycdc/uncompyle6 反编译（不同 Python 版本选择对应反编译器）。本题在源码里直接可见校验逻辑与目标摘要。
- **校验逻辑**：`FLAG_IS_ME` 字符串中包含 `salt_1 + salt_2 + salt_3` 拼接、`data = 'HZNUCTF{xxxxx}'`（5 位 ascii+digits+_）、`sha256(salt_data)` 与目标 `c08521f3...`；sha256 不可逆，只能依赖盐值已知 + 小输入空间爆破。
- **盐值藏在游戏逻辑里**：贪吃蛇得分达到 10/20/30 时在屏幕上打印 `salt_1 : mxx307shuai`、`salt_2 : mxx407shuai`、`salt_3 : ''.join([chr(ord(c)+i) for i, c in enumerate('xxxxxxxxxxxx')]) answer: mhigexn|irlt`；前两个是明文，salt_3 是逐字符 `+i` 后的结果，逆运算 `chr(ord(c)-i)` 即得真实盐。
- **为什么能爆**：flag 内容仅 5 位、字符集约 63 个，空间约 63^5≈1e9；sha256(盐+flag) 单次计算极快，GPU/hashcat 或优化脚本可完成。
- **边界**：若 PyInstaller 版本/加密（key-encrypted PYZ）不同，提取方式不同；若目标摘要对应更长或更大字符集，需改用字典/规则而不是纯掩码。

## 触发条件

- CTF 题目为 PyInstaller 打包的 Python 程序（exe/elf），可解包得到 pyc。
- 校验使用 sha256(已知盐 + 小空间输入) 与固定摘要比较。
- 盐值可从源码/界面/资源中恢复（含简单可逆变换）。

## 利用步骤

1. 用 pyinstxtractor 解包 exe，定位主程序 pyc；按 Python 版本用 pycdc/uncompyle6 反编译（题目给出 tool.lu/pyc 也可）。
2. 阅读主逻辑，找到 `FLAG_IS_ME` 校验字符串与 sha256 目标值、输入格式（5 位）。
3. 运行游戏或用分值触发/直接读源码，取 salt_1、salt_2、salt_3 的显示值；对 salt_3 执行 `chr(ord(c)-i)` 逆变换。
4. 拼接 `salt = salt_1 + salt_2 + salt_3`，对候选 flag 计算 `sha256(salt + flag)`。
5. 用 hashcat 掩码（`-a 3`，字符集 `?d?u?l_` 等）或 Python 脚本爆破 5 位内容，命中 `c08521f3c380906d05ee8afbc7fa2943afb3788d9cec94c1b86771ee35ca4738`。
6. 得到 `HZNUCTF{1s_R4}`。

## PoC

```python
import hashlib, itertools

salt_1, salt_2 = 'mxx307shuai', 'mxx407shuai'
salt_3 = ''.join(chr(ord(c) - i) for i, c in enumerate('mhigexn|irlt'))  # mggdashuaibi
salt = salt_1 + salt_2 + salt_3
target = 'c08521f3c380906d05ee8afbc7fa2943afb3788d9cec94c1b86771ee35ca4738'

for tup in itertools.product('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_', repeat=5):
    data = 'HZNUCTF{' + ''.join(tup) + '}'
    if hashlib.sha256((salt + data).encode()).hexdigest() == target:
        print(data)  # HZNUCTF{1s_R4}
        break
```

```text
# hashcat 等价：-m 1400 -a 3 'c08521f3...' 'mxx307shuaimxx407shuaimggdashuaibiHZNUCTF{?1?1?1?1?1}'
```

## 变体与关联

- 变体：PyInstaller 加密 PYZ 需先用密钥解密/脱壳（见关联卡）；pyc 版本不匹配时用 magic 修正或对应版本反编译器。
- 变体：盐值可来自资源文件、注册表、网络接口或游戏状态，逆向时全局搜索拼接点。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller 解包总览）、[[code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt]]（加密 PYZ）、[[ctf-reverse-embedded-game-validator-pipe-snake-path-solve]]（同游戏题材的校验题）。
- 边界：sha256 掩码爆破受字符集与长度限制；更大空间改用字典/规则/差分。

## 检测与防御

- CTF/开发视角：客户端内嵌盐与摘要只能提高爆破成本，密钥/口令不要放在客户端；使用慢哈希 + 足够长度。
- 逆向视角：PyInstaller 程序先解包再谈反编译；隐藏信息常在 UI 文本/分数触发逻辑中。
