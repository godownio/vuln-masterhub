---
id: ctf-misc-pyc-magic-dict-pseudo-zip-des-bruteforce
title: WKCTF2024 不套是你的谎言：pyc 魔术头版本字典还原十六进制 + 伪加密 zip + DES/rockyou 爆破
type: scenario
domain: ctf
path: ctf/misc
technique: pyc-magic-version-dict-zip-pseudo-des-bruteforce
tags:
- ctf
- misc
- pyc
- magic-number
- zip
- pseudo-encryption
- des
- rockyou
- bruteforce
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:01:22+08:00'
  notes: 已对照原文与13张图核对：图07 zip 十六进制（PK/secret.txt）、正文 pyc 魔术头字典脚本与 DES/rockyou 脚本逐行一致；图08 实际显示 secret.txt 为 flask-session/HS256 Data 字段，与正文 DES 密文不符，已在卡内边界注明按正文蒸馏。原文未给组件版本，affected_versions 空正确。dedup 最高分为卡自身，其余 related/new 为不同链；dup-scan 无本篇 pair。未复跑爆破。
url: /docs/ctf/misc/ctf-misc-pyc-magic-dict-pseudo-zip-des-bruteforce/
draft: false
kb_aliases:
- WKCTF2024 不套是你的谎言
- pyc 魔术头版本字典
- 伪加密 zip
- DES rockyou 爆破
- magic.txt dic.txt
- pyDes
---

## 一句话结论

题目给出由大量 pyc 魔术头组成的 `magic.txt`；用 Python 魔术头对照表 `dic.txt` 把每个魔术头映射成对应 Python 版本号（取主/次版本两位），按顺序拼接成十六进制字符串，再转 ASCII 得到下一步线索；按线索修复 zip 伪加密位、解压出 DES 密文，最后用 `rockyou.txt` 字典爆破 DES 密钥，解出 flag。

## 原理

- **pyc 魔术头即版本指纹**：CPython 的 `.pyc` 文件开头 4 字节是 magic number（前 2 字节为版本标识，后 2 字节通常是 `\r\n`）。不同 Python 版本（2.x/3.x）的 magic 不同，且官方/第三方对照表会给出“magic → 版本号”的映射（如 `belong 3.8` 一类格式）。题目把一串魔术头按顺序给出，映射成版本号后拼接，就得到一段十进制/十六进制数字串。
- **为什么版本号能变成十六进制**：把版本号取两位（如 `3.8 -> 38`）依次拼接，得到的字符串按十六进制解释/转换，即可还原出 ASCII 文本（文章脚本 `convert_magic_to_version` 输出后“再转换一下得到”下一关线索）。这是 CTF misc 常见的“编码层套娃”：文件头本身不是数据，而是用版本号作为数字编码。
- **zip 伪加密**：zip 的本地文件头/中央目录中有加密标志位（general purpose bit flag）。有些题目只改标志位、不真正加密，或反之；把标志位改成未加密（如 `09 00 -> 00 00`）即可正常解压。文章在得到 hex 后修改伪加密、解压出 `secret.txt`/密文。
- **DES 弱口令爆破**：解压得到的密文是 Base64 编码的 DES 输出；题目提示/命名为“不套”（弱口令），用 `pyDes.des(key).decrypt(base64.b64decode(cipher))` 遍历 `rockyou.txt` 的每一行作为 key，能 `decode()` 且包含可打印/flag 特征的就是正确密钥。
- **为什么可行**：DES 密钥空间在弱口令字典下很小；CTF 题目故意使用常见口令；Base64 解码后的密文长度是 8 的倍数（DES 块大小）；错误 key 解密通常抛异常或得到乱码，正确 key 得到可读 flag。
- **整体链**：pyc 魔术头版本映射 -> 十六进制/ASCII 线索 -> zip 伪加密修复 -> DES 密文 -> 字典爆破 -> flag。

## 触发条件

- 题目给出大量 pyc 魔术头序列与魔法头对照表（`magic.txt`/`dic.txt`），提示“不套”/多层解码。
- 后续 zip 存在伪加密（本地头/中央目录标志位不一致或被修改），但数据本身未真正加密或可修复。
- 解压出的密文为 Base64 的 DES/对称加密输出，密钥是弱口令且可在 rockyou 等字典中命中。
- 允许运行 Python（pycryptodome/pyDes）与字典爆破。

## 利用步骤

1. 准备 `dic.txt`（含 `belong <version>` 的 magic 对照表）与 `magic.txt`（题目给出的魔术头列表）。
2. 运行文章脚本 `load_magic_dict` + `convert_magic_to_version`：按 `magic.txt` 每行查表，输出版本号字符串；把结果按十六进制/ASCII 转换，得到下一关提示（文章得到一串十六进制）。
3. 按提示找到 zip；用 010/hex 查看本地文件头与中央目录的加密标志位，修复伪加密（如把 `09 00` 改为 `00 00`），解压得到密文文件（如 `secret.txt`）。
4. 取 Base64 密文（文章 `UnAmPVY4at+vnBjzYO7+TdFR2fDbxRs+jC7l1kvohT0ZxrPC8BTMbA==`），用 `pyDes.des(key).decrypt(base64.b64decode(cipher))` 遍历 `rockyou.txt`；捕获异常，打印可读明文/含 flag 的结果。
5. 得到 flag 后按题目格式提交；若 DES 失败，检查是否 AES/3DES、密钥是否需先做 MD5/截断、或字典需要清洗。

## PoC

pyc 魔术头 → 版本号：

```python
def load_magic_dict(file_path):
    magic_dict = {}
    with open(file_path, encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if 'belong' in line:
                parts = line.split(' ')
                magic = parts[3]
                version = parts[4].split(' ')[1].replace('.', '')[:2]
                magic_dict[magic] = version
    return magic_dict

def convert_magic_to_version(magic_file_path, magic_dict):
    output = ''
    with open(magic_file_path, encoding='utf-8') as file:
        for line in file:
            output += magic_dict.get(line.strip(), '未知')
    return output

magic_dict = load_magic_dict('dic.txt')
print(convert_magic_to_version('magic.txt', magic_dict))
```

DES 字典爆破：

```python
from pyDes import des
import base64

def des_decrypt(cipher_b64, key):
    return des(key).decrypt(base64.b64decode(cipher_b64))

cipher_text = 'UnAmPVY4at+vnBjzYO7+TdFR2fDbxRs+jC7l1kvohT0ZxrPC8BTMbA=='
with open('rockyou.txt', encoding='utf-8', errors='ignore') as f:
    for i, line in enumerate(f):
        key = line.strip()
        try:
            flag = des_decrypt(cipher_text, key).decode()
            print(f'Found! Flag: {flag}, Key: {key}')
            break
        except Exception:
            if i % 1000 == 0:
                print(f'Tried {i} passwords, currently at: {key}')
```

## 变体与关联

- **pyc 版本变体**：不同 Python 版本的 magic 表；也可用 `importlib.util.MAGIC_NUMBER` 生成当前版本 magic；若题目给的是版本号序列而非魔术头，反向映射即可。
- **zip 变体**：本地头与中央目录标志位不一致、CRC/文件名长度被改、注释藏密码；参考 zip 伪加密修复卡。
- **对称加密变体**：DES/AES/3DES、ECB/CBC、密钥需 MD5/截断/补零；用 hashcat/john 或 CyberChef 辅助。
- **关联**：[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（zip 本地头修复/伪加密）、[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]（图片尾部 zip + 伪加密套娃）、[[ctf-forensics-cinnamon-image-steghide-zip-binary-leet-chain]]（多段编码/隐写链）、[[ctf-forensics-keepass-kdbx-hashcat-master-crack]]（字典爆破弱口令）。
- **边界**：若 zip 是真加密且密码不在字典、DES 使用非弱密钥/加盐、或 pyc 魔术头表与题目版本不匹配，本链需换方法（已知明文、hashcat 规则、源码恢复）。另：原文图 08 实际显示 `secret.txt` 内容为 “please decrypt the flask-session, the password is weak.” 与 `Data: eyJhbGci...`（HS256 flask-session/JWT），与正文所述 DES 密文不一致；本卡按正文文字与 DES 脚本蒸馏，复现时以实际附件为准。

## 检测与防御

- **说明**：本文是 CTF misc 解题链，不对应现实漏洞；防御视角是“不要在压缩包/加密中使用弱口令，不要用伪加密冒充加密”。
- **检测**：压缩包标志位异常、加密数据可被字典快速命中、pyc 文件头被用作数据编码；企业环境中对弱口令压缩包/加密文件做口令强度检测。
- **加固**：使用 AES-GCM/强 KDF（PBKDF2/Argon2）+ 高熵口令；不要依赖伪加密或简单 DES。
