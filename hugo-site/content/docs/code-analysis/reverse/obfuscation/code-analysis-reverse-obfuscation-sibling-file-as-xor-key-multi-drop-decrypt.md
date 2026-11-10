---
id: code-analysis-reverse-obfuscation-sibling-file-as-xor-key-multi-drop-decrypt
title: 兄弟文件当密钥的重复异或：同目录 .dll 作 key 解其余三份落地文件，解出配置与二级载荷地址
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: sibling-file-as-repeating-xor-key-multi-drop
tags:
- malware
- xor
- loader
- dropper
- keyfile
- powershell
- forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:50+08:00'
  notes: 已对照原文核对；本次核对未读取图片；VBS 下载 csrss.exe/csrss.dll/csrss.exe.config/wanted.pdf 四文件、生成 temp.ps1 用 ReadAllBytes + -bxor 循环（key=csrss.dll）解密其余三份，与正文代码一致；解出后的文件内容与沙箱结论未读图验证
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-sibling-file-as-xor-key-multi-drop-decrypt/
draft: false
kb_aliases:
- 密钥文件异或解密
- csrss.dll 当 key
- 多文件投放 一个当密钥
- file[i] ^ key[i % len]
- temp.ps1 解密三文件
---

## 一句话结论

当样本一次投放多个文件（`a.exe` + `a.dll` + `a.exe.config` + 诱饵文档）且每个单独看都是乱码时，先假设"其中一个是密钥、其余是被加密的载荷"：用 `.dll` 的**全部字节**做重复密钥，对其他文件做 `out[i] = data[i] ^ key[i % keylen]`，往往一次就能解出明文配置（下一级 URL）、可执行载荷与被当诱饵的文档。

## 原理

- 重复密钥异或（repeating-key XOR）是最省事的对称混淆：加密与解密是同一段代码，密钥可以是任意长度字节串。作者常偷懒到"直接把一个文件实体当密钥"，于是**密钥不需要内嵌在代码里**，静态搜字符串永远搜不到。
- 因为密钥是文件字节而非短口令，异或后的结果看起来完全随机，熵接近 8 bit/byte，`file`/`binwalk` 也识别不出文件头——这解释了"四个文件全是乱码"的表面现象。
- 解密必须知道三件事：**哪个文件是密钥**、**密钥是否从头开始的对齐**、**密钥是否包含全部字节**（有些实现只用前 N 字节或跳过头部）。样本通过 `-KeyPath` 参数把 `.dll` 传给同一个脚本，说明它自己就把"密钥文件"抽象成了一个参数，这对分析者是极强的提示。
- 一旦密钥选错，输出仍然是"乱码"，但错误密钥的特征是：无任何可打印串、无合法文件头、长度与明文一致。因此可以**自动枚举**——把同目录每个文件依次当密钥去解其他文件，检测输出是否出现 `MZ`、`PK`、`%PDF`、`http://`、`<?xml` 等标志，即自动定位配对关系。
- 反过来，这也是蓝队的检测点：一次网络会话里下载"若干同名前缀 + 不同扩展名"的文件，且其中某个文件始终不被直接执行，只被当成数据读取。

## 触发条件

- 拿到投放的多份文件（全部或大部分），且至少包含真正的密钥文件。
- 加密实现是对称的重复密钥异或，密钥为整份文件（或其中一段）内容。
- 知道或能推出对齐方式（从第 0 字节开始、密钥循环使用）。
- 若密钥文件本身也被加密/压缩，需先解一层（本例密钥文件是明文密文对中的"密钥"角色，未再加密）。

## 利用步骤

1. 列出同目录所有落地文件，按"大小 + 扩展名"分组；通常最小的那个纯随机文件就是密钥。
2. 写脚本：以候选密钥文件为 key，对每个候选密文做 `data[i] ^ key[i % len(key)]`，输出到新文件（**不要原地覆盖**）。
3. 自动判定成功：检查输出前 2–4 字节是否为已知文件头（`MZ`、`PK\x03\x04`、`%PDF`、`\x7fELF`、`<?xm`），或前 512 字节是否含可打印 URL/路径。
4. 对命中的明文分类：可执行载荷（转逆向/沙箱）、配置文件（`.config`/`.json`/`.xml`，常含下一级地址）、诱饵文档（证明投递话术）。
5. 若标准对齐失败，尝试偏移量（key 从第 n 字节开始）、截断密钥（仅前 16/32 字节）、以及先 base64 解一层再异或。
6. 记录密钥文件哈希——它本身就是 IOC，同一家族复用同一密钥文件的情况很多。

## PoC

```python
import pathlib

def xor_file(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))

MAGIC = (b"MZ", b"PK\x03\x04", b"%PDF", b"\x7fELF", b"<?xm", b"{\\rtf")

def score(buf: bytes) -> bool:
    return any(buf.startswith(m) for m in MAGIC) or b"http" in buf[:512]

files = [p for p in pathlib.Path(".").iterdir() if p.is_file()]
for kp in files:
    key = kp.read_bytes()
    if len(key) < 8:
        continue
    for fp in files:
        if fp == kp:
            continue
        out = xor_file(fp.read_bytes(), key)
        if score(out):
            print(f"[+] key={kp.name}  data={fp.name}  -> {out[:64]!r}")
```

```powershell
# 样本自身的等价逻辑（VBS 生成的 temp.ps1 核心循环）
$key = [System.IO.File]::ReadAllBytes($KeyPath)
$fileContent = [System.IO.File]::ReadAllBytes($FilePath)
for ($i = 0; $i -lt $fileContent.Length; $i++) {
    $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $key.Length]
}
[System.IO.File]::WriteAllBytes($FilePath, $fileContent)
```

## 变体与关联

- 变体（部分密钥 + 拼接头部）：只取密钥前 N 字节循环，或先写一段明文头再异或；用"头部是否可读"来判断偏移。
- 变体（异或后再解密）：异或解出的 `.config` 里可能只是一句话指向下一级 URL，或再套 base64/AES；逐层按文件头判定推进。
- 变体（诱饵与执行顺序）：本例 VBS 先解三份文件、最后才 `Run` 可执行文件与诱饵文档，并删除 `.dll`/`temp.ps1` 自清理；分析时应先把所有文件固定留存再复算，别让清理逻辑毁掉证据。
- 关联：[[code-analysis-reverse-windows-dotnet-aes-sha256-passphrase-key-utf8-iv-zero-padding]]（同一族链条的下一层：AES 参数还原）、[[ctf-forensics-hta-layered-unescape-to-vbs-charshift-defiller]]（上一层：HTA/VBS 如何把这几份文件拉下来）、[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（同类"逐层静态解密"方法论）。
- 边界：密钥文件缺失（未下载全）时无法恢复；若加密不是异或而是流密码（RC4/AES-CTR），同样的"文件当密钥"设计仍然存在，但需要按算法还原。

## 检测与防御

- 检测：一次会话中同源下载多个"同前缀不同扩展名"文件，且其中一份从未被执行（只被读入内存）——这是"文件当密钥"的强行为特征。
- 加固：终端侧对 `[System.IO.File]::ReadAllBytes` + `WriteAllBytes` 组合的脚本行为告警；限制 `powershell -ExecutionPolicy Bypass -File <随机名>.ps1` 的落盘执行。
- 狩猎：对已捕获的投放集合批量跑"枚举密钥 + 头部判定"脚本，可自动化拆出大量同族样本的配置；密钥文件哈希作为家族聚类特征。
- 响应：取证时先做全盘/全目录镜像再分析，因为样本末尾常带删除自身与兄弟文件的逻辑。
