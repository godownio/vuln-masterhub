---
id: ctf-forensics-repeating-xor-wav-riff-size-field-derived-key
title: 循环异或的 WAV/RIFF 头：第 4–8 字节是文件长度而非常量，用密文自身长度（XOR 不改变长度）补出该字段，凑齐 16 字节已知明文反推出可读的密钥串
type: scenario
domain: ctf
path: ctf/forensics
technique: repeating-xor-wav-riff-size-field-derived-known-plaintext
aliases:
- eZ_Steg0
- flag XOR flag.wav = KEY
- WAV 文件头当密钥
- RIFF 头 52494646
- 用密文长度推出 wav 头 size 字段
- 异或密钥是可读字符串
- 音频文件已知明文恢复 key
tags:
- ctf
- forensics
- xor
- known-plaintext
- wav
- riff
- repeating-key
- key-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:39:34+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；WAV 头 52494646+f4fd2200+57415645666D7420、2293236=0x22FDF4、key sSeCre7KeY?!!@$ 等数据与正文一致，长度换算已本地复算；原文把完整文件长度当 ChunkSize（规范应为长度-8）属题目做法，卡片已提示两种都试；已把『每 16 字节坏一次』改为按 15 字节密钥周期描述
---

## 一句话结论

循环异或加密的样本若是音频，已知明文不能直接抄一个「标准 WAV 头」——RIFF 头的第 4–8 字节是**该文件自己的长度**，每个文件都不同；但异或**不改变数据长度**，所以解密后文件长度必然等于密文长度，把密文长度按小端写进这 4 字节，就能拼出真正完整的 16 字节已知明文（`52494646` + 长度 + `57415645666D7420`），与密文前 16 字节异或即得密钥；本题得到的密钥还恰好是一串可读 UTF-8（`sSeCre7KeY?!!@$`），再用它循环异或整文件即解出可播放的 wav。

## 原理

- **XOR 自反**：`C = P ⊕ K`，故 `K = C ⊕ P`；已知任意一段明文即可取出对应位置的密钥流。循环异或下这段密钥流就是一个完整周期（密钥长度 ≤ 已知明文长度时）。
- **WAV/RIFF 头只有 12 字节是常量**：`RIFF`（4 字节）+ `ChunkSize`（4 字节，**该文件总长度减 8**）+ `WAVE`（4 字节）+ `fmt `（4 字节）。若只抄「`52 49 46 46` + 随便填 + `57 41 56 45 66 6D 74 20`」，那 4 字节错误会让密钥流在同一位置产生 4 字节错误——密钥是周期性使用的，这 4 字节错位会被密钥周期带到整个文件（本例密钥 15 字节，即每 15 字节坏一次），解出来必然是杂音。这是 WAV 已知明文最容易踩的坑，也是与 PNG（前 16 字节全确定）最大的差别。
- **补长度字段的依据是「长度不变」**：异或是逐字节运算，`len(P) == len(C)`。所以解密后的 wav 长度 = 密文长度（本例 2293236 字节 = `0x22FDF4`），小端写作 `F4 FD 22 00`，直接填进 `ChunkSize`。注意 `ChunkSize` 在规范里是「文件长度 - 8」，本题原文直接取了完整文件长度（与「长度 - 8」相差 8 字节，只影响该 chunk 末尾的少数几个字节，不影响识别与播放），实践中两种都试一遍即可。
- **解出来的「密钥」应当是可读串**：如果反推出的 16 字节是全随机字节，说明已知明文有错（长度字段填错、或格式判断错）。本题反推结果是 `sSeCre7KeY?!!@$` 这种明显人为构造的字符串，**这正是判断已知明文正确的强信号**——出题人给的 key 通常是可读的，密钥可读性反过来验证了头部推测。
- **第二步用字符串而不是原始字节当 key**：确认是可读串后按 UTF-8 取字节（本例与反推出的原始字节一致，故等价；若反推出的字节串含不可打印字节但能拼出一个可读串，应以可读串为准再试）。
- **为什么可以反过来算**：题面关系写成 `flag XOR KEY = flag.wav`，等价于 `flag XOR flag.wav = KEY`。当两个文件一个已知（或可推测头部）时，直接两文件异或就能拿到密钥流，不需要知道哪边是密文——XOR 的对称性让「已知明文」和「已知密钥」的角色可以互换。

## 触发条件

- 有密文样本 + 题目暗示明文格式（音频/图片/压缩包等），加密方式为定长密钥循环异或（或可推测为循环）。
- 明文头部长度 ≥ 密钥长度，且头部中**非固定字段**可以靠「长度不变」「结构约束」推出来（RIFF 的 ChunkSize、ZIP 的 CRC/压缩后大小、PE 的节表偏移等）。
- 密钥为可读串或长度固定（本例 15 字节，略短于 16 字节的已知明文，足够覆盖一个完整周期）。

## 利用步骤

1. 确认密文长度 `L`，并记录其十六进制小端形式（`L = 2293236` → `F4 FD 22 00`）。
2. 按目标格式拼已知明文：WAV 用 `52494646` + `小端(L)` + `57415645` + `666D7420`；PNG 用 8 字节魔数 + `00 00 00 0D` + `IHDR`。
3. `key = ct[:16] ⊕ known_pt`，打印为 hex/ASCII 检查：应为可读串或至少不含明显错位的随机块。
4. 用该 key（或其可读形式对应的 UTF-8 字节）`xor(ct, cycle(key))` 解密整文件，写回并校验文件头/可播放性。
5. 若解出仍是噪声：把 `ChunkSize` 换成「`L - 8`」再试一次；再不行就缩短已知明文到 12 字节（只用 `RIFF…WAVE`+`fmt ` 的固定部分）反推密钥前 12 字节。
6. 拿到明文后按常规流程提取（wav 看频谱/看波形、png 解析像素等）。

## PoC

```python
import itertools

def xor(data, key):
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

ct = open("flag", "rb").read()          # 密文，长度 2293236
L  = len(ct)                            # XOR 不改变长度 -> 明文 wav 也是这么长

# RIFF + ChunkSize(小端, 用密文长度补) + WAVE + "fmt "
known = bytes.fromhex("52494646") + L.to_bytes(4, "little") \
      + bytes.fromhex("57415645666D7420")
assert len(known) == 16

key = xor(known, ct[:16])
print(key)                              # b'sSeCre7KeY?!!@$'

open("flag.wav", "wb").write(xor(ct, key))
```

等价思路（把密钥当明文差）：

```python
# flag XOR KEY = flag.wav  ==>  flag XOR flag.wav = KEY
key = xor(open("flag", "rb").read(), open("flag.wav", "rb").read())
```

## 变体与关联

- **变体（PNG/JPEG 一类头部全确定的格式）**：前 16 字节（PNG 为魔数 + IHDR 长度 + `IHDR`）无需推导，直接抄，见关联卡。
- **变体（ZIP）**：本地文件头里 `压缩方式/时间/CRC/压缩后大小` 均不确定，只能靠魔数 `50 4B 03 04` + 版本字段反推密钥前缀，再用「CRC 正确」迭代扩展——与 WAV 同一思路（用结构约束补非固定字段）。
- **变体（密钥比已知明文长）**：只能得到密钥前缀，需要靠后续结构（如 wav 的 `data` chunk 头、`fmt ` 字段取值合理）继续拼。
- **变体（加密不是异或）**：若为逐字节加常数或位置相关变换，改用对应逆运算；异或之所以好用，正在于密钥可由任一段已知明文直接取出。
- **关联**：[[ctf-forensics-repeating-xor-png-header-key-recovery]]（同样用已知明文反推循环异或密钥，但头部 16 字节全部确定；本卡的增量是「RIFF 头含文件长度字段，必须先用密文长度把它补出来」，否则密钥错 4 字节、整文件每周期坏一次）、[[ctf-forensics-xor-known-key-large-pixel-block]]（已知 key 的正向解密）、[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（two-time pad 方向的对称性利用）。
- **边界**：若加密引入了 padding 或先压缩再异或，长度不变性被破坏，ChunkSize 推导失效；若密钥长度与 16 不互质且非整除，前 16 字节仍能覆盖一个完整周期（只要密钥长度 ≤16），否则只能得到前缀。

## 检测与防御

- **检测（CTF/取证）**：文件头熵高但长度与常见媒体文件同量级；`file` 识别失败；两文件异或后出现可读串或已知魔数，即为简单异或加密。
- **防御（真实场景）**：绝不要用循环异或做加密——已知明文可直接取出密钥，且定长密钥复用会泄露明文差分；应使用带认证的 AEAD（AES-GCM / ChaCha20-Poly1305）并对密钥做 KDF。
- **取证记录**：保留「已知明文如何构造」的依据（长度字段来源、格式判断），它是复现的关键，比密钥本身更易错。
