---
id: ctf-reverse-base64-group-char-swap-position-permutation
title: 魔改 Base64 只打乱组内字符位置（每组第 2/3 位对调）：与标准编码比对找出换位规律后换回再解码
type: scenario
domain: ctf
path: ctf/reverse
technique: base64-group-internal-character-position-swap
aliases:
- 每组第2第3位反过来的base64
- base64 输出字符位置换位
- 组内字符对调魔改 base64
- 不用换表只换位置的 base64
tags:
- ctf
- reverse
- base64
- custom-encoding
- position-permutation
- android
- jeb
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:35:42+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文 BASE64_CHARS 为标准表、编码循环内 v6=0/1/2/3 时取 6 位块的顺序为 0,2,1,3，即每组第 2/3 位对调，卡内描述与 PoC 逆排列一致；未验证点：第 4 位起多解的具体数目与最终明文靠猜，仅见于正文文字与截图，未读图确认
---

## 一句话结论

魔改 Base64 不只有「换表」和「索引变换」两种改法，还有第三种：表是标准表、索引也不动，只在拼输出串时把每个 4 字符组内部的字符顺序打乱（本例把每组第 2、3 位对调）。这种改法用肉眼对不出差异，但只要拿一个已知明文分别过一遍题目实现和标准 `base64`，逐位比对就能读出换位规律，解码时把每组字符换回原位置即可。

## 原理

- Base64 的结构是「3 字节 → 4 个 6 位索引 → 4 个字符」；任何可逆的解码都必须还原这两层。换表改的是「索引 → 字符」，索引变换改的是索引值，而**组内换位改的是第三层：字符在组内的排布位置**，前两层完全不动。
- 因为表是标准表，密文里每个字符单独看都是合法 Base64 字符，直接 `b64decode` 会成功但得到乱码——错误不在字符，而在「哪个字符代表哪 6 位」。这就是它容易骗过"看着像 Base64 就丢进解码器"的原因。
- 换位是纯置换，逆变换就是把位置换回来：若加密是组内 `[0,2,1,3]` 输出，则解密要先按 `[0,2,1,3]` 把密文组还原成 `[0,1,2,3]`（自逆的 2-循环对调）再解码。任意换位规律都同理，只需取其逆排列。
- 找规律的手段很简单：让题目实现去编码一个自选字符串（长度要覆盖组边界），把输出和标准 Base64 逐字符对齐，位置不一致的地方就是换位点；再换不同长度复测，区分「全局偏移」和「组内换位」。
- 组内换位与换表的区别特征：换表会让密文的字符集合整体偏移（某明文字符永远映射到另一个固定字符），组内换位不会改变字符集合，只改变顺序。

## 触发条件

- 逆向目标是移动端/PC 端 App 或校验程序，取用户名、密码、序列号时先做了一次"长得像 Base64"的编码。
- 该实现的字符表就是标准 `A-Za-z0-9+/`，也没有索引异或/加 key——换表与索引变换都被排除后，才轮到怀疑输出位置。
- 密文长度是 4 的倍数、尾部可能有 `=` 填充。
- 能拿到可运行的编码函数（或能按反编译伪代码原样重写一份），用于生成对照样例。

## 利用步骤

1. 从反编译里定位编码函数，确认表是标准表、无索引变换，但输出循环里存在下标重排（如 `charAt`/数组下标按非 `0,1,2,3` 顺序取）。
2. 按伪代码原样重写一份编码器（不要"顺手修正"看着别扭的下标，这正是要复现的魔改点）。
3. 用一个长度 9（或任意 3 的倍数）的自选字符串过一遍自写编码器和标准 `base64.b64encode`，逐字符比对。
4. 记录每个 4 字符组内错位的位置（本例是每组第 2、3 位互换，等价排列 `[0,2,1,3]`），并换几种长度复测，确认是"组内"而不是"整串"错位。
5. 写解码：按逆排列重排每个 4 字符组 → 用标准表解码；尾部 `=` 原样保留参与重排但不要进查表逻辑。
6. 用「解码结果再按题目规则编码，能逐字符复现密文」做闭环验证，避免把方向写反。

## PoC

复现并按逆排列还原（示意；`swapped` 为题目实现输出的对照样例）：

```python
import base64

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
PERM = [0, 2, 1, 3]          # 加密：组内按此顺序输出 → 第 2、3 位被对调
INV = [PERM.index(i) for i in range(4)]

def variant_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode()
    out = []
    for i in range(0, len(std), 4):
        g = std[i:i + 4]
        out.append("".join(g[p] for p in PERM))
    return "".join(out)

def variant_decode(cipher: str) -> bytes:
    chars = list(cipher)
    n = len(chars) - len(chars) % 4
    for i in range(0, n, 4):
        g = chars[i:i + 4]
        chars[i:i + 4] = [g[p] for p in INV]
    return base64.b64decode("".join(chars))

probe = b"abcdefghi"
swapped = variant_encode(probe)
print(swapped, base64.b64encode(probe).decode())   # 对齐后可见每组第 2/3 位颠倒
assert variant_encode(variant_decode(swapped)) == swapped
```

长度推断（配合「已知密文长度反推明文长度」的做法）：密文 12 字符说明明文 9 字节，用它选探测用的明文长度即可覆盖组边界。

## 变体与关联

- **变体一（换位规律不同）**：组内任意置换（`[0,2,1,3]`、`[0,3,2,1]`、整组反转 `[3,2,1,0]`），甚至按位置轮换（第 n 组用第 n 个排列）；找出规律后统一用逆排列处理。
- **变体二（跨组）**：以整串为单位做局部交换（如每 8 字符内两两对调），此时需要按整串长度对齐，不能按 4 字符组切。
- **变体三（叠加换表/索引）**：组内换位常与换表、索引异或叠加使用，此时必须按「先逆换位 → 再逆索引 → 再逆换表 → 标准解码」的逆序逐层剥。
- **关联**：[[ctf-reverse-base64-table-index-mutation]]（换表与索引异或/加 key 两种魔改的还原；本卡是第三层「组内位置置换」，表中字符与索引均未变，故不可混用同一套解码）、[[ctf-reverse-base64-custom-table-then-repeating-xor]]（换表后再循环异或的叠加链）、[[ctf-reverse-arkts-abc-modified-rc4-addition-rsa-custom-base64]]（自定义 Base64 与其它算法串联的案例）。

## 检测与防御

- 识别信号：二进制/字节码中出现「每 4 字符一组、组内下标非递增」的取字符循环，且没有 64 字符换表数组。
- 判别顺序：先看表是否等于标准表 → 再看索引有无异或/加常量 → 都排除后才怀疑输出位置；三条都改动时按逆序逐层还原。
- 防御视角：位置置换与换表一样只是混淆，不提供任何保密性；不要把凭据/授权数据交给自定义编码保护，真正的完整性校验要用带密钥的 MAC 或签名。
- 复核建议：还原后必须回编码比对；只做"解码出可读字符串"的验证会漏掉部分错误位（可读乱码也常见）。
