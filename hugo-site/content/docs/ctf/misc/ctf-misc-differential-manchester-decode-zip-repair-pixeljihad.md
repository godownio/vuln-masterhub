---
id: ctf-misc-differential-manchester-decode-zip-repair-pixeljihad
title: 差分曼彻斯特解码 01 串还原 ZIP，按固定周期剔除插入字节修复，续爆破与 PixelJihad 提取 flag
type: scenario
domain: ctf
path: ctf/misc
technique: differential-manchester-zip-repair-chain
tags:
- manchester
- differential-manchester
- zip-repair
- archive-bruteforce
- pixeljihad
- png
- base64
- misc
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-31
  verified_at: '2026-11-08T16:14:04+08:00'
  notes: 已对照原文与21张图核对：差分初始电平0解码ASCII预览现PK、flag.zip头部6未知字节+每16字节插6字节(44=6+16对齐高亮图证)、跳6留16修复后Bandizip打开、ARCHPR暴力爆破密码12345678耗时26m28s(图为12%进度命中，卡文'约26分钟跑完8位纯数字段'措辞略不准但事实相符)、010 PNG模板passed end of file+尾部base64 cHBhYXNzd20=解码ppaasswd、PixelJihad提取wdflag{f3b32f2151a877cad089c25994e5da4a}、题目'卫星流量也能被截取?'印证alias。与WAV卡为不同链路，dedup无同链候选。未验证点：未本机复跑；frontmatter无sources。
url: /docs/ctf/misc/ctf-misc-differential-manchester-decode-zip-repair-pixeljihad/
draft: false
kb_aliases:
- 曼彻斯特解码
- 差分曼彻斯特
- zip 修复
- PixelJihad
- 卫星流量截取
---

## 一句话结论

Misc 题中一段看似"二进制转 ASCII"的长 01 字符串实为 ZIP 字节流的差分曼彻斯特编码：按"比特开始处有跳变为 0、无跳变为 1"解码并把比特串还原成原始二进制即出现 `PK` 魔数；解出的文件按固定周期（首部 6 字节未知 + 之后每 16 字节插入 6 字节）混入垃圾数据，按"跳 6 留 16"剔除后得到可打开的加密 ZIP，爆破密码后再从 PNG 末尾附加的 base64 得到 PixelJihad 隐写 key，最终提取 flag。

## 原理

- **为什么 01 串不是普通二进制**：直接按 8 位转 ASCII 得到乱码，说明比特流经过线路编码。曼彻斯特类编码每个原始比特被展开为两个电平码元（`01`/`10`），因此编码流长度恰为原始比特数的 2 倍，且只含 `01`/`10` 交替模式；这解释了"转 ASCII 无意义、长度翻倍"的特征。
- **三种约定一次枚举**：曼彻斯特只有 IEEE 802.3（`0`→`10`、`1`→`01`）、G.E. Thomas（`0`→`01`、`1`→`10`）、差分曼彻斯特（比特开始处有跳变→`0`、无跳变→`1`，且比特中点必有一次跳变；差分解码需要数据流开始前的初始电平作参考）三种。逐个试解码并以 ASCII 预览验证，出现 `PK` 即命中正确约定与初始电平。
- **ZIP 修复的规律识别**：解出的二进制以 `PK\x03\x04` 开头但结构错乱，说明出题人按固定周期插入垃圾字节。用"每行固定 44 字节"的十六进制输出对齐观察（44 = 6+16+6+16），可发现首部 6 字节未知数据、之后每 16 字节合法 ZIP 数据后跟 6 字节插入数据的规律；ZIP 正常头部长度多为 16 的倍数，这也是选 44 对齐的依据。
- **按位置剔除**：无需解析 ZIP 结构，直接按"跳过 6 字节、保留 16 字节"循环切分并拼接即可恢复完整 ZIP（含 central directory），Bandizip 等工具可直接打开。
- **后续两层隐写**：ZIP 真加密（非伪加密、无明文攻击素材）→ ARCHPR 暴力爆破短数字密码；secret.png 用 PNG 模板解析报 "passed end of file"，即 IEND 后有附加数据，发现尾部 base64，解码得到 PixelJihad（HTML5 像素隐写工具）的解密 key，用该 key 从图中提取 flag。

## 触发条件

- 题目给出一长串 `0/1` 字符（文件或文本），按二进制转 ASCII 无意义；
- 编码流长度约为"某有意义文件比特数"的 2 倍；
- 差分曼彻斯特解码（初始电平试 0/1）后 ASCII 预览出现 `PK`、`\x89PNG` 等已知魔数。

## 利用步骤

1. 清理 01 串（去空白/无效字符），用曼彻斯特解码脚本依次尝试 IEEE 802.3、G.E. Thomas、差分（初始电平 0 与 1）四种组合。
2. 以 ASCII 预览判读：出现 `PK` 即选差分曼彻斯特、初始电平 0；把解码比特串按"原始二进制文件"保存，得到混入垃圾字节的 flag.zip。
3. 用脚本把 ZIP 按 44 字节/行输出十六进制，确认 6+16+6+16 的插入规律。
4. 按"跳 6 留 16"循环切分拼接生成新 ZIP，验证可正常打开（内含 secret.png）。
5. 排除伪加密与已知明文攻击后，用 ARCHPR 暴力爆破（数字密码 12345678，约 26 分钟跑完 8 位纯数字段）。
6. 用 010 Editor 的 PNG 模板解析 secret.png，模板报错处即 IEND 后的附加 base64，解码得到 PixelJihad 的 key。
7. 在 PixelJihad 网页工具中载入 secret.png 并输入 key，提取 flag（如 `wdflag{...}`）。

## PoC

核心修复逻辑（跳 6 留 16）：

```python
data = open("flag.zip", "rb").read()
out = b""
pos = 0
while pos < len(data):
    pos += 6                 # 跳过插入的 6 字节
    out += data[pos:pos+16]  # 保留 16 字节合法数据
    pos += 16
open("output.zip", "wb").write(out)
```

解码/判读用三约定曼彻斯特解码脚本（IEEE 802.3 / G.E. Thomas / 差分，差分需初始电平），ASCII 预览命中 `PK` 后按原始二进制保存。

## 变体与关联

- 编码约定互换时症状相同：IEEE 802.3 与 G.E. Thomas 互为反相，差分需要初始电平；有时还需对比特串整体逆序后再解。
- ZIP 修复思路与"伪加密修复""本地头修复"同族，但本题是按固定周期剔除插入字节，不涉及标志位改写。
- PixelJihad 属像素级带 key 隐写，同类还有 steghide、SilentEye；PNG IEND 后附加数据是常见的"提示隐藏"手法。
- 关联：[[ctf-misc-zip-local-header-repair-pseudo-encryption]]、[[ctf-misc-jpeg-steghide-exif-elf-xor-pseudo-zip]]、[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]。

## 检测与防御

- CTF 出题视角：该链路每一环（编码约定、插入周期、密码强度、隐写 key）都可独立加固，如插入字节周期不定长、密码加盐、隐写工具冷门化。
- 流量检测视角：卫星/无线电链路若采用曼彻斯特线路编码，攻防双方都需正确约定与初始电平；防御方可对"自同步编码流中出现可执行/归档魔数"做异常检测。
- 说明：仅适用于授权 CTF 竞赛与靶场环境。
