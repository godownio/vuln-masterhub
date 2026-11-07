---
id: ctf-reverse-upx-pe-data-lcg-printable-shift-or-branch
title: UPX 脱壳 + PE .data 参数提取 + LCG 可打印字符环移逆推（OR 分支只解快分支）
type: scenario
domain: ctf
path: ctf/reverse
technique: upx-pe-data-lcg-printable-shift
aliases:
- UPX 脱壳
- caterpillar7.exe
- PE .data seed
- LCG 可打印字符
- 快慢分支 OR
- 20 字符 target
tags:
- ctf
- reverse
- upx
- pe
- lcg
- printable-shift
- windows
- unpack
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:23+08:00'
  notes: 已对照原文核对：UPX0/1/2 脱壳、main 校验 ISCC{20字符}、.data +0x10 seed/+0x18 target/+0x00,+0x08 慢分支哈希指针、快分支 LCG 0x41C64E6D/0x3039 取 >>24 %95 可打印环移、快慢分支 OR、实测 ISCC{I3Rs&)d,Nj'`;$+WU(>+} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

PE 由 UPX 加壳，脱壳后 `main` 校验 `ISCC{20字符}`；快分支用 `.data` 中的 seed 驱动 LCG，对每个输入字符在 95 个可打印字符环上做加法移位并与 20 字符 target 比较，慢分支是耗时超过 5 秒后的 SHA-256 校验；两条分支是 OR，因此只逆快分支即可恢复 flag。

## 原理

- **UPX 识别与脱壳**：PE 节区出现 `UPX0`/`UPX1`/`UPX2` 即标准 UPX 壳；`upx -d` 可直接还原，脱壳后字符串与主逻辑才可见。
- **快分支变换**：LCG 状态 `state = state * 0x41C64E6D + 0x3039 (mod 2^32)`，每字符取 `shift = (state >> 24) % 95`，正向 `out = ((in - 0x20 + shift) % 95) + 0x20`；逆向只需 `in = ((out - 0x20 - shift) % 95) + 0x20`。
- **参数位置**：`.data` 偏移 +0x10 是 32 位 seed，+0x18 是 20 字符 target；+0x00/+0x08 是指向慢分支 SHA-256 十六进制串的指针。
- **分支 OR**：`if (time_diff <= 5.0) { 快分支 }` 与 `if (hash1 == 0 && hash2 == 0) { 慢分支 }` 最终是 `bVar4 || bVar5`；攻击者不需要满足慢分支，只要快分支校验通过即输出 `Success!`。

## 触发条件

- 附件是 Windows x64 PE，带 UPX 壳。
- 程序校验 `ISCC{...}` 格式与固定长度，主体由可逆变换生成。
- `.data` 中存在 seed/target 参数，或可从反编译中恢复 LCG 参数。

## 利用步骤

1. 解压附件，`file`/`rabin2 -S` 确认 PE32+ 与 UPX 节区；`upx -d` 脱壳。
2. `rizin -A -q -c 's main; pdg'` 或 IDA 反编译 main，确认长度/格式校验与快慢分支的 OR 关系。
3. `objdump -s -j .data` 读 `.data` 头部：+0x10 取 seed，+0x18 取 target 字符串。
4. 按 `state = state * 0x41C64E6D + 0x3039` 逐字符生成 shift，逆向还原主体。
5. 拼 `ISCC{主体}`，正向再算一遍确认等于 target。
6. 若 `.data` 布局或 LCG 参数变化，从反编译的立即数中重新提取，不要写死 seed/target。

## PoC

```python
def invert_fast_branch(target: str, seed: int) -> str:
    state = seed & 0xFFFFFFFF
    out = []
    for ch in target:
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        shift = (state >> 24) % 95
        plain = ((ord(ch) - 0x20 - shift) % 95) + 0x20
        out.append(chr(plain))
    return "".join(out)

# target = "WY|lFW#ImVR&OKNX-%Ji"; seed = 7
# flag = "ISCC{" + invert_fast_branch(target, seed) + "}"
```

## 变体与关联

- **壳变体**：可能是 UPX 变种、ASPack、Themida；UPX 变种需手动 OEP/内存 dump。
- **变换变体**：LCG 参数可能不同；字符环可能是 94/96 而非 95；移位可能用 `state >> 16` 或 `% 94`；也可能用 XOR 而非加法。
- **分支变体**：慢分支可能是真实校验而快分支是诱饵，需要确认 OR/AND 关系；时间阈值可能不同。
- **关联卡片**：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（UPX+自定义 VM）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（UPX+逐字符滚动哈希）、[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（改版 UPX 脱壳）。
- **边界**：若 UPX 被修改导致 `upx -d` 失败，需先修复或手动脱壳；若 target 含不可打印字符，环移公式需按实际字符集调整。

## 检测与防御

- **CTF 验证**：逆推结果正向变换后应逐字符等于 target；`Success!` 分支应只依赖快分支。
- **防御**：不要用单层 LCG + 可打印环移做校验；关键逻辑放服务端；UPX 等公开壳不能作为保护手段。
- **检测信号**：PE 中出现 UPX 节区；`.data` 中有固定长度 target 与 seed；程序对输入做逐字符可逆变换。
