---
id: ctf-reverse-byte-multiply-reverse-26-byte-check-inverse
title: 逐字节乘法+整体反转的 26 字节校验逆向：允许字符集内枚举求逆
type: scenario
domain: ctf
path: ctf/reverse
technique: byte-multiply-reverse-26-byte-check-inverse
tags:
- ctf
- reverse
- byte-transform
- inverse
- multiplication
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:17:49+08:00'
  notes: 已对照原文 Stage3 Reverse-eniffa 段与图17/18/19核对：26 字节长度、buf[i]=(i+1)*(input[i]+2)、整体反转、常量 0x3DC0F1E2952091E6/28712/0x7B1A99A48ABCDB00/0x68DC29A471BEE658 与原文 exp 一致；已把一句话结论中“映射为双射”修正为“系数与 256 互素时为双射”（偶数系数时非双射，靠字符集约束取解）。PoC 未本机复跑；原文未标注组件版本。
url: /docs/ctf/reverse/ctf-reverse-byte-multiply-reverse-26-byte-check-inverse/
draft: false
kb_aliases:
- eniffa
- 逐字节乘法
- 整体反转
- (i+1)*(x+2)
- 26 字节校验
---

## 一句话结论

程序对 26 字节输入逐字节做 `buf[i] = (i+1)*(input[i]+2) mod 256`，再把整个缓冲区反转后与常量比较；由于每字节独立（系数与 256 互素时为双射），从反转后的目标逐字节在允许字符集内枚举 `x` 使 `(i+1)*(x+2) & 0xff == target` 即可恢复 flag。

## 原理

- **逐字节独立**：变换 `out[i] = ((i+1) * (in[i] + 2)) & 0xff` 只依赖位置 `i` 和当前字节，不跨字节混合；对固定 `i`，`in` 在 0..255 上到 `out` 是双射（`i+1` 与 256 互素时），可以逐字节求逆。
- **整体反转**：变换后程序把 `buf[0..n-1]` 原地反转（`swap(buf[j], buf[n-1-j])`）；因此比较常量 `v` 的第 `i` 个字节对应的是变换后 `buf[n-1-i]`，求逆时先取 `target = v[25-i]`。
- **常量组装**：样本常量由四个小端整数拼成 26 字节：`0x3DC0F1E2952091E6`（8 字节）+ `28712`（2 字节）+ `0x7B1A99A48ABCDB00`（8 字节）+ `0x68DC29A471BEE658`（8 字节）。
- **字符集约束**：flag 格式限定为 `abcdefghijklmnopqrstuvwxyz0123456789_{}`，枚举时只接受该集合内的 `x`，可避免多解并加快速度。
- **为什么成立**：没有密钥/随机数，比较常量完整给出；每字节只有 256 种可能，最多 26×256 次检查。

## 触发条件

- 输入长度固定（样本 26 字节），程序提示 `Enter flag`/`Wrong`/`Correct`。
- 反编译中出现 `(i+1) * (input[i] + 2)` 形式的逐字节循环，随后整体反转。
- 最终与栈上/数据区 26 字节常量比较；常量可由 qword/dword 小端拼出。

## 利用步骤

1. 定位比较常量与长度，按小端把 qword/dword 拼成 26 字节数组 `v`。
2. 确认变换顺序：先逐字节乘法，再整体反转；求逆时先反转（取 `v[25-i]`），再逐字节枚举。
3. 对 `i=0..25`，令 `target = v[25-i]`，枚举 `x` 在允许字符集内，检查 `((i+1)*(x+2)) & 0xff == target`；命中即 `input[i]=x`。
4. 拼接输出，按 `flag{...}` 格式检查；用原程序验证。
5. 若有多解，叠加格式/字符集/其他校验筛选。

## PoC

```python
v = list((0x3DC0F1E2952091E6).to_bytes(8, "little"))
v += list((28712).to_bytes(2, "little"))
v += list((0x7B1A99A48ABCDB00).to_bytes(8, "little"))
v += list((0x68DC29A471BEE658).to_bytes(8, "little"))
assert len(v) == 26

charset = set(b"abcdefghijklmnopqrstuvwxyz0123456789_{}")
out = []
for i in range(26):
    target = v[25 - i]          # 先撤销整体反转
    for x in range(256):
        if ((i + 1) * (x + 2)) & 0xff == target and x in charset:
            out.append(chr(x))
            break
    else:
        raise ValueError(f"no candidate at {i}")
print("".join(out))
# 原文结果：flag{shiagia00snnrmnkq1j7}
```

## 变体与关联

- **运算变体**：乘法可换加法/异或/循环移位，系数可随位置变化；只要逐字节独立且双射，都能枚举/解析求逆。
- **顺序变体**：可能先反转再变换，或只反转一半；按反编译顺序严格逆序。
- **常量变体**：常量可能由 qword/dword/word 混合小端拼接，注意字节序与对齐。
- **关联卡片**：[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（字节对加法+ROL8+轮转）、[[ctf-reverse-z3-constraint-equation-solve]]（约束求解）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（逐字符可逆变换）。
- **边界**：若变换不是双射（如 `(i+1)` 与 256 不互素）或存在跨字节依赖，需改用 z3/暴力组合。

## 检测与防御

- **检测特征**：`Enter flag`/`Wrong`/`Correct` 字符串、26 字节比较、`(i+1)*(x+2)` 循环、整体反转。
- **分析建议**：先写正向函数验证常量；求逆时先处理反转，再逐字节枚举；用字符集约束排除多解。
- **防御视角**：这类逐字节变换只是提高逆向成本；应使用标准密码学原语与带密钥的校验，而不是可解析的固定公式。
