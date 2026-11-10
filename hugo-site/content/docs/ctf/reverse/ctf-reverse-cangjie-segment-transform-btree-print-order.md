---
id: ctf-reverse-cangjie-segment-transform-btree-print-order
title: 仓颉(Cangjie)二进制逆向：StringBuilder::append 切片定位 7 段可逆字符变换，二叉树 DFS 打印顺序错位后重排还原
type: scenario
domain: ctf
path: ctf/reverse
technique: cangjie-binary-segment-transform-btree-print-order
tags:
- ctf
- reverse
- cangjie
- binary
- ida
- string-transform
- xor
- caesar
- permutation
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:12:37+08:00'
  notes: 已对照原文核对分段常数(+1/^2/-1/+10/-10/^2/^5)、打表置换 A B C D E F G→C D B A F E G 与 7 段还原输出(w1a} 与 120^5=125 一致)；本次核对未读取图片，DFS 打印序仅依据原文打表结论，未在二进制中复核
url: /docs/ctf/reverse/ctf-reverse-cangjie-segment-transform-btree-print-order/
draft: false
kb_aliases:
- 仓颉语言逆向
- Cangjie 反编译
- std.core::StringBuilder::append 识别
- 分段异或加减逆解
- 二叉树打印顺序错位
- 华为仓颉加密逻辑
---

## 一句话结论

仓颉编译出的 ELF 未去符号，可直接在 IDA 里靠 `std.core::StringBuilder::append` 与 `std.core::Array<UInt8>` 的取值函数定位校验逻辑：题目把 28 字符输入按 4 字符切成 7 段、每段套一种可逆单字符运算（`+1`、`^2`、`-1`、`+10`、`-10`、`^2`、`^5`），再把 7 段结果挂到二叉树的 7 个节点上按深度优先打印；打印顺序与逻辑顺序不一致（A B C D E F G 打成 C D B A F E G），所以逆解必须「先按打印序重排回逻辑段序，再逐段逆运算」，否则得到的是乱序字符串。

## 原理

- **为什么能逆**：每段变换都只作用于单个字节（加法、减法、异或），且常数固定，属于逐字符可逆映射：`x+1 → x-1`、`x-10 → x+10`、`x^k → x^k`（异或自逆）。段与段之间没有链式依赖（没有「上一段结果参与下一段密钥」），因此可以并行逐段反算。
- **为什么要重排**：`node(value, left, right)` 是个闭包递归结构，执行 `tree()` 时先递归左子树、再 `print` 自身、再递归右子树，即中序/前序混合的深度优先遍历；题目用 `node(A, left: node(B, left: node(C, right: node(D))), right: node(E, left: node(F), right: node(G)))` 挂了 7 个节点，实际打印次序是 C、D、B、A、F、E、G（打表法：输入 `flag{1234567890123456789012}` 后比对各段密文确定对应关系），把逻辑上的第 1~7 段打乱成另一个顺序。
- **为什么用 StringBuilder 定位**：仓颉的 `StringBuilder::append` 在二进制里保留可读符号，一段连续多个 `append` 且循环边界是 4 的整数倍（0..4、4..8、…、24..28），几乎必然是「切片 + 逐字符变换 + 拼接」的校验逻辑；`Array<UInt8>::El`（`ZN8std_core5ArrayIh2__El`）的返回值即输入字节，紧跟在它后面的 `^2u`、`+10`、`-1`、`<0x0A` 之类小常数就是该段运算。
- **为什么运算符要从汇编里读**：仓颉对无符号字节做减法会带溢出检查分支（`__CFADD__`/`__OFADD__` 后跟 `rt_CreateOverflowException_msg` + `CJ_MCC_ThrowException`），看到「比较 + 抛异常」的膨胀骨架不要被干扰，真正的运算在正常分支里（如 `v32 ^ 2u`、`v34 + 10`、`v35 - 10`）。

## 触发条件

- 目标是仓颉语言编译的原生二进制，且未做去符号/混淆（能搜到 `std.core::` 前缀符号）；
- 校验逻辑是「输入定长切片 + 每段固定逐字符变换 + 结果拼接/打印」，而不是分组密码或带状态链的哈希；
- 段数、段长、打印顺序都能从二进制或打表复现。

## 利用步骤

1. 二进制里搜 `std.core::`（`StringBuilder::append`、`ArrayIh2__El`、`Array` 等），找到连续 append 的主函数。
2. 按循环边界切段（本例每 4 字节一段，共 7 段），逐段读出紧跟取值函数后的常数运算：第 1 段 `+1`、第 2 段 `^2`、第 3 段 `-1`、第 4 段 `+10`、第 5 段 `-10`、第 6 段 `^2`、第 7 段 `^5`。
3. 找到 `node(...)` 树构造与 `print` 的位置，确认遍历顺序；用「输入已知明文 + 观察打印顺序」的打表法确定逻辑段 → 打印位置的置换（本例 A B C D E F G → C D B A F E G）。
4. 从程序输出的密文（题面直接给出 7 个 4 字节数组）反推：先把密文按打印顺序排回逻辑段序，再对每段套逆运算。
5. 拼接得到 flag；若打印序未对齐会得到可读但乱序的字符串（见下例输出），可作为「还差一步重排」的自检信号。

## PoC

逆解脚本（仅演示算法，不执行任何文中命令）：

```python
# 逻辑段序 -> 变换（正变换常数）
ops = [lambda c: c + 1, lambda c: c ^ 2, lambda c: c - 1,
       lambda c: c + 10, lambda c: c - 10, lambda c: c ^ 2, lambda c: c ^ 5]
# 逆变换与正变换同构：加减号取反，异或自逆
inv = [lambda c: c - 1, lambda c: c ^ 2, lambda c: c + 1,
       lambda c: c - 10, lambda c: c + 10, lambda c: c ^ 2, lambda c: c ^ 5]

# 程序打印顺序 A B C D E F G -> C D B A F E G，即打印序列第 i 项对应逻辑段 perm[i]
perm = [2, 3, 1, 0, 5, 4, 6]   # 0-based：C=2, D=3, B=1, A=0, F=5, E=4, G=6
printed = [
    [119, 48, 104, 48],   # C（逻辑第 3 段，正变换 -1）
    [115, 111, 123, 58],  # D（逻辑第 4 段，正变换 +10）
    [121, 109, 104, 102], # B（逻辑第 2 段，正变换 ^2）
    [71, 77, 66, 72],     # A（逻辑第 1 段，正变换 +1）
    [97, 115, 105, 108],  # F（逻辑第 6 段，正变换 ^2）
    [109, 110, 96, 90],   # E（逻辑第 5 段，正变换 -10）
    [114, 52, 100, 120],  # G（逻辑第 7 段，正变换 ^5）
]

seg = [None] * 7
for i, data in enumerate(printed):
    seg[perm[i]] = ''.join(chr(inv[perm[i]](b)) for b in data)
print(''.join(seg))
```

要点：`perm` 必须与打表结果一致，它由「打印序 → 逻辑段号」的置换决定，写错就会把整段结果搬到别的位置；逐段输出与原文一致时为 `FLAG` / `{ojd` / `x1i1` / `ieq0` / `wxjd` / `cqkn` / `w1a}`，可据此自检置换与逆运算是否对齐（这 7 段仍是分段还原结果，原文未再给出拼接后的完整 flag 串，实战中应把打表结论与二进制里每个 append 循环绑定的常数逐段复核）。

## 变体与关联

- **变体（同篇第二个样本）**：同一套符号定位手法也适用于凯撒移位校验——IDA 里出现固定的 `shift=10`、只对 `65-90` 与 `97-122` 两个区间做 `((c-65+shift)%26)+65`（大写）和 `((c-97+shift)%26)+97`（小写）、其余字符直通，就是标准凯撒；逆解把 shift 换成 `26-shift`（或负移位）即可，无需重排。
- **变体**：段变换可换成 `xor` 不同常数、`rol/ror` 小位数、`+i`（与段内下标相关）等，仍逐字符可逆，逆解按「先反置换再逐段反算」的同一套路。
- **关联**：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（常量/轮数/S 盒识别定位算法后再取密钥）、[[code-analysis-reverse-go-interface-swissmap-disassembly]]（另一门带符号/运行时的语言在 IDA 中的布局识别）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（Caesar + 置换表组合的逆解）。

## 检测与防御

- 对逆向分析方：这类题的保护价值几乎为零，段运算与打印顺序都能静态读出；真正提高成本的做法是去符号 + 内联 + 控制流平坦化，或把逐字符可逆变换换成需要密钥的分组密码。
- 对防守方（识别仿冒/破解程序）：仓颉等新语言编译产物会带 `std.core::` 前缀符号与自带运行时（`rt_CreateOverflowException_msg`、`CJ_MCC_ThrowException`），可作为语言指纹；结合「字符串拼接 + 逐字符小常数运算」的密集模式，可判定为校验逻辑而非业务逻辑。
- 值得注意的检测点：`StringBuilder::append` 在同一函数内被连续调用 7 次以上且循环上界都是小整数倍，是「分段编码」的强特征，可让分析直接跳到结论。
