---
id: ctf-misc-selectric-typeball-tilt-rotation
title: IBM Selectric 字球卡死编码：T1/T2 倾斜位与旋转列还原乱序记录
type: scenario
domain: ctf
path: ctf/misc
technique: selectric-typeball-tilt-rotation-recovery
tags:
- ctf
- misc
- selectric
- typeball
- encoding
- puzzle
- mechanical
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:27+08:00'
  notes: 已对照原文核对；T1/T2 行号公式、A/B 页互补恢复、行表与数字映射、48 位压缩包密码一致
url: /docs/ctf/misc/ctf-misc-selectric-typeball-tilt-rotation/
draft: false
kb_aliases:
- Jammed
- Selectric 打字机
- 字球倾斜/旋转
- T1/T2 行号
- 机械卡死编码
- 乱序记录恢复
---

## 一句话结论

题目给两页被打字机“卡死”弄乱的记录：每条原始格式为两位序号、五位流水码、两位片段，共 11 字符；A 页的序号变成 `xl`、`xk`、`xh` 等，B 页前两位仍是 01..24 但顺序被打乱，分隔符也变了。IBM Selectric 字球通过倾斜位 T1/T2 与旋转位选字，倾斜行号 `r = T1 + 2*T2`；A 页 T1 固定为 1（`rA = r | 1`），B 页 T2 固定为 0（`rB = r & ~2`），两页旋转列不变，因此 `r = (rA & 2) | (rB & 1)`，再按同一旋转列与字符集约束即可逐字恢复 24 条记录；连接每条末尾两位得到 48 位压缩包密码，解出 flag。

## 原理

- **记录格式**：两位序号（01..24）、五位流水码、两位片段，总计 11 字符；原始分隔符可能被变换，不能直接按斜线切分，而应按固定位置读取：前两位序号，第四至第八位流水码，最后两位片段。
- **Selectric 字球**：字球通过倾斜（tilt）与旋转（rotate）选择字符；倾斜位置由两个位 T1、T2 控制，倾斜行号等于 `T1 + 2*T2`。标准美式 88 字符字球未按 Shift 的字符在倾斜行与旋转列上的排列为：
  - 第 0 行：`1 3 7 8 4 z 2 5 6 0 9`
  - 第 1 行：`x u d c l t n e k h b`
  - 第 2 行：`m v r a o ½ . ' i s w`
  - 第 3 行：`g f ; , / j = p q y -`
  - 列从 R-5 到 R+5。
- **两种卡死状态**：A 页 T1 固定为 1，行号等于原始行号按位或 1（只输出第 1、3 行）；B 页 T2 固定为 0，行号等于原始行号按位与取反 2（只输出第 0、1 行）。旋转位置保持不变。
- **互补恢复**：A 页保留原始 T2，B 页保留原始 T1，因此原始行号 `r = (rA & 2) | (rB & 1)`；要求两个输出字符位于同一旋转列，就能恢复原字符。
- **数字与分隔符**：A 页数字 0 到 9 分别输出 `h x n u l e k d c b`，可用这张表反查 A 页每行的前两位恢复序号（例如 `xl` 对应 14、`hx` 对应 01、`nh` 对应 20）。B 页中数字都在第 0 行，所以序号不变；原始分隔符斜线位于第 3 行、R-1 列，在 B 页变成同列第 1 行的 `l`，这也解释了 B 页看起来像一串没有分隔符的字符。
- **歧义处理**：数字 `1` 与小写 `l` 容易混淆，可在 B 页同时保留两个候选，再利用另一页字符的旋转列与原始字符集约束筛选；分隔符位置只允许原字符为斜线，其余位置只允许小写字母和数字，本题所有位置都能筛出唯一字符。

## 触发条件

- 题目给出两页机械打字机/字球编码的记录，记录长度固定、格式可从描述推断。
- 两页分别固定 T1 或 T2，形成互补的行号信息；旋转列不变。
- 已知标准字球布局表（或可从题目/资料恢复）。
- 记录末尾片段连接后是压缩包口令，可用解密成功验证。

## 利用步骤

1. 按固定位置切分每条记录：前两位序号、第 4-8 位流水码、最后两位片段。
2. 识别 A 页 T1 固定、B 页 T2 固定；对每个字符查字球表得到 `(rA, col)` 与 `(rB, col)`。
3. 用 `r = (rA & 2) | (rB & 1)` 恢复原始行号；要求两页旋转列一致，按行列查表得到原字符。
4. 用 A 页数字映射表反查序号；用 B 页分隔符位置（第 3 行 R-1 列 -> 第 1 行 `l`）识别斜线。
5. 对 `1`/`l` 等歧义保留候选，用字符集与分隔符位置约束筛选唯一解。
6. 按原始序号 01..24 排序，连接每条最后两位片段得到 48 位密码；用 7z/解压工具解密，读取 flag。

## PoC

```python
# 标准 88 字符字球未按 Shift 的倾斜行/旋转列布局（列 R-5..R+5）
ROWS = [
    "13784z25609",
    "xudcltnekhb",
    "mvrao½.'isw",
    "gf;,/j=pqy-",
]

def decode_char(row_a, col_a, row_b, col_b):
    assert col_a == col_b
    r = (row_a & 2) | (row_b & 1)
    return ROWS[r][col_a + 5]

# A 页数字映射：原始 0..9 -> A 页输出
A_DIGITS = "hxnulekdcb"   # 0->h, 1->x, 2->n, 3->u, 4->l, 5->e, 6->k, 7->d, 8->c, 9->b

# 恢复后的 24 条记录（序号/流水码/片段），片段连接得到密码
records = {
    1: "lrz9w/wm", 2: "0oorg/a1", 3: "ckbnq/w1", 4: "8db91/03",
    5: "ieghg/x9", 6: "hdj7u/1i", 7: "91kml/ek", 8: "esh5f/5f",
    9: "cil1y/q8", 10: "oip9w/89", 11: "oc6og/1i", 12: "srfcm/ap",
    13: "htyb4/j3", 14: "19xey/ow", 15: "p3sm8/03", 16: "s1vg7/k5",
    17: "j1zyw/i2", 18: "2yw2n/r0", 19: "vx20o/2a", 20: "clntx/p1",
    21: "gr8xj/3u", 22: "f4a3f/l2", 23: "ppshm/8d", 24: "xr0xp/c4",
}
password = "".join(records[i][-2:] for i in sorted(records))
print(password)
# wma1w103x91iek5fq8891iapj3ow03k5i2r02ap13ul28dc4
```

```bash
7z x -y -pwma1w103x91iek5fq8891iapj3ow03k5i2r02ap13ul28dc4 treasure.zip
```

## 变体与关联

- 其他机械编码：Baudot/五单位码、打字机键盘移位、转轮密码机、邮票齿孔/打孔卡；核心都是“固定位置 + 已知表 + 互补信息”。
- 若两页固定的是不同位（T1/T2 交换），恢复公式相应调整；若旋转也固定，则需要更多页/线索。
- 歧义字符可用字典、校验和、压缩包解密成功等外部约束筛选。
- 关联：CTF Misc 机械编码、字符集恢复、压缩包口令恢复卡。

## 检测与防御

- 这是 CTF 谜题，不是软件漏洞；防御意义在于：不要把敏感口令编码在可被物理/图像恢复的机械/字符布局中，压缩包口令应有足够熵。
- 取证/分析时保留原始图像与扫描分辨率，记录字符位置与表版本；对歧义字符保留候选并做约束求解。
