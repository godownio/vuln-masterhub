---
id: code-analysis-reverse-modified-rc6-key-schedule-gdb-rk-decrypt
title: 样本通信算法对比识别改版 RC6：key schedule 常量/算子差异 + GDB 提取 rk 重构 Go 解密器
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: modified-rc6-key-schedule-identification-rebuild
aliases:
- 改版 RC6 识别
- 修改 RC6 解密
- RC6 key schedule 差异
- 通信载荷解密重构
- seconddate RC6
tags:
- reverse
- crypto
- rc6
- key-schedule
- malware
- traffic-decrypt
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V643
  verified_at: '2026-11-13T02:28:36+08:00'
  notes: 已对照原文与19张图逐图核对：rk dump地址0x0808afe0/44字、Go New()重构代码、0x61E57CC6首层校验与IV/序号/指令字段均与原文一致。核对中修正两处技术表述：(1)标准RC6 key schedule应为S[i]=S[i-1]+0x9E3779B9(等价-0x61C88647)，原表述符号写反；(2)按截图15/16，if (v15 != 3)/do-while(v10>=0)/_ROL4(...,3)属当前56/60样本，旧1048/1060样本为if (v8 != 2)/++v10==132/_ROR4(...,29)，原卡误把if (v15 != 3)归给旧样本。dedup余项均为related，非同链。未实际解密验证。
---

## 一句话结论

当同一恶意家族的旧版解密脚本解不开新版通信载荷时，对比两版二进制中 RC6 初始化函数的 key schedule 常量与循环/轮数差异（如 `0xb7e15163`、`-0x61C88647`、轮数 3/43 与算子改动），用 GDB 在运行时 `x /44xw` 读出实际 rk 表，按差异点重写 RC6 的 `New(key)`（Go 版），即可还原该家族 56/60 字节小载荷样本的通信解密。

## 原理

- RC6 的标准 key schedule：`S[0]=0xB7E15163`，随后 `S[i]=S[i-1]+0x9E3779B9`（等价于 `-0x61C88647` 取模，两者互为补数）；把密钥装入 `L[]` 后做 `3*rounds` 轮混合，每轮 `S[i]=ROL(S[i]+A+B,3)`、`L[j]=ROL(L[j]+A+B,A+B)`。
- 改版实现常在这三处留下可对比指纹：初始常量/步长、`roundKeys` 数量、混合轮数与旋转量表达式。原文截图对比：当前 56/60 小载荷样本初始化循环为 `while(v2 <= 43)`、`a2[v2] = a2[v2-1] - 0x61C88647`，混合循环为 `do{...}while(v10 >= 0)`（`v10` 初值 131，共 132 次），带 `if (v15 != 3) v13 = v15 + 1`、旋转写作 `_ROL4(...,3)`；旧 1048/1060 样本则是 `while(1)` 结构，`if (v8 != 2) result = v8 + 1`、`if (++v10 == 132) return;`、旋转写作 `_ROR4(...,29)`（`v15/v8` 的回绕模数不同，对应 keyWords 4 与 3 的差异）。两版循环条件与算子不同，同一密钥算出的 rk 表不同，旧脚本解密失败。
- 直接逆向常量不一定可靠（编译优化会展开/改写循环），更稳的办法是运行时在初始化完成后 dump rk 表：`x /44xw 0x0808afe0`（44 个 32 位字），与算法结构一起确定改版后的 schedule。
- 解密流程还依赖通信模型：`output[:4] + output[4:8] == 0x61E57CC6` 校验、`output[:4]-0x61E57CC6` 作为第一层异或值、`output[8:0xc]` 是首层解密数据的 4 字节循环异或校验；之后才是 RC6 密文（8 字节随机 IV + 固定值 + 序号 + 指令 + 参数）。
- 重构解密器的关键是按样本实际的 `roundKeys/轮数/旋转表达式` 重写，而不是直接使用标准库 RC6；用一条已知明文（如控制端 ping）验证。

## 触发条件

- 拿到同家族新旧版本样本（至少一个可正常解密的旧版脚本/实现作参照）；
- 能在调试环境中运行样本并让 RC6 初始化函数执行到 rk 生成完成（核心函数无法正常触发时先用 GDB 强制驱动，见关联卡）；
- 已知或可推出通信包的校验与 IV/序号布局。

## 利用步骤

1. 静态对比两版样本的 RC6 初始化函数：记录初始常量、步长、循环上界、旋转量与轮数差异。
2. GDB 在初始化函数返回后下断点，`x /44xw <rk 表地址>` 导出实际 rk。
3. 按差异重写 Go 版 RC6 `New(key []byte)`：初始化 `skeytable[0]=0xb7e15163`，步长用 `-0x61C88647`，`keyWords=4`，混合循环次数/旋转表达式按样本改。
4. 按通信模型先做首层异或与校验，再把 RC6 密文解密，拆出 IV/固定值/序列号/指令。
5. 用控制端 ping 指令的抓包验证解密结果（原文实测可解出 `00000009` 指令与序号）。

## PoC

重写后的 Go RC6 初始化（原文，基于 dgryski/go-rc6 修改）：

```go
func New(key []byte) (cipher.Block, error) {
    skeytable := make([]uint32, 44)
    skeytable[0] = uint32(0xb7e15163)
    for i := 1; i < 44; i++ {
        skeytable[i] = skeytable[i-1] - uint32(0x61C88647)
    }
    if l := len(key); l != 16 { return nil, KeySizeError(l) }
    c := &rc6cipher{}
    const keyWords = 4
    var L [keyWords]uint32
    for i := 0; i < keyWords; i++ {
        L[i] = binary.LittleEndian.Uint32(key[:4])
        key = key[4:]
    }
    copy(c.rk[:], skeytable)
    var A, B uint32
    var i, j int
    for k := 0; k < 3*roundKeys; k++ {
        c.rk[i] = bits.RotateLeft32(c.rk[i]+(A+B), 3)
        A = c.rk[i]
        L[j] = bits.RotateLeft32(L[j]+(A+B), int(A+B))
        B = L[j]
        i = (i + 1) % roundKeys
        j = (j + 1) % keyWords
    }
    return c, nil
}
```

GDB 提取 rk：

```gdb
x /44xw 0x0808afe0
```

## 变体与关联

- 变体：同一家族大载荷（1048/1060）改 RC6 算子 + keyWords 循环次数；小载荷（56/60）改算子；不定长版本改用 Salsa20，识别方式换成 Salsa20 的 `expand 32-byte k` 常量与 20 轮结构。
- 变体：没有已知明文时，可用 `output[8:0xc]` 校验与魔数和约束做判定，或对 IV/序号字段做已知结构匹配。
- 关联：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]——通用的常量/结构指纹识别思路；本卡是“改版 RC6 + key schedule 差异”的具体场景。
- 关联：[[code-analysis-dynamic-debugging-gdb-eip-skip-init-fake-packet-drive-sample]]——样本无法正常运行时如何用 GDB 驱动到 RC6 解密代码。
- 关联：[[ctf-reverse-tag-crc32-encrypted-sqlite-seed-rc6]]、[[ctf-reverse-apk-rc6-base58-dex-db-derive]]——其它改版 RC6 的逆向案例。

## 检测与防御

- 该卡为分析/解密手法，不针对目标系统防护。
- 对防守方：识别恶意流量的“定长小 UDP + 固定 8 字节边界校验（`[:4]+[4:8]` 为常量）”和加密后的随机 IV，可作为家族指纹；同一算法改版后仍保持包长与校验结构。
