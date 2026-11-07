---
id: ctf-reverse-elf-rel-differential-relocation-affine-model
title: ELF REL 可重定位目标文件差分重定位建模：未定义符号作输入位点还原仿射校验
type: scenario
domain: ctf
path: ctf/reverse
technique: elf-rel-differential-relocation-affine-model
aliases:
- l11nk
- REL 目标文件
- 重定位差分
- __lm_cacheline
- 仿射模型
tags:
- ctf
- reverse
- elf
- relocatable
- relocation
- undefined-symbol
- differential
- affine
- mips
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:26:42+08:00'
  notes: 已对照原文核对：ELF32 big-endian MIPS ET_REL、.lm.auth/.lm.auth.rel、26 个 UND __lm_cacheline_*、R_MIPS_32/HI16/LO16 应用、差分得 word[0]+=0xe、slot[0x2a4+0x24i]+=0x10、末槽基线 1、样本 SHA256 与 flag ISCC{n9Q4vX7k2P0mLd8R5tYz} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当题目给的是 `ET_REL` 半成品目标文件、把输入值挂在 `UND` 未定义符号上时，把每个未定义符号当成变量，离线应用重定位并逐个置 1 做差分，就能提取出“头字 += k·Σx_i、每个槽位 += k·x_i”的闭式仿射模型；`.o` 本身不含具体输入值，需要外部链接值或已知样本才能闭合。

## 原理

- **REL 与可执行文件的区别**：`readelf -h` 显示 `Type: REL` 表示可重定位目标文件，没有 program header、没有入口点，不能直接运行；未定义符号（`UND`）的值本应由链接器在链接阶段填入，因此它们天然是“输入位点”。
- **模板 + 重定位表**：`.lm.auth` 是待填充的模板节，`.lm.auth.rel` 是重定位节。重定位记录 `(r_offset, r_info)` 中 `r_info>>8` 是符号表下标、`r_info&0xff` 是类型；对 MIPS 常见 `R_MIPS_32(2)`、`R_MIPS_HI16(5)`、`R_MIPS_LO16(6)`。
- **重定位语义**：`R_MIPS_32` 在 32 位字上做 `word += symbol_value`；`HI16/LO16` 成对使用，`LO16` 取 `symbol_value & 0xffff` 加到低半字，`HI16` 取 `(symbol_value + 0x8000) >> 16` 加到高半字。按记录顺序应用即可得到“链接后”的字节布局。
- **差分提取线性模型**：先令所有 `x_i=0` 得到基线，再每次只令一个 `x_i=1`，比较前后哪些 32 位字发生变化。若每个符号只影响“一个公共头字 + 一个独占槽位”，且增量固定，则整个样本是仿射的：`word[0] = base + Σ k_i·x_i`、`word[slot_i] = base_i + m_i·x_i`。
- **本例模型**：`word[0x0000] += 0x0e * x_i`，`word[0x02a4 + 0x24*i] += 0x10 * x_i`；最后一个槽位 `__lm_cacheline_25` 的基线为 1 而非 0，是区分末字符的标记。26 个符号对应 26 个单字节字符。
- **信息论边界**：`.o` 只给出生成规则，不包含具体输入值；孤立分析只能恢复模型，不能自动吐出 flag。拿到具体样本（如固定 SHA256）或链接期实际值后，才能验证/回填。

## 触发条件

- 附件是 `ELF32/ELF64` 的 `ET_REL` 目标文件，`readelf -s` 中出现一组命名规整的 `UND` 符号（如 `__lm_cacheline_00..25`）。
- 存在自定义节区（如 `.lm.auth`）与对应重定位节区，且大部分重定位是模板噪声。
- `.comment`、`.ai.guard` 等节区出现“建议工作流 / LLM hint / fallback token”等文本——应视为诱饵，不参与链接与运行。

## 利用步骤

1. `readelf -h` 确认 `Type: REL`；`readelf -S` 找目标节与重定位节；`readelf -s` 找成组的 `UND` 符号。
2. 解析 ELF 头、节头表、`.symtab`/`.strtab`，建立符号下标到名字/值的映射。
3. 实现目标架构的重定位类型；先全零应用一次得基线。
4. 对每个输入符号单独置 1，记录发生变化的 32 位字、偏移与增量；若布局符合“公共头字 + 独占槽位”，写出仿射模型。
5. 用第二个/第三个符号置 2、置 3 验证线性（增量应成倍），并检查末槽位基线等特殊标记。
6. 若有已知样本，按模型注入候选 flag，正向计算头字与各槽位，与样本哈希/比较常量核对。

## PoC

```python
import struct

def be16(b, o): return struct.unpack_from(">H", b, o)[0]
def be32(b, o): return struct.unpack_from(">I", b, o)[0]
def cstr(b, o):
    e = b.find(b"\0", o)
    return b[o:e if e >= 0 else len(b)].decode("latin1", "ignore")

class Rel:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        assert self.d[:4] == b"\x7fELF" and self.d[4] == 1 and self.d[5] == 2
        shoff, shentsize, shnum, shstrndx = be32(self.d, 32), be16(self.d, 46), be16(self.d, 48), be16(self.d, 50)
        self.sec = [struct.unpack_from(">10I", self.d, shoff + i * shentsize) for i in range(shnum)]
        shstr = self.d[self.sec[shstrndx][4]: self.sec[shstrndx][4] + self.sec[shstrndx][5]]
        self.names = [cstr(shstr, s[0]) for s in self.sec]
        self.idx = {n: i for i, n in enumerate(self.names)}
        sym = self.sec[self.idx[".symtab"]]
        strtab = self.d[self.sec[sym[6]][4]: self.sec[sym[6]][4] + self.sec[sym[6]][5]]
        self.syms = []
        for o in range(sym[4], sym[4] + sym[5], sym[9]):
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(">IIIBBH", self.d, o)
            self.syms.append({"name": cstr(strtab, st_name) if st_name else "", "value": st_value})

    def sec_bytes(self, name):
        s = self.sec[self.idx[name]]
        return self.d[s[4]: s[4] + s[5]]

    def apply(self, overrides=None):
        overrides = overrides or {}
        buf = bytearray(self.sec_bytes(".lm.auth"))
        rel = self.sec[self.idx[".lm.auth.rel"]]
        hi_pending = []
        for o in range(rel[4], rel[4] + rel[5], rel[9]):
            r_off, r_info = struct.unpack_from(">II", self.d, o)
            sym, typ = self.syms[r_info >> 8], r_info & 0xff
            sval = overrides.get(sym["name"], sym["value"])
            if typ == 2:  # R_MIPS_32
                buf[r_off:r_off + 4] = struct.pack(">I", (be32(buf, r_off) + sval) & 0xffffffff)
            elif typ == 5:  # R_MIPS_HI16
                hi_pending.append((r_off, sym["name"], sval))
            elif typ == 6:  # R_MIPS_LO16
                buf[r_off:r_off + 2] = struct.pack(">H", (be16(buf, r_off) + (sval & 0xffff)) & 0xffff)
                hi = ((sval + 0x8000) >> 16) & 0xffff
                rest = []
                for off, name, v in hi_pending:
                    if name == sym["name"] and v == sval:
                        buf[off:off + 2] = struct.pack(">H", (be16(buf, off) + hi) & 0xffff)
                    else:
                        rest.append((off, name, v))
                hi_pending = rest
        return bytes(buf)

def changed(base, trial):
    out = []
    for o in range(0, min(len(base), len(trial)) & ~3, 4):
        a, b = be32(base, o), be32(trial, o)
        if a != b:
            out.append((o, a, (b - a) & 0xffffffff))
    return out

obj = Rel("l11nk.o")
base = obj.apply()
for name in sorted(s["name"] for s in obj.syms if s["name"].startswith("__lm_cacheline_")):
    diffs = changed(base, obj.apply({name: 1}))
    print(name, [(hex(o), hex(v), hex(d)) for o, v, d in diffs])
# 期望：[(0x0, 0xfa220000, 0xe), (0x2a4+0x24*i, base_i, 0x10)]
```

## 变体与关联

- **架构变体**：x86-64 常见 `RELA`（addend 显式存于 `r_addend`），类型 `R_X86_64_32/32S/PC32/64`；AArch64、ARM、RISC-V 的重定位编号不同，但“符号值 → 模板字节”的线性关系不变。
- **符号使用方式变体**：一个符号可能被多条重定位引用、参与乘加或只影响高位；差分仍能看出依赖，但需要按字/半字分别建模。
- **输入面变体**：可能不是 26 个单字节，而是多个 32 位符号；可用置 1/置 2 确认斜率，用不同符号组合确认是否有交叉项。
- **诱饵变体**：`.comment`/`.ai.guard` 中的“工作流建议”“LLM hint”“fallback token”通常是题目针对自动分析放置的烟雾弹；以节区类型和重定位引用为准。
- **关联卡片**：[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（符号/输入位点恢复）、[[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]（stripped ELF 结构恢复）。

## 检测与防御

- **检测特征**：`readelf -h` 的 `REL` 类型、`readelf -r` 大量重定位、`readelf -s` 成组 `UND` 符号；`strings` 中出现诱饵性提示文本。
- **分析建议**：不要试图直接执行 `.o`；先把重定位语义实现正确，再用差分而非阅读模板结构来建模。差分结果应做线性验证（置 1/置 2/组合）。
- **防御视角**：把校验逻辑放进可重定位模板只是提高分析门槛；输入值最终仍需以符号/常量形式存在于链接产物中，无法替代真正的密钥保护。
