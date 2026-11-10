---
id: code-analysis-reverse-obfuscation-idapython-wildcard-binsearch-patch
title: IDAPython 通配符掩码 bin_search 批量定位花指令并 NOP/重建跳转
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: idapython-wildcard-binsearch-batch-patch
tags:
- reverse
- obfuscation
- ida
- idapython
- junk-code
- pattern-scan
- patch
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T08:43:00+08:00'
  notes: 已对照原文第六节去花脚本与 GFCTF/NCTF 例题脚本核对：ida_bytes.bin_search(start,end,pattern,mask,flags)、BIN_SEARCH_FORWARD/NOBREAK/NOSHOW、BADADDR 语义正确；worker 对原文 mask 的修正复核成立——原文 replace('00','01') 使固定字节 mask=0x01，IDA 位掩码语义下只比较最低位会误报，本卡改为固定字节 0xFF/通配 0x00 的严格写法正确(pattern 处通配填 0 亦正确)；半字节掩码 0x0F 的说明正确。与 tools-ida-xor-string-call-arg-backtrack-decrypt 等现有 IDAPython 卡任务不同，非重复。原文未给版本，已 clear。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-idapython-wildcard-binsearch-patch/
draft: false
kb_aliases:
- ida_bytes.bin_search
- BIN_SEARCH_FORWARD
- 通配符字节模式搜索
- 花指令批量 patch
- IDAPython 去花脚本
- ?? 掩码匹配
---

## 一句话结论

用 `ida_bytes.bin_search(start, end, pattern, mask, flags)` 的位掩码语义（mask 中为 1 的位必须与 pattern 一致、为 0 的位忽略）批量定位含立即数的花指令字节序列，再用 `ida_bytes.patch_byte/patch_bytes` 把它们 NOP 或重建为跳转；构造时固定字节的 mask 用 `0xFF`、`??` 通配字节用 `0x00`，循环中把下一次搜索起点设为 `命中地址 + 模式长度` 以避免重复命中。

## 原理

- **API 与参数**：`ida_bytes.bin_search(start_ea, end_ea, pattern, mask, flags)` 在 `[start_ea, end_ea)` 内扫描。`pattern` 与 `mask` 等长；匹配条件等价于 `(data[i] & mask[i]) == (pattern[i] & mask[i])`，即 mask 为 `0xFF` 时整字节必须相等，`0x00` 时整字节忽略；`0x0F` 这类部分掩码可用于只比较低 4 位（半字节通配）。
- **常用 flags**：`BIN_SEARCH_FORWARD`（向前）、`BIN_SEARCH_NOBREAK`（命中后不中断）、`BIN_SEARCH_NOSHOW`（不弹搜索结果窗口）；返回值 `ida_idaapi.BADADDR` 表示未找到。
- **为什么需要通配符**：花指令里的 `add reg, imm`、`mov edi, imm32`、`call rel32` 等立即数随样本/字符变化，只有操作码与固定字节可作模式；把立即数位置标成 `??` 才能一条脚本覆盖全部实例。
- **构造 pattern/mask**：把十六进制字符串按空格拆成字节；`??` 在 pattern 中填 `0x00`（占位），mask 填 `0x00`；固定字节在 pattern 中填原值，mask 填 `0xFF`。注意 mask 是位级的——文中常见的 `replace('00','01')` 写法会让固定字节的 mask 变成 `0x01`，只要求最低位匹配，容易产生误报，严格匹配应使用 `0xFF`。
- **批量 patch**：NOP 用 `patch_byte(ea+i, 0x90)`；重建跳转用 `patch_bytes` 写 `E9 rel32`/`EB rel8`（见 [[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]）。patch 后需 `C`/`P` 重新定义指令与函数、`F5` 刷新伪代码。
- **循环终止**：命中后令 `begin = hit + len(pattern)`，避免在已 patch 区域内反复命中；若模式重叠（如自相似字节），按实际语义调整步长。
- **风险控制**：先用小范围/单条命中人工确认，再全段执行；保留原始样本与 patch 日志；部分匹配（如 mask 只覆盖操作码）可能命中真实指令，必须结合上下文验证。

## 触发条件

- 目标为 PE/ELF/so 等可由 IDA 加载的二进制，花指令/冗余序列有固定字节模式，仅立即数或偏移变化。
- IDA 可用 IDAPython（`ida_bytes`、`idc`），允许修改数据库/文件。
- 需要批量处理多处相同花指令，手工逐处 patch 成本过高。
- patch 前已确认该模式不会命中真实业务指令（或已人工抽查）。

## 利用步骤

1. 在 IDA 中人工定位一处花指令，抄下含操作码的十六进制字节串，把变化的立即数/偏移替换为 `??`。
2. 用脚本把字符串转成 `pattern`（通配填 0）与 `mask`（固定 `0xFF`、通配 `0x00`）。
3. 设定搜索范围（如 `.text` 节起止）与 flags，循环调用 `bin_search`，打印每次命中地址。
4. 对每个命中按花指令类型 patch：整段 NOP、改写为 `E9/EB` 跳转、或只改关键字节。
5. 下一次搜索从 `hit + len(pattern)` 继续，直到 `BADADDR`。
6. `auto_wait` 后在 IDA 中重新分析（`C`/`P`/`F5`），确认反汇编/伪代码恢复，动态单步验证 patch 后语义。
7. 保存 patched 文件，记录模式串、命中数与 patch 偏移。

## PoC

```python
import ida_bytes, ida_idaapi, idc

def build_pattern(hexstr):
    toks = hexstr.split()
    pat  = bytes(0x00 if t == '??' else int(t, 16) for t in toks)
    mask = bytes(0x00 if t == '??' else 0xFF for t in toks)
    return pat, mask

def find_all(start, end, hexstr):
    pat, mask = build_pattern(hexstr)
    ea = start
    while ea < end:
        hit = ida_bytes.bin_search(
            ea, end, pat, mask,
            ida_bytes.BIN_SEARCH_FORWARD |
            ida_bytes.BIN_SEARCH_NOBREAK |
            ida_bytes.BIN_SEARCH_NOSHOW)
        if hit == ida_idaapi.BADADDR:
            break
        yield hit
        ea = hit + len(pat)

# 示例：把固定长度的花指令整段 NOP
for hit in find_all(0x1000, 0x5000, "EB FF C0 BF ?? 00 00 00 E8"):
    print(hex(hit))
    for i in range(3):                      # 只 NOP 前 3 字节的干扰前缀
        ida_bytes.patch_byte(hit + i, 0x90)
```

对照说明：原文脚本用 `bMask = bytes.fromhex(hexStr.replace('00','01').replace('??','00'))`，把固定字节的掩码设成 `0x01`，在 IDA 的位掩码语义下只检查最低位，可能命中非目标字节；本卡改为 `0xFF`/`0x00` 的严格写法。原文的匹配逻辑（`??` 在 pattern 中填 0、mask 中填 0）本身正确。

## 变体与关联

- **文本模式编译**：IDA 自带 `parse_binpat_str` 可解析 `"48 8B ?? ?0 90"` 这类带半字节通配的文本模式，得到 `compiled_binpat_t` 后用 `bin_search` 的编译版接口；适合需要 nibble 级通配的场景。
- **只搜不 patch**：`find_bytes`/`bin_search` 可用于定位后下断点、动态跟踪；patch 只是后续动作。
- **关联**：[[code-analysis-reverse-obfuscation-arm64-jni-onload-junk-jump-br-patch]]（`bin_search` 精确模式 + 模拟求跳转目标 + keystone patch）、[[code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation]]（IDC 固定串替换）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jz/E8 花指令修复）、[[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]（通配模式命中后的跳转重建）、[[ctf-reverse-gfctf2021-wordy-jmp-db-patch-putchar-extract]]（通配搜索 + 读取立即数字符的 CTF 应用）。
- **边界**：位掩码部分匹配容易误伤；x86 变长指令下同一字节串可能落在不同指令边界，需用 `create_insn`/上下文确认；patch 后若被其他跳转引用需重新检查交叉引用。

## 检测与防御

- 这是本地逆向/去混淆工具技术，不产生攻击面。
- 使用侧：patch 前备份数据库与原始文件；先小范围验证模式唯一性；记录每次命中与改写字节；对 mask 做严格构造（`0xFF`/`0x00`），避免 `0x01` 造成的弱匹配。
- 检测信号（蓝队/样本分析）：样本中出现大量可被单一通配模式覆盖的固定花指令序列，本身也是“该混淆器可被批量还原”的特征；IDA 中 `sp-analysis failed`/`JUMPOUT` 密集的函数通常就是批量 patch 的目标。
