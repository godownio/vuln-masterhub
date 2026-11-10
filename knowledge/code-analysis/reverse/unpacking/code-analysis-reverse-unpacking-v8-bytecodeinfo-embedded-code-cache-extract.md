---
id: code-analysis-reverse-unpacking-v8-bytecodeinfo-embedded-code-cache-extract
title: 无 asar 的 Electron 客户端：按 ByteCodeInfo 结构数组与「?? ?? DE C0」魔数从 .node 加壳模块批量导出内嵌 V8 字节码
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: v8-bytecodeinfo-embedded-code-cache-extract
aliases:
- bytenode 保护
- V8 字节码提取
- ByteCodeInfo 结构数组
- major.node wrapper.node
- Electron 无 app.asar
- 内嵌 code cache
tags:
- v8
- bytenode
- code-cache
- electron
- node
- ida
- unpacking
- js-source-protection
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:52:47+08:00'
  notes: 已对照原文核对：无 app.asar、wrapper.node/major.node 巨型 PE、_static_initialization_and_destruction_0 内联数百个 ByteCodeInfo、四元组 lea rax(地址)/mov 0x490(长度)/lea rsi internal_index(函数名)/lea rsi index.js(文件名)、魔数 ?? ?? DE C0 与 69 05 DE C0 头部、IDA Python 批量导出均与截图 04/08/12/14/16 一致。未验证点：PoC 脚本未执行；0xC0DE0569 与 ExternalReferenceTable::kSize 的具体对应未独立复算。
---

## 一句话结论

用 Electron 重写的客户端如果安装目录里没有 `app.asar`，JS 源码往往被编译成 V8 code cache 存进原生加壳模块（`wrapper.node`/`major.node` 这类几十 MB 的 PE DLL）里；在 IDA 中定位那个「组装数百个 `ByteCodeInfo` 结构体」的巨型初始化函数，按结构体里的 `字节码地址 / 字节码长度 / 函数名 / 文件名` 四个字段（汇编特征为 `lea rax, <blob>` + `mov [..], <len>` + `lea rsi, "internal_index"` + `lea rsi, "index.js"`）写一个 IDA Python 脚本遍历全函数，即可把所有字节码按「文件名_函数名」导出成 `.jsc`，后续再交给同版本 V8 反汇编。

## 原理

- bytenode 一类保护的核心不是加密，而是「打包形态替换」：作者先用 `node -e "require('v8').serialize(...)"`/`bytenode.compileFile` 把每个 JS 文件编译成 V8 的 `SerializedCodeData`（内部叫 code cache / `.jsc`），再把字节流嵌进一个原生 addon；运行时只调 `ScriptCompiler::CompileUnboundScript` + `kConsumeCodeCache` 直接从缓存还原函数，源码根本不进安装包。
- 因此 Electron 常规切入点（解 `app.asar`、看 `resources/app`）会落空，真正的入口是那些体积异常、导出符号很少的 `.node` PE 文件：它们是 addon，用 `String::NewFromUtf8` 级的 C++ 代码把「文件名 → 字节码」注册进一张表。
- 表的元素是 `std::pair<std::string, ByteCodeInfo>`（反编译里能看到 `std::pair<...ByteCodeInfo...>::pair` 调用）；`ByteCodeInfo` 本身是一个 `(const char* data, uint32_t len, const char* function_name, const char* file_name)` 结构，构造函数里四个 `lea` 分别取地址：`lea rax, blob`（字节码地址）、`mov [rbp+var], <len>`（字节码长度，紧跟在 `lea rdi,[rbx+0x10]` 之后）、`lea rsi, "internal_index"`（函数名）、`lea rsi, "index.js"`（文件名）。
- 为什么能用「函数体异常巨大」快速定位：几百个 JS 文件 × 每个一次结构体构造，全部内联在同一个 `static_initialization_and_destruction_0` 里，函数长度（Length 列）会到几十 KB，远超正常初始化函数；IDA 函数窗口按 Length 排序即可命中。
- 为什么字节码能被识别：`SerializedCodeData` 头部第一个 4 字节是魔数 `0xC0DE0000 ^ ExternalReferenceTable::kSize`，小端落到文件里就是 `?? ?? DE C0`（后两字节固定为 `DE C0`，前两字节随 ExternalReferenceTable 大小浮动），所以用通配模式在二进制里搜 `?? ?? DE C0` 就能标出所有 code cache 起点；紧接着的 4 字节是版本哈希，可用于反推引擎版本。
- 为什么必须成对导出「文件名 + 函数名」：`code cache` 反序列化只还原字节码本身，函数名/文件名来自 `SharedFunctionInfo`，而这两个字符串在结构体里是明文；先按文件名归档，才不会把几百个函数混成一团。

## 触发条件

- 目标为 Electron/Node 应用，且安装目录无 `app.asar`/`resources/app` 明文 JS，只有体积异常的 `.node`（PE64 DLL）。
- 加壳模块用内联 `ByteCodeInfo` 结构数组注册字节码（而非运行时从网络/加密文件读入）。
- 能静态分析该 PE（IDA/x64dbg），或用 DIE 等工具确认它是 VC++ 编译的 DLL。
- 字节码版本与后续用于反汇编的 V8 版本可对齐（否则需先做版本哈希逆推或改魔数校验）。

## 利用步骤

1. 遍历安装目录，找体积最大且扩展名为 `.node` 的文件（原文 `wrapper.node`、`major.node` 均数十 MB）；用 Detect It Easy 确认 `PE64 / DLL / C++ / Overlay`。
2. 在字符串窗口搜索 `.js`（如 `index.js`、`796.prelode.js`）与 `p_`/`r_` 前缀的函数名，确认存在「明文文件名 + 函数名」；这类字符串密集处即是注册表。
3. 跳到引用这些字符串的函数：在 IDA 函数列表按 Length 降序，取那个体量最大的 `_static_initialization_and_destruction_0`（原文两处，Length 分别 `0x228A`/`0x14B12`）。
4. 在函数里识别重复出现的四元组模式：`lea rax, <blob>`（字节码地址）、`mov [rbp+var], 0x490`（长度，值随函数不同）、`lea rsi, aInternalIndex`（函数名）、`lea rsi, aIndexJs`（文件名），后面紧跟 `std::string` 构造与 `std::pair` 构造。
5. 用 IDAPython 从函数起点顺序反汇编，状态机追踪「`lea rax, X` → 记地址；随后 `mov [..], imm` → 记长度；再 `lea rsi, 字符串` 取函数名；再 `lea rsi, 字符串` 取文件名」，凑齐四元组就用 `idc.get_bytes(addr, len)` 取出字节码并写成 `<文件名>_<函数名>.jsc`。
6. 全函数扫完后核对总数（原文字节码数量与 JS 文件数量一致，且每个都以 `?? ?? DE C0` 开头）。
7. 对每个 `.jsc` 用 `xxd`/hex 查看头部确认魔数与版本哈希，把该版本信息带到下一步（版本哈希逆推或按对应 V8 tag 编译反汇编器）。

## PoC

```python
# IDAPython：遍历巨型初始化函数，按 lea rax(地址)/mov len/lea rsi(函数名)/lea rsi(文件名) 四元组导出字节码
# 未在本机执行，仅示意最小骨架
import idc, ida_bytes, idautils

func_ea = idc.get_name_ea_simple("_static_initialization_and_destruction_0")
end = idc.find_func_end(func_ea)

cur = func_ea
blob = None       # 字节码地址
blen = None       # 字节码长度
fname = None      # 函数名
jname = None      # 文件名
n = 0
while cur < end:
    mnem = idc.print_insn_mnem(cur)
    if mnem == "lea":
        op0 = idc.print_operand(cur, 0)
        op1 = idc.print_operand(cur, 1)
        if op0 == "rax":                       # 字节码地址
            blob = idc.get_operand_value(cur, 1)
        elif op0 == "rsi":
            if fname is None:
                fname = idc.get_strlit_contents(idc.get_operand_value(cur, 1)).decode()
            else:
                jname = idc.get_strlit_contents(idc.get_operand_value(cur, 1)).decode()
    elif mnem == "mov":
        if idc.print_operand(cur, 0).startswith("[") and idc.get_operand_type(cur, 1) == idc.o_imm:
            blen = idc.get_operand_value(cur, 1)   # 字节码长度
    if blob and blen and fname and jname:
        data = ida_bytes.get_bytes(blob, blen)
        open("%s_%s.jsc" % (jname.replace("/", "_"), fname), "wb").write(data)
        n += 1
        blob = blen = fname = jname = None
    cur = idc.next_head(cur, end)
print("extracted", n)
```

```text
# 导出结果头部（小端）：69 05 DE C0 | EC 22 1A 81 | 76 07 00 00 | 87 9A 84 0E
#   0x00 魔数 0xC0DE0569（= 0xC0DE0000 ^ ExternalReferenceTable::kSize）
#   0x04 版本哈希（用于反推 V8 版本）
# 其余为 source hash / flag hash / payload length / checksum
```

## 变体与关联

- 变体：结构不是 `ByteCodeInfo` 数组而是运行时逐条 `ScriptCompiler::Compile` 的字符串表；此时改在 `CachedData` 构造点（`new ScriptCompiler::CachedData(buf,len)`）下断点动态 dump。
- 变体：字节码被压缩/异或后再嵌入；先用魔数 `?? ?? DE C0` 在解压后的内存镜像里定位，或对 `v8::ScriptCompiler` 的入参做 hook。
- 变体：安装目录确实有 `app.asar` 但 JS 只是薄壳（真正逻辑仍在 `.node`），两处都要看。
- 关联：[[code-analysis-reverse-unpacking-v8-bytecode-version-hash-recover]]（拿到字节码后用魔数后的版本哈希定位 V8 版本）、[[code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch]]（编译同版本 V8 反汇编这些 `.jsc`）。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object]]（同为「原生扩展里藏字节码/字节流」的脱壳思路）。
- 边界：V8 12+ 的字节码在沙箱/压缩指针下有更多校验，反汇编失败（原文明确说新版 12.* 未成功）；若加壳模块在运行时才拼装字节码，静态提取拿不到完整集合。

## 检测与防御

- 检测（作为分析方）：安装目录存在无对应 `.js` 的巨型 `.node`；其字符串区出现成批 `.js` 文件名与短函数名；文件内可搜到 `?? ?? DE C0` 模式；静态初始化函数体积异常（几十 KB）。
- 防御（作为开发者）：不要把「保护」押在字节码上——`.jsc` 可被直接反序列化并反汇编，等价于可读伪代码；敏感逻辑与密钥必须放服务端，客户端只保留调用协议。
- 加固：若必须本地保护，至少对字节码二次加密并运行时解密、对 addon 做完整性校验与反调试；但仍无法阻止运行时 dump。
