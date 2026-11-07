---
id: tools-ida-bison-flex-parser-table-struct-recovery
title: IDA 还原 bison/flex 生成 parser：批量重命名 yypact/yytable/yycheck 并导入 yy_buffer_state/yyguts_t
type: scenario
domain: tools
path: tools/ida
technique: ida-bison-flex-parser-recovery
aliases:
- IDA 还原 bison parser
- flex DFA 表恢复
- yypact yytable yycheck 重命名
- yy_buffer_state yyguts_t
- IDAPython 批量恢复符号
- bison/flex 逆向
tags:
- ida
- idapython
- bison
- flex
- parser
- reverse
- struct-recovery
- hexrays
- symbolic-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:54:53+08:00'
  notes: 已对照原文与3张图核对：IDAPython 导入 StreamCtx/OP_Ctx（对应 yy_buffer_state/yyguts_t）、按 byte_4068xx/word_4063xx 地址批量重命名 bison/flex 表（yypact/yytable/yycheck/yydefact/yytranslate/yyr1/yyr2/yypgoto/yydefgoto、yybase/yychk/yynxt/yydflt/yyaccept/yycmap/yymeta）、SetType/parse_decls/set_member_name 用法与原文脚本一致；图01为 malloc 断点结构体布局、图02为 IDA 反汇编与动调对照、图03为 base-256 写 byte_write_cursor 越界写 out。跳过项核对：AFL 2小时无 crash、base-256 仅写坏 error 字段进入错误分支、残留 ctx 栈写未完成利用、malloc/动调方法论均属未打通/半链/通用方法，跳过合理；可复用方法已并入本卡。工具卡无产品版本，affected_versions 为空；无 sources/source_url。未在本机 IDA 执行脚本。
---

## 一句话结论

分析由 bison/flex 生成的 parser 二进制时，先按全局表特征识别 `yypact/yytable/yycheck/yydefact/yytranslate/yyr1/yyr2/yypgoto/yydefgoto` 与 flex 的 `yybase/yychk/yynxt/yydflt/yyaccept/yycmap/yymeta`，再用 IDAPython 批量重命名、给表打数组类型、按偏移恢复 `yy_buffer_state`（StreamCtx）与 `yyguts_t`（OP_Ctx）成员，即可把大量 `a1+偏移` 还原成有语义的字段访问。

## 原理

- **生成代码的固定骨架**：bison 生成的 LALR 解析器与 flex 生成的 DFA 扫描器会输出一组命名稳定的全局表；即使符号被剥离，表的相对布局、元素宽度（byte/word）和交叉引用模式仍然可辨认。恢复这些表名后，`yyparse` 中的状态跳转、移进/归约分支会立刻可读。
- **bison 表含义**：`yypact` 是状态到动作表基址的偏移，`yycheck` 做边界/符号校验，`yytable` 存动作，`yydefact` 是默认归约规则，`yytranslate` 把 token 映射为内部符号，`yyr1/yyr2` 描述规则左右部，`yypgoto/yydefgoto` 用于非终结符跳转。
- **flex 表含义**：`yybase/yychk/yynxt` 组成 DFA 转移的 base/check/next 结构，`yydflt` 是默认转移，`yyaccept` 标记接受态，`yycmap` 做字符到字符类映射，`yymeta` 处理元字符。
- **结构体布局**：flex 的 `yy_buffer_state`（缓冲区文件指针、buf、pos、cap、len、交互/行号等）与 `yyguts_t`（输入输出、buffer stack、yytext 指针、last accepting state 等）在生成代码中以固定偏移访问；把这些偏移命名后，反编译结果中的 `*(_QWORD *)(a1 + 0x28)` 会变成 `yy_buffer_stack`。
- **API 版本差异**：部分 IDA 发行版没有 `ida_struct` 模块，结构体操作需走 `idc.get_struc_id`、`idc.set_member_name`、`idc.SetType`、`idc.set_local_type` 或 `ida_typeinf`；脚本要按版本做能力探测与回退。
- **刷新限制**：`idaapi.refresh_idaview()` 主要刷新反汇编视图，Hex-Rays 伪代码需要按 F5 或重新打开反编译窗口才会使用新类型。

## 触发条件

- 目标为 bison/flex（或 yacc/lex）生成的 parser/计算器/协议解析器二进制，符号被剥离或只有 `sub_xxx`。
- 反编译中出现大量 `a1 + 常数`、byte/word 全局表索引、状态机式 `switch`/跳转。
- 需要理解语法规则、语义动作或定位解析过程中的越界/整数问题。
- 已能在 IDA 中定位 parser 主函数与全局表地址。

## 利用步骤

1. 在 parser 主函数中定位状态机循环，顺着全局表的交叉引用找到 byte/word 数组；按元素宽度、访问模式和相邻关系区分 bison 表与 flex 表。
2. 把已知结构体声明导入 Local Types：`idc.parse_decls(decls, idc.PT_TYP)` 或 `idc.set_local_type(-1, decl, idc.PT_TYP)`。
3. 用 `ida_name.set_name(ea, new_name, ida_name.SN_FORCE)` 批量重命名表；地址按目标二进制实际交叉引用调整，不要照搬示例地址。
4. 用 `idc.SetType(ea, "const unsigned char yycheck[];")` 等给表打数组类型；有符号/无符号按表的实际用途选择。
5. 用 `idc.get_struc_id` + `idc.set_member_name(sid, offset, name)` 按偏移命名结构体成员；若版本不支持则跳过，不影响其余步骤。
6. 按 F5 刷新 Hex-Rays，检查字段访问是否展开；再对照 malloc/初始化断点核对偏移与运行时布局。
7. 对无法确认的表，用动态调试观察索引范围与取值，反推是 `yypact` 还是 `yycheck`，避免仅凭地址猜测。

## PoC

最小 IDAPython 骨架（地址与表名需按目标二进制替换；未在本机 IDA 执行）：

```python
import idc, ida_name, ida_kernwin

DECLS = r"""
typedef struct StreamCtx {
    void *fp; unsigned char *buf; unsigned char *ptr;
    int cap; int len; int can_realloc; int is_tty;
    int unk40; int unk44; int unk48; int buf_inited;
    int slot_state; int _pad5C;
} StreamCtx;

typedef struct OP_Ctx {
    int *nest_counter; void *in; void *out;
    unsigned __int64 stream_index; unsigned __int64 stream_cap;
    StreamCtx **streams;
    unsigned char ch_saved; unsigned char _pad49[3];
    int buf_valid; int tok_len; unsigned char *cur;
    int inited; int state; int flag80; int _pad84;
    unsigned __int64 _unk88; unsigned __int64 _unk96;
    int back_state; int _pad108; unsigned char *back_ptr;
    unsigned __int64 _unk120; unsigned char *tok_start;
    unsigned __int64 _unk136; __int64 *yylval_out;
} OP_Ctx;
"""

idc.parse_decls(DECLS, idc.PT_TYP)

renames = {
    "byte_4069F0": "yypact", "byte_4068B0": "yycheck",
    "byte_406890": "yytable", "byte_406870": "yydefact",
    "byte_4068E0": "yytranslate", "byte_406858": "yyr2",
    "byte_406848": "yyr1", "byte_406843": "yypgoto",
    "byte_406840": "yydefgoto",
    "byte_406740": "yycmap", "byte_406658": "yymeta",
    "word_4063A0": "yybase", "word_406320": "yychk",
    "word_4062A0": "yynxt", "word_406400": "yydflt",
    "word_406460": "yyaccept",
}

for old, new in renames.items():
    ea = idc.get_name_ea_simple(old)
    if ea not in (idc.BADADDR, -1):
        ida_name.set_name(ea, new, ida_name.SN_FORCE)

types = {
    "yypact": "const signed char yypact[];",
    "yytable": "const signed char yytable[];",
    "yycheck": "const unsigned char yycheck[];",
    "yydefact": "const unsigned char yydefact[];",
    "yytranslate": "const unsigned char yytranslate[];",
    "yyr1": "const unsigned char yyr1[];",
    "yyr2": "const unsigned char yyr2[];",
    "yypgoto": "const signed char yypgoto[];",
    "yydefgoto": "const signed char yydefgoto[];",
    "yybase": "const unsigned short yybase[];",
    "yychk": "const unsigned short yychk[];",
    "yynxt": "const unsigned short yynxt[];",
    "yydflt": "const unsigned short yydflt[];",
    "yyaccept": "const unsigned short yyaccept[];",
}
for name, decl in types.items():
    ea = idc.get_name_ea_simple(name)
    if ea not in (idc.BADADDR, -1):
        idc.SetType(ea, decl)

ida_kernwin.info("tables renamed; press F5 to refresh Hex-Rays")
```

结构体成员命名同理：`sid = idc.get_struc_id("OP_Ctx")` 后对每个 `(offset, name)` 调用 `idc.set_member_name(sid, offset, name)`；不同 IDA 版本可能无此 API，需 try/except 跳过。

## 变体与关联

- 变体：其他 parser 生成器（yacc、lemon、ANTLR、ragel）有各自的表布局；先识别生成器再套对应命名，不要硬套 bison/flex。
- 变体：64 位/32 位下指针与 `size_t` 宽度不同，结构体偏移需按目标架构重算；表元素也可能是 `int` 而非 `short`。
- 变体：无符号剥离时可先用 FLIRT/签名或字符串定位 parser 生成器版本，再按该版本模板恢复。
- 关联：[[tools-ida-kernel-source-struct-import-decompiler-cleanup]]（Local Types 导入结构体与 Hex-Rays 校正）、[[tools-ida-xor-string-call-arg-backtrack-decrypt]]（IDAPython 批量处理调用点）；与 [[code-analysis-reverse-go-binary-layout-symbol-recovery]] 同属“按布局/模式恢复符号”的思路。

## 检测与防御

- 对分析者：先确认生成器与版本，再批量重命名；所有地址、表宽、结构体偏移都要用交叉引用与动态调试核对，不能照搬脚本。
- 对防御方：剥离符号只能提高逆向成本，不能替代输入校验；parser 类目标仍可通过表结构与运行时行为恢复语义。
- 对 CTF/样本分析：优先恢复语法/语义动作，再定位算术与缓冲区边界；AI 生成的脚本要逐项验证 API 与地址，不能直接信任。
