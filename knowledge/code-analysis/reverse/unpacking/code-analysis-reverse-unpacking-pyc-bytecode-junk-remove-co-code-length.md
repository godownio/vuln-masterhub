---
id: code-analysis-reverse-unpacking-pyc-bytecode-junk-remove-co-code-length
title: pyc 字节码去花：删除 co_code 中的 JUMP/垃圾指令并修正 co_code 长度，恢复反编译与运行
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyc-bytecode-junk-remove-co-code-length-fix
aliases:
- pyc 加花
- pyc 去花
- co_code 花指令
- JUMP_ABSOLUTE 垃圾指令
- bad marshal data
- co_code 长度修正
- pyc_obscure
- BabyMaze
tags:
- reverse
- unpacking
- python
- pyc
- bytecode
- obfuscation
- junk-code
- co-code
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V684
  verified_at: '2026-11-13T14:23:07+08:00'
  notes: 已对照原文与全部47图核对：uncompyle6 失败段显示开头 JUMP_ABSOLUTE 4 / JUMP_ABSOLUTE 6 / JUMP_BACK 2（img39/40）、010editor 中 BabyMaze.pyc 0x29 处 73 EE 07 00 00（co_code 长度 0x7EE=2030，内容自 0x2E 起 71 04 71 06 71 02，img41）、len(code.co_code)=2030（img42）、删除 6 字节后程序恢复运行 Welcome To VNCTF2022（img43）、DFS 出路径（img44）；kkkk 失败示例删 4 条指令(8字节)并把 26(0x1A) 改 18(0x12) 后仍报 bad marshal data (invalid reference)/(unknown type code)/Bad code object in .pyc file（img35/37，kkkk.pyc 0x29 处 73 1A 00 00 00、kkkk1 0x2A 处 1A，img34/36）均与原文一致。修正：co_code bytes 对象 0x73 的偏移由 0x20 更正为 0x29（0x20 行第 9 列，长度前缀 0x2A-0x2D）。7 项跳过抽查：PyInstaller 解包、--key 加密、pycdas、自定义 Python VM、TEA 识别对应卡片均存在且为 verified，merge 理由成立；.pyd/Cython 为源码保护创建教程、无 pyd 逆向原语，babypython 源码级干扰行筛选无新增原语，跳过合理；cards.json 跳过理由中卡片 id 拼写由 brutorce 更正为 ctf-misc-pyc-magic-dict-pseudo-zip-des-bruteforce。dedup 判 new 成立（top 相关卡 nested-marshal 为 co_consts 嵌套解码，其余为补头/解密/反汇编，非 co_code 去花）；dup-scan 无本篇 pair。原文未标注受影响版本（Python 3.8 为环境），未设 affected_versions；frontmatter 无 sources/source_url。PoC 未本机复跑。
---

## 一句话结论

pyc 加花是在 `co_code` 中插入不影响执行的垃圾指令——如读取越界变量/常量的 `LOAD_*` 后紧跟跳转跳过，或一串 `JUMP_ABSOLUTE` 乱跳——让 uncompyle6/pycdc 等反编译器在解析控制流/引用时失败；去花要用 `marshal.loads` + `dis` 看清字节码，按 Python 版本 `opcode.h` 的编号在十六进制中定位并删除这些字节，**再把 marshal 里 `co_code` bytes 对象的 4 字节长度前缀减去删除的字节数**。只删字节不改长度会得到 `bad marshal data (invalid reference)`；原文 [VNCTF2022] BabyMaze 删除开头 `71 04 71 06 71 02`（6 字节）并把长度 2030→2024 后，pyc 恢复运行与反编译。

## 原理

- **Python 字节码布局**：CPython 的 `co_code` 是「操作码 + 操作数」序列；Python 3 每条指令 2 字节（opcode + oparg），Python 2 每条 3 字节。`opcode.h` 给出编号（示例：`LOAD_FAST`=124=0x7C、`LOAD_CONST`=100=0x64、`BINARY_ADD`=23=0x17、`STORE_FAST`=125=0x7D、`JUMP_ABSOLUTE`=113=0x71）。`dis.dis` 输出「源码行号 | 字节码偏移 | 指令 | 参数」。
- **pyc 与 marshal**：pyc 文件 = 头部（Python 3.7+ 为 16 字节：4B magic + 4B 位字段 + 4B 时间戳 + 4B 文件大小；更早版本为 8 字节/12 字节）+ marshal 序列化的 `PyCodeObject`。`co_code` 在 marshal 中是一个 bytes 对象：**类型字节 0x73（`TYPE_STRING`/'s'）+ 4 字节小端长度 + 内容**。原文 BabyMaze.pyc 在 0x29 处可见 `73 EE 07 00 00`（`co_code` 内容自 0x2E 起），即 `co_code` 长度 0x7EE = 2030。
- **加花手法**：
  - 插入一条越界引用指令（如 `LOAD_FAST` 索引超出 `co_varnames`、`LOAD_CONST` 超出常量表）再插入跳转跳过，解释器执行时被跳过，不影响结果，但反编译器解析 marshal 引用时越界/找不到目标；
  - 或插入 `JUMP_ABSOLUTE`/`JUMP_BACK` 垃圾跳转链（BabyMaze 开头 `71 04 71 06 71 02`：JUMP_ABSOLUTE 4、JUMP_ABSOLUTE 6、JUMP_BACK 2），使反编译器的控制流恢复陷入死循环或找不到合法块入口，报 `Parse error at or near 'None' instruction at offset -1`；
  - `pyc_obscure` 一类工具即向 `co_code` 插入垃圾数据来干扰 uncompyle6。
- **为什么“只删字节”不够**：marshal 解析 bytes 时按前缀长度读取，删除内容但保留旧长度会导致读取越过实际数据、后续引用错位，典型报错 `ValueError: bad marshal data (invalid reference)` 或 `bad marshal data (unknown type code)`；因此必须同步修正长度。原文的失败示例：删除 4 条指令（8 字节）后把 `len(co_code)` 从 26（0x1A）改为 18（0x12），仍反编译失败——说明除长度外，`co_lnotab`/跳转目标/嵌套 code object 等也可能引用被删偏移，需要逐项核对；BabyMaze 的成功在于垃圾在函数开头且没有其他结构依赖这些偏移。
- **修复的完整路径**：先用 `dis` 确认垃圾指令与偏移 → 在十六进制编辑器按 opcode/操作数定位（如搜 `0x71` 的所有出现，结合上下文确认哪几条是垃圾）→ 删除垃圾字节 → 在 marshal 中定位 `co_code` 长度前缀（搜 `len(code.co_code)` 的值）→ 减去删除字节数（见下方 BabyMaze 示例）→ 保存 → 用对应 Python 版本运行/反编译验证。
- **版本敏感**：magic/头长度、指令宽度（2 vs 3 字节）、opcode 编号都随 Python 版本变化，必须用生成该 pyc 的版本（或同版本 opcode.h）处理；Python 3.8 的 `0x71` 是 `JUMP_ABSOLUTE`，其他版本编号可能不同。

## 触发条件

- 拿到一个 pyc/pyo 文件，`uncompyle6`/`pycdc` 反编译失败（`Parse error`、`bad marshal data`、输出乱码或控制流错乱），但文件头与 marshal 结构基本正常。
- `dis.dis(marshal.loads(pyc[16:]))` 能看到不合理的跳转链或越界操作数（花指令特征）。
- 能获得目标 Python 版本的 `opcode.h`（源码 `Include/opcode.h` 或 Python 安装目录），并有十六进制编辑器（010 Editor/WinHex）。
- 有权修改/复制 pyc 文件，并可反复用同版本解释器验证运行结果。

## 利用步骤

1. **确认反编译失败点**：`uncompyle6 -o out.py target.pyc`/`pycdc target.pyc` 看报错；`dis` 输出中定位异常块（如开头的 `JUMP_ABSOLUTE 4; JUMP_ABSOLUTE 6; JUMP_BACK 2`）。
2. **查 opcode 编号**：在对应版本 `opcode.h` 中查垃圾指令的十进制/十六进制编号（如 `JUMP_ABSOLUTE` 113 = 0x71）；注意 Python 2 指令 3 字节、Python 3 指令 2 字节。
3. **十六进制定位**：在 010 Editor/WinHex 搜索该字节序列（带操作数，如 `71 04 71 06 71 02`），结合 `dis` 偏移确认哪些是垃圾、哪些是正常跳转。
4. **删除垃圾字节**：按指令宽度整条删除（Python 3 每 2 字节），记录删除的总字节数。
5. **修正 co_code 长度**：在 marshal 中搜索 `len(code.co_code)` 的旧值（如 2030 = 0x7EE，小端 `EE 07 00 00`，前面是 0x73 类型字节），改为旧值减去删除字节数（2030-6=2024 = 0x7E8 → `E8 07 00 00`）。
6. **验证**：用同版本 Python 运行 pyc（或 `dis`/反编译）确认逻辑恢复；BabyMaze 修复后正常运行并进入 maze 校验，再按反编译出的逻辑写 DFS 求路径。
7. **若仍失败**：检查是否还有 `co_lnotab`、跳转目标、嵌套 code object 的偏移需要同步调整；必要时用 `dis` 逐条对比原始/修复后的字节码，确认没有残留越界引用。

## PoC

原文查看字节码与长度（Python 3.8；未在本机复跑）：

```python
import marshal, dis
f = open("BabyMaze.pyc", "rb").read()
code = marshal.loads(f[16:])   # Python 3.7+ 头部 16 字节
dis.dis(code)                  # 看到开头 JUMP_ABSOLUTE 4/6、JUMP_BACK 2 的垃圾块
print(len(code.co_code))       # 2030
```

十六进制定位与修复（原文）：

```text
BabyMaze.pyc @0x29: 73 EE 07 00 00 ...   # 0x73=TYPE_STRING，0x7EE=2030=co_code 长度；内容自 0x2E 起
@0x2E:              71 04 71 06 71 02    # JUMP_ABSOLUTE 4 / JUMP_ABSOLUTE 6 / JUMP_BACK 2（6 字节垃圾）
删除 6 字节后：      EE 07 00 00 -> E8 07 00 00   # 2030 - 6 = 2024
```

失败对照（原文 kkkk 示例）：删除 4 条指令（8 字节）后仅把 `len(co_code)` 26→18，反编译仍报：

```text
ValueError: bad marshal data (invalid reference)
ValueError: bad marshal data (unknown type code)
RuntimeError: Bad code object in .pyc file
```

## 变体与关联

- **加花工具**：`pyc_obscure`（向 PyCodeObject 的 co_code 插入垃圾数据）即本卡对抗目标；同类还有源码级混淆（Oxyry 仅混淆源码、字节码仍可读）、pyminifier（重命名标识符）、PyArmor（加密/运行时解密，见 [[code-analysis-reverse-obfuscation-pyarmor-static-unpack-aes-ctr]]）。
- **pyc 提取与反编译**：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller 中取出 pyc）、[[code-analysis-reverse-unpacking-pycdas-constants-key-disassembly]]（反编译不全时用 pycdas 直读 Names/Constants）、[[code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt]]（补 pyc 头/magic 表）。本卡处理的是“能取出但反编译被花指令破坏”的 pyc。
- **自定义 VM**：[[ctf-reverse-custom-python-vm-bytecode-disassembler]] 是从 pyc/pyd 恢复自定义 VM 指令集；本卡是 CPython 原生字节码被插入垃圾指令，二者层次不同。
- **变体**：垃圾指令可能在函数开头（BabyMaze，最容易修）、函数中间（需同时修正跳转目标/lnotab）、或散布在多个嵌套 code object 中；也可用 0x09 `NOP`、无副作用的常量加载等更隐蔽的填充。

## 检测与防御

- **分析侧检测**：`dis` 输出中出现大量连续/无意义的 `JUMP_ABSOLUTE`/`JUMP_BACK`、操作数越界的 `LOAD_FAST`/`LOAD_CONST`、与源码行号不匹配的偏移，或反编译器报 `Parse error near None instruction`，都应怀疑 pyc 加花；可用 `pycdas` 直接逐条核对字节码与引用表。
- **防御/开发**：pyc 混淆不是安全边界，只提高逆向成本；敏感逻辑应放服务端或使用编译型扩展（pyd/Cython）并配合完整性校验/签名；发布时校验 pyc magic/长度一致性，防止被篡改后仍加载。
- **检测（终端）**：监控异常的 pyc 文件（magic 与版本不符、co_code 长度与实际不符、文件被替换）；对 `__pycache__`/打包目录做哈希与签名校验，避免“源码正常但 pyc 被改”的执行差异（另见 .pyc 源码不一致的供应链投毒场景）。
