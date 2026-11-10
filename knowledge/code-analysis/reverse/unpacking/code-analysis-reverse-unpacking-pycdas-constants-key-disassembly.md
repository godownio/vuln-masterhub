---
id: code-analysis-reverse-unpacking-pycdas-constants-key-disassembly
title: PyInstaller pyc 反编译不全时用 pycdas 反汇编：从 Names/Constants 表直取硬编码 AES 密钥，按 LOAD_NAME/LOAD_METHOD/CALL_METHOD 还原解密调用链
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pycdas-bytecode-constants-call-chain-recover
aliases:
- pycdas 反汇编 pyc
- pycdc Decompile incomplete
- Unsupported opcode WITH_EXCEPT_START
- pyc 字节码恢复密钥
- Python 3.10 pyc 人工还原
- Constants 表取密钥
- 反编译失败兜底
tags:
- reverse
- unpacking
- python
- pyc
- pycdas
- bytecode
- pyinstaller
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:37:43+08:00'
  notes: 已对照原文及19张图核验：pycdas 输出 Names/Constants/Disassembly 结构、Constants 中 dfhkAsDFAjDShdfu、LOAD_CONST->STORE_NAME aes_key、LOAD_NAME/LOAD_METHOD/CALL_METHOD 还原 decrypt/fromhex/exec 均与原文一致；与既有 pyd-xor/CArchive/PYZ-key/nested-marshal 卡为不同技法（反编译失败兜底读字节码），非同链，与同篇 Windows 样本卡互补不重复。原文未标组件版本，不设 affected_versions。dup-scan(11-08)早于建卡。
---

## 一句话结论

当 pycdc 对 Python 3.10 的 pyc 报 `Unsupported opcode: WITH_EXCEPT_START` / `# WARNING: Decompile incomplete` 时，不必强求反编译：用 pycdas 对同一 pyc 做 unmarshal + 反汇编，输出的 `[Names]`、`[Constants]` 表里就能直接看到硬编码密钥、文件名和字段名，再按 `LOAD_CONST→STORE_NAME`（赋值）与 `LOAD_NAME→LOAD_METHOD→CALL_METHOD`（调用）序列手工还原出完整解密流程。

## 原理

- **pycdas 不受反编译器 opcode 支持限制**：pycdc 需要把字节码翻译回 Python 源码，遇到新版本/未实现的 opcode（如 Python 3.10 的 `WITH_EXCEPT_START`）会中断并输出不完整代码；pycdas 只做 pyc 反序列化与指令级反汇编，逐条打印 opcode 与参数，因此总能给出完整字节码。
- **pycdas 输出的结构**：头部是 code object 元信息（File Name、Object Name、Arg Count、Stack Size、Flags），随后是 `[Names]`（`co_names`，被引用的模块名/函数名/变量名）、`[Var Names]`、`[Free Vars]`、`[Cell Vars]`、`[Constants]`（`co_consts`，字符串/数字/None 等字面量），最后是带行号的 `[Disassembly]`。
- **常量表直接泄露密钥**：样本里的硬编码密钥通常在 `[Constants]` 中以明文字符串出现，例如 `dfhkAsDFAjDShdfu`；即使不在常量表里，也能在反汇编里通过 `LOAD_CONST 6: '...'` 后紧跟 `STORE_NAME aes_key` 定位到“把该常量赋给密钥变量”的指令。
- **调用链读取规则**：Python 3.10 字节码中，`LOAD_NAME mod; LOAD_METHOD fn; LOAD_NAME key; LOAD_NAME data; CALL_METHOD 2; STORE_NAME out` 对应 `out = mod.fn(key, data)`；`LOAD_NAME bytes; LOAD_METHOD fromhex; LOAD_NAME code; CALL_METHOD 1` 对应 `bytes.fromhex(code)`；`LOAD_NAME exec; LOAD_NAME load; CALL_FUNCTION 1` 对应 `exec(load)`。按栈顺序还原实参与调用即可。
- **为什么可行**：CPython 字节码保留了所有名字与常量，只是丢失了表达式结构和部分语法糖；对于“读 JSON → 解密钥 → 解密两段数据 → 执行”这类线性逻辑，指令序列足以 1:1 还原。

## 触发条件

- 目标为 PyInstaller 等打包的 Python 样本，已用 pyinstxtractor 等解出入口/依赖 pyc，且 Python 版本较新（如 3.10/3.11/3.13）。
- pycdc/uncompyle6 等反编译器不支持该版本或该 opcode，输出被截断/报 `Decompile incomplete`。
- 需要提取硬编码密钥、加密算法参数、接口路径或理解解密/执行流程。
- 分析环境有与样本匹配的 Python 版本（pycdas 随 pycdc 项目提供；也可用 `marshal.loads` + `dis` 替代）。

## 利用步骤

1. 用 pyinstxtractor 解包，确认 Python 版本与入口 pyc（如 `ma.pyc`），必要时先按版本补 pyc 头。
2. 运行 `pycdas ma.pyc > ma.dis`（或 `python pycdas.py ma.pyc`），得到完整反汇编文本。
3. 先看 `[Names]`：定位可疑模块/函数名（如 `aesdecypto`、`decrypt`、`fromhex`、`exec`），确定样本在做什么。
4. 再看 `[Constants]`：提取所有字符串常量，找密钥、文件名、JSON 字段名等；对照反汇编中的 `LOAD_CONST`.
5. 在 `[Disassembly]` 中从 `STORE_NAME aes_key` 之类赋值点回溯上一条 `LOAD_CONST`，取得密钥字面量。
6. 顺 `LOAD_NAME/LOAD_METHOD/CALL_METHOD/CALL_FUNCTION` 序列还原每个表达式与调用顺序，写成等价 Python 伪代码。
7. 按还原出的算法（如 AES-CBC、key 与 IV 相同、PKCS7、base64）离线解密样本数据；若字节码仍歧义，用同版本 `marshal.loads(pyc[16:])` + `dis.dis` 交叉验证。
8. 对解密出的下一阶段载荷（脚本/shellcode）继续分析或沙箱验证。

## PoC

```bash
# 解包与反汇编
python pyinstxtractor.py ma.exe
pycdas ma.exe_extracted/ma.pyc | tee ma.dis
# 在输出中查找：
#   [Constants] ... 'dfhkAsDFAjDShdfu'
#   LOAD_CONST 6: 'dfhkAsDFAjDShdfu'
#   STORE_NAME 11: aes_key
#   LOAD_NAME aesdecypto / LOAD_METHOD decrypt / LOAD_NAME aes_key / LOAD_NAME code / CALL_METHOD 2
```

```python
# 无 pycdas 时的等价兜底：直接读取 code object 的常量/名字并反汇编
import marshal, dis
data = open("ma.pyc", "rb").read()
code = marshal.loads(data[16:])   # 跳过 16 字节 pyc 头（按实际版本调整）
print("names:", code.co_names)
print("consts:", code.co_consts)
dis.dis(code)
```

## 变体与关联

- **工具替代**：pycdas 与 pycdc 同源；也可用 `xdis`/`dis` 模块或同版本 Python 的 `marshal.loads` + `dis.dis` 得到等价信息。
- **反编译成功的场景**：若能直接反编译，优先用源码；pycdas 适合作为“反编译失败/不完整”的兜底。
- **与多层 marshal 的区别**：多层套娃样本还要逐层 `marshal.loads(co_consts[...])`，见 [[code-analysis-reverse-unpacking-python-nested-marshal-consts-chain]]；本卡只处理“单层 pyc 但反编译失败”的情况。
- **PyInstaller 解包前置步骤**见 [[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]；PYZ 加密场景见 [[code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt]]。
- **常见坑**：pyc 头长度/版本不一致会导致 marshal 失败；不同 Python 小版本的 opcode 名称可能变化，读反汇编时要按实际版本注释。

## 检测与防御

- 检测：PyInstaller 样本中出现 `aesdecypto`、`decrypt`、`fromhex`、`exec` 等名字组合，JSON 配置与 EXE 同目录；pyc 内硬编码密钥/IV。
- 防御：客户端密钥与算法只是提高分析成本，不能作为安全边界；敏感逻辑放服务端，配合样本哈希与 YARA 规则。
- 分析侧：不要直接 exec 未知样本；在隔离环境用字节码/静态方式还原，必要时替换 `exec`/`open` 为审计桩。
