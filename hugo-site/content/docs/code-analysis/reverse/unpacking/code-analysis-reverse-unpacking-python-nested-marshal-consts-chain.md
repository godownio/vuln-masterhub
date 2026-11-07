---
id: code-analysis-reverse-unpacking-python-nested-marshal-consts-chain
title: Python 恶意样本多层套娃：base64+gzip/bz2/lzma/zlib → compile/exec → reverse+marshal co_consts 链还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: python-nested-marshal-code-consts-unpack
tags:
- reverse
- unpacking
- python
- marshal
- pyc
- bytecode
- obfuscation
- malware-analysis
- multiline-decode
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T02:14:31+08:00'
  notes: 已对照原文与全部7图核对：图1 lambda+compile/exec 与 zlib(lzma(bz2(gzip(base64)))) 套娃、图2 格式化后的嵌套、图3/4 隐藏字符与 ((h<<6&64|c&63)+22)%133+10 变换、图5 co_consts[0] 为反转 marshal bytes、图6 dis 出'获取机器码'/RETURN_GENERATOR、图7 还原 get_machine_code/verify_kami，均与原文一致；pyc 头 b'\xf3\x0d\x0d\x0a'+12 零字节与原文代码一致。未验证点：未获取样本、未实际执行解码；原文未标注样本/Python 具体小版本以外的组件版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-python-nested-marshal-consts-chain/
draft: false
kb_aliases:
- Python 多层解压套娃
- marshal co_consts 链
- pyc 魔数伪造
- compile exec 载荷分析
- Python 3.13 字节码还原
- 隐藏字符干扰解码
- pycdc 不支持新版本
---

## 一句话结论

Python 恶意样本常用“多层 base64 + gzip/bz2/lzma/zlib 套娃 → compile(...,'<string>','exec') 执行 → 内层 payload 反转后 marshal.loads”的组合；分析时按正则逐层抽 `base64.b64decode('...')` 并循环解压、清理异常字符，再伪造对应版本 `.pyc` 头（如 Python 3.13 的 `f3 0d 0d 0a`）与逐层取 `code.co_consts[0][::-1]` 继续 marshal.loads，最后用 `dis` 在字节码层面还原出被反编译工具放弃的新版本代码。

## 原理

- **多层编码/压缩**：样本把下一阶段 payload 写成 `zlib.decompress(lzma.decompress(bz2.decompress(gzip.decompress(base64.b64decode('...')))))` 的嵌套表达式，或把同样结构重复多层；每一层都是可逆的公开编码/压缩，不需要密钥，只需按代码中的顺序反向剥离。
- **compile + exec**：剥离到底后得到 Python 源码字符串，样本用 `compile(src, '<string>', 'exec')` 生成 code object，再 `exec` 执行；`<string>` 隐藏真实文件名，`globals()/locals()` 可被自定义以污染命名空间或替换 `__import__`。
- **隐藏字符干扰**：部分层解码后会出现大量非预期字节（如 0xcd、不可见字符），导致长度异常、语法不完整或后续解压失败；这类字符可能是上一层自定义变换的副产物，也可能是刻意插入的噪声。先打印长度与 hex、按可打印性过滤/替换，再继续解码。
- **reverse + marshal**：内层把 `marshal.dumps(code_obj)` 的结果整体反转后作为 bytes 常量保存，执行时 `marshal.loads(data[::-1])` 还原 code object。`marshal` 是 CPython 内部序列化格式，不保证跨版本稳定，必须用与样本相同的 Python 版本解析。
- **pyc 头伪造**：`.pyc` = magic(4) + flags/bitfield(4) + mtime/size 或 hash(8) + marshal 数据。样本用 `b'\xf3\x0d\x0d\x0a' + b'\x00'*12` 伪造 Python 3.13 的头部，把后续 12 字节清零，让工具把它当作合法 pyc；魔数随 Python 版本变化，选错会导致 `marshal.loads`/反编译失败。
- **co_consts 链**：外层 code object 的 `co_consts[0]` 仍是反转后的 marshal 字节流；循环 `marshal.loads(code.co_consts[0][::-1])` 可逐层下钻，直到 `co_consts` 中不再有 marshal bytes。
- **字节码还原**：当 uncompyle6/pycdc 尚不支持目标版本（如 3.13）时，用 `dis.dis(code_obj)` 查看字节码与常量，结合函数名、字符串常量、控制流和 LLM 辅助重建源码；字节码中的 `LOAD_CONST`/`CALL`/`RETURN_GENERATOR` 等足以还原业务逻辑（如图片中的“获取机器码”“验证卡密”）。
- **为什么成立**：整套链路只依赖可逆编码与 CPython 公开的 code object 结构；只要分析环境与样本 Python 版本一致，就能逐层还原。难度来自层数、噪声字符和工具版本支持，而不是密码学强度。

## 触发条件

- 拿到可疑 `.py`/`.pyc`/打包产物，源码中出现长 base64 字符串、多层 `decompress` 嵌套、`compile`+`exec`、`marshal.loads`、`[::-1]` 等特征。
- 有与样本匹配的 Python 版本（可从 pyc 魔数、`sys.version`、依赖/打包信息推断）。
- 解码层使用标准库 `base64/gzip/bz2/lzma/zlib/marshal`；若使用自定义加密/异或，需先逆向该变换。
- 分析环境可安全执行/隔离样本（沙箱、容器、只读 FS、无网络）；不要在宿主机直接跑未知 Python 代码。

## 利用步骤

1. 静态阅读入口：搜索 `exec`、`compile`、`eval`、`marshal`、`base64.b64decode`、`decompress`、`[::-1]`，标记 payload 变量与解码函数。
2. 对 `0O0O00O...` 之类混淆变量重命名，把入口改写成可读的嵌套表达式或 `deobf` 函数。
3. 写循环：用正则抽取当前文本中 `base64.b64decode('...')` 的字面量，调用 `deobf`（内部依次尝试 zlib/lzma/bz2/gzip），覆盖 payload 后继续，直到匹配不到。
4. 每层输出长度与 hex；发现异常字符/长度骤变时，先可视化并按可打印字符过滤/替换，再继续。
5. 遇到 `marshal.loads(data[::-1])`：用样本同版本 Python 执行 `marshal.loads`，打印 `co_consts`、`co_names`、`co_code`；若工具报错，用 `b'\xf3\x0d\x0d\x0a'+b'\x00'*12`（或 `importlib.util.MAGIC_NUMBER`）补 pyc 头另存。
6. 循环 `code = marshal.loads(code.co_consts[0][::-1])`，每层 `dis.dis(code)`，直到 `co_consts` 不再含 marshal 字节流。
7. 以字节码 + 字符串常量 + 控制流重建源码；对不确定处用 LLM 辅助校对，但要在同版本环境执行验证关键函数（隔离环境）。
8. 记录每层产物哈希/长度，便于回溯与报告。

## PoC

```python
import base64, gzip, bz2, lzma, zlib, re, marshal, dis, types

def deobf(b64s):
    data = base64.b64decode(b64s)
    for fn in (zlib.decompress, lzma.decompress, bz2.decompress, gzip.decompress):
        try:
            return fn(data)
        except Exception:
            continue
    return data

text = open("sample.py", "r", encoding="utf-8", errors="ignore").read()
for i in range(50):
    m = re.search(r"base64\.b64decode\('([^']*)'\)", text)
    if not m:
        break
    raw = deobf(m.group(1))
    # 异常字符清理：只保留可打印 ASCII/常见空白，或按样本变换还原
    text = raw.decode("utf-8", errors="ignore")
    print(i, len(raw), raw[:32].hex())
```

```python
# pyc 头伪造 + 逐层 marshal co_consts 下钻（同一 Python 版本）
import importlib.util, marshal, dis

data = open("stage.bin", "rb").read()
pyc = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + data   # 用当前版本魔数，等价于硬编码 f3 0d 0d 0a (3.13)
open("dec.pyc", "wb").write(pyc)

code = marshal.loads(data[::-1])
for depth in range(20):
    print("=" * 20, "depth", depth, "=" * 20)
    dis.dis(code)
    if not code.co_consts:
        break
    nxt = code.co_consts[0]
    if not isinstance(nxt, (bytes, bytearray)):
        break
    code = marshal.loads(bytes(nxt)[::-1])
```

```text
提示：若样本使用自定义字符变换（如图片中的 ((h<<6&64|c&63)+22)%133+10 逐字节映射），
需先把该变换的逆函数写在 deobf 前；不要把未知样本直接 exec，可在隔离容器中用
types.FunctionType(code, globals) 仅做静态观察或替换危险内置后再执行。
```

## 变体与关联

- 变体：payload 不是 marshal 而是 `marshal.loads` 后的 code object 再 `exec`；或用 `types.FunctionType(code, globals)` 绑定命名空间。
- 变体：自定义 globals 污染 `__import__`/`open`/`eval`，分析时需替换为审计桩（记录调用而不真正执行危险操作）。
- 变体：多层压缩顺序变化、加入异或/反转/字符位移、把 base64 拆成多段拼接；按实际代码逐层复刻，不要假设固定顺序。
- 变体：打包为 PyInstaller/Nuitka 时先解包（见关联卡），再对 `PYZ-00.pyz` 中的 marshal code object 做同样下钻。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller CArchive/PYZ 提取）、[[ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt]]（marshal code object + XXTEA）、[[defense-forensics-python-malware-reversed-base64-url-config]]（Python 木马字符串反转+Base64+URL 还原）。

## 检测与防御

- 检测：脚本中出现 `compile(..., '<string>', 'exec')`、`eval/exec` 嵌套、`marshal.loads`、`[::-1]`、多层 `decompress(base64.b64decode(...))`、大段不可读字符串等特征。
- 检测：`.pyc` 魔数与当前 Python 版本不匹配、头部 mtime/size 全零、`co_consts` 中出现 bytes 常量且反转后符合 marshal 结构。
- 防御：不要执行未知 Python 脚本；在隔离容器/沙箱中分析，禁用网络与敏感挂载，使用只读 FS。
- 防御（供应链）：锁定 Python 版本与依赖哈希，扫描 `sitecustomize.py`/`.pth` 等自动加载点，监控运行期 `exec`/`marshal` 行为。
- 响应：保留原始样本与每层解码产物哈希；提取 C2/持久化配置后封锁；对同源样本按魔数与解码链特征做批量检测。
